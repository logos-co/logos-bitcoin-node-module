//! The module without the SDK: source lists, the proxy, the route table, Kyoto's peers, health
//! and events. The glue gates callers and forwards here; replies are flat JSON strings.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use tokio::sync::Notify;

use crate::book::{self, Book, Report};
use crate::health::{self, Health, Row, State};
use crate::net::client::{is_lan_host, route_for, Route};
use crate::net::p2p::Gossip;
use crate::network::{bad_network, networks, BNetwork};
use crate::peers::{self, peer_host};
use crate::proxy::{self, BUILT_IN, DEFAULT_PROXY};
use crate::reply;
use crate::sources::{self, Changes, Credentials, Kind, Source, LOCAL_ID};
use crate::store::{NetConfig, Store, Suspicion};

pub const NO_PROXY: &str = "no proxy is set";
pub const TOR_STARTING: &str = "the Tor that comes with Logos is starting";
pub const TOR_SOCKS_OFF: &str = "Tor's SOCKS port is off: turn it on in the Tor app";
pub const TOR_MISSING: &str = "the Tor that comes with Logos is not available";
pub const LOCKED: &str = "Close the wallet to change these settings.";
pub const SUSPECT: &str = "suspect";
/// How long probe waits on the network, inside the 20 s IPC deadline.
pub const CALL_BUDGET: Duration = Duration::from_secs(15);

pub enum Event {
    HealthChanged { network: BNetwork, payload: String },
    RoutesChanged { network: BNetwork },
    Suspect { network: BNetwork, source_id: String, kind: String },
}

pub type Sink = Arc<dyn Fn(Event) + Send + Sync>;

/// One server to probe, on its route.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    pub network: BNetwork,
    pub id: String,
    pub kind: Kind,
    pub url: String,
    pub route: Route,
    /// Set only for routes through Tor.
    pub proxy: Option<String>,
    pub credentials: Option<Credentials>,
    pub cert_sha256: Option<String>,
}

/// Work the health thread does for a caller that waits on `done`.
pub enum Job {
    Probe { targets: Vec<Target>, done: mpsc::Sender<()> },
}

/// Fixed seeds the health thread asks for addresses: up to 8 of one network, each once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Harvest {
    pub network: BNetwork,
    /// `host:port` and the route to it.
    pub seeds: Vec<(String, Route)>,
    pub proxy: Option<String>,
}

/// The built-in Tor as tor_module last reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorView {
    /// connecting, ready, blocked or failed.
    pub state: String,
    pub progress: u8,
    /// Why it is blocked or failed; empty otherwise, so progress alone does not churn events.
    pub detail: String,
    /// Its SOCKS port, `socks5h://IP:PORT`, which Tor routes dial; none while the user has it off.
    pub socks: Option<String>,
    /// tor_module answered; false when it is not loaded or did not answer.
    pub answered: bool,
}

impl TorView {
    /// tor_module's status() reply, or why there was none.
    pub fn from_reply(reply: Result<String, String>) -> Self {
        let failed = |detail: String| Self { state: "failed".into(), progress: 0, detail, socks: None, answered: false };
        let v: Value = match reply.and_then(|t| serde_json::from_str(&t).map_err(|e| format!("tor_module: {e}"))) {
            Ok(v) => v,
            Err(e) => return failed(e),
        };
        match v["error"].as_str() {
            _ if v["ok"] == true => {}
            Some("starting") => return Self { state: "connecting".into(), progress: 0, detail: String::new(), socks: None, answered: false },
            e => return failed(e.unwrap_or("tor_module answered without ok").into()),
        }
        // Asking starts an idle Tor, so idle is only ever a moment's answer.
        let state = match v["state"].as_str() {
            None | Some("idle") => "connecting".to_string(),
            Some(s) => s.to_string(),
        };
        let detail = match state.as_str() {
            "blocked" | "failed" => v["detail"].as_str().unwrap_or("").to_string(),
            _ => String::new(),
        };
        let progress = v["progress"].as_u64().unwrap_or(0).min(100) as u8;
        let socks = v["socks"].as_str().and_then(|s| proxy::normalize(s).ok()).filter(|s| s != BUILT_IN);
        Self { state, progress, detail, socks, answered: true }
    }
}

/// bitcoind_module's status, when it is loaded. A trait so the pure tests can stand one in.
pub trait LocalStatus: Send + Sync {
    fn status(&self) -> Result<Value, String>;
}

pub struct Node {
    inner: Mutex<Inner>,
    path: Option<PathBuf>,
    sink: Sink,
    wake: Notify,
    local: Mutex<Option<Arc<dyn LocalStatus>>>,
    jobs: Mutex<Option<tokio::sync::mpsc::UnboundedSender<Job>>>,
}

struct Inner {
    store: Store,
    /// Live health by (network, id), with the url and pin it was measured with (`tag`).
    health: HashMap<(BNetwork, String), (String, Health)>,
    sent_health: HashMap<BNetwork, String>,
    sent_routes: HashMap<BNetwork, String>,
    /// Networks the backend says a wallet is open on: their settings are locked.
    wallet_open: BTreeSet<BNetwork>,
    /// Kyoto's peer book per network, kept beside the sources file.
    books: BTreeMap<BNetwork, Book>,
    dir: Option<PathBuf>,
    /// Regtest's fixed seeds: a test-only setting from regtest.json.
    regtest_seeds: Vec<String>,
    /// The built-in Tor, once tor_module has been asked.
    tor: Option<TorView>,
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn parse_net(network: &str) -> Result<BNetwork, String> {
    BNetwork::parse(network).ok_or_else(bad_network)
}

fn not_configured(net: BNetwork) -> String {
    format!("{} is not configured: the wallet backend calls init_defaults first", net.name())
}

/// What a health result was measured against: a new url or pin makes it stale.
fn tag(url: &str, pin: Option<&str>) -> String {
    format!("{url} {}", pin.unwrap_or(""))
}

fn names(nets: impl IntoIterator<Item = BNetwork>) -> Vec<&'static str> {
    nets.into_iter().map(BNetwork::name).collect()
}

impl Inner {
    fn cfg(&self, net: BNetwork) -> Option<&NetConfig> {
        self.store.networks.get(&net)
    }

    fn route_of(cfg: &NetConfig, s: &Source) -> Route {
        match s.kind {
            Kind::Local => Route::Direct,
            Kind::Kyoto => peers::kyoto_route(&cfg.own_peers, s.tor),
            _ => route_for(&sources::host(s), s.tor),
        }
    }

    fn lan_of(cfg: &NetConfig, s: &Source) -> bool {
        match s.kind {
            Kind::Local => true,
            Kind::Kyoto => peers::kyoto_lan(&cfg.own_peers),
            _ => is_lan_host(&sources::host(s)),
        }
    }

    /// Where Tor routes dial: the user's own Tor, or the built-in one's SOCKS port while it has one.
    fn dial_proxy(&self) -> Option<&str> {
        match self.store.proxy() {
            Some(BUILT_IN) => self.tor.as_ref().and_then(|t| t.socks.as_deref()),
            p => p,
        }
    }

    /// Why Tor routes have nowhere to dial.
    fn no_proxy(&self) -> &'static str {
        match (self.store.proxy(), &self.tor) {
            (Some(BUILT_IN), None) => TOR_STARTING,
            (Some(BUILT_IN), Some(t)) if t.answered => TOR_SOCKS_OFF,
            (Some(BUILT_IN), Some(t)) if t.state == "connecting" => TOR_STARTING,
            (Some(BUILT_IN), Some(_)) => TOR_MISSING,
            _ => NO_PROXY,
        }
    }

    /// The built-in Tor for health, while the proxy is it.
    fn tor_value(&self) -> Value {
        if self.store.proxy() != Some(BUILT_IN) {
            return Value::Null;
        }
        match &self.tor {
            Some(t) => json!({"state": t.state, "progress": t.progress, "detail": t.detail, "socks": t.socks}),
            None => json!({"state": "connecting", "progress": 0, "detail": "", "socks": null}),
        }
    }

    /// Fail closed: a source whose route goes through Tor has none without the proxy.
    fn blocked(&self, cfg: &NetConfig, s: &Source) -> Option<&'static str> {
        let tor = matches!(Self::route_of(cfg, s), Route::Tor | Route::Onion);
        (tor && self.dial_proxy().is_none()).then(|| self.no_proxy())
    }

    /// Why a source gets no route, if it gets none.
    fn unrouted(&self, net: BNetwork, cfg: &NetConfig, s: &Source) -> Option<&'static str> {
        if let Some(why) = self.blocked(cfg, s) {
            return Some(why);
        }
        if cfg.suspects.contains_key(&s.id) {
            return Some(SUSPECT);
        }
        if self.health_of(net, s).is_some_and(|h| h.state == State::WrongNetwork) {
            return Some(health::WRONG_NETWORK);
        }
        None
    }

    fn health_of(&self, net: BNetwork, s: &Source) -> Option<&Health> {
        match self.health.get(&(net, s.id.clone())) {
            Some((t, h)) if *t == tag(&s.url, s.cert_sha256.as_deref()) => Some(h),
            _ => None,
        }
    }

    fn forget_stale_health(&mut self, net: BNetwork) {
        let live: Vec<(String, String)> =
            self.cfg(net).map(|c| c.sources.iter().map(|s| (s.id.clone(), tag(&s.url, s.cert_sha256.as_deref()))).collect()).unwrap_or_default();
        self.health.retain(|(n, id), (t, _)| *n != net || live.iter().any(|(i, lt)| i == id && lt == t));
    }

    fn target(&self, net: BNetwork, cfg: &NetConfig, s: &Source) -> Target {
        let route = Self::route_of(cfg, s);
        let proxy = matches!(route, Route::Tor | Route::Onion).then(|| self.dial_proxy().map(String::from)).flatten();
        Target {
            network: net,
            id: s.id.clone(),
            kind: s.kind,
            url: s.url.clone(),
            route,
            proxy,
            credentials: s.credentials.clone(),
            cert_sha256: s.cert_sha256.clone(),
        }
    }

    /// Every peer Kyoto may dial, `{ peer, source, ok }`: your own peers, which replace the book,
    /// or the book's list and learned peers, skipped ones left out.
    fn usable(&self, net: BNetwork, cfg: &NetConfig) -> Vec<Value> {
        if !cfg.own_peers.is_empty() {
            return cfg.own_peers.iter().map(|p| json!({"peer": p, "source": "own", "ok": false})).collect();
        }
        let Some(book) = self.books.get(&net) else { return vec![] };
        book.usable(cfg.kyoto_tor(), now()).into_iter().map(|e| json!({"peer": e.peer(), "source": e.source, "ok": e.last_ok.is_some()})).collect()
    }

    fn save_book(&self, net: BNetwork) {
        if let (Some(dir), Some(b)) = (&self.dir, self.books.get(&net)) {
            if let Err(e) = b.save(dir) {
                eprintln!("bitcoin_node_module: saving the {} peer book: {e}", net.name());
            }
        }
    }

    /// The book on disk (or a new one), merged with the shipped list and seeds, pruned.
    fn load_book(&mut self, net: BNetwork) {
        let loaded = self.dir.as_deref().map(|d| Book::load(d, net)).unwrap_or_else(|| Book::new(net));
        let mut b = loaded.clone();
        let list = peers::shipped(net);
        let seeds = if net == BNetwork::Regtest { self.regtest_seeds.clone() } else { peers::fixed_seeds(net).to_vec() };
        b.sync_shipped(&list.peers, list.version, &seeds, now());
        b.prune(now());
        let changed = b != loaded;
        self.books.insert(net, b);
        if changed {
            self.save_book(net);
        }
    }

    fn roles(&self, net: BNetwork, cfg: &NetConfig) -> sources::Roles {
        sources::roles(&cfg.sources, |s| Self::route_of(cfg, s), |s| self.unrouted(net, cfg, s).is_none())
    }

    fn route_table(&self, net: BNetwork) -> String {
        let Some(cfg) = self.cfg(net) else { return reply::err(not_configured(net)) };
        let r = self.roles(net, cfg);
        let peers = if r.history.iter().any(|e| e.kind == Kind::Kyoto) { self.usable(net, cfg) } else { vec![] };
        let unrouted: Vec<Value> = cfg
            .sources
            .iter()
            .filter(|s| s.enabled)
            .filter_map(|s| self.unrouted(net, cfg, s).map(|why| json!({"id": s.id, "reason": why})))
            .collect();
        reply::ok(json!({
            "network": net.name(),
            "proxy": self.dial_proxy(),
            "chain": r.chain,
            "history": r.history,
            "pending": r.pending,
            "fees": r.fees,
            "broadcast": r.broadcast,
            "check": r.check,
            "peers": peers,
            "crossCheck": r.cross_check,
            "unrouted": unrouted,
        }))
    }

    /// get_sources' fields: never a credential.
    fn sources_value(&self, net: BNetwork) -> Value {
        let wallet_open = self.wallet_open.contains(&net);
        let Some(cfg) = self.cfg(net) else {
            return json!({"network": net.name(), "configured": false, "walletOpen": wallet_open, "proxy": self.store.proxy(),
                          "sources": [], "exposes": [], "withoutTor": [], "crossCheck": false});
        };
        let route = |s: &Source| Self::route_of(cfg, s);
        let lan = |s: &Source| Self::lan_of(cfg, s);
        let list: Vec<Value> = cfg
            .sources
            .iter()
            .map(|s| {
                json!({"id": s.id, "kind": s.kind, "url": s.url, "operator": s.operator, "label": s.label, "use": s.enabled,
                       "history": s.history, "tor": s.tor, "lan": lan(s), "hasCredentials": s.credentials.is_some(),
                       "certSha256": s.cert_sha256, "route": route(s), "suspect": cfg.suspects.contains_key(&s.id)})
            })
            .collect();
        json!({
            "network": net.name(),
            "configured": true,
            "walletOpen": wallet_open,
            "proxy": self.store.proxy(),
            "sources": list,
            "exposes": sources::exposes(&cfg.sources, lan),
            "withoutTor": sources::without_tor(&cfg.sources, route, lan),
            "crossCheck": self.roles(net, cfg).cross_check,
        })
    }

    fn kyoto_health(&self, net: BNetwork, cfg: &NetConfig, s: &Source) -> (Health, usize) {
        if let Some(why) = self.blocked(cfg, s) {
            return (Health { state: State::NoRoute, error: Some(why.into()), ..Health::default() }, 0);
        }
        let n = self.usable(net, cfg).len();
        if n == 0 {
            let why = format!("no peer to dial: {}", peers::shipped(net).note);
            return (Health { state: State::NoPeers, error: Some(why), ..Health::default() }, 0);
        }
        (Health { state: State::NotProbed, ..Health::default() }, n)
    }

    /// source_health()'s fields, without `ok`.
    fn health_value(&self, net: BNetwork) -> Value {
        let Some(cfg) = self.cfg(net) else {
            return json!({"network": net.name(), "configured": false, "overall": health::Overall::Offline, "pending": false, "sources": []});
        };
        let measured: Vec<(&Source, Option<Health>, usize)> = cfg
            .sources
            .iter()
            .map(|s| match s.kind {
                Kind::Kyoto => {
                    let (h, n) = self.kyoto_health(net, cfg, s);
                    (s, Some(h), n)
                }
                Kind::Local => (s, Some(Health { state: State::NotProbed, ..Health::default() }), 0),
                _ => (s, self.health_of(net, s).cloned(), 0),
            })
            .collect();
        let rows: Vec<Row> = measured
            .iter()
            .filter(|(s, ..)| s.enabled)
            .map(|(s, h, _)| Row { operator: &s.operator, suspect: cfg.suspects.contains_key(&s.id), health: h.as_ref() })
            .collect();
        let list: Vec<Value> = measured
            .iter()
            .map(|(s, h, peers)| {
                let mut v = serde_json::to_value(h.clone().unwrap_or_default()).unwrap_or_else(|_| json!({}));
                let sus = cfg.suspects.get(&s.id);
                if let Value::Object(m) = &mut v {
                    for (k, val) in [
                        ("id", json!(s.id)),
                        ("kind", json!(s.kind)),
                        ("url", json!(s.url)),
                        ("operator", json!(s.operator)),
                        ("label", json!(s.label)),
                        ("use", json!(s.enabled)),
                        ("route", json!(Self::route_of(cfg, s))),
                        ("suspect", json!(sus.is_some())),
                        ("suspectKind", json!(sus.map(|x| &x.kind))),
                        ("suspectHeight", json!(sus.and_then(|x| x.height).map(|h| h.to_string()))),
                    ] {
                        m.insert(k.into(), val);
                    }
                    if s.kind == Kind::Kyoto {
                        m.insert("peers".into(), json!(peers.to_string()));
                    }
                }
                v
            })
            .collect();
        json!({
            "network": net.name(),
            "configured": true,
            "overall": health::overall(&rows),
            "pending": measured.iter().any(|(s, h, _)| s.enabled && h.is_none()),
            "sources": list,
            "tor": self.tor_value(),
        })
    }

    fn counts(&self, net: BNetwork, cfg: &NetConfig) -> book::Counts {
        let mut c = self.books.get(&net).map(|b| b.counts(cfg.kyoto_tor(), now())).unwrap_or_default();
        c.usable = self.usable(net, cfg).len();
        c
    }

    fn peer_list_value(&self, net: BNetwork, cfg: &NetConfig) -> Value {
        let tor = cfg.kyoto_tor();
        json!({
            "network": net.name(),
            "list": peers::shipped(net),
            "ownPeers": cfg.own_peers,
            "usable": self.usable(net, cfg),
            "counts": self.counts(net, cfg),
            "route": peers::kyoto_route(&cfg.own_peers, tor),
            "kyotoTor": tor,
        })
    }

    /// Events for whatever changed since they were last sent. Round-trip times and
    /// timestamps alone do not count as a change.
    fn changes(&mut self, net: BNetwork) -> Vec<Event> {
        let mut events = Vec::new();
        let routes = self.route_table(net);
        if self.sent_routes.get(&net) != Some(&routes) {
            self.sent_routes.insert(net, routes);
            events.push(Event::RoutesChanged { network: net });
        }
        let value = self.health_value(net);
        let signature = signature(&value);
        if self.sent_health.get(&net) != Some(&signature) {
            self.sent_health.insert(net, signature);
            events.push(Event::HealthChanged { network: net, payload: reply::ok(value) });
        }
        events
    }
}

fn signature(health: &Value) -> String {
    let mut v = health.clone();
    if let Some(list) = v.get_mut("sources").and_then(Value::as_array_mut) {
        for s in list.iter_mut().filter_map(Value::as_object_mut) {
            s.remove("rttMs");
            s.remove("checkedAt");
        }
    }
    v.to_string()
}

impl Node {
    /// Loads `path`, or starts unconfigured; `None` keeps everything in memory.
    /// Peer books live beside the sources file, one per network (`kyoto_peers_<network>.json`).
    pub fn open(path: Option<PathBuf>, sink: Sink) -> Arc<Self> {
        let store = match &path {
            Some(p) => Store::load_or_empty(p),
            None => Store::empty(),
        };
        let dir = path.as_deref().and_then(Path::parent).map(Path::to_path_buf);
        let mut inner = Inner {
            store,
            health: HashMap::new(),
            sent_health: HashMap::new(),
            sent_routes: HashMap::new(),
            wallet_open: BTreeSet::new(),
            books: BTreeMap::new(),
            dir,
            regtest_seeds: vec![],
            tor: None,
        };
        for net in networks() {
            inner.load_book(net);
            let _ = inner.changes(net);
        }
        Arc::new(Self { inner: Mutex::new(inner), path, sink, wake: Notify::new(), local: Mutex::new(None), jobs: Mutex::new(None) })
    }

    /// Regtest's fixed seeds, reached directly: a test-only setting (regtest.json's harvestSeeds).
    pub fn set_regtest_seeds(&self, seeds: &[String]) -> Result<(), String> {
        for s in seeds {
            if peers::normalize_peer(BNetwork::Regtest, s).as_deref() != Ok(s.as_str()) || !is_lan_host(peer_host(s)) {
                return Err(format!("harvestSeeds: {s} is not host:port on your network"));
            }
        }
        if !networks().contains(&BNetwork::Regtest) {
            return Err("regtest is not configured".into());
        }
        let events = {
            let mut inner = self.lock();
            inner.regtest_seeds = seeds.to_vec();
            inner.load_book(BNetwork::Regtest);
            inner.changes(BNetwork::Regtest)
        };
        self.emit(events);
        Ok(())
    }

    /// The wallet core's report on Kyoto's peers: outcomes, which update each peer's record and
    /// skip one for 24 h after 3 failures in a row, and peers learned from gossip.
    pub fn report_peers(&self, network: &str, report_json: &str) -> String {
        let net = match parse_net(network) {
            Ok(n) => n,
            Err(e) => return reply::err(e),
        };
        let report = match Report::parse(report_json) {
            Ok(r) => r,
            Err(e) => return reply::err(e),
        };
        let (out, events) = {
            let mut inner = self.lock();
            let now = now();
            let Some(book) = inner.books.get_mut(&net) else { return reply::err(format!("no peer book for {}", net.name())) };
            let (mut applied, mut unknown) = (0, 0);
            for o in &report.outcomes {
                if book.outcome(&o.peer, o.ok, now) {
                    applied += 1;
                } else {
                    unknown += 1;
                }
            }
            let results: Vec<_> = report.learned.iter().map(|l| book.learn(l, now)).collect();
            let learned = Book::tally(results);
            book.prune(now);
            inner.save_book(net);
            let counts = inner.cfg(net).map(|c| inner.counts(net, c)).unwrap_or_default();
            let out = reply::ok(json!({"network": net.name(), "outcomes": {"applied": applied, "unknown": unknown}, "learned": learned, "counts": counts}));
            (out, inner.changes(net))
        };
        self.emit(events);
        out
    }

    /// Networks with a wallet open whose book holds fewer than 12 usable peers that worked in
    /// 30 days, Kyoto on and dialling the book, when a harvest is due (`Book::harvest_due`): up
    /// to 8 seeds each. An onion seed needs the proxy; only regtest's test seeds go direct.
    pub fn harvest_plan(&self) -> Vec<Harvest> {
        let mut inner = self.lock();
        let now = now();
        let proxy = inner.dial_proxy().map(String::from);
        let mut out = Vec::new();
        for net in networks() {
            let Some(cfg) = inner.cfg(net) else { continue };
            let kyoto = cfg.sources.iter().any(|s| s.kind == Kind::Kyoto && s.enabled);
            if !kyoto || !cfg.own_peers.is_empty() || !inner.wallet_open.contains(&net) {
                continue;
            }
            let tor = cfg.kyoto_tor();
            let Some(book) = inner.books.get(&net) else { continue };
            if !book.harvest_due(tor, now) {
                continue;
            }
            let seeds: Vec<(String, Route)> = book
                .pick_seeds()
                .into_iter()
                .filter_map(|p| match route_for(peer_host(&p), true) {
                    Route::Onion if proxy.is_some() => Some((p, Route::Onion)),
                    Route::Direct if net == BNetwork::Regtest => Some((p, Route::Direct)),
                    _ => None,
                })
                .collect();
            if seeds.is_empty() {
                continue;
            }
            if let Some(b) = inner.books.get_mut(&net) {
                b.harvest_started(now);
            }
            inner.save_book(net);
            let proxy = seeds.iter().any(|(_, r)| *r == Route::Onion).then(|| proxy.clone()).flatten();
            out.push(Harvest { network: net, seeds, proxy });
        }
        out
    }

    /// What a seed that answered gossiped: onion v3 peers with bits 0, 3 and 6 seen within 3
    /// days, as learned. The harvest counts as answered.
    pub fn record_harvest(&self, net: BNetwork, seed: &str, gossip: &[Gossip]) -> book::Learning {
        let (learning, events) = {
            let mut inner = self.lock();
            let now = now();
            let Some(book) = inner.books.get_mut(&net) else { return book::Learning::default() };
            book.harvest_answered = true;
            let results: Vec<_> = gossip.iter().map(|g| book.harvested(&g.host, g.port, g.services, u64::from(g.time), seed, now)).collect();
            let learning = Book::tally(results);
            book.prune(now);
            inner.save_book(net);
            (learning, inner.changes(net))
        };
        self.emit(events);
        learning
    }

    /// Whether the proxy is the built-in Tor: only then is tor_module asked, and asking is what
    /// starts it.
    pub fn uses_built_in_tor(&self) -> bool {
        self.lock().store.proxy() == Some(BUILT_IN)
    }

    /// tor_module's latest status. Routes follow its SOCKS port and health shows it. The poller
    /// looks again once Tor is ready, and when the port appears: probes made meanwhile failed.
    pub fn set_tor(&self, view: TorView) {
        let (events, look_again) = {
            let mut inner = self.lock();
            if inner.tor.as_ref() == Some(&view) {
                return;
            }
            let old = inner.tor.replace(view.clone());
            let ready = |t: &Option<TorView>| t.as_ref().is_some_and(|t| t.state == "ready");
            let socks = |t: &Option<TorView>| t.as_ref().and_then(|t| t.socks.clone());
            let look_again = (!ready(&old) && view.state == "ready") || socks(&old) != view.socks;
            let events: Vec<Event> = networks().into_iter().flat_map(|net| inner.changes(net)).collect();
            (events, look_again)
        };
        self.emit(events);
        if look_again {
            self.wake.notify_one();
        }
    }

    /// Notified when sources or the proxy change, so the poller looks at once.
    pub fn wake(&self) -> &Notify {
        &self.wake
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn emit(&self, events: Vec<Event>) {
        for e in events {
            (self.sink)(e);
        }
    }

    /// Set by the health thread while it runs.
    pub fn set_jobs(&self, tx: Option<tokio::sync::mpsc::UnboundedSender<Job>>) {
        *self.jobs.lock().unwrap_or_else(|e| e.into_inner()) = tx;
    }

    fn submit(&self, job: Job) -> Result<(), String> {
        let jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        let tx = jobs.as_ref().ok_or("the health thread is not running")?;
        tx.send(job).map_err(|_| "the health thread has stopped".into())
    }

    /// Applies `change` to a copy of the store, validates and saves it, then swaps it in and
    /// answers from the new state. `change` also sees the networks with a wallet open.
    fn mutate<T>(
        &self,
        poke: bool,
        change: impl FnOnce(&mut Store, &BTreeSet<BNetwork>) -> Result<(T, Vec<Event>), String>,
        answer: impl FnOnce(&Inner, T) -> String,
    ) -> String {
        let (out, events) = {
            let mut inner = self.lock();
            let mut store = inner.store.clone();
            let (t, mut events) = match change(&mut store, &inner.wallet_open).and_then(|r| store.validate().map(|_| r)) {
                Ok(r) => r,
                Err(e) => return reply::err(e),
            };
            if store != inner.store {
                if let Some(p) = &self.path {
                    if let Err(e) = store.save(p) {
                        return reply::err(format!("saving {}: {e}", p.display()));
                    }
                }
                inner.store = store;
                for net in networks() {
                    inner.forget_stale_health(net);
                    events.extend(inner.changes(net));
                }
            }
            (answer(&inner, t), events)
        };
        if poke {
            self.wake.notify_one();
        }
        self.emit(events);
        out
    }

    /// `{ ok, networks }`: mainnet, testnet4, signet, and regtest when regtest.json exists.
    pub fn list_networks(&self) -> String {
        reply::ok(json!({"networks": names(networks())}))
    }

    /// `unconfigured` until anything is set, `configured` once every network has its sources
    /// and the proxy is set (or cleared), `unready` in between.
    pub fn config_status(&self) -> String {
        let inner = self.lock();
        let (configured, unconfigured): (Vec<BNetwork>, Vec<BNetwork>) = networks().into_iter().partition(|n| inner.store.networks.contains_key(n));
        let proxy_set = inner.store.proxy.is_some();
        let state = match (configured.is_empty(), unconfigured.is_empty()) {
            (true, _) if !proxy_set => "unconfigured",
            (_, true) if proxy_set => "configured",
            _ => "unready",
        };
        reply::ok(json!({"state": state, "configured": names(configured), "unconfigured": names(unconfigured),
                         "proxySet": proxy_set, "walletOpen": names(inner.wallet_open.iter().copied())}))
    }

    /// Fills what is absent, field by field: the proxy, and each network's sources (Kyoto on,
    /// one Esplora server for fee rates, every other source off). Never changes what is set.
    pub fn init_defaults(&self) -> String {
        self.mutate(
            true,
            |store, open| {
                let mut applied = Vec::new();
                if store.proxy.is_none() {
                    store.proxy = Some(Some(DEFAULT_PROXY.into()));
                    applied.push("proxy".to_string());
                }
                for net in networks() {
                    if let std::collections::btree_map::Entry::Vacant(e) = store.networks.entry(net) {
                        e.insert(NetConfig::seeded(net));
                        applied.push(format!("{}.sources", net.name()));
                    }
                }
                if !applied.is_empty() && !open.is_empty() {
                    return Err(LOCKED.into());
                }
                Ok((applied, vec![]))
            },
            |_, applied| reply::ok(json!({"applied": applied})),
        )
    }

    pub fn get_sources(&self, network: &str) -> String {
        match parse_net(network) {
            Ok(net) => reply::ok(self.lock().sources_value(net)),
            Err(e) => reply::err(e),
        }
    }

    /// Replaces a network's list (configuring it if needed). Refused while a wallet is open.
    pub fn set_sources(&self, network: &str, list_json: &str) -> String {
        let net = match parse_net(network) {
            Ok(n) => n,
            Err(e) => return reply::err(e),
        };
        self.mutate(
            true,
            |store, open| {
                if open.contains(&net) {
                    return Err(LOCKED.into());
                }
                let cfg = store.networks.entry(net).or_insert_with(|| NetConfig { sources: vec![], ..NetConfig::seeded(net) });
                let list = sources::parse_list(list_json, &cfg.sources)?;
                cfg.replace_sources(list);
                Ok(((), vec![]))
            },
            |inner, ()| reply::ok(inner.sources_value(net)),
        )
    }

    /// Changes one source's `use`, `history` or `tor`. Refused while a wallet is open.
    pub fn set_source(&self, network: &str, source_id: &str, changes_json: &str) -> String {
        let net = match parse_net(network) {
            Ok(n) => n,
            Err(e) => return reply::err(e),
        };
        let changes = match Changes::parse(changes_json) {
            Ok(c) => c,
            Err(e) => return reply::err(e),
        };
        self.mutate(
            true,
            |store, open| {
                if open.contains(&net) {
                    return Err(LOCKED.into());
                }
                let cfg = store.networks.get_mut(&net).ok_or_else(|| not_configured(net))?;
                let s = cfg.sources.iter_mut().find(|s| s.id == source_id).ok_or_else(|| format!("unknown source {source_id}"))?;
                changes.apply(s)?;
                Ok(((), vec![]))
            },
            |inner, ()| reply::ok(inner.sources_value(net)),
        )
    }

    /// The Tor proxy for every source; empty clears it. Refused while any wallet is open.
    pub fn set_proxy(&self, proxy: &str) -> String {
        let p = match proxy::parse_setting(proxy) {
            Ok(p) => p,
            Err(e) => return reply::err(e),
        };
        self.mutate(
            true,
            |store, open| {
                if !open.is_empty() {
                    return Err(LOCKED.into());
                }
                store.proxy = Some(p);
                Ok(((), vec![]))
            },
            |inner, ()| reply::ok(json!({"proxy": inner.store.proxy()})),
        )
    }

    /// The backend says whether a wallet is open on `network`. Kept in memory only.
    pub fn set_wallet_open(&self, network: &str, open: bool) -> String {
        let net = match parse_net(network) {
            Ok(n) => n,
            Err(e) => return reply::err(e),
        };
        let mut inner = self.lock();
        if open {
            inner.wallet_open.insert(net);
        } else {
            inner.wallet_open.remove(&net);
        }
        reply::ok(json!({"network": net.name(), "walletOpen": open}))
    }

    pub fn route_table(&self, network: &str) -> String {
        match parse_net(network) {
            Ok(net) => self.lock().route_table(net),
            Err(e) => reply::err(e),
        }
    }

    /// Marks a source suspect until the backend clears it. `height` is decimal, or empty.
    pub fn report_mismatch(&self, network: &str, source_id: &str, kind: &str, height: &str) -> String {
        let net = match parse_net(network) {
            Ok(n) => n,
            Err(e) => return reply::err(e),
        };
        if kind.trim().is_empty() || kind.chars().count() > 64 || kind.chars().any(char::is_control) {
            return reply::err("kind must be 1 to 64 printable characters");
        }
        let height = match height.trim() {
            "" => None,
            h => match crate::strnum::parse(h) {
                Some(h) => Some(h),
                None => return reply::err("height must be a decimal block height, or empty"),
            },
        };
        self.mutate(
            false,
            |store, _| {
                let cfg = store.networks.get_mut(&net).ok_or_else(|| not_configured(net))?;
                if cfg.source(source_id).is_none() {
                    return Err(format!("unknown source {source_id}"));
                }
                cfg.suspects.insert(source_id.into(), Suspicion { kind: kind.into(), height, at: now() });
                Ok(((), vec![Event::Suspect { network: net, source_id: source_id.into(), kind: kind.into() }]))
            },
            |_, ()| reply::ok(json!({"network": net.name(), "sourceId": source_id, "suspect": true, "kind": kind, "height": height.map(|h| h.to_string())})),
        )
    }

    pub fn clear_suspect(&self, network: &str, source_id: &str) -> String {
        let net = match parse_net(network) {
            Ok(n) => n,
            Err(e) => return reply::err(e),
        };
        self.mutate(
            false,
            |store, _| {
                let cfg = store.networks.get_mut(&net).ok_or_else(|| not_configured(net))?;
                if cfg.source(source_id).is_none() {
                    return Err(format!("unknown source {source_id}"));
                }
                Ok((cfg.suspects.remove(source_id).is_some(), vec![]))
            },
            |_, cleared| reply::ok(json!({"network": net.name(), "sourceId": source_id, "cleared": cleared})),
        )
    }

    /// The curated list with its version and date, the user's own peers, and the usable peers.
    pub fn peer_list(&self, network: &str) -> String {
        let net = match parse_net(network) {
            Ok(n) => n,
            Err(e) => return reply::err(e),
        };
        let inner = self.lock();
        match inner.cfg(net) {
            Some(cfg) => reply::ok(inner.peer_list_value(net, cfg)),
            None => reply::err(not_configured(net)),
        }
    }

    /// The user's own peers, which replace the list; `[]` goes back to it. Refused while a
    /// wallet is open.
    pub fn set_own_peers(&self, network: &str, peers_json: &str) -> String {
        let net = match parse_net(network) {
            Ok(n) => n,
            Err(e) => return reply::err(e),
        };
        let own = match peers::parse_own(net, peers_json) {
            Ok(p) => p,
            Err(e) => return reply::err(e),
        };
        self.mutate(
            true,
            |store, open| {
                if open.contains(&net) {
                    return Err(LOCKED.into());
                }
                store.networks.get_mut(&net).ok_or_else(|| not_configured(net))?.own_peers = own;
                Ok(((), vec![]))
            },
            |inner, ()| inner.cfg(net).map(|c| reply::ok(inner.peer_list_value(net, c))).unwrap_or_else(|| reply::err(not_configured(net))),
        )
    }

    pub fn source_health(&self, network: &str) -> String {
        match parse_net(network) {
            Ok(net) => reply::ok(self.lock().health_value(net)),
            Err(e) => reply::err(e),
        }
    }

    /// Probes one source now (any server, switched on or not), or with an empty id every
    /// enabled server, and answers source_health once they answer or the budget runs out.
    pub fn probe(&self, network: &str, source_id: &str) -> String {
        let net = match parse_net(network) {
            Ok(n) => n,
            Err(e) => return reply::err(e),
        };
        let targets: Vec<Target> = {
            let mut inner = self.lock();
            let Some(cfg) = inner.cfg(net) else { return reply::err(not_configured(net)) };
            let picked: Vec<&Source> = match source_id {
                "" => cfg.sources.iter().filter(|s| s.enabled).collect(),
                id => match cfg.source(id) {
                    Some(s) => vec![s],
                    None => return reply::err(format!("unknown source {id}")),
                },
            };
            let mut targets = Vec::new();
            let mut blocked = Vec::new();
            for s in picked.into_iter().filter(|s| s.kind.is_server()) {
                match inner.blocked(cfg, s) {
                    Some(why) => blocked.push((s.id.clone(), tag(&s.url, s.cert_sha256.as_deref()), why)),
                    None => targets.push(inner.target(net, cfg, s)),
                }
            }
            for (id, t, why) in blocked {
                inner.health.insert((net, id), (t, Health::no_route(why, now())));
            }
            targets
        };
        let mut answered = true;
        if !targets.is_empty() {
            let (done, rx) = mpsc::channel();
            if let Err(e) = self.submit(Job::Probe { targets, done }) {
                return reply::err(e);
            }
            answered = rx.recv_timeout(CALL_BUDGET).is_ok();
        }
        self.flush();
        let mut v = self.lock().health_value(net);
        v["answered"] = json!(answered);
        reply::ok(v)
    }

    /// Installed by the glue: bitcoind_module is an optional dependency.
    pub fn set_local_status(&self, s: Arc<dyn LocalStatus>) {
        *self.local.lock().unwrap_or_else(|e| e.into_inner()) = Some(s);
    }

    /// `{ ok, network, enabled, available, status?, error? }`: whether the local source is on,
    /// and whether bitcoind_module runs a node for `network` now.
    pub fn local_node(&self, network: &str) -> String {
        let net = match parse_net(network) {
            Ok(n) => n,
            Err(e) => return reply::err(e),
        };
        let enabled = self.lock().cfg(net).and_then(|c| c.source(LOCAL_ID)).is_some_and(|s| s.enabled);
        let source = self.local.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let Some(source) = source else {
            return reply::ok(json!({"network": net.name(), "enabled": enabled, "available": false, "error": "bitcoind_module is not installed"}));
        };
        match source.status() {
            Ok(st) => {
                // Core names mainnet "main".
                let on_net = st["network"].as_str().is_some_and(|n| n.eq_ignore_ascii_case(net.name()) || (net == BNetwork::Mainnet && n == "main"));
                let available = st["state"] == "running" && on_net;
                reply::ok(json!({"network": net.name(), "enabled": enabled, "available": available, "status": st}))
            }
            Err(e) => reply::ok(json!({"network": net.name(), "enabled": enabled, "available": false, "error": e})),
        }
    }

    /// An Esplora server's credentials, for the wallet core alone.
    pub fn source_credentials(&self, network: &str, source_id: &str) -> String {
        let net = match parse_net(network) {
            Ok(n) => n,
            Err(e) => return reply::err(e),
        };
        let inner = self.lock();
        let Some(cfg) = inner.cfg(net) else { return reply::err(not_configured(net)) };
        match cfg.source(source_id) {
            Some(s) => {
                let c = s.credentials.as_ref();
                reply::ok(json!({"network": net.name(), "sourceId": source_id, "username": c.map(|c| &c.username), "password": c.map(|c| &c.password)}))
            }
            None => reply::err(format!("unknown source {source_id}")),
        }
    }

    /// The enabled servers to poll, and those that cannot be dialled as configured, with why.
    pub fn poll_plan(&self) -> (Vec<Target>, Vec<(Target, &'static str)>) {
        let inner = self.lock();
        let (mut targets, mut skipped) = (Vec::new(), Vec::new());
        for (net, cfg) in &inner.store.networks {
            for s in cfg.sources.iter().filter(|s| s.enabled && s.kind.is_server()) {
                let t = inner.target(*net, cfg, s);
                match inner.blocked(cfg, s) {
                    Some(why) => skipped.push((t, why)),
                    None => targets.push(t),
                }
            }
        }
        (targets, skipped)
    }

    /// Stores a probe result, unless the source changed or went away meanwhile.
    pub fn record(&self, t: &Target, health: Health) {
        let mut inner = self.lock();
        let measured = tag(&t.url, t.cert_sha256.as_deref());
        let current = inner.cfg(t.network).is_some_and(|c| c.sources.iter().any(|s| s.id == t.id && tag(&s.url, s.cert_sha256.as_deref()) == measured));
        if current {
            inner.health.insert((t.network, t.id.clone()), (measured, health));
        }
    }

    /// Sends the events for everything that changed since the last flush.
    pub fn flush(&self) {
        let events: Vec<Event> = {
            let mut inner = self.lock();
            networks().into_iter().flat_map(|n| inner.changes(n)).collect()
        };
        self.emit(events);
    }
}

#[cfg(test)]
mod tests;
