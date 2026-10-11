//! The module without the SDK: source lists, the proxy, the route table, Kyoto's peers, health
//! and events. The glue gates callers and forwards here; replies are flat JSON strings.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use tokio::sync::Notify;

use crate::addr;
use crate::health::{self, Health, Row, State};
use crate::net::client::{is_lan_host, route_for, Route};
use crate::network::{bad_network, networks, BNetwork};
use crate::peers::{self, PeerList};
use crate::proxy::{self, DEFAULT_PROXY};
use crate::reply;
use crate::sources::{self, Changes, Credentials, Kind, Source, LOCAL_ID};
use crate::store::{NetConfig, Store, Suspicion};

pub const NO_PROXY: &str = "no proxy is set";
pub const LOCKED: &str = "Close the wallet to change these settings.";
pub const SUSPECT: &str = "suspect";
/// How long probe and refresh_peer_list wait on the network, inside the 20 s IPC deadline.
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
}

/// Work the health thread does for a caller that waits on `done`.
pub enum Job {
    Probe { targets: Vec<Target>, done: mpsc::Sender<()> },
    Fetch { url: String, route: Route, proxy: Option<String>, done: mpsc::Sender<Result<Vec<u8>, String>> },
}

/// bitcoind_module's status, when it is loaded. A trait so the pure tests can stand one in.
pub trait LocalStatus: Send + Sync {
    fn status(&self) -> Result<Value, String>;
}

/// Checks a peer list's signature: `peers::verify`, against the keys compiled in.
pub type Verify = fn(&PeerList) -> Result<(), String>;

pub struct Node {
    inner: Mutex<Inner>,
    path: Option<PathBuf>,
    sink: Sink,
    wake: Notify,
    local: Mutex<Option<Arc<dyn LocalStatus>>>,
    jobs: Mutex<Option<tokio::sync::mpsc::UnboundedSender<Job>>>,
    verify: Verify,
}

struct Inner {
    store: Store,
    /// Live health by (network, id), with the url it was measured at.
    health: HashMap<(BNetwork, String), (String, Health)>,
    sent_health: HashMap<BNetwork, String>,
    sent_routes: HashMap<BNetwork, String>,
    /// Networks the backend says a wallet is open on: their settings are locked.
    wallet_open: BTreeSet<BNetwork>,
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

    /// Fail closed: a source whose route goes through Tor has none without the proxy.
    fn blocked(&self, cfg: &NetConfig, s: &Source) -> Option<&'static str> {
        let tor = matches!(Self::route_of(cfg, s), Route::Tor | Route::Onion);
        (tor && self.store.proxy().is_none()).then_some(NO_PROXY)
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
            Some((url, h)) if *url == s.url => Some(h),
            _ => None,
        }
    }

    fn forget_stale_health(&mut self, net: BNetwork) {
        let live: Vec<(String, String)> = self.cfg(net).map(|c| c.sources.iter().map(|s| (s.id.clone(), s.url.clone())).collect()).unwrap_or_default();
        self.health.retain(|(n, id), (url, _)| *n != net || live.iter().any(|(i, u)| i == id && u == url));
    }

    fn target(&self, net: BNetwork, cfg: &NetConfig, s: &Source) -> Target {
        let route = Self::route_of(cfg, s);
        let proxy = matches!(route, Route::Tor | Route::Onion).then(|| self.store.proxy().map(String::from)).flatten();
        Target { network: net, id: s.id.clone(), kind: s.kind, url: s.url.clone(), route, proxy, credentials: s.credentials.clone() }
    }

    /// Every peer Kyoto's route can use; the wallet core picks from these per start.
    fn usable(&self, net: BNetwork, cfg: &NetConfig) -> Vec<String> {
        peers::usable(&cfg.peer_list(net), &cfg.own_peers, cfg.kyoto_tor())
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
            "proxy": self.store.proxy(),
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
                       "route": route(s), "suspect": cfg.suspects.contains_key(&s.id)})
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
            let why = format!("no peer to dial: {}", cfg.peer_list(net).note);
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
        })
    }

    fn peer_list_value(&self, net: BNetwork, cfg: &NetConfig) -> Value {
        let tor = cfg.kyoto_tor();
        json!({
            "network": net.name(),
            "list": cfg.peer_list(net),
            "source": if cfg.peer_list.as_ref().is_some_and(|l| l.version > peers::shipped(net).version) { "fetched" } else { "shipped" },
            "ownPeers": cfg.own_peers,
            "usable": self.usable(net, cfg),
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
    pub fn open(path: Option<PathBuf>, sink: Sink) -> Arc<Self> {
        Self::open_with(path, sink, peers::verify)
    }

    pub fn open_with(path: Option<PathBuf>, sink: Sink, verify: Verify) -> Arc<Self> {
        let mut store = match &path {
            Some(p) => Store::load_or_empty(p),
            None => Store::empty(),
        };
        // A stored list must still check against this build's keys, which may have changed.
        for (net, cfg) in store.networks.iter_mut() {
            if let Some(Err(e)) = cfg.peer_list.as_ref().map(verify) {
                eprintln!("bitcoin_node_module: dropping the stored {} peer list: {e}", net.name());
                cfg.peer_list = None;
            }
        }
        let mut inner = Inner { store, health: HashMap::new(), sent_health: HashMap::new(), sent_routes: HashMap::new(), wallet_open: BTreeSet::new() };
        for net in networks() {
            let _ = inner.changes(net);
        }
        Arc::new(Self { inner: Mutex::new(inner), path, sink, wake: Notify::new(), local: Mutex::new(None), jobs: Mutex::new(None), verify })
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
                changes.apply(s);
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

    /// Fetches a newer list from the current list's refresh URL, through the proxy, and keeps
    /// it only if its signature checks against the keys compiled in.
    pub fn refresh_peer_list(&self, network: &str) -> String {
        let net = match parse_net(network) {
            Ok(n) => n,
            Err(e) => return reply::err(e),
        };
        let (url, route, proxy, current) = {
            let inner = self.lock();
            let Some(cfg) = inner.cfg(net) else { return reply::err(not_configured(net)) };
            let current = cfg.peer_list(net);
            let Some(url) = current.refresh_url.clone() else {
                return reply::err(format!("the {} peer list has no refresh URL yet: the curated list is not published", net.name()));
            };
            let route = route_for(&addr::host_of(&url), true);
            let proxy = inner.store.proxy().map(String::from);
            if route != Route::Direct && proxy.is_none() {
                return reply::err(NO_PROXY);
            }
            (url, route, proxy.filter(|_| route != Route::Direct), current)
        };
        let (done, rx) = mpsc::channel();
        if let Err(e) = self.submit(Job::Fetch { url, route, proxy, done }) {
            return reply::err(e);
        }
        let body = match rx.recv_timeout(CALL_BUDGET) {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => return reply::err(e),
            Err(_) => return reply::err("the peer list did not arrive in time"),
        };
        let fetched = match peers::accept(net, &current, &body, self.verify) {
            Ok(l) => l,
            Err(e) => return reply::err(e),
        };
        self.mutate(
            true,
            |store, _| {
                let cfg = store.networks.get_mut(&net).ok_or_else(|| not_configured(net))?;
                let newer = fetched.version > cfg.peer_list(net).version;
                if newer {
                    cfg.peer_list = Some(fetched);
                }
                Ok((newer, vec![]))
            },
            |inner, updated| match inner.cfg(net) {
                Some(c) => {
                    let mut v = inner.peer_list_value(net, c);
                    v["updated"] = json!(updated);
                    reply::ok(v)
                }
                None => reply::err(not_configured(net)),
            },
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
                    Some(why) => blocked.push((s.id.clone(), s.url.clone(), why)),
                    None => targets.push(inner.target(net, cfg, s)),
                }
            }
            for (id, url, why) in blocked {
                inner.health.insert((net, id), (url, Health::no_route(why, now())));
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
        let current = inner.cfg(t.network).is_some_and(|c| c.sources.iter().any(|s| s.id == t.id && s.url == t.url));
        if current {
            inner.health.insert((t.network, t.id.clone()), (t.url.clone(), health));
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
