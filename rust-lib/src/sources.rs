//! Source lists per network: kinds, validation, the defaults, and the roles each source fills.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::addr;
use crate::net::client::{is_onion, Route};
use crate::network::BNetwork;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Kyoto's Bitcoin peers, from the curated list or the user's own.
    Kyoto,
    Electrum,
    Esplora,
    /// The node bitcoind_module runs in-process (stage 2), over Logos IPC.
    Local,
}

impl Kind {
    pub fn is_server(self) -> bool {
        matches!(self, Kind::Electrum | Kind::Esplora)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Source {
    pub id: String,
    pub kind: Kind,
    pub url: String,
    pub operator: String,
    pub label: String,
    /// Switched on: the wallet may use it for the roles its kind fills.
    #[serde(rename = "use")]
    pub enabled: bool,
    /// Asked about the wallet's addresses. Servers only, and they learn every one.
    pub history: bool,
    /// Reached through Tor. Onion services always are; the user's network never is.
    pub tor: bool,
    /// Esplora's HTTP basic auth. Stored, never read back but by the wallet core.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Credentials>,
}

pub const KYOTO_ID: &str = "kyoto";
pub const KYOTO_URL: &str = "p2p://peer-list";
pub const KYOTO_OPERATOR: &str = "peers";
pub const LOCAL_ID: &str = "local";
/// The route the wallet core reaches the local node by, over Logos IPC.
pub const LOCAL_URL: &str = "logos://bitcoind_module";
pub const LOCAL_OPERATOR: &str = "local";
pub const MAX_SOURCES: usize = 32;

/// The url as stored, and any credentials it carried.
pub fn normalize_url(kind: Kind, url: &str) -> Result<(String, Option<Credentials>), String> {
    match (kind, url.trim()) {
        (Kind::Kyoto, "" | KYOTO_URL) => Ok((KYOTO_URL.into(), None)),
        (Kind::Kyoto, u) => Err(format!("{u}: Kyoto's address is {KYOTO_URL}; its peers come from the peer list")),
        (Kind::Local, "" | LOCAL_URL) => Ok((LOCAL_URL.into(), None)),
        (Kind::Local, u) => Err(format!("{u}: the local node's address is {LOCAL_URL}")),
        (Kind::Electrum, u) => Ok((addr::electrum(u)?, None)),
        (Kind::Esplora, u) => {
            let (url, creds) = addr::esplora(u)?;
            Ok((url, creds.map(|(username, password)| Credentials { username, password })))
        }
    }
}

/// A server's host; empty for Kyoto and the local node.
pub fn host(s: &Source) -> String {
    if s.kind.is_server() { addr::host_of(&s.url) } else { String::new() }
}

fn id_ok(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || "-._".contains(c))
}

fn text_ok(t: &str, max: usize) -> bool {
    t.chars().count() <= max && !t.chars().any(char::is_control)
}

/// The rules every stored list obeys, whoever wrote it.
pub fn validate(list: &[Source]) -> Result<(), String> {
    if list.len() > MAX_SOURCES {
        return Err(format!("a list holds at most {MAX_SOURCES} sources"));
    }
    let (mut ids, mut urls) = (HashSet::new(), HashSet::new());
    for s in list {
        if !id_ok(&s.id) {
            return Err(format!("bad source id {:?}: use letters, digits, '-', '.', '_' (at most 64)", s.id));
        }
        if !ids.insert(s.id.as_str()) {
            return Err(format!("duplicate source id {}", s.id));
        }
        if (s.id == KYOTO_ID) != (s.kind == Kind::Kyoto) || (s.id == LOCAL_ID) != (s.kind == Kind::Local) {
            return Err(format!("{}: the ids {KYOTO_ID} and {LOCAL_ID} belong to Kyoto and the local node", s.id));
        }
        match normalize_url(s.kind, &s.url) {
            Ok((n, None)) if n == s.url => {}
            Ok((n, _)) => return Err(format!("{}: url must be written as {n}", s.id)),
            Err(e) => return Err(format!("{}: {e}", s.id)),
        }
        if !urls.insert(s.url.as_str()) {
            return Err(format!("duplicate source url {}", s.url));
        }
        if s.operator.is_empty() || !text_ok(&s.operator, 64) || s.operator.trim() != s.operator {
            return Err(format!("{}: operator must be 1 to 64 characters", s.id));
        }
        if !text_ok(&s.label, 128) {
            return Err(format!("{}: label is longer than 128 characters", s.id));
        }
        if s.history && !s.kind.is_server() {
            return Err(format!("{}: only Electrum and Esplora servers are asked about addresses", s.id));
        }
        if !s.tor && is_onion(&host(s)) {
            return Err(format!("{}: an onion service is reached through Tor only", s.id));
        }
        if s.tor && s.kind == Kind::Local {
            return Err(format!("{}: the local node is reached over Logos IPC; its own Tor setting is the node app's", s.id));
        }
        if let Some(c) = &s.credentials {
            if s.kind != Kind::Esplora {
                return Err(format!("{}: only Esplora servers take credentials", s.id));
            }
            if c.username.is_empty() || !text_ok(&c.username, 256) || !text_ok(&c.password, 256) || c.username.contains(':') {
                return Err(format!("{}: credentials need a user name without ':', each at most 256 characters", s.id));
            }
        }
    }
    Ok(())
}

pub fn kyoto(on: bool) -> Source {
    Source {
        id: KYOTO_ID.into(),
        kind: Kind::Kyoto,
        url: KYOTO_URL.into(),
        operator: KYOTO_OPERATOR.into(),
        label: "Bitcoin peers (Kyoto)".into(),
        enabled: on,
        history: false,
        tor: true,
        credentials: None,
    }
}

pub fn local(on: bool) -> Source {
    Source {
        id: LOCAL_ID.into(),
        kind: Kind::Local,
        url: LOCAL_URL.into(),
        operator: LOCAL_OPERATOR.into(),
        label: "Your node".into(),
        enabled: on,
        history: false,
        tor: false,
        credentials: None,
    }
}

struct Seed {
    id: &'static str,
    kind: Kind,
    url: &'static str,
    operator: &'static str,
    label: &'static str,
    on: bool,
}

const fn seed(id: &'static str, kind: Kind, url: &'static str, operator: &'static str, label: &'static str, on: bool) -> Seed {
    Seed { id, kind, url, operator, label, on }
}

/// The onion services in the defaults, as each operator publishes them: blockstream.info's and
/// mempool.space's Onion-Location headers, and Blockstream's own server.features (2026-10-10).
pub const VERIFIED_ONIONS: [&str; 2] = [
    "explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion",
    "mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion",
];

// The one enabled server gives fee rates only (history off). The rest stay off until switched on.
const MAINNET: &[Seed] = &[
    seed("blockstream.info-onion", Kind::Esplora, "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/api", "blockstream.info", "Blockstream Esplora (onion)", true),
    seed("blockstream.info", Kind::Esplora, "https://blockstream.info/api", "blockstream.info", "Blockstream Esplora", false),
    seed("mempool.space-onion", Kind::Esplora, "http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion/api", "mempool.space", "mempool.space (onion)", false),
    seed("mempool.space", Kind::Esplora, "https://mempool.space/api", "mempool.space", "mempool.space", false),
    seed("electrum.blockstream.info-onion", Kind::Electrum, "tcp://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion:110", "blockstream.info", "Blockstream Electrum (onion)", false),
    seed("electrum.blockstream.info", Kind::Electrum, "ssl://electrum.blockstream.info:50002", "blockstream.info", "Blockstream Electrum", false),
];

const TESTNET4: &[Seed] = &[
    seed("mempool.space", Kind::Esplora, "https://mempool.space/testnet4/api", "mempool.space", "mempool.space", true),
    seed("mempool.space-onion", Kind::Esplora, "http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion/testnet4/api", "mempool.space", "mempool.space (onion)", false),
];

const SIGNET: &[Seed] = &[
    seed("blockstream.info-onion", Kind::Esplora, "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/signet/api", "blockstream.info", "Blockstream Esplora (onion)", true),
    seed("blockstream.info", Kind::Esplora, "https://blockstream.info/signet/api", "blockstream.info", "Blockstream Esplora", false),
    seed("mempool.space-onion", Kind::Esplora, "http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion/signet/api", "mempool.space", "mempool.space (onion)", false),
    seed("mempool.space", Kind::Esplora, "https://mempool.space/signet/api", "mempool.space", "mempool.space", false),
];

/// Kyoto on, one Esplora server for fee rates, every other source off. Regtest has no public
/// servers: its sources are the user's own.
pub fn defaults(net: BNetwork) -> Vec<Source> {
    let seeds: &[Seed] = match net {
        BNetwork::Mainnet => MAINNET,
        BNetwork::Testnet4 => TESTNET4,
        BNetwork::Signet => SIGNET,
        BNetwork::Regtest => &[],
    };
    let mut out = vec![kyoto(true)];
    out.extend(seeds.iter().map(|s| Source {
        id: s.id.into(),
        kind: s.kind,
        url: s.url.into(),
        operator: s.operator.into(),
        label: s.label.into(),
        enabled: s.on,
        history: false,
        tor: true,
        credentials: None,
    }));
    out.push(local(false));
    out
}

/// One entry of set_sources' list. get_sources' computed fields are accepted for round trips.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceInput {
    id: String,
    kind: Kind,
    #[serde(default)]
    url: String,
    #[serde(default)]
    operator: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(rename = "use", default)]
    enabled: Option<bool>,
    #[serde(default)]
    history: Option<bool>,
    #[serde(default)]
    tor: Option<bool>,
    /// Absent keeps the stored ones; null clears them.
    #[serde(default, deserialize_with = "crate::strnum::double_option")]
    credentials: Option<Option<Credentials>>,
    #[serde(default)]
    #[allow(dead_code)]
    lan: Option<bool>,
    #[serde(default)]
    #[allow(dead_code)]
    has_credentials: Option<bool>,
    #[serde(default)]
    #[allow(dead_code)]
    route: Option<Route>,
    #[serde(default)]
    #[allow(dead_code)]
    suspect: Option<bool>,
}

fn given(t: Option<String>) -> Option<String> {
    t.map(|t| t.trim().to_string()).filter(|t| !t.is_empty())
}

/// Parses set_sources' list. An entry left without credentials keeps those stored for the
/// same id at the same url, since get_sources never returns them.
pub fn parse_list(json: &str, current: &[Source]) -> Result<Vec<Source>, String> {
    let items: Vec<serde_json::Value> = serde_json::from_str(json).map_err(|e| format!("source list: {e}"))?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if !item.is_object() {
            return Err("source list: every entry must be a JSON object".into());
        }
        let s: SourceInput = serde_json::from_value(item).map_err(|e| format!("source list: {e}"))?;
        let (url, in_url) = normalize_url(s.kind, &s.url).map_err(|e| format!("{}: {e}", s.id))?;
        let host = if s.kind.is_server() { addr::host_of(&url) } else { String::new() };
        let credentials = match (in_url, s.credentials) {
            (Some(_), Some(_)) => return Err(format!("{}: credentials given twice, in the url and apart", s.id)),
            (Some(c), None) | (None, Some(Some(c))) => Some(c),
            (None, Some(None)) => None,
            (None, None) => current.iter().find(|c| c.id == s.id && c.url == url && c.kind == s.kind).and_then(|c| c.credentials.clone()),
        };
        let operator = given(s.operator).unwrap_or_else(|| match s.kind {
            Kind::Kyoto => KYOTO_OPERATOR.into(),
            Kind::Local => LOCAL_OPERATOR.into(),
            _ => addr::site(&host),
        });
        let label = given(s.label).unwrap_or_else(|| match s.kind {
            Kind::Kyoto => kyoto(true).label,
            Kind::Local => local(true).label,
            _ => host.clone(),
        });
        out.push(Source {
            id: s.id,
            kind: s.kind,
            url,
            operator,
            label,
            enabled: s.enabled.unwrap_or(true),
            history: s.history.unwrap_or(false),
            tor: s.tor.unwrap_or(s.kind != Kind::Local),
            credentials,
        });
    }
    validate(&out)?;
    Ok(out)
}

/// set_source's change to one source; every field optional.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Changes {
    #[serde(rename = "use", default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub history: Option<bool>,
    #[serde(default)]
    pub tor: Option<bool>,
}

impl Changes {
    pub fn parse(json: &str) -> Result<Self, String> {
        let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("changes: {e}"))?;
        if !v.is_object() {
            return Err("changes must be a JSON object, such as {\"use\":true}".into());
        }
        serde_json::from_value(v).map_err(|e| format!("changes: {e}"))
    }

    pub fn apply(&self, s: &mut Source) {
        if let Some(v) = self.enabled {
            s.enabled = v;
        }
        if let Some(v) = self.history {
            s.history = v;
        }
        if let Some(v) = self.tor {
            s.tor = v;
        }
    }
}

/// One route of the route table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteEntry {
    pub id: String,
    pub kind: Kind,
    pub url: String,
    pub operator: String,
    pub route: Route,
    /// The wallet core fetches them with source_credentials.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub credentials: bool,
}

/// The routes per role, each in failover order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Roles {
    pub chain: Vec<RouteEntry>,
    pub history: Vec<RouteEntry>,
    pub pending: Vec<RouteEntry>,
    pub fees: Vec<RouteEntry>,
    pub broadcast: Vec<RouteEntry>,
    pub check: Vec<RouteEntry>,
    pub cross_check: bool,
}

/// Distinct operators: Kyoto's many peers count as one, as does the user's local node.
fn operator_key(e: &RouteEntry) -> String {
    match e.kind {
        Kind::Kyoto => "kyoto:".into(),
        Kind::Local => "local:".into(),
        _ => e.operator.to_ascii_lowercase(),
    }
}

/// The roles over the enabled sources `usable` admits, in failover order (README, Routes). The
/// chain follows what is switched on, so an unreachable Kyoto never hands it to a server.
pub fn roles(list: &[Source], route: impl Fn(&Source) -> Route, usable: impl Fn(&Source) -> bool) -> Roles {
    let on = |s: &Source| s.enabled && usable(s);
    let entry = |s: &Source| RouteEntry {
        id: s.id.clone(),
        kind: s.kind,
        url: s.url.clone(),
        operator: s.operator.clone(),
        route: route(s),
        credentials: s.credentials.is_some(),
    };
    let pick = |keep: &dyn Fn(&Source) -> bool| -> Vec<RouteEntry> { list.iter().filter(|s| on(s) && keep(s)).map(&entry).collect() };
    let authority = list.iter().any(|s| s.enabled && matches!(s.kind, Kind::Local | Kind::Kyoto));
    let (local, kyoto) = (pick(&|s| s.kind == Kind::Local), pick(&|s| s.kind == Kind::Kyoto));
    let servers = pick(&|s| s.kind.is_server());
    let history_servers = pick(&|s| s.kind.is_server() && s.history);
    let cat = |parts: &[&Vec<RouteEntry>]| parts.iter().flat_map(|p| p.iter().cloned()).collect::<Vec<_>>();
    let chain = if authority { cat(&[&local, &kyoto]) } else { pick(&|s| s.kind == Kind::Electrum) };
    let broadcast = if authority { cat(&[&local, &kyoto]) } else { history_servers.clone() };
    let operators: HashSet<String> = chain.iter().chain(servers.iter()).map(operator_key).collect();
    Roles {
        history: cat(&[&local, &kyoto, &history_servers]),
        pending: cat(&[&local, &history_servers]),
        fees: cat(&[&local, &servers, &kyoto]),
        check: servers.clone(),
        cross_check: operators.len() >= 2,
        chain,
        broadcast,
    }
}

/// A source in exposes or withoutTor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Named {
    pub id: String,
    pub url: String,
    pub operator: String,
    pub lan: bool,
}

fn named(s: &Source, lan: bool) -> Named {
    Named { id: s.id.clone(), url: s.url.clone(), operator: s.operator.clone(), lan }
}

/// The enabled sources that learn the wallet's addresses: every server with history on, in
/// failover order, since each one asked after a failure learns them too.
pub fn exposes(list: &[Source], lan: impl Fn(&Source) -> bool) -> Vec<Named> {
    list.iter().filter(|s| s.enabled && s.history && s.kind.is_server()).map(|s| named(s, lan(s))).collect()
}

/// The enabled sources outside the user's network reached without Tor, by the user's choice:
/// they see this computer's IP address.
pub fn without_tor(list: &[Source], route: impl Fn(&Source) -> Route, lan: impl Fn(&Source) -> bool) -> Vec<Named> {
    list.iter()
        .filter(|s| s.enabled && s.kind != Kind::Local && route(s) == Route::Direct && !lan(s))
        .map(|s| named(s, false))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::client::{is_lan_host, route_for};

    fn server_route(s: &Source) -> Route {
        match s.kind {
            Kind::Local => Route::Direct,
            Kind::Kyoto => Route::Onion,
            _ => route_for(&host(s), s.tor),
        }
    }

    fn lan(s: &Source) -> bool {
        s.kind == Kind::Local || is_lan_host(&host(s))
    }

    fn ids(r: &[RouteEntry]) -> Vec<&str> {
        r.iter().map(|e| e.id.as_str()).collect()
    }

    fn all(_: &Source) -> bool {
        true
    }

    #[test]
    fn defaults_are_valid_and_private() {
        for net in [BNetwork::Mainnet, BNetwork::Testnet4, BNetwork::Signet, BNetwork::Regtest] {
            let list = defaults(net);
            validate(&list).unwrap();
            let on: Vec<&Source> = list.iter().filter(|s| s.enabled).collect();
            assert_eq!(on[0].id, KYOTO_ID, "{net:?}");
            assert!(list.iter().all(|s| !s.history && (s.tor || s.kind == Kind::Local)), "{net:?}");
            let fee: Vec<&&Source> = on.iter().filter(|s| s.kind.is_server()).collect();
            assert_eq!(fee.len(), usize::from(net != BNetwork::Regtest), "{net:?}: one fee server");
            assert!(fee.iter().all(|s| s.kind == Kind::Esplora));
            assert_eq!(list.last().unwrap().id, LOCAL_ID);
            assert!(!list.last().unwrap().enabled);
            let r = roles(&list, server_route, all);
            assert!(r.history.iter().all(|e| !e.kind.is_server()), "{net:?}: no server is asked about addresses");
            assert!(exposes(&list, lan).is_empty() && without_tor(&list, server_route, lan).is_empty());
        }
        let main = defaults(BNetwork::Mainnet);
        let fee = main.iter().find(|s| s.enabled && s.kind.is_server()).unwrap();
        assert!(is_onion(&host(fee)) && fee.url.ends_with("/api"));
        let r = roles(&main, server_route, all);
        assert_eq!((ids(&r.chain), ids(&r.fees), ids(&r.check)), (vec!["kyoto"], vec![fee.id.as_str(), "kyoto"], vec![fee.id.as_str()]));
        assert_eq!(ids(&r.broadcast), ["kyoto"]);
        assert!(r.cross_check, "Kyoto's peers and the fee server's operator");
    }

    #[test]
    fn every_default_onion_is_one_an_operator_published() {
        for net in [BNetwork::Mainnet, BNetwork::Testnet4, BNetwork::Signet] {
            for s in defaults(net).iter().filter(|s| s.kind.is_server()) {
                let h = host(s);
                assert!(!h.ends_with(".onion") || VERIFIED_ONIONS.contains(&h.as_str()), "{net:?} {}", s.url);
            }
        }
    }

    #[test]
    fn the_chain_follows_what_is_switched_on() {
        let mut list = defaults(BNetwork::Mainnet);
        for s in list.iter_mut() {
            s.enabled = true;
        }
        let r = roles(&list, server_route, all);
        assert_eq!(ids(&r.chain), ["local", "kyoto"]);
        assert_eq!(ids(&r.broadcast), ["local", "kyoto"]);
        assert_eq!(ids(&r.pending), ["local"], "no server has history on");
        // Kyoto unreachable: the chain stays empty rather than move to a server.
        let r = roles(&list, server_route, |s| s.kind != Kind::Kyoto && s.kind != Kind::Local);
        assert!(r.chain.is_empty() && r.broadcast.is_empty());
        // Kyoto and the node off: every Electrum server, and history servers broadcast.
        list.iter_mut().filter(|s| !s.kind.is_server()).for_each(|s| s.enabled = false);
        list.iter_mut().filter(|s| s.id == "blockstream.info").for_each(|s| s.history = true);
        let r = roles(&list, server_route, all);
        assert_eq!(ids(&r.chain), ["electrum.blockstream.info-onion", "electrum.blockstream.info"]);
        assert_eq!((ids(&r.history), ids(&r.broadcast)), (vec!["blockstream.info"], vec!["blockstream.info"]));
        assert_eq!(r.check.len(), 6);
        assert!(r.cross_check, "blockstream.info and mempool.space");
        // One operator alone: no cross-check.
        list.retain(|s| s.operator == "blockstream.info");
        assert!(!roles(&list, server_route, all).cross_check);
    }

    #[test]
    fn exposes_and_without_tor() {
        let mut list = defaults(BNetwork::Signet);
        let home = r#"[{"id":"home","kind":"electrum","url":"192.168.1.20","history":true}]"#;
        list.extend(parse_list(home, &[]).unwrap());
        for s in list.iter_mut().filter(|s| s.id == "blockstream.info") {
            (s.enabled, s.history, s.tor) = (true, true, false);
        }
        let ex = exposes(&list, lan);
        assert_eq!(ex.iter().map(|n| (n.id.as_str(), n.lan)).collect::<Vec<_>>(), [("blockstream.info", false), ("home", true)]);
        let direct = without_tor(&list, server_route, lan);
        assert_eq!(direct.iter().map(|n| n.id.as_str()).collect::<Vec<_>>(), ["blockstream.info"], "the LAN server is not listed");
    }

    #[test]
    fn parses_and_validates_lists() {
        let list = parse_list(
            r#"[{"id":"kyoto","kind":"kyoto"},
                {"id":"e1","kind":"electrum","url":"Electrum.Example.COM"},
                {"id":"x","kind":"esplora","url":"https://u:p@esplora.example/api","use":false,"label":" Mine "},
                {"id":"local","kind":"local","lan":true,"route":"direct","hasCredentials":false}]"#,
            &[],
        )
        .unwrap();
        assert_eq!(list[0], kyoto(true));
        assert_eq!((list[1].url.as_str(), list[1].operator.as_str(), list[1].label.as_str()), ("ssl://electrum.example.com:50002", "example.com", "electrum.example.com"));
        assert_eq!((list[2].url.as_str(), list[2].label.as_str(), list[2].enabled), ("https://esplora.example/api", "Mine", false));
        assert_eq!(list[2].credentials, Some(Credentials { username: "u".into(), password: "p".into() }));
        assert_eq!(list[3], local(true));

        // Credentials survive a round trip that leaves them out, and go with null or a new url.
        let back = r#"[{"id":"x","kind":"esplora","url":"https://esplora.example/api"}]"#;
        assert!(parse_list(back, &list).unwrap()[0].credentials.is_some());
        let cleared = r#"[{"id":"x","kind":"esplora","url":"https://esplora.example/api","credentials":null}]"#;
        assert!(parse_list(cleared, &list).unwrap()[0].credentials.is_none());
        let moved = r#"[{"id":"x","kind":"esplora","url":"https://other.example/api"}]"#;
        assert!(parse_list(moved, &list).unwrap()[0].credentials.is_none());
        let apart = r#"[{"id":"x","kind":"esplora","url":"https://esplora.example/api","credentials":{"username":"a","password":"b"}}]"#;
        assert_eq!(parse_list(apart, &[]).unwrap()[0].credentials.as_ref().unwrap().username, "a");

        let onion = format!("{}.onion", "a2".repeat(28));
        for (bad, why) in [
            (r#"[{"id":"a","kind":"electrum","url":"tcp://electrum.example:50001"}]"#.to_string(), "plain tcp"),
            (r#"[{"id":"a","kind":"esplora","url":"http://esplora.example"}]"#.into(), "plain http"),
            (r#"[{"id":"a","kind":"electrum","url":"x.example"},{"id":"a","kind":"electrum","url":"y.example"}]"#.into(), "duplicate source id"),
            (r#"[{"id":"a","kind":"electrum","url":"x.example"},{"id":"b","kind":"electrum","url":"ssl://x.example:50002"}]"#.into(), "duplicate source url"),
            (r#"[{"id":"kyoto","kind":"electrum","url":"x.example"}]"#.into(), "belong to Kyoto"),
            (r#"[{"id":"peers","kind":"kyoto"}]"#.into(), "belong to Kyoto"),
            (r#"[{"id":"kyoto","kind":"kyoto","url":"192.168.1.20:8333"}]"#.into(), "peer list"),
            (r#"[{"id":"kyoto","kind":"kyoto","history":true}]"#.into(), "asked about addresses"),
            (r#"[{"id":"local","kind":"local","tor":true}]"#.into(), "Logos IPC"),
            (format!(r#"[{{"id":"o","kind":"esplora","url":"http://{onion}/api","tor":false}}]"#), "through Tor only"),
            (r#"[{"id":"a","kind":"electrum","url":"x.example","credentials":{"username":"u","password":"p"}}]"#.into(), "only Esplora"),
            (r#"[{"id":"a","kind":"esplora","url":"https://u:p@x.example","credentials":{"username":"u","password":"p"}}]"#.into(), "given twice"),
            (r#"[{"id":"a b","kind":"electrum","url":"x.example"}]"#.into(), "bad source id"),
            (r#"[{"id":"a","kind":"electrum","url":"x.example","enable":true}]"#.into(), "source list"),
            (r#"[{"id":"a","kind":"nostr","url":"x.example"}]"#.into(), "source list"),
            (r#"[["a"]]"#.into(), "JSON object"),
            (r#"{"sources":[]}"#.into(), "source list"),
        ] {
            let e = parse_list(&bad, &[]).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
        assert!(parse_list("[]", &[]).unwrap().is_empty(), "nothing switched on is allowed");
    }

    #[test]
    fn changes() {
        let mut s = defaults(BNetwork::Mainnet)[2].clone();
        Changes::parse(r#"{"use":true,"history":true}"#).unwrap().apply(&mut s);
        assert!(s.enabled && s.history && s.tor);
        Changes::parse(r#"{"tor":false}"#).unwrap().apply(&mut s);
        assert!(!s.tor && s.enabled);
        for bad in [r#"{"enabled":true}"#, "[]", r#"{"use":"yes"}"#] {
            assert!(Changes::parse(bad).is_err(), "{bad}");
        }
    }
}
