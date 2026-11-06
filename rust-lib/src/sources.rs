//! Source lists per network: kinds, validation, the defaults, and the roles each source fills.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::addr;
use crate::net::client::{is_onion, route_for, Route};
use crate::network::BNetwork;
use crate::reply::INVALID;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Kyoto's Bitcoin peers, from the curated list or the user's own.
    Kyoto,
    Electrum,
    /// Only in files from before store version 4, which loading migrates; refused everywhere else.
    Esplora,
    Rpc,
    /// The node bitcoind_module runs in-process (stage 2), over Logos IPC.
    Local,
}

impl Kind {
    pub fn is_server(self) -> bool {
        matches!(self, Kind::Electrum | Kind::Rpc)
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
    /// RPC's HTTP basic auth. Stored, never read back but by the wallet core.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Credentials>,
    /// The SHA-256 of the server's end-entity certificate, 64 lowercase hex characters, pinned
    /// in place of the CAs and the name check (TLS servers only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_sha256: Option<String>,
}

pub const KYOTO_ID: &str = "kyoto";
pub const KYOTO_URL: &str = "p2p://peer-list";
pub const KYOTO_OPERATOR: &str = "peers";
pub const LOCAL_ID: &str = "local";
/// The route the wallet core reaches the local node by, over Logos IPC.
pub const LOCAL_URL: &str = "logos://bitcoind_module";
pub const LOCAL_OPERATOR: &str = "local";
pub const MAX_SOURCES: usize = 32;
pub const ESPLORA_GONE: &str = "Esplora servers are no longer supported; use an Electrum server";

/// The url as stored, and any credentials it carried.
pub fn normalize_url(kind: Kind, url: &str) -> Result<(String, Option<Credentials>), String> {
    match (kind, url.trim()) {
        (Kind::Kyoto, "" | KYOTO_URL) => Ok((KYOTO_URL.into(), None)),
        (Kind::Kyoto, u) => Err(format!("{u}: Kyoto's address is {KYOTO_URL}; its peers come from the peer list")),
        (Kind::Local, "" | LOCAL_URL) => Ok((LOCAL_URL.into(), None)),
        (Kind::Local, u) => Err(format!("{u}: the local node's address is {LOCAL_URL}")),
        (Kind::Electrum, u) => Ok((addr::electrum(u)?, None)),
        (Kind::Esplora, _) => Err(format!("{INVALID}{ESPLORA_GONE}")),
        (Kind::Rpc, u) => {
            let (url, creds) = addr::rpc(u)?;
            Ok((url, creds.map(|(username, password)| Credentials { username, password })))
        }
    }
}

/// A server's host; empty for Kyoto and the local node.
pub fn host(s: &Source) -> String {
    if s.kind.is_server() { addr::host_of(&s.url) } else { String::new() }
}

/// A server reached over TLS, the only kind a certificate pin applies to.
pub fn tls_server(kind: Kind, url: &str) -> bool {
    (kind == Kind::Electrum && url.starts_with("ssl://")) || (kind == Kind::Rpc && url.starts_with("https://"))
}

/// A pin as stored: 64 lowercase hex characters. Colons are allowed in, as the wallet core reads it.
pub fn normalize_pin(text: &str) -> Result<String, String> {
    let digits: String = text.trim().chars().filter(|c| *c != ':').collect::<String>().to_ascii_lowercase();
    if digits.len() == 64 && digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(digits)
    } else {
        Err(format!("{INVALID}certSha256 must be the certificate's SHA-256: 64 hex characters"))
    }
}

pub fn pin_bytes(pin: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(pin, &mut out).ok().map(|_| out)
}

fn pin_refused(id: &str) -> String {
    format!("{INVALID}{id}: certSha256 is for a server reached over TLS (ssl:// or https://)")
}

/// `id: why`, keeping the invalid-parameters prefix in front for the caller to see.
fn about(id: &str, why: &str) -> String {
    match why.strip_prefix(INVALID) {
        Some(rest) => format!("{INVALID}{id}: {rest}"),
        None => format!("{id}: {why}"),
    }
}

/// A server this install's defaults do not carry: the person added it. The wallet core lets
/// only such a server on the person's network speak plain text.
pub fn user_added(s: &Source) -> bool {
    s.kind.is_server() && ![MAINNET, TESTNET4, SIGNET].iter().any(|seeds| seeds.iter().any(|d| d.id == s.id && d.kind == s.kind && d.url == s.url))
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
    if list.iter().filter(|s| s.enabled && matches!(s.kind, Kind::Local | Kind::Rpc)).count() > 1 {
        return Err("Enable only one node at a time: the local node or one Bitcoin Core RPC endpoint".into());
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
        if s.history && s.kind != Kind::Electrum {
            return Err(format!("{}: only Electrum servers are asked about addresses", s.id));
        }
        if !s.tor && is_onion(&host(s)) {
            return Err(format!("{}: an onion service is reached through Tor only", s.id));
        }
        if s.tor && s.kind == Kind::Local {
            return Err(format!("{}: the local node is reached over Logos IPC; its own Tor setting is the node app's", s.id));
        }
        if let Some(p) = &s.cert_sha256 {
            if normalize_pin(p).as_deref() != Ok(p.as_str()) {
                return Err(format!("{}: certSha256 must be stored as 64 lowercase hex characters", s.id));
            }
            if !tls_server(s.kind, &s.url) {
                return Err(pin_refused(&s.id));
            }
        }
        if let Some(c) = &s.credentials {
            if s.kind != Kind::Rpc {
                return Err(format!("{}: only RPC servers take credentials", s.id));
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
        cert_sha256: None,
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
        cert_sha256: None,
    }
}

struct Seed {
    id: &'static str,
    kind: Kind,
    url: &'static str,
    operator: &'static str,
    label: &'static str,
    on: bool,
    pin: Option<&'static str>,
}

const fn seed(id: &'static str, kind: Kind, url: &'static str, operator: &'static str, label: &'static str, on: bool) -> Seed {
    Seed { id, kind, url, operator, label, on, pin: None }
}

impl Seed {
    /// A self-signed server, shipped with its certificate's SHA-256.
    const fn pinned(self, pin: &'static str) -> Seed {
        Seed { pin: Some(pin), ..self }
    }
}

/// The onion services in the defaults, from where each is published: blockstream.info's
/// Onion-Location header and Blockstream's own server.features (2026-10-10), and for testnet4
/// Electrum's own server list, electrum/chains/testnet4/servers.json (2026-10-11).
pub const VERIFIED_ONIONS: [&str; 2] = [
    "explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion",
    "gsw6sn27quwf6u3swgra6o7lrp5qau6kt3ymuyoxgkth6wntzm2bjwyd.onion",
];

// The one enabled server gives fee rates only (history off); it answered 7 of 8 probes over Tor
// (2026-11-03), missing only a 2,016-header batch, which a fee server is never asked for.
const MAINNET: &[Seed] = &[
    seed("electrum.blockstream.info-onion", Kind::Electrum, "tcp://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion:110", "blockstream.info", "Blockstream Electrum (onion)", true),
    seed("electrum.blockstream.info", Kind::Electrum, "ssl://electrum.blockstream.info:50002", "blockstream.info", "Blockstream Electrum", false),
];

// Electrum servers that answered 3 of 3 probes (2026-10-11), each on a fresh circuit, with a
// certificate the web PKI trusts or over an onion service.
const TESTNET4: &[Seed] = &[
    seed("electrum-testnet4-onion", Kind::Electrum, "tcp://gsw6sn27quwf6u3swgra6o7lrp5qau6kt3ymuyoxgkth6wntzm2bjwyd.onion:52001", "gsw6sn27quwf6u3swgra6o7lrp5qau6kt3ymuyoxgkth6wntzm2bjwyd.onion", "Electrum testnet4 (onion)", true),
    seed("bitcoin.stagemole.eu", Kind::Electrum, "ssl://bitcoin.stagemole.eu:5010", "stagemole.eu", "stagemole.eu Electrum", false),
    seed("blackie.c3-soft.com", Kind::Electrum, "ssl://blackie.c3-soft.com:57010", "c3-soft.com", "c3-soft.com Electrum", false),
];

// Self-signed ElectrumX servers that answered 8 of 8 probes over Tor with these pins (2026-11-03).
// Defaults on are web-PKI-trusted or onion services; these keep that rule by shipping off.
const SIGNET: &[Seed] = &[
    seed("electrum.emzy.de", Kind::Electrum, "ssl://electrum.emzy.de:53002", "emzy.de", "emzy.de Electrum", false)
        .pinned("ae52a2307cb9878024b61dbf948d3aac8fea705dfefe562cc62191b6995c48cc"),
    seed("signet-electrumx.wakiyamap.dev", Kind::Electrum, "ssl://signet-electrumx.wakiyamap.dev:50002", "wakiyamap.dev", "wakiyamap.dev Electrum", false)
        .pinned("aeef7989269830a269c15c841e68bee776e1a15b208804418762471cd1ccce85"),
];

/// Kyoto on, one Electrum server for fee rates, every other source off. Signet runs Kyoto alone,
/// its fee the relay floor. Regtest has no public servers: its sources are the user's own.
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
        cert_sha256: s.pin.map(String::from),
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
    /// Absent keeps the stored pin; null or "" clears it.
    #[serde(default, deserialize_with = "crate::strnum::double_option")]
    cert_sha256: Option<Option<String>>,
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
        let (url, in_url) = normalize_url(s.kind, &s.url).map_err(|e| about(&s.id, &e))?;
        let host = if s.kind.is_server() { addr::host_of(&url) } else { String::new() };
        let credentials = match (in_url, s.credentials) {
            (Some(_), Some(_)) => return Err(format!("{}: credentials given twice, in the url and apart", s.id)),
            (Some(c), None) | (None, Some(Some(c))) => Some(c),
            (None, Some(None)) => None,
            (None, None) => current.iter().find(|c| c.id == s.id && c.url == url && c.kind == s.kind).and_then(|c| c.credentials.clone()),
        };
        let cert_sha256 = match s.cert_sha256 {
            None => current.iter().find(|c| c.id == s.id && c.url == url && c.kind == s.kind).and_then(|c| c.cert_sha256.clone()),
            Some(None) => None,
            Some(Some(t)) if t.trim().is_empty() => None,
            Some(Some(t)) => Some(normalize_pin(&t).map_err(|e| about(&s.id, &e))?),
        };
        if cert_sha256.is_some() && !tls_server(s.kind, &url) {
            return Err(pin_refused(&s.id));
        }
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
            cert_sha256,
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
    /// A pin to set; null or "" clears it.
    #[serde(default, deserialize_with = "crate::strnum::double_option")]
    pub cert_sha256: Option<Option<String>>,
}

impl Changes {
    pub fn parse(json: &str) -> Result<Self, String> {
        let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("changes: {e}"))?;
        if !v.is_object() {
            return Err("changes must be a JSON object, such as {\"use\":true}".into());
        }
        serde_json::from_value(v).map_err(|e| format!("changes: {e}"))
    }

    pub fn apply(&self, s: &mut Source) -> Result<(), String> {
        if let Some(pin) = &self.cert_sha256 {
            let pin = match pin.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
                Some(t) => Some(normalize_pin(t).map_err(|e| about(&s.id, &e))?),
                None => None,
            };
            if pin.is_some() && !tls_server(s.kind, &s.url) {
                return Err(pin_refused(&s.id));
            }
            s.cert_sha256 = pin;
        }
        if let Some(v) = self.enabled {
            s.enabled = v;
        }
        if let Some(v) = self.history {
            s.history = v;
        }
        if let Some(v) = self.tor {
            s.tor = v;
        }
        Ok(())
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
    /// The pinned certificate's SHA-256, when the source has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_sha256: Option<String>,
    /// The person added this server (it is not one of the defaults).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub user_added: bool,
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
}

/// Your node, in Logos or at an address.
pub fn own_node(s: &Source) -> bool {
    matches!(s.kind, Kind::Local | Kind::Rpc)
}

pub fn own_node_on(list: &[Source]) -> bool {
    list.iter().any(|s| s.enabled && own_node(s))
}

/// Switched on and asked: while your node is on it is asked alone, and the other switches wait.
pub fn in_use(list: &[Source], s: &Source) -> bool {
    s.enabled && (own_node(s) || !own_node_on(list))
}

/// The roles over the sources in use that `usable` admits, in failover order (README, Routes).
/// The chain follows what is switched on, so an unreachable Kyoto never hands it to a server.
pub fn roles(list: &[Source], route: impl Fn(&Source) -> Route, usable: impl Fn(&Source) -> bool) -> Roles {
    let on = |s: &Source| in_use(list, s) && usable(s);
    let entry = |s: &Source| route_entry(s, route(s));
    let pick = |keep: &dyn Fn(&Source) -> bool| -> Vec<RouteEntry> { list.iter().filter(|s| on(s) && keep(s)).map(&entry).collect() };
    let authority = list.iter().any(|s| s.enabled && matches!(s.kind, Kind::Local | Kind::Rpc | Kind::Kyoto));
    let (node, kyoto) = (pick(&|s| matches!(s.kind, Kind::Local | Kind::Rpc)), pick(&|s| s.kind == Kind::Kyoto));
    let servers = pick(&|s| s.kind == Kind::Electrum);
    let history_servers = pick(&|s| s.kind == Kind::Electrum && s.history);
    let cat = |parts: &[&Vec<RouteEntry>]| parts.iter().flat_map(|p| p.iter().cloned()).collect::<Vec<_>>();
    let chain = if authority { cat(&[&node, &kyoto]) } else { servers.clone() };
    let broadcast = if authority { cat(&[&node, &kyoto]) } else { history_servers.clone() };
    Roles {
        history: cat(&[&node, &kyoto, &history_servers]),
        pending: cat(&[&node, &history_servers]),
        fees: cat(&[&node, &servers, &kyoto]),
        check: servers,
        chain,
        broadcast,
    }
}

pub fn route_entry(s: &Source, route: Route) -> RouteEntry {
    RouteEntry {
        id: s.id.clone(),
        kind: s.kind,
        url: s.url.clone(),
        operator: s.operator.clone(),
        route,
        credentials: s.credentials.is_some(),
        cert_sha256: s.cert_sha256.clone(),
        user_added: user_added(s),
    }
}

/// Where payments go with your node on and public servers picked: the Electrum servers switched
/// on, else the network's shipped onion server; over Tor whatever Use Tor for says, one on your
/// own network directly. Empty when there is none, and then your node sends them.
pub fn public_senders(net: BNetwork, list: &[Source], usable: impl Fn(&Source) -> bool) -> Vec<RouteEntry> {
    let entry = |s: &Source| route_entry(s, route_for(&host(s), true));
    let on: Vec<RouteEntry> = list.iter().filter(|s| s.enabled && s.kind == Kind::Electrum && usable(s)).map(entry).collect();
    if !on.is_empty() {
        return on;
    }
    defaults(net).iter().filter(|s| s.enabled && s.kind == Kind::Electrum && is_onion(&host(s)) && usable(s)).map(entry).collect()
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

/// The sources in use that learn the wallet's addresses: every server with history on, in
/// failover order, since each one asked after a failure learns them too.
pub fn exposes(list: &[Source], lan: impl Fn(&Source) -> bool) -> Vec<Named> {
    list.iter().filter(|s| in_use(list, s) && s.history && s.kind.is_server()).map(|s| named(s, lan(s))).collect()
}

/// The sources in use outside the user's network reached without Tor, by the user's choice:
/// they see this computer's IP address.
pub fn without_tor(list: &[Source], route: impl Fn(&Source) -> Route, lan: impl Fn(&Source) -> bool) -> Vec<Named> {
    list.iter()
        .filter(|s| in_use(list, s) && s.kind != Kind::Local && route(s) == Route::Direct && !lan(s))
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
            assert!(list.iter().all(|s| matches!(s.kind, Kind::Kyoto | Kind::Electrum | Kind::Local)), "{net:?}");
            let fee: Vec<&&Source> = on.iter().filter(|s| s.kind.is_server()).collect();
            let fee_server = matches!(net, BNetwork::Mainnet | BNetwork::Testnet4);
            assert_eq!(fee.len(), usize::from(fee_server), "{net:?}: one fee server, none on signet");
            assert!(fee.iter().all(|s| is_onion(&host(s))), "{net:?}");
            assert!(on.iter().all(|s| s.cert_sha256.is_none()), "{net:?}: a pinned server ships off");
            assert_eq!(list.last().unwrap().id, LOCAL_ID);
            assert!(!list.last().unwrap().enabled);
            let r = roles(&list, server_route, all);
            assert!(r.history.iter().all(|e| !e.kind.is_server()), "{net:?}: no server is asked about addresses");
            assert!(exposes(&list, lan).is_empty() && without_tor(&list, server_route, lan).is_empty());
        }
        let main = defaults(BNetwork::Mainnet);
        let r = roles(&main, server_route, all);
        let fee = "electrum.blockstream.info-onion";
        assert_eq!((ids(&r.chain), ids(&r.fees), ids(&r.check)), (vec!["kyoto"], vec![fee, "kyoto"], vec![fee]));
        assert_eq!(ids(&r.broadcast), ["kyoto"]);
        let signet = defaults(BNetwork::Signet);
        let pinned: Vec<(&str, Option<&str>)> = signet.iter().filter(|s| s.kind.is_server()).map(|s| (s.id.as_str(), s.cert_sha256.as_deref())).collect();
        assert_eq!(pinned, [
            ("electrum.emzy.de", Some("ae52a2307cb9878024b61dbf948d3aac8fea705dfefe562cc62191b6995c48cc")),
            ("signet-electrumx.wakiyamap.dev", Some("aeef7989269830a269c15c841e68bee776e1a15b208804418762471cd1ccce85")),
        ]);
        let r = roles(&signet, server_route, all);
        assert_eq!((ids(&r.chain), ids(&r.fees), r.check.len()), (vec!["kyoto"], vec!["kyoto"], 0), "Kyoto alone");
    }

    #[test]
    fn every_default_onion_is_a_published_one() {
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
        list.iter_mut().for_each(|s| s.enabled = true);
        list.iter_mut().filter(|s| s.kind == Kind::Electrum).for_each(|s| s.history = true);
        // Your node on: it alone, in every role; the other switches stay as they were.
        let r = roles(&list, server_route, all);
        for role in [&r.chain, &r.history, &r.pending, &r.fees, &r.broadcast] {
            assert_eq!(ids(role), ["local"]);
        }
        assert!(r.check.is_empty());
        assert!(exposes(&list, lan).is_empty() && list.iter().filter(|s| s.enabled).count() == 4);
        // Your node unreachable: nothing, rather than a peer or a server.
        let r = roles(&list, server_route, |s| s.kind != Kind::Local);
        assert!([&r.chain, &r.history, &r.pending, &r.fees, &r.broadcast, &r.check].iter().all(|x| x.is_empty()));
        // The node off: Kyoto and the servers, as switched.
        list.iter_mut().filter(|s| s.kind == Kind::Local).for_each(|s| s.enabled = false);
        list.iter_mut().filter(|s| s.kind == Kind::Electrum).for_each(|s| s.history = false);
        let r = roles(&list, server_route, all);
        assert_eq!((ids(&r.chain), ids(&r.broadcast)), (vec!["kyoto"], vec!["kyoto"]));
        assert!(r.pending.is_empty(), "no server has history on");
        // Kyoto unreachable: the chain stays empty rather than move to a server.
        let r = roles(&list, server_route, |s| s.kind != Kind::Kyoto);
        assert!(r.chain.is_empty() && r.broadcast.is_empty());
        // Kyoto and the node off: every Electrum server, and history servers broadcast.
        list.iter_mut().filter(|s| !s.kind.is_server()).for_each(|s| s.enabled = false);
        list.iter_mut().filter(|s| s.id == "electrum.blockstream.info").for_each(|s| s.history = true);
        let r = roles(&list, server_route, all);
        assert_eq!(ids(&r.chain), ["electrum.blockstream.info-onion", "electrum.blockstream.info"]);
        assert_eq!((ids(&r.history), ids(&r.broadcast)), (vec!["electrum.blockstream.info"], vec!["electrum.blockstream.info"]));
        assert_eq!(r.check.len(), 2);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v.as_object().unwrap().keys().collect::<Vec<_>>(), ["broadcast", "chain", "check", "fees", "history", "pending"], "no crossCheck");
    }

    #[test]
    fn your_node_at_an_address_is_asked_alone() {
        let mut list = defaults(BNetwork::Mainnet);
        list.extend(parse_list(r#"[{"id":"mine","kind":"rpc","url":"https://node.example","tor":false},
                                    {"id":"home","kind":"electrum","url":"192.168.1.20","history":true}]"#, &[]).unwrap());
        let r = roles(&list, server_route, all);
        for role in [&r.chain, &r.history, &r.pending, &r.fees, &r.broadcast] {
            assert_eq!(ids(role), ["mine"]);
        }
        assert!(r.check.is_empty() && exposes(&list, lan).is_empty());
        assert_eq!(without_tor(&list, server_route, lan).iter().map(|n| n.id.as_str()).collect::<Vec<_>>(), ["mine"], "it sees this computer");
        let used: Vec<&str> = list.iter().filter(|s| in_use(&list, s)).map(|s| s.id.as_str()).collect();
        assert_eq!(used, ["mine"], "Kyoto, the fee server and the history server wait, switched on");
    }

    #[test]
    fn exposes_and_without_tor() {
        let mut list = defaults(BNetwork::Signet);
        let home = r#"[{"id":"home","kind":"electrum","url":"192.168.1.20","history":true}]"#;
        list.extend(parse_list(home, &[]).unwrap());
        for s in list.iter_mut().filter(|s| s.id == "electrum.emzy.de") {
            (s.enabled, s.history, s.tor) = (true, true, false);
        }
        let ex = exposes(&list, lan);
        assert_eq!(ex.iter().map(|n| (n.id.as_str(), n.lan)).collect::<Vec<_>>(), [("electrum.emzy.de", false), ("home", true)]);
        let direct = without_tor(&list, server_route, lan);
        assert_eq!(direct.iter().map(|n| n.id.as_str()).collect::<Vec<_>>(), ["electrum.emzy.de"], "the LAN server is not listed");
    }

    #[test]
    fn parses_and_validates_lists() {
        let list = parse_list(
            r#"[{"id":"kyoto","kind":"kyoto"},
                {"id":"e1","kind":"electrum","url":"Electrum.Example.COM"},
                {"id":"x","kind":"rpc","url":"https://u:p@node.example/rpc","use":false,"label":" Mine "},
                {"id":"local","kind":"local","lan":true,"route":"direct","hasCredentials":false}]"#,
            &[],
        )
        .unwrap();
        assert_eq!(list[0], kyoto(true));
        assert_eq!((list[1].url.as_str(), list[1].operator.as_str(), list[1].label.as_str()), ("ssl://electrum.example.com:50002", "example.com", "electrum.example.com"));
        assert_eq!((list[2].url.as_str(), list[2].label.as_str(), list[2].enabled), ("https://node.example/rpc", "Mine", false));
        assert_eq!(list[2].credentials, Some(Credentials { username: "u".into(), password: "p".into() }));
        assert_eq!(list[3], local(true));

        // Credentials survive a round trip that leaves them out, and go with null or a new url.
        let back = r#"[{"id":"x","kind":"rpc","url":"https://node.example/rpc"}]"#;
        assert!(parse_list(back, &list).unwrap()[0].credentials.is_some());
        let cleared = r#"[{"id":"x","kind":"rpc","url":"https://node.example/rpc","credentials":null}]"#;
        assert!(parse_list(cleared, &list).unwrap()[0].credentials.is_none());
        let moved = r#"[{"id":"x","kind":"rpc","url":"https://other.example/rpc"}]"#;
        assert!(parse_list(moved, &list).unwrap()[0].credentials.is_none());
        let apart = r#"[{"id":"x","kind":"rpc","url":"https://node.example/rpc","credentials":{"username":"a","password":"b"}}]"#;
        assert_eq!(parse_list(apart, &[]).unwrap()[0].credentials.as_ref().unwrap().username, "a");

        let onion = format!("{}.onion", "a2".repeat(28));
        for (bad, why) in [
            (r#"[{"id":"a","kind":"electrum","url":"tcp://electrum.example:50001"}]"#.to_string(), "plain tcp"),
            (r#"[{"id":"a","kind":"rpc","url":"http://node.example"}]"#.into(), "plain http"),
            (r#"[{"id":"a","kind":"esplora","url":"https://esplora.example/api"}]"#.into(), "invalid parameters: a: Esplora servers are no longer supported; use an Electrum server"),
            (r#"[{"id":"a","kind":"esplora"}]"#.into(), ESPLORA_GONE),
            (r#"[{"id":"a","kind":"electrum","url":"x.example"},{"id":"a","kind":"electrum","url":"y.example"}]"#.into(), "duplicate source id"),
            (r#"[{"id":"a","kind":"electrum","url":"x.example"},{"id":"b","kind":"electrum","url":"ssl://x.example:50002"}]"#.into(), "duplicate source url"),
            (r#"[{"id":"kyoto","kind":"electrum","url":"x.example"}]"#.into(), "belong to Kyoto"),
            (r#"[{"id":"peers","kind":"kyoto"}]"#.into(), "belong to Kyoto"),
            (r#"[{"id":"kyoto","kind":"kyoto","url":"192.168.1.20:8333"}]"#.into(), "peer list"),
            (r#"[{"id":"kyoto","kind":"kyoto","history":true}]"#.into(), "asked about addresses"),
            (r#"[{"id":"local","kind":"local","tor":true}]"#.into(), "Logos IPC"),
            (format!(r#"[{{"id":"o","kind":"rpc","url":"http://{onion}","tor":false}}]"#), "through Tor only"),
            (r#"[{"id":"a","kind":"electrum","url":"x.example","credentials":{"username":"u","password":"p"}}]"#.into(), "only RPC servers"),
            (r#"[{"id":"a","kind":"electrum","url":"x.example","history":true},{"id":"b","kind":"rpc","url":"https://y.example","history":true}]"#.into(), "only Electrum servers are asked"),
            (r#"[{"id":"a","kind":"rpc","url":"https://u:p@x.example","credentials":{"username":"u","password":"p"}}]"#.into(), "given twice"),
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
    fn certificate_pins() {
        let typed = "AB:".repeat(31) + "AB";
        let pin = "ab".repeat(32);
        assert_eq!(normalize_pin(&typed).unwrap(), pin, "colons and capitals, as fingerprints are shown");
        for bad in ["ab".repeat(31), "zz".repeat(32), "ab".repeat(33), String::new()] {
            assert!(normalize_pin(&bad).unwrap_err().starts_with(INVALID), "{bad}");
        }
        let one = |extra: &str| format!(r#"[{{"id":"mine","kind":"electrum","url":"ssl://electrum.example:50002"{extra}}}]"#);
        let parsed = parse_list(&one(&format!(r#","certSha256":"{typed}""#)), &[]).unwrap();
        assert_eq!(parsed[0].cert_sha256.as_deref(), Some(pin.as_str()));
        assert_eq!(parse_list(&one(""), &parsed).unwrap()[0].cert_sha256, parsed[0].cert_sha256, "absent keeps it");
        assert_eq!(parse_list(&one(r#","certSha256":null"#), &parsed).unwrap()[0].cert_sha256, None, "null clears it");
        let moved = parse_list(r#"[{"id":"mine","kind":"electrum","url":"ssl://other.example:50002"}]"#, &parsed).unwrap();
        assert_eq!(moved[0].cert_sha256, None, "not carried to another url");
        let rpc = format!(r#"[{{"id":"e","kind":"rpc","url":"https://node.example","certSha256":"{pin}"}}]"#);
        assert_eq!(parse_list(&rpc, &[]).unwrap()[0].cert_sha256.as_deref(), Some(pin.as_str()));
        for (kind, url) in [("electrum", "tcp://192.168.1.20:50001"), ("rpc", "http://192.168.1.20:8332")] {
            let l = format!(r#"[{{"id":"x","kind":"{kind}","url":"{url}","certSha256":"{pin}"}}]"#);
            let e = parse_list(&l, &[]).unwrap_err();
            assert!(e.starts_with("invalid parameters: x: certSha256 is for a server reached over TLS"), "{e}");
        }
        assert!(parse_list(&one(r#","certSha256":"12""#), &[]).unwrap_err().starts_with("invalid parameters: mine: certSha256 must be"));
        // set_source: set, clear, refuse.
        let mut s = parsed[0].clone();
        Changes::parse(r#"{"certSha256":null}"#).unwrap().apply(&mut s).unwrap();
        assert_eq!(s.cert_sha256, None);
        Changes::parse(&format!(r#"{{"certSha256":"{typed}"}}"#)).unwrap().apply(&mut s).unwrap();
        assert_eq!(s.cert_sha256.as_deref(), Some(pin.as_str()));
        Changes::parse(r#"{"certSha256":""}"#).unwrap().apply(&mut s).unwrap();
        assert_eq!(s.cert_sha256, None, "empty clears too");
        assert!(Changes::parse(r#"{"certSha256":"12"}"#).unwrap().apply(&mut s).unwrap_err().starts_with("invalid parameters: mine: certSha256 must be"));
        let mut k = kyoto(true);
        assert!(Changes::parse(&format!(r#"{{"certSha256":"{pin}"}}"#)).unwrap().apply(&mut k).unwrap_err().starts_with("invalid parameters: kyoto: certSha256 is for"));
        // What is stored is already normalized.
        let mut stored = parsed.clone();
        stored[0].cert_sha256 = Some(typed);
        assert!(validate(&stored).is_err());
    }

    #[test]
    fn plain_text_only_to_onion_services_and_your_network() {
        let onion = format!("{}.onion", "a2".repeat(28));
        for (kind, url) in [("electrum", "tcp://electrum.example:50001"), ("rpc", "http://node.example:8332")] {
            let e = parse_list(&format!(r#"[{{"id":"x","kind":"{kind}","url":"{url}"}}]"#), &[]).unwrap_err();
            assert!(e.starts_with("invalid parameters: x: ") && e.contains("plain"), "{e}");
        }
        let fine = [
            ("electrum", "tcp://192.168.1.20:50001".to_string()),
            ("electrum", format!("tcp://{onion}:50001")),
            ("rpc", "http://umbrel.local:8332".to_string()),
            ("rpc", format!("http://{onion}")),
        ];
        for (kind, url) in fine {
            assert!(parse_list(&format!(r#"[{{"id":"x","kind":"{kind}","url":"{url}"}}]"#), &[]).is_ok(), "{url}");
        }
    }

    #[test]
    fn route_entries_carry_the_pin_and_who_added_the_server() {
        let pin = "ab".repeat(32);
        let mut list = defaults(BNetwork::Mainnet);
        list.extend(parse_list(&format!(r#"[{{"id":"mine","kind":"electrum","url":"ssl://electrum.example:50002","certSha256":"{pin}"}}]"#), &[]).unwrap());
        let r = roles(&list, |_| Route::Tor, |_| true);
        let mine = r.check.iter().find(|e| e.id == "mine").unwrap();
        assert_eq!((mine.cert_sha256.as_deref(), mine.user_added), (Some(pin.as_str()), true));
        let theirs = r.fees.iter().find(|e| e.id == "electrum.blockstream.info-onion").unwrap();
        assert_eq!((theirs.cert_sha256.as_deref(), theirs.user_added), (None, false), "a default");
        let v = serde_json::to_value(mine).unwrap();
        assert_eq!((&v["certSha256"], &v["userAdded"]), (&serde_json::json!(pin), &serde_json::json!(true)));
        let v = serde_json::to_value(theirs).unwrap();
        assert!(v.get("userAdded").is_none() && v.get("certSha256").is_none(), "left out when unset");
        // A pinned default, switched on, carries its pin and is still a default.
        let mut signet = defaults(BNetwork::Signet);
        signet.iter_mut().filter(|s| s.id == "electrum.emzy.de").for_each(|s| s.enabled = true);
        let r = roles(&signet, |_| Route::Tor, |_| true);
        assert_eq!((r.check[0].id.as_str(), r.check[0].cert_sha256.as_deref().map(str::len), r.check[0].user_added), ("electrum.emzy.de", Some(64), false));
    }

    #[test]
    fn changes() {
        let mut s = defaults(BNetwork::Mainnet)[2].clone();
        Changes::parse(r#"{"use":true,"history":true}"#).unwrap().apply(&mut s).unwrap();
        assert!(s.enabled && s.history && s.tor);
        Changes::parse(r#"{"tor":false}"#).unwrap().apply(&mut s).unwrap();
        assert!(!s.tor && s.enabled);
        for bad in [r#"{"enabled":true}"#, "[]", r#"{"use":"yes"}"#] {
            assert!(Changes::parse(bad).is_err(), "{bad}");
        }
    }
}

#[cfg(test)]
mod rpc_tests {
    use super::*;
    #[test]
    fn rpc_routes_as_an_authority_and_preserves_credentials() {
        let list=parse_list(r#"[{"id":"rpc","kind":"rpc","url":"http://127.0.0.1:8332","tor":false,"credentials":{"username":"user","password":"pass"}}]"#,&[]).unwrap();
        let roles=roles(&list, |_| Route::Direct, |_| true);
        assert_eq!(roles.chain[0].kind,Kind::Rpc);
        assert_eq!(roles.broadcast[0].kind,Kind::Rpc);
        assert!(roles.check.is_empty());
        let preserved=parse_list(r#"[{"id":"rpc","kind":"rpc","url":"http://127.0.0.1:8332","tor":false}]"#,&list).unwrap();
        assert_eq!(preserved[0].credentials,list[0].credentials);
        assert!(parse_list(r#"[{"id":"rpc","kind":"rpc","url":"http://public.example:8332"}]"#,&[]).is_err());
        assert!(parse_list(r#"[{"id":"rpc","kind":"rpc","url":"https://public.example","history":true}]"#,&[]).is_err());
    }

    #[test]
    fn at_most_one_node_source_is_on() {
        let one = "Enable only one node at a time: the local node or one Bitcoin Core RPC endpoint";
        for two in [
            r#"[{"id":"a","kind":"rpc","url":"https://one.example"},{"id":"b","kind":"rpc","url":"https://two.example"}]"#,
            r#"[{"id":"local","kind":"local"},{"id":"b","kind":"rpc","url":"https://two.example"}]"#,
        ] {
            assert_eq!(parse_list(two, &[]).unwrap_err(), one, "{two}");
        }
        let off = r#"[{"id":"local","kind":"local"},{"id":"a","kind":"rpc","url":"https://one.example","use":false},{"id":"b","kind":"rpc","url":"https://two.example","use":false}]"#;
        assert_eq!(parse_list(off, &[]).unwrap().len(), 3, "a user's RPC entries stay, switched off");
    }
}
