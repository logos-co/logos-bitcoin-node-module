//! Kyoto's peers: the curated lists per network (onion and clearnet, versioned, compiled in),
//! the user's own peers, which replace them, and the peers Kyoto's route can use.

use std::net::IpAddr;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::addr;
use crate::net::client::{is_lan_host, is_onion, Route};
use crate::network::BNetwork;

/// 2 since `keyId`, `signature` and `refreshUrl` left with the signature (2026-11-02).
pub const FORMAT: u32 = 2;
/// Distinct peers of your own; a signet node list can reach 20 or more.
pub const MAX_OWN_PEERS: usize = 64;
pub const MAX_LIST_PEERS: usize = 1024;
/// Clearnet peers kept per /16 (IPv4) or /32 (IPv6), in the list and in the book.
pub const PER_NETGROUP: usize = 2;

/// A curated peer list as the crawler writes it. Unsigned: it is compiled in, and Jenkins signs
/// the package; a list fetched at runtime would need a signature again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeerList {
    pub format: u32,
    pub network: BNetwork,
    /// Grows with each release.
    #[serde(serialize_with = "crate::strnum::ser", deserialize_with = "crate::strnum::de")]
    pub version: u64,
    /// When the crawler built it, YYYY-MM-DDTHH:MM:SSZ.
    pub created: Option<String>,
    /// The UTC day the crawler last checked the peers, YYYY-MM-DD.
    pub date: Option<String>,
    pub note: String,
    /// `host:port`: v3 onion services or IP addresses, never a name to resolve.
    pub peers: Vec<String>,
}

fn date_ok(d: &str) -> bool {
    let b = d.as_bytes();
    b.len() == 10 && b[4] == b'-' && b[7] == b'-' && b.iter().enumerate().all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
}

fn time_ok(t: &str) -> bool {
    let b = t.as_bytes();
    b.len() == 20 && date_ok(&t[..10]) && b[10] == b'T' && b[13] == b':' && b[16] == b':' && b[19] == b'Z'
        && [11, 12, 14, 15, 17, 18].iter().all(|&i| b[i].is_ascii_digit())
}

impl PeerList {
    pub fn validate(&self, net: BNetwork) -> Result<(), String> {
        if self.format != FORMAT {
            return Err(format!("peer list format {} is not {FORMAT}", self.format));
        }
        if self.network != net {
            return Err(format!("the peer list is for {}, not {}", self.network.name(), net.name()));
        }
        if self.peers.is_empty() || self.peers.len() > MAX_LIST_PEERS {
            return Err(format!("a peer list holds 1 to {MAX_LIST_PEERS} peers"));
        }
        for p in &self.peers {
            let h = peer_host(p);
            let onion_ok = !h.ends_with(".onion") || crate::net::p2p::onion_key(h).is_some();
            if normalize_peer(net, p).as_deref() != Ok(p.as_str()) || is_lan_host(h) || !onion_ok {
                return Err(format!("peer list: {p} is not an onion service or public IP address as host:port"));
            }
        }
        if self.date.as_deref().is_some_and(|d| !date_ok(d)) {
            return Err("peer list: date must be YYYY-MM-DD".into());
        }
        if self.created.as_deref().is_some_and(|t| !time_ok(t)) {
            return Err("peer list: created must be YYYY-MM-DDTHH:MM:SSZ".into());
        }
        Ok(())
    }

    fn empty(net: BNetwork, note: &str) -> Self {
        Self { format: FORMAT, network: net, version: 0, created: None, date: None, note: note.into(), peers: vec![] }
    }
}

/// An IPv4 or IPv6 peer of the clearnet list, with the services it announced (decimal).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearnetPeer {
    pub peer: String,
    #[serde(serialize_with = "crate::strnum::ser", deserialize_with = "crate::strnum::de")]
    pub services: u64,
}

/// The clearnet list Kyoto syncs headers and filters from when Tor is not used for them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearnetList {
    pub format: u32,
    pub network: BNetwork,
    #[serde(serialize_with = "crate::strnum::ser", deserialize_with = "crate::strnum::de")]
    pub version: u64,
    pub created: Option<String>,
    pub date: Option<String>,
    pub note: String,
    pub peers: Vec<ClearnetPeer>,
}

impl ClearnetList {
    pub fn validate(&self, net: BNetwork) -> Result<(), String> {
        if self.format != FORMAT {
            return Err(format!("clearnet list format {} is not {FORMAT}", self.format));
        }
        if self.network != net {
            return Err(format!("the clearnet list is for {}, not {}", self.network.name(), net.name()));
        }
        if self.peers.is_empty() || self.peers.len() > MAX_LIST_PEERS {
            return Err(format!("a clearnet list holds 1 to {MAX_LIST_PEERS} peers"));
        }
        let mut groups: std::collections::HashMap<(u8, u32), usize> = std::collections::HashMap::new();
        for p in &self.peers {
            let ip = peer_host(&p.peer).parse::<IpAddr>().ok().filter(|ip| public_ip(*ip));
            let Some(ip) = ip.filter(|_| normalize_peer(net, &p.peer).as_deref() == Ok(p.peer.as_str())) else {
                return Err(format!("clearnet list: {} is not a public IP address as host:port", p.peer));
            };
            let n = groups.entry(netgroup(ip)).or_default();
            *n += 1;
            if *n > PER_NETGROUP {
                return Err(format!("clearnet list: more than {PER_NETGROUP} peers in the netgroup of {}", p.peer));
            }
        }
        if self.date.as_deref().is_some_and(|d| !date_ok(d)) || self.created.as_deref().is_some_and(|t| !time_ok(t)) {
            return Err("clearnet list: date must be YYYY-MM-DD and created YYYY-MM-DDTHH:MM:SSZ".into());
        }
        Ok(())
    }

    fn empty(net: BNetwork, note: &str) -> Self {
        Self { format: FORMAT, network: net, version: 0, created: None, date: None, note: note.into(), peers: vec![] }
    }
}

/// A globally routed unicast address: no private, loopback, link-local, CGNAT, documentation,
/// benchmarking, multicast or reserved range; IPv6 only from 2000::/3, without Teredo or 6to4.
pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(o[0] == 0
                || o[0] == 10
                || o[0] == 127
                || o[0] >= 224
                || (o[0] == 100 && (64..128).contains(&o[1]))
                || (o[0] == 169 && o[1] == 254)
                || (o[0] == 172 && (16..32).contains(&o[1]))
                || (o[0] == 192 && o[1] == 0 && (o[2] == 0 || o[2] == 2))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113))
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            s[0] & 0xe000 == 0x2000 && !(s[0] == 0x2001 && (s[1] == 0 || s[1] == 0xdb8 || (0x10..0x30).contains(&s[1]))) && s[0] != 0x2002
        }
    }
}

/// The /16 of an IPv4 address or the /32 of an IPv6 one.
pub fn netgroup(ip: IpAddr) -> (u8, u32) {
    match ip {
        IpAddr::V4(a) => (4, u32::from(a.octets()[0]) << 8 | u32::from(a.octets()[1])),
        IpAddr::V6(a) => (6, u32::from(a.segments()[0]) << 16 | u32::from(a.segments()[1])),
    }
}

fn load_shipped(net: BNetwork, text: &str) -> PeerList {
    let list: PeerList = serde_json::from_str(text).expect("the shipped peer lists parse (see tests)");
    match list.validate(net) {
        Ok(()) => list,
        Err(e) => PeerList::empty(net, &format!("The shipped list was refused ({e}): add your own node with set_own_peers.")),
    }
}

/// The list this build ships, checked once: lists for mainnet, signet and testnet4, none for
/// regtest.
pub fn shipped(net: BNetwork) -> PeerList {
    static LISTS: OnceLock<[PeerList; 3]> = OnceLock::new();
    let lists = LISTS.get_or_init(|| {
        [
            load_shipped(BNetwork::Mainnet, include_str!("../peer-lists/mainnet.json")),
            load_shipped(BNetwork::Testnet4, include_str!("../peer-lists/testnet4.json")),
            load_shipped(BNetwork::Signet, include_str!("../peer-lists/signet.json")),
        ]
    });
    match net {
        BNetwork::Mainnet => lists[0].clone(),
        BNetwork::Testnet4 => lists[1].clone(),
        BNetwork::Signet => lists[2].clone(),
        BNetwork::Regtest => PeerList::empty(net, "Regtest has no curated peers: add your node with set_own_peers."),
    }
}

fn load_shipped_clearnet(net: BNetwork, text: &str) -> ClearnetList {
    let list: ClearnetList = serde_json::from_str(text).expect("the shipped clearnet lists parse (see tests)");
    match list.validate(net) {
        Ok(()) => list,
        Err(e) => ClearnetList::empty(net, &format!("The shipped clearnet list was refused ({e}).")),
    }
}

/// The clearnet list this build ships, checked once; none for regtest.
pub fn shipped_clearnet(net: BNetwork) -> ClearnetList {
    static LISTS: OnceLock<[ClearnetList; 3]> = OnceLock::new();
    let lists = LISTS.get_or_init(|| {
        [
            load_shipped_clearnet(BNetwork::Mainnet, include_str!("../peer-lists/clearnet-mainnet.json")),
            load_shipped_clearnet(BNetwork::Testnet4, include_str!("../peer-lists/clearnet-testnet4.json")),
            load_shipped_clearnet(BNetwork::Signet, include_str!("../peer-lists/clearnet-signet.json")),
        ]
    });
    match net {
        BNetwork::Mainnet => lists[0].clone(),
        BNetwork::Testnet4 => lists[1].clone(),
        BNetwork::Signet => lists[2].clone(),
        BNetwork::Regtest => ClearnetList::empty(net, "Regtest has no curated peers: add your node with set_own_peers."),
    }
}

fn load_seeds(net: BNetwork, text: &str, keep: fn(&str) -> bool) -> Vec<String> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Seeds {
        network: BNetwork,
        peers: Vec<String>,
    }
    let s: Seeds = serde_json::from_str(text).expect("the shipped seeds parse (see tests)");
    assert_eq!(s.network, net, "seeds for the wrong network");
    // Only well-formed host:port of the right kind; a bad line is dropped, not dialled.
    s.peers.into_iter().filter(|p| normalize_peer(net, p).as_deref() == Ok(p.as_str()) && keep(peer_host(p))).collect()
}

/// Bitcoin Core's fixed seeds this build ships, onion v3 only (peer-lists/seeds-<network>.json,
/// written by the crawler's `seeds` command). Regtest has none.
pub fn fixed_seeds(net: BNetwork) -> &'static [String] {
    let onion = |h: &str| crate::net::p2p::onion_key(h).is_some();
    static SEEDS: OnceLock<[Vec<String>; 3]> = OnceLock::new();
    let s = SEEDS.get_or_init(|| {
        [
            load_seeds(BNetwork::Mainnet, include_str!("../peer-lists/seeds-mainnet.json"), onion),
            load_seeds(BNetwork::Testnet4, include_str!("../peer-lists/seeds-testnet4.json"), onion),
            load_seeds(BNetwork::Signet, include_str!("../peer-lists/seeds-signet.json"), onion),
        ]
    });
    match net {
        BNetwork::Mainnet => &s[0],
        BNetwork::Testnet4 => &s[1],
        BNetwork::Signet => &s[2],
        BNetwork::Regtest => &[],
    }
}

/// Core's public IPv4 and IPv6 fixed seeds (peer-lists/clearnet-seeds-<network>.json), dialled
/// directly, only when Kyoto takes the chain from clearnet peers. Regtest has none.
pub fn clearnet_seeds(net: BNetwork) -> &'static [String] {
    let public = |h: &str| h.parse::<IpAddr>().is_ok_and(public_ip);
    static SEEDS: OnceLock<[Vec<String>; 3]> = OnceLock::new();
    let s = SEEDS.get_or_init(|| {
        [
            load_seeds(BNetwork::Mainnet, include_str!("../peer-lists/clearnet-seeds-mainnet.json"), public),
            load_seeds(BNetwork::Testnet4, include_str!("../peer-lists/clearnet-seeds-testnet4.json"), public),
            load_seeds(BNetwork::Signet, include_str!("../peer-lists/clearnet-seeds-signet.json"), public),
        ]
    });
    match net {
        BNetwork::Mainnet => &s[0],
        BNetwork::Testnet4 => &s[1],
        BNetwork::Signet => &s[2],
        BNetwork::Regtest => &[],
    }
}

/// Bitcoin Core 31.2's DNS seeds that answer `x49.<seed>` (network, witness and compact
/// filters; Core's notes say the others answer x9 or less), asked through the system resolver,
/// only in the direct modes and only when the book runs low.
pub fn dns_seeds(net: BNetwork) -> &'static [&'static str] {
    match net {
        BNetwork::Mainnet => &["seed.bitcoin.sprovoost.nl", "dnsseed.emzy.de", "seed.bitcoin.wiz.biz", "seed.mainnet.achownodes.xyz"],
        BNetwork::Testnet4 => &["seed.testnet4.bitcoin.sprovoost.nl", "seed.testnet4.wiz.biz"],
        BNetwork::Signet => &["seed.signet.bitcoin.sprovoost.nl", "seed.signet.achownodes.xyz"],
        BNetwork::Regtest => &[],
    }
}

/// The host of `host:port` (IPv6 without brackets).
pub fn peer_host(p: &str) -> &str {
    let h = match p.rsplit_once(':') {
        Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => p,
    };
    h.trim_start_matches('[').trim_end_matches(']')
}

/// `host[:port]` as Kyoto dials it: an IP address, a v3 onion service or a name on your network.
/// Public names are refused, since Kyoto resolves them outside Tor.
pub fn normalize_peer(net: BNetwork, s: &str) -> Result<String, String> {
    let t = s.trim();
    let bad = || format!("{t}: not a peer address; use host:port");
    let p = addr::split(&format!("p2p://{t}")).map_err(|_| bad())?;
    if p.user.is_some() || !p.path.is_empty() {
        return Err(bad());
    }
    if p.host.ends_with(".onion") && !is_onion(&p.host) {
        return Err(format!("{t}: only v3 onion services (56 characters) are supported"));
    }
    if !(is_onion(&p.host) || p.host.parse::<IpAddr>().is_ok() || is_lan_host(&p.host)) {
        return Err(format!("{t}: use an IP address, an onion address or a name on your network; Kyoto would resolve {} outside Tor", p.host));
    }
    Ok(format!("{}:{}", addr::fmt_host(&p.host), p.port.unwrap_or(net.p2p_port())))
}

/// set_own_peers' argument: a JSON array of `host[:port]`, duplicates dropped, at most
/// `MAX_OWN_PEERS` distinct ones.
pub fn parse_own(net: BNetwork, json: &str) -> Result<Vec<String>, String> {
    let items: Vec<String> = serde_json::from_str(json).map_err(|e| format!("peers must be a JSON array of host:port strings: {e}"))?;
    let too_many = || format!("at most {MAX_OWN_PEERS} peers of your own");
    if items.len() > 4 * MAX_OWN_PEERS {
        return Err(too_many());
    }
    let mut out: Vec<String> = Vec::new();
    for i in items {
        let p = normalize_peer(net, &i)?;
        if !out.contains(&p) {
            out.push(p);
        }
    }
    if out.len() > MAX_OWN_PEERS {
        return Err(too_many());
    }
    Ok(out)
}

/// The user's own peers are all on their network.
pub fn kyoto_lan(own: &[String]) -> bool {
    !own.is_empty() && own.iter().all(|p| is_lan_host(peer_host(p)))
}

/// Kyoto's one connection type for every peer: direct when the user's peers are all on their
/// network or Tor is off; otherwise through Tor, `onion` when every peer is an onion service.
pub fn kyoto_route(own: &[String], tor: bool) -> Route {
    if kyoto_lan(own) || !tor {
        Route::Direct
    } else if own.iter().all(|p| is_onion(peer_host(p))) {
        Route::Onion
    } else {
        Route::Tor
    }
}

/// Kyoto cannot dial some peers directly and others through Tor (one connection type per
/// client), nor reach an onion service without Tor.
pub fn check_own(own: &[String], tor: bool) -> Result<(), String> {
    let lan = own.iter().filter(|p| is_lan_host(peer_host(p))).count();
    if tor && lan > 0 && lan < own.len() {
        return Err("Kyoto uses one connection type for every peer: peers on your network are dialled directly and the others through Tor, so add one kind, or switch Kyoto's Tor off".into());
    }
    if !tor && own.iter().any(|p| is_onion(peer_host(p))) {
        return Err("an onion peer is reached through Tor only: switch Kyoto's Tor on".into());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Made-up onion names (qqqq...), for tests only: no real peer is listed anywhere in this crate.
    fn fake_onions(n: usize) -> Vec<String> {
        const B32: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        (0..n).map(|i| {
            let tail: String = (0..4).rev().map(|k| B32[(i >> (5 * k)) & 31] as char).collect();
            format!("{}{tail}.onion:8333", "q".repeat(52))
        }).collect()
    }

    /// A list of made-up onions with valid checksums.
    pub(crate) fn made_up(net: BNetwork, version: u64, note: &str) -> PeerList {
        let peers = (1..=3u8).map(|i| format!("{}:8333", crate::net::p2p::onion_from_key(&[i; 32]))).collect();
        PeerList { version, created: Some("2026-10-11T02:00:00Z".into()), date: Some("2026-10-11".into()), peers, ..PeerList::empty(net, note) }
    }

    #[test]
    fn shipped_lists_are_well_formed_or_explained() {
        for net in [BNetwork::Mainnet, BNetwork::Signet, BNetwork::Testnet4] {
            let l = shipped(net);
            l.validate(net).unwrap();
            assert!(!l.peers.is_empty() && l.version > 0 && l.created.is_some(), "{net:?}");
            assert!(l.peers.iter().all(|p| is_onion(peer_host(p))), "{net:?}: onion v3 only");
        }
        let r = shipped(BNetwork::Regtest);
        assert!(r.peers.is_empty() && r.version == 0 && r.note.contains("set_own_peers"));
        // A shipped list that fails its check is replaced by an empty one that says why.
        let mut bad = shipped(BNetwork::Signet);
        bad.peers.push("192.168.1.20:38333".into());
        let refused = load_shipped(BNetwork::Signet, &serde_json::to_string(&bad).unwrap());
        assert!(refused.peers.is_empty() && refused.note.contains("not an onion service"), "{}", refused.note);
    }

    #[test]
    fn peer_addresses() {
        let onion = format!("{}.onion", "a2".repeat(28));
        for (typed, peer) in [
            ("192.168.1.20", "192.168.1.20:8333".to_string()),
            ("127.0.0.1:18444", "127.0.0.1:18444".into()),
            ("[fd00::2]", "[fd00::2]:8333".into()),
            ("Umbrel.Local:8333", "umbrel.local:8333".into()),
            ("203.0.113.5:8333", "203.0.113.5:8333".into()),
            (onion.as_str(), format!("{onion}:8333")),
        ] {
            assert_eq!(normalize_peer(BNetwork::Mainnet, typed).unwrap(), peer, "{typed}");
        }
        assert_eq!(normalize_peer(BNetwork::Signet, "10.0.0.2").unwrap(), "10.0.0.2:38333");
        for (typed, why) in [("seed.bitcoin.example", "outside Tor"), ("expyuzz4wqqyqhjn.onion", "v3"), ("u@1.2.3.4", "host:port"), ("1.2.3.4/x", "host:port"), ("1.2.3.4:0", "host:port")] {
            let e = normalize_peer(BNetwork::Mainnet, typed).unwrap_err();
            assert!(e.contains(why), "{typed}: {e}");
        }
        assert_eq!(parse_own(BNetwork::Regtest, r#"["127.0.0.1","127.0.0.1:18444"]"#).unwrap(), ["127.0.0.1:18444"]);
        assert!(parse_own(BNetwork::Mainnet, "\"1.2.3.4\"").is_err());
        assert_eq!(peer_host("[fd00::2]:8333"), "fd00::2");
    }

    #[test]
    fn up_to_64_peers_of_your_own() {
        let ips: Vec<String> = (1..=64).map(|i| format!("10.0.0.{i}")).collect();
        let mut sent = ips.clone();
        sent.extend(ips.iter().take(10).cloned());
        let own = parse_own(BNetwork::Signet, &serde_json::to_string(&sent).unwrap()).unwrap();
        assert_eq!(own.len(), 64, "duplicates dropped before counting");
        assert!(own.iter().all(|p| p.ends_with(":38333")));
        let onions = fake_onions(23);
        assert_eq!(parse_own(BNetwork::Signet, &serde_json::to_string(&onions).unwrap()).unwrap(), onions, "a privacy test's 23 signet candidates");
        let mut over = ips;
        over.push("10.0.1.1".into());
        assert!(parse_own(BNetwork::Signet, &serde_json::to_string(&over).unwrap()).unwrap_err().contains("at most 64"));
        assert!(parse_own(BNetwork::Signet, &serde_json::to_string(&vec!["10.0.0.1"; 257]).unwrap()).is_err(), "bounded before parsing each");
        assert!(parse_own(BNetwork::Signet, r#"["10.0.0.1","seed.example.org"]"#).unwrap_err().contains("outside Tor"), "still validated");
    }

    #[test]
    fn one_connection_type_per_client() {
        let onion = format!("{}.onion:8333", "a2".repeat(28));
        let (lan, public) = ("192.168.1.20:8333".to_string(), "203.0.113.5:8333".to_string());
        // (own peers, tor) -> route, or refused.
        let cases: Vec<(Vec<String>, bool, Option<Route>)> = vec![
            (vec![], true, Some(Route::Onion)),
            (vec![], false, Some(Route::Direct)),
            (vec![lan.clone()], true, Some(Route::Direct)),
            (vec![lan.clone()], false, Some(Route::Direct)),
            (vec![public.clone()], true, Some(Route::Tor)),
            (vec![public.clone()], false, Some(Route::Direct)),
            (vec![onion.clone()], true, Some(Route::Onion)),
            (vec![onion.clone()], false, None),
            (vec![onion.clone(), public.clone()], true, Some(Route::Tor)),
            (vec![lan.clone(), public.clone()], true, None),
            (vec![lan.clone(), public.clone()], false, Some(Route::Direct)),
            (vec![lan.clone(), onion.clone()], true, None),
        ];
        for (own, tor, want) in cases {
            match want {
                Some(r) => {
                    check_own(&own, tor).unwrap();
                    assert_eq!(kyoto_route(&own, tor), r, "{own:?} tor={tor}");
                }
                None => assert!(check_own(&own, tor).is_err(), "{own:?} tor={tor}"),
            }
        }
        assert!(kyoto_lan(std::slice::from_ref(&lan)) && !kyoto_lan(&[]) && !kyoto_lan(&[lan, public]));
    }

    #[test]
    fn a_list_for_another_network_or_malformed_is_refused() {
        let signet = shipped(BNetwork::Signet);
        let as_mainnet = load_shipped(BNetwork::Mainnet, &serde_json::to_string(&signet).unwrap());
        assert!(as_mainnet.peers.is_empty() && as_mainnet.note.contains("for signet, not mainnet"), "{}", as_mainnet.note);
        let lan = PeerList { peers: vec!["192.168.1.20:8333".into()], ..made_up(BNetwork::Mainnet, 2, "lan") };
        assert!(lan.validate(BNetwork::Mainnet).is_err(), "no LAN peer in a curated list");
        let bad_time = PeerList { created: Some("2026-10-11 02:00".into()), ..made_up(BNetwork::Mainnet, 2, "t") };
        assert!(bad_time.validate(BNetwork::Mainnet).unwrap_err().contains("created"));
        made_up(BNetwork::Mainnet, 2, "ok").validate(BNetwork::Mainnet).unwrap();
        // A v3 name with a wrong checksum or version, and an empty list, are refused.
        let bad_sum = PeerList { peers: vec![format!("{}.onion:8333", "q".repeat(56))], ..made_up(BNetwork::Mainnet, 2, "sum") };
        assert!(bad_sum.validate(BNetwork::Mainnet).unwrap_err().contains("not an onion service"));
        assert!(PeerList { peers: vec![], ..made_up(BNetwork::Mainnet, 2, "none") }.validate(BNetwork::Mainnet).unwrap_err().contains("1 to"));
    }

    #[test]
    fn the_fixed_seeds_are_core_onions() {
        assert!(fixed_seeds(BNetwork::Regtest).is_empty());
        let files = [
            (BNetwork::Mainnet, include_str!("../peer-lists/seeds-mainnet.json")),
            (BNetwork::Testnet4, include_str!("../peer-lists/seeds-testnet4.json")),
            (BNetwork::Signet, include_str!("../peer-lists/seeds-signet.json")),
        ];
        for (net, text) in files {
            let raw: serde_json::Value = serde_json::from_str(text).unwrap();
            let seeds = fixed_seeds(net);
            assert!(!seeds.is_empty() && seeds.len() == raw["peers"].as_array().unwrap().len(), "{net:?}: none dropped");
            assert!(seeds.iter().all(|p| crate::net::p2p::onion_key(peer_host(p)).is_some() && p.ends_with(&format!(":{}", net.p2p_port()))), "{net:?}");
        }
    }

    #[test]
    fn the_list_format() {
        let l = made_up(BNetwork::Signet, 7, "n");
        let m = serde_json::to_string(&l).unwrap();
        assert!(m.starts_with("{\"format\":2,\"network\":\"signet\",\"version\":\"7\",\"created\":\"2026-10-11T02:00:00Z\",\"date\":\"2026-10-11\",\"note\":\"n\",\"peers\":["), "{m}");
        // Format 1's keyId, signature and refreshUrl are refused, and so is format 1.
        for gone in ["keyId", "signature", "refreshUrl"] {
            let mut v = serde_json::to_value(&l).unwrap();
            v[gone] = serde_json::Value::Null;
            assert!(serde_json::from_value::<PeerList>(v).is_err(), "{gone}");
        }
        assert!(PeerList { format: 1, ..l }.validate(BNetwork::Signet).unwrap_err().contains("format 1 is not 2"));
    }

    #[test]
    fn the_clearnet_lists_and_core_seeds() {
        for net in [BNetwork::Mainnet, BNetwork::Signet, BNetwork::Testnet4] {
            let l = shipped_clearnet(net);
            l.validate(net).unwrap();
            assert!(!l.peers.is_empty() && l.version > 0 && l.created.is_some(), "{net:?}");
            let seeds = clearnet_seeds(net);
            assert!(seeds.len() > 50, "{net:?}: Core 31.2's IPv4 and IPv6 seeds");
            assert!(seeds.iter().all(|p| peer_host(p).parse::<IpAddr>().is_ok_and(public_ip) && p.ends_with(&format!(":{}", net.p2p_port()))), "{net:?}");
            assert!(!dns_seeds(net).is_empty());
        }
        assert!(clearnet_seeds(BNetwork::Regtest).is_empty() && dns_seeds(BNetwork::Regtest).is_empty());
    }

    #[test]
    fn a_clearnet_list_is_well_formed() {
        let peer = |p: &str, services: u64| ClearnetPeer { peer: p.into(), services };
        let l = ClearnetList { version: 7, created: Some("2026-11-02T18:00:00Z".into()), peers: vec![peer("1.2.3.4:38333", 3145), peer("[2a01:4f8::1]:38333", 1097)], ..ClearnetList::empty(BNetwork::Signet, "n") };
        l.validate(BNetwork::Signet).unwrap();
        // The crawler's format (logos-bitcoin-peer-list, list.rs).
        let m = serde_json::to_string(&l).unwrap();
        assert!(m.starts_with("{\"format\":2,\"network\":\"signet\",\"version\":\"7\",\"created\":\"2026-11-02T18:00:00Z\",\"date\":null,\"note\":\"n\",\"peers\":[{\"peer\":\"1.2.3.4:38333\",\"services\":\"3145\"},"), "{m}");
        for bad in [vec![], vec![peer("192.168.1.2:38333", 73)], vec![peer(&format!("{}.onion:38333", "a2".repeat(28)), 73)], vec![peer("1.2.3.4:38333", 73), peer("1.2.5.5:38333", 73), peer("1.2.6.6:38333", 73)]] {
            assert!(ClearnetList { peers: bad.clone(), ..l.clone() }.validate(BNetwork::Signet).is_err(), "{bad:?}");
        }
        // A shipped list that fails its check is refused, with why.
        let crowded = ClearnetList { peers: vec![peer("1.2.3.4:38333", 73), peer("1.2.5.5:38333", 73), peer("1.2.6.6:38333", 73)], ..l.clone() };
        let refused = load_shipped_clearnet(BNetwork::Signet, &serde_json::to_string(&crowded).unwrap());
        assert!(refused.peers.is_empty() && refused.note.contains("more than 2"), "{}", refused.note);
    }
}
