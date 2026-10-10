//! Kyoto's peers: the curated list per network (versioned, signed), the user's own peers, which
//! replace it, and the subset Kyoto dials today.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::addr;
use crate::net::client::{is_lan_host, is_onion, Route};
use crate::network::BNetwork;

pub const FORMAT: u32 = 1;
pub const SUBSET: usize = 8;
pub const MAX_OWN_PEERS: usize = 16;
pub const MAX_LIST_PEERS: usize = 1024;
pub const MAX_LIST_BYTES: usize = 256 * 1024;

/// A curated peer list as the crawler publishes it. The signature covers `signed_message()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeerList {
    pub format: u32,
    pub network: BNetwork,
    /// Grows with each release; a fetched list replaces this one only when newer.
    #[serde(serialize_with = "crate::strnum::ser", deserialize_with = "crate::strnum::de")]
    pub version: u64,
    /// The UTC day the crawler last checked the peers, YYYY-MM-DD.
    pub date: Option<String>,
    pub note: String,
    /// Where newer lists are published; none until the crawler runs.
    pub refresh_url: Option<String>,
    /// `host:port`: v3 onion services or IP addresses, never a name to resolve.
    pub peers: Vec<String>,
    /// The release key that signed it.
    pub key_id: Option<String>,
    pub signature: Option<String>,
}

fn date_ok(d: &str) -> bool {
    let b = d.as_bytes();
    b.len() == 10 && b[4] == b'-' && b[7] == b'-' && b.iter().enumerate().all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
}

impl PeerList {
    pub fn validate(&self, net: BNetwork) -> Result<(), String> {
        if self.format != FORMAT {
            return Err(format!("peer list format {} is not {FORMAT}", self.format));
        }
        if self.network != net {
            return Err(format!("the peer list is for {}, not {}", self.network.name(), net.name()));
        }
        if self.peers.len() > MAX_LIST_PEERS {
            return Err(format!("a peer list holds at most {MAX_LIST_PEERS} peers"));
        }
        for p in &self.peers {
            if normalize_peer(net, p).as_deref() != Ok(p.as_str()) || is_lan_host(peer_host(p)) {
                return Err(format!("peer list: {p} is not an onion service or public IP address as host:port"));
            }
        }
        if self.date.as_deref().is_some_and(|d| !date_ok(d)) {
            return Err("peer list: date must be YYYY-MM-DD".into());
        }
        if let Some(u) = &self.refresh_url {
            crate::addr::esplora(u).map_err(|e| format!("peer list refreshUrl: {e}"))?;
        }
        Ok(())
    }

    /// The bytes a signature covers: this list with `signature` null, as compact JSON in field order.
    pub fn signed_message(&self) -> Vec<u8> {
        let unsigned = PeerList { signature: None, ..self.clone() };
        serde_json::to_vec(&unsigned).unwrap_or_default()
    }

    fn empty(net: BNetwork, note: &str) -> Self {
        Self { format: FORMAT, network: net, version: 0, date: None, note: note.into(), refresh_url: None, peers: vec![], key_id: None, signature: None }
    }
}

/// The list this build ships. Mainnet, testnet4 and signet are empty until the crawler fills
/// them; regtest never has one.
pub fn shipped(net: BNetwork) -> PeerList {
    let text = match net {
        BNetwork::Mainnet => include_str!("../peer-lists/mainnet.json"),
        BNetwork::Testnet4 => include_str!("../peer-lists/testnet4.json"),
        BNetwork::Signet => include_str!("../peer-lists/signet.json"),
        BNetwork::Regtest => return PeerList::empty(net, "Regtest has no curated peers: add your node with set_own_peers."),
    };
    serde_json::from_str(text).expect("the shipped peer lists parse (see tests)")
}

/// STUB: no release key exists yet, so every fetched list is refused. The real check verifies
/// `signature` over `signed_message()` with the release key `key_id` names.
pub fn verify_stub(_list: &PeerList) -> Result<(), String> {
    Err("peer list signatures are not checked yet (stub), so the fetched list is refused".into())
}

/// A fetched list, kept only if it parses, is for `net`, is newer than `current` and its
/// signature checks.
pub fn accept(net: BNetwork, current: &PeerList, body: &[u8], verify: fn(&PeerList) -> Result<(), String>) -> Result<PeerList, String> {
    if body.len() > MAX_LIST_BYTES {
        return Err(format!("the fetched peer list is over {MAX_LIST_BYTES} bytes"));
    }
    let list: PeerList = serde_json::from_slice(body).map_err(|e| format!("the fetched peer list: {e}"))?;
    list.validate(net)?;
    if list.version <= current.version {
        return Err(format!("the fetched peer list (version {}) is not newer than version {}", list.version, current.version));
    }
    if list.signature.is_none() || list.key_id.is_none() {
        return Err("the fetched peer list is not signed".into());
    }
    verify(&list)?;
    Ok(list)
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

/// set_own_peers' argument: a JSON array of `host[:port]`, duplicates dropped.
pub fn parse_own(net: BNetwork, json: &str) -> Result<Vec<String>, String> {
    let items: Vec<String> = serde_json::from_str(json).map_err(|e| format!("peers must be a JSON array of host:port strings: {e}"))?;
    if items.len() > MAX_OWN_PEERS {
        return Err(format!("at most {MAX_OWN_PEERS} peers of your own"));
    }
    let mut out: Vec<String> = Vec::new();
    for i in items {
        let p = normalize_peer(net, &i)?;
        if !out.contains(&p) {
            out.push(p);
        }
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

/// What Kyoto dials today: your own peers, which replace the list, or up to 8 of the list's that
/// its route reaches, picked afresh each UTC day and per install.
pub fn subset(list: &PeerList, own: &[String], tor: bool, salt: &str, net: BNetwork, day: u64) -> Vec<String> {
    if !own.is_empty() {
        return own.to_vec();
    }
    let mut usable: Vec<&String> = list.peers.iter().filter(|p| is_onion(peer_host(p)) == tor).collect();
    for i in (1..usable.len()).rev() {
        let mut h = Sha256::new();
        h.update(salt.as_bytes());
        h.update([0]);
        h.update(net.name().as_bytes());
        h.update(day.to_be_bytes());
        h.update((i as u64).to_be_bytes());
        let d = h.finalize();
        let r = u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]);
        usable.swap(i, (r % (i as u64 + 1)) as usize);
    }
    usable.into_iter().take(SUBSET).cloned().collect()
}

/// The UTC day number of unix time `now`.
pub fn today(now: u64) -> u64 {
    now / 86_400
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Made-up onion names (qqqq...), for tests only: no real peer is listed anywhere in this crate.
    fn fake_onions(n: usize) -> Vec<String> {
        const B32: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        (0..n).map(|i| {
            let tail: String = (0..4).rev().map(|k| B32[(i >> (5 * k)) & 31] as char).collect();
            format!("{}{tail}.onion:8333", "q".repeat(52))
        }).collect()
    }

    fn list_of(peers: Vec<String>) -> PeerList {
        PeerList { peers, ..shipped(BNetwork::Mainnet) }
    }

    #[test]
    fn shipped_lists_are_empty_versioned_and_explained() {
        for net in [BNetwork::Mainnet, BNetwork::Testnet4, BNetwork::Signet, BNetwork::Regtest] {
            let l = shipped(net);
            l.validate(net).unwrap();
            assert!(l.peers.is_empty() && l.version == 0 && l.signature.is_none() && l.refresh_url.is_none(), "{net:?}");
            assert!(l.note.contains("set_own_peers"), "{net:?}");
        }
        assert!(shipped(BNetwork::Mainnet).note.contains("crawler"));
        let v = serde_json::to_value(shipped(BNetwork::Signet)).unwrap();
        assert_eq!((&v["version"], &v["format"]), (&serde_json::json!("0"), &serde_json::json!(1)));
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
    fn todays_subset() {
        let list = list_of(fake_onions(30));
        list.validate(BNetwork::Mainnet).unwrap();
        let a = subset(&list, &[], true, "salt1", BNetwork::Mainnet, 20_000);
        assert_eq!(a.len(), SUBSET);
        assert_eq!(a, subset(&list, &[], true, "salt1", BNetwork::Mainnet, 20_000), "stable within a day");
        assert_ne!(a, subset(&list, &[], true, "salt1", BNetwork::Mainnet, 20_001), "new each day");
        assert_ne!(a, subset(&list, &[], true, "salt2", BNetwork::Mainnet, 20_000), "per install");
        assert!(a.iter().all(|p| list.peers.contains(p)));
        assert!(subset(&list, &[], false, "salt1", BNetwork::Mainnet, 20_000).is_empty(), "onion peers need Tor");
        assert_eq!(subset(&list_of(fake_onions(3)), &[], true, "s", BNetwork::Mainnet, 1).len(), 3);
        let own = vec!["192.168.1.20:8333".to_string()];
        assert_eq!(subset(&list, &own, true, "salt1", BNetwork::Mainnet, 20_000), own, "your peers replace the list");
        assert_eq!(today(86_400 * 3 + 5), 3);
    }

    #[test]
    fn fetched_lists_need_a_newer_version_and_a_signature() {
        let current = shipped(BNetwork::Mainnet);
        let mut newer = PeerList { version: 3, date: Some("2026-10-10".into()), key_id: Some("k1".into()), signature: Some("00".into()), ..current.clone() };
        let body = serde_json::to_vec(&newer).unwrap();
        let ok: fn(&PeerList) -> Result<(), String> = |_| Ok(());
        assert_eq!(accept(BNetwork::Mainnet, &current, &body, ok).unwrap(), newer);
        assert!(accept(BNetwork::Mainnet, &current, &body, verify_stub).unwrap_err().contains("stub"));
        assert!(accept(BNetwork::Signet, &current, &body, ok).unwrap_err().contains("for mainnet"));
        assert!(accept(BNetwork::Mainnet, &newer, &body, ok).unwrap_err().contains("not newer"));
        newer.signature = None;
        assert!(accept(BNetwork::Mainnet, &current, &serde_json::to_vec(&newer).unwrap(), ok).unwrap_err().contains("not signed"));
        newer.peers = vec!["192.168.1.20:8333".into()];
        assert!(accept(BNetwork::Mainnet, &current, &serde_json::to_vec(&newer).unwrap(), ok).is_err(), "no LAN peer in a curated list");
        assert!(accept(BNetwork::Mainnet, &current, b"{", ok).is_err());
        // The signature covers everything but itself.
        let signed = PeerList { signature: Some("ff".into()), ..current.clone() };
        assert_eq!(signed.signed_message(), current.signed_message());
        assert!(!String::from_utf8(current.signed_message()).unwrap().contains("\"signature\":\"ff\""));
    }
}
