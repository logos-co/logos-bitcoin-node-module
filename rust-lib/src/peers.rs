//! Kyoto's peers: the curated list per network (versioned, signed with a key compiled in here),
//! the user's own peers, which replace it, and the peers Kyoto's route can use.

use std::net::IpAddr;
use std::sync::OnceLock;

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

use crate::addr;
use crate::net::client::{is_lan_host, is_onion, Route};
use crate::network::BNetwork;

pub const FORMAT: u32 = 1;
pub const MAX_OWN_PEERS: usize = 16;
pub const MAX_LIST_PEERS: usize = 1024;
pub const MAX_LIST_BYTES: usize = 256 * 1024;
/// In front of the canonical JSON, so a list key's signature means nothing anywhere else.
pub const DOMAIN: &[u8] = b"logos-bitcoin-peer-list/1\n";
/// The public half of the TEST key the crawler (logos-bitcoin-peer-list) signs with. The release
/// key is not chosen yet; it replaces this one.
const TEST_KEY: &str = include_str!("../keys/peer-list-test-key.pub.json");

/// A curated peer list as the crawler publishes it. The signature covers `signed_message()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeerList {
    pub format: u32,
    pub network: BNetwork,
    /// Grows with each release; a fetched list replaces this one only when newer.
    #[serde(serialize_with = "crate::strnum::ser", deserialize_with = "crate::strnum::de")]
    pub version: u64,
    /// When the crawler built and signed it, YYYY-MM-DDTHH:MM:SSZ.
    pub created: Option<String>,
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
        if self.created.as_deref().is_some_and(|t| !time_ok(t)) {
            return Err("peer list: created must be YYYY-MM-DDTHH:MM:SSZ".into());
        }
        if let Some(u) = &self.refresh_url {
            crate::addr::esplora(u).map_err(|e| format!("peer list refreshUrl: {e}"))?;
        }
        Ok(())
    }

    /// The bytes a signature covers: `DOMAIN`, then this list with `signature` null, as compact
    /// JSON in field order (the crawler's canonical bytes).
    pub fn signed_message(&self) -> Vec<u8> {
        let unsigned = PeerList { signature: None, ..self.clone() };
        let mut m = DOMAIN.to_vec();
        m.extend(serde_json::to_vec(&unsigned).unwrap_or_default());
        m
    }

    fn empty(net: BNetwork, note: &str) -> Self {
        Self { format: FORMAT, network: net, version: 0, created: None, date: None, note: note.into(), refresh_url: None, peers: vec![], key_id: None, signature: None }
    }
}

/// The keys a list may be signed with, as (key id, Ed25519 public key): the TEST key only.
fn list_keys() -> &'static [(String, Vec<u8>)] {
    static KEYS: OnceLock<Vec<(String, Vec<u8>)>> = OnceLock::new();
    KEYS.get_or_init(|| {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Key {
            key_id: String,
            ed25519: String,
        }
        let k: Key = serde_json::from_str(TEST_KEY).expect("the compiled-in list key parses (see tests)");
        let pk = hex::decode(&k.ed25519).ok().filter(|p| p.len() == 32).expect("the compiled-in list key is 32 bytes of hex");
        vec![(k.key_id, pk)]
    })
}

/// Checks `signature` over `signed_message()` with the key `keyId` names, among `keys`.
pub fn verify_with(list: &PeerList, keys: &[(String, Vec<u8>)]) -> Result<(), String> {
    let id = list.key_id.as_deref().ok_or("the peer list is not signed")?;
    let (_, pk) = keys.iter().find(|(k, _)| k == id).ok_or_else(|| format!("the peer list is signed with an unknown key {id}"))?;
    let sig = list.signature.as_deref().and_then(|s| hex::decode(s).ok()).filter(|s| s.len() == 64).ok_or("the peer list's signature is not 64 bytes of hex")?;
    UnparsedPublicKey::new(&ED25519, pk).verify(&list.signed_message(), &sig).map_err(|_| "the peer list's signature does not check".to_string())
}

/// Checks a list against the keys compiled into this build.
pub fn verify(list: &PeerList) -> Result<(), String> {
    verify_with(list, list_keys())
}

fn load_shipped(net: BNetwork, text: &str) -> PeerList {
    let list: PeerList = serde_json::from_str(text).expect("the shipped peer lists parse (see tests)");
    // An unsigned, empty placeholder may ship; a list with peers is used only if its signature checks.
    if list.peers.is_empty() && list.signature.is_none() {
        return list;
    }
    match list.validate(net).and_then(|_| verify(&list)) {
        Ok(()) => list,
        Err(e) => PeerList::empty(net, &format!("The shipped list was refused ({e}): add your own node with set_own_peers.")),
    }
}

/// The list this build ships, checked once: signed lists for mainnet and signet, a placeholder
/// for testnet4, none for regtest.
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

/// Every peer Kyoto's route can use: your own peers, which replace the list, or the list's peers
/// that route reaches (onion peers through Tor). The wallet core draws its own 8 per start.
pub fn usable(list: &PeerList, own: &[String], tor: bool) -> Vec<String> {
    if !own.is_empty() {
        return own.to_vec();
    }
    list.peers.iter().filter(|p| is_onion(peer_host(p)) == tor).cloned().collect()
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

    fn list_of(peers: Vec<String>) -> PeerList {
        PeerList { peers, ..shipped(BNetwork::Mainnet) }
    }

    /// A key for tests only, from a fixed seed: what it signs checks with `verify_fixture`,
    /// never with the keys this build ships.
    fn fixture() -> (ring::signature::Ed25519KeyPair, Vec<(String, Vec<u8>)>) {
        use ring::signature::KeyPair;
        let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).unwrap();
        let keys = vec![("fixture-1".to_string(), pair.public_key().as_ref().to_vec())];
        (pair, keys)
    }

    pub(crate) fn sign_fixture(mut l: PeerList) -> PeerList {
        l.key_id = Some("fixture-1".into());
        l.signature = None;
        l.signature = Some(hex::encode(fixture().0.sign(&l.signed_message()).as_ref()));
        l
    }

    pub(crate) fn verify_fixture(l: &PeerList) -> Result<(), String> {
        verify_with(l, &fixture().1)
    }

    /// A fixture-signed list of made-up onions.
    pub(crate) fn signed(net: BNetwork, version: u64, note: &str) -> PeerList {
        let l = PeerList { version, created: Some("2026-10-11T02:00:00Z".into()), date: Some("2026-10-11".into()), peers: fake_onions(3), ..PeerList::empty(net, note) };
        sign_fixture(l)
    }

    #[test]
    fn shipped_lists_are_signed_with_the_test_key_or_explained() {
        let test_key = &list_keys()[0].0;
        assert!(test_key.starts_with("test-"), "{test_key}");
        for net in [BNetwork::Mainnet, BNetwork::Signet] {
            let l = shipped(net);
            l.validate(net).unwrap();
            verify(&l).unwrap();
            assert!(!l.peers.is_empty() && l.version > 0 && l.key_id.as_ref() == Some(test_key), "{net:?}");
            assert!(l.peers.iter().all(|p| is_onion(peer_host(p))), "{net:?}: onion v3 only");
            assert!(l.created.is_some() && l.note.contains("TEST key"), "{net:?}");
        }
        for net in [BNetwork::Testnet4, BNetwork::Regtest] {
            let l = shipped(net);
            l.validate(net).unwrap();
            assert!(l.peers.is_empty() && l.version == 0 && l.signature.is_none(), "{net:?}");
            assert!(l.note.contains("set_own_peers"), "{net:?}");
        }
        // A shipped list whose signature fails is replaced by an empty one that says why.
        let mut bad = shipped(BNetwork::Signet);
        bad.peers.pop();
        let refused = load_shipped(BNetwork::Signet, &serde_json::to_string(&bad).unwrap());
        assert!(refused.peers.is_empty() && refused.note.contains("does not check"), "{}", refused.note);
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
    fn the_whole_usable_list() {
        let list = list_of(fake_onions(30));
        list.validate(BNetwork::Mainnet).unwrap();
        assert_eq!(usable(&list, &[], true), list.peers, "every listed peer: the wallet core picks its own 8");
        assert!(usable(&list, &[], false).is_empty(), "onion peers need Tor");
        let own = vec!["192.168.1.20:8333".to_string()];
        assert_eq!(usable(&list, &own, true), own, "your peers replace the list");
    }

    #[test]
    fn a_good_list_is_kept() {
        let current = shipped(BNetwork::Mainnet);
        let good = signed(BNetwork::Mainnet, current.version + 1, "good");
        let body = serde_json::to_vec(&good).unwrap();
        assert_eq!(accept(BNetwork::Mainnet, &current, &body, verify_fixture).unwrap(), good);
        // This build's keys do not include the fixture key.
        assert!(accept(BNetwork::Mainnet, &current, &body, verify).unwrap_err().contains("unknown key fixture-1"));
    }

    #[test]
    fn a_bad_signature_is_refused() {
        let current = shipped(BNetwork::Mainnet);
        let good = signed(BNetwork::Mainnet, current.version + 1, "good");
        let check = |l: &PeerList| accept(BNetwork::Mainnet, &current, &serde_json::to_vec(l).unwrap(), verify_fixture);
        let mut more = good.clone();
        more.peers.push(fake_onions(4)[3].clone());
        assert!(check(&more).unwrap_err().contains("does not check"), "a peer added after signing");
        let mut flipped = good.clone();
        let sig = flipped.signature.take().unwrap();
        flipped.signature = Some(format!("{}{}", if sig.starts_with('0') { "1" } else { "0" }, &sig[1..]));
        assert!(check(&flipped).unwrap_err().contains("does not check"));
        let short = PeerList { signature: Some("00".into()), ..good.clone() };
        assert!(check(&short).unwrap_err().contains("64 bytes"));
        let unsigned = PeerList { signature: None, ..good.clone() };
        assert!(check(&unsigned).unwrap_err().contains("not signed"));
        // The bare JSON, without the domain tag, is not what a list key signs.
        let mut bare = good.clone();
        bare.signature = Some(hex::encode(fixture().0.sign(&bare.signed_message()[DOMAIN.len()..]).as_ref()));
        assert!(check(&bare).unwrap_err().contains("does not check"));
    }

    #[test]
    fn the_wrong_network_is_refused() {
        let current = shipped(BNetwork::Mainnet);
        let list = signed(BNetwork::Signet, current.version + 1, "signet");
        let e = accept(BNetwork::Mainnet, &current, &serde_json::to_vec(&list).unwrap(), verify_fixture).unwrap_err();
        assert!(e.contains("for signet, not mainnet"), "{e}");
        // Relabelled as mainnet, its signature no longer checks.
        let relabelled = PeerList { network: BNetwork::Mainnet, ..list };
        assert!(accept(BNetwork::Mainnet, &current, &serde_json::to_vec(&relabelled).unwrap(), verify_fixture).unwrap_err().contains("does not check"));
    }

    #[test]
    fn an_old_version_is_refused() {
        let current = shipped(BNetwork::Mainnet);
        for version in [current.version, current.version - 1] {
            let old = signed(BNetwork::Mainnet, version, "old");
            let e = accept(BNetwork::Mainnet, &current, &serde_json::to_vec(&old).unwrap(), verify_fixture).unwrap_err();
            assert!(e.contains("not newer"), "{version}: {e}");
        }
        // Nor does a stored list shadow a newer shipped one.
        let mut cfg = crate::store::NetConfig::seeded(BNetwork::Mainnet);
        cfg.peer_list = Some(signed(BNetwork::Mainnet, current.version - 1, "stored"));
        assert_eq!(cfg.peer_list(BNetwork::Mainnet), current);
        cfg.peer_list = Some(signed(BNetwork::Mainnet, current.version + 1, "stored"));
        assert_eq!(cfg.peer_list(BNetwork::Mainnet).version, current.version + 1);
    }

    #[test]
    fn malformed_lists_are_refused() {
        let current = shipped(BNetwork::Mainnet);
        let mut lan = signed(BNetwork::Mainnet, current.version + 1, "lan");
        lan.peers = vec!["192.168.1.20:8333".into()];
        let lan = sign_fixture(lan);
        assert!(accept(BNetwork::Mainnet, &current, &serde_json::to_vec(&lan).unwrap(), verify_fixture).is_err(), "no LAN peer in a curated list");
        assert!(accept(BNetwork::Mainnet, &current, b"{", verify_fixture).is_err());
        let bad_time = sign_fixture(PeerList { created: Some("2026-10-11 02:00".into()), ..signed(BNetwork::Mainnet, current.version + 1, "t") });
        assert!(accept(BNetwork::Mainnet, &current, &serde_json::to_vec(&bad_time).unwrap(), verify_fixture).unwrap_err().contains("created"));
    }

    #[test]
    fn the_signed_bytes() {
        let l = signed(BNetwork::Signet, 7, "n");
        let m = String::from_utf8(l.signed_message()).unwrap();
        assert!(m.starts_with("logos-bitcoin-peer-list/1\n{\"format\":1,\"network\":\"signet\",\"version\":\"7\",\"created\":\"2026-10-11T02:00:00Z\",\"date\":\"2026-10-11\",\"note\":\"n\","), "{m}");
        assert!(m.ends_with(",\"keyId\":\"fixture-1\",\"signature\":null}"), "{m}");
        // The signature covers everything but itself.
        assert_eq!(PeerList { signature: Some("ff".into()), ..l.clone() }.signed_message(), l.signed_message());
    }
}
