use super::*;
use crate::health::Observed;
use crate::sources::{KYOTO_ID, LOCAL_URL};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Instant;

struct Harness {
    node: Arc<Node>,
    events: Arc<Mutex<Vec<String>>>,
    dir: tempfile::TempDir,
}

fn sink_into(log: Arc<Mutex<Vec<String>>>) -> Sink {
    Arc::new(move |e| {
        let line = match e {
            Event::HealthChanged { network, payload } => {
                let v: Value = serde_json::from_str(&payload).unwrap();
                format!("health {} {}", network.name(), v["overall"].as_str().unwrap())
            }
            Event::RoutesChanged { network } => format!("routes {}", network.name()),
            Event::Suspect { network, source_id, kind } => format!("suspect {} {source_id} {kind}", network.name()),
        };
        log.lock().unwrap().push(line);
    })
}

fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let events: Arc<Mutex<Vec<String>>> = Arc::default();
    let node = Node::open(Some(dir.path().join(crate::store::FILE_NAME)), sink_into(events.clone()));
    Harness { node, events, dir }
}

/// Configured with the defaults, `identifying` chosen on every network, the built-in Tor ready at
/// `TOR`, and the events so far dropped.
fn configured() -> Harness {
    let h = harness();
    assert_eq!(v(h.node.init_defaults())["ok"], true);
    h.tor_use("identifying");
    h.node.set_tor(tor_view("ready", Some(TOR)));
    h.take();
    h
}

/// The built-in Tor as tor_module would report it.
fn tor_view(state: &str, socks: Option<&str>) -> TorView {
    TorView { state: state.into(), progress: if state == "ready" { 100 } else { 40 }, detail: String::new(), socks: socks.map(String::from), answered: true }
}

impl Harness {
    /// The same Use Tor for on every network.
    fn tor_use(&self, mode: &str) {
        for net in networks() {
            assert_eq!(v(self.node.set_tor_use(net.name(), mode))["ok"], true, "{}", net.name());
        }
    }

    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }
}

fn v(s: String) -> Value {
    serde_json::from_str(&s).unwrap()
}

fn ids(v: &Value, role: &str) -> Vec<String> {
    v[role].as_array().unwrap_or_else(|| panic!("{role} in {v}")).iter().map(|r| r["id"].as_str().unwrap().to_string()).collect()
}

fn route_of(v: &Value, role: &str, id: &str) -> String {
    v[role].as_array().unwrap().iter().find(|r| r["id"] == id).map(|r| r["route"].as_str().unwrap().to_string()).unwrap_or_default()
}

/// The `peer` of each route_table `peers` entry (or peer_list `usable`).
fn peer_strings(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(|p| p["peer"].as_str().unwrap().to_string()).collect()
}

fn onion() -> String {
    format!("{}.onion", "a2".repeat(28))
}

const TOR: &str = "socks5h://127.0.0.1:9050";

#[test]
fn starts_unconfigured_and_init_defaults_fills_only_what_is_absent() {
    let h = harness();
    let st = v(h.node.config_status());
    assert_eq!((st["state"].as_str(), &st["proxySet"]), (Some("unconfigured"), &json!(false)));
    assert!(v(h.node.route_table("mainnet"))["error"].as_str().unwrap().contains("init_defaults"));
    assert_eq!(v(h.node.get_sources("mainnet"))["configured"], false);
    assert_eq!(v(h.node.list_networks())["networks"], json!(["mainnet", "testnet4", "signet"]));

    let applied = v(h.node.init_defaults());
    assert_eq!(applied["applied"], json!(["proxy", "mainnet.sources", "testnet4.sources", "signet.sources"]));
    assert_eq!(h.take().iter().filter(|e| e.starts_with("routes")).count(), 3);
    assert_eq!(v(h.node.config_status())["state"], "configured");
    // A second call has nothing to fill; a user's choices are never reset.
    h.node.set_proxy("socks5h://127.0.0.1:19050");
    h.node.set_source("mainnet", KYOTO_ID, r#"{"use":false}"#);
    assert_eq!(v(h.node.init_defaults())["applied"], json!([]));
    let s = v(h.node.get_sources("mainnet"));
    assert_eq!((s["proxy"].as_str(), &s["sources"][0]["use"]), (Some("socks5h://127.0.0.1:19050"), &json!(false)));
    // A cleared proxy stays cleared.
    h.node.set_proxy("");
    assert_eq!(v(h.node.init_defaults())["applied"], json!([]));
    assert_eq!(v(h.node.get_sources("mainnet"))["proxy"], Value::Null);
    assert_eq!(v(h.node.config_status())["state"], "configured");
}

#[test]
fn unready_until_every_network_and_the_proxy_are_set() {
    let h = harness();
    h.node.set_proxy(TOR);
    assert_eq!(v(h.node.config_status())["state"], "unready");
    let one = r#"[{"id":"kyoto","kind":"kyoto"}]"#;
    for net in ["mainnet", "testnet4"] {
        assert_eq!(v(h.node.set_sources(net, one))["configured"], true);
    }
    let st = v(h.node.config_status());
    assert_eq!((st["state"].as_str(), &st["unconfigured"]), (Some("unready"), &json!(["signet"])));
    assert_eq!(v(h.node.init_defaults())["applied"], json!(["signet.sources"]));
    assert_eq!(v(h.node.config_status())["state"], "configured");
    assert_eq!(v(h.node.get_sources("mainnet"))["sources"].as_array().unwrap().len(), 1, "kept, not defaulted");
}

#[test]
fn the_default_route_table() {
    let h = configured();
    let rt = v(h.node.route_table("mainnet"));
    assert_eq!(rt["proxy"], TOR);
    assert_eq!(ids(&rt, "chain"), ["kyoto"]);
    assert_eq!(ids(&rt, "history"), ["kyoto"], "no server is asked about addresses");
    assert!(ids(&rt, "pending").is_empty());
    assert_eq!(ids(&rt, "fees"), ["electrum.blockstream.info-onion", "kyoto"]);
    assert_eq!(ids(&rt, "broadcast"), ["kyoto"]);
    assert_eq!(ids(&rt, "check"), ["electrum.blockstream.info-onion"]);
    assert_eq!((route_of(&rt, "fees", "electrum.blockstream.info-onion"), route_of(&rt, "chain", "kyoto")), ("onion".into(), "onion".into()));
    assert!(rt.get("crossCheck").is_none() && v(h.node.get_sources("mainnet")).get("crossCheck").is_none(), "an older core only printed it");
    let shipped = peers::shipped(BNetwork::Mainnet);
    assert_eq!(peer_strings(&rt["peers"]), shipped.peers, "the whole curated list: the wallet core picks its own 8");
    assert!(rt["peers"].as_array().unwrap().iter().all(|p| p["source"] == "list" && p["ok"] == false), "none worked yet");
    assert_eq!(rt["unrouted"], json!([]));
    let entry = &rt["fees"][0];
    assert_eq!(entry.as_object().unwrap().keys().cloned().collect::<Vec<_>>(), ["id", "kind", "operator", "route", "url"]);
    for role in ["chain", "history", "pending", "fees", "broadcast", "check"] {
        assert!(rt[role].as_array().unwrap().iter().all(|e| e["id"] != "electrum.blockstream.info"), "{role}: a disabled source is never routed");
    }
    assert_eq!(ids(&v(h.node.route_table("testnet4")), "fees"), ["electrum-testnet4-onion", "kyoto"]);
    let signet = v(h.node.route_table("signet"));
    assert_eq!((ids(&signet, "fees"), ids(&signet, "check")), (vec!["kyoto".to_string()], vec![]), "Kyoto alone, its fee the relay floor");
    assert_eq!(route_of(&v(h.node.route_table("testnet4")), "fees", "electrum-testnet4-onion"), "onion");
}

/// Every combination of tor, lan and onion, with the proxy set and without it.
#[test]
fn routes_for_every_combination_of_tor_lan_and_onion() {
    let h = configured();
    let o = onion();
    let list = json!([
        {"id": "public-tor", "kind": "electrum", "url": "electrum.example", "tor": true},
        {"id": "public-direct", "kind": "electrum", "url": "direct.example", "tor": false},
        {"id": "lan-tor", "kind": "electrum", "url": "192.168.1.20:50001", "tor": true},
        {"id": "lan-direct", "kind": "electrum", "url": "tcp://192.168.1.21:50001", "tor": false},
        {"id": "lan-name", "kind": "electrum", "url": "tcp://umbrel.local:50001"},
        {"id": "onion-tor", "kind": "electrum", "url": format!("{o}:110"), "tor": true},
    ]);
    let s = v(h.node.set_sources("signet", &list.to_string()));
    assert_eq!(s["ok"], true, "{s}");
    let lan: Vec<(String, bool, String)> = s["sources"].as_array().unwrap().iter().map(|x| (x["id"].as_str().unwrap().into(), x["lan"].as_bool().unwrap(), x["route"].as_str().unwrap().into())).collect();
    assert_eq!(lan, [
        ("public-tor".into(), false, "tor".into()),
        ("public-direct".into(), false, "direct".into()),
        ("lan-tor".into(), true, "direct".into()),
        ("lan-direct".into(), true, "direct".into()),
        ("lan-name".into(), true, "direct".into()),
        ("onion-tor".into(), false, "onion".into()),
    ]);
    // An onion service with Tor off is refused, and nothing changes.
    let refused = json!([{"id": "onion-direct", "kind": "electrum", "url": format!("{o}:110"), "tor": false}]);
    assert!(v(h.node.set_sources("signet", &refused.to_string()))["error"].as_str().unwrap().contains("through Tor only"));
    assert!(v(h.node.set_source("signet", "onion-tor", r#"{"tor":false}"#))["error"].as_str().unwrap().contains("through Tor only"));

    let all = ["public-tor", "public-direct", "lan-tor", "lan-direct", "lan-name", "onion-tor"];
    let rt = v(h.node.route_table("signet"));
    assert_eq!(ids(&rt, "check"), all, "with the proxy every source is routed");
    assert_eq!(ids(&rt, "chain"), all, "Electrum servers define the chain with Kyoto absent");
    for (id, route) in [("public-tor", "tor"), ("public-direct", "direct"), ("lan-tor", "direct"), ("lan-direct", "direct"), ("lan-name", "direct"), ("onion-tor", "onion")] {
        assert_eq!(route_of(&rt, "check", id), route, "{id}");
    }
    assert_eq!(s["withoutTor"].as_array().unwrap().iter().map(|n| n["id"].as_str().unwrap()).collect::<Vec<_>>(), ["public-direct"]);

    // Without a proxy, Tor routes fail closed; direct ones stay.
    h.node.set_proxy("");
    let rt = v(h.node.route_table("signet"));
    assert_eq!(rt["proxy"], Value::Null);
    assert_eq!(ids(&rt, "check"), ["public-direct", "lan-tor", "lan-direct", "lan-name"]);
    let unrouted: Vec<(&str, &str)> = rt["unrouted"].as_array().unwrap().iter().map(|u| (u["id"].as_str().unwrap(), u["reason"].as_str().unwrap())).collect();
    assert_eq!(unrouted, [("public-tor", NO_PROXY), ("onion-tor", NO_PROXY)]);
    let (targets, skipped) = h.node.poll_plan();
    let signet: Vec<(&str, Route, Option<&str>)> = targets.iter().filter(|t| t.network == BNetwork::Signet).map(|t| (t.id.as_str(), t.route, t.proxy.as_deref())).collect();
    assert_eq!(signet, [("public-direct", Route::Direct, None), ("lan-tor", Route::Direct, None), ("lan-direct", Route::Direct, None), ("lan-name", Route::Direct, None)]);
    let skipped: Vec<&str> = skipped.iter().filter(|(t, _)| t.network == BNetwork::Signet).map(|(t, _)| t.id.as_str()).collect();
    assert_eq!(skipped, ["public-tor", "onion-tor"]);
    // And with it back, the Tor routes carry it and the direct ones never do.
    h.node.set_proxy(TOR);
    let (targets, _) = h.node.poll_plan();
    for t in targets.iter().filter(|t| t.network == BNetwork::Signet) {
        assert_eq!(t.proxy.is_some(), matches!(t.route, Route::Tor | Route::Onion), "{}", t.id);
    }
}

#[test]
fn kyoto_routes_with_its_peers() {
    let h = configured();
    let peers = |n: &str| v(h.node.peer_list(n));
    let p = peers("signet");
    let shipped = peers::shipped(BNetwork::Signet);
    assert_eq!((p["route"].as_str(), &p["list"]["version"]), (Some("onion"), &json!(shipped.version.to_string())));
    assert_eq!(peer_strings(&p["usable"]), shipped.peers);
    // A fixed seed the list also names counts as a list peer.
    let seeds = peers::fixed_seeds(BNetwork::Signet).iter().filter(|p| !shipped.peers.contains(p)).count();
    assert_eq!(p["counts"], json!({"list": shipped.peers.len(), "learned": 0, "seed": seeds, "usable": shipped.peers.len(), "okLast30d": 0}));
    let kh = &v(h.node.source_health("signet"))["sources"][0];
    assert_eq!((kh["state"].as_str(), kh["peers"].as_str()), (Some("not_probed"), Some(shipped.peers.len().to_string().as_str())));
    // Your node on your network: Kyoto dials it directly, and needs no proxy.
    let p = v(h.node.set_own_peers("signet", r#"["192.168.1.20"]"#));
    let own = json!([{"peer": "192.168.1.20:38333", "source": "own", "ok": false}]);
    assert_eq!((p["ownPeers"].clone(), p["usable"].clone(), p["route"].as_str()), (json!(["192.168.1.20:38333"]), own.clone(), Some("direct")));
    h.node.set_proxy("");
    let rt = v(h.node.route_table("signet"));
    assert_eq!((ids(&rt, "chain"), route_of(&rt, "chain", "kyoto"), rt["peers"].clone()), (vec!["kyoto".to_string()], "direct".into(), own));
    assert_eq!(v(h.node.get_sources("signet"))["sources"][0]["lan"], true);
    let kh = &v(h.node.source_health("signet"))["sources"][0];
    assert_eq!((kh["state"].as_str(), kh["peers"].as_str()), (Some("not_probed"), Some("1")));
    // One connection type: your network and Tor do not mix.
    assert!(v(h.node.set_own_peers("signet", r#"["192.168.1.20","203.0.113.5"]"#))["error"].as_str().unwrap().contains("one connection type"));
    h.node.set_proxy(TOR);
    let public = format!(r#"["203.0.113.5","{}"]"#, onion());
    assert_eq!(v(h.node.set_own_peers("signet", &public))["route"], "tor");
    assert!(v(h.node.set_source("signet", KYOTO_ID, r#"{"tor":false}"#))["error"].as_str().unwrap().contains("through Tor only"));
    assert_eq!(v(h.node.set_own_peers("signet", r#"["203.0.113.5"]"#))["route"], "tor");
    let s = v(h.node.set_source("signet", KYOTO_ID, r#"{"tor":false}"#));
    assert_eq!(s["withoutTor"][0]["id"], "kyoto", "Kyoto reached without Tor is listed");
    assert_eq!(v(h.node.peer_list("signet"))["route"], "direct");
    // Without a proxy, a Kyoto routed through Tor has no route and holds no peers.
    h.node.set_source("signet", KYOTO_ID, r#"{"tor":true}"#);
    h.node.set_proxy("");
    let rt = v(h.node.route_table("signet"));
    assert!(ids(&rt, "chain").is_empty() && rt["peers"] == json!([]));
    assert_eq!(rt["unrouted"][0], json!({"id": "kyoto", "reason": NO_PROXY}));
    // Back to the curated list.
    h.node.set_proxy(TOR);
    assert_eq!(v(h.node.set_own_peers("signet", "[]"))["route"], "onion");
    assert!(v(h.node.set_own_peers("signet", r#"["seed.example.org"]"#))["error"].as_str().unwrap().contains("outside Tor"));
}

#[test]
fn history_exposes_addresses_and_credentials_never_come_back() {
    let h = configured();
    let s = v(h.node.set_source("mainnet", "electrum.blockstream.info", r#"{"use":true,"history":true}"#));
    assert_eq!(s["exposes"], json!([{"id": "electrum.blockstream.info", "url": "ssl://electrum.blockstream.info:50002", "operator": "blockstream.info", "lan": false}]));
    let rt = v(h.node.route_table("mainnet"));
    assert_eq!((ids(&rt, "history"), ids(&rt, "pending")), (vec!["kyoto".to_string(), "electrum.blockstream.info".into()], vec!["electrum.blockstream.info".to_string()]));
    assert_eq!(ids(&rt, "broadcast"), ["kyoto"], "Kyoto broadcasts while it is on");

    let mut list = s["sources"].clone();
    list.as_array_mut().unwrap().push(json!({"id": "mine", "kind": "rpc", "url": "https://me:s3cret@node.example"}));
    let s = v(h.node.set_sources("mainnet", &list.to_string()));
    let text = s.to_string();
    assert!(!text.contains("s3cret") && !text.contains("me:"), "{text}");
    let mine = s["sources"].as_array().unwrap().iter().find(|x| x["id"] == "mine").unwrap().clone();
    assert_eq!((mine["url"].as_str(), &mine["hasCredentials"]), (Some("https://node.example"), &json!(true)));
    for read in [h.node.get_sources("mainnet"), h.node.route_table("mainnet"), h.node.source_health("mainnet")] {
        assert!(!read.contains("s3cret"), "{read}");
    }
    assert_eq!(v(h.node.route_table("mainnet"))["chain"][0], json!({"id": "mine", "kind": "rpc", "url": "https://node.example", "operator": "node.example", "route": "tor", "credentials": true, "userAdded": true}));
    // A round trip of what get_sources returned keeps them; only the wallet core reads them.
    let back = v(h.node.get_sources("mainnet"))["sources"].clone();
    h.node.set_sources("mainnet", &back.to_string());
    let c = v(h.node.source_credentials("mainnet", "mine"));
    assert_eq!((c["username"].as_str(), c["password"].as_str()), (Some("me"), Some("s3cret")));
    assert_eq!(v(h.node.source_credentials("mainnet", KYOTO_ID))["username"], Value::Null);
    assert!(std::fs::read_to_string(h.dir.path().join(crate::store::FILE_NAME)).unwrap().contains("s3cret"), "kept on disk, owner-only");
}

#[test]
fn settings_are_locked_while_a_wallet_is_open() {
    let h = configured();
    assert_eq!(v(h.node.set_wallet_open("signet", true))["walletOpen"], true);
    assert_eq!(v(h.node.get_sources("signet"))["walletOpen"], true);
    assert_eq!(v(h.node.config_status())["walletOpen"], json!(["signet"]));
    let before = h.node.get_sources("signet");
    for refused in [
        h.node.set_sources("signet", "[]"),
        h.node.set_source("signet", KYOTO_ID, r#"{"use":false}"#),
        h.node.set_own_peers("signet", r#"["192.168.1.20"]"#),
        h.node.set_proxy("socks5h://127.0.0.1:19050"),
    ] {
        assert_eq!(v(refused)["error"], LOCKED);
    }
    assert_eq!(h.node.get_sources("signet"), before, "nothing changed");
    // Another network's sources still change, but not the proxy every network shares.
    assert_eq!(v(h.node.set_source("mainnet", KYOTO_ID, r#"{"use":false}"#))["ok"], true);
    // Health stays live: reports, clearing suspects and probes go on.
    assert_eq!(v(h.node.report_mismatch("signet", "electrum.emzy.de", "anchor_mismatch", "325000"))["suspect"], true);
    assert_eq!(v(h.node.clear_suspect("signet", "electrum.emzy.de"))["cleared"], true);
    assert_eq!(v(h.node.init_defaults())["applied"], json!([]));
    h.node.set_wallet_open("signet", false);
    assert_eq!(v(h.node.set_source("signet", KYOTO_ID, r#"{"use":false}"#))["ok"], true);
    // Not kept across a restart: the backend says it again when a wallet opens.
    h.node.set_wallet_open("signet", true);
    let again = Node::open(Some(h.dir.path().join(crate::store::FILE_NAME)), Arc::new(|_| {}));
    assert_eq!(v(again.get_sources("signet"))["walletOpen"], false);
}

fn answer(net: BNetwork, tip: u64) -> Health {
    Health::observed(net, Observed { genesis: net.genesis().into(), tip_height: tip, tip_hash: "00".repeat(32), rtt_ms: 700, server_version: None }, now())
}

fn poll_all(node: &Node, f: impl Fn(&Target) -> Health) {
    let (targets, skipped) = node.poll_plan();
    for (t, why) in &skipped {
        node.record(t, Health::no_route(why, now()));
    }
    for t in &targets {
        node.record(t, f(t));
    }
    node.flush();
}

#[test]
fn health_events_suspects_and_wrong_networks() {
    let h = configured();
    h.node.set_source("mainnet", "electrum.blockstream.info", r#"{"use":true}"#);
    h.take();
    assert_eq!(v(h.node.source_health("mainnet"))["pending"], true);
    let ok = |t: &Target| answer(t.network, 970_838);
    poll_all(&h.node, ok);
    let events = h.take();
    assert!(events.contains(&"health mainnet ok".to_string()), "{events:?}: Kyoto has the curated peers and both servers answer");
    let sh = v(h.node.source_health("mainnet"));
    assert_eq!((&sh["pending"], sh["sources"][1]["tipHeight"].as_str(), sh["sources"][1]["state"].as_str()), (&json!(false), Some("970838"), Some("ok")));
    for key in ["state", "tipHeight", "tipHash", "rttMs", "route", "checkedAt", "error", "suspect"] {
        assert!(sh["sources"][1].get(key).is_some(), "{key}");
    }
    assert!(sh["sources"][1]["rttMs"].is_string() && sh["sources"][1]["checkedAt"].is_string());
    // The same answers again: nothing to report, though round trips and times moved.
    poll_all(&h.node, |t| Health { rtt_ms: Some(1), checked_at: Some(1), ..ok(t) });
    assert!(h.take().is_empty());

    // A suspect leaves the routes until the backend clears it.
    assert_eq!(v(h.node.report_mismatch("mainnet", "electrum.blockstream.info", "anchor_mismatch", ""))["suspect"], true);
    assert_eq!(h.take(), ["suspect mainnet electrum.blockstream.info anchor_mismatch", "routes mainnet", "health mainnet degraded"]);
    let rt = v(h.node.route_table("mainnet"));
    assert!(!ids(&rt, "check").contains(&"electrum.blockstream.info".to_string()));
    assert_eq!(rt["unrouted"], json!([{"id": "electrum.blockstream.info", "reason": SUSPECT}]));
    for bad in [h.node.report_mismatch("mainnet", "nope", "x", ""), h.node.report_mismatch("mainnet", KYOTO_ID, "", ""), h.node.report_mismatch("mainnet", KYOTO_ID, "a\nb", ""), h.node.report_mismatch("mainnet", KYOTO_ID, "x", "-1")] {
        assert_eq!(v(bad)["ok"], false);
    }
    assert_eq!(v(h.node.clear_suspect("mainnet", "electrum.blockstream.info"))["cleared"], true);
    assert_eq!(h.take(), ["routes mainnet", "health mainnet ok"], "cleared, and Kyoto has its peers");
    assert_eq!(v(h.node.clear_suspect("mainnet", "electrum.blockstream.info"))["cleared"], false);

    // A server on another network answers but is never routed.
    let signet_genesis = Observed { genesis: BNetwork::Signet.genesis().into(), tip_height: 270_000, tip_hash: "00".repeat(32), rtt_ms: 1, server_version: None };
    poll_all(&h.node, |t| match t.id.as_str() {
        "electrum.blockstream.info" => Health::observed(t.network, signet_genesis.clone(), now()),
        _ => ok(t),
    });
    let row = v(h.node.source_health("mainnet"))["sources"].as_array().unwrap().iter().find(|s| s["id"] == "electrum.blockstream.info").unwrap().clone();
    assert_eq!(row["state"], "wrong_network");
    assert_eq!(v(h.node.route_table("mainnet"))["unrouted"][0]["reason"], health::WRONG_NETWORK);
    // Two operators' tips 3 blocks apart disagree.
    h.node.set_source("mainnet", "electrum.blockstream.info", r#"{"use":false}"#);
    let mut list = v(h.node.get_sources("mainnet"))["sources"].clone();
    list.as_array_mut().unwrap().push(json!({"id": "other", "kind": "electrum", "url": "electrum.other.example"}));
    h.node.set_sources("mainnet", &list.to_string());
    poll_all(&h.node, |t| match t.id.as_str() {
        "other" => answer(t.network, 970_841),
        _ => ok(t),
    });
    assert_eq!(v(h.node.source_health("mainnet"))["overall"], "disagreement");
    // Without a proxy nothing is dialled: Tor sources read no_route.
    h.node.set_proxy("");
    poll_all(&h.node, ok);
    let sh = v(h.node.source_health("mainnet"));
    assert_eq!((sh["overall"].as_str(), sh["sources"][1]["state"].as_str()), (Some("offline"), Some("no_route")));
}

#[test]
fn state_persists() {
    let h = configured();
    h.node.set_proxy("socks5h://127.0.0.1:19050");
    h.node.set_own_peers("signet", r#"["10.0.0.2:38333"]"#);
    h.node.report_mismatch("mainnet", "electrum.blockstream.info-onion", "anchor_mismatch", "970000");
    let path = h.dir.path().join(crate::store::FILE_NAME);
    let again = Node::open(Some(path), Arc::new(|_| {}));
    for net in ["mainnet", "testnet4", "signet"] {
        assert_eq!(again.get_sources(net), h.node.get_sources(net));
        assert_eq!(again.route_table(net), h.node.route_table(net), "{net}: the same peers too");
        assert_eq!(again.peer_list(net), h.node.peer_list(net));
    }
    assert_eq!(v(again.source_health("mainnet"))["sources"][1]["suspectHeight"], "970000");
}

#[test]
fn many_peers_of_your_own() {
    let h = configured();
    const B32: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let onions: Vec<String> = (0..23).map(|i| format!("{}{}{}.onion:38333", "a2".repeat(27), B32[i / 32] as char, B32[i % 32] as char)).collect();
    let p = v(h.node.set_own_peers("signet", &serde_json::to_string(&onions).unwrap()));
    assert_eq!((p["ownPeers"].as_array().map(Vec::len), &p["route"]), (Some(23), &json!("onion")), "{p}");
    assert_eq!(peer_strings(&v(h.node.route_table("signet"))["peers"]), onions, "your peers replace the list, all of them");
    let again = Node::open(Some(h.dir.path().join(crate::store::FILE_NAME)), Arc::new(|_| {}));
    assert_eq!(v(again.peer_list("signet"))["ownPeers"], json!(onions), "kept across a restart");
}

/// A valid onion v3 name for `n` (checksum and all).
fn onion_v3(n: u8) -> String {
    crate::net::p2p::onion_from_key(&[n; 32])
}

#[test]
fn the_wallet_core_reports_on_kyotos_peers() {
    let h = configured();
    let shipped = peers::shipped(BNetwork::Signet);
    let (a, b) = (shipped.peers[0].clone(), shipped.peers[1].clone());
    let report = |j: Value| v(h.node.report_peers("signet", &j.to_string()));
    let r = report(json!({"outcomes": [{"peer": a, "ok": true}, {"peer": b, "ok": false, "reason": "timeout"}, {"peer": format!("{}:38333", onion_v3(1)), "ok": true}]}));
    assert_eq!(r["outcomes"], json!({"applied": 2, "unknown": 1}), "{r}");
    h.take();
    // The third failure in a row skips b for 24 h, and the routes say so.
    report(json!({"outcomes": [{"peer": b, "ok": false}, {"peer": b, "ok": false}]}));
    assert!(h.take().contains(&"routes signet".to_string()));
    let rt = v(h.node.route_table("signet"));
    let listed = peer_strings(&rt["peers"]);
    assert!(!listed.contains(&b) && listed.len() == shipped.peers.len() - 1);
    assert_eq!(rt["peers"][0], json!({"peer": a, "source": "list", "ok": true}), "the peer that worked first");
    // Learned peers: onion v3 with bits 0, 3 and 6, seen within 3 days; the rest refused.
    let seen = now().to_string();
    let learned = json!([
        {"addr": onion_v3(2), "port": 38333, "services": 1097, "seenAt": seen, "from": a},
        {"addr": "203.0.113.5", "port": 38333, "services": 73, "seenAt": now(), "from": a},
        {"addr": onion_v3(3), "port": 38333, "services": 9, "seenAt": now(), "from": a},
        {"addr": onion_v3(4), "port": 38333, "services": 73, "seenAt": now() - 4 * 86_400, "from": a},
    ]);
    let r = report(json!({"learned": learned}));
    assert_eq!((&r["learned"], &r["counts"]["learned"]), (&json!({"added": 1, "updated": 0, "refused": 3}), &json!(1)), "{r}");
    let entry = v(h.node.route_table("signet"))["peers"].as_array().unwrap().iter().find(|p| p["peer"] == format!("{}:38333", onion_v3(2))).cloned();
    assert_eq!(entry, Some(json!({"peer": format!("{}:38333", onion_v3(2)), "source": "learned", "ok": false})));
    // Refusals of the whole report.
    for bad in [r#"{"outcomes":"x"}"#.to_string(), "[]".into(), format!(r#"{{"learned":[{{"addr":"{}"}}]}}"#, onion_v3(5))] {
        assert!(v(h.node.report_peers("signet", &bad))["error"].as_str().unwrap().starts_with("invalid parameters: report:"), "{bad}");
    }
    assert_eq!(v(h.node.report_peers("testnet3", "{}"))["error"], "network must be mainnet, testnet4 or signet");
    // Kept across a restart: records, skips and learned peers.
    let again = Node::open(Some(h.dir.path().join(crate::store::FILE_NAME)), Arc::new(|_| {}));
    again.set_tor(tor_view("ready", Some(TOR)));
    assert_eq!(again.route_table("signet"), h.node.route_table("signet"));
    let c = v(again.peer_list("signet"))["counts"].clone();
    assert_eq!((&c["learned"], &c["okLast30d"], &c["usable"]), (&json!(1), &json!(1), &json!(shipped.peers.len())));
    let book: Value = serde_json::from_slice(&std::fs::read(h.dir.path().join("kyoto_peers_signet.json")).unwrap()).unwrap();
    let rec = book["entries"].as_array().unwrap().iter().find(|e| format!("{}:{}", e["addr"].as_str().unwrap(), e["port"]) == b).cloned().unwrap();
    assert!(rec["skipUntil"].is_string() && rec["failStreak"] == 0 && rec["source"] == "list", "{rec}");
}

#[test]
fn the_fixed_seeds_are_asked_only_when_the_book_runs_short() {
    let h = configured();
    h.tor_use("all");
    assert!(h.node.harvest_plan().is_empty(), "no wallet open");
    h.node.set_wallet_open("signet", true);
    let plan = h.node.harvest_plan();
    assert_eq!(plan.len(), 1);
    assert_eq!((plan[0].network, plan[0].seeds.len(), plan[0].proxy.as_deref()), (BNetwork::Signet, 8, Some(TOR)));
    assert!(plan[0].seeds.iter().all(|(p, r)| *r == Route::Onion && peers::fixed_seeds(BNetwork::Signet).contains(p)));
    assert!(h.node.harvest_plan().is_empty(), "not again within the hour");
    let book = |h: &Harness| -> Value { serde_json::from_slice(&std::fs::read(h.dir.path().join("kyoto_peers_signet.json")).unwrap()).unwrap() };
    assert_eq!((&book(&h)["harvestAnswered"], book(&h)["harvestTries"].as_array().unwrap().len()), (&json!(false), 1));
    // What a seed gossiped becomes learned, credited to it.
    let seed = plan[0].seeds[0].0.clone();
    let g = |host: String, services: u64| Gossip { host, port: 38333, services, time: now() as u32 };
    let l = h.node.record_harvest(BNetwork::Signet, &seed, &[g(onion_v3(9), 0x49), g("203.0.113.5".into(), 0x49), g(onion_v3(10), 0x09)], false);
    assert_eq!((l.added, l.refused), (1, 2));
    let book = book(&h);
    assert_eq!(book["harvestAnswered"], true, "a seed answered");
    let e = book["entries"].as_array().unwrap().iter().find(|e| e["addr"] == onion_v3(9)).cloned().unwrap();
    assert_eq!((&e["source"], &e["from"]), (&json!("learned"), &json!(seed)));
    assert!(book["harvestedAt"].is_string());
    // Not with your own peers, nor without the proxy, nor once 12 peers worked this month.
    let own = configured();
    own.node.set_own_peers("signet", r#"["192.168.1.20"]"#);
    own.node.set_wallet_open("signet", true);
    let off = configured();
    off.node.set_proxy("");
    off.node.set_wallet_open("signet", true);
    let fine = configured();
    let outcomes: Vec<Value> = peers::shipped(BNetwork::Mainnet).peers.iter().take(12).map(|p| json!({"peer": p, "ok": true})).collect();
    fine.node.report_peers("mainnet", &json!({"outcomes": outcomes}).to_string());
    fine.node.set_wallet_open("mainnet", true);
    for (name, n) in [("own peers", &own), ("no proxy", &off), ("12 worked", &fine)] {
        n.node.set_wallet_open("signet", false);
        n.node.set_wallet_open("mainnet", false);
        n.tor_use("all");
        n.node.set_wallet_open(if name == "12 worked" { "mainnet" } else { "signet" }, true);
        assert!(n.node.harvest_plan().is_empty(), "{name}");
    }
}

#[test]
fn certificate_pins_through_the_api() {
    let h = configured();
    let (typed, pin) = ("AB:".repeat(31) + "AB", "ab".repeat(32));
    let row = |v: &Value, id: &str| v["sources"].as_array().unwrap().iter().find(|x| x["id"] == id).cloned().unwrap();
    let mut list = v(h.node.get_sources("mainnet"))["sources"].clone();
    list.as_array_mut().unwrap().push(json!({"id": "mine", "kind": "electrum", "url": "ssl://electrum.example:50002", "certSha256": typed}));
    let s = v(h.node.set_sources("mainnet", &list.to_string()));
    assert_eq!(row(&s, "mine")["certSha256"], pin);
    let rt = v(h.node.route_table("mainnet"));
    let entry = rt["check"].as_array().unwrap().iter().find(|e| e["id"] == "mine").cloned().unwrap();
    assert_eq!((&entry["certSha256"], &entry["userAdded"]), (&json!(pin), &json!(true)));
    // A round trip of get_sources keeps it.
    let back = v(h.node.get_sources("mainnet"))["sources"].clone();
    assert_eq!(row(&v(h.node.set_sources("mainnet", &back.to_string())), "mine")["certSha256"], pin);
    // A result measured with another pin no longer stands.
    poll_all(&h.node, |t| answer(t.network, 970_838));
    assert_eq!(row(&v(h.node.source_health("mainnet")), "mine")["state"], "ok");
    assert_eq!(row(&v(h.node.set_source("mainnet", "mine", &format!(r#"{{"certSha256":"{}"}}"#, "cd".repeat(32)))), "mine")["certSha256"], "cd".repeat(32));
    assert_eq!(row(&v(h.node.source_health("mainnet")), "mine")["state"], "unknown");
    // Refusals, each led by "invalid parameters: ".
    let pin_kyoto = h.node.set_source("mainnet", KYOTO_ID, &format!(r#"{{"certSha256":"{pin}"}}"#));
    assert!(v(pin_kyoto)["error"].as_str().unwrap().starts_with("invalid parameters: kyoto: certSha256 is for"));
    assert!(v(h.node.set_source("mainnet", "mine", r#"{"certSha256":"xyz"}"#))["error"].as_str().unwrap().starts_with("invalid parameters: mine: certSha256 must be"));
    let mut plain = back.clone();
    plain.as_array_mut().unwrap().push(json!({"id": "plain", "kind": "electrum", "url": "tcp://electrum.example:50001"}));
    assert!(v(h.node.set_sources("mainnet", &plain.to_string()))["error"].as_str().unwrap().starts_with("invalid parameters: plain: "));
    // Kept across a restart; null clears it.
    let again = Node::open(Some(h.dir.path().join(crate::store::FILE_NAME)), Arc::new(|_| {}));
    assert_eq!(row(&v(again.get_sources("mainnet")), "mine")["certSha256"], "cd".repeat(32));
    assert_eq!(row(&v(h.node.set_source("mainnet", "mine", r#"{"certSha256":null}"#)), "mine")["certSha256"], Value::Null);
}

struct FakeLocal(Value);

impl LocalStatus for FakeLocal {
    fn status(&self) -> Result<Value, String> {
        Ok(self.0.clone())
    }
}

#[test]
fn local_node() {
    let h = configured();
    assert_eq!(v(h.node.local_node("signet"))["error"], "bitcoind_module is not installed");
    h.node.set_source("signet", LOCAL_ID, r#"{"use":true}"#);
    let rt = v(h.node.route_table("signet"));
    assert_eq!(ids(&rt, "chain"), ["local"], "your node alone; Kyoto's switch stays on");
    assert_eq!(rt["chain"][0]["url"], LOCAL_URL);
    assert_eq!((ids(&rt, "pending"), ids(&rt, "broadcast")), (vec!["local".to_string()], vec!["local".to_string()]));
    assert_eq!(rt["unrouted"], json!([{"id": "kyoto", "reason": OWN_NODE}]));
    h.node.set_local_status(Arc::new(FakeLocal(json!({"state": "running", "network": "signet", "blocks": 270000}))));
    let st = v(h.node.local_node("signet"));
    assert_eq!((&st["enabled"], &st["available"], &st["status"]["blocks"]), (&json!(true), &json!(true), &json!(270000)));
    assert_eq!(v(h.node.local_node("mainnet"))["available"], false);
    assert!(v(h.node.set_source("signet", LOCAL_ID, r#"{"tor":true}"#))["error"].as_str().unwrap().contains("Logos IPC"));
}

#[test]
fn probe_needs_the_health_thread() {
    let h = configured();
    assert_eq!(v(h.node.probe("signet", "electrum.emzy.de"))["error"], "the health thread is not running");
    assert_eq!(v(h.node.probe("signet", "nope"))["error"], "unknown source nope");
    // Kyoto and the local node are not dialled by this module: their state answers at once.
    let p = v(h.node.probe("signet", KYOTO_ID));
    assert_eq!((&p["answered"], p["sources"][0]["state"].as_str()), (&json!(true), Some("not_probed")));
}

/// A blocking fake Tor SOCKS port: records each CONNECT target, then refuses it.
fn fake_socks() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("socks5h://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let log = seen.clone();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            let log = log.clone();
            std::thread::spawn(move || -> std::io::Result<()> {
                let mut b = [0u8; 2];
                s.read_exact(&mut b)?;
                let mut methods = vec![0u8; b[1] as usize];
                s.read_exact(&mut methods)?;
                s.write_all(&[5, 2])?;
                let mut a = [0u8; 2];
                s.read_exact(&mut a)?;
                let mut user = vec![0u8; a[1] as usize + 1];
                s.read_exact(&mut user)?;
                let mut pass = vec![0u8; user[a[1] as usize] as usize];
                s.read_exact(&mut pass)?;
                s.write_all(&[1, 0])?;
                let mut req = [0u8; 4];
                s.read_exact(&mut req)?;
                let host = match req[3] {
                    3 => {
                        let mut n = [0u8; 1];
                        s.read_exact(&mut n)?;
                        let mut name = vec![0u8; n[0] as usize];
                        s.read_exact(&mut name)?;
                        String::from_utf8_lossy(&name).to_string()
                    }
                    t => format!("address type {t}"),
                };
                let mut port = [0u8; 2];
                s.read_exact(&mut port)?;
                log.lock().unwrap().push(format!("{host}:{}", u16::from_be_bytes(port)));
                s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
            });
        }
    });
    (url, seen)
}

fn wait_until(what: &str, secs: u64, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The plan's rule: every outbound connection takes its source's route. Tor routes reach only
/// the proxy, by name; the user's network is dialled directly; nothing falls back.
#[test]
fn every_connection_takes_its_sources_route() {
    let h = configured();
    let (proxy, socks) = fake_socks();
    let lan = TcpListener::bind("127.0.0.1:0").unwrap();
    lan.set_nonblocking(true).unwrap();
    let o = onion();
    for net in ["mainnet", "testnet4"] {
        h.node.set_sources(net, "[]");
    }
    let list = json!([
        {"id": "public", "kind": "electrum", "url": "electrum.example"},
        {"id": "hidden", "kind": "electrum", "url": format!("{o}:110")},
        {"id": "home", "kind": "electrum", "url": format!("tcp://127.0.0.1:{}", lan.local_addr().unwrap().port())},
        {"id": "kyoto", "kind": "kyoto"},
    ]);
    assert_eq!(v(h.node.set_sources("signet", &list.to_string()))["ok"], true);
    assert_eq!(v(h.node.set_proxy(&proxy))["proxy"], proxy);
    let poller = crate::poll::Poller::start(h.node.clone()).unwrap();
    let mut accepted = 0;
    wait_until("the proxy and the LAN server to be dialled", 10, || {
        if lan.accept().is_ok() {
            accepted += 1;
        }
        accepted >= 1 && socks.lock().unwrap().len() >= 2
    });
    let mut seen = socks.lock().unwrap().clone();
    seen.sort();
    assert_eq!(seen, [format!("{o}:110"), "electrum.example:50002".into()], "only Tor routes, by name");
    // No proxy: the Tor sources fail closed and nothing new reaches the proxy.
    h.node.set_proxy("");
    wait_until("no_route", 10, || {
        let sh = v(h.node.source_health("signet"));
        sh["sources"].as_array().unwrap().iter().filter(|s| s["state"] == "no_route").count() == 3
    });
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(socks.lock().unwrap().len(), 2);
    assert!(poller.stop(Duration::from_millis(1000)), "joined");
}

#[test]
fn probes_go_through_the_health_thread() {
    let h = configured();
    // The fake Electrum server runs on its own thread and runtime.
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let (url, server) = crate::net::electrum::tests::fake_server(Some(BNetwork::Signet.genesis()), 270_123).await;
            tx.send(url).unwrap();
            let _ = server.await;
        });
    });
    let url = rx.recv().unwrap();
    let list = json!([{"id": "home", "kind": "electrum", "url": url, "use": false}]);
    h.node.set_sources("signet", &list.to_string());
    // No proxy: no unit test dials Tor, even with one listening on this machine.
    h.node.set_proxy("");
    let poller = crate::poll::Poller::start(h.node.clone()).unwrap();
    // A source switched off is probed only when asked.
    let p = v(h.node.probe("signet", "home"));
    let row = &p["sources"][0];
    assert_eq!((&p["answered"], row["state"].as_str(), row["tipHeight"].as_str(), row["serverVersion"].as_str()), (&json!(true), Some("ok"), Some("270123"), Some("fake 1.0")));
    assert!(poller.stop(Duration::from_millis(1000)));
}


#[test]
fn the_built_in_tor_is_the_default_and_routes_follow_its_socks_port() {
    let h = harness();
    h.node.init_defaults();
    h.tor_use("identifying");
    assert!(h.node.uses_built_in_tor());
    assert_eq!(v(h.node.get_sources("mainnet"))["proxy"], "tor");
    // Not heard from yet: Tor routes wait, and health says Tor is starting.
    let rt = v(h.node.route_table("mainnet"));
    assert_eq!((&rt["proxy"], &rt["unrouted"][0]["reason"]), (&Value::Null, &json!(TOR_STARTING)));
    assert_eq!(v(h.node.source_health("mainnet"))["tor"], json!({"state": "connecting", "progress": 0, "detail": "", "socks": null, "answered": false}));
    h.take();

    // Joining, with the port listening: routes dial it already; the poller looks again when ready.
    h.node.set_tor(tor_view("connecting", Some("socks5h://127.0.0.1:9250")));
    assert_eq!(v(h.node.route_table("mainnet"))["proxy"], "socks5h://127.0.0.1:9250");
    assert!(v(h.node.route_table("mainnet"))["unrouted"].as_array().unwrap().is_empty());
    assert_eq!(h.take().iter().filter(|e| e.starts_with("routes")).count(), 3, "every network's routes changed");
    let t = h.node.poll_plan().0;
    assert!(t.iter().filter(|t| t.route != Route::Direct).all(|t| t.proxy.as_deref() == Some("socks5h://127.0.0.1:9250")) && !t.is_empty());
    h.node.set_tor(tor_view("ready", Some("socks5h://127.0.0.1:9250")));
    assert!(h.take().iter().all(|e| e.starts_with("health")), "ready changes health, not routes");
    assert_eq!(v(h.node.source_health("signet"))["tor"]["state"], "ready");

    // The port moved, as when 9250 was taken: routes follow.
    h.node.set_tor(tor_view("ready", Some("socks5h://127.0.0.1:41234")));
    assert_eq!(v(h.node.route_table("testnet4"))["proxy"], "socks5h://127.0.0.1:41234");

    // The user turned the port off in the Tor app: fail closed, and say so.
    h.node.set_tor(tor_view("ready", None));
    assert_eq!(v(h.node.source_health("signet"))["tor"]["answered"], true, "answered, and the port is off");
    let rt = v(h.node.route_table("mainnet"));
    assert_eq!((&rt["proxy"], &rt["unrouted"][0]["reason"]), (&Value::Null, &json!(TOR_SOCKS_OFF)));
    // tor_module missing.
    h.node.set_tor(TorView::from_reply(Err("object_unavailable".into())));
    assert_eq!(v(h.node.route_table("mainnet"))["unrouted"][0]["reason"], TOR_MISSING);

    // The user's own Tor: tor_module is no longer asked, and health leaves it out.
    h.node.set_proxy(TOR);
    assert!(!h.node.uses_built_in_tor());
    assert_eq!(v(h.node.route_table("mainnet"))["proxy"], TOR);
    assert_eq!(v(h.node.source_health("mainnet"))["tor"], Value::Null);
    assert_eq!(v(h.node.set_proxy("tor"))["proxy"], "tor");
    assert!(h.node.uses_built_in_tor());
}

#[test]
fn tor_modules_status_reply() {
    let ok = |s: &str| TorView::from_reply(Ok(s.into()));
    let ready = ok(r#"{"ok":true,"state":"ready","progress":100,"detail":"x","socks":"socks5h://127.0.0.1:9250"}"#);
    assert_eq!(ready, tor_view("ready", Some("socks5h://127.0.0.1:9250")));
    let idle = ok(r#"{"ok":true,"state":"idle","progress":0,"socks":null}"#);
    assert_eq!((idle.state.as_str(), idle.socks, idle.answered), ("connecting", None, true));
    let blocked = ok(r#"{"ok":true,"state":"blocked","progress":40,"detail":"no network","socks":"socks5h://127.0.0.1:9250"}"#);
    assert_eq!((blocked.detail.as_str(), blocked.progress), ("no network", 40));
    assert_eq!(ok(r#"{"ok":false,"error":"starting"}"#), TorView { state: "connecting".into(), progress: 0, detail: String::new(), socks: None, answered: false });
    let missing = TorView::from_reply(Err("object_unavailable".into()));
    assert_eq!((missing.state.as_str(), missing.answered), ("failed", false));
    assert_eq!(ok(r#"{"ok":true,"state":"ready","socks":"socks5://127.0.0.1:9250"}"#).socks, None, "never a port that resolves names locally");
}

fn clear_gossip(hosts: &[&str]) -> Vec<Gossip> {
    hosts.iter().map(|h| Gossip { host: h.to_string(), port: 38333, services: 0x849, time: now() as u32 }).collect()
}

#[test]
fn tor_use_is_chosen_per_network_and_locked_while_a_wallet_is_open() {
    let h = harness();
    assert_eq!(v(h.node.init_defaults())["ok"], true);
    let status = |h: &Harness| v(h.node.config_status());
    assert_eq!((&status(&h)["torUse"]["signet"], &status(&h)["torUseChosen"]["signet"]), (&json!("identifying"), &json!(false)), "a fresh install");
    assert_eq!(v(h.node.set_tor_use("signet", "everything"))["error"], "invalid parameters: torUse must be all, identifying or none");
    assert_eq!(v(h.node.set_tor_use("testnet3", "none"))["error"], "network must be mainnet, testnet4 or signet");
    h.node.set_wallet_open("testnet4", true);
    assert_eq!(v(h.node.set_tor_use("signet", "none"))["error"], LOCKED, "any open wallet locks it");
    h.node.set_wallet_open("testnet4", false);
    assert_eq!(v(h.node.set_tor_use("signet", "none")), json!({"ok": true, "network": "signet", "torUse": "none", "torUseChosen": true}));
    for (name, r) in [("sources", v(h.node.get_sources("signet"))), ("health", v(h.node.source_health("signet")))] {
        assert_eq!((&r["torUse"], &r["torUseChosen"]), (&json!("none"), &json!(true)), "{name}");
    }
    assert_eq!(v(h.node.route_table("signet"))["torUse"], "none");
    // Another network keeps its own, still to be chosen.
    for r in [v(h.node.get_sources("mainnet")), v(h.node.source_health("mainnet"))] {
        assert_eq!((&r["torUse"], &r["torUseChosen"]), (&json!("identifying"), &json!(false)));
    }
    assert_eq!(v(h.node.route_table("mainnet"))["torUse"], "identifying");
    let again = Node::open(Some(h.dir.path().join(crate::store::FILE_NAME)), Arc::new(|_| {}));
    let st = v(again.config_status());
    assert_eq!((&st["torUse"]["signet"], &st["torUseChosen"]["signet"], &st["torUseChosen"]["mainnet"]), (&json!("none"), &json!(true), &json!(false)), "kept");
}

/// Nothing is probed, and Tor is not started, for a network before its choice or an open wallet.
#[test]
fn a_network_not_yet_set_up_is_left_alone() {
    let h = harness();
    assert_eq!(v(h.node.init_defaults())["ok"], true);
    assert!(!h.node.uses_built_in_tor(), "no network chosen yet");
    assert!(h.node.poll_plan().0.is_empty() && h.node.poll_plan().1.is_empty());
    h.node.set_tor_use("mainnet", "none");
    assert!(!h.node.uses_built_in_tor(), "mainnet goes without Tor");
    let (targets, skipped) = h.node.poll_plan();
    assert!(!skipped.is_empty() && targets.iter().chain(skipped.iter().map(|(t, _)| t)).all(|t| t.network == BNetwork::Mainnet && t.proxy.is_none()));
    h.node.set_wallet_open("testnet4", true);
    assert!(h.node.uses_built_in_tor(), "testnet4's wallet uses identifying");
    assert!(h.node.poll_plan().0.iter().chain(h.node.poll_plan().1.iter().map(|(t, _)| t)).any(|t| t.network == BNetwork::Testnet4));
}

#[test]
fn none_turns_tor_off_and_kyoto_dials_the_clearnet_book() {
    let h = configured();
    assert!(h.node.uses_built_in_tor());
    h.tor_use("none");
    assert!(!h.node.uses_built_in_tor(), "tor_module is never asked");
    let t = v(h.node.route_table("signet"));
    assert_eq!((&t["proxy"], &t["torUse"], &t["kyotoSplit"]), (&Value::Null, &json!("none"), &Value::Null));
    for role in ["chain", "history", "fees", "broadcast", "check"] {
        assert!(t[role].as_array().unwrap().iter().all(|e| e["route"] == "direct"), "{role}: {t}");
    }
    assert_eq!(t["unrouted"], json!([]), "signet's servers are off");
    let unrouted = v(h.node.route_table("mainnet"))["unrouted"].clone();
    assert_eq!(unrouted, json!([{"id": "electrum.blockstream.info-onion", "reason": TOR_OFF}]));
    let listed: Vec<String> = peers::shipped_clearnet(BNetwork::Signet).peers.into_iter().map(|p| p.peer).collect();
    let start = peer_strings(&t["peers"]);
    assert!(!start.is_empty() && start.iter().all(|p| listed.contains(p)), "the shipped clearnet list: {start:?}");
    assert_eq!(v(h.node.source_health("signet"))["tor"], Value::Null);
    // While a wallet is open: Core's clearnet seeds directly, and the DNS seeds, never through Tor.
    h.node.set_wallet_open("signet", true);
    let plan = h.node.harvest_plan();
    assert_eq!(plan.len(), 1, "no onion harvest without Tor");
    let p = &plan[0];
    assert!(p.clearnet && p.proxy.is_none() && p.seeds.len() == 8 && p.dns == ["seed.signet.bitcoin.sprovoost.nl", "seed.signet.achownodes.xyz"]);
    assert!(p.seeds.iter().all(|(s, r)| *r == Route::Direct && peers::clearnet_seeds(BNetwork::Signet).contains(s)));
    // 11.22/16 is in no crawled list.
    let l = h.node.record_harvest(BNetwork::Signet, &p.seeds[0].0, &clear_gossip(&["11.22.3.4", "11.22.9.9", "11.22.10.10", "192.168.1.5", &onion_v3(4)]), true);
    assert_eq!((l.added, l.refused), (2, 3), "the third in 11.22/16, a LAN address and an onion refused");
    let usable = v(h.node.peer_list("signet"))["clearnet"]["usable"].clone();
    let learned = |peer: &str| usable.as_array().unwrap().iter().find(|p| p["peer"] == peer).cloned();
    assert_eq!(learned("11.22.3.4:38333").map(|p| p["services"].clone()), Some(json!("2121")), "BIP324 shows in the services: {usable}");
    assert!(learned("11.22.9.9:38333").is_some() && learned("11.22.10.10:38333").is_none());
    assert_eq!(route_of(&v(h.node.route_table("signet")), "chain", KYOTO_ID), "direct");
    // An onion peer of your own has no route.
    h.node.set_wallet_open("signet", false);
    h.tor_use("all");
    h.node.set_own_peers("signet", &json!([format!("{}:38333", onion())]).to_string());
    h.tor_use("none");
    assert!(v(h.node.route_table("signet"))["unrouted"].as_array().unwrap().iter().any(|u| u["id"] == KYOTO_ID && u["reason"] == TOR_OFF));
}

#[test]
fn identifying_splits_kyoto_once_both_books_have_peers() {
    let h = configured();
    let t = v(h.node.route_table("signet"));
    let onion_peers = t["peers"].clone();
    assert_eq!(t["torUse"], json!("identifying"));
    assert_eq!(route_of(&t, "chain", KYOTO_ID), "onion", "the mode-1 entry stays all-Tor for an older core");
    // Both books have peers from the start: the shipped onion and clearnet lists.
    let listed: Vec<String> = peers::shipped_clearnet(BNetwork::Signet).peers.into_iter().map(|p| p.peer).collect();
    let split = &t["kyotoSplit"];
    assert_eq!((&split["chain"]["route"], &split["tor"]["route"]), (&json!("direct"), &json!("onion")));
    let chain = peer_strings(&split["chain"]["peers"]);
    assert!(!chain.is_empty() && chain.iter().all(|p| listed.contains(p)), "{chain:?}");
    assert_eq!(split["tor"]["peers"], onion_peers);
    h.node.set_wallet_open("signet", true);
    let plan = h.node.harvest_plan();
    assert_eq!(plan.iter().map(|p| p.clearnet).collect::<Vec<_>>(), [true, false], "both books are asked");
    let seed = plan[0].seeds[0].0.clone();
    h.node.record_harvest(BNetwork::Signet, &seed, &clear_gossip(&["11.22.3.4", "11.33.7.8"]), true);
    // The core's report: IP addresses to the clearnet book, onions to the onion book.
    let seen = now();
    let r = v(h.node.report_peers("signet", &json!({"outcomes": [{"peer": "11.22.3.4:38333", "ok": true}],
        "learned": [{"addr": "9.9.9.9", "port": 38333, "services": 2121, "seenAt": seen, "from": "11.22.3.4:38333"},
                    {"addr": onion_v3(7), "port": 38333, "services": 73, "seenAt": seen, "from": "11.22.3.4:38333"}]}).to_string()));
    assert_eq!((&r["outcomes"]["applied"], &r["learned"]["added"]), (&json!(1), &json!(2)), "{r}");
    let t = v(h.node.route_table("signet"));
    assert!(peer_strings(&t["kyotoSplit"]["chain"]["peers"]).contains(&"9.9.9.9:38333".to_string()));
    assert!(peer_strings(&t["kyotoSplit"]["tor"]["peers"]).contains(&format!("{}:38333", onion_v3(7))));
    assert_eq!(t["kyotoSplit"]["chain"]["peers"][0]["peer"], "11.22.3.4:38333", "the peer that worked first");
    let clear = &v(h.node.peer_list("signet"))["clearnet"];
    let version = peers::shipped_clearnet(BNetwork::Signet).version.to_string();
    assert_eq!((&clear["counts"]["learned"], &clear["list"]["version"]), (&json!(3), &json!(version)));
    // Kyoto's own Tor switch off: all of Kyoto direct on the clearnet book, no split.
    h.node.set_wallet_open("signet", false);
    h.node.set_source("signet", KYOTO_ID, r#"{"tor":false}"#);
    let t = v(h.node.route_table("signet"));
    assert_eq!((route_of(&t, "chain", KYOTO_ID).as_str(), &t["kyotoSplit"]), ("direct", &Value::Null));
    assert!(peer_strings(&t["peers"]).contains(&"9.9.9.9:38333".to_string()));
    // All, or peers of your own: no split.
    h.node.set_source("signet", KYOTO_ID, r#"{"tor":true}"#);
    h.tor_use("all");
    assert_eq!(v(h.node.route_table("signet"))["kyotoSplit"], Value::Null);
    h.tor_use("identifying");
    assert!(v(h.node.route_table("signet"))["kyotoSplit"].is_object());
    h.node.set_own_peers("signet", r#"["192.168.1.20"]"#);
    assert_eq!(v(h.node.route_table("signet"))["kyotoSplit"], Value::Null);
}

/// Your node on: no peer, server or seed is contacted, and the other switches are kept, so
/// turning it off brings them back.
#[test]
fn your_node_alone_makes_no_other_request() {
    let h = configured();
    let (proxy, socks) = fake_socks();
    let electrum = TcpListener::bind("127.0.0.1:0").unwrap();
    electrum.set_nonblocking(true).unwrap();
    for net in ["mainnet", "testnet4"] {
        h.node.set_sources(net, "[]");
    }
    let o = onion();
    let list = json!([
        {"id": "kyoto", "kind": "kyoto"},
        {"id": "home", "kind": "electrum", "url": format!("tcp://127.0.0.1:{}", electrum.local_addr().unwrap().port()), "history": true},
        {"id": "hidden", "kind": "electrum", "url": format!("{o}:110")},
        {"id": "local", "kind": "local"},
    ]);
    let s = v(h.node.set_sources("signet", &list.to_string()));
    assert_eq!((&s["exposes"], &s["withoutTor"]), (&json!([]), &json!([])), "{s}");
    h.node.set_proxy(&proxy);
    assert_eq!(v(h.node.set_local_sends("signet", "node"))["localSends"], "node", "payments through your node too");
    let rt = v(h.node.route_table("signet"));
    assert_eq!(rt["localSends"], "node");
    for role in ["chain", "history", "pending", "fees", "broadcast"] {
        assert_eq!(ids(&rt, role), ["local"], "{role}");
    }
    assert!(ids(&rt, "check").is_empty() && rt["peers"] == json!([]) && rt["proxy"].is_null(), "{rt}");
    let waiting: Vec<(&str, &str)> = rt["unrouted"].as_array().unwrap().iter().map(|u| (u["id"].as_str().unwrap(), u["reason"].as_str().unwrap())).collect();
    assert_eq!(waiting, [("kyoto", OWN_NODE), ("home", OWN_NODE), ("hidden", OWN_NODE)]);
    let health = v(h.node.source_health("signet"));
    assert_eq!((&health["pending"], &health["tor"]), (&json!(false), &Value::Null), "nothing to wait for, no Tor to show");
    h.node.set_wallet_open("signet", true);
    assert!(h.node.harvest_plan().is_empty(), "no seed is asked for peers");
    let poller = crate::poll::Poller::start(h.node.clone()).unwrap();
    assert_eq!(v(h.node.probe("signet", "home"))["error"], OWN_NODE);
    let all = v(h.node.probe("signet", ""));
    assert_eq!(all["answered"], true);
    std::thread::sleep(Duration::from_millis(1500));
    assert!(electrum.accept().is_err(), "the Electrum server was never dialled");
    assert!(socks.lock().unwrap().is_empty(), "nothing went to Tor: {:?}", socks.lock().unwrap());
    // Off again: the servers' switches are as they were, and they are probed at once.
    h.node.set_wallet_open("signet", false);
    let s = v(h.node.set_source("signet", LOCAL_ID, r#"{"use":false}"#));
    assert_eq!(s["exposes"][0]["id"], "home", "History is still on");
    let mut dialled = false;
    wait_until("the Electrum server to be probed", 10, || {
        dialled |= electrum.accept().is_ok();
        dialled && !socks.lock().unwrap().is_empty()
    });
    assert_eq!(ids(&v(h.node.route_table("signet")), "chain"), ["kyoto"]);
    assert!(poller.stop(Duration::from_millis(1000)), "joined");
}

/// With your node on, payments go through public servers over Tor until bitcoind sends privately
/// or the person picks; the switched-on Electrum servers, else the shipped onion one, else the node.
#[test]
fn payments_with_your_node_follow_the_pick_else_the_node() {
    let h = configured();
    let o = onion();
    let list = json!([
        {"id": "kyoto", "kind": "kyoto"},
        {"id": "home", "kind": "electrum", "url": "tcp://192.168.1.5:50001", "history": true},
        {"id": "hidden", "kind": "electrum", "url": format!("{o}:110")},
        {"id": "far", "kind": "electrum", "url": "ssl://electrum.example:50002", "use": false},
        {"id": "local", "kind": "local"},
    ]);
    v(h.node.set_sources("signet", &list.to_string()));
    let sends = |h: &Harness| v(h.node.get_sources("signet"))["sends"].clone();
    let s = sends(&h);
    assert_eq!((&s["localSends"], &s["localSendsChosen"], &s["localSendsRecommended"]), (&json!("servers"), &json!(false), &json!("servers")), "{s}");
    let rt = v(h.node.route_table("signet"));
    assert_eq!((ids(&rt, "broadcast"), &rt["localSends"], &rt["proxy"]), (vec!["home".to_string(), "hidden".into(), "local".into()], &json!("servers"), &json!(TOR)), "your node last, for an older core");
    assert_eq!((route_of(&rt, "broadcast", "home"), route_of(&rt, "broadcast", "hidden")), ("direct".into(), "onion".into()), "your own network directly");
    assert_eq!(ids(&rt, "history"), ["local"], "reads stay with your node");
    assert!(h.node.uses_built_in_tor(), "sends over Tor ask the built-in Tor");
    // bitcoind sends privately: through your node, with no proxy.
    h.node.set_local_private(BNetwork::Signet, Some(true));
    assert!(h.take().contains(&"routes signet".to_string()));
    let rt = v(h.node.route_table("signet"));
    assert_eq!((ids(&rt, "broadcast"), &rt["localSends"], &rt["proxy"]), (vec!["local".to_string()], &json!("node"), &Value::Null));
    assert_eq!(sends(&h)["localSendsRecommended"], "node");
    // The person's pick wins, and is kept.
    assert_eq!(v(h.node.set_local_sends("signet", "servers"))["localSendsChosen"], true);
    assert_eq!(ids(&v(h.node.route_table("signet")), "broadcast"), ["home", "hidden", "local"]);
    assert!(v(h.node.set_local_sends("signet", "peers"))["error"].as_str().unwrap().contains("servers or node"));
    h.node.set_wallet_open("signet", true);
    assert_eq!(v(h.node.set_local_sends("signet", "node"))["error"], LOCKED);
    h.node.set_wallet_open("signet", false);
    let back = Node::open(Some(h.dir.path().join(crate::store::FILE_NAME)), Arc::new(|_| {}));
    assert_eq!(v(back.get_sources("signet"))["sends"]["localSends"], "servers", "stored");
    // No Electrum server on and none shipped on signet: your node sends them.
    let none = json!([{"id": "kyoto", "kind": "kyoto"}, {"id": "hidden", "kind": "electrum", "url": format!("{o}:110"), "use": false}, {"id": "local", "kind": "local"}]);
    v(h.node.set_sources("signet", &none.to_string()));
    let rt = v(h.node.route_table("signet"));
    assert_eq!((ids(&rt, "broadcast"), &rt["localSends"]), (vec!["local".to_string()], &json!("node")));
    assert_eq!(sends(&h)["sendServers"], json!([]));
    // Mainnet ships an onion server: it carries them when none is on.
    let main = json!([{"id": "kyoto", "kind": "kyoto"}, {"id": "electrum.blockstream.info", "kind": "electrum", "url": "ssl://electrum.blockstream.info:50002", "use": false},
                      {"id": "local", "kind": "local"}]);
    v(h.node.set_sources("mainnet", &main.to_string()));
    let rt = v(h.node.route_table("mainnet"));
    assert_eq!((ids(&rt, "broadcast"), route_of(&rt, "broadcast", "electrum.blockstream.info-onion")), (vec!["electrum.blockstream.info-onion".to_string(), "local".into()], "onion".into()));
    // Your node at an address can't be asked: public servers stay recommended.
    let rpc = json!([{"id": "kyoto", "kind": "kyoto"}, {"id": "hidden", "kind": "electrum", "url": format!("{o}:110")}, {"id": "mine", "kind": "rpc", "url": "http://192.168.1.9:8332"}]);
    v(h.node.set_sources("testnet4", &rpc.to_string()));
    h.node.set_local_private(BNetwork::Testnet4, Some(true));
    let s = v(h.node.get_sources("testnet4"))["sends"].clone();
    assert_eq!((&s["localSends"], &s["localSendsRecommended"]), (&json!("servers"), &json!("servers")));
    assert_eq!(ids(&v(h.node.route_table("testnet4")), "broadcast"), ["hidden", "mine"]);
    // Without your node, nothing changes.
    assert_eq!(v(h.node.get_sources("testnet4"))["sends"]["localSends"], "servers");
    v(h.node.set_source("testnet4", "mine", r#"{"use":false}"#));
    let s = v(h.node.get_sources("testnet4"))["sends"].clone();
    assert_eq!((&s["localSends"], &v(h.node.route_table("testnet4"))["localSends"]), (&Value::Null, &Value::Null));
}

#[test]
fn bitcoind_is_asked_for_every_network_using_the_node_in_logos_saved_or_not() {
    let h = harness();
    let local = |on: bool| json!([{"id": "kyoto", "kind": "kyoto"}, {"id": "local", "kind": "local", "use": on}]).to_string();
    v(h.node.set_sources("mainnet", &local(true)));
    v(h.node.set_sources("signet", &local(false)));
    v(h.node.set_sources("testnet4", &json!([{"id": "kyoto", "kind": "kyoto"}, {"id": "mine", "kind": "rpc", "url": "http://192.168.1.9:8332"}]).to_string()));
    assert_eq!(v(h.node.get_sources("mainnet"))["torUseChosen"], false, "never saved");
    assert_eq!(h.node.local_sends_watch(), [BNetwork::Mainnet], "only the network whose own node is on and in Logos");
    v(h.node.set_tor_use("mainnet", "identifying"));
    assert_eq!(h.node.local_sends_watch(), [BNetwork::Mainnet]);
}

#[test]
fn bitcoind_sends_privately_by_its_status_else_its_settings() {
    let n = BNetwork::Signet;
    let running = |mode: &str| json!({"state": "running", "network": "signet", "privateSends": mode});
    assert_eq!(sends_privately(n, None, Some(&running("on"))), Some(true));
    assert_eq!(sends_privately(n, None, Some(&running("proxy"))), Some(true));
    assert_eq!(sends_privately(n, Some(&json!({"privateSends": true})), Some(&running("unavailable"))), Some(false), "what runs wins");
    let other = json!({"state": "running", "network": "main", "privateSends": "off"});
    assert_eq!(sends_privately(n, Some(&json!({"privateSends": true, "proxy": ""})), Some(&other)), Some(true), "another network runs");
    assert_eq!(sends_privately(BNetwork::Mainnet, None, Some(&json!({"state": "running", "network": "main", "privateSends": "on"}))), Some(true));
    assert_eq!(sends_privately(n, Some(&json!({"proxy": "127.0.0.1:9050"})), None), Some(true), "an older bitcoind with a proxy");
    assert_eq!(sends_privately(n, Some(&json!({"proxy": ""})), None), Some(false), "an older bitcoind without one");
    assert_eq!(sends_privately(n, None, None), None);
}

/// Use Tor for is for public sources: your node at an address takes its own Tor switch, and an
/// onion address always goes through Tor.
#[test]
fn your_node_at_an_address_follows_its_own_tor_switch() {
    let h = configured();
    h.tor_use("none");
    assert!(!h.node.uses_built_in_tor());
    let o = onion();
    let list = json!([{"id": "kyoto", "kind": "kyoto"}, {"id": "mine", "kind": "rpc", "url": "https://node.example", "tor": true},
                      {"id": "hidden", "kind": "rpc", "url": format!("http://{o}:8332"), "use": false}]);
    assert_eq!(v(h.node.set_sources("signet", &list.to_string()))["ok"], true);
    assert!(h.node.uses_built_in_tor(), "tor_module is asked for your node");
    let rt = v(h.node.route_table("signet"));
    assert_eq!((ids(&rt, "chain"), route_of(&rt, "chain", "mine"), &rt["proxy"]), (vec!["mine".to_string()], "tor".into(), &json!(TOR)));
    assert_eq!(v(h.node.source_health("signet"))["tor"]["state"], "ready", "its Tor shows");
    let (targets, _) = h.node.poll_plan();
    let mine: Vec<(&str, Route, Option<&str>)> = targets.iter().filter(|t| t.network == BNetwork::Signet).map(|t| (t.id.as_str(), t.route, t.proxy.as_deref())).collect();
    assert_eq!(mine, [("mine", Route::Tor, Some(TOR))]);
    // At an onion address.
    h.node.set_source("signet", "mine", r#"{"use":false}"#);
    h.node.set_source("signet", "hidden", r#"{"use":true}"#);
    let rt = v(h.node.route_table("signet"));
    assert_eq!((ids(&rt, "chain"), route_of(&rt, "chain", "hidden"), &rt["unrouted"]), (vec!["hidden".to_string()], "onion".into(), &json!([{"id": "kyoto", "reason": OWN_NODE}])));
    // Its switch off: direct, which a public address needs TLS for; no Tor is asked.
    h.node.set_source("signet", "hidden", r#"{"use":false}"#);
    let s = v(h.node.set_source("signet", "mine", r#"{"use":true,"tor":false}"#));
    assert_eq!(s["withoutTor"][0]["id"], "mine");
    assert!(!h.node.uses_built_in_tor());
    let rt = v(h.node.route_table("signet"));
    assert_eq!((route_of(&rt, "chain", "mine"), &rt["proxy"]), ("direct".into(), &Value::Null));
    assert_eq!(v(h.node.source_health("signet"))["tor"], Value::Null);
    // Public sources again: Use Tor for applies, so Kyoto dials directly.
    h.node.set_source("signet", "mine", r#"{"use":false}"#);
    assert_eq!(route_of(&v(h.node.route_table("signet")), "chain", "kyoto"), "direct");
}
