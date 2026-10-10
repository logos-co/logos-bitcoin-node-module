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

/// Configured with the defaults, and the events so far dropped.
fn configured() -> Harness {
    let h = harness();
    assert_eq!(v(h.node.init_defaults())["ok"], true);
    h.take();
    h
}

impl Harness {
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
    assert_eq!(ids(&rt, "fees"), ["blockstream.info-onion", "kyoto"]);
    assert_eq!(ids(&rt, "broadcast"), ["kyoto"]);
    assert_eq!(ids(&rt, "check"), ["blockstream.info-onion"]);
    assert_eq!((route_of(&rt, "fees", "blockstream.info-onion"), route_of(&rt, "chain", "kyoto")), ("onion".into(), "onion".into()));
    assert_eq!(rt["crossCheck"], true);
    assert_eq!((&rt["peers"], &rt["unrouted"]), (&json!([]), &json!([])), "mainnet's curated list is empty");
    let entry = &rt["fees"][0];
    assert_eq!(entry.as_object().unwrap().keys().cloned().collect::<Vec<_>>(), ["id", "kind", "operator", "route", "url"]);
    for role in ["chain", "history", "pending", "fees", "broadcast", "check"] {
        assert!(rt[role].as_array().unwrap().iter().all(|e| e["id"] != "mempool.space"), "{role}: a disabled source is never routed");
    }
    assert_eq!(ids(&v(h.node.route_table("testnet4")), "fees"), ["mempool.space", "kyoto"]);
    assert_eq!(route_of(&v(h.node.route_table("testnet4")), "fees", "mempool.space"), "tor");
}

/// Every combination of tor, lan and onion, with the proxy set and without it.
#[test]
fn routes_for_every_combination_of_tor_lan_and_onion() {
    let h = configured();
    let o = onion();
    let list = json!([
        {"id": "public-tor", "kind": "esplora", "url": "https://esplora.example/api", "tor": true},
        {"id": "public-direct", "kind": "esplora", "url": "https://direct.example/api", "tor": false},
        {"id": "lan-tor", "kind": "electrum", "url": "192.168.1.20:50001", "tor": true},
        {"id": "lan-direct", "kind": "electrum", "url": "tcp://192.168.1.21:50001", "tor": false},
        {"id": "lan-name", "kind": "esplora", "url": "http://umbrel.local:3002/api"},
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
    assert_eq!(ids(&rt, "chain"), ["lan-tor", "lan-direct", "onion-tor"], "Electrum servers define the chain with Kyoto absent");
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
    assert_eq!((p["route"].as_str(), &p["source"], &p["list"]["version"], &p["today"]), (Some("onion"), &json!("shipped"), &json!("0"), &json!([])));
    assert_eq!(v(h.node.source_health("signet"))["sources"][0]["state"], "no_peers");
    // Your node on your network: Kyoto dials it directly, and needs no proxy.
    let p = v(h.node.set_own_peers("signet", r#"["192.168.1.20"]"#));
    assert_eq!((p["ownPeers"].clone(), p["today"].clone(), p["route"].as_str()), (json!(["192.168.1.20:38333"]), json!(["192.168.1.20:38333"]), Some("direct")));
    h.node.set_proxy("");
    let rt = v(h.node.route_table("signet"));
    assert_eq!((ids(&rt, "chain"), route_of(&rt, "chain", "kyoto"), rt["peers"].clone()), (vec!["kyoto".to_string()], "direct".into(), json!(["192.168.1.20:38333"])));
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
    let s = v(h.node.set_source("mainnet", "blockstream.info", r#"{"use":true,"history":true}"#));
    assert_eq!(s["exposes"], json!([{"id": "blockstream.info", "url": "https://blockstream.info/api", "operator": "blockstream.info", "lan": false}]));
    let rt = v(h.node.route_table("mainnet"));
    assert_eq!((ids(&rt, "history"), ids(&rt, "pending")), (vec!["kyoto".to_string(), "blockstream.info".into()], vec!["blockstream.info".to_string()]));
    assert_eq!(ids(&rt, "broadcast"), ["kyoto"], "Kyoto broadcasts while it is on");

    let mut list = s["sources"].clone();
    list.as_array_mut().unwrap().push(json!({"id": "mine", "kind": "esplora", "url": "https://me:s3cret@esplora.example/api"}));
    let s = v(h.node.set_sources("mainnet", &list.to_string()));
    let text = s.to_string();
    assert!(!text.contains("s3cret") && !text.contains("me:"), "{text}");
    let mine = s["sources"].as_array().unwrap().iter().find(|x| x["id"] == "mine").unwrap().clone();
    assert_eq!((mine["url"].as_str(), &mine["hasCredentials"]), (Some("https://esplora.example/api"), &json!(true)));
    for read in [h.node.get_sources("mainnet"), h.node.route_table("mainnet"), h.node.source_health("mainnet")] {
        assert!(!read.contains("s3cret"), "{read}");
    }
    assert_eq!(v(h.node.route_table("mainnet"))["check"].as_array().unwrap().iter().find(|e| e["id"] == "mine").unwrap()["credentials"], true);
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
    assert_eq!(v(h.node.report_mismatch("signet", "blockstream.info-onion", "anchor_mismatch", "325000"))["suspect"], true);
    assert_eq!(v(h.node.clear_suspect("signet", "blockstream.info-onion"))["cleared"], true);
    assert_eq!(v(h.node.init_defaults())["applied"], json!([]));
    h.node.set_wallet_open("signet", false);
    assert_eq!(v(h.node.set_source("signet", KYOTO_ID, r#"{"use":false}"#))["ok"], true);
    // Not kept across a restart: the backend says it again when a wallet opens.
    h.node.set_wallet_open("signet", true);
    let again = Node::open(Some(h.dir.path().join(crate::store::FILE_NAME)), Arc::new(|_| {}));
    assert_eq!(v(again.get_sources("signet"))["walletOpen"], false);
}

fn answer(net: BNetwork, tip: u64) -> Health {
    Health::observed(net, Observed { genesis: Some(net.genesis().into()), tip_height: tip, tip_hash: "00".repeat(32), rtt_ms: 700, server_version: None }, now())
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
    assert!(events.contains(&"health mainnet degraded".to_string()), "{events:?}: Kyoto has no mainnet peers yet");
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
    assert_eq!(h.take(), ["routes mainnet", "health mainnet degraded"]);
    assert_eq!(v(h.node.clear_suspect("mainnet", "electrum.blockstream.info"))["cleared"], false);

    // A server on another network answers but is never routed.
    let signet_genesis = Observed { genesis: Some(BNetwork::Signet.genesis().into()), tip_height: 270_000, tip_hash: "00".repeat(32), rtt_ms: 1, server_version: None };
    poll_all(&h.node, |t| match t.id.as_str() {
        "electrum.blockstream.info" => Health::observed(t.network, signet_genesis.clone(), now()),
        _ => ok(t),
    });
    let row = v(h.node.source_health("mainnet"))["sources"].as_array().unwrap().iter().find(|s| s["id"] == "electrum.blockstream.info").unwrap().clone();
    assert_eq!(row["state"], "wrong_network");
    assert_eq!(v(h.node.route_table("mainnet"))["unrouted"][0]["reason"], health::WRONG_NETWORK);
    // Two operators' tips 3 blocks apart disagree.
    h.node.set_source("mainnet", "electrum.blockstream.info", r#"{"use":false}"#);
    h.node.set_source("mainnet", "mempool.space", r#"{"use":true}"#);
    poll_all(&h.node, |t| match t.id.as_str() {
        "mempool.space" => answer(t.network, 970_841),
        _ => ok(t),
    });
    assert_eq!(v(h.node.source_health("mainnet"))["overall"], "disagreement");
    // Without a proxy nothing is dialled: Tor sources read no_route.
    h.node.set_proxy("");
    poll_all(&h.node, ok);
    let sh = v(h.node.source_health("signet"));
    assert_eq!((sh["overall"].as_str(), sh["sources"][1]["state"].as_str()), (Some("offline"), Some("no_route")));
}

#[test]
fn state_persists() {
    let h = configured();
    h.node.set_proxy("socks5h://127.0.0.1:19050");
    h.node.set_own_peers("signet", r#"["10.0.0.2:38333"]"#);
    h.node.report_mismatch("mainnet", "blockstream.info-onion", "stale", "970000");
    let path = h.dir.path().join(crate::store::FILE_NAME);
    let again = Node::open(Some(path), Arc::new(|_| {}));
    for net in ["mainnet", "testnet4", "signet"] {
        assert_eq!(again.get_sources(net), h.node.get_sources(net));
        assert_eq!(again.route_table(net), h.node.route_table(net), "{net}: the same daily peers too");
        assert_eq!(again.peer_list(net), h.node.peer_list(net));
    }
    assert_eq!(v(again.source_health("mainnet"))["sources"][1]["suspectHeight"], "970000");
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
    assert_eq!(ids(&rt, "chain"), ["local", "kyoto"]);
    assert_eq!(rt["chain"][0]["url"], LOCAL_URL);
    assert_eq!((ids(&rt, "pending"), ids(&rt, "broadcast")), (vec!["local".to_string()], vec!["local".to_string(), "kyoto".into()]));
    h.node.set_local_status(Arc::new(FakeLocal(json!({"state": "running", "network": "signet", "blocks": 270000}))));
    let st = v(h.node.local_node("signet"));
    assert_eq!((&st["enabled"], &st["available"], &st["status"]["blocks"]), (&json!(true), &json!(true), &json!(270000)));
    assert_eq!(v(h.node.local_node("mainnet"))["available"], false);
    assert!(v(h.node.set_source("signet", LOCAL_ID, r#"{"tor":true}"#))["error"].as_str().unwrap().contains("Logos IPC"));
}

#[test]
fn probe_and_refresh_need_the_health_thread() {
    let h = configured();
    assert_eq!(v(h.node.probe("signet", "blockstream.info-onion"))["error"], "the health thread is not running");
    assert!(v(h.node.refresh_peer_list("mainnet"))["error"].as_str().unwrap().contains("no refresh URL"));
    assert_eq!(v(h.node.probe("signet", "nope"))["error"], "unknown source nope");
    // Kyoto and the local node are not dialled by this module: their state answers at once.
    let p = v(h.node.probe("signet", KYOTO_ID));
    assert_eq!((&p["answered"], p["sources"][0]["state"].as_str()), (&json!(true), Some("no_peers")));
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
        {"id": "public", "kind": "esplora", "url": "https://esplora.example/api"},
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
    assert_eq!(seen, [format!("{o}:110"), "esplora.example:443".into()], "only Tor routes, by name");
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
fn refresh_keeps_a_newer_list_only_when_its_signature_checks() {
    let srv = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}/peers.json", srv.local_addr().unwrap().port());
    let newer = PeerList { version: 2, date: Some("2026-10-10".into()), key_id: Some("k".into()), signature: Some("00".into()), refresh_url: Some(url.clone()), ..peers::shipped(BNetwork::Signet) };
    let body = serde_json::to_string(&newer).unwrap();
    std::thread::spawn(move || {
        for s in srv.incoming().flatten() {
            let mut s = s;
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
        }
    });
    for (verify, kept) in [(peers::verify_stub as Verify, false), ((|_: &PeerList| Ok(())) as Verify, true)] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(crate::store::FILE_NAME);
        // A stored list that names where newer ones are published.
        let mut store = Store::empty();
        store.proxy = Some(None);
        let mut cfg = NetConfig::seeded(BNetwork::Signet);
        cfg.peer_list = Some(PeerList { version: 1, refresh_url: Some(url.clone()), ..peers::shipped(BNetwork::Signet) });
        store.networks.insert(BNetwork::Signet, cfg);
        store.save(&path).unwrap();
        let node = Node::open_with(Some(path), Arc::new(|_| {}), verify);
        let poller = crate::poll::Poller::start(node.clone()).unwrap();
        let r = v(node.refresh_peer_list("signet"));
        if kept {
            assert_eq!((&r["updated"], &r["list"]["version"], &r["source"]), (&json!(true), &json!("2"), &json!("fetched")), "{r}");
        } else {
            assert!(r["error"].as_str().unwrap().contains("stub"), "{r}");
            assert_eq!(v(node.peer_list("signet"))["list"]["version"], "1");
        }
        assert!(poller.stop(Duration::from_millis(1000)));
    }
}
