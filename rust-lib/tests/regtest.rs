//! Regtest in its own process. The live check needs electrs on loopback (REGTEST_ESPLORA optional):
//! REGTEST_ELECTRUM=tcp://127.0.0.1:60401 cargo test --no-default-features --test regtest -- --ignored --nocapture

use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin_node::network::{configure_regtest, networks, BNetwork};
use bitcoin_node::node::Node;
use bitcoin_node::poll::Poller;
use serde_json::{json, Value};

fn configure() {
    configure_regtest();
    assert_eq!(networks(), [BNetwork::Mainnet, BNetwork::Testnet4, BNetwork::Signet, BNetwork::Regtest]);
}

fn v(s: String) -> Value {
    serde_json::from_str(&s).unwrap()
}

/// Configured, with no proxy, so no test dials Tor: only regtest's loopback sources are reached.
fn open(dir: &tempfile::TempDir) -> Arc<Node> {
    let node = Node::open(Some(dir.path().join("bitcoin_sources.json")), Arc::new(|_| {}));
    assert_eq!(v(node.init_defaults())["ok"], true);
    assert_eq!(v(node.set_proxy(""))["proxy"], Value::Null);
    node
}

#[test]
fn regtest_is_kept_once_configured() {
    configure();
    let dir = tempfile::tempdir().unwrap();
    let node = open(&dir);
    assert_eq!(v(node.list_networks())["networks"], json!(["mainnet", "testnet4", "signet", "regtest"]));
    assert_eq!(v(node.config_status())["state"], "configured");
    // Kyoto on and the local node off; no public server, so nothing learns anything.
    let s = v(node.get_sources("regtest"));
    let ids: Vec<&str> = s["sources"].as_array().unwrap().iter().map(|x| x["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["kyoto", "local"]);
    assert_eq!(v(node.peer_list("regtest"))["list"]["peers"], json!([]));
}

#[test]
fn route_table_over_loopback() {
    configure();
    let dir = tempfile::tempdir().unwrap();
    let node = open(&dir);
    let p = v(node.set_own_peers("regtest", r#"["127.0.0.1"]"#));
    assert_eq!((p["ownPeers"].clone(), p["route"].as_str()), (json!(["127.0.0.1:18444"]), Some("direct")));
    let list = json!([
        {"id": "kyoto", "kind": "kyoto"},
        {"id": "electrs", "kind": "electrum", "url": "127.0.0.1:60401", "history": true},
        {"id": "esplora", "kind": "esplora", "url": "127.0.0.1:3002"},
    ]);
    let s = v(node.set_sources("regtest", &list.to_string()));
    assert_eq!(s["sources"][1]["url"], "tcp://127.0.0.1:60401");
    assert_eq!(s["sources"][2]["url"], "http://127.0.0.1:3002");
    assert_eq!(s["exposes"][0]["lan"], true);
    assert_eq!(s["withoutTor"], json!([]), "loopback is the user's own network");
    let rt = v(node.route_table("regtest"));
    let ids = |role: &str| rt[role].as_array().unwrap().iter().map(|e| e["id"].as_str().unwrap().to_string()).collect::<Vec<_>>();
    assert_eq!(ids("chain"), ["kyoto"]);
    assert_eq!(ids("history"), ["kyoto", "electrs"]);
    assert_eq!(ids("pending"), ["electrs"]);
    assert_eq!(ids("fees"), ["electrs", "esplora", "kyoto"]);
    assert_eq!(ids("broadcast"), ["kyoto"]);
    assert_eq!(ids("check"), ["electrs", "esplora"]);
    assert!(rt["chain"].as_array().unwrap().iter().chain(rt["check"].as_array().unwrap()).all(|e| e["route"] == "direct"));
    assert_eq!((&rt["peers"], &rt["proxy"], &rt["unrouted"]), (&json!(["127.0.0.1:18444"]), &Value::Null, &json!([])));
    // It persists.
    let again = Node::open(Some(dir.path().join("bitcoin_sources.json")), Arc::new(|_| {}));
    assert_eq!(again.route_table("regtest"), node.route_table("regtest"));
}

#[test]
fn the_poller_dials_regtest_without_a_proxy() {
    configure();
    // A listener that accepts and never answers: the dial itself is what is checked.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    let node = open(&dir);
    let list = json!([{"id": "electrs", "kind": "electrum", "url": format!("tcp://127.0.0.1:{port}")}]);
    assert_eq!(v(node.set_sources("regtest", &list.to_string()))["ok"], true);
    let poller = Poller::start(node.clone()).unwrap();
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut held = None;
    while held.is_none() && Instant::now() < deadline {
        match listener.accept() {
            Ok((s, _)) => held = Some(s),
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    assert!(held.is_some(), "the poller never dialled the regtest server");
    assert!(poller.stop(Duration::from_millis(1000)), "joined");
}

/// The real poller against a regtest Electrum server (electrs) and, optionally, Esplora.
#[test]
#[ignore]
fn poller_reports_a_live_regtest_chain() {
    configure();
    let electrum = std::env::var("REGTEST_ELECTRUM").expect("set REGTEST_ELECTRUM=tcp://127.0.0.1:PORT");
    let esplora = std::env::var("REGTEST_ESPLORA").ok();
    let dir = tempfile::tempdir().unwrap();
    let node = open(&dir);
    let mut list = vec![json!({"id": "electrs", "kind": "electrum", "url": electrum, "operator": "local-electrs"})];
    if let Some(e) = &esplora {
        list.push(json!({"id": "esplora", "kind": "esplora", "url": e, "operator": "local-esplora"}));
    }
    assert_eq!(v(node.set_sources("regtest", &Value::from(list).to_string()))["ok"], true);
    if let Ok(peer) = std::env::var("REGTEST_PEER") {
        assert_eq!(v(node.set_own_peers("regtest", &json!([peer]).to_string()))["ok"], true);
    }
    let poller = Poller::start(node.clone()).unwrap();
    // An explicit probe answers inside the IPC deadline.
    let t0 = Instant::now();
    let p = v(node.probe("regtest", "electrs"));
    println!("probe in {:?}: {p}", t0.elapsed());
    assert_eq!((&p["answered"], p["sources"][0]["state"].as_str()), (&json!(true), Some("ok")), "{p}");
    let deadline = Instant::now() + Duration::from_secs(30);
    while v(node.source_health("regtest"))["pending"] != false && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    let h = v(node.source_health("regtest"));
    println!("{h}\n{}", node.route_table("regtest"));
    for s in h["sources"].as_array().unwrap().iter().filter(|s| s["kind"] == "electrum" || s["kind"] == "esplora") {
        assert_eq!((s["state"].as_str(), s["route"].as_str()), (Some("ok"), Some("direct")), "{s}");
        assert!(s["tipHeight"].as_str().unwrap().parse::<u64>().unwrap() > 0 && s["tipHash"].as_str().unwrap().len() == 64);
    }
    let t0 = Instant::now();
    assert!(poller.stop(Duration::from_millis(1000)));
    println!("poller stopped in {:?}", t0.elapsed());
}
