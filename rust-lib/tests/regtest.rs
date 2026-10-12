//! Regtest in its own process. The live check needs electrs on loopback (REGTEST_ESPLORA optional):
//! REGTEST_ELECTRUM=tcp://127.0.0.1:60401 cargo test --no-default-features --test regtest -- --ignored --nocapture
//! The harvest check starts its own bitcoind (31.x): BITCOIND=/path/to/bitcoind ... -- --ignored harvest_against

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
    let own = json!([{"peer": "127.0.0.1:18444", "source": "own", "ok": false}]);
    assert_eq!((&rt["peers"], &rt["proxy"], &rt["unrouted"]), (&own, &Value::Null, &json!([])));
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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// JSON-RPC to the test node with its cookie.
fn rpc(port: u16, datadir: &std::path::Path, method: &str, params: Value) -> Result<Value, String> {
    use base64::Engine;
    use std::io::{Read, Write};
    let cookie = std::fs::read_to_string(datadir.join("regtest/.cookie")).map_err(|e| e.to_string())?;
    let body = json!({"jsonrpc": "1.0", "id": "t", "method": method, "params": params}).to_string();
    let auth = base64::engine::general_purpose::STANDARD.encode(cookie.trim());
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    write!(s, "POST / HTTP/1.0\r\nAuthorization: Basic {auth}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).map_err(|e| e.to_string())?;
    let mut out = String::new();
    s.read_to_string(&mut out).map_err(|e| e.to_string())?;
    let json = out.split_once("\r\n\r\n").map(|(_, b)| b).ok_or("no body")?;
    let v: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    if !v["error"].is_null() {
        return Err(v["error"].to_string());
    }
    Ok(v["result"].clone())
}

/// Stops the test bitcoind when dropped, panics included, before its datadir goes.
struct Bitcoind {
    child: std::process::Child,
    rpc_port: u16,
    data: tempfile::TempDir,
}

impl Drop for Bitcoind {
    fn drop(&mut self) {
        let _ = rpc(self.rpc_port, self.data.path(), "stop", json!([]));
        let stop = Instant::now();
        while matches!(self.child.try_wait(), Ok(None)) {
            if stop.elapsed() > Duration::from_secs(30) {
                let _ = self.child.kill();
                let _ = self.child.wait();
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

/// Bitcoin Core on regtest, its address book filled two ways, then the node module's harvest
/// against it, reached directly through regtest's test seeds.
#[test]
#[ignore]
fn harvest_against_a_regtest_bitcoind() {
    use bitcoin_node::net::client::{dial, Route};
    use bitcoin_node::net::p2p::{encode_addrv2, onion_from_key, Gossip, Peer};
    use bitcoin_node::net::socks::Isolation;
    configure();
    let bitcoind = std::env::var("BITCOIND").expect("set BITCOIND to a bitcoind 31 binary");
    let data = tempfile::tempdir().unwrap();
    let (p2p, rpc_port) = (free_port(), free_port());
    // addr permission for loopback: unlimited addr, getaddr without the cache. A dummy onion
    // proxy makes onion addresses reachable, so the node keeps them; it never dials out.
    let child = std::process::Command::new(bitcoind)
        .arg("-regtest")
        .arg(format!("-datadir={}", data.path().display()))
        .args(["-listen=1", "-bind=127.0.0.1", "-server=1", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1"])
        .args(["-whitelist=addr@127.0.0.1", "-onion=127.0.0.1:9", "-connect=0", "-dnsseed=0", "-fixedseeds=0"])
        .args(["-disablewallet=1", "-printtoconsole=0"])
        .arg(format!("-port={p2p}"))
        .arg(format!("-rpcport={rpc_port}"))
        .spawn()
        .unwrap();
    let bitcoind = Bitcoind { child, rpc_port, data };
    let data = bitcoind.data.path();
    let up = Instant::now();
    while rpc(rpc_port, data, "getblockcount", json!([])).is_err() {
        assert!(up.elapsed() < Duration::from_secs(60), "bitcoind did not start");
        std::thread::sleep(Duration::from_millis(200));
    }
    let onion = |i: u8, j: u8| {
        let mut k = [i; 32];
        k[0] = j;
        onion_from_key(&k)
    };
    // addpeeraddress gives NODE_NETWORK | NODE_WITNESS only: no compact filters, never kept.
    let plain: Vec<String> = (0..10).map(|i| onion(1, i)).collect();
    for h in &plain {
        assert_eq!(rpc(rpc_port, data, "addpeeraddress", json!([h, 18444])).unwrap()["success"], true);
    }
    // Gossip with bits 0, 3 and 6, as a peer would relay it.
    let capable: Vec<Gossip> = (0..100).map(|i| Gossip { host: onion(2, i), port: 18444, services: 0x49, time: bitcoin_node::node::now() as u32 }).collect();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let s = dial("127.0.0.1", p2p, Route::Direct, None, &Isolation::fresh()).await.unwrap();
        let (mut peer, _) = Peer::handshake(s, BNetwork::Regtest, bitcoin_node::node::now()).await.unwrap();
        peer.send("addrv2", &encode_addrv2(&capable)).await.unwrap();
        peer.ping().await.unwrap();
    });
    // Addrman drops some on bucket collisions, so most of each kind, not all.
    let known = rpc(rpc_port, data, "getnodeaddresses", json!([0, "onion"])).unwrap();
    let held = |services: u64| known.as_array().unwrap().iter().filter(|e| e["services"] == services).count();
    println!("bitcoind holds {} capable and {} plain onions", held(0x49), held(0x09));
    assert!(held(0x49) >= 50 && held(0x09) >= 1, "{known}");
    // The harvest, as the health thread runs it.
    let dir = tempfile::tempdir().unwrap();
    let node = open(&dir);
    let seed = format!("127.0.0.1:{p2p}");
    node.set_regtest_seeds(std::slice::from_ref(&seed)).unwrap();
    assert!(node.harvest_plan().is_empty(), "no wallet open on regtest");
    node.set_wallet_open("regtest", true);
    let plan = node.harvest_plan();
    assert_eq!((plan.len(), plan[0].seeds.clone(), plan[0].proxy.clone()), (1, vec![(seed.clone(), Route::Direct)], None));
    let learned = rt.block_on(bitcoin_node::poll::harvest(node.clone(), plan[0].clone()));
    let book: Value = serde_json::from_slice(&std::fs::read(dir.path().join("kyoto_peers_regtest.json")).unwrap()).unwrap();
    let kept: Vec<&Value> = book["entries"].as_array().unwrap().iter().filter(|e| e["source"] == "learned").collect();
    println!("getaddr gave {} learned peers of {} capable and {} plain", kept.len(), capable.len(), plain.len());
    assert!(learned >= 1 && kept.len() == learned, "{learned} {book}");
    for e in &kept {
        let host = e["addr"].as_str().unwrap();
        assert!(capable.iter().any(|g| g.host == host) && !plain.contains(&host.to_string()), "{e}");
        assert_eq!((&e["from"], &e["services"], &e["port"]), (&json!(seed), &json!("73"), &json!(18444)));
    }
    assert!(book["harvestedAt"].is_string() && book["harvestAnswered"] == true && node.harvest_plan().is_empty(), "once a day");
    drop(bitcoind);
}

/// A seed that does not answer: the harvest stays unanswered, so it is tried again in an hour.
#[test]
fn a_harvest_no_seed_answers() {
    configure();
    let dir = tempfile::tempdir().unwrap();
    let node = open(&dir);
    let closed = format!("127.0.0.1:{}", free_port());
    node.set_regtest_seeds(std::slice::from_ref(&closed)).unwrap();
    node.set_wallet_open("regtest", true);
    let plan = node.harvest_plan();
    assert_eq!(plan.len(), 1);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    assert_eq!(rt.block_on(bitcoin_node::poll::harvest(node.clone(), plan[0].clone())), 0);
    let book: Value = serde_json::from_slice(&std::fs::read(dir.path().join("kyoto_peers_regtest.json")).unwrap()).unwrap();
    assert_eq!((&book["harvestAnswered"], book["harvestTries"].as_array().unwrap().len()), (&json!(false), 1), "{book}");
    assert!(node.harvest_plan().is_empty(), "not again within the hour");
}
