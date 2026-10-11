//! Live checks over Tor, ignored by default. Run with
//! BITCOIN_TEST_TOR=socks5h://127.0.0.1:9050 cargo test --no-default-features --test live -- --ignored --nocapture

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{stream, StreamExt};
use serde_json::Value;
use bitcoin_node::health::State;
use bitcoin_node::net::client::route_for;
use bitcoin_node::net::socks::Isolation;
use bitcoin_node::network::BNetwork;
use bitcoin_node::node::{Event, Node, Sink, Target};
use bitcoin_node::poll::{probe, Poller};
use bitcoin_node::sources::{self, defaults};

fn tor() -> String {
    std::env::var("BITCOIN_TEST_TOR").expect("set BITCOIN_TEST_TOR=socks5h://127.0.0.1:PORT")
}

/// Every server in the defaults, switched on or not, each on its own circuit, with the
/// address-free calls only.
#[test]
#[ignore]
fn every_default_server_answers() {
    let proxy = tor();
    let mut targets = Vec::new();
    for net in [BNetwork::Mainnet, BNetwork::Testnet4, BNetwork::Signet] {
        for s in defaults(net).into_iter().filter(|s| s.kind.is_server()) {
            let route = route_for(&sources::host(&s), s.tor);
            targets.push(Target { network: net, id: s.id, kind: s.kind, url: s.url, route, proxy: Some(proxy.clone()), credentials: None, cert_sha256: None });
        }
    }
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let results = rt.block_on(
        stream::iter(targets)
            .map(|t| async move {
                let t0 = Instant::now();
                let h = probe(&t, &Isolation::fresh(), true).await;
                (t, h, t0.elapsed())
            })
            .buffer_unordered(4)
            .collect::<Vec<_>>(),
    );
    let mut answered = Vec::new();
    for (t, h, took) in &results {
        println!(
            "{:8} {:32} {:?} {:6?} tip={:?} hash={:?} rttMs={:?} server={:?} error={:?} in {:.1}s",
            t.network.name(), t.id, t.route, h.state, h.tip_height, h.tip_hash.as_deref().map(|x| &x[..16]), h.rtt_ms, h.server_version, h.error, took.as_secs_f64()
        );
        if h.state == State::Ok {
            answered.push((t.network, t.id.clone()));
        }
        assert_ne!(h.state, State::WrongNetwork, "{} {} answers for another network", t.network.name(), t.url);
    }
    // The servers on by default, and Blockstream's Electrum servers over clearnet TLS and onion.
    for (net, id) in [
        (BNetwork::Mainnet, "blockstream.info-onion"),
        (BNetwork::Signet, "blockstream.info-onion"),
        (BNetwork::Testnet4, "electrum-testnet4-onion"),
        (BNetwork::Mainnet, "electrum.blockstream.info"),
        (BNetwork::Mainnet, "electrum.blockstream.info-onion"),
    ] {
        assert!(answered.contains(&(net, id.to_string())), "{} {id} did not answer", net.name());
    }
}

/// The real poller over Tor on the defaults: every network gets health, then it stops in 1 s.
#[test]
#[ignore]
fn poller_reports_and_stops() {
    let dir = tempfile::tempdir().unwrap();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let log = seen.clone();
    let sink: Sink = Arc::new(move |e| {
        if let Event::HealthChanged { network, .. } = e {
            log.lock().unwrap().push(network.name().into());
        }
    });
    let node = Node::open(Some(dir.path().join("bitcoin_sources.json")), sink);
    assert!(node.init_defaults().starts_with(r#"{"ok":true"#));
    assert!(node.set_proxy(&tor()).starts_with(r#"{"ok":true"#));
    let poller = Poller::start(node.clone()).unwrap();
    let health = |n: &str| serde_json::from_str::<Value>(&node.source_health(n)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(150);
    while ["mainnet", "signet"].iter().any(|n| health(n)["pending"] != false) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
    }
    for n in ["mainnet", "testnet4", "signet"] {
        println!("{}\n{}", node.source_health(n), node.route_table(n));
    }
    for n in ["mainnet", "signet"] {
        let h = health(n);
        assert_eq!(h["pending"], false, "{n} still pending");
        let fee = &h["sources"][1];
        assert_eq!((fee["state"].as_str(), fee["route"].as_str()), (Some("ok"), Some("onion")), "{n}: {fee}");
    }
    let t0 = Instant::now();
    assert!(poller.stop(Duration::from_millis(1000)));
    println!("poller stopped in {:?}", t0.elapsed());
    let seen = seen.lock().unwrap();
    assert!(seen.iter().any(|n| n == "mainnet") && seen.iter().any(|n| n == "signet"), "{seen:?}");
}
