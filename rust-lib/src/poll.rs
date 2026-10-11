//! The health thread: probes every enabled server once a minute, four at a time, one Tor
//! circuit each, and runs the probes and peer list fetches callers hand it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use futures_util::{stream, StreamExt};
use tokio::sync::Notify;

use crate::health::{Health, State};
use crate::net::socks::{Isolation, ProxyAddr};
use crate::net::{electrum, esplora, http};
use crate::node::{now, Job, Node, Target};
use crate::peers;
use crate::sources::{self, Kind};

pub const POLL_INTERVAL: Duration = Duration::from_secs(60);
/// A cold onion circuit took 27 s for the Zcash module; this leaves room for that.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(50);
pub const MAX_CONCURRENT: usize = 4;

pub struct Poller {
    stop: Arc<AtomicBool>,
    stop_notify: Arc<Notify>,
    done: mpsc::Receiver<()>,
    handle: Option<JoinHandle<()>>,
}

impl Poller {
    /// Starts the thread. It probes straight away.
    pub fn start(node: Arc<Node>) -> std::io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_notify = Arc::new(Notify::new());
        let (done_tx, done) = mpsc::channel();
        // Callers may hand it work as soon as this returns.
        let (jobs_tx, jobs) = tokio::sync::mpsc::unbounded_channel();
        node.set_jobs(Some(jobs_tx));
        let handle = std::thread::Builder::new().name("bitcoin-node-health".into()).spawn({
            let (stop, stop_notify, node) = (stop.clone(), stop_notify.clone(), node.clone());
            move || {
                run(&node, jobs, &stop, &stop_notify);
                let _ = done_tx.send(());
            }
        });
        let handle = match handle {
            Ok(h) => h,
            Err(e) => {
                node.set_jobs(None);
                return Err(e);
            }
        };
        Ok(Self { stop, stop_notify, done, handle: Some(handle) })
    }

    /// Stops the thread, cancelling calls in flight, and joins it if it ends within
    /// `within`. Returns whether it was joined.
    pub fn stop(mut self, within: Duration) -> bool {
        self.signal();
        match self.done.recv_timeout(within) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                if let Some(h) = self.handle.take() {
                    let _ = h.join();
                }
                true
            }
            Err(RecvTimeoutError::Timeout) => false,
        }
    }

    fn signal(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.stop_notify.notify_one();
    }
}

impl Drop for Poller {
    fn drop(&mut self) {
        self.signal();
    }
}

fn run(node: &Arc<Node>, rx: tokio::sync::mpsc::UnboundedReceiver<Job>, stop: &AtomicBool, stop_notify: &Notify) {
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("bitcoin_node_module: health runtime: {e}");
            node.set_jobs(None);
            return;
        }
    };
    let mut prober = Prober::default();
    rt.block_on(async {
        let jobs = tokio::spawn(serve(node.clone(), rx));
        while !stop.load(Ordering::SeqCst) {
            let next = tokio::time::Instant::now() + POLL_INTERVAL;
            tokio::select! {
                _ = cycle(node, &mut prober) => {}
                _ = stop_notify.notified() => break,
            }
            tokio::select! {
                _ = tokio::time::sleep_until(next) => {}
                _ = node.wake().notified() => {}
                _ = stop_notify.notified() => break,
            }
        }
        jobs.abort();
    });
    // Callers still waiting see their reply channel close.
    node.set_jobs(None);
    drop(prober);
    rt.shutdown_background();
}

async fn serve(node: Arc<Node>, mut rx: tokio::sync::mpsc::UnboundedReceiver<Job>) {
    while let Some(job) = rx.recv().await {
        tokio::spawn(run_job(node.clone(), job));
    }
}

async fn run_job(node: Arc<Node>, job: Job) {
    match job {
        Job::Probe { targets, done } => {
            let mut results = stream::iter(targets)
                .map(|t| async move {
                    let h = probe(&t, &Isolation::fresh(), true).await;
                    (t, h)
                })
                .buffer_unordered(MAX_CONCURRENT);
            while let Some((t, h)) = results.next().await {
                node.record(&t, h);
            }
            node.flush();
            let _ = done.send(());
        }
        Job::Fetch { url, route, proxy, done } => {
            let proxy = match proxy.as_deref().map(ProxyAddr::parse).transpose() {
                Ok(p) => p,
                Err(e) => {
                    let _ = done.send(Err(e));
                    return;
                }
            };
            let iso = Isolation::fresh();
            let fetched = http::fetch(&url, route, proxy.as_ref(), &iso, peers::MAX_LIST_BYTES);
            let r = match tokio::time::timeout(PROBE_TIMEOUT, fetched).await {
                Ok(r) => r.map(|b| b.to_vec()),
                Err(_) => Err("timed out".into()),
            };
            let _ = done.send(r);
        }
    }
}

/// The circuit of one server for the session: fixed SOCKS credentials, and whether its
/// genesis block was checked on it (Esplora asks once; Electrum's features carry it).
struct Circuit {
    isolation: Isolation,
    genesis_ok: bool,
}

#[derive(Default)]
struct Prober {
    circuits: HashMap<Target, Circuit>,
}

async fn cycle(node: &Node, prober: &mut Prober) {
    let (targets, skipped) = node.poll_plan();
    for (t, why) in &skipped {
        node.record(t, Health::no_route(why, now()));
    }
    prober.circuits.retain(|t, _| targets.contains(t));
    let jobs: Vec<(Target, Isolation, bool)> = targets
        .into_iter()
        .map(|t| {
            let c = prober.circuits.entry(t.clone()).or_insert_with(|| Circuit { isolation: Isolation::fresh(), genesis_ok: false });
            let (iso, check) = (c.isolation.clone(), !c.genesis_ok);
            (t, iso, check)
        })
        .collect();
    let mut results = stream::iter(jobs)
        .map(|(t, iso, check)| async move {
            let h = probe(&t, &iso, check).await;
            (t, h, check)
        })
        .buffer_unordered(MAX_CONCURRENT);
    while let Some((t, h, checked)) = results.next().await {
        if let Some(c) = prober.circuits.get_mut(&t) {
            c.genesis_ok = match h.state {
                State::Ok if checked => true,
                State::WrongNetwork => false,
                _ => c.genesis_ok,
            };
        }
        node.record(&t, h);
    }
    node.flush();
}

/// Probes one server on its route with address-free calls only.
pub async fn probe(t: &Target, iso: &Isolation, check_genesis: bool) -> Health {
    let proxy = match t.proxy.as_deref().map(ProxyAddr::parse).transpose() {
        Ok(p) => p,
        Err(e) => return Health::unreachable(e, now()),
    };
    let creds = t.credentials.as_ref().map(|c| (c.username.as_str(), c.password.as_str()));
    let pin = t.cert_sha256.as_deref().and_then(sources::pin_bytes);
    let attempt = async {
        match t.kind {
            Kind::Electrum => electrum::probe(&t.url, t.route, proxy.as_ref(), iso, pin).await,
            Kind::Esplora => esplora::probe(&t.url, creds, t.route, proxy.as_ref(), iso, check_genesis, pin).await,
            Kind::Kyoto | Kind::Local => (Err("not probed by this module".into()), None),
        }
    };
    match tokio::time::timeout(PROBE_TIMEOUT, attempt).await {
        Ok((Ok(o), certificate)) => Health { certificate, ..Health::observed(t.network, o, now()) },
        Ok((Err(e), certificate)) => Health { certificate, ..Health::unreachable(e.chars().take(240).collect::<String>(), now()) },
        Err(_) => Health::unreachable("timed out", now()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Sink;
    use std::time::Instant;

    #[test]
    fn stops_within_a_second_while_calls_hang() {
        // A proxy that accepts and never answers: every probe hangs until stopped.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let dir = tempfile::tempdir().unwrap();
        let sink: Sink = Arc::new(|_| {});
        let node = Node::open(Some(dir.path().join(crate::store::FILE_NAME)), sink);
        assert!(node.init_defaults().starts_with(r#"{"ok":true"#));
        assert!(node.set_proxy(&format!("socks5h://127.0.0.1:{port}")).starts_with(r#"{"ok":true"#));
        let poller = Poller::start(node.clone()).unwrap();
        let mut held = Vec::new();
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while held.len() < 3 && Instant::now() < deadline {
            match listener.accept() {
                Ok((s, _)) => held.push(s),
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        assert_eq!(held.len(), 3, "one fee server per network, dialled at once");
        let started = Instant::now();
        assert!(poller.stop(Duration::from_millis(1000)), "joined");
        assert!(started.elapsed() < Duration::from_millis(1000));
    }

    #[tokio::test]
    async fn a_pinned_server_is_probed_and_a_wrong_pin_refused() {
        use crate::net::cert::tests::{V1, V1_KEY, V3, V3_KEY};
        use crate::net::client::tests::{pin_of, tls_server};
        let electrum = tls_server(V1, V1_KEY, false).await;
        let esplora = tls_server(V3, V3_KEY, false).await;
        for (kind, url, cert) in [
            (Kind::Electrum, format!("ssl://127.0.0.1:{electrum}"), V1),
            (Kind::Esplora, format!("https://127.0.0.1:{esplora}/api"), V3),
        ] {
            let t = Target {
                network: crate::network::BNetwork::Mainnet,
                id: "mine".into(),
                kind,
                url,
                route: crate::net::client::Route::Direct,
                proxy: None,
                credentials: None,
                cert_sha256: Some(hex::encode(pin_of(cert))),
            };
            let h = probe(&t, &Isolation::fresh(), true).await;
            assert_eq!((h.state, h.tip_height), (State::Ok, Some(970_838)), "{kind:?}: {:?}", h.error);
            assert!(h.certificate.as_ref().is_some_and(|c| c.trusted && c.cert_sha256 == hex::encode(pin_of(cert))));
            let wrong = probe(&Target { cert_sha256: Some("ab".repeat(32)), ..t.clone() }, &Isolation::fresh(), true).await;
            assert_eq!(wrong.state, State::Unreachable, "{kind:?}");
            assert!(wrong.error.as_deref().is_some_and(|e| e.contains("not the pinned one")), "{:?}", wrong.error);
            assert!(wrong.certificate.is_some_and(|c| !c.trusted && c.cert_sha256 == hex::encode(pin_of(cert))), "offered to pin anew");
            // Unpinned, the web PKI refuses the self-signed certificate and the probe shows it.
            let unpinned = probe(&Target { cert_sha256: None, ..t }, &Isolation::fresh(), true).await;
            let c = unpinned.certificate.expect("shown for Trust this certificate?");
            assert_eq!((unpinned.state, c.trusted), (State::Unreachable, false));
        }
    }

    #[test]
    fn bad_proxies_and_unprobed_kinds() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let t = Target {
            network: crate::network::BNetwork::Signet,
            id: "x".into(),
            kind: Kind::Kyoto,
            url: "p2p://peer-list".into(),
            route: crate::net::client::Route::Onion,
            proxy: Some("socks5://bad".into()),
            credentials: None,
            cert_sha256: None,
        };
        let h = rt.block_on(probe(&t, &Isolation::fresh(), false));
        assert_eq!(h.state, State::Unreachable);
        let t = Target { proxy: None, ..t };
        assert_eq!(rt.block_on(probe(&t, &Isolation::fresh(), false)).error.as_deref(), Some("not probed by this module"));
    }
}
