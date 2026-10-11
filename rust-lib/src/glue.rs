//! Logos glue for `bitcoin_node_module` (rust-first, `concurrency: "multi"`). Replies are
//! flat JSON strings, `{ ok, ... }` or `{ ok: false, error }`; gate.rs says who may call.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use logos_rust_sdk::{AboutToUnload, LogosCaller, Shutdown};

use crate::gate::{Access, Caller, Callers};
use crate::node::{Event, Node, Sink};
use crate::poll::Poller;
use crate::reply;
use crate::store::FILE_NAME;

pub trait BitcoinNodeModule: Send + Sync + 'static {
    /// `{ ok, networks }`: mainnet, testnet4 and signet, and regtest when the instance directory
    /// holds regtest.json.
    fn list_networks(&self) -> String;
    /// `{ ok, state: unconfigured|unready|configured, configured, unconfigured, proxySet, walletOpen }`.
    fn config_status(&self) -> String;
    /// Fills what is absent: the Tor proxy, and each network's sources (Kyoto on, one Esplora
    /// server for fee rates, every other source off). `{ ok, applied }`. Backend only.
    fn init_defaults(&self) -> String;
    /// `{ ok, network, configured, walletOpen, proxy, sources: [{ id, kind, url, operator, label, use,
/// history, tor, lan, hasCredentials, certSha256, route, suspect }], exposes, withoutTor, crossCheck }`; no credential.
    fn get_sources(&self, network: String) -> String;
    /// Replaces the list (a JSON array of sources); answers as get_sources. A source's
/// `certSha256` (TLS servers only) is kept when absent and cleared by null. Plain tcp:// or
/// http:// to a public host is refused with `invalid parameters: …`. Backend only; refused
/// while a wallet is open on `network`.
    fn set_sources(&self, network: String, list_json: String) -> String;
    /// Changes one source: `{ use?, history?, tor?, certSha256? }`. tor: false is refused for an
    /// onion service. certSha256 pins the server's end-entity certificate (64 hex characters,
    /// colons allowed; ssl:// or https:// only); null or "" clears it. Answers as get_sources.
    /// Backend only; refused while a wallet is open.
    fn set_source(&self, network: String, source_id: String, changes_json: String) -> String;
    /// The Tor proxy for every source, socks5h://host:port; empty clears it, which leaves
    /// every source routed through Tor without a route. Backend only; refused while a wallet is open.
    fn set_proxy(&self, proxy: String) -> String;
    /// Whether a wallet is open on `network`, which locks its settings. Backend only.
    fn set_wallet_open(&self, network: String, open: bool) -> String;
    /// `{ ok, network, proxy, chain, history, pending, fees, broadcast, check, peers, crossCheck, unrouted }`,
/// each role `[{ id, kind, url, operator, route: tor|direct|onion, credentials?, certSha256?, userAdded? }]`.
/// Backend and wallet core.
    fn route_table(&self, network: String) -> String;
    /// Marks a source suspect until the backend clears it; `height` decimal, or empty.
    /// Backend and wallet core.
    fn report_mismatch(&self, network: String, source_id: String, kind: String, height: String) -> String;
    /// `{ ok, network, sourceId, cleared }`. Backend only.
    fn clear_suspect(&self, network: String, source_id: String) -> String;
    /// `{ ok, network, list: { format, network, version, created, date, note, refreshUrl, peers,
    /// keyId, signature }, source: shipped|fetched, ownPeers, usable, route, kyotoTor }`.
    fn peer_list(&self, network: String) -> String;
    /// The user's own Kyoto peers (a JSON array of host[:port]), which replace the list; `[]`
    /// goes back to it. Answers as peer_list. Backend only; refused while a wallet is open.
    fn set_own_peers(&self, network: String, peers_json: String) -> String;
    /// Fetches a newer signed list through the proxy and keeps it if its signature checks.
    /// Backend only.
    fn refresh_peer_list(&self, network: String) -> String;
    /// `{ ok, network, overall, pending, sources: [{ id, kind, state, tipHeight, tipHash, rttMs,
    /// route, checkedAt, error, serverVersion, suspect, certificate?, ... }] }` from address-free
    /// calls only. A TLS server's `certificate` is `{ certSha256, subject, issuer, notBefore,
    /// notAfter, trusted }`, also when untrusted, for the app to offer pinning it.
    fn source_health(&self, network: String) -> String;
    /// Probes `source_id` now, or every enabled server when empty, then answers as
    /// source_health plus `answered`, within 15 s.
    fn probe(&self, network: String, source_id: String) -> String;
    /// `{ ok, network, enabled, available, status?, error? }` from bitcoind_module, when loaded.
    fn local_node(&self, network: String) -> String;
    /// `{ ok, network, sourceId, username, password }` of an Esplora server. Wallet core only.
    fn source_credentials(&self, network: String, source_id: String) -> String;

    fn on_context_ready(&self, _ctx: &RustModuleContext) {}
}

#[allow(dead_code)] // Read by logos-lidl-gen, which generates the emitters.
pub trait BitcoinNodeModuleEvents {
    /// source_health()'s reply, when anything but round-trip times changed.
    fn source_health_changed(&self, network: String, payload: String);
    /// route_table(network) would now answer differently.
    fn routes_changed(&self, network: String);
    fn source_suspect(&self, network: String, source_id: String, kind: String);
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
pub struct BitcoinNodeModuleImpl {
    node: OnceLock<Arc<Node>>,
    // Qualified: the generated scaffold already imports `Mutex` into this module.
    callers: std::sync::Mutex<Callers>,
    poller: std::sync::Mutex<Option<Poller>>,
}

impl BitcoinNodeModuleImpl {
    /// Runs `f` for a caller `access` admits, once the node exists. The caller is read
    /// first, on the dispatching thread.
    fn gated(&self, access: Access, f: impl FnOnce(&Node) -> String) -> String {
        let caller = match logos_rust_sdk::current_caller() {
            LogosCaller::Module { name, .. } => Caller::Module(name),
            LogosCaller::HostAnchor => Caller::Host,
            LogosCaller::Unknown => Caller::Unknown,
            _ => Caller::Other,
        };
        if !self.callers.lock().unwrap().admits(access, &caller) {
            return reply::NOT_AUTHORIZED.into();
        }
        match self.node.get() {
            Some(n) => f(n),
            None => reply::err("starting"),
        }
    }
}

impl BitcoinNodeModule for BitcoinNodeModuleImpl {
    fn list_networks(&self) -> String {
        self.gated(Access::Open, |n| n.list_networks())
    }

    fn config_status(&self) -> String {
        self.gated(Access::Open, |n| n.config_status())
    }

    fn init_defaults(&self) -> String {
        self.gated(Access::Backend, |n| n.init_defaults())
    }

    fn get_sources(&self, network: String) -> String {
        self.gated(Access::Open, |n| n.get_sources(&network))
    }

    fn set_sources(&self, network: String, list_json: String) -> String {
        self.gated(Access::Backend, |n| n.set_sources(&network, &list_json))
    }

    fn set_source(&self, network: String, source_id: String, changes_json: String) -> String {
        self.gated(Access::Backend, |n| n.set_source(&network, &source_id, &changes_json))
    }

    fn set_proxy(&self, proxy: String) -> String {
        self.gated(Access::Backend, |n| n.set_proxy(&proxy))
    }

    fn set_wallet_open(&self, network: String, open: bool) -> String {
        self.gated(Access::Backend, |n| n.set_wallet_open(&network, open))
    }

    fn route_table(&self, network: String) -> String {
        self.gated(Access::BackendOrCore, |n| n.route_table(&network))
    }

    fn report_mismatch(&self, network: String, source_id: String, kind: String, height: String) -> String {
        self.gated(Access::BackendOrCore, |n| n.report_mismatch(&network, &source_id, &kind, &height))
    }

    fn clear_suspect(&self, network: String, source_id: String) -> String {
        self.gated(Access::Backend, |n| n.clear_suspect(&network, &source_id))
    }

    fn peer_list(&self, network: String) -> String {
        self.gated(Access::Open, |n| n.peer_list(&network))
    }

    fn set_own_peers(&self, network: String, peers_json: String) -> String {
        self.gated(Access::Backend, |n| n.set_own_peers(&network, &peers_json))
    }

    fn refresh_peer_list(&self, network: String) -> String {
        self.gated(Access::Backend, |n| n.refresh_peer_list(&network))
    }

    fn source_health(&self, network: String) -> String {
        self.gated(Access::Open, |n| n.source_health(&network))
    }

    fn probe(&self, network: String, source_id: String) -> String {
        self.gated(Access::Open, |n| n.probe(&network, &source_id))
    }

    fn local_node(&self, network: String) -> String {
        self.gated(Access::Open, |n| n.local_node(&network))
    }

    fn source_credentials(&self, network: String, source_id: String) -> String {
        self.gated(Access::Core, |n| n.source_credentials(&network, &source_id))
    }

    /// Loads the sources and starts the health thread; the thread makes the calls.
    fn on_context_ready(&self, ctx: &RustModuleContext) {
        let dir = std::path::PathBuf::from(&ctx.instance_persistence_path);
        let callers = std::fs::read_to_string(dir.join("callers.json")).ok();
        *self.callers.lock().unwrap() = Callers::from_file(callers.as_deref());
        // A local test chain, for test harnesses only.
        match std::fs::read_to_string(dir.join("regtest.json")) {
            Ok(t) if crate::network::regtest_file_ok(&t) => crate::network::configure_regtest(),
            Ok(_) => eprintln!("bitcoin_node_module: regtest.json is not a JSON object; regtest stays off"),
            Err(_) => {}
        }
        let sink: Sink = Arc::new(|ev| match ev {
            Event::HealthChanged { network, payload } => emit_source_health_changed(network.name(), &payload),
            Event::RoutesChanged { network } => emit_routes_changed(network.name()),
            Event::Suspect { network, source_id, kind } => emit_source_suspect(network.name(), &source_id, &kind),
        });
        let node = Node::open(Some(dir.join(FILE_NAME)), sink);
        node.set_local_status(Arc::new(BitcoindStatus::default()));
        if self.node.set(node.clone()).is_ok() {
            match Poller::start(node) {
                Ok(p) => *self.poller.lock().unwrap() = Some(p),
                Err(e) => eprintln!("bitcoin_node_module: health thread: {e}"),
            }
        }
    }
}

/// bitcoind_module, an OPTIONAL dependency: when it is not loaded, local_node() says so.
/// The client is made on first use and kept: each new one opens its own connection.
#[derive(Default)]
struct BitcoindStatus(std::sync::OnceLock<bitcoind_module::BitcoindModuleClient>);

/// Bounded so an absent bitcoind_module costs 1.5 s, not the protocol deadline.
const LOCAL_BUDGET: Duration = Duration::from_millis(1500);

impl crate::node::LocalStatus for BitcoindStatus {
    fn status(&self) -> Result<serde_json::Value, String> {
        self.0
            .get_or_init(bitcoind_module::BitcoindModuleClient::new)
            .status_with_timeout(LOCAL_BUDGET)
            .map(|m| serde_json::Value::Object(m.into_iter().collect()))
            .map_err(|e| {
                let s = e.to_string();
                if s.contains("object_unavailable") { "bitcoind_module is not loaded".into() } else { format!("bitcoind_module: {s}") }
            })
    }
}

impl AboutToUnload for BitcoinNodeModuleImpl {
    /// Stops the health thread, cancelling calls in flight, and joins it within ~1 s.
    fn about_to_unload(&self) -> Shutdown {
        if let Some(p) = self.poller.lock().unwrap().take() {
            if !p.stop(Duration::from_millis(1000)) {
                eprintln!("bitcoin_node_module: health thread did not stop within 1 s");
            }
        }
        Shutdown::Synchronous
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    logos_install!(BitcoinNodeModuleImpl);
}
