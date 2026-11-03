//! What persists, written atomically and owner-only to `bitcoin_sources.json`: the proxy, what
//! Tor is used for, and per network the sources, suspects, own peers and a fetched peer list.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use rand::RngExt;
use serde::{Deserialize, Serialize};

use crate::network::{networks, BNetwork};
use crate::peers;
use crate::proxy;
use crate::sources::{self, Kind, Source};
use crate::strnum::{de, de_opt, double_option, ser, ser_opt};

pub const FILE_NAME: &str = "bitcoin_sources.json";
/// 2: the proxy may be `tor`, the Tor that comes with Logos. 3: `torUse` and `torUseChosen`.
/// 4: no Esplora or PublicNode, and at most one node source on.
pub const VERSION: u32 = 4;

/// Version 3's mainnet Esplora seeds, and the same operator's Electrum entry each moves to.
const ESPLORA_TO_ELECTRUM: [(&str, &str, &str); 2] = [
    ("blockstream.info-onion", "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/api", "electrum.blockstream.info-onion"),
    ("blockstream.info", "https://blockstream.info/api", "electrum.blockstream.info"),
];
const PUBLICNODE: (&str, &str) = ("publicnode-rpc", "https://bitcoin-rpc.publicnode.com");

/// What Tor carries: everything, only what identifies the wallet, or nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TorUse {
    /// The routing of every file before version 3, so an upgrade never weakens it.
    #[default]
    All,
    Identifying,
    None,
}

impl TorUse {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "all" => Some(Self::All),
            "identifying" => Some(Self::Identifying),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    /// Whether any connection goes through Tor.
    pub fn tor(self) -> bool {
        self != Self::None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Suspicion {
    pub kind: String,
    #[serde(serialize_with = "ser_opt", deserialize_with = "de_opt", default)]
    pub height: Option<u64>,
    #[serde(serialize_with = "ser", deserialize_with = "de")]
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetConfig {
    pub sources: Vec<Source>,
    /// By source id.
    #[serde(default)]
    pub suspects: BTreeMap<String, Suspicion>,
    /// Kyoto dials only these when there are any.
    #[serde(default)]
    pub own_peers: Vec<String>,
}

impl NetConfig {
    pub fn seeded(net: BNetwork) -> Self {
        Self { sources: sources::defaults(net), suspects: BTreeMap::new(), own_peers: vec![] }
    }

    pub fn source(&self, id: &str) -> Option<&Source> {
        self.sources.iter().find(|s| s.id == id)
    }

    /// Kyoto's Tor switch, on when Kyoto is not in the list.
    pub fn kyoto_tor(&self) -> bool {
        self.sources.iter().find(|s| s.kind == Kind::Kyoto).is_none_or(|s| s.tor)
    }

    /// Replaces the list, keeping only the suspicions of sources still at the same url.
    pub fn replace_sources(&mut self, list: Vec<Source>) {
        let old = std::mem::replace(&mut self.sources, list);
        let url = |l: &[Source], id: &str| l.iter().find(|s| s.id == id).map(|s| s.url.clone());
        let new = self.sources.clone();
        self.suspects.retain(|id, _| url(&old, id).is_some() && url(&old, id) == url(&new, id));
    }

    /// Version 4 (README, Store): Esplora and PublicNode go, local wins over RPC, and the new
    /// default servers are added off. Pins and credentials stay with the entry they were set on.
    fn upgrade_to_4(&mut self, net: BNetwork) {
        let (mut esplora, mut public_on) = (Vec::new(), false);
        self.sources.retain(|s| {
            let public = (s.id.as_str(), s.url.as_str()) == PUBLICNODE;
            public_on |= public && s.enabled;
            if s.kind == Kind::Esplora {
                esplora.push(s.clone());
            }
            !public && s.kind != Kind::Esplora
        });
        let on = |l: &[Source], kinds: &[Kind]| l.iter().any(|s| s.enabled && kinds.contains(&s.kind));
        if on(&self.sources, &[Kind::Local]) {
            self.sources.iter_mut().filter(|s| s.kind == Kind::Rpc).for_each(|s| s.enabled = false);
        }
        // PublicNode was the only chain source: "Use only this" had switched Kyoto off.
        if public_on && !on(&self.sources, &[Kind::Local, Kind::Rpc, Kind::Kyoto]) {
            self.sources.iter_mut().filter(|s| s.kind == Kind::Kyoto).for_each(|s| s.enabled = true);
        }
        for seed in sources::defaults(net).into_iter().filter(|d| d.kind.is_server()) {
            if self.sources.len() < sources::MAX_SOURCES && !self.sources.iter().any(|s| s.id == seed.id || s.url == seed.url) {
                let at = self.sources.iter().position(|s| s.kind == Kind::Local).unwrap_or(self.sources.len());
                self.sources.insert(at, Source { enabled: false, ..seed });
            }
        }
        // The default fee server moves over when on, any other only with history.
        for e in esplora.iter().filter(|_| net == BNetwork::Mainnet) {
            let Some(&(_, _, to)) = ESPLORA_TO_ELECTRUM.iter().find(|(id, url, _)| (e.id.as_str(), e.url.as_str()) == (*id, *url)) else { continue };
            let Some(t) = self.sources.iter_mut().find(|s| s.id == to && !sources::user_added(s)) else { continue };
            if e.history || (e.enabled && e.id == ESPLORA_TO_ELECTRUM[0].0) {
                if !t.enabled {
                    t.tor = e.tor;
                }
                t.enabled |= e.enabled;
                t.history |= e.history;
            }
        }
        let ids: Vec<String> = self.sources.iter().map(|s| s.id.clone()).collect();
        self.suspects.retain(|id, _| ids.contains(id));
    }

    pub fn validate(&self, net: BNetwork) -> Result<(), String> {
        sources::validate(&self.sources)?;
        if self.own_peers.len() > peers::MAX_OWN_PEERS {
            return Err(format!("at most {} peers of your own", peers::MAX_OWN_PEERS));
        }
        for p in &self.own_peers {
            if peers::normalize_peer(net, p).as_deref() != Ok(p.as_str()) {
                return Err(format!("own peer {p} is not normalized"));
            }
        }
        peers::check_own(&self.own_peers, self.kyoto_tor())?;
        match self.suspects.keys().find(|id| self.source(id).is_none()) {
            Some(id) => Err(format!("suspect {id} is not a source")),
            None => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Store {
    pub version: u32,
    /// Absent until set or defaulted; null once cleared, which leaves Tor routes closed.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "double_option")]
    pub proxy: Option<Option<String>>,
    /// Per install. No longer read since the wallet core picks Kyoto's peers; kept so stored
    /// files, which carry it, still load.
    #[serde(default)]
    pub salt: String,
    #[serde(default)]
    pub networks: BTreeMap<BNetwork, NetConfig>,
    #[serde(default)]
    pub tor_use: TorUse,
    /// Set once the person picked `tor_use`; until then the app asks before any account.
    #[serde(default)]
    pub tor_use_chosen: bool,
}

pub enum Loaded {
    Absent,
    Found(Store),
    Corrupt(String),
}

fn fresh_salt() -> String {
    let mut b = [0u8; 16];
    rand::rng().fill(&mut b[..]);
    hex::encode(b)
}

impl Store {
    /// Nothing configured: the backend calls init_defaults. A new install starts at
    /// `identifying`, not yet chosen.
    pub fn empty() -> Self {
        Self { version: VERSION, proxy: None, salt: fresh_salt(), networks: BTreeMap::new(), tor_use: TorUse::Identifying, tor_use_chosen: false }
    }

    /// Version 1's default, a Tor the user had to run, becomes the Tor that comes with Logos,
    /// once: the file keeps version 1 until the next save, so an older build still reads it.
    /// Before version 3 everything went through Tor: `all`, not chosen.
    fn upgrade(&mut self) {
        if self.version == 1 && self.proxy() == Some(proxy::OLD_DEFAULT_PROXY) {
            self.proxy = Some(Some(proxy::BUILT_IN.into()));
        }
        if self.version < 3 {
            (self.tor_use, self.tor_use_chosen) = (TorUse::All, false);
        }
        if self.version < 4 {
            self.networks.iter_mut().for_each(|(net, cfg)| cfg.upgrade_to_4(*net));
        }
        self.version = VERSION;
    }

    pub fn proxy(&self) -> Option<&str> {
        self.proxy.as_ref().and_then(|p| p.as_deref())
    }

    pub fn validate(&self) -> Result<(), String> {
        if let Some(Some(p)) = &self.proxy {
            if proxy::normalize(p)? != *p {
                return Err(format!("proxy {p} is not normalized"));
            }
        }
        for (net, cfg) in &self.networks {
            cfg.validate(*net).map_err(|e| format!("{}: {e}", net.name()))?;
        }
        Ok(())
    }

    /// Reads the file. Regtest is dropped unless it is configured.
    pub fn load(path: &Path) -> Loaded {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Loaded::Absent,
            Err(e) => return Loaded::Corrupt(e.to_string()),
        };
        let mut store: Store = match serde_json::from_str(&text) {
            Ok(s) => s,
            Err(e) => return Loaded::Corrupt(e.to_string()),
        };
        if !(1..=VERSION).contains(&store.version) {
            return Loaded::Corrupt(format!("unknown version {}", store.version));
        }
        store.upgrade();
        let kept = networks();
        store.networks.retain(|net, _| kept.contains(net));
        if let Err(e) = store.validate() {
            return Loaded::Corrupt(e);
        }
        if store.salt.len() != 32 || !store.salt.bytes().all(|b| b.is_ascii_hexdigit()) {
            store.salt = fresh_salt();
        }
        Loaded::Found(store)
    }

    /// Writes `<file>.tmp` (owner-only), syncs it, then renames it over the file.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = tmp_path(path);
        let body = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let mut f = opts.open(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    }

    /// Loads the file, or starts empty when it is absent. A corrupt file is kept aside as
    /// `<file>.corrupt` and replaced by an empty store, which config_status reports.
    pub fn load_or_empty(path: &Path) -> Self {
        let store = match Self::load(path) {
            Loaded::Found(s) => return s,
            Loaded::Absent => Self::empty(),
            Loaded::Corrupt(why) => {
                eprintln!("bitcoin_node_module: {} is unusable ({why}); starting unconfigured", path.display());
                let _ = std::fs::rename(path, corrupt_path(path));
                Self::empty()
            }
        };
        if let Err(e) = store.save(path) {
            eprintln!("bitcoin_node_module: writing {}: {e}", path.display());
        }
        store
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

pub fn tmp_path(path: &Path) -> PathBuf {
    with_suffix(path, ".tmp")
}

pub fn corrupt_path(path: &Path) -> PathBuf {
    with_suffix(path, ".corrupt")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::Credentials;

    fn configured() -> Store {
        let mut s = Store::empty();
        s.proxy = Some(Some(proxy::DEFAULT_PROXY.into()));
        for net in networks() {
            s.networks.insert(net, NetConfig::seeded(net));
        }
        s
    }

    fn esplora(id: &str, url: &str, operator: &str, on: bool) -> Source {
        Source { id: id.into(), kind: Kind::Esplora, url: url.into(), operator: operator.into(), label: id.into(), enabled: on, history: false, tor: true, credentials: None, cert_sha256: None }
    }

    fn rpc(id: &str, url: &str, on: bool) -> Source {
        Source { id: id.into(), kind: Kind::Rpc, url: url.into(), operator: "node".into(), label: id.into(), enabled: on, history: false, tor: false, credentials: None, cert_sha256: None }
    }

    const MEMPOOL_ONION: &str = "http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion";

    /// A version 3 store with that version's defaults: Esplora fee servers on mainnet and signet.
    fn version_3() -> Store {
        let mut s = configured();
        s.version = 3;
        let (onion, bi) = (ESPLORA_TO_ELECTRUM[0].1, ESPLORA_TO_ELECTRUM[1].1);
        let electrum: Vec<Source> = sources::defaults(BNetwork::Mainnet).into_iter().filter(|s| s.kind == Kind::Electrum).map(|s| Source { enabled: false, ..s }).collect();
        let mut main = vec![sources::kyoto(true), esplora("blockstream.info-onion", onion, "blockstream.info", true), esplora("blockstream.info", bi, "blockstream.info", false)];
        main.push(esplora("mempool.space-onion", &format!("{MEMPOOL_ONION}/api"), "mempool.space", false));
        main.push(esplora("mempool.space", "https://mempool.space/api", "mempool.space", false));
        main.extend(electrum);
        main.extend([rpc(PUBLICNODE.0, PUBLICNODE.1, false), sources::local(false)]);
        s.networks.get_mut(&BNetwork::Mainnet).unwrap().sources = main;
        let signet = onion.replace("/api", "/signet/api");
        s.networks.get_mut(&BNetwork::Signet).unwrap().sources = vec![
            sources::kyoto(true),
            esplora("blockstream.info-onion", &signet, "blockstream.info", true),
            esplora("blockstream.info", "https://blockstream.info/signet/api", "blockstream.info", false),
            esplora("mempool.space-onion", &format!("{MEMPOOL_ONION}/signet/api"), "mempool.space", false),
            esplora("mempool.space", "https://mempool.space/signet/api", "mempool.space", false),
            sources::local(false),
        ];
        s
    }

    /// Saves `old`, loads it, and checks the file keeps its version until the next save.
    fn upgraded(old: &Store) -> Store {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        old.save(&path).unwrap();
        let Loaded::Found(up) = Store::load(&path) else { panic!("set aside") };
        assert!(std::fs::read_to_string(&path).unwrap().contains(&format!("\"version\": {}", old.version)), "an older build still reads it");
        assert_eq!(up.version, VERSION);
        up.save(&path).unwrap();
        let Loaded::Found(again) = Store::load(&path) else { panic!() };
        assert_eq!(again, up);
        up
    }

    fn net(s: &mut Store, n: BNetwork) -> &mut NetConfig {
        s.networks.get_mut(&n).unwrap()
    }

    fn find<'a>(s: &'a Store, n: BNetwork, id: &str) -> Option<&'a Source> {
        s.networks[&n].source(id)
    }

    #[test]
    fn version_3_defaults_become_version_4_defaults() {
        let up = upgraded(&version_3());
        for n in [BNetwork::Mainnet, BNetwork::Testnet4, BNetwork::Signet] {
            assert_eq!(up.networks[&n].sources, sources::defaults(n), "{n:?}: the Electrum onion takes fees; the signet servers come off, pinned");
        }
    }

    #[test]
    fn esplora_with_history_moves_to_the_operators_electrum_entry() {
        let mut old = version_3();
        for id in ["blockstream.info", "blockstream.info-onion", "mempool.space"] {
            let s = net(&mut old, BNetwork::Mainnet).sources.iter_mut().find(|s| s.id == id).unwrap();
            (s.enabled, s.history, s.tor) = (true, true, id == "blockstream.info-onion");
        }
        let bi = net(&mut old, BNetwork::Mainnet).sources.iter_mut().find(|s| s.id == "blockstream.info").unwrap();
        bi.credentials = Some(Credentials { username: "u".into(), password: "p".into() });
        bi.cert_sha256 = Some("ab".repeat(32));
        net(&mut old, BNetwork::Signet).sources[1].history = true;
        let up = upgraded(&old);
        let e = find(&up, BNetwork::Mainnet, "electrum.blockstream.info").unwrap();
        assert_eq!((e.enabled, e.history, e.tor), (true, true, false), "the same use, history and tor");
        assert_eq!((&e.credentials, &e.cert_sha256), (&None, &None), "no pin or credentials carried over");
        let o = find(&up, BNetwork::Mainnet, "electrum.blockstream.info-onion").unwrap();
        assert_eq!((o.enabled, o.history, o.tor), (true, true, true));
        assert!(up.networks[&BNetwork::Mainnet].sources.iter().all(|s| s.operator != "mempool.space"), "no Electrum entry of its own: removed");
        assert_eq!(up.networks[&BNetwork::Signet].sources, sources::defaults(BNetwork::Signet), "signet has no Electrum default on");

        // A history server switched off keeps history, off; one already on keeps its own tor.
        let mut old = version_3();
        let main = net(&mut old, BNetwork::Mainnet);
        main.sources.iter_mut().filter(|s| s.id == "blockstream.info").for_each(|s| (s.history, s.tor) = (true, false));
        main.sources.iter_mut().filter(|s| s.id == "electrum.blockstream.info-onion").for_each(|s| s.enabled = true);
        main.sources.iter_mut().filter(|s| s.id == "blockstream.info-onion").for_each(|s| (s.enabled, s.history) = (false, true));
        let up = upgraded(&old);
        let e = find(&up, BNetwork::Mainnet, "electrum.blockstream.info").unwrap();
        assert_eq!((e.enabled, e.history, e.tor), (false, true, false));
        let o = find(&up, BNetwork::Mainnet, "electrum.blockstream.info-onion").unwrap();
        assert_eq!((o.enabled, o.history, o.tor), (true, true, true));
    }

    #[test]
    fn other_esplora_entries_and_their_suspicions_go() {
        let mut old = version_3();
        let main = net(&mut old, BNetwork::Mainnet);
        main.sources.iter_mut().for_each(|s| s.enabled = s.kind != Kind::Esplora || s.id == "blockstream.info");
        main.sources.retain(|s| s.kind != Kind::Rpc);
        main.sources.insert(1, Source { credentials: Some(Credentials { username: "u".into(), password: "p".into() }), ..esplora("mine", "https://esplora.example/api", "example", true) });
        main.suspects.insert("blockstream.info".into(), Suspicion { kind: "anchor_mismatch".into(), height: None, at: 1 });
        main.suspects.insert(sources::KYOTO_ID.into(), Suspicion { kind: "authority_suspect".into(), height: None, at: 2 });
        let up = upgraded(&old);
        let main = &up.networks[&BNetwork::Mainnet];
        let ids: Vec<&str> = main.sources.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["kyoto", "electrum.blockstream.info-onion", "electrum.blockstream.info", "local"], "user-added and fee-only Esplora removed");
        assert!(main.sources.iter().all(|s| s.enabled), "what was on stays on");
        assert_eq!(main.suspects.keys().collect::<Vec<_>>(), ["kyoto"]);
    }

    #[test]
    fn publicnode_goes_and_kyoto_comes_back_if_it_was_alone() {
        let mut old = version_3();
        // "Use only this": PublicNode on, every other source off.
        net(&mut old, BNetwork::Mainnet).sources.iter_mut().for_each(|s| s.enabled = s.id == PUBLICNODE.0);
        let up = upgraded(&old);
        let main = &up.networks[&BNetwork::Mainnet];
        assert!(main.source(PUBLICNODE.0).is_none());
        assert_eq!(main.sources.iter().filter(|s| s.enabled).map(|s| s.id.as_str()).collect::<Vec<_>>(), ["kyoto"]);

        // Beside your node it just goes; your own entry for its URL stays.
        let mut old = version_3();
        net(&mut old, BNetwork::Mainnet).sources.iter_mut().for_each(|s| s.enabled = matches!(s.kind, Kind::Rpc | Kind::Local));
        let up = upgraded(&old);
        let main = &up.networks[&BNetwork::Mainnet];
        assert_eq!(main.sources.iter().filter(|s| s.enabled).map(|s| s.id.as_str()).collect::<Vec<_>>(), ["local"]);
        assert!(main.source(PUBLICNODE.0).is_none());
        let mut old = version_3();
        let main = net(&mut old, BNetwork::Mainnet);
        main.sources.retain(|s| s.id != PUBLICNODE.0);
        main.sources.push(rpc("my-publicnode", PUBLICNODE.1, true));
        assert_eq!(find(&upgraded(&old), BNetwork::Mainnet, "my-publicnode").map(|s| s.enabled), Some(true), "the user's, not the catalog's");
    }

    #[test]
    fn local_wins_over_rpc() {
        let mut old = version_3();
        let main = net(&mut old, BNetwork::Mainnet);
        main.sources.retain(|s| s.id != PUBLICNODE.0);
        main.sources.push(Source { credentials: Some(Credentials { username: "u".into(), password: "p".into() }), ..rpc("nas", "http://192.168.1.20:8332", true) });
        main.sources.iter_mut().filter(|s| s.kind == Kind::Local).for_each(|s| s.enabled = true);
        let up = upgraded(&old);
        let (local, nas) = (find(&up, BNetwork::Mainnet, "local").unwrap(), find(&up, BNetwork::Mainnet, "nas").unwrap());
        assert_eq!((local.enabled, nas.enabled, nas.credentials.is_some()), (true, false, true), "switched off, not deleted");
        // Without the local node on, the RPC endpoint stays on.
        net(&mut old, BNetwork::Mainnet).sources.iter_mut().filter(|s| s.kind == Kind::Local).for_each(|s| s.enabled = false);
        assert!(find(&upgraded(&old), BNetwork::Mainnet, "nas").unwrap().enabled);
    }

    #[test]
    fn new_default_servers_are_added_off_once() {
        let mut old = version_3();
        let signet = net(&mut old, BNetwork::Signet);
        signet.sources.push(Source { id: "mine".into(), url: "ssl://electrum.emzy.de:53002".into(), ..sources::defaults(BNetwork::Signet)[1].clone() });
        let up = upgraded(&old);
        let ids: Vec<&str> = up.networks[&BNetwork::Signet].sources.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["kyoto", "signet-electrumx.wakiyamap.dev", "local", "mine"], "not twice under another id");
        // A full list takes what fits.
        let mut full = version_3();
        let signet = net(&mut full, BNetwork::Signet);
        signet.sources.retain(|s| s.kind != Kind::Esplora);
        for i in signet.sources.len()..sources::MAX_SOURCES - 1 {
            signet.sources.push(Source { id: format!("s{i}"), url: format!("ssl://s{i}.example:50002"), ..sources::defaults(BNetwork::Signet)[1].clone() });
        }
        let signet = &upgraded(&full).networks[&BNetwork::Signet];
        assert_eq!((signet.sources.len(), signet.source("electrum.emzy.de").is_some()), (sources::MAX_SOURCES, true));
        // Removed after version 4, a default stays removed.
        let mut v4 = configured();
        net(&mut v4, BNetwork::Signet).sources.retain(|s| s.id != "electrum.emzy.de");
        assert!(find(&upgraded(&v4), BNetwork::Signet, "electrum.emzy.de").is_none());
    }

    #[test]
    fn esplora_is_never_loaded_from_a_version_4_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let mut s = configured();
        net(&mut s, BNetwork::Mainnet).sources.push(esplora("mine", "https://esplora.example/api", "example", true));
        s.save(&path).unwrap();
        assert!(matches!(Store::load(&path), Loaded::Corrupt(e) if e.contains(sources::ESPLORA_GONE)));
    }

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join(FILE_NAME);
        assert!(matches!(Store::load(&path), Loaded::Absent));
        let mut store = configured();
        let main = store.networks.get_mut(&BNetwork::Mainnet).unwrap();
        main.sources.push(Source { credentials: Some(Credentials { username: "u".into(), password: "p".into() }), ..rpc("nas", "https://node.example", false) });
        main.suspects.insert("electrum.blockstream.info".into(), Suspicion { kind: "anchor_mismatch".into(), height: Some(7), at: 9 });
        main.own_peers = vec!["203.0.113.5:8333".into()];
        store.save(&path).unwrap();
        assert!(!tmp_path(&path).exists());
        match Store::load(&path) {
            Loaded::Found(back) => assert_eq!(back, store),
            _ => panic!("reload failed"),
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"testnet4\"") && text.contains("\"height\": \"7\"") && text.contains("\"use\": true"), "{text}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn unset_and_cleared_proxies_differ() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let mut s = Store::empty();
        s.save(&path).unwrap();
        assert!(!std::fs::read_to_string(&path).unwrap().contains("proxy"));
        let Loaded::Found(back) = Store::load(&path) else { panic!() };
        assert_eq!(back.proxy, None);
        s.proxy = Some(None);
        s.save(&path).unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().contains("\"proxy\": null"));
        let Loaded::Found(back) = Store::load(&path) else { panic!() };
        assert_eq!((back.proxy, back.salt), (Some(None), s.salt));
    }

    #[test]
    fn version_1s_default_proxy_becomes_the_built_in_tor_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let load = || match Store::load(&path) {
            Loaded::Found(s) => s,
            _ => panic!("reload failed"),
        };
        let mut old = configured();
        (old.version, old.proxy) = (1, Some(Some(proxy::OLD_DEFAULT_PROXY.into())));
        old.save(&path).unwrap();
        let up = load();
        assert_eq!((up.version, up.proxy()), (VERSION, Some(proxy::BUILT_IN)));
        assert!(std::fs::read_to_string(&path).unwrap().contains("\"version\": 1"), "an older build can still read it until a save");

        // The user's own Tor elsewhere, and a cleared proxy, stay as they were.
        old.proxy = Some(Some("socks5h://127.0.0.1:9150".into()));
        old.save(&path).unwrap();
        assert_eq!(load().proxy(), Some("socks5h://127.0.0.1:9150"));
        old.proxy = Some(None);
        old.save(&path).unwrap();
        assert_eq!(load().proxy, Some(None));

        // Saved by this version, 9050 is the user's choice.
        let mut chosen = configured();
        chosen.proxy = Some(Some(proxy::OLD_DEFAULT_PROXY.into()));
        chosen.save(&path).unwrap();
        assert_eq!(load().proxy(), Some(proxy::OLD_DEFAULT_PROXY));

        chosen.version = VERSION + 1;
        chosen.save(&path).unwrap();
        assert!(matches!(Store::load(&path), Loaded::Corrupt(e) if e.contains("unknown version")));
    }

    #[test]
    fn tor_use_starts_at_identifying_and_older_files_load_as_all() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let fresh = Store::load_or_empty(&path);
        assert_eq!((fresh.tor_use, fresh.tor_use_chosen), (TorUse::Identifying, false));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"version\": 4") && text.contains("\"torUse\": \"identifying\"") && text.contains("\"torUseChosen\": false"), "{text}");

        // A version 2 file, which has neither field: everything stays on Tor, the choice still to make.
        let mut v2 = serde_json::to_value(configured()).unwrap();
        v2["version"] = 2.into();
        v2.as_object_mut().unwrap().retain(|k, _| k != "torUse" && k != "torUseChosen");
        std::fs::write(&path, v2.to_string()).unwrap();
        let Loaded::Found(up) = Store::load(&path) else { panic!() };
        assert_eq!((up.version, up.tor_use, up.tor_use_chosen), (VERSION, TorUse::All, false));
        // Even one that somehow says otherwise.
        v2["torUse"] = "none".into();
        v2["torUseChosen"] = true.into();
        std::fs::write(&path, v2.to_string()).unwrap();
        let Loaded::Found(up) = Store::load(&path) else { panic!() };
        assert_eq!((up.tor_use, up.tor_use_chosen), (TorUse::All, false));

        let mut chosen = configured();
        (chosen.tor_use, chosen.tor_use_chosen) = (TorUse::None, true);
        chosen.save(&path).unwrap();
        let Loaded::Found(back) = Store::load(&path) else { panic!() };
        assert_eq!(back, chosen);
        std::fs::write(&path, std::fs::read_to_string(&path).unwrap().replace("\"none\"", "\"some\"")).unwrap();
        assert!(matches!(Store::load(&path), Loaded::Corrupt(_)));
        assert_eq!([TorUse::parse("all"), TorUse::parse(" none "), TorUse::parse("everything")], [Some(TorUse::All), Some(TorUse::None), None]);
    }

    #[test]
    fn bad_files_are_set_aside() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let mut bad = configured();
        bad.networks.get_mut(&BNetwork::Mainnet).unwrap().sources[2].url = "tcp://electrum.blockstream.info:50001".into();
        bad.save(&path).unwrap();
        assert!(matches!(Store::load(&path), Loaded::Corrupt(e) if e.contains("mainnet")));
        let mut socks = configured();
        socks.proxy = Some(Some("socks5://127.0.0.1:9050".into()));
        socks.save(&path).unwrap();
        assert!(matches!(Store::load(&path), Loaded::Corrupt(_)));
        let mut mixed = configured();
        mixed.networks.get_mut(&BNetwork::Signet).unwrap().own_peers = vec!["192.168.1.20:38333".into(), "203.0.113.5:38333".into()];
        mixed.save(&path).unwrap();
        assert!(matches!(Store::load(&path), Loaded::Corrupt(e) if e.contains("one connection type")));

        std::fs::write(&path, "{ not json").unwrap();
        let s = Store::load_or_empty(&path);
        assert!(s.networks.is_empty() && s.proxy.is_none());
        assert_eq!(std::fs::read_to_string(corrupt_path(&path)).unwrap(), "{ not json");
        assert!(matches!(Store::load(&path), Loaded::Found(_)));
    }

    #[test]
    fn regtest_is_dropped_unless_configured() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let mut store = configured();
        store.networks.insert(BNetwork::Regtest, NetConfig::seeded(BNetwork::Regtest));
        store.save(&path).unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().contains("\"regtest\""));
        let Loaded::Found(s) = Store::load(&path) else { panic!("expected a store") };
        assert_eq!(s, configured_like(&store));
    }

    fn configured_like(s: &Store) -> Store {
        let mut c = s.clone();
        c.networks.remove(&BNetwork::Regtest);
        c
    }

    #[test]
    fn suspicions_follow_the_source_url() {
        let mut cfg = NetConfig::seeded(BNetwork::Mainnet);
        for id in ["electrum.blockstream.info", "electrum.blockstream.info-onion"] {
            cfg.suspects.insert(id.into(), Suspicion { kind: "k".into(), height: None, at: 1 });
        }
        let mut list = cfg.sources.clone();
        list.retain(|s| s.id != "electrum.blockstream.info-onion");
        cfg.replace_sources(list.clone());
        assert_eq!(cfg.suspects.keys().collect::<Vec<_>>(), ["electrum.blockstream.info"]);
        list.iter_mut().filter(|s| s.id == "electrum.blockstream.info").for_each(|s| s.url = "ssl://elsewhere.example:50002".into());
        cfg.replace_sources(list);
        assert!(cfg.suspects.is_empty());
    }
}
