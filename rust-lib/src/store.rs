//! What persists, written atomically and owner-only to `bitcoin_sources.json`: the proxy, and
//! per network the sources, suspects, own peers and a fetched peer list.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use rand::RngExt;
use serde::{Deserialize, Serialize};

use crate::network::{networks, BNetwork};
use crate::peers::{self, PeerList};
use crate::proxy;
use crate::sources::{self, Kind, Source};
use crate::strnum::{de, de_opt, double_option, ser, ser_opt};

pub const FILE_NAME: &str = "bitcoin_sources.json";
pub const VERSION: u32 = 1;

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
    /// A fetched list newer than the shipped one, kept once its signature checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_list: Option<PeerList>,
}

impl NetConfig {
    pub fn seeded(net: BNetwork) -> Self {
        Self { sources: sources::defaults(net), suspects: BTreeMap::new(), own_peers: vec![], peer_list: None }
    }

    pub fn source(&self, id: &str) -> Option<&Source> {
        self.sources.iter().find(|s| s.id == id)
    }

    /// Kyoto's Tor switch, on when Kyoto is not in the list.
    pub fn kyoto_tor(&self) -> bool {
        self.sources.iter().find(|s| s.kind == Kind::Kyoto).is_none_or(|s| s.tor)
    }

    /// The list Kyoto picks from: a fetched one, or this build's.
    pub fn peer_list(&self, net: BNetwork) -> PeerList {
        self.peer_list.clone().unwrap_or_else(|| peers::shipped(net))
    }

    /// Replaces the list, keeping only the suspicions of sources still at the same url.
    pub fn replace_sources(&mut self, list: Vec<Source>) {
        let old = std::mem::replace(&mut self.sources, list);
        let url = |l: &[Source], id: &str| l.iter().find(|s| s.id == id).map(|s| s.url.clone());
        let new = self.sources.clone();
        self.suspects.retain(|id, _| url(&old, id).is_some() && url(&old, id) == url(&new, id));
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
        if let Some(l) = &self.peer_list {
            l.validate(net)?;
        }
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
    /// Per install: seeds the daily pick of Kyoto peers.
    #[serde(default)]
    pub salt: String,
    #[serde(default)]
    pub networks: BTreeMap<BNetwork, NetConfig>,
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
    /// Nothing configured: the backend calls init_defaults.
    pub fn empty() -> Self {
        Self { version: VERSION, proxy: None, salt: fresh_salt(), networks: BTreeMap::new() }
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
        if store.version != VERSION {
            return Loaded::Corrupt(format!("unknown version {}", store.version));
        }
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

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join(FILE_NAME);
        assert!(matches!(Store::load(&path), Loaded::Absent));
        let mut store = configured();
        let main = store.networks.get_mut(&BNetwork::Mainnet).unwrap();
        main.sources[2].credentials = Some(Credentials { username: "u".into(), password: "p".into() });
        main.sources[2].kind = Kind::Esplora;
        main.suspects.insert("blockstream.info".into(), Suspicion { kind: "anchor_mismatch".into(), height: Some(7), at: 9 });
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
    fn bad_files_are_set_aside() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let mut bad = configured();
        bad.networks.get_mut(&BNetwork::Mainnet).unwrap().sources[1].url = "http://blockstream.info/api".into();
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
        for id in ["blockstream.info", "mempool.space"] {
            cfg.suspects.insert(id.into(), Suspicion { kind: "k".into(), height: None, at: 1 });
        }
        let mut list = cfg.sources.clone();
        list.retain(|s| s.id != "mempool.space");
        cfg.replace_sources(list.clone());
        assert_eq!(cfg.suspects.keys().collect::<Vec<_>>(), ["blockstream.info"]);
        list.iter_mut().filter(|s| s.id == "blockstream.info").for_each(|s| s.url = "https://elsewhere.example/api".into());
        cfg.replace_sources(list);
        assert!(cfg.suspects.is_empty());
    }
}
