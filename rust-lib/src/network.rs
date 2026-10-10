//! The networks this module keeps sources for.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BNetwork {
    Mainnet,
    Testnet4,
    Signet,
    /// A local test chain, kept only when `regtest.json` exists. Test harnesses only.
    Regtest,
}

pub const NETWORKS: [BNetwork; 3] = [BNetwork::Mainnet, BNetwork::Testnet4, BNetwork::Signet];

static REGTEST: OnceLock<()> = OnceLock::new();

/// Keeps regtest from now on, for this process; called before the node opens.
pub fn configure_regtest() {
    let _ = REGTEST.set(());
}

pub fn regtest_configured() -> bool {
    REGTEST.get().is_some()
}

/// `regtest.json` turns regtest on when it holds a JSON object; its keys are for other modules.
pub fn regtest_file_ok(text: &str) -> bool {
    matches!(serde_json::from_str::<serde_json::Value>(text), Ok(serde_json::Value::Object(_)))
}

/// mainnet, testnet4 and signet, and regtest once configured.
pub fn networks() -> Vec<BNetwork> {
    let mut out = NETWORKS.to_vec();
    if regtest_configured() {
        out.push(BNetwork::Regtest);
    }
    out
}

/// The refusal for a network name this instance does not keep.
pub fn bad_network() -> String {
    let names = if regtest_configured() { "mainnet, testnet4, signet or regtest" } else { "mainnet, testnet4 or signet" };
    format!("network must be {names}")
}

impl BNetwork {
    pub fn name(self) -> &'static str {
        match self {
            BNetwork::Mainnet => "mainnet",
            BNetwork::Testnet4 => "testnet4",
            BNetwork::Signet => "signet",
            BNetwork::Regtest => "regtest",
        }
    }

    /// Regtest only parses once configured.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "mainnet" | "main" | "bitcoin" => Some(BNetwork::Mainnet),
            "testnet4" => Some(BNetwork::Testnet4),
            "signet" => Some(BNetwork::Signet),
            "regtest" if regtest_configured() => Some(BNetwork::Regtest),
            _ => None,
        }
    }

    /// The genesis block hash, as block explorers print it.
    pub fn genesis(self) -> &'static str {
        match self {
            BNetwork::Mainnet => "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            BNetwork::Testnet4 => "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
            BNetwork::Signet => "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
            BNetwork::Regtest => "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        }
    }

    /// Bitcoin Core's default P2P port, for a peer given without one.
    pub fn p2p_port(self) -> u16 {
        match self {
            BNetwork::Mainnet => 8333,
            BNetwork::Testnet4 => 48333,
            BNetwork::Signet => 38333,
            BNetwork::Regtest => 18444,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(BNetwork::parse("main"), Some(BNetwork::Mainnet));
        assert_eq!(BNetwork::parse("testnet4").map(BNetwork::name), Some("testnet4"));
        assert_eq!(BNetwork::parse("testnet"), None, "testnet3 is not kept");
        assert_eq!(serde_json::to_string(&BNetwork::Testnet4).unwrap(), "\"testnet4\"");
        assert_eq!(BNetwork::Signet.p2p_port(), 38333);
    }

    #[test]
    fn regtest_is_refused_until_configured() {
        // Per process: no unit test configures it, tests/regtest.rs does.
        assert!(!regtest_configured());
        assert_eq!(BNetwork::parse("regtest"), None);
        assert_eq!(networks(), NETWORKS);
        assert_eq!(bad_network(), "network must be mainnet, testnet4 or signet");
        assert!(regtest_file_ok("{}") && regtest_file_ok(r#"{"anything":1}"#));
        assert!(!regtest_file_ok("[]") && !regtest_file_ok("nope") && !regtest_file_ok(""));
    }

    #[test]
    fn genesis_hashes_are_64_hex() {
        for n in [BNetwork::Mainnet, BNetwork::Testnet4, BNetwork::Signet, BNetwork::Regtest] {
            assert!(n.genesis().len() == 64 && n.genesis().bytes().all(|b| b.is_ascii_hexdigit()), "{n:?}");
        }
    }
}
