//! Per-source health and the overall verdict, as pure functions over probe results.

use serde::Serialize;

use crate::net::cert::CertInfo;
use crate::network::BNetwork;
use crate::strnum::ser_opt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Not checked yet.
    #[default]
    Unknown,
    Ok,
    Unreachable,
    /// Answered for another network: not routed.
    WrongNetwork,
    /// Routed through Tor with no proxy set: nothing is dialled.
    NoRoute,
    /// Kyoto with no peer to dial.
    NoPeers,
    /// Kyoto and the local node: the wallet core dials them, not this module.
    NotProbed,
}

/// What one probe learned about one source. u64 values serialize as strings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Health {
    pub state: State,
    #[serde(serialize_with = "ser_opt")]
    pub tip_height: Option<u64>,
    pub tip_hash: Option<String>,
    #[serde(serialize_with = "ser_opt")]
    pub rtt_ms: Option<u64>,
    #[serde(serialize_with = "ser_opt")]
    pub checked_at: Option<u64>,
    pub error: Option<String>,
    /// An Electrum server's `server.version` software string.
    pub server_version: Option<String>,
    /// A TLS server's certificate, once it proved it holds the key: trusted or not, so the app
    /// can ask whether to pin it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<CertInfo>,
}

/// What an address-free probe saw. `genesis` is `None` when this probe did not ask.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observed {
    pub genesis: Option<String>,
    pub tip_height: u64,
    pub tip_hash: String,
    pub rtt_ms: u64,
    pub server_version: Option<String>,
}

pub const WRONG_NETWORK: &str = "wrong network";

impl Health {
    pub fn unreachable(error: impl Into<String>, now: u64) -> Self {
        Self { state: State::Unreachable, error: Some(error.into()), checked_at: Some(now), ..Self::default() }
    }

    pub fn no_route(why: &str, now: u64) -> Self {
        Self { state: State::NoRoute, error: Some(why.into()), checked_at: Some(now), ..Self::default() }
    }

    /// A server whose genesis block is another network's answers, but must not be routed.
    pub fn observed(net: BNetwork, o: Observed, now: u64) -> Self {
        let wrong = o.genesis.as_deref().is_some_and(|g| !g.eq_ignore_ascii_case(net.genesis()));
        Self {
            state: if wrong { State::WrongNetwork } else { State::Ok },
            tip_height: Some(o.tip_height),
            tip_hash: Some(o.tip_hash),
            rtt_ms: Some(o.rtt_ms),
            checked_at: Some(now),
            error: wrong.then(|| format!("{WRONG_NETWORK}: its genesis block is not {}'s", net.name())),
            server_version: o.server_version,
            certificate: None,
        }
    }
}

/// Tips of different operators may differ by this many blocks before they disagree.
pub const TIP_TOLERANCE: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Overall {
    Ok,
    Degraded,
    Disagreement,
    Offline,
}

/// One enabled source as the verdict sees it; `health` is `None` until its first probe.
pub struct Row<'a> {
    pub operator: &'a str,
    pub suspect: bool,
    pub health: Option<&'a Health>,
}

/// The verdict over the enabled sources, first rule that applies: disagreement (two operators'
/// tips more than 2 blocks apart), offline (nothing usable), degraded, ok.
pub fn overall(rows: &[Row]) -> Overall {
    let usable = |h: &Health| matches!(h.state, State::Ok | State::NotProbed);
    let tips: Vec<(&str, u64)> = rows
        .iter()
        .filter_map(|r| r.health.filter(|h| h.state == State::Ok).and_then(|h| h.tip_height).map(|t| (r.operator, t)))
        .collect();
    let disagree = tips.iter().enumerate().any(|(i, (oa, a))| {
        tips[i + 1..].iter().any(|(ob, b)| !oa.eq_ignore_ascii_case(ob) && a.abs_diff(*b) > TIP_TOLERANCE)
    });
    if disagree {
        return Overall::Disagreement;
    }
    if !rows.iter().any(|r| r.health.is_some_and(usable)) {
        return Overall::Offline;
    }
    let unusable = rows.iter().any(|r| r.health.is_some_and(|h| !usable(h)));
    if unusable || rows.iter().any(|r| r.suspect) {
        return Overall::Degraded;
    }
    Overall::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen(net: BNetwork, genesis: Option<&str>, tip: u64) -> Health {
        let o = Observed { genesis: genesis.map(String::from), tip_height: tip, tip_hash: "00".repeat(32), rtt_ms: 900, server_version: None };
        Health::observed(net, o, 1_000)
    }

    fn row<'a>(operator: &'a str, h: Option<&'a Health>) -> Row<'a> {
        Row { operator, suspect: false, health: h }
    }

    #[test]
    fn genesis_decides_the_network() {
        let main = BNetwork::Mainnet.genesis();
        assert_eq!(seen(BNetwork::Mainnet, Some(main), 1).state, State::Ok);
        assert_eq!(seen(BNetwork::Mainnet, Some(&main.to_uppercase()), 1).state, State::Ok);
        assert_eq!(seen(BNetwork::Mainnet, None, 1).state, State::Ok, "not asked this time");
        let wrong = seen(BNetwork::Testnet4, Some(main), 1);
        assert_eq!(wrong.state, State::WrongNetwork);
        assert!(wrong.error.unwrap().starts_with(WRONG_NETWORK));
        let v = serde_json::to_value(seen(BNetwork::Mainnet, None, 970_838)).unwrap();
        assert_eq!((&v["tipHeight"], &v["rttMs"], &v["checkedAt"], &v["state"]), (&"970838".into(), &"900".into(), &"1000".into(), &"ok".into()));
    }

    #[test]
    fn verdicts() {
        let (a, b, far) = (seen(BNetwork::Mainnet, None, 100), seen(BNetwork::Mainnet, None, 102), seen(BNetwork::Mainnet, None, 103));
        assert_eq!(overall(&[row("x", Some(&a)), row("y", Some(&b))]), Overall::Ok);
        assert_eq!(overall(&[row("x", Some(&a)), row("y", Some(&far))]), Overall::Disagreement);
        assert_eq!(overall(&[row("x", Some(&a)), row("X", Some(&far))]), Overall::Ok, "one operator's hosts");
        let down = Health::unreachable("timed out", 1);
        assert_eq!(overall(&[row("x", Some(&a)), row("y", Some(&down))]), Overall::Degraded);
        assert_eq!(overall(&[row("x", Some(&down))]), Overall::Offline);
        assert_eq!(overall(&[row("x", None)]), Overall::Offline);
        assert_eq!(overall(&[row("x", Some(&a)), row("y", None)]), Overall::Ok, "pending does not degrade");
        let kyoto = Health { state: State::NotProbed, ..Health::default() };
        assert_eq!(overall(&[row("peers", Some(&kyoto))]), Overall::Ok);
        let mut rows = [row("x", Some(&a))];
        rows[0].suspect = true;
        assert_eq!(overall(&rows), Overall::Degraded);
    }
}
