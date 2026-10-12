//! Kyoto's peer book, one per network: the signed list, Bitcoin Core's fixed seeds and peers
//! learned from gossip, each with its record of successes and failures. The wallet core
//! reports what it saw with `report_peers`; the book decides which peers Kyoto is given.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize};

use crate::net::client::{is_lan_ip, is_onion};
use crate::net::p2p::{onion_key, X49};
use crate::network::BNetwork;
use crate::peers::{normalize_peer, peer_host};
use crate::strnum;

pub const FORMAT: u32 = 1;
pub const MAX_ENTRIES: usize = 2000;
/// Learned entries credited to any one peer that told us of them.
pub const MAX_PER_FROM: usize = 64;
/// Entries per list in one report.
pub const MAX_REPORT: usize = 500;
pub const DAY: u64 = 86_400;
const SKIP_AFTER: u32 = 3;
const SKIP_FOR: u64 = DAY;
/// Gossip older than this is stale; a clock this far ahead is wrong.
const FRESH: u64 = 3 * DAY;
const SKEW: u64 = 600;
const NEVER_OK_FOR: u64 = 7 * DAY;
const OK_WITHIN: u64 = 30 * DAY;
/// Below this many peers that worked in 30 days, the fixed seeds are asked for more.
pub const HARVEST_BELOW: usize = 12;
/// After a harvest a seed answered; after one none answered, an hour, at most 3 tries a day.
pub const HARVEST_EVERY: u64 = DAY;
pub const HARVEST_RETRY: u64 = 3600;
pub const HARVEST_TRIES: usize = 3;
pub const HARVEST_SEEDS: usize = 8;
/// `from` of a list peer kept as learned after a newer list dropped it.
pub const FROM_LIST: &str = "list";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    /// The signed list this build ships.
    List,
    /// Gossip: reported by the wallet core, or harvested from a fixed seed.
    Learned,
    /// Bitcoin Core's fixed seeds: asked for addresses, never given to Kyoto.
    Seed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entry {
    pub addr: String,
    pub port: u16,
    #[serde(serialize_with = "strnum::ser", deserialize_with = "strnum::de")]
    pub services: u64,
    pub source: Origin,
    /// The peer that told us of a learned entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(serialize_with = "strnum::ser", deserialize_with = "strnum::de")]
    pub first_seen: u64,
    #[serde(serialize_with = "strnum::ser", deserialize_with = "strnum::de")]
    pub last_seen: u64,
    #[serde(default, serialize_with = "strnum::ser_opt", deserialize_with = "strnum::de_opt")]
    pub last_ok: Option<u64>,
    pub ok_count: u32,
    pub fail_streak: u32,
    #[serde(default, serialize_with = "strnum::ser_opt", deserialize_with = "strnum::de_opt")]
    pub skip_until: Option<u64>,
}

impl Entry {
    /// `host:port` as Kyoto dials it and the wallet core reports it.
    pub fn peer(&self) -> String {
        format!("{}:{}", crate::addr::fmt_host(&self.addr), self.port)
    }

    fn new(addr: &str, port: u16, services: u64, source: Origin, from: Option<String>, seen: u64, now: u64) -> Self {
        Entry { addr: addr.to_string(), port, services, source, from, first_seen: now, last_seen: seen, last_ok: None, ok_count: 0, fail_streak: 0, skip_until: None }
    }

    fn skipped(&self, now: u64) -> bool {
        self.skip_until.is_some_and(|t| t > now)
    }

    fn ok_since(&self, t: u64) -> bool {
        self.last_ok.is_some_and(|ok| ok >= t)
    }
}

/// A number or a decimal string, for fields the wallet core may send either way.
fn num_or_str<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum N {
        Num(u64),
        Str(String),
    }
    match N::deserialize(d)? {
        N::Num(n) => Ok(n),
        N::Str(s) => strnum::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("not a decimal u64: {s:?}"))),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Outcome {
    pub peer: String,
    pub ok: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Learned {
    pub addr: String,
    pub port: u16,
    #[serde(deserialize_with = "num_or_str")]
    pub services: u64,
    #[serde(deserialize_with = "num_or_str")]
    pub seen_at: u64,
    pub from: String,
}

/// report_peers' argument.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Report {
    #[serde(default)]
    pub outcomes: Vec<Outcome>,
    #[serde(default)]
    pub learned: Vec<Learned>,
}

impl Report {
    pub fn parse(json: &str) -> Result<Self, String> {
        let bad = |e: String| format!("{}report: {e}", crate::reply::INVALID);
        let v: serde_json::Value = serde_json::from_str(json).map_err(|e| bad(e.to_string()))?;
        if !v.is_object() {
            return Err(bad("must be a JSON object".into()));
        }
        let r: Report = serde_json::from_value(v).map_err(|e| bad(e.to_string()))?;
        if r.outcomes.len() > MAX_REPORT || r.learned.len() > MAX_REPORT {
            return Err(format!("{}a report holds at most {MAX_REPORT} outcomes and {MAX_REPORT} learned peers", crate::reply::INVALID));
        }
        Ok(r)
    }
}

/// What a batch of learned peers did to the book.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Learning {
    pub added: usize,
    pub updated: usize,
    pub refused: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub list: usize,
    pub learned: usize,
    pub seed: usize,
    pub usable: usize,
    pub ok_last30d: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Book {
    pub format: u32,
    pub network: BNetwork,
    /// The shipped list last merged.
    #[serde(serialize_with = "strnum::ser", deserialize_with = "strnum::de")]
    pub list_version: u64,
    /// When the fixed seeds were last asked for addresses.
    #[serde(default, serialize_with = "strnum::ser_opt", deserialize_with = "strnum::de_opt")]
    pub harvested_at: Option<u64>,
    /// Whether a seed answered that harvest.
    #[serde(default)]
    pub harvest_answered: bool,
    /// When the harvests of the last 24 h started.
    #[serde(default, serialize_with = "strnum::ser_vec", deserialize_with = "strnum::de_vec")]
    pub harvest_tries: Vec<u64>,
    pub entries: Vec<Entry>,
}

/// Gossip the book keeps: fresh, with the services Kyoto needs.
fn fresh(services: u64, seen_at: u64, now: u64) -> Result<(), &'static str> {
    if services & X49 != X49 {
        return Err("services lack bits 0, 3 or 6");
    }
    if seen_at.saturating_add(FRESH) < now || seen_at > now.saturating_add(SKEW) {
        return Err("not seen within 3 days");
    }
    Ok(())
}

impl Book {
    pub fn new(net: BNetwork) -> Self {
        Book { format: FORMAT, network: net, list_version: 0, harvested_at: None, harvest_answered: false, harvest_tries: vec![], entries: vec![] }
    }

    pub fn file_name(net: BNetwork) -> String {
        format!("kyoto_peers_{}.json", net.name())
    }

    fn index(&self) -> HashMap<(String, u16), usize> {
        self.entries.iter().enumerate().map(|(i, e)| ((e.addr.clone(), e.port), i)).collect()
    }

    fn find(&mut self, peer: &str) -> Option<&mut Entry> {
        let (host, port) = peer.rsplit_once(':')?;
        let (host, port) = (host.trim_start_matches('[').trim_end_matches(']'), port.parse::<u16>().ok()?);
        self.entries.iter_mut().find(|e| e.addr == host && e.port == port)
    }

    /// Merges the shipped list and the fixed seeds: missing peers added, the record of every peer
    /// kept. A list peer the new list drops stays as learned (`from: "list"`) if it worked here
    /// in 30 days, and goes otherwise; dropped seeds go. Learned entries stay as they are.
    pub fn sync_shipped(&mut self, list: &[String], list_version: u64, seeds: &[String], now: u64) {
        let split = |p: &String| p.rsplit_once(':').and_then(|(h, port)| Some((h.trim_start_matches('[').trim_end_matches(']').to_string(), port.parse::<u16>().ok()?)));
        let list: HashSet<(String, u16)> = list.iter().filter_map(split).collect();
        let seeds: HashSet<(String, u16)> = seeds.iter().filter_map(split).filter(|k| !list.contains(k)).collect();
        let since = now.saturating_sub(OK_WITHIN);
        for e in self.entries.iter_mut().filter(|e| e.source == Origin::List && e.ok_since(since)) {
            if !list.contains(&(e.addr.clone(), e.port)) {
                e.source = Origin::Learned;
                e.from = Some(FROM_LIST.to_string());
            }
        }
        self.entries.retain(|e| match e.source {
            Origin::List => list.contains(&(e.addr.clone(), e.port)),
            Origin::Seed => seeds.contains(&(e.addr.clone(), e.port)),
            Origin::Learned => true,
        });
        let index = self.index();
        for (keys, source, services) in [(&list, Origin::List, X49), (&seeds, Origin::Seed, 0)] {
            let mut keys: Vec<&(String, u16)> = keys.iter().collect();
            keys.sort();
            for k in keys {
                match index.get(k) {
                    // A learned peer the shipped list now names becomes a list peer.
                    Some(&i) if self.entries[i].source == Origin::Learned && source == Origin::List => {
                        self.entries[i].source = Origin::List;
                        self.entries[i].from = None;
                    }
                    Some(_) => {}
                    None => self.entries.push(Entry::new(&k.0, k.1, services, source, None, now, now)),
                }
            }
        }
        self.list_version = list_version;
    }

    /// A success clears the strikes; the third failure in a row skips the peer for 24 h.
    /// False when the book does not hold `peer`.
    pub fn outcome(&mut self, peer: &str, ok: bool, now: u64) -> bool {
        let Some(e) = self.find(peer) else { return false };
        if ok {
            e.last_ok = Some(now);
            e.ok_count = e.ok_count.saturating_add(1);
            e.fail_streak = 0;
            e.skip_until = None;
        } else {
            e.fail_streak += 1;
            if e.fail_streak >= SKIP_AFTER {
                e.skip_until = Some(now + SKIP_FOR);
                e.fail_streak = 0;
            }
        }
        true
    }

    /// Adds or refreshes one learned peer, under the caps: 2,000 entries, 64 per `from`.
    fn add_learned(&mut self, addr: &str, port: u16, services: u64, seen_at: u64, from: &str, now: u64) -> Result<bool, &'static str> {
        if let Some(e) = self.entries.iter_mut().find(|e| e.addr == addr && e.port == port) {
            e.services = services;
            e.last_seen = e.last_seen.max(seen_at.min(now));
            return Ok(false);
        }
        if self.entries.iter().filter(|e| e.source == Origin::Learned && e.from.as_deref() == Some(from)).count() >= MAX_PER_FROM {
            return Err("its peer already gave 64");
        }
        if self.entries.len() >= MAX_ENTRIES {
            // Make room by dropping the stalest learned peer that never worked.
            let stalest = self.entries.iter().enumerate().filter(|(_, e)| e.source == Origin::Learned && e.last_ok.is_none()).min_by_key(|(_, e)| e.last_seen).map(|(i, _)| i);
            match stalest {
                Some(i) => {
                    self.entries.swap_remove(i);
                }
                None => return Err("the book is full"),
            }
        }
        self.entries.push(Entry::new(addr, port, services, Origin::Learned, Some(from.to_string()), seen_at.min(now), now));
        Ok(true)
    }

    /// A peer the wallet core learned: onion v3 on public networks, your network on regtest,
    /// bits 0, 3 and 6, seen within 3 days, from a peer named as Kyoto names them.
    pub fn learn(&mut self, l: &Learned, now: u64) -> Result<bool, &'static str> {
        let net = self.network;
        let host_ok = match net {
            BNetwork::Regtest => l.addr.parse::<IpAddr>().is_ok_and(is_lan_ip),
            _ => onion_key(&l.addr).is_some(),
        };
        if !host_ok {
            return Err(if net == BNetwork::Regtest { "not an address on your network" } else { "not an onion v3 address" });
        }
        if l.port == 0 {
            return Err("no port");
        }
        if normalize_peer(net, &l.from).as_deref() != Ok(l.from.as_str()) {
            return Err("from is not host:port");
        }
        fresh(l.services, l.seen_at, now)?;
        self.add_learned(&l.addr, l.port, l.services, l.seen_at, &l.from, now)
    }

    /// Gossip from a fixed seed: onion v3 only, bits 0, 3 and 6, seen within 3 days.
    pub fn harvested(&mut self, host: &str, port: u16, services: u64, seen_at: u64, seed: &str, now: u64) -> Result<bool, &'static str> {
        if onion_key(host).is_none() || port == 0 {
            return Err("not an onion v3 address");
        }
        fresh(services, seen_at, now)?;
        self.add_learned(host, port, services, seen_at, seed, now)
    }

    /// Added, refreshed and refused, from `learn` or `harvested` results.
    pub fn tally<'a>(items: impl IntoIterator<Item = Result<bool, &'a str>>) -> Learning {
        let mut l = Learning::default();
        for r in items {
            match r {
                Ok(true) => l.added += 1,
                Ok(false) => l.updated += 1,
                Err(_) => l.refused += 1,
            }
        }
        l
    }

    /// Learned peers that never worked go after 7 days, any after 30 days without a success.
    pub fn prune(&mut self, now: u64) {
        self.entries.retain(|e| {
            e.source != Origin::Learned
                || match e.last_ok {
                    None => e.first_seen.saturating_add(NEVER_OK_FOR) >= now,
                    Some(ok) => ok.saturating_add(OK_WITHIN) >= now,
                }
        });
    }

    /// The peers Kyoto may dial on its route (onion peers through Tor), the ones that worked
    /// first, skipped ones left out unless every one is skipped. Seeds are never given.
    pub fn usable(&self, tor: bool, now: u64) -> Vec<&Entry> {
        let mut candidates: Vec<&Entry> = self.entries.iter().filter(|e| e.source != Origin::Seed && is_onion(peer_host(&e.peer())) == tor).collect();
        candidates.sort_by(|a, b| b.last_ok.cmp(&a.last_ok).then((a.source == Origin::Learned).cmp(&(b.source == Origin::Learned))).then(a.addr.cmp(&b.addr)));
        let open: Vec<&Entry> = candidates.iter().copied().filter(|e| !e.skipped(now)).collect();
        if open.is_empty() {
            candidates
        } else {
            open
        }
    }

    pub fn counts(&self, tor: bool, now: u64) -> Counts {
        let n = |o: Origin| self.entries.iter().filter(|e| e.source == o).count();
        let usable = self.usable(tor, now);
        let since = now.saturating_sub(OK_WITHIN);
        Counts {
            list: n(Origin::List),
            learned: n(Origin::Learned),
            seed: n(Origin::Seed),
            ok_last30d: usable.iter().filter(|e| e.ok_since(since)).count(),
            usable: usable.len(),
        }
    }

    /// Fewer than 12 usable peers worked in 30 days and there are seeds to ask: a day after a
    /// harvest a seed answered, an hour after one none answered, at most 3 tries a day.
    pub fn harvest_due(&self, tor: bool, now: u64) -> bool {
        if self.counts(tor, now).ok_last30d >= HARVEST_BELOW || !self.entries.iter().any(|e| e.source == Origin::Seed) {
            return false;
        }
        let Some(last) = self.harvested_at else { return true };
        if self.harvest_answered {
            return last.saturating_add(HARVEST_EVERY) <= now;
        }
        let today = self.harvest_tries.iter().filter(|&&t| t.saturating_add(DAY) > now).count();
        last.saturating_add(HARVEST_RETRY) <= now && today < HARVEST_TRIES
    }

    /// A harvest starting: unanswered until a seed answers (`harvest_answered`).
    pub fn harvest_started(&mut self, now: u64) {
        self.harvest_tries.retain(|&t| t.saturating_add(DAY) > now);
        self.harvest_tries.push(now);
        self.harvested_at = Some(now);
        self.harvest_answered = false;
    }

    /// Up to 8 seeds, a fresh random pick each time.
    pub fn pick_seeds(&self) -> Vec<String> {
        use rand::seq::SliceRandom;
        let mut seeds: Vec<String> = self.entries.iter().filter(|e| e.source == Origin::Seed).map(Entry::peer).collect();
        seeds.shuffle(&mut rand::rng());
        seeds.truncate(HARVEST_SEEDS);
        seeds
    }

    /// The book in `dir`, or a new one; a file that does not parse is kept aside.
    pub fn load(dir: &Path, net: BNetwork) -> Self {
        let path = dir.join(Self::file_name(net));
        let Ok(text) = std::fs::read_to_string(&path) else { return Self::new(net) };
        match serde_json::from_str::<Book>(&text) {
            Ok(b) if b.network == net && b.format == FORMAT => b,
            other => {
                let why = other.map(|_| "another network or format".to_string()).unwrap_or_else(|e| e.to_string());
                eprintln!("bitcoin_node_module: {} is unusable ({why}); starting a new peer book", path.display());
                let _ = std::fs::rename(&path, path.with_extension("json.corrupt"));
                Self::new(net)
            }
        }
    }

    /// Writes `<file>.tmp` (owner-only), syncs it, then renames it over the file.
    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(Self::file_name(self.network));
        let tmp: PathBuf = path.with_extension("json.tmp");
        let body = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let mut f = opts.open(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::p2p::onion_from_key;

    const NOW: u64 = 2_000_000_000;

    fn onion(i: u16) -> String {
        let mut pk = [7u8; 32];
        pk[..2].copy_from_slice(&i.to_be_bytes());
        onion_from_key(&pk)
    }

    fn peer(i: u16) -> String {
        format!("{}:8333", onion(i))
    }

    fn book_with(list: usize, seeds: usize) -> Book {
        let mut b = Book::new(BNetwork::Mainnet);
        let l: Vec<String> = (0..list as u16).map(peer).collect();
        let s: Vec<String> = (1000..1000 + seeds as u16).map(peer).collect();
        b.sync_shipped(&l, 7, &s, NOW);
        b
    }

    fn at<'a>(b: &'a Book, p: &str) -> &'a Entry {
        b.entries.iter().find(|e| e.peer() == p).unwrap()
    }

    fn learned(i: u16, from: u16, seen: u64) -> Learned {
        Learned { addr: onion(i), port: 8333, services: X49 | 0x400, seen_at: seen, from: peer(from) }
    }

    #[test]
    fn the_shipped_list_and_seeds_seed_the_book_and_keep_their_records() {
        let mut b = book_with(3, 2);
        assert_eq!((b.entries.len(), b.list_version), (5, 7));
        assert!(b.outcome(&peer(0), true, NOW));
        // A new list: peer 2 is dropped, peer 9 added, peer 0 keeps its record.
        b.sync_shipped(&[peer(0), peer(1), peer(9)], 8, &[peer(1000)], NOW + 10);
        let keys: HashSet<(String, Origin)> = b.entries.iter().map(|e| (e.peer(), e.source)).collect();
        let want = HashSet::from([(peer(0), Origin::List), (peer(1), Origin::List), (peer(9), Origin::List), (peer(1000), Origin::Seed)]);
        assert_eq!(keys, want);
        assert_eq!((at(&b, &peer(0)).ok_count, b.list_version), (1, 8));
        // A learned peer the list later names becomes a list peer.
        b.learn(&learned(50, 0, NOW), NOW).unwrap();
        b.sync_shipped(&[peer(0), peer(1), peer(9), peer(50)], 9, &[peer(1000)], NOW);
        let e = b.entries.iter().find(|e| e.addr == onion(50)).unwrap();
        assert_eq!((e.source, e.from.as_deref()), (Origin::List, None));
    }

    #[test]
    fn three_failures_in_a_row_skip_a_peer_for_a_day() {
        let mut b = book_with(2, 0);
        for _ in 0..2 {
            b.outcome(&peer(0), false, NOW);
        }
        assert_eq!(b.usable(true, NOW).len(), 2, "two strikes are not out");
        b.outcome(&peer(0), false, NOW);
        assert_eq!(at(&b, &peer(0)).skip_until, Some(NOW + DAY));
        assert_eq!(b.usable(true, NOW).iter().map(|e| e.peer()).collect::<Vec<_>>(), [peer(1)]);
        assert_eq!(b.usable(true, NOW + DAY).len(), 2, "back after 24 h");
        // A success clears the strikes.
        b.outcome(&peer(1), false, NOW);
        b.outcome(&peer(1), true, NOW);
        let e = at(&b, &peer(1));
        assert_eq!((e.fail_streak, e.ok_count, e.last_ok), (0, 1, Some(NOW)));
        // Every peer skipped: all of them are given, as before.
        for _ in 0..3 {
            b.outcome(&peer(1), false, NOW);
        }
        assert_eq!(b.usable(true, NOW).len(), 2);
        assert!(!b.outcome("nobody.onion:8333", true, NOW), "a peer the book lacks");
        assert!(b.usable(false, NOW).is_empty(), "onion peers need Tor");
    }

    #[test]
    fn learned_peers_are_checked() {
        let mut b = book_with(1, 0);
        assert_eq!(b.learn(&learned(10, 0, NOW - 3600), NOW), Ok(true));
        assert_eq!(b.learn(&learned(10, 0, NOW), NOW), Ok(false), "known: refreshed");
        let refused = [
            Learned { addr: "203.0.113.5".into(), ..learned(11, 0, NOW) },
            Learned { addr: onion(11).replacen('a', "b", 1), ..learned(11, 0, NOW) },
            Learned { services: 0x09, ..learned(11, 0, NOW) },
            learned(11, 0, NOW - 3 * DAY - 1),
            learned(11, 0, NOW + 3600),
            learned(11, 0, u64::MAX),
            Learned { port: 0, ..learned(11, 0, NOW) },
            Learned { from: "seed.example.org:8333".into(), ..learned(11, 0, NOW) },
        ];
        for l in &refused {
            assert!(b.learn(l, NOW).is_err(), "{l:?}");
        }
        // Regtest takes addresses on your network only.
        let mut r = Book::new(BNetwork::Regtest);
        let lan = |a: &str| Learned { addr: a.into(), port: 18444, services: X49, seen_at: NOW, from: "127.0.0.1:18444".into() };
        assert!(r.learn(&lan("127.0.0.1"), NOW).is_ok() && r.learn(&lan("192.168.1.20"), NOW).is_ok());
        assert!(r.learn(&lan("203.0.113.5"), NOW).is_err() && r.learn(&Learned { addr: onion(1), ..lan("x") }, NOW).is_err());
        // Services and seenAt arrive as numbers or decimal strings.
        let r = Report::parse(&format!(r#"{{"outcomes":[{{"peer":"{}","ok":false,"reason":"timeout"}}],"learned":[{{"addr":"{}","port":8333,"services":"1097","seenAt":{NOW},"from":"{}"}}]}}"#, peer(0), onion(3), peer(0))).unwrap();
        assert_eq!((r.learned[0].services, r.learned[0].seen_at, r.outcomes[0].reason.as_deref()), (1097, NOW, Some("timeout")));
    }

    #[test]
    fn reports_are_bounded_and_strict() {
        let one = format!(r#"{{"peer":"{}","ok":true}}"#, peer(0));
        let many = format!(r#"{{"outcomes":[{}]}}"#, vec![one.as_str(); MAX_REPORT + 1].join(","));
        assert!(Report::parse(&many).unwrap_err().starts_with("invalid parameters: a report holds at most 500"));
        assert!(Report::parse(r#"{"outcomes":[],"extra":1}"#).unwrap_err().starts_with("invalid parameters: report:"));
        assert!(Report::parse("[]").is_err());
        assert_eq!(Report::parse("{}").unwrap(), Report::default());
    }

    #[test]
    fn caps_per_peer_and_per_book() {
        let mut b = book_with(1, 0);
        for i in 0..MAX_PER_FROM as u16 {
            assert_eq!(b.learn(&learned(100 + i, 0, NOW), NOW), Ok(true));
        }
        assert_eq!(b.learn(&learned(999, 0, NOW), NOW), Err("its peer already gave 64"));
        assert_eq!(b.learn(&learned(999, 1, NOW), NOW), Ok(true), "another peer may still");
        // A full book makes room by dropping the stalest learned peer that never worked.
        let mut b = book_with(2, 0);
        let mut i = 0u16;
        while b.entries.len() < MAX_ENTRIES {
            b.learn(&learned(3000 + i, 4000 + i / 60, NOW - u64::from(i)), NOW).unwrap();
            i += 1;
        }
        let stalest = b.entries.iter().filter(|e| e.source == Origin::Learned).min_by_key(|e| e.last_seen).unwrap().addr.clone();
        assert_eq!(b.learn(&learned(9000, 9001, NOW), NOW), Ok(true));
        assert_eq!(b.entries.len(), MAX_ENTRIES);
        assert!(!b.entries.iter().any(|e| e.addr == stalest) && b.entries.iter().filter(|e| e.source == Origin::List).count() == 2);
    }

    #[test]
    fn pruning_learned_peers() {
        let mut b = book_with(1, 1);
        b.learn(&learned(10, 0, NOW), NOW).unwrap();
        b.learn(&learned(11, 0, NOW), NOW).unwrap();
        b.outcome(&peer(11), true, NOW);
        b.prune(NOW + 7 * DAY);
        assert_eq!(b.entries.len(), 4, "a week is still within reach");
        b.prune(NOW + 7 * DAY + 1);
        assert!(!b.entries.iter().any(|e| e.addr == onion(10)), "never worked, older than 7 days");
        b.prune(NOW + 30 * DAY + 1);
        assert!(!b.entries.iter().any(|e| e.addr == onion(11)), "no success in 30 days");
        assert_eq!(b.entries.len(), 2, "list and seed entries stay");
    }

    #[test]
    fn counts_and_when_to_harvest() {
        let mut b = book_with(20, 3);
        assert_eq!(b.counts(true, NOW), Counts { list: 20, learned: 0, seed: 3, usable: 20, ok_last30d: 0 });
        assert!(b.harvest_due(true, NOW));
        for i in 0..12 {
            b.outcome(&peer(i), true, NOW);
        }
        assert!(!b.harvest_due(true, NOW), "12 peers worked this month");
        assert!(b.harvest_due(true, NOW + 31 * DAY), "a month later they no longer count");
        b.harvest_started(NOW + 31 * DAY - 3600);
        b.harvest_answered = true;
        assert!(!b.harvest_due(true, NOW + 31 * DAY), "a seed answered: once a day");
        assert_eq!(b.pick_seeds().len(), 3);
        assert!(!book_with(1, 0).harvest_due(true, NOW), "no seeds to ask");
        let first = b.usable(true, NOW)[0].peer();
        assert!(at(&b, &first).last_ok.is_some(), "peers that worked come first");
    }

    #[test]
    fn a_harvest_no_seed_answered_is_tried_again_in_an_hour_three_times_a_day() {
        const HOUR: u64 = 3600;
        let mut b = book_with(20, 3);
        b.harvest_started(NOW);
        assert!(!b.harvest_due(true, NOW + HOUR - 1), "an hour between tries");
        assert!(b.harvest_due(true, NOW + HOUR), "no seed answered");
        b.harvest_started(NOW + HOUR);
        b.harvest_started(NOW + 2 * HOUR);
        assert!(!b.harvest_due(true, NOW + 3 * HOUR) && !b.harvest_due(true, NOW + DAY - 1), "3 tries a day");
        assert!(b.harvest_due(true, NOW + DAY), "the first try is a day old");
        // A seed answered: the 24 h clock.
        b.harvest_started(NOW + DAY);
        b.harvest_answered = true;
        assert!(!b.harvest_due(true, NOW + DAY + HOUR) && !b.harvest_due(true, NOW + 2 * DAY - 1));
        assert!(b.harvest_due(true, NOW + 2 * DAY));
        assert_eq!(b.harvest_tries, [NOW + HOUR, NOW + 2 * HOUR, NOW + DAY], "only the last day's tries");
        // Kept across a restart.
        let back: Book = serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn a_list_peer_a_newer_list_drops_stays_learned_if_it_worked_here() {
        let mut b = book_with(3, 0);
        b.outcome(&peer(0), true, NOW);
        b.outcome(&peer(1), true, NOW - 31 * DAY);
        // Peer 0 worked this month, peer 1 longer ago, peer 2 never.
        b.sync_shipped(&[peer(9)], 8, &[], NOW);
        let e = at(&b, &peer(0));
        assert_eq!((e.source, e.from.as_deref(), e.ok_count), (Origin::Learned, Some(FROM_LIST), 1));
        assert!(!b.entries.iter().any(|e| e.addr == onion(1) || e.addr == onion(2)));
        assert_eq!(b.usable(true, NOW).iter().map(|e| e.peer()).collect::<Vec<_>>(), [peer(0), peer(9)]);
        // A later list naming it again makes it a list peer; otherwise pruning as any learned peer.
        let mut again = b.clone();
        again.sync_shipped(&[peer(0), peer(9)], 9, &[], NOW);
        assert_eq!((at(&again, &peer(0)).source, at(&again, &peer(0)).from.as_deref()), (Origin::List, None));
        b.prune(NOW + 30 * DAY);
        assert!(b.entries.iter().any(|e| e.addr == onion(0)));
        b.prune(NOW + 30 * DAY + 1);
        assert!(!b.entries.iter().any(|e| e.addr == onion(0)), "30 days without a success");
    }

    #[test]
    fn harvested_gossip_is_onion_v3_fresh_and_capable() {
        let mut b = book_with(0, 1);
        let seed = peer(1000);
        assert_eq!(b.harvested(&onion(5), 8333, X49, NOW as u32 as u64, &seed, NOW), Ok(true));
        assert!(b.harvested("203.0.113.5", 8333, X49, NOW, &seed, NOW).is_err());
        assert!(b.harvested(&onion(6), 8333, 0x09, NOW, &seed, NOW).is_err(), "no compact filters");
        assert!(b.harvested(&onion(6), 8333, X49, NOW - 4 * DAY, &seed, NOW).is_err());
        assert_eq!(b.entries.iter().find(|e| e.addr == onion(5)).unwrap().from.as_deref(), Some(seed.as_str()));
    }

    #[test]
    fn kept_on_disk_and_set_aside_when_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = book_with(2, 1);
        b.learn(&learned(10, 0, NOW), NOW).unwrap();
        b.outcome(&peer(0), true, NOW);
        b.save(dir.path()).unwrap();
        assert_eq!(Book::load(dir.path(), BNetwork::Mainnet), b);
        assert_eq!(Book::load(dir.path(), BNetwork::Signet), Book::new(BNetwork::Signet), "another network's file is not read");
        let path = dir.path().join(Book::file_name(BNetwork::Mainnet));
        std::fs::write(&path, "{").unwrap();
        assert_eq!(Book::load(dir.path(), BNetwork::Mainnet), Book::new(BNetwork::Mainnet));
        assert!(dir.path().join("kyoto_peers_mainnet.json.corrupt").exists());
        #[cfg(unix)]
        {
            b.save(dir.path()).unwrap();
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
