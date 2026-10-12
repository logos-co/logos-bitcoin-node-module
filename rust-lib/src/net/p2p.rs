//! The little of Bitcoin's P2P protocol a harvest needs, in the order the peer-list crawler
//! uses: version, sendaddrv2 before verack, one getaddr, and the addrv2 (or addr) answer.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::client::Stream;
use crate::network::BNetwork;

pub const PROTOCOL: i32 = 70016;
/// NODE_NETWORK | NODE_WITNESS | NODE_COMPACT_FILTERS: what Kyoto needs of a peer.
pub const X49: u64 = 0x49;
const MAX_PAYLOAD: usize = 4_000_000;
const MAX_ADDRS: u64 = 1000;
const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// One address a peer gossiped: an IPv4, IPv6 or onion v3 host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gossip {
    pub host: String,
    pub port: u16,
    pub services: u64,
    pub time: u32,
}

fn sha256d(b: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(b)).into()
}

fn onion_checksum(pk: &[u8; 32]) -> [u8; 2] {
    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(pk);
    h.update([3u8]);
    let d = h.finalize();
    [d[0], d[1]]
}

/// `<56 characters>.onion` for a v3 service key.
pub fn onion_from_key(pk: &[u8; 32]) -> String {
    let mut raw = pk.to_vec();
    raw.extend(onion_checksum(pk));
    raw.push(3);
    let (mut out, mut buf, mut bits) = (String::new(), 0u32, 0u32);
    for b in raw {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
        buf &= (1 << bits) - 1;
    }
    format!("{out}.onion")
}

/// The service key of a v3 onion host, when its version and checksum check.
pub fn onion_key(host: &str) -> Option<[u8; 32]> {
    let label = host.strip_suffix(".onion").filter(|l| l.len() == 56)?;
    let (mut raw, mut buf, mut bits) = (Vec::with_capacity(35), 0u32, 0u32);
    for c in label.bytes() {
        buf = (buf << 5) | B32.iter().position(|&x| x == c)? as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            raw.push((buf >> bits) as u8);
        }
        buf &= (1 << bits) - 1;
    }
    let pk: [u8; 32] = raw.get(..32)?.try_into().ok()?;
    (raw.len() == 35 && raw[34] == 3 && raw[32..34] == onion_checksum(&pk)).then_some(pk)
}

pub fn frame(magic: [u8; 4], cmd: &str, payload: &[u8]) -> Vec<u8> {
    let mut m = magic.to_vec();
    let mut name = [0u8; 12];
    name[..cmd.len()].copy_from_slice(cmd.as_bytes());
    m.extend(name);
    m.extend((payload.len() as u32).to_le_bytes());
    m.extend(&sha256d(payload)[..4]);
    m.extend(payload);
    m
}

pub fn compact(n: u64) -> Vec<u8> {
    match n {
        0..=0xfc => vec![n as u8],
        0xfd..=0xffff => [vec![0xfd], (n as u16).to_le_bytes().to_vec()].concat(),
        0x1_0000..=0xffff_ffff => [vec![0xfe], (n as u32).to_le_bytes().to_vec()].concat(),
        _ => [vec![0xff], n.to_le_bytes().to_vec()].concat(),
    }
}

fn take<'a>(b: &mut &'a [u8], n: usize) -> Result<&'a [u8], String> {
    if b.len() < n {
        return Err("a message ends early".into());
    }
    let (head, rest) = b.split_at(n);
    *b = rest;
    Ok(head)
}

fn read_compact(b: &mut &[u8]) -> Result<u64, String> {
    let first = take(b, 1)?[0];
    Ok(match first {
        0xfd => u64::from(u16::from_le_bytes(take(b, 2)?.try_into().unwrap_or_default())),
        0xfe => u64::from(u32::from_le_bytes(take(b, 4)?.try_into().unwrap_or_default())),
        0xff => u64::from_le_bytes(take(b, 8)?.try_into().unwrap_or_default()),
        n => u64::from(n),
    })
}

/// A version message that names nothing: no services, no addresses, no user agent, no height.
pub fn version_payload(now: u64, nonce: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(86);
    p.extend(PROTOCOL.to_le_bytes());
    p.extend(0u64.to_le_bytes());
    p.extend((now as i64).to_le_bytes());
    p.extend([0u8; 26]);
    p.extend([0u8; 26]);
    p.extend(nonce.to_le_bytes());
    p.push(0);
    p.extend(0i32.to_le_bytes());
    p.push(0);
    p
}

/// BIP155 addrv2: the IPv4, IPv6 and onion v3 entries; other networks are skipped.
pub fn parse_addrv2(payload: &[u8]) -> Result<Vec<Gossip>, String> {
    let mut b = payload;
    let n = read_compact(&mut b)?;
    if n > MAX_ADDRS {
        return Err(format!("addrv2 with {n} entries"));
    }
    let mut out = Vec::new();
    for _ in 0..n {
        let time = u32::from_le_bytes(take(&mut b, 4)?.try_into().unwrap_or_default());
        let services = read_compact(&mut b)?;
        let network = take(&mut b, 1)?[0];
        let len = read_compact(&mut b)?;
        if len > 512 {
            return Err("addrv2 address too long".into());
        }
        let addr = take(&mut b, len as usize)?;
        let port = u16::from_be_bytes(take(&mut b, 2)?.try_into().unwrap_or_default());
        let host = match (network, addr.len()) {
            (1, 4) => Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string(),
            (2, 16) => Ipv6Addr::from(<[u8; 16]>::try_from(addr).unwrap_or_default()).to_string(),
            (4, 32) => onion_from_key(&addr.try_into().unwrap_or_default()),
            _ => continue,
        };
        out.push(Gossip { host, port, services, time });
    }
    Ok(out)
}

/// Legacy addr: IPv4 (mapped) and IPv6 only, which carry no onion v3.
pub fn parse_addr(payload: &[u8]) -> Result<Vec<Gossip>, String> {
    let mut b = payload;
    let n = read_compact(&mut b)?;
    if n > MAX_ADDRS {
        return Err(format!("addr with {n} entries"));
    }
    let mut out = Vec::new();
    for _ in 0..n {
        let time = u32::from_le_bytes(take(&mut b, 4)?.try_into().unwrap_or_default());
        let services = u64::from_le_bytes(take(&mut b, 8)?.try_into().unwrap_or_default());
        let ip = Ipv6Addr::from(<[u8; 16]>::try_from(take(&mut b, 16)?).unwrap_or_default());
        let port = u16::from_be_bytes(take(&mut b, 2)?.try_into().unwrap_or_default());
        let host = ip.to_ipv4_mapped().map(|v4| v4.to_string()).unwrap_or_else(|| ip.to_string());
        out.push(Gossip { host, port, services, time });
    }
    Ok(out)
}

/// An addrv2 payload of onion v3 entries (`host`, `port`, `services`, `time`), for tests.
pub fn encode_addrv2(entries: &[Gossip]) -> Vec<u8> {
    let mut p = compact(entries.len() as u64);
    for g in entries {
        p.extend(g.time.to_le_bytes());
        p.extend(compact(g.services));
        if let Some(pk) = onion_key(&g.host) {
            p.push(4);
            p.extend(compact(32));
            p.extend(pk);
        } else if let Ok(ip) = g.host.parse::<Ipv4Addr>() {
            p.push(1);
            p.extend(compact(4));
            p.extend(ip.octets());
        }
        p.extend(g.port.to_be_bytes());
    }
    p
}

pub struct Peer {
    s: Stream,
    magic: [u8; 4],
}

impl Peer {
    pub async fn send(&mut self, cmd: &str, payload: &[u8]) -> Result<(), String> {
        self.s.write_all(&frame(self.magic, cmd, payload)).await.map_err(|e| format!("p2p send: {e}"))?;
        self.s.flush().await.map_err(|e| format!("p2p send: {e}"))
    }

    /// The next message, its magic, length and checksum checked.
    async fn recv(&mut self) -> Result<(String, Vec<u8>), String> {
        let mut head = [0u8; 24];
        self.s.read_exact(&mut head).await.map_err(|e| format!("p2p recv: {e}"))?;
        if head[..4] != self.magic {
            return Err("p2p: wrong network magic".into());
        }
        let len = u32::from_le_bytes([head[16], head[17], head[18], head[19]]) as usize;
        if len > MAX_PAYLOAD {
            return Err(format!("p2p: a {len}-byte message"));
        }
        let mut payload = vec![0u8; len];
        self.s.read_exact(&mut payload).await.map_err(|e| format!("p2p recv: {e}"))?;
        if sha256d(&payload)[..4] != head[20..24] {
            return Err("p2p: bad checksum".into());
        }
        let cmd = String::from_utf8_lossy(&head[4..16]).trim_end_matches('\0').to_string();
        Ok((cmd, payload))
    }

    /// version, then sendaddrv2 and verack once the peer's version arrives; the peer's services.
    pub async fn handshake(s: Stream, net: BNetwork, now: u64) -> Result<(Self, u64), String> {
        let mut p = Peer { s, magic: net.magic() };
        p.send("version", &version_payload(now, rand::random())).await?;
        let (mut services, mut version, mut verack) = (0u64, false, false);
        while !(version && verack) {
            let (cmd, payload) = p.recv().await?;
            match cmd.as_str() {
                "version" if !version => {
                    services = u64::from_le_bytes(payload.get(4..12).ok_or("p2p: a short version")?.try_into().unwrap_or_default());
                    version = true;
                    p.send("sendaddrv2", &[]).await?;
                    p.send("verack", &[]).await?;
                }
                "verack" => verack = true,
                "ping" => p.send("pong", &payload).await?,
                _ => {}
            }
        }
        Ok((p, services))
    }

    /// A ping answered: the peer has handled every message sent before it.
    pub async fn ping(&mut self) -> Result<(), String> {
        let nonce = rand::random::<u64>().to_le_bytes();
        self.send("ping", &nonce).await?;
        loop {
            let (cmd, payload) = self.recv().await?;
            match cmd.as_str() {
                "pong" if payload == nonce => return Ok(()),
                "ping" => self.send("pong", &payload).await?,
                _ => {}
            }
        }
    }

    /// One getaddr; addresses until the bulk answer (2 or more) or until `window` ends.
    pub async fn getaddr(&mut self, window: Duration) -> Result<Vec<Gossip>, String> {
        self.send("getaddr", &[]).await?;
        let deadline = tokio::time::Instant::now() + window;
        let mut out = Vec::new();
        while let Ok(r) = tokio::time::timeout_at(deadline, self.recv()).await {
            let (cmd, payload) = r?;
            let batch = match cmd.as_str() {
                "addrv2" => parse_addrv2(&payload)?,
                "addr" => parse_addr(&payload)?,
                "ping" => {
                    self.send("pong", &payload).await?;
                    continue;
                }
                _ => continue,
            };
            let bulk = batch.len() >= 2;
            out.extend(batch);
            // At most one bulk answer's worth, however the peer splits it.
            if bulk || out.len() as u64 >= MAX_ADDRS {
                out.truncate(MAX_ADDRS as usize);
                break;
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real onion v3 seed from Bitcoin Core 31.1's nodes_signet.txt.
    fn real() -> String {
        crate::peers::fixed_seeds(BNetwork::Signet)[0].split(':').next().unwrap().to_string()
    }

    #[test]
    fn onion_names_round_trip_and_check_their_checksum() {
        let host = real();
        let pk = onion_key(&host).expect("a valid v3 name");
        assert_eq!(onion_from_key(&pk), host);
        let mut bad = host.clone().into_bytes();
        bad[3] = if bad[3] == b'a' { b'b' } else { b'a' };
        assert_eq!(onion_key(std::str::from_utf8(&bad).unwrap()), None);
        assert_eq!(onion_key("expyuzz4wqqyqhjn.onion"), None, "v2");
        assert_eq!(onion_key(&host.to_uppercase()), None);
    }

    #[test]
    fn addrv2_and_addr() {
        let host = real();
        let entries = vec![
            Gossip { host: host.clone(), port: 38333, services: X49, time: 1_700_000_000 },
            Gossip { host: "203.0.113.5".into(), port: 8333, services: 1, time: 7 },
        ];
        assert_eq!(parse_addrv2(&encode_addrv2(&entries)).unwrap(), entries);
        // An I2P entry (network 5) is skipped, the rest still read.
        let mut p = compact(2);
        p.extend([1, 0, 0, 0, 0x01, 5, 32]);
        p.extend([9u8; 32]);
        p.extend(0u16.to_be_bytes());
        p.extend(&encode_addrv2(&entries[..1])[1..]);
        assert_eq!(parse_addrv2(&p).unwrap(), entries[..1]);
        assert!(parse_addrv2(&compact(1001)).is_err());
        assert!(parse_addrv2(&[1, 0, 0]).is_err(), "cut short");
        // Legacy addr: an IPv4-mapped entry.
        let mut a = compact(1);
        a.extend(5u32.to_le_bytes());
        a.extend(9u64.to_le_bytes());
        a.extend(Ipv4Addr::new(10, 0, 0, 2).to_ipv6_mapped().octets());
        a.extend(18444u16.to_be_bytes());
        assert_eq!(parse_addr(&a).unwrap(), vec![Gossip { host: "10.0.0.2".into(), port: 18444, services: 9, time: 5 }]);
    }

    #[test]
    fn frames() {
        let f = frame(BNetwork::Regtest.magic(), "verack", &[]);
        assert_eq!(f.len(), 24);
        assert_eq!(&f[..4], &[0xfa, 0xbf, 0xb5, 0xda]);
        assert_eq!(&f[20..24], &sha256d(&[])[..4]);
        assert_eq!(compact(0xfd), [0xfd, 0xfd, 0]);
        assert_eq!(version_payload(1, 2).len(), 86);
    }
}
