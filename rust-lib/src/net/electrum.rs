//! Address-free Electrum probes: `server.version`, `server.features` (for the genesis block)
//! and `blockchain.headers.subscribe` (the tip). Nothing about any wallet is sent.

use std::time::Instant;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use super::cert::CertInfo;
use super::client::{dial, tls, Route, Stream};
use super::socks::{Isolation, ProxyAddr};
use crate::addr;
use crate::health::Observed;

/// The longest reply line taken; these replies are a few hundred bytes.
const MAX_LINE: u64 = 64 * 1024;

/// The client name sent with `server.version`: none, so the server learns nothing.
pub const CLIENT_NAME: &str = "";
pub const PROTOCOL: &str = "1.4";

async fn send(s: &mut BufReader<Stream>, calls: &[(u64, &str, Value)]) -> Result<(), String> {
    let mut out = String::new();
    for (id, method, params) in calls {
        out.push_str(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string());
        out.push('\n');
    }
    s.write_all(out.as_bytes()).await.map_err(|e| format!("send: {e}"))?;
    s.flush().await.map_err(|e| format!("send: {e}"))
}

/// The result of call `id`, skipping notifications and other replies.
async fn recv(s: &mut BufReader<Stream>, id: u64) -> Result<Value, String> {
    loop {
        let mut line = Vec::new();
        let n = (&mut *s).take(MAX_LINE).read_until(b'\n', &mut line).await.map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("the server closed the connection".into());
        }
        if !line.ends_with(b"\n") && n as u64 >= MAX_LINE {
            return Err("a reply line is too long".into());
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let v: Value = serde_json::from_slice(&line).map_err(|e| format!("not JSON-RPC: {e}"))?;
        if v.get("id").and_then(Value::as_u64) != Some(id) {
            continue;
        }
        if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
            return Err(format!("server error: {}", e.to_string().chars().take(160).collect::<String>()));
        }
        return v.get("result").cloned().ok_or_else(|| "a reply without a result".into());
    }
}

/// A block header's hash as explorers print it: double SHA-256, bytes reversed.
pub fn header_hash(hex_header: &str) -> Result<String, String> {
    let bytes = hex::decode(hex_header.trim()).map_err(|_| "the header is not hex".to_string())?;
    if bytes.len() != 80 {
        return Err(format!("the header is {} bytes, not 80", bytes.len()));
    }
    let mut h: [u8; 32] = Sha256::digest(Sha256::digest(&bytes)).into();
    h.reverse();
    Ok(hex::encode(h))
}

/// Probes `ssl://host:port` (pinned when `pin` is set) or `tcp://host:port` on the route given,
/// with the certificate a TLS server proved it holds. The round trip timed is headers.subscribe's,
/// on a connection already open.
pub async fn probe(url: &str, route: Route, proxy: Option<&ProxyAddr>, iso: &Isolation, pin: Option<[u8; 32]>) -> (Result<Observed, String>, Option<CertInfo>) {
    let mut cert = None;
    let r = probe_on(url, route, proxy, iso, pin, &mut cert).await;
    (r, cert)
}

async fn probe_on(url: &str, route: Route, proxy: Option<&ProxyAddr>, iso: &Isolation, pin: Option<[u8; 32]>, cert: &mut Option<CertInfo>) -> Result<Observed, String> {
    let p = addr::split(url)?;
    let port = p.port.ok_or_else(|| format!("{url}: no port"))?;
    let stream = dial(&p.host, port, route, proxy, iso).await.map_err(|e| e.to_string())?;
    let stream = match p.scheme.as_str() {
        "ssl" => match tls(stream, &p.host, false, pin).await {
            Ok((s, c)) => {
                *cert = Some(c);
                s
            }
            Err(f) => {
                *cert = f.cert;
                return Err(f.error.to_string());
            }
        },
        "tcp" => stream,
        s => return Err(format!("{s}:// is not an Electrum transport")),
    };
    let mut s = BufReader::new(stream);
    send(&mut s, &[(1, "server.version", json!([CLIENT_NAME, PROTOCOL])), (2, "server.features", json!([]))]).await?;
    let version = recv(&mut s, 1).await?;
    let features = recv(&mut s, 2).await?;
    let started = Instant::now();
    send(&mut s, &[(3, "blockchain.headers.subscribe", json!([]))]).await?;
    let tip = recv(&mut s, 3).await?;
    let rtt_ms = started.elapsed().as_millis() as u64;
    let genesis = match features.get("genesis_hash").and_then(Value::as_str) {
        Some(g) => g.to_ascii_lowercase(),
        None => {
            send(&mut s, &[(4, "blockchain.block.header", json!([0]))]).await?;
            header_hash(recv(&mut s, 4).await?.as_str().ok_or("blockchain.block.header: not hex")?)?
        }
    };
    let height = tip.get("height").and_then(Value::as_u64).ok_or("headers.subscribe: no height")?;
    let hex_header = tip.get("hex").and_then(Value::as_str).ok_or("headers.subscribe: no header")?;
    Ok(Observed {
        genesis: Some(genesis),
        tip_height: height,
        tip_hash: header_hash(hex_header)?,
        rtt_ms,
        server_version: version.get(0).and_then(Value::as_str).map(|v| v.chars().take(64).collect()),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::network::BNetwork;
    use tokio::io::AsyncWriteExt;

    pub const GENESIS_HEADER: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";

    #[test]
    fn hashes_headers() {
        assert_eq!(header_hash(GENESIS_HEADER).unwrap(), BNetwork::Mainnet.genesis());
        assert!(header_hash("00").unwrap_err().contains("80"));
        assert!(header_hash("zz").is_err());
    }

    /// A loopback Electrum server: answers the three calls; `features` may leave out the genesis.
    pub async fn fake_server(genesis: Option<&'static str>, height: u64) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("tcp://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let task = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let mut s = BufReader::new(s);
            let mut seen = Vec::new();
            let mut line = String::new();
            while s.read_line(&mut line).await.unwrap_or(0) > 0 {
                let v: Value = serde_json::from_str(&line).unwrap();
                line.clear();
                let method = v["method"].as_str().unwrap().to_string();
                let result = match method.as_str() {
                    "server.version" => json!(["fake 1.0", "1.4"]),
                    "server.features" => json!({"genesis_hash": genesis, "protocol_max": "1.4"}),
                    "blockchain.headers.subscribe" => json!({"height": height, "hex": GENESIS_HEADER}),
                    "blockchain.block.header" => json!(GENESIS_HEADER),
                    _ => Value::Null,
                };
                seen.push(format!("{method} {}", v["params"]));
                // A notification first, which the client must skip.
                let note = json!({"jsonrpc": "2.0", "method": "blockchain.headers.subscribe", "params": [{"height": 1}]});
                let reply = json!({"jsonrpc": "2.0", "id": v["id"], "result": result});
                s.get_mut().write_all(format!("{note}\n{reply}\n").as_bytes()).await.unwrap();
            }
            seen
        });
        (url, task)
    }

    #[tokio::test]
    async fn probes_a_server_without_naming_any_address() {
        let (url, server) = fake_server(Some(BNetwork::Mainnet.genesis()), 970_838).await;
        let o = probe(&url, Route::Direct, None, &Isolation::fresh(), None).await.0.unwrap();
        assert_eq!((o.tip_height, o.tip_hash.as_str(), o.genesis.as_deref()), (970_838, BNetwork::Mainnet.genesis(), Some(BNetwork::Mainnet.genesis())));
        assert_eq!(o.server_version.as_deref(), Some("fake 1.0"));
        drop(o);
        let seen = server.await.unwrap();
        assert_eq!(seen, [r#"server.version ["","1.4"]"#, "server.features []", "blockchain.headers.subscribe []"]);
    }

    #[tokio::test]
    async fn asks_for_the_genesis_header_when_features_leave_it_out() {
        let (url, server) = fake_server(None, 5).await;
        let o = probe(&url, Route::Direct, None, &Isolation::fresh(), None).await.0.unwrap();
        assert_eq!(o.genesis.as_deref(), Some(BNetwork::Mainnet.genesis()));
        drop(o);
        assert_eq!(server.await.unwrap().last().unwrap(), "blockchain.block.header [0]");
    }
}
