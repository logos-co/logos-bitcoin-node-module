//! Address-free Esplora probes: `/blocks/tip/height` and `/blocks/tip/hash`, and the genesis
//! block's hash once per circuit. Nothing about any wallet is sent.

use std::time::Instant;

use super::client::Route;
use super::http::Conn;
use super::socks::{Isolation, ProxyAddr};
use crate::health::Observed;

fn hash_ok(what: &str, h: &str) -> Result<String, String> {
    if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(h.to_ascii_lowercase())
    } else {
        Err(format!("{what}: not a block hash: {}", h.chars().take(80).collect::<String>()))
    }
}

/// Probes the Esplora base URL `url` on the route given; `check_genesis` also asks for block 0.
/// The round trip timed is the tip height's, on a connection already open.
pub async fn probe(
    url: &str,
    creds: Option<(&str, &str)>,
    route: Route,
    proxy: Option<&ProxyAddr>,
    iso: &Isolation,
    check_genesis: bool,
) -> Result<Observed, String> {
    let mut c = Conn::open(url, creds, route, proxy, iso).await?;
    let started = Instant::now();
    let height = c.get_text("/blocks/tip/height").await?;
    let rtt_ms = started.elapsed().as_millis() as u64;
    let tip_height = crate::strnum::parse(&height)
        .ok_or_else(|| format!("/blocks/tip/height: not a height: {}", height.chars().take(80).collect::<String>()))?;
    let tip_hash = hash_ok("/blocks/tip/hash", &c.get_text("/blocks/tip/hash").await?)?;
    let genesis = match check_genesis {
        true => Some(hash_ok("/block-height/0", &c.get_text("/block-height/0").await?)?),
        false => None,
    };
    Ok(Observed { genesis, tip_height, tip_hash, rtt_ms, server_version: None })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::network::BNetwork;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A loopback Esplora server answering any number of keep-alive GETs; returns the paths asked.
    pub async fn fake_server(genesis: &'static str, height: &'static str) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}/api", listener.local_addr().unwrap().port());
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut asked = Vec::new();
            let mut buf = Vec::new();
            loop {
                let mut chunk = [0u8; 2048];
                let n = s.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]).to_string();
                    buf.drain(..end + 4);
                    let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                    let body = match path.as_str() {
                        "/api/blocks/tip/height" => height.to_string(),
                        "/api/blocks/tip/hash" => "AB".repeat(32),
                        "/api/block-height/0" => genesis.to_string(),
                        _ => "not found".to_string(),
                    };
                    let status = if body == "not found" { "404 Not Found" } else { "200 OK" };
                    asked.push(head);
                    let reply = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                    s.write_all(reply.as_bytes()).await.unwrap();
                }
            }
            asked
        });
        (url, task)
    }

    #[tokio::test]
    async fn probes_tip_and_genesis_on_one_connection() {
        let (url, server) = fake_server(BNetwork::Signet.genesis(), "325810").await;
        let o = probe(&url, None, Route::Direct, None, &Isolation::fresh(), true).await.unwrap();
        assert_eq!((o.tip_height, o.tip_hash, o.genesis.as_deref()), (325_810, "ab".repeat(32), Some(BNetwork::Signet.genesis())));
        let asked = server.await.unwrap();
        let paths: Vec<&str> = asked.iter().map(|h| h.split_whitespace().nth(1).unwrap()).collect();
        assert_eq!(paths, ["/api/blocks/tip/height", "/api/blocks/tip/hash", "/api/block-height/0"]);
        assert!(asked.iter().all(|h| !h.to_ascii_lowercase().contains("authorization")));
    }

    #[tokio::test]
    async fn refuses_answers_that_are_not_heights_or_hashes() {
        let (url, _s) = fake_server("nope", "12a").await;
        let e = probe(&url, None, Route::Direct, None, &Isolation::fresh(), false).await.unwrap_err();
        assert!(e.contains("not a height"), "{e}");
        let (url, _s) = fake_server("nope", "12").await;
        let e = probe(&url, None, Route::Direct, None, &Isolation::fresh(), true).await.unwrap_err();
        assert!(e.contains("/block-height/0: not a block hash"), "{e}");
    }
}
