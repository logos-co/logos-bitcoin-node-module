//! HTTP/1.1 JSON-RPC POSTs over a stream `dial` opened: Bitcoin Core RPC.

use base64::Engine;
use http::{header, Request, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;

use super::cert::CertInfo;
use super::client::{dial, tls, Route};
use super::socks::{Isolation, ProxyAddr};
use crate::addr;

/// What a request says about the client: nothing beyond what every browser says.
pub const USER_AGENT: &str = "Mozilla/5.0";

/// One keep-alive connection to an http(s) base URL.
pub struct Conn {
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    host: String,
    base: String,
    auth: Option<String>,
    /// The certificate an https server proved it holds.
    pub cert: Option<CertInfo>,
}

impl Conn {
    /// Opens it; https is pinned when `pin` is set. A failure carries the certificate an https
    /// server proved it holds, for the person to pin.
    pub async fn open(base_url: &str, auth: Option<(&str, &str)>, route: Route, proxy: Option<&ProxyAddr>, iso: &Isolation, pin: Option<[u8; 32]>) -> Result<Self, (String, Option<CertInfo>)> {
        let p = addr::split(base_url).map_err(|e| (e, None))?;
        let https = match p.scheme.as_str() {
            "https" => true,
            "http" => false,
            s => return Err((format!("{s}:// is not http"), None)),
        };
        let port = p.port.unwrap_or(if https { 443 } else { 80 });
        let stream = dial(&p.host, port, route, proxy, iso).await.map_err(|e| (e.to_string(), None))?;
        let (stream, cert) = match https {
            true => match tls(stream, &p.host, true, pin).await {
                Ok((s, c)) => (s, Some(c)),
                Err(f) => return Err((f.error.to_string(), f.cert)),
            },
            false => (stream, None),
        };
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|e| (format!("http: {e}"), cert.clone()))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let host = addr::fmt_host(&p.host);
        let host = if port == if https { 443 } else { 80 } { host } else { format!("{host}:{port}") };
        let auth = auth.map(|(u, pw)| format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{u}:{pw}"))));
        Ok(Self { sender, host, base: p.path, auth, cert })
    }

    /// JSON-RPC POST to the configured endpoint; never follows redirects.
    pub async fn rpc(&mut self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        self.sender.ready().await.map_err(|e| format!("http: {e}"))?;
        let body = serde_json::json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}).to_string();
        let mut req = Request::post(if self.base.is_empty() { "/" } else { &self.base })
            .header(header::HOST, &self.host).header(header::USER_AGENT, USER_AGENT)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(a) = &self.auth { req = req.header(header::AUTHORIZATION, a); }
        let resp = self.sender.send_request(req.body(Full::new(Bytes::from(body))).map_err(|_| "invalid RPC request")?)
            .await.map_err(|e| format!("http: {e}"))?;
        let status = resp.status();
        if status != StatusCode::OK && status != StatusCode::INTERNAL_SERVER_ERROR {
            return Err(format!("RPC HTTP {}", status.as_u16()));
        }
        let body = Limited::new(resp.into_body(), 4 * 1024 * 1024).collect().await.map_err(|_| "RPC response too large or incomplete")?.to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).map_err(|_| "RPC response is not JSON")?;
        if v["id"] != 1 { return Err("RPC response ID mismatch".into()); }
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A one-request HTTP server on loopback; returns its URL and what it was asked.
    async fn serve_once(answer: &'static str) -> (String, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}/api", listener.local_addr().unwrap().port());
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(answer.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        });
        (url, task)
    }

    #[tokio::test]
    async fn rpc_sends_a_generic_request() {
        let (url, server) = serve_once("HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\n{\"result\":5,\"error\":null,\"id\":1}").await;
        let mut c = Conn::open(&url, Some(("me", "pw")), Route::Direct, None, &Isolation::fresh(), None).await.unwrap();
        assert_eq!(c.rpc("getblockcount", serde_json::json!([])).await.unwrap()["result"], 5);
        let asked = server.await.unwrap().to_ascii_lowercase();
        assert!(asked.starts_with("post /api http/1.1\r\n"), "{asked}");
        assert!(asked.contains("user-agent: mozilla/5.0\r\n") && asked.contains("authorization: basic bwu6chc=\r\n"), "{asked}");
        assert!(!asked.contains('@'), "{asked}");
    }

    #[tokio::test]
    async fn errors() {
        for (answer, why) in [
            ("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found", "RPC HTTP 404"),
            ("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nnot json!", "not JSON"),
            ("HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n{\"id\":2}", "ID mismatch"),
        ] {
            let (url, _s) = serve_once(answer).await;
            let mut c = Conn::open(&url, None, Route::Direct, None, &Isolation::fresh(), None).await.unwrap();
            let e = c.rpc("getblockcount", serde_json::json!([])).await.unwrap_err();
            assert!(e.contains(why), "{e}");
        }
    }
}
