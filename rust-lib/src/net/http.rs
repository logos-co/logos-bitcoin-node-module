//! HTTP/1.1 GETs over a stream `dial` opened: Esplora servers and peer list updates.

use base64::Engine;
use http::{header, Request, StatusCode};
use http_body_util::{BodyExt, Empty, Limited};
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
    sender: hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
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

    /// GETs the base URL's path followed by `path`; a body longer than `limit` is an error.
    pub async fn get(&mut self, path: &str, limit: usize) -> Result<(StatusCode, Bytes), String> {
        self.sender.ready().await.map_err(|e| format!("http: {e}"))?;
        let target = match format!("{}{path}", self.base) {
            t if t.is_empty() => "/".to_string(),
            t => t,
        };
        let mut req = Request::get(target).header(header::HOST, &self.host).header(header::USER_AGENT, USER_AGENT);
        if let Some(a) = &self.auth {
            req = req.header(header::AUTHORIZATION, a);
        }
        let req = req.body(Empty::new()).map_err(|e| format!("http: {e}"))?;
        let resp = self.sender.send_request(req).await.map_err(|e| format!("http: {e}"))?;
        let status = resp.status();
        let body = Limited::new(resp.into_body(), limit).collect().await.map_err(|e| format!("http body: {e}"))?.to_bytes();
        Ok((status, body))
    }

    /// GET whose answer must be 200 and short UTF-8 text, returned trimmed.
    pub async fn get_text(&mut self, path: &str) -> Result<String, String> {
        let (status, body) = self.get(path, 4096).await?;
        let text = String::from_utf8_lossy(&body).trim().to_string();
        if status != StatusCode::OK {
            return Err(format!("{path}: HTTP {} {}", status.as_u16(), text.chars().take(80).collect::<String>()));
        }
        Ok(text)
    }
}

/// One GET of a whole URL, as a peer list update is fetched.
pub async fn fetch(url: &str, route: Route, proxy: Option<&ProxyAddr>, iso: &Isolation, limit: usize) -> Result<Bytes, String> {
    let mut c = Conn::open(url, None, route, proxy, iso, None).await.map_err(|(e, _)| e)?;
    let (status, body) = c.get("", limit).await?;
    if status != StatusCode::OK {
        return Err(format!("{url}: HTTP {}", status.as_u16()));
    }
    Ok(body)
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
    async fn get_sends_a_generic_request() {
        let (url, server) = serve_once("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n970838").await;
        let mut c = Conn::open(&url, Some(("me", "pw")), Route::Direct, None, &Isolation::fresh(), None).await.unwrap();
        assert_eq!(c.get_text("/blocks/tip/height").await.unwrap(), "970838");
        let asked = server.await.unwrap().to_ascii_lowercase();
        assert!(asked.starts_with("get /api/blocks/tip/height http/1.1\r\n"), "{asked}");
        assert!(asked.contains("user-agent: mozilla/5.0\r\n") && asked.contains("authorization: basic bwu6chc=\r\n"), "{asked}");
        assert!(!asked.contains('@'), "{asked}");
    }

    #[tokio::test]
    async fn errors_and_limits() {
        let (url, _s) = serve_once("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found").await;
        let mut c = Conn::open(&url, None, Route::Direct, None, &Isolation::fresh(), None).await.unwrap();
        assert!(c.get_text("/x").await.unwrap_err().contains("HTTP 404"));
        let (url, _s) = serve_once("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789").await;
        let mut c = Conn::open(&url, None, Route::Direct, None, &Isolation::fresh(), None).await.unwrap();
        assert!(c.get("", 4).await.is_err(), "over the limit");
    }
}
