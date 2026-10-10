//! Opening connections: every socket this crate opens goes through `dial`, which takes the
//! source's route and never falls back to another one.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use super::socks::{self, Isolation, ProxyAddr};

/// How a source is reached: through Tor to a public host, directly, or to an onion service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Route {
    Tor,
    Direct,
    Onion,
}

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("no proxy is set")]
    NoProxy,
    #[error("{0} is an onion service, which is reached through Tor only")]
    NeedsTor(String),
    #[error("{0} is on your network, which Tor cannot reach")]
    NeedsDirect(String),
    #[error("{0} does not resolve to an address on your network")]
    NotLan(String),
    #[error("connect to {0}: {1}")]
    Connect(String, String),
    #[error("TLS with {0}: {1}")]
    Tls(String, String),
}

/// A v3 onion service. Tor authenticates and encrypts it end to end, so it is reached
/// through Tor without TLS.
pub fn is_onion(host: &str) -> bool {
    host.strip_suffix(".onion")
        .is_some_and(|name| name.len() == 56 && name.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')))
}

/// An address on the user's own network, which Tor cannot reach: loopback, the private
/// IPv4 ranges, CGNAT's 100.64/10 (Tailscale), link-local, and IPv6 unique-local.
pub fn is_lan_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, ..] = ip.octets();
            ip.is_loopback() || ip.is_private() || ip.is_link_local() || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(ip) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00 || (ip.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// A LAN address, or a name only the user's network resolves: mDNS `.local`, and the `.lan`,
/// `.home.arpa` and `.internal` names home routers hand out.
pub fn is_lan_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']').trim_end_matches('.').to_ascii_lowercase();
    match host.parse::<IpAddr>() {
        Ok(ip) => is_lan_ip(ip),
        Err(_) => host == "localhost" || [".local", ".lan", ".home.arpa", ".internal"].iter().any(|s| host.len() > s.len() && host.ends_with(s)),
    }
}

/// The route a host can take at all: onion services through Tor, the user's network
/// directly, and any other host through Tor or, by the user's choice, directly.
pub fn route_for(host: &str, tor: bool) -> Route {
    if is_lan_host(host) {
        Route::Direct
    } else if is_onion(host) {
        Route::Onion
    } else if tor {
        Route::Tor
    } else {
        Route::Direct
    }
}

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type Stream = Box<dyn Io>;

/// Connects by `route`: Tor routes need the proxy and fail closed without one; a name on your
/// network must resolve only onto it, or the connection would leave it outside Tor.
pub async fn dial(host: &str, port: u16, route: Route, proxy: Option<&ProxyAddr>, iso: &Isolation) -> Result<Stream, NetError> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let target = || format!("{host}:{port}");
    match route {
        _ if is_onion(bare) && route != Route::Onion => Err(NeedsTor(target())),
        _ if is_lan_host(bare) && route != Route::Direct => Err(NeedsDirect(target())),
        Route::Onion if !is_onion(bare) => Err(Connect(target(), "not an onion service".into())),
        Route::Direct => {
            let addrs: Vec<SocketAddr> = match bare.parse::<IpAddr>() {
                Ok(ip) => vec![SocketAddr::new(ip, port)],
                Err(_) => tokio::net::lookup_host((bare, port)).await.map(Iterator::collect).unwrap_or_default(),
            };
            if is_lan_host(bare) && (addrs.is_empty() || !addrs.iter().all(|a| is_lan_ip(a.ip()))) {
                return Err(NotLan(target()));
            }
            if addrs.is_empty() {
                return Err(Connect(target(), "the name does not resolve".into()));
            }
            let s = TcpStream::connect(&addrs[..]).await.map_err(|e| Connect(target(), e.to_string()))?;
            let _ = s.set_nodelay(true);
            Ok(Box::new(s))
        }
        Route::Tor | Route::Onion => {
            let proxy = proxy.ok_or(NoProxy)?;
            let s = socks::connect(proxy, bare, port, iso).await.map_err(|e| Connect(target(), e))?;
            Ok(Box::new(s))
        }
    }
}

use NetError::{Connect, NeedsDirect, NeedsTor, NoProxy, NotLan};

fn config(alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut c = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(c)
}

/// Wraps `stream` in TLS for `host`, checked against the web PKI roots. `http` asks for
/// HTTP/1.1 by ALPN; Electrum servers get none.
pub async fn tls(stream: Stream, host: &str, http: bool) -> Result<Stream, NetError> {
    static PLAIN: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    static HTTP: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    let cfg = if http { HTTP.get_or_init(|| config(&[b"http/1.1"])) } else { PLAIN.get_or_init(|| config(&[])) };
    let bare = host.trim_start_matches('[').trim_end_matches(']').to_string();
    let name = ServerName::try_from(bare.clone()).map_err(|e| NetError::Tls(bare.clone(), e.to_string()))?;
    let s = TlsConnector::from(cfg.clone()).connect(name, stream).await.map_err(|e| NetError::Tls(bare, e.to_string()))?;
    Ok(Box::new(s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn lan_addresses() {
        for host in ["127.0.0.1", "10.0.0.5", "172.16.3.4", "172.31.255.1", "192.168.1.10", "100.64.0.1", "100.127.1.1", "169.254.1.1", "[::1]", "[fd12:3456::1]", "[fe80::1]"] {
            assert!(is_lan_host(host), "{host}");
        }
        for host in ["localhost", "nas.local", "framework.lan", "Node.LAN.", "box.home.arpa", "electrs.internal"] {
            assert!(is_lan_host(host), "{host}");
        }
        for host in ["8.8.8.8", "172.32.0.1", "100.128.0.1", "193.168.1.1", "[2001:db8::1]", "mempool.space", "lan", ".local", "local.example.com", "planet"] {
            assert!(!is_lan_host(host), "{host}");
        }
    }

    #[test]
    fn onion_names() {
        let v3 = format!("{}.onion", "a2".repeat(28));
        assert!(is_onion(&v3));
        assert!(!is_onion("expyuzz4wqqyqhjn.onion"), "a retired v2 name");
        assert!(!is_onion(&v3.to_uppercase()) && !is_onion(&format!("{}.onion", "a1".repeat(28))));
    }

    #[test]
    fn routes_per_host() {
        let onion = format!("{}.onion", "a2".repeat(28));
        for tor in [true, false] {
            assert_eq!(route_for("192.168.1.20", tor), Route::Direct);
            assert_eq!(route_for("umbrel.local", tor), Route::Direct);
            assert_eq!(route_for(&onion, tor), Route::Onion);
        }
        assert_eq!(route_for("mempool.space", true), Route::Tor);
        assert_eq!(route_for("mempool.space", false), Route::Direct);
    }

    #[tokio::test]
    async fn refused_before_anything_is_dialled() {
        let tor = ProxyAddr::parse("socks5h://127.0.0.1:9").unwrap();
        let iso = Isolation::fresh();
        let onion = format!("{}.onion", "a2".repeat(28));
        assert!(matches!(dial(&onion, 80, Route::Direct, None, &iso).await, Err(NeedsTor(_))));
        assert!(matches!(dial(&onion, 80, Route::Tor, Some(&tor), &iso).await, Err(NeedsTor(_))));
        assert!(matches!(dial(&onion, 80, Route::Onion, None, &iso).await, Err(NoProxy)));
        assert!(matches!(dial("192.168.1.20", 50001, Route::Tor, Some(&tor), &iso).await, Err(NeedsDirect(_))));
        assert!(matches!(dial("mempool.space", 443, Route::Tor, None, &iso).await, Err(NoProxy)));
        assert!(matches!(dial("mempool.space", 443, Route::Onion, Some(&tor), &iso).await, Err(Connect(..))));
        let name = "this-name-does-not-exist.home.arpa";
        assert!(matches!(dial(name, 50001, Route::Direct, Some(&tor), &iso).await, Err(NotLan(_))));
    }

    #[tokio::test]
    async fn a_lan_host_is_dialled_directly_even_with_a_proxy() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Through this proxy, which nothing listens on, the listener would never hear a thing.
        let dead = ProxyAddr::parse("socks5h://127.0.0.1:9").unwrap();
        let dialled = tokio::spawn(async move { dial("127.0.0.1", port, Route::Direct, Some(&dead), &Isolation::fresh()).await.map(|_| ()) });
        let accepted = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await;
        assert!(accepted.is_ok_and(|a| a.is_ok()), "dialled directly");
        assert!(dialled.await.unwrap().is_ok());
    }
}
