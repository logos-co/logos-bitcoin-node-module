//! socks5h to Tor: names resolve at the proxy, and the SOCKS credentials choose the Tor
//! circuit (IsolateSOCKSAuth).

use rand::RngExt;
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

/// The proxy URL scheme we accept. Plain socks5 resolves names locally and http
/// proxies cannot isolate circuits, so both are refused.
pub const SCHEME: &str = "socks5h://";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyAddr {
    pub host: String,
    pub port: u16,
}

impl ProxyAddr {
    pub fn parse(url: &str) -> Result<Self, String> {
        let rest = url
            .strip_prefix(SCHEME)
            .ok_or_else(|| format!("proxy must be {SCHEME}host:port"))?;
        let rest = rest.trim_end_matches('/');
        let (host, port) = rest
            .rsplit_once(':')
            .ok_or_else(|| "proxy needs a port".to_string())?;
        let port = port.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| "bad proxy port".to_string())?;
        if host.is_empty() {
            return Err("proxy needs a host".into());
        }
        Ok(Self { host: host.trim_matches(['[', ']']).to_string(), port })
    }
}

/// SOCKS username and password. Tor never lets streams with different
/// credentials share a circuit.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Isolation {
    user: String,
    pass: String,
}

impl Isolation {
    /// A circuit no other request will use.
    pub fn fresh() -> Self {
        let mut bytes = [0u8; 24];
        rand::rng().fill(&mut bytes[..]);
        // Hex never starts with "<", so arti's "<torS0X>" handling cannot trigger.
        Self { user: hex::encode(&bytes[..12]), pass: hex::encode(&bytes[12..]) }
    }
}

/// Opens a stream to `host:port` through the proxy, on the circuit `iso` names.
pub async fn connect(proxy: &ProxyAddr, host: &str, port: u16, iso: &Isolation) -> Result<Socks5Stream<TcpStream>, String> {
    let s = Socks5Stream::connect_with_password((proxy.host.as_str(), proxy.port), (host, port), &iso.user, &iso.pass)
        .await
        .map_err(|e| format!("through the proxy {}:{}: {e}", proxy.host, proxy.port))?;
    let _ = s.set_nodelay(true);
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_urls() {
        assert_eq!(
            ProxyAddr::parse("socks5h://127.0.0.1:9050").unwrap(),
            ProxyAddr { host: "127.0.0.1".into(), port: 9050 }
        );
        assert_eq!(ProxyAddr::parse("socks5h://[::1]:9050").unwrap().host, "::1");
        assert!(ProxyAddr::parse("socks5://127.0.0.1:9050").is_err());
        assert!(ProxyAddr::parse("http://127.0.0.1:8118").is_err());
        assert!(ProxyAddr::parse("socks5h://127.0.0.1").is_err());
        assert!(ProxyAddr::parse("socks5h://127.0.0.1:0").is_err());
    }

    #[test]
    fn fresh_isolation_differs() {
        let (a, b) = (Isolation::fresh(), Isolation::fresh());
        assert_ne!(a.user, b.user);
        assert_eq!(a.user.len(), 24);
    }

    /// A fake SOCKS5 server sees the target as a name, with the circuit's credentials.
    #[tokio::test]
    async fn names_resolve_at_the_proxy() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = ProxyAddr { host: "127.0.0.1".into(), port: listener.local_addr().unwrap().port() };
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut greet = [0u8; 4];
            s.read_exact(&mut greet).await.unwrap();
            assert_eq!(greet, [5, 2, 0, 2], "no auth, or username/password");
            s.write_all(&[5, 2]).await.unwrap();
            let mut head = [0u8; 2];
            s.read_exact(&mut head).await.unwrap();
            let mut user = vec![0u8; head[1] as usize];
            s.read_exact(&mut user).await.unwrap();
            let mut plen = [0u8; 1];
            s.read_exact(&mut plen).await.unwrap();
            let mut pass = vec![0u8; plen[0] as usize];
            s.read_exact(&mut pass).await.unwrap();
            s.write_all(&[1, 0]).await.unwrap();
            let mut req = [0u8; 5];
            s.read_exact(&mut req).await.unwrap();
            assert_eq!(&req[..4], &[5, 1, 0, 3], "CONNECT to a domain name");
            let mut name = vec![0u8; req[4] as usize + 2];
            s.read_exact(&mut name).await.unwrap();
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
            (String::from_utf8(user).unwrap(), String::from_utf8(name[..name.len() - 2].to_vec()).unwrap())
        });
        let iso = Isolation::fresh();
        connect(&proxy, "mempool.space", 443, &iso).await.unwrap();
        let (user, name) = server.await.unwrap();
        assert_eq!((user, name.as_str()), (iso.user.clone(), "mempool.space"));
    }
}
