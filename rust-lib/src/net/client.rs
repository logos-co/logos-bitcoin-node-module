//! Opening connections: every socket this crate opens goes through `dial`, which takes the
//! source's route and never falls back to another one.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use tokio_rustls::rustls::{self, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio_rustls::TlsConnector;

use super::cert::{self, CertInfo};
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
    #[error("TLS with {0}: the certificate is not trusted: {1}")]
    Untrusted(String, String),
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

fn provider() -> Arc<CryptoProvider> {
    static P: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    P.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider())).clone()
}

fn webpki() -> Result<Arc<WebPkiServerVerifier>, String> {
    static V: OnceLock<Result<Arc<WebPkiServerVerifier>, String>> = OnceLock::new();
    V.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider()).build().map_err(|e| e.to_string())
    })
    .clone()
}

/// Judges a server's certificate by the source's pin (its SHA-256, in place of the CAs and the
/// name, as the wallet core pins) or, without one, by the web PKI. The verdict is applied once
/// the handshake signature, checked with that certificate's own key, shows the server holds it,
/// so a probe can offer an untrusted certificate for pinning; nothing is sent on a refused session.
/// The end-entity certificate's DER and the verdict on it.
type Seen = Option<(Vec<u8>, Result<(), String>)>;

#[derive(Debug)]
struct Judge {
    pin: Option<[u8; 32]>,
    webpki: Arc<WebPkiServerVerifier>,
    provider: Arc<CryptoProvider>,
    seen: Mutex<Seen>,
}

impl ServerCertVerifier for Judge {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], name: &ServerName<'_>, ocsp: &[u8], now: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        let verdict = match self.pin {
            Some(pin) if Sha256::digest(end_entity.as_ref())[..] == pin[..] => Ok(()),
            Some(_) => Err("the server's certificate is not the pinned one".to_string()),
            None => self.webpki.verify_server_cert(end_entity, intermediates, name, ocsp, now).map(|_| ()).map_err(|e| e.to_string()),
        };
        *self.seen.lock().unwrap_or_else(|e| e.into_inner()) = Some((end_entity.to_vec(), verdict));
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify(message, cert, dss, &self.provider, false)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        if !tls13_scheme(dss.scheme) {
            return Err(rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into());
        }
        verify(message, cert, dss, &self.provider, true)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// The schemes TLS 1.3 signs handshakes with (RFC 8446, 4.2.3).
fn tls13_scheme(s: SignatureScheme) -> bool {
    use SignatureScheme::*;
    matches!(s, ECDSA_NISTP256_SHA256 | ECDSA_NISTP384_SHA384 | ECDSA_NISTP521_SHA512 | RSA_PSS_SHA256 | RSA_PSS_SHA384 | RSA_PSS_SHA512 | ED25519 | ED448)
}

/// The handshake signature, checked with the certificate's own key read from its DER.
fn verify(message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct, provider: &CryptoProvider, tls13: bool) -> Result<HandshakeSignatureValid, rustls::Error> {
    let general = |why: String| rustls::Error::General(why);
    let spki = SubjectPublicKeyInfoDer::from(cert::spki_of(cert.as_ref()).ok_or_else(|| general("the certificate has no readable public key".into()))?);
    let key = webpki::RawPublicKeyEntity::try_from(&spki).map_err(|e| general(format!("the certificate's public key: {e}")))?;
    let algs = provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .find(|(scheme, _)| *scheme == dss.scheme)
        .map(|(_, algs)| *algs)
        .ok_or(rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme)?;
    // TLS 1.3 names one algorithm per scheme; TLS 1.2 may need each candidate tried.
    let tried = if tls13 { &algs[..algs.len().min(1)] } else { algs };
    if tried.iter().any(|alg| key.verify_signature(*alg, message, dss.signature()).is_ok()) {
        Ok(HandshakeSignatureValid::assertion())
    } else {
        Err(rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature))
    }
}

/// A TLS failure, with the certificate when the server proved it holds its key.
#[derive(Debug)]
pub struct TlsFailure {
    pub error: NetError,
    pub cert: Option<CertInfo>,
}

/// Wraps `stream` in TLS for `host`: pinned when `pin` is set, else checked against the web PKI
/// roots. `http` asks for HTTP/1.1 by ALPN; Electrum servers get none.
pub async fn tls(stream: Stream, host: &str, http: bool, pin: Option<[u8; 32]>) -> Result<(Stream, CertInfo), TlsFailure> {
    let bare = host.trim_start_matches('[').trim_end_matches(']').to_string();
    let fail = |e: String| TlsFailure { error: NetError::Tls(bare.clone(), e), cert: None };
    let name = ServerName::try_from(bare.clone()).map_err(|e| fail(e.to_string()))?;
    let judge = Arc::new(Judge { pin, webpki: webpki().map_err(fail)?, provider: provider(), seen: Mutex::new(None) });
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| fail(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(judge.clone())
        .with_no_client_auth();
    if http {
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    }
    let s = TlsConnector::from(Arc::new(cfg)).connect(name, stream).await.map_err(|e| fail(e.to_string()))?;
    let seen = judge.seen.lock().unwrap_or_else(|e| e.into_inner()).take();
    let (der, verdict) = seen.ok_or_else(|| fail("the server presented no certificate".into()))?;
    let info = cert::info(&der, verdict.is_ok());
    match verdict {
        Ok(()) => Ok((Box::new(s), info)),
        Err(why) => Err(TlsFailure { error: NetError::Untrusted(bare, why), cert: Some(info) }),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::time::Duration;
    use crate::net::cert::tests::{RSA, RSA_KEY, V1, V1_KEY, V3, V3_KEY};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio_rustls::rustls::pki_types::PrivateKeyDer;

    /// What the wallet core's `pin::certificate_sha256` returns for the same fixtures, run at its
    /// commit 0eb9c5c against a server presenting each (v1: its own test that the pin a probe
    /// reads is the certificate's SHA-256).
    pub const CORE_PINS: [(&[u8], &str); 3] = [
        (V3, "ddba707608ce56cf9d36cef6896af057c4a3e8315e485483269926d8efcbc64b"),
        (RSA, "cad8a719c3b90ecb80e7d6523910999f936dce35991afac706db75bc823abda5"),
        (V1, "8c8c0fe514a15ee68bbdc0f6e06d11772fefb756cd4d58adcd2f7032fb4ce2d8"),
    ];

    /// Serves one certificate with one key, matching or not, as a misconfigured or lying server might.
    #[derive(Debug)]
    struct Fixed(Arc<rustls::sign::CertifiedKey>);

    impl rustls::server::ResolvesServerCert for Fixed {
        fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    fn electrum_reply(line: &str) -> String {
        let v: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
        let result = match v["method"].as_str() {
            Some("server.version") => serde_json::json!(["pinned 1.0", "1.4"]),
            Some("server.features") => serde_json::json!({"genesis_hash": crate::network::BNetwork::Mainnet.genesis()}),
            _ => serde_json::json!({"height": 970_838, "hex": crate::net::electrum::tests::GENESIS_HEADER}),
        };
        serde_json::json!({"jsonrpc": "2.0", "id": v["id"], "result": result}).to_string() + "\n"
    }

    fn http_reply(path: &str) -> String {
        let body = match path {
            "/api/blocks/tip/height" => "970838".to_string(),
            "/api/blocks/tip/hash" => "ab".repeat(32),
            _ => crate::network::BNetwork::Mainnet.genesis().to_string(),
        };
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len())
    }

    /// A loopback TLS server for one certificate and key, answering Electrum or HTTP GETs.
    pub async fn tls_server(cert: &'static [u8], key: &'static [u8], tls12_only: bool) -> u16 {
        let provider = provider();
        let signing = provider.key_provider.load_private_key(PrivateKeyDer::try_from(key).unwrap()).unwrap();
        let certified = rustls::sign::CertifiedKey::new(vec![CertificateDer::from(cert)], signing);
        let versions: &[&rustls::SupportedProtocolVersion] = if tls12_only { &[&rustls::version::TLS12] } else { rustls::DEFAULT_VERSIONS };
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fixed(Arc::new(certified))));
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else { return };
                    let (mut s, mut line, mut get) = (BufReader::new(tls), String::new(), None::<String>);
                    while s.read_line(&mut line).await.unwrap_or(0) > 0 {
                        let reply = if let Some(path) = line.strip_prefix("GET ").and_then(|r| r.split_whitespace().next()) {
                            get = Some(path.to_string());
                            None
                        } else if line.trim().is_empty() {
                            get.take().map(|p| http_reply(&p))
                        } else if get.is_none() {
                            Some(electrum_reply(&line))
                        } else {
                            None
                        };
                        line.clear();
                        if let Some(r) = reply {
                            if s.get_mut().write_all(r.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                    }
                });
            }
        });
        port
    }

    pub fn pin_of(cert: &[u8]) -> [u8; 32] {
        Sha256::digest(cert).into()
    }

    async fn handshake(port: u16, pin: Option<[u8; 32]>) -> Result<CertInfo, TlsFailure> {
        let stream = dial("127.0.0.1", port, Route::Direct, None, &Isolation::fresh()).await.unwrap();
        tls(stream, "127.0.0.1", false, pin).await.map(|(_, c)| c)
    }

    #[tokio::test]
    async fn a_pinned_certificate_is_accepted_and_any_other_refused() {
        for (cert, key, tls12) in [(V3, V3_KEY, false), (V1, V1_KEY, false), (RSA, RSA_KEY, true), (V1, V1_KEY, true)] {
            let port = tls_server(cert, key, tls12).await;
            let ok = handshake(port, Some(pin_of(cert))).await.unwrap_or_else(|f| panic!("tls12={tls12}: {}", f.error));
            assert!(ok.trusted && ok.cert_sha256 == hex::encode(pin_of(cert)));
            let wrong = handshake(port, Some(pin_of(V3_KEY))).await.expect_err("another pin is refused");
            assert!(matches!(&wrong.error, NetError::Untrusted(_, why) if why.contains("not the pinned one")), "{}", wrong.error);
            let shown = wrong.cert.expect("the certificate is shown, to pin anew");
            assert_eq!((shown.trusted, shown.cert_sha256), (false, hex::encode(pin_of(cert))));
        }
    }

    #[tokio::test]
    async fn without_a_pin_the_web_pki_refuses_and_the_certificate_is_offered() {
        let port = tls_server(V3, V3_KEY, false).await;
        let f = handshake(port, None).await.expect_err("a self-signed certificate is not trusted");
        assert!(f.error.to_string().contains("the certificate is not trusted"), "{}", f.error);
        let c = f.cert.expect("offered for Trust this certificate?");
        assert_eq!((c.subject.as_str(), c.issuer.as_str(), c.trusted), ("CN=electrum.test", "CN=electrum.test", false));
        assert_eq!(c.not_after.as_deref(), Some("2126-09-17T01:43:03Z"));
    }

    #[tokio::test]
    async fn a_certificate_without_its_key_is_refused() {
        // The pinned certificate served with another key: the handshake signature gives it away,
        // and nothing is offered, since the server did not prove it holds the key.
        for tls12 in [false, true] {
            let port = tls_server(V3, V1_KEY, tls12).await;
            let f = handshake(port, Some(pin_of(V3))).await.expect_err("refused");
            assert!(matches!(f.error, NetError::Tls(..)) && f.error.to_string().to_lowercase().contains("signature"), "tls12={tls12}: {}", f.error);
            assert!(f.cert.is_none());
        }
    }

    #[tokio::test]
    async fn the_sha256_agrees_with_the_wallet_core() {
        for (cert, core) in CORE_PINS {
            let key = if cert == V3 { V3_KEY } else if cert == RSA { RSA_KEY } else { V1_KEY };
            let port = tls_server(cert, key, cert == RSA).await;
            let offered = handshake(port, None).await.err().and_then(|f| f.cert).expect("a certificate");
            assert_eq!(offered.cert_sha256, core);
            assert_eq!(cert::sha256_hex(cert), core);
            assert!(handshake(port, crate::sources::pin_bytes(core)).await.is_ok(), "the core's pin opens it here too");
        }
    }

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
