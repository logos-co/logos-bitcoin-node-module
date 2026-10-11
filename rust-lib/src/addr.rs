//! Source addresses: splitting and normalizing what the user typed, and the operator a host
//! counts as.

use std::net::{IpAddr, Ipv6Addr};

use crate::net::client::{is_lan_host, is_onion};
use crate::reply::INVALID;

/// `scheme://[user[:password]@]host[:port][/path]`, host lowercase and without brackets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parts {
    pub scheme: String,
    pub user: Option<String>,
    pub password: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    /// Empty, or starting with '/', without a trailing '/'.
    pub path: String,
}

fn bad(url: &str) -> String {
    format!("{url}: not a server address")
}

/// Splits a URL. A query or fragment is refused: sources are base URLs.
pub fn split(url: &str) -> Result<Parts, String> {
    let url = url.trim();
    let (scheme, rest) = url.split_once("://").ok_or_else(|| bad(url))?;
    if scheme.is_empty() || !scheme.chars().all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c)) {
        return Err(bad(url));
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if tail.contains(['?', '#']) {
        return Err(format!("{url}: a server address has no query or fragment"));
    }
    if !tail.chars().all(|c| c.is_ascii_graphic()) {
        return Err(bad(url));
    }
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };
    let (user, password) = match userinfo {
        None => (None, None),
        Some(u) => match u.split_once(':') {
            Some((name, pw)) => (Some(decode(name)?), Some(decode(pw)?)),
            None => (Some(decode(u)?), None),
        },
    };
    let (host, port) = if let Some(inner) = hostport.strip_prefix('[') {
        let (h, after) = inner.split_once(']').ok_or_else(|| bad(url))?;
        h.parse::<Ipv6Addr>().map_err(|_| bad(url))?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or_else(|| bad(url))?),
        };
        (h.to_ascii_lowercase(), port)
    } else {
        match hostport.split_once(':') {
            Some((h, p)) if !p.contains(':') => (h.to_ascii_lowercase(), Some(p)),
            Some(_) => return Err(format!("{url}: write an IPv6 address in brackets, [::1]:port")),
            None => (hostport.to_ascii_lowercase(), None),
        }
    };
    let host = host.trim_end_matches('.').to_string();
    if !host_ok(&host) {
        return Err(bad(url));
    }
    let port = match port {
        None => None,
        Some(p) => Some(p.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| format!("{url}: bad port"))?),
    };
    let path = tail.trim_end_matches('/').to_string();
    Ok(Parts { scheme: scheme.to_ascii_lowercase(), user, password, host, port, path })
}

/// An IPv6 address, or a name or IPv4 address of letters, digits, '-' and '.'.
pub fn host_ok(host: &str) -> bool {
    if host.contains(':') {
        return host.parse::<Ipv6Addr>().is_ok();
    }
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-'))
        && host.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
}

/// The host as it goes in a URL: IPv6 in brackets.
pub fn fmt_host(host: &str) -> String {
    if host.contains(':') { format!("[{host}]") } else { host.to_string() }
}

fn decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3).ok_or("bad %-escape in the credentials")?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| "bad %-escape in the credentials")?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "credentials must be UTF-8".into())
}

/// Adds the scheme a bare `host[:port][/path]` takes: `plain` for onion services and the
/// user's network, which Tor or the LAN already protect, `secure` for the rest.
fn with_scheme(url: &str, plain: &str, secure: &str) -> String {
    let url = url.trim();
    if url.contains("://") {
        return url.to_string();
    }
    let host = split(&format!("{plain}://{url}")).map(|p| p.host).unwrap_or_default();
    let scheme = if is_onion(&host) || is_lan_host(&host) { plain } else { secure };
    format!("{scheme}://{url}")
}

fn v3_only(p: &Parts, url: &str) -> Result<(), String> {
    if p.host.ends_with(".onion") && !is_onion(&p.host) {
        return Err(format!("{url}: only v3 onion services (56 characters) are supported"));
    }
    Ok(())
}

pub const ELECTRUM_TLS_PORT: u16 = 50002;
pub const ELECTRUM_TCP_PORT: u16 = 50001;

/// `ssl://host:port`, port 50002 when absent, or `tcp://host:port` (port 50001) for onion
/// services and the user's network. A bare host takes tcp when it is one of those, else ssl.
pub fn electrum(url: &str) -> Result<String, String> {
    let full = with_scheme(url, "tcp", "ssl");
    let p = split(&full)?;
    v3_only(&p, url)?;
    if p.user.is_some() {
        return Err(format!("{url}: an Electrum server takes no credentials"));
    }
    if !p.path.is_empty() {
        return Err(format!("{url}: an Electrum address is host:port, with no path"));
    }
    let host = fmt_host(&p.host);
    match p.scheme.as_str() {
        "ssl" => Ok(format!("ssl://{host}:{}", p.port.unwrap_or(ELECTRUM_TLS_PORT))),
        "tcp" if is_onion(&p.host) || is_lan_host(&p.host) => Ok(format!("tcp://{host}:{}", p.port.unwrap_or(ELECTRUM_TCP_PORT))),
        "tcp" => Err(format!("{INVALID}{url}: plain tcp is only for onion services and servers on your network; use ssl://")),
        _ => Err(format!("{url}: an Electrum server is ssl://host:port, or tcp://host:port")),
    }
}

/// `https://host[:port][/path]`, or `http://` for onion services and the user's network;
/// default ports are left out. Credentials in the address come back separately.
pub fn esplora(url: &str) -> Result<(String, Option<(String, String)>), String> {
    let full = with_scheme(url, "http", "https");
    let p = split(&full)?;
    v3_only(&p, url)?;
    let creds = match (&p.user, &p.password) {
        (Some(u), _) if u.is_empty() => return Err(format!("{url}: credentials need a user name")),
        (Some(u), pw) => Some((u.clone(), pw.clone().unwrap_or_default())),
        (None, _) => None,
    };
    let default_port = match p.scheme.as_str() {
        "https" => 443,
        "http" if is_onion(&p.host) || is_lan_host(&p.host) => 80,
        "http" => return Err(format!("{INVALID}{url}: plain http is only for onion services and servers on your network; use https://")),
        _ => return Err(format!("{url}: an Esplora server is https://host[:port][/path]")),
    };
    let port = match p.port {
        Some(port) if port != default_port => format!(":{port}"),
        _ => String::new(),
    };
    Ok((format!("{}://{}{port}{}", p.scheme, fmt_host(&p.host), p.path), creds))
}

/// The host of a normalized source URL.
pub fn host_of(url: &str) -> String {
    split(url).map(|p| p.host).unwrap_or_default()
}

/// The operator a host counts as unless the user names one: `you` on your network, an onion
/// service or IP address itself, else its registered domain, so one operator's hosts count once.
pub fn site(host: &str) -> String {
    if is_lan_host(host) {
        return "you".into();
    }
    if is_onion(host) || host.parse::<IpAddr>().is_ok() {
        return host.to_string();
    }
    let labels: Vec<&str> = host.split('.').collect();
    let n = labels.len();
    if n <= 2 {
        return host.to_string();
    }
    // A country code's own second level (co.uk, com.au) takes one label more.
    let second_level = ["co", "com", "net", "org", "gov", "ac", "edu", "or", "ne"];
    let keep = if labels[n - 1].len() == 2 && second_level.contains(&labels[n - 2]) { 3 } else { 2 };
    labels[n - keep..].join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn onion() -> String {
        format!("{}.onion", "a2".repeat(28))
    }

    #[test]
    fn splits() {
        let p = split(" HTTPS://U%40x:p%3Aw@Mempool.Space:8443/api/ ").unwrap();
        assert_eq!(p, Parts {
            scheme: "https".into(),
            user: Some("U@x".into()),
            password: Some("p:w".into()),
            host: "mempool.space".into(),
            port: Some(8443),
            path: "/api".into(),
        });
        assert_eq!(split("tcp://[FD00::2]:50001").unwrap().host, "fd00::2");
        for bad in ["mempool.space", "https://", "https://a b", "https://x.example/api?x=1", "https://x.example#f", "tcp://fd00::2:50001", "https://x.example:0", "https://x.example:99999", "https://-x.example", "https://x..example", "https://x_y.example"] {
            assert!(split(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn electrum_addresses() {
        for (typed, url) in [
            ("electrum.blockstream.info", "ssl://electrum.blockstream.info:50002"),
            ("SSL://Electrum.Blockstream.Info:50002/", "ssl://electrum.blockstream.info:50002"),
            ("192.168.1.20", "tcp://192.168.1.20:50001"),
            ("192.168.1.20:50002", "tcp://192.168.1.20:50002"),
            ("ssl://192.168.1.20", "ssl://192.168.1.20:50002"),
            ("electrs.lan", "tcp://electrs.lan:50001"),
            ("[fd00::2]:60001", "tcp://[fd00::2]:60001"),
        ] {
            assert_eq!(electrum(typed).unwrap(), url, "{typed}");
        }
        assert_eq!(electrum(&format!("{}:110", onion())).unwrap(), format!("tcp://{}:110", onion()));
        assert_eq!(electrum(&format!("tcp://{}", onion())).unwrap(), format!("tcp://{}:50001", onion()));
        for (typed, why) in [
            ("tcp://electrum.example:50001", "plain tcp"),
            ("http://electrum.example", "ssl://host:port"),
            ("ssl://u:p@electrum.example", "no credentials"),
            ("ssl://electrum.example/x", "no path"),
            ("tcp://expyuzz4wqqyqhjn.onion:50001", "v3"),
        ] {
            let e = electrum(typed).unwrap_err();
            assert!(e.contains(why), "{typed}: {e}");
        }
    }

    #[test]
    fn esplora_addresses() {
        for (typed, url) in [
            ("https://mempool.space/api/", "https://mempool.space/api"),
            ("mempool.space/testnet4/api", "https://mempool.space/testnet4/api"),
            ("https://blockstream.info:443/signet/api", "https://blockstream.info/signet/api"),
            ("https://esplora.example:8443", "https://esplora.example:8443"),
            ("192.168.1.20:3002/api", "http://192.168.1.20:3002/api"),
            ("http://umbrel.local", "http://umbrel.local"),
        ] {
            let (u, creds) = esplora(typed).unwrap();
            assert_eq!((u.as_str(), creds), (url, None), "{typed}");
        }
        let (u, creds) = esplora(&format!("{}/api", onion())).unwrap();
        assert_eq!((u, creds), (format!("http://{}/api", onion()), None));
        let (u, creds) = esplora("https://me:s3cret@esplora.example/api").unwrap();
        assert_eq!((u.as_str(), creds), ("https://esplora.example/api", Some(("me".into(), "s3cret".into()))));
        for (typed, why) in [
            ("http://mempool.space/api", "plain http"),
            ("ftp://x.example", "https://host"),
            ("https://:pw@x.example", "user name"),
            ("http://expyuzz4wqqyqhjn.onion/api", "v3"),
        ] {
            let e = esplora(typed).unwrap_err();
            assert!(e.contains(why), "{typed}: {e}");
        }
    }

    #[test]
    fn operators() {
        assert_eq!(site("electrum.blockstream.info"), "blockstream.info");
        assert_eq!(site("mempool.space"), "mempool.space");
        assert_eq!(site("node.example.co.uk"), "example.co.uk");
        assert_eq!(site("203.0.113.5"), "203.0.113.5");
        assert_eq!(site(&onion()), onion());
        for lan in ["192.168.1.20", "umbrel.local", "fd00::2"] {
            assert_eq!(site(lan), "you", "{lan}");
        }
    }
}
