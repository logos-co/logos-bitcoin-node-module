//! The proxy: Tor's SOCKS port, one for every source, socks5h only (socks5 resolves names
//! locally; http proxies cannot isolate circuits). Without one, Tor routes have no route.

use crate::net::socks::ProxyAddr;

pub const DEFAULT_PROXY: &str = "socks5h://127.0.0.1:9050";

/// set_proxy's argument: an empty string clears the proxy.
pub fn parse_setting(s: &str) -> Result<Option<String>, String> {
    match s.trim() {
        "" => Ok(None),
        url => normalize(url).map(Some),
    }
}

/// Normalizes a proxy URL to `socks5h://host:port`, refusing every other scheme.
pub fn normalize(url: &str) -> Result<String, String> {
    let lower = url.trim().to_ascii_lowercase();
    if lower.starts_with("socks5://") || lower.starts_with("socks4") || lower.starts_with("socks://") {
        return Err("socks5:// resolves names locally; use socks5h://host:port".into());
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Err("http(s) proxies cannot isolate circuits; use socks5h://host:port".into());
    }
    let Some(rest) = lower.strip_prefix("socks5h://") else {
        return Err("proxy must be socks5h://host:port".into());
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.contains(['@', '/', '?', '#']) {
        return Err("proxy must be socks5h://host:port".into());
    }
    let addr = ProxyAddr::parse(&format!("socks5h://{rest}"))?;
    if addr.port == 0 || !addr.host.chars().all(|c| c.is_ascii_alphanumeric() || "-._:".contains(c)) {
        return Err("proxy must be socks5h://host:port".into());
    }
    let host = if addr.host.contains(':') { format!("[{}]", addr.host) } else { addr.host };
    Ok(format!("socks5h://{host}:{}", addr.port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_socks5h() {
        assert_eq!(normalize("socks5h://127.0.0.1:9050").unwrap(), "socks5h://127.0.0.1:9050");
        assert_eq!(normalize(" SOCKS5H://Tor.Local:9150/ ").unwrap(), "socks5h://tor.local:9150");
        assert_eq!(normalize("socks5h://[::1]:9050").unwrap(), "socks5h://[::1]:9050");
        for (url, why) in [
            ("socks5://127.0.0.1:9050", "resolves names locally"),
            ("socks4a://127.0.0.1:9050", "resolves names locally"),
            ("http://127.0.0.1:8118", "cannot isolate"),
            ("https://proxy.example:443", "cannot isolate"),
            ("tor://127.0.0.1:9050", "must be socks5h"),
            ("127.0.0.1:9050", "must be socks5h"),
            ("socks5h://127.0.0.1", "port"),
            ("socks5h://127.0.0.1:0", "port"),
            ("socks5h://127.0.0.1:99999", "port"),
            ("socks5h://user:pw@127.0.0.1:9050", "must be socks5h"),
            ("socks5h://127.0.0.1:9050/path", "must be socks5h"),
            ("socks5h://:9050", "host"),
        ] {
            let e = normalize(url).unwrap_err();
            assert!(e.contains(why), "{url}: {e}");
        }
    }

    #[test]
    fn empty_clears() {
        assert_eq!(parse_setting("  ").unwrap(), None);
        assert_eq!(parse_setting("socks5h://127.0.0.1:19050").unwrap().as_deref(), Some("socks5h://127.0.0.1:19050"));
        assert!(parse_setting("direct").is_err());
    }
}
