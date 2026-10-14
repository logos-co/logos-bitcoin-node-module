//! Address-free Bitcoin Core RPC capability probe, on the configured TLS/Tor route.
use super::{
    cert::CertInfo,
    client::Route,
    http::Conn,
    socks::{Isolation, ProxyAddr},
};
use crate::health::Observed;
use serde_json::{json, Value};
use std::time::Instant;

fn result(v: Value) -> Result<Value, String> {
    if !v["error"].is_null() {
        return Err(format!("RPC error {}", v["error"]["code"]));
    }
    v.get("result")
        .cloned()
        .ok_or_else(|| "RPC result missing".into())
}

pub async fn probe(
    url: &str,
    creds: Option<(&str, &str)>,
    route: Route,
    proxy: Option<&ProxyAddr>,
    iso: &Isolation,
    pin: Option<[u8; 32]>,
) -> (Result<Observed, String>, Option<CertInfo>) {
    let mut c = match Conn::open(url, creds, route, proxy, iso, pin).await {
        Ok(c) => c,
        Err(e) => return (Err(e.0), e.1),
    };
    let cert = c.cert.clone();
    let ask = async {
        let started = Instant::now();
        let info = result(c.rpc("getblockchaininfo", json!([])).await?)?;
        let rtt_ms = started.elapsed().as_millis() as u64;
        let tip_height = info["blocks"]
            .as_u64()
            .and_then(|h| u32::try_from(h).ok())
            .ok_or("RPC returned an invalid height")?;
        let tip_hash = info["bestblockhash"]
            .as_str()
            .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or("RPC returned an invalid tip hash")?
            .to_string();
        let genesis = result(c.rpc("getblockhash", json!([0])).await?)?
            .as_str()
            .ok_or("RPC returned no genesis hash")?
            .to_string();
        let filters = c.rpc("getblockfilter", json!([tip_hash])).await?;
        let mode = if filters["result"]["filter"].is_string() {
            "Block filters available"
        } else if filters["error"]["code"] == -32601
            || filters["error"]["message"]
                .as_str()
                .is_some_and(|s| s.contains("not enabled"))
        {
            "Full-block scan (no filters; restores are slower)"
        } else {
            return Err(
                "RPC block filters are not ready; try again after the node finishes indexing"
                    .into(),
            );
        };
        Ok(Observed {
            genesis: Some(genesis),
            tip_height: u64::from(tip_height),
            tip_hash,
            rtt_ms,
            server_version: Some(mode.into()),
        })
    }
    .await;
    (ask, cert)
}
