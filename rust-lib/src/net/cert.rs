//! A server certificate as a probe shows it: its SHA-256 over the end-entity DER, which is what a
//! pin holds (the wallet core's `pin::certificate_sha256` computes the same), plus the subject,
//! issuer and validity dates for "Trust this certificate?". Read from the DER directly, like the
//! core's, since webpki refuses version 1 certificates.

use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertInfo {
    pub cert_sha256: String,
    pub subject: String,
    pub issuer: String,
    /// RFC 3339, UTC; absent when the certificate's time cannot be read.
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    /// It passed the check that applies: the source's pin, or the web PKI roots and its name.
    pub trusted: bool,
}

pub fn sha256_hex(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

/// One DER element: its tag, its contents and what follows it.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let first = *b.get(1)? as usize;
    let (len, header) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    (end <= b.len()).then(|| (tag, &b[header..end], &b[end..]))
}

/// tbsCertificate's issuer, validity and subject, and what follows them (the key first).
struct Tbs<'a> {
    issuer: &'a [u8],
    validity: &'a [u8],
    subject: &'a [u8],
    rest: &'a [u8],
}

fn fields(cert: &[u8]) -> Option<Tbs<'_>> {
    let (tag, certificate, _) = tlv(cert)?;
    let (tbs_tag, tbs, _) = tlv(certificate)?;
    if tag != 0x30 || tbs_tag != 0x30 {
        return None;
    }
    let mut rest = tbs;
    // The explicit [0] version is absent in version 1.
    if rest.first() == Some(&0xa0) {
        rest = tlv(rest)?.2;
    }
    // serialNumber, signature.
    rest = tlv(rest)?.2;
    rest = tlv(rest)?.2;
    let (it, issuer, rest) = tlv(rest)?;
    let (vt, validity, rest) = tlv(rest)?;
    let (st, subject, rest) = tlv(rest)?;
    (it == 0x30 && vt == 0x30 && st == 0x30).then_some(Tbs { issuer, validity, subject, rest })
}

/// The SubjectPublicKeyInfo element, version 1 or 3.
pub fn spki_of(cert: &[u8]) -> Option<&[u8]> {
    let rest = fields(cert)?.rest;
    let (tag, _, after) = tlv(rest)?;
    (tag == 0x30).then(|| &rest[..rest.len() - after.len()])
}

fn oid(b: &[u8]) -> String {
    let (mut arcs, mut v) = (Vec::new(), 0u64);
    for &x in b.iter().take(32) {
        v = (v << 7) | u64::from(x & 0x7f);
        if x & 0x80 == 0 {
            if arcs.is_empty() {
                let first = (v / 40).min(2);
                arcs.extend([first, v - 40 * first]);
            } else {
                arcs.push(v);
            }
            v = 0;
        }
    }
    arcs.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
}

fn attribute(oid: &str) -> String {
    let short = match oid {
        "2.5.4.3" => "CN",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "1.2.840.113549.1.9.1" => "emailAddress",
        "0.9.2342.19200300.100.1.25" => "DC",
        other => other,
    };
    short.to_string()
}

/// A directory string as text: control characters replaced, at most 256 characters.
fn text(tag: u8, b: &[u8]) -> String {
    let s: String = match tag {
        // UTF8String, NumericString, PrintableString, IA5String, VisibleString.
        0x0c | 0x12 | 0x13 | 0x16 | 0x1a => String::from_utf8_lossy(b).into_owned(),
        // TeletexString, read as Latin-1.
        0x14 => b.iter().map(|&c| char::from(c)).collect(),
        // BMPString (UTF-16BE) and UniversalString (UTF-32BE).
        0x1e => String::from_utf16_lossy(&b.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect::<Vec<_>>()),
        0x1c => b.chunks_exact(4).map(|c| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]])).unwrap_or('\u{fffd}')).collect(),
        _ => format!("#{}", hex::encode(b)),
    };
    s.chars().map(|c| if c.is_control() { '\u{fffd}' } else { c }).take(256).collect()
}

/// A Name as `CN=..., O=...`, in the certificate's order.
fn name(b: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut rdns = b;
    while let Some((0x31, set, rest)) = tlv(rdns) {
        rdns = rest;
        let mut atvs = set;
        while let Some((0x30, atv, rest)) = tlv(atvs) {
            atvs = rest;
            if let Some((0x06, id, after)) = tlv(atv) {
                if let Some((tag, value, _)) = tlv(after) {
                    parts.push(format!("{}={}", attribute(&oid(id)), text(tag, value)));
                }
            }
        }
        if parts.len() >= 16 {
            break;
        }
    }
    parts.join(", ")
}

/// UTCTime or GeneralizedTime, Zulu with seconds (RFC 5280), as RFC 3339.
fn time(tag: u8, b: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(b).ok()?.strip_suffix('Z')?;
    let (year, rest) = match (tag, s.len()) {
        (0x17, 12) => {
            let yy: u32 = s[..2].parse().ok()?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, &s[2..])
        }
        (0x18, 14) => (s[..4].parse().ok()?, &s[4..]),
        _ => return None,
    };
    if !rest.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(format!("{year:04}-{}-{}T{}:{}:{}Z", &rest[0..2], &rest[2..4], &rest[4..6], &rest[6..8], &rest[8..10]))
}

/// What the app shows before the person pins `der`.
pub fn info(der: &[u8], trusted: bool) -> CertInfo {
    let mut c = CertInfo { cert_sha256: sha256_hex(der), subject: String::new(), issuer: String::new(), not_before: None, not_after: None, trusted };
    if let Some(t) = fields(der) {
        c.issuer = name(t.issuer);
        c.subject = name(t.subject);
        if let Some((t1, v1, rest)) = tlv(t.validity) {
            c.not_before = time(t1, v1);
            c.not_after = tlv(rest).and_then(|(t2, v2, _)| time(t2, v2));
        }
    }
    c
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The wallet core's own fixtures (its tests/data/pin), copied unchanged.
    pub const V3: &[u8] = include_bytes!("../../tests/data/pin/v3.der");
    pub const V3_KEY: &[u8] = include_bytes!("../../tests/data/pin/v3.key.der");
    pub const V1: &[u8] = include_bytes!("../../tests/data/pin/v1.der");
    pub const V1_KEY: &[u8] = include_bytes!("../../tests/data/pin/v1.key.der");
    pub const RSA: &[u8] = include_bytes!("../../tests/data/pin/rsa.der");
    pub const RSA_KEY: &[u8] = include_bytes!("../../tests/data/pin/rsa.key.der");

    #[test]
    fn reads_subject_issuer_and_dates() {
        // As `openssl x509 -subject -issuer -dates` prints them for the same files.
        for (der, cn, from, to) in [
            (V3, "CN=electrum.test", "2026-10-11T01:43:03Z", "2126-09-17T01:43:03Z"),
            (V1, "CN=old-electrum", "2026-10-11T01:43:21Z", "2126-09-17T01:43:21Z"),
            (RSA, "CN=rsa-electrum", "2026-10-11T01:43:03Z", "2126-09-17T01:43:03Z"),
        ] {
            let c = info(der, false);
            assert_eq!((c.subject.as_str(), c.issuer.as_str()), (cn, cn));
            assert_eq!((c.not_before.as_deref(), c.not_after.as_deref()), (Some(from), Some(to)), "UTCTime, then GeneralizedTime past 2049");
            assert_eq!(c.cert_sha256, sha256_hex(der));
            assert!(spki_of(der).is_some_and(|k| k[0] == 0x30));
        }
        let broken = info(&V3[..40], true);
        assert!(broken.subject.is_empty() && broken.not_after.is_none() && broken.trusted);
        assert_eq!(spki_of(b"\x02\x01\x00"), None);
    }

    #[test]
    fn names_with_several_attributes() {
        // SEQUENCE { SET { C=US } SET { O=Ex, BMPString } SET { CN=a\nb } }
        let mut n = vec![0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, b'U', b'S'];
        n.extend([0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x1e, 0x04, 0x00, b'E', 0x00, b'x']);
        n.extend([0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x03, b'a', b'\n', b'b']);
        assert_eq!(name(&n), "C=US, O=Ex, CN=a\u{fffd}b");
        assert_eq!(oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01]), "1.2.840.113549.1.9.1");
        assert_eq!(time(0x17, b"991231235959Z").as_deref(), Some("1999-12-31T23:59:59Z"));
        assert_eq!(time(0x17, b"9912312359Z"), None, "seconds are required");
    }
}
