//! u64 values cross as decimal strings, so no JSON reader rounds them.

use serde::{Deserialize, Deserializer, Serializer};

/// Digits only: no sign, no spaces, no leading '+'.
pub fn parse(t: &str) -> Option<u64> {
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    t.parse().ok()
}

pub fn ser<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&v.to_string())
}

pub fn de<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let t = String::deserialize(d)?;
    parse(&t).ok_or_else(|| serde::de::Error::custom(format!("not a decimal u64: {t:?}")))
}

pub fn ser_opt<S: Serializer>(v: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(v) => s.serialize_some(&v.to_string()),
        None => s.serialize_none(),
    }
}

pub fn de_opt<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    match Option::<String>::deserialize(d)? {
        None => Ok(None),
        Some(t) => parse(&t).map(Some).ok_or_else(|| serde::de::Error::custom(format!("not a decimal u64: {t:?}"))),
    }
}

pub fn ser_vec<S: Serializer>(v: &[u64], s: S) -> Result<S::Ok, S::Error> {
    s.collect_seq(v.iter().map(u64::to_string))
}

pub fn de_vec<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u64>, D::Error> {
    Vec::<String>::deserialize(d)?.iter().map(|t| parse(t).ok_or_else(|| serde::de::Error::custom(format!("not a decimal u64: {t:?}")))).collect()
}

/// Missing stays `None`, `null` becomes `Some(None)`: "never set" differs from "cleared".
pub fn double_option<'de, T: Deserialize<'de>, D: Deserializer<'de>>(d: D) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct T {
        #[serde(serialize_with = "ser", deserialize_with = "de")]
        a: u64,
        #[serde(serialize_with = "ser_opt", deserialize_with = "de_opt", default)]
        b: Option<u64>,
        #[serde(default, deserialize_with = "double_option", skip_serializing_if = "Option::is_none")]
        c: Option<Option<String>>,
    }

    #[test]
    fn strings_both_ways() {
        let t = T { a: u64::MAX, b: Some(7), c: Some(None) };
        let s = serde_json::to_string(&t).unwrap();
        assert_eq!(s, r#"{"a":"18446744073709551615","b":"7","c":null}"#);
        assert_eq!(serde_json::from_str::<T>(&s).unwrap(), t);
        let missing: T = serde_json::from_str(r#"{"a":"1"}"#).unwrap();
        assert_eq!((missing.b, missing.c), (None, None));
        for bad in [r#"{"a":1}"#, r#"{"a":"-1"}"#, r#"{"a":" 1"}"#, r#"{"a":"+1"}"#, r#"{"a":""}"#] {
            assert!(serde_json::from_str::<T>(bad).is_err(), "{bad}");
        }
        assert_eq!(parse("042"), Some(42));
    }
}
