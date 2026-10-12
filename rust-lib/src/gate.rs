//! Who may call what: reads are open, changes take the wallet backend, routes and mismatch
//! reports also the wallet core, credentials and Kyoto's peer reports the wallet core only.
//! callers.json widens it.

use serde::Deserialize;

pub const BACKEND: &str = "bitcoin_wallet_backend";
pub const CORE: &str = "bitcoin_wallet_core_module";

/// What a method requires of its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Open,
    Backend,
    BackendOrCore,
    Core,
}

/// The caller as the host reported it, mirrored so this file needs no SDK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    Unknown,
    Host,
    Module(String),
    Other,
}

/// Callers admitted beyond the defaults, to every gated method.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Callers {
    #[serde(default)]
    pub modules: Vec<String>,
    /// Admits calls that carry a host anchor, such as `logosctl call`.
    #[serde(default)]
    pub allow_host: bool,
}

impl Callers {
    /// Absent or unreadable file: the defaults only, so a typo never opens the door.
    pub fn from_file(contents: Option<&str>) -> Self {
        contents.and_then(|t| serde_json::from_str(t).ok()).unwrap_or_default()
    }

    pub fn admits(&self, access: Access, caller: &Caller) -> bool {
        if access == Access::Open {
            return true;
        }
        match caller {
            Caller::Module(name) if !name.is_empty() => {
                let named = match access {
                    Access::Open => true,
                    Access::Backend => name == BACKEND,
                    Access::BackendOrCore => name == BACKEND || name == CORE,
                    Access::Core => name == CORE,
                };
                named || self.modules.iter().any(|m| m == name)
            }
            Caller::Host => self.allow_host,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(name: &str) -> Caller {
        Caller::Module(name.into())
    }

    #[test]
    fn defaults() {
        let c = Callers::default();
        for who in [m(BACKEND), m(CORE), m("bitcoin_wallet_ui"), Caller::Host, Caller::Unknown, Caller::Other] {
            assert!(c.admits(Access::Open, &who));
        }
        assert!(c.admits(Access::Backend, &m(BACKEND)) && !c.admits(Access::Backend, &m(CORE)));
        assert!(c.admits(Access::BackendOrCore, &m(BACKEND)) && c.admits(Access::BackendOrCore, &m(CORE)));
        assert!(c.admits(Access::Core, &m(CORE)) && !c.admits(Access::Core, &m(BACKEND)));
        for who in [m("bitcoin_wallet_ui"), m(""), Caller::Host, Caller::Unknown, Caller::Other] {
            for a in [Access::Backend, Access::BackendOrCore, Access::Core] {
                assert!(!c.admits(a, &who), "{who:?} {a:?}");
            }
        }
    }

    #[test]
    fn file_widens_every_gated_method() {
        let c = Callers::from_file(Some(r#"{"modules":["probe"],"allowHost":true}"#));
        for a in [Access::Backend, Access::BackendOrCore, Access::Core] {
            assert!(c.admits(a, &m("probe")) && c.admits(a, &Caller::Host));
            assert!(!c.admits(a, &Caller::Unknown) && !c.admits(a, &m("other")));
        }
        assert!(!c.admits(Access::Backend, &m(CORE)));
    }

    #[test]
    fn unreadable_file_admits_only_the_defaults() {
        assert_eq!(Callers::from_file(None), Callers::default());
        for text in [r#"{"modules":["probe"],"typo":1}"#, "not json", r#"{"allowHost":"yes"}"#] {
            let c = Callers::from_file(Some(text));
            assert_eq!(c, Callers::default(), "{text}");
            assert!(!c.admits(Access::Backend, &m("probe")) && !c.admits(Access::Backend, &Caller::Host));
            assert!(c.admits(Access::Backend, &m(BACKEND)));
        }
    }
}
