//! Who may do what: from the `Tailscale-App-Capabilities` header that `tailscale serve` sets, or
//! for a local peer from the config's `[[serve.grant]]` tables.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::config::LocalGrant;
use crate::vault::validate_name;

/// The application capability the grants in the tailnet policy file use.
pub const CAP: &str = "github.com/falistos/agentsafe/cap/agentsafe";

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    List,
    Get,
    Put,
    Admin,
}

impl Action {
    /// Whether a grant of `self` also grants `wanted`.
    fn implies(self, wanted: Action) -> bool {
        match self {
            Action::Admin => true,
            Action::Get | Action::Put => wanted == self || wanted == Action::List,
            Action::List => wanted == Action::List,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Pattern {
    Exact(String),
    /// `prefix*`; an empty prefix is `*`, every entry.
    Prefix(String),
}

impl Pattern {
    fn parse(s: &str) -> Option<Pattern> {
        match s.strip_suffix('*') {
            Some("") => Some(Pattern::Prefix(String::new())),
            Some(prefix) => validate_name(prefix)
                .ok()
                .map(|()| Pattern::Prefix(prefix.into())),
            None => validate_name(s).ok().map(|()| Pattern::Exact(s.into())),
        }
    }

    fn matches(&self, name: &str) -> bool {
        match self {
            Pattern::Exact(exact) => name == exact,
            Pattern::Prefix(prefix) => name.starts_with(prefix.as_str()),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGrant {
    entries: Vec<String>,
    actions: Vec<Action>,
}

#[derive(Debug, Clone)]
struct Grant {
    entries: Vec<Pattern>,
    actions: Vec<Action>,
}

/// The union of the caller's grants: an action on an entry is allowed when one grant both
/// matches the entry and holds or implies the action.
#[derive(Debug, Clone)]
pub struct Rights {
    grants: Vec<Grant>,
}

impl Rights {
    /// Whether any grant holds `admin`, on whichever entries.
    pub fn has_admin(&self) -> bool {
        self.grants
            .iter()
            .any(|g| g.actions.contains(&Action::Admin))
    }

    pub fn allows(&self, action: Action, name: &str) -> bool {
        self.grants.iter().any(|g| {
            g.actions.iter().any(|a| a.implies(action)) && g.entries.iter().any(|p| p.matches(name))
        })
    }
}

/// Why a request carries no rights at all.
#[derive(Debug, PartialEq, Eq)]
pub enum Denial {
    /// No header: the peer has no grant for any served capability, or did not come through Serve.
    Missing,
    /// Not ASCII, Q-encoded, or not a JSON object of arrays.
    Malformed,
    /// The header has no valid value for [`CAP`].
    NoGrant,
    /// A local peer whose uid has no `[[serve.grant]]`.
    NoLocalGrant,
    /// The kernel did not give the peer's credentials.
    UnknownPeer,
}

impl Denial {
    pub fn reason(&self) -> &'static str {
        match self {
            Denial::Missing => "no capability header",
            Denial::Malformed => "malformed capability header",
            Denial::NoGrant => "no valid agentsafe grant",
            Denial::NoLocalGrant => "no grant for this uid",
            Denial::UnknownPeer => "cannot identify the peer",
        }
    }
}

/// Parses the header value; the warnings name the values that were ignored and why.
pub fn parse(header: Option<&[u8]>) -> (Result<Rights, Denial>, Vec<String>) {
    let mut warnings = Vec::new();
    let rights = parse_header(header, &mut warnings);
    (rights, warnings)
}

fn parse_header(header: Option<&[u8]>, warnings: &mut Vec<String>) -> Result<Rights, Denial> {
    let header = header.ok_or(Denial::Missing)?;
    // Serve Q-encodes (RFC 2047) a header that is not ASCII, which then fails to parse as JSON;
    // grants never need either.
    if !header.is_ascii() {
        return Err(Denial::Malformed);
    }
    let caps: BTreeMap<String, Vec<serde_json::Value>> =
        serde_json::from_slice(header).map_err(|_| Denial::Malformed)?;
    let values = caps.get(CAP).ok_or(Denial::NoGrant)?;
    let mut grants = Vec::new();
    for (i, value) in values.iter().enumerate() {
        match grant(value) {
            Ok(g) => grants.push(g),
            Err(why) => warnings.push(format!("ignoring {CAP} value {i}: {why}")),
        }
    }
    if grants.is_empty() {
        return Err(Denial::NoGrant);
    }
    Ok(Rights { grants })
}

/// The rights of each uid that has `[[serve.grant]]` tables; an invalid pattern is an error.
pub fn local(grants: &[LocalGrant]) -> Result<BTreeMap<u32, Rights>, String> {
    let mut rights: BTreeMap<u32, Rights> = BTreeMap::new();
    for g in grants {
        let grant = Grant {
            entries: patterns(&g.entries)?,
            actions: g.actions.clone(),
        };
        rights
            .entry(g.uid)
            .or_insert_with(|| Rights { grants: Vec::new() })
            .grants
            .push(grant);
    }
    Ok(rights)
}

fn patterns(entries: &[String]) -> Result<Vec<Pattern>, String> {
    entries
        .iter()
        .map(|p| Pattern::parse(p).ok_or_else(|| format!("invalid entry pattern {p:?}")))
        .collect()
}

fn grant(value: &serde_json::Value) -> Result<Grant, String> {
    // The serde error names the offending field or variant: grant values are policy, not secrets.
    let raw = RawGrant::deserialize(value).map_err(|e| e.to_string())?;
    Ok(Grant {
        entries: patterns(&raw.entries)?,
        actions: raw.actions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(values: &str) -> String {
        format!(r#"{{"other/cap": [{{"x": 1}}], "{CAP}": [{values}]}}"#)
    }

    fn rights(values: &str) -> Rights {
        let (rights, warnings) = parse(Some(header(values).as_bytes()));
        assert!(warnings.is_empty(), "{warnings:?}");
        rights.unwrap()
    }

    #[test]
    fn patterns_match_exact_names_prefixes_and_everything() {
        let r = rights(r#"{"entries": ["db", "app-*"], "actions": ["list"]}"#);
        assert!(r.allows(Action::List, "db"));
        assert!(!r.allows(Action::List, "db2"));
        assert!(!r.allows(Action::List, "d"));
        assert!(r.allows(Action::List, "app-"));
        assert!(r.allows(Action::List, "app-web"));
        assert!(!r.allows(Action::List, "app"));
        assert!(!r.allows(Action::List, "my-app-web"));

        let all = rights(r#"{"entries": ["*"], "actions": ["list"]}"#);
        for name in ["a", "db", "app-web", "x.y_z"] {
            assert!(all.allows(Action::List, name), "{name}");
        }
    }

    #[test]
    fn actions_imply_only_what_the_spec_says() {
        let cases = [
            ("list", [true, false, false, false]),
            ("get", [true, true, false, false]),
            ("put", [true, false, true, false]),
            ("admin", [true, true, true, true]),
        ];
        let wanted = [Action::List, Action::Get, Action::Put, Action::Admin];
        for (granted, expected) in cases {
            let r = rights(&format!(
                r#"{{"entries": ["*"], "actions": ["{granted}"]}}"#
            ));
            for (w, e) in wanted.iter().zip(expected) {
                assert_eq!(r.allows(*w, "x"), e, "{granted} -> {w:?}");
            }
        }
    }

    #[test]
    fn rights_are_the_union_of_the_values_not_a_cross_product() {
        let r = rights(
            r#"{"entries": ["app-*"], "actions": ["get"]},
               {"entries": ["db"], "actions": ["list", "put"]}"#,
        );
        assert!(r.allows(Action::Get, "app-web"));
        assert!(r.allows(Action::Put, "db"));
        assert!(r.allows(Action::List, "db"));
        assert!(!r.allows(Action::Get, "db"));
        assert!(!r.allows(Action::Put, "app-web"));
        assert!(!r.allows(Action::Admin, "db"));
        assert!(!r.allows(Action::List, "other"));
    }

    #[test]
    fn invalid_values_are_ignored_with_a_warning() {
        let (r, warnings) = parse(Some(
            header(
                r#"{"entries": ["*"], "actions": ["delete"]},
                   {"entries": ["*"], "actions": ["get"], "extra": true},
                   {"entries": ["a*b"], "actions": ["get"]},
                   {"entries": ["a**"], "actions": ["get"]},
                   {"entries": ["a/*"], "actions": ["get"]},
                   {"entries": [""], "actions": ["get"]},
                   {"entries": ["db"]},
                   "db",
                   {"entries": ["db"], "actions": ["get"]}"#,
            )
            .as_bytes(),
        ));
        let r = r.unwrap();
        assert_eq!(warnings.len(), 8, "{warnings:?}");
        assert!(r.allows(Action::Get, "db"));
        assert!(!r.allows(Action::List, "app"));
    }

    #[test]
    fn a_header_without_a_valid_grant_gives_no_rights() {
        let no_value = header("");
        let cases: [(Option<&[u8]>, Denial); 8] = [
            (None, Denial::Missing),
            (Some(b""), Denial::Malformed),
            (Some(b"not json"), Denial::Malformed),
            (Some(b"[1]"), Denial::Malformed),
            (Some("{\"é\": []}".as_bytes()), Denial::Malformed),
            (Some(b"=?utf-8?q?{}?="), Denial::Malformed),
            (Some(br#"{"other/cap": [{}]}"#), Denial::NoGrant),
            (Some(no_value.as_bytes()), Denial::NoGrant),
        ];
        for (h, expected) in cases {
            assert_eq!(parse(h).0.unwrap_err(), expected, "{h:?}");
        }
        let only_invalid = header(r#"{"entries": ["*"], "actions": ["root"]}"#);
        assert_eq!(
            parse(Some(only_invalid.as_bytes())).0.unwrap_err(),
            Denial::NoGrant
        );
    }
}
