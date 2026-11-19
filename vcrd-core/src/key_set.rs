//! The caller-supplied key set: a JWK Set (RFC 7517 §5) the caller passes in, from which
//! the caller-supplied key is matched (ARCHITECTURE §8; DEVELOPMENT-PLAN.md, milestone
//! 2, decided 2026-11-18).

use std::fmt;

use crate::context::Limits;
use crate::finding::{
    Attribution, Finding, FindingDetail, JwkProblem, KeySetEntryProblem, Severity,
};
use crate::json::{self, Json};
use crate::keys::{Jwk, MatchedBy, PRIVATE_MEMBERS};
use crate::redact::ClaimValue;
use crate::registry::KeyType;
use crate::report::Phase;

/// A JWK Set the caller supplies (RFC 7517 §5): the entries vcrd keeps, and those RFC
/// 7517 §5 says to ignore. Its `Debug` shows no key material.
#[derive(Clone, Default)]
pub struct KeySet {
    pub(crate) entries: Vec<KeySetEntry>,
    pub(crate) ignored: Vec<IgnoredEntry>,
}

/// One entry vcrd keeps, with the members that constrain its use (RFC 7517 §4.2–4.4).
#[derive(Clone)]
pub(crate) struct KeySetEntry {
    /// Its position in `keys`, from 0.
    pub index: usize,
    pub kid: Option<String>,
    pub alg: Option<String>,
    /// `use` (RFC 7517 §4.2).
    pub key_use: Option<String>,
    pub key_ops: Option<Vec<String>>,
    pub key: EntryKey,
    /// The private or secret members it carries, besides an `oct` key's `k`.
    pub private_members: Vec<&'static str>,
}

/// An entry's key.
#[derive(Clone)]
pub(crate) enum EntryKey {
    /// An asymmetric key's public members, and the key, when vcrd can use it. Boxed, as
    /// it is many times the size of the other variant.
    Public(Box<Jwk>),
    /// A symmetric key (RFC 7518 §6.4). `k` is a secret, which vcrd does not yet use.
    Symmetric { k: ClaimValue },
}

/// An entry RFC 7517 §5 says to ignore, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IgnoredEntry {
    /// Its position in `keys`, from 0.
    pub index: usize,
    /// Its `kid`, when that is a string.
    pub kid: Option<String>,
    pub problem: KeySetEntryProblem,
}

/// Why bytes are not a key set vcrd can use: a caller error (ARCHITECTURE §6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeySetError {
    /// More than `Limits::max_key_set_bytes`, checked before anything is parsed.
    TooLarge { limit: usize, found: usize },
    /// Nested deeper than `Limits::max_depth`, checked before anything is parsed.
    TooDeep { limit: usize, found: usize },
    /// Not JSON; `message` is the parser's.
    NotJson { message: String },
    /// JSON, but not a JWK Set.
    NotJwkSet(NotJwkSet),
}

/// What was found in place of a JWK Set (RFC 7517 §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotJwkSet {
    /// Not an object; `found` is its JSON type.
    NotObject { found: &'static str },
    /// A single JWK: an object with `kty` and no `keys`.
    SingleJwk,
    /// An object with neither `keys` nor `kty`.
    KeysMissing,
    /// `keys` is not an array; `found` is its JSON type.
    KeysNotArray { found: &'static str },
    /// `keys` appears more than once (RFC 7517 §5 applies §4's rule on member names).
    KeysRepeated,
}

impl KeySet {
    /// Reads a JWK Set, its size and depth checked against `limits` before it is
    /// parsed (ARCHITECTURE §4). An entry RFC 7517 §5 says to ignore is kept aside, to
    /// be reported, rather than failing the set.
    pub fn parse(bytes: &[u8], limits: &Limits) -> Result<KeySet, KeySetError> {
        if bytes.len() > limits.max_key_set_bytes {
            return Err(KeySetError::TooLarge {
                limit: limits.max_key_set_bytes,
                found: bytes.len(),
            });
        }
        let depth = json::nesting_depth(bytes);
        if depth > limits.max_depth {
            return Err(KeySetError::TooDeep {
                limit: limits.max_depth,
                found: depth,
            });
        }
        let json = Json::parse(bytes).map_err(|e| KeySetError::NotJson {
            message: e.to_string(),
        })?;
        let not_set = |found| Err(KeySetError::NotJwkSet(found));
        let Some(members) = json.members() else {
            return not_set(NotJwkSet::NotObject {
                found: json.type_name(),
            });
        };
        let keys: Vec<&Json> = members
            .iter()
            .filter(|m| m.name == "keys")
            .map(|m| &m.value)
            .collect();
        let items = match keys[..] {
            [] if json.get("kty").is_some() => return not_set(NotJwkSet::SingleJwk),
            [] => return not_set(NotJwkSet::KeysMissing),
            [Json::Array(items)] => items,
            [other] => {
                return not_set(NotJwkSet::KeysNotArray {
                    found: other.type_name(),
                });
            }
            [_, _, ..] => return not_set(NotJwkSet::KeysRepeated),
        };
        let mut set = KeySet::default();
        for (index, item) in items.iter().enumerate() {
            match entry(index, item) {
                Ok(entry) => set.entries.push(entry),
                Err(ignored) => set.ignored.push(ignored),
            }
        }
        Ok(set)
    }

    /// The warnings about the set itself, in the order of its entries: each entry it
    /// ignores, and each with private members (DEVELOPMENT-PLAN.md, milestone 2, decided
    /// 2026-11-18). Attributed to caller policy: the set is the caller's.
    pub(crate) fn findings(&self) -> Vec<Finding> {
        let ignored = self.ignored.iter().map(|ignored| {
            (
                ignored.index,
                FindingDetail::KeySetEntryIgnored {
                    index: ignored.index,
                    kid: ignored.kid.clone(),
                    problem: ignored.problem.clone(),
                },
            )
        });
        let private = self
            .entries
            .iter()
            .filter(|entry| !entry.private_members.is_empty())
            .map(|entry| {
                (
                    entry.index,
                    FindingDetail::KeySetPrivateKey {
                        index: entry.index,
                        kid: entry.kid.clone(),
                        members: entry.private_members.clone(),
                    },
                )
            });
        let mut details: Vec<(usize, FindingDetail)> = ignored.chain(private).collect();
        details.sort_by_key(|(index, _)| *index);
        details
            .into_iter()
            .map(|(_, detail)| {
                Finding::new(
                    Phase::Verify,
                    Attribution::Policy,
                    Severity::Warning,
                    detail,
                )
            })
            .collect()
    }
}

/// What matching found in the caller's key set (DEVELOPMENT-PLAN.md, milestone 2,
/// decided 2026-11-18).
pub(crate) enum CallerMatch<'a> {
    Matched(&'a KeySetEntry, MatchedBy),
    NotFound,
    /// The entries left: those with the `kid`, or, with no `kid`, every entry.
    Ambiguous(Vec<&'a KeySetEntry>),
}

impl KeySet {
    /// The entry that is the caller-supplied key. `kid` is the header's, resolved as
    /// inspect resolves it; `takes` says whether the declared algorithm takes a key of
    /// a type, and only breaks ties among entries with the `kid`.
    pub(crate) fn find(
        &self,
        kid: Option<&str>,
        takes: impl Fn(KeyType<'_>) -> bool,
    ) -> CallerMatch<'_> {
        if let Some(kid) = kid {
            let equal: Vec<&KeySetEntry> = self
                .entries
                .iter()
                .filter(|e| e.kid.as_deref() == Some(kid))
                .collect();
            match equal.as_slice() {
                [] => {}
                [one] => return CallerMatch::Matched(one, MatchedBy::Kid),
                several => {
                    let fitting: Vec<&KeySetEntry> = several
                        .iter()
                        .copied()
                        .filter(|e| takes(e.key_type()))
                        .collect();
                    return match fitting.as_slice() {
                        [one] => CallerMatch::Matched(one, MatchedBy::Kid),
                        _ => CallerMatch::Ambiguous(equal),
                    };
                }
            }
        }
        match self.entries.as_slice() {
            [only] if kid.is_none() || only.kid.is_none() => {
                CallerMatch::Matched(only, MatchedBy::SoleEntry)
            }
            [_, _, ..] if kid.is_none() => CallerMatch::Ambiguous(self.entries.iter().collect()),
            _ => CallerMatch::NotFound,
        }
    }
}

impl KeySetEntry {
    /// The entry's key type: its `kty`, and its `crv` where it has one.
    pub(crate) fn key_type(&self) -> KeyType<'_> {
        match &self.key {
            EntryKey::Public(jwk) => {
                let member = |name| {
                    jwk.public
                        .members
                        .iter()
                        .find(|(n, _)| *n == name)
                        .map(|(_, v)| v.as_str())
                };
                KeyType {
                    kty: member("kty").unwrap_or_default(),
                    crv: member("crv"),
                }
            }
            EntryKey::Symmetric { .. } => KeyType {
                kty: "oct",
                crv: None,
            },
        }
    }
}

/// One entry of `keys`, or why RFC 7517 §5 says to ignore it.
fn entry(index: usize, json: &Json) -> Result<KeySetEntry, IgnoredEntry> {
    let kid_text = json.get("kid").and_then(Json::as_str).map(str::to_owned);
    let ignored = |problem| IgnoredEntry {
        index,
        kid: kid_text.clone(),
        problem,
    };
    let Some(members) = json.members() else {
        return Err(ignored(KeySetEntryProblem::NotObject));
    };
    // RFC 7517 §4 lets a parser reject a JWK whose member names repeat.
    if let Some(repeated) = members
        .iter()
        .enumerate()
        .find(|(i, m)| members.iter().skip(i + 1).any(|n| n.name == m.name))
        .map(|(_, m)| m.name.clone())
    {
        return Err(ignored(KeySetEntryProblem::MemberRepeated {
            member: repeated,
        }));
    }
    let string = |member: &'static str| match json.get(member) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(|s| Some(s.to_owned()))
            .ok_or_else(|| ignored(KeySetEntryProblem::MemberInvalid { member })),
    };
    let kid = string("kid")?;
    let alg = string("alg")?;
    let key_use = string("use")?;
    let key_ops = match json.get("key_ops") {
        None => None,
        Some(Json::Array(ops)) => Some(
            ops.iter()
                .map(|op| op.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| ignored(KeySetEntryProblem::MemberInvalid { member: "key_ops" }))?,
        ),
        Some(_) => {
            return Err(ignored(KeySetEntryProblem::MemberInvalid {
                member: "key_ops",
            }));
        }
    };
    let symmetric = json.get("kty").and_then(Json::as_str) == Some("oct");
    let key = if symmetric {
        match json.get("k") {
            Some(Json::Scalar(k)) if k.as_str().is_some() => EntryKey::Symmetric { k: k.clone() },
            _ => return Err(ignored(KeySetEntryProblem::MemberMissing { member: "k" })),
        }
    } else {
        EntryKey::Public(Box::new(Jwk::parse(json).map_err(|problem| {
            ignored(match problem {
                JwkProblem::NotObject => KeySetEntryProblem::NotObject,
                JwkProblem::KtyMissing => KeySetEntryProblem::KtyMissing,
                JwkProblem::KtyUnknown { kty } => KeySetEntryProblem::KtyUnknown { kty },
                JwkProblem::MemberMissing { member } => {
                    KeySetEntryProblem::MemberMissing { member }
                }
                // `oct` is read above, so `Jwk::parse` does not see it.
                JwkProblem::Symmetric | JwkProblem::KeyInvalid => KeySetEntryProblem::KeyInvalid,
            })
        })?))
    };
    // An `oct` key's `k` is the key itself, not a private member beside it.
    let private_members = PRIVATE_MEMBERS
        .iter()
        .copied()
        .filter(|&member| !(symmetric && member == "k") && json.get(member).is_some())
        .collect();
    Ok(KeySetEntry {
        index,
        kid,
        alg,
        key_use,
        key_ops,
        key,
        private_members,
    })
}

impl fmt::Debug for KeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeySet")
            .field("entries", &self.entries.len())
            .field("ignored", &self.ignored)
            .finish()
    }
}

impl fmt::Display for KeySetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeySetError::TooLarge { limit, .. } => {
                write!(f, "over the key set size limit of {limit} bytes")
            }
            KeySetError::TooDeep { limit, found } => write!(
                f,
                "nested {found} levels deep, over the limit of {limit} levels"
            ),
            KeySetError::NotJson { message } => write!(f, "not JSON: {message}"),
            KeySetError::NotJwkSet(found) => write!(f, "{found}"),
        }
    }
}

impl std::error::Error for KeySetError {}

impl fmt::Display for NotJwkSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const SET: &str = "a JWK Set is an object whose \"keys\" member is an array of \
                           JWKs (RFC 7517 §5)";
        match self {
            NotJwkSet::NotObject { found: "array" } => write!(
                f,
                "a JSON array, not a JWK Set: put the keys in {{\"keys\": [...]}}; {SET}"
            ),
            NotJwkSet::NotObject { found } => write!(f, "a JSON {found}, not a JWK Set; {SET}"),
            NotJwkSet::SingleJwk => write!(
                f,
                "a single JWK, not a JWK Set: put it in {{\"keys\": [...]}}; {SET}"
            ),
            NotJwkSet::KeysMissing => write!(f, "an object with no \"keys\" member; {SET}"),
            NotJwkSet::KeysNotArray { found } => {
                write!(f, "\"keys\" is a JSON {found}, not an array; {SET}")
            }
            NotJwkSet::KeysRepeated => write!(
                f,
                "\"keys\" appears more than once, where member names must be unique \
                 (RFC 7517 §4, §5)"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8037 appendix A.1–A.2's key: its private and public members.
    const D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
    const X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    const K: &str = "c2VjcmV0IGtleSBtYXRlcmlhbA";

    fn parse(text: &str) -> Result<KeySet, KeySetError> {
        KeySet::parse(text.as_bytes(), &Limits::default())
    }

    fn not_jwk_set(found: NotJwkSet) -> Result<(), KeySetError> {
        Err(KeySetError::NotJwkSet(found))
    }

    /// RFC 7517 §5: a JWK Set is an object with a `keys` array, and nothing else is one,
    /// a single JWK included (DEVELOPMENT-PLAN.md, milestone 2, decided 2026-11-13).
    #[test]
    fn a_jwk_set_is_read_and_anything_else_is_named() {
        let empty = parse(r#"{"keys": []}"#).unwrap();
        assert!(empty.entries.is_empty() && empty.ignored.is_empty());
        for (text, expected) in [
            ("[]", not_jwk_set(NotJwkSet::NotObject { found: "array" })),
            (
                r#""keys""#,
                not_jwk_set(NotJwkSet::NotObject { found: "string" }),
            ),
            (
                &format!(r#"{{"kty": "OKP", "crv": "Ed25519", "x": "{X}"}}"#),
                not_jwk_set(NotJwkSet::SingleJwk),
            ),
            ("{}", not_jwk_set(NotJwkSet::KeysMissing)),
            (
                r#"{"keys": {}}"#,
                not_jwk_set(NotJwkSet::KeysNotArray { found: "object" }),
            ),
            (
                r#"{"keys": [], "keys": []}"#,
                not_jwk_set(NotJwkSet::KeysRepeated),
            ),
        ] {
            assert_eq!(parse(text).map(|_| ()), expected, "{text}");
        }
        assert!(
            matches!(parse("{\"keys\": ["), Err(KeySetError::NotJson { .. })),
            "truncated"
        );
    }

    /// ARCHITECTURE §4: each limit applies before the work it bounds, so input that is
    /// not JSON at all is refused for its size or depth, not parsed. The size limit is
    /// the caller's to raise.
    #[test]
    fn size_and_depth_are_checked_before_parsing_and_the_size_limit_can_be_raised() {
        let limits = Limits::default();
        let set = r#"{"keys": []}"#;
        // Padded with whitespace, which JSON allows, to one byte past the limit.
        let padded = format!(
            "{set}{}",
            " ".repeat(limits.max_key_set_bytes + 1 - set.len())
        );
        assert_eq!(
            KeySet::parse(padded.as_bytes(), &limits).map(|_| ()),
            Err(KeySetError::TooLarge {
                limit: limits.max_key_set_bytes,
                found: padded.len(),
            })
        );
        let raised = Limits {
            max_key_set_bytes: padded.len(),
            ..limits
        };
        assert!(KeySet::parse(padded.as_bytes(), &raised).is_ok());
        let oversize_garbage = "x".repeat(limits.max_key_set_bytes + 1);
        assert!(matches!(
            KeySet::parse(oversize_garbage.as_bytes(), &limits),
            Err(KeySetError::TooLarge { .. })
        ));
        let deep = "[".repeat(limits.max_depth + 1);
        assert_eq!(
            KeySet::parse(deep.as_bytes(), &limits).map(|_| ()),
            Err(KeySetError::TooDeep {
                limit: limits.max_depth,
                found: deep.len(),
            })
        );
    }

    /// RFC 7517 §5: an entry with a key type vcrd does not know, a required member
    /// missing, or a value out of range is ignored, and the set is still read. Each is
    /// kept aside with why, by its position in `keys`.
    #[test]
    fn an_ignored_entry_says_why_and_the_rest_are_kept() {
        let text = format!(
            r#"{{"keys": [
                7,
                {{"kty": "OKP", "crv": "Ed25519"}},
                {{"kty": "XYZ", "kid": "k2"}},
                {{"kid": "k3"}},
                {{"kty": "OKP", "crv": "Ed25519", "x": "AAAA"}},
                {{"kty": "OKP", "crv": "Ed25519", "x": "{X}", "kid": 5}},
                {{"kty": "OKP", "crv": "Ed25519", "x": "{X}", "use": 1}},
                {{"kty": "OKP", "crv": "Ed25519", "x": "{X}", "key_ops": "verify"}},
                {{"kty": "OKP", "crv": "Ed25519", "x": "{X}", "alg": 1}},
                {{"kty": "OKP", "crv": "Ed25519", "x": "{X}", "x": "{X}", "kid": "k9"}},
                {{"kty": "OKP", "crv": "Ed25519", "x": "{X}", "kid": "k10",
                  "alg": "Ed25519", "use": "sig", "key_ops": ["verify"]}}
            ]}}"#
        );
        let set = parse(&text).unwrap();
        let ignored = |index, kid: Option<&str>, problem| IgnoredEntry {
            index,
            kid: kid.map(str::to_owned),
            problem,
        };
        use KeySetEntryProblem::*;
        assert_eq!(
            set.ignored,
            [
                ignored(0, None, NotObject),
                ignored(1, None, MemberMissing { member: "x" }),
                ignored(
                    2,
                    Some("k2"),
                    KtyUnknown {
                        kty: "XYZ".to_owned()
                    }
                ),
                ignored(3, Some("k3"), KtyMissing),
                ignored(4, None, KeyInvalid),
                ignored(5, None, MemberInvalid { member: "kid" }),
                ignored(6, None, MemberInvalid { member: "use" }),
                ignored(7, None, MemberInvalid { member: "key_ops" }),
                ignored(8, None, MemberInvalid { member: "alg" }),
                ignored(
                    9,
                    Some("k9"),
                    MemberRepeated {
                        member: "x".to_owned()
                    }
                ),
            ]
        );
        let [entry] = set.entries.as_slice() else {
            panic!("one entry kept: {set:?}")
        };
        assert_eq!(entry.index, 10);
        assert_eq!(entry.kid.as_deref(), Some("k10"));
        assert_eq!(entry.alg.as_deref(), Some("Ed25519"));
        assert_eq!(entry.key_use.as_deref(), Some("sig"));
        assert_eq!(entry.key_ops, Some(vec!["verify".to_owned()]));
        assert!(entry.private_members.is_empty());
        assert!(matches!(&entry.key, EntryKey::Public(jwk) if jwk.key.is_some()));
    }

    /// An `oct` entry is kept, though vcrd cannot yet use it (DEVELOPMENT-PLAN.md,
    /// milestone 2, decided 2026-11-16); its `k` is the key, not a private member. An
    /// asymmetric key's private members are noted, to be reported.
    #[test]
    fn an_oct_entry_is_kept_and_private_members_are_noted() {
        let text = format!(
            r#"{{"keys": [
                {{"kty": "oct", "k": "{K}"}},
                {{"kty": "OKP", "crv": "Ed25519", "x": "{X}", "d": "{D}"}},
                {{"kty": "oct"}}
            ]}}"#
        );
        let set = parse(&text).unwrap();
        let [oct, private] = set.entries.as_slice() else {
            panic!("two entries kept: {set:?}")
        };
        assert!(matches!(&oct.key, EntryKey::Symmetric { k } if k.as_str() == Some(K)));
        assert!(oct.private_members.is_empty());
        assert_eq!(private.private_members, ["d"]);
        assert_eq!(
            set.ignored,
            [IgnoredEntry {
                index: 2,
                kid: None,
                problem: KeySetEntryProblem::MemberMissing { member: "k" },
            }]
        );
    }

    /// A set of Ed25519 entries (`true`) and EC entries (`false`), each with the `kid`
    /// given, if any.
    fn set_of(entries: &[(Option<&str>, bool)]) -> KeySet {
        let entries: Vec<String> = entries
            .iter()
            .map(|(kid, ed25519)| {
                let kid = kid.map_or_else(String::new, |k| format!(r#", "kid": "{k}""#));
                if *ed25519 {
                    format!(r#"{{"kty": "OKP", "crv": "Ed25519", "x": "{X}"{kid}}}"#)
                } else {
                    format!(r#"{{"kty": "EC", "crv": "P-256", "x": "x", "y": "y"{kid}}}"#)
                }
            })
            .collect();
        let set = parse(&format!(r#"{{"keys": [{}]}}"#, entries.join(", "))).unwrap();
        assert!(set.ignored.is_empty(), "{set:?}");
        set
    }

    /// The rules of matching (DEVELOPMENT-PLAN.md, milestone 2, decided 2026-11-13 and
    /// 2026-11-18), for an algorithm that takes Ed25519 keys alone: the `kid`; among
    /// entries that share it, the key type; otherwise the sole entry, when it or the
    /// header has no `kid`.
    #[test]
    fn matching_takes_the_kid_then_the_key_type_then_the_sole_entry() {
        let takes = |t: KeyType<'_>| t.kty == "OKP" && t.crv == Some("Ed25519");
        let (a, b, c) = (Some("a"), Some("b"), Some("c"));
        let (ed, ec) = (true, false);
        for (entries, kid, expected) in [
            (&[(a, ed)][..], a, ("kid", vec![0])),
            (&[(a, ec), (a, ed)], a, ("kid", vec![1])),
            (&[(a, ed), (a, ed)], a, ("ambiguous", vec![0, 1])),
            (&[(a, ec), (a, ec)], a, ("ambiguous", vec![0, 1])),
            // One entry with the `kid` is the match, whatever its type: whether it fits
            // the algorithm is the suite's check.
            (&[(a, ec)], a, ("kid", vec![0])),
            (&[(None, ed)], a, ("sole_entry", vec![0])),
            (&[(b, ed)], None, ("sole_entry", vec![0])),
            (&[(None, ed)], None, ("sole_entry", vec![0])),
            (&[(b, ed)], a, ("not_found", vec![])),
            (&[(b, ed), (c, ed)], a, ("not_found", vec![])),
            (&[(a, ed), (None, ed)], c, ("not_found", vec![])),
            (&[(a, ed), (b, ed)], None, ("ambiguous", vec![0, 1])),
            (&[], a, ("not_found", vec![])),
            (&[], None, ("not_found", vec![])),
        ] {
            let set = set_of(entries);
            let found = match set.find(kid, takes) {
                CallerMatch::Matched(entry, MatchedBy::Kid) => ("kid", vec![entry.index]),
                CallerMatch::Matched(entry, MatchedBy::SoleEntry) => {
                    ("sole_entry", vec![entry.index])
                }
                CallerMatch::NotFound => ("not_found", vec![]),
                CallerMatch::Ambiguous(left) => {
                    ("ambiguous", left.iter().map(|e| e.index).collect())
                }
            };
            assert_eq!(found, expected, "{entries:?}, kid {kid:?}");
        }
    }

    /// The caller's secrets stay out of debug output, as the credential's claims do
    /// (ARCHITECTURE §7).
    #[test]
    fn debug_output_shows_no_key_material() {
        let text = format!(
            r#"{{"keys": [
                {{"kty": "oct", "k": "{K}", "kid": "secret"}},
                {{"kty": "OKP", "crv": "Ed25519", "x": "{X}", "d": "{D}", "kid": "private"}}
            ]}}"#
        );
        let set = parse(&text).unwrap();
        assert_eq!(set.entries.len(), 2);
        let debug = format!("{set:?}");
        for value in [K, X, D] {
            assert!(!debug.contains(value), "{debug}");
        }
    }
}
