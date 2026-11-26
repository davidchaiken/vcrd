//! The caller-supplied key set: a JWK Set (RFC 7517 §5) the caller passes in, from which
//! the caller-supplied key is chosen (ARCHITECTURE §8; DEVELOPMENT-PLAN.md, milestone 2,
//! decided 2026-11-18 and 2026-11-24).

use std::fmt;

use crate::context::Limits;
use crate::finding::{
    Attribution, Finding, FindingDetail, JwkProblem, KeySetMemberProblem, MemberRef, Severity,
};
use crate::json::{self, Json};
use crate::keys::{Jwk, PRIVATE_MEMBERS};
use crate::redact::ClaimValue;
use crate::registry::KeyType;
use crate::report::Phase;

/// A JWK Set the caller supplies (RFC 7517 §5): the members vcrd keeps, and those RFC
/// 7517 §5 says to ignore. A set, unordered: `index` only names a member, by its position
/// in the file. Its `Debug` shows no key material.
#[derive(Clone, Default)]
pub struct KeySet {
    pub(crate) members: Vec<KeySetMember>,
    pub(crate) ignored: Vec<IgnoredMember>,
    pub(crate) checks: KeySetChecks,
}

/// How the caller's key set is checked, `--key-set-checks` (DEVELOPMENT-PLAN.md, milestone
/// 2, decided 2026-11-24). Strict rejects a set with any [`KeySetProblem`], and makes a
/// member that is not eligible of one whose `kid` is not the header's or whose `alg`
/// names the declared algorithm by its other name. Lenient warns of each, and uses the
/// rest of the set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeySetChecks {
    #[default]
    Strict,
    Lenient,
}

/// A problem found when the caller's key set is read: with [`KeySetChecks::Strict`], the
/// set is rejected; with lenient, each is a warning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeySetProblem {
    /// A member RFC 7517 §5 says to ignore.
    MemberIgnored {
        index: usize,
        kid: Option<String>,
        problem: KeySetMemberProblem,
    },
    /// A member with private or secret parameters.
    PrivateParameters {
        index: usize,
        kid: Option<String>,
        parameters: Vec<&'static str>,
    },
    /// One `kid` on two or more different keys of one key type (RFC 7517 §4.5).
    KidRepeated {
        kid: String,
        kty: String,
        crv: Option<String>,
        members: Vec<usize>,
    },
}

/// One member vcrd keeps: a JWK, with the parameters that constrain its use (RFC 7517
/// §4.2–4.4).
#[derive(Clone)]
pub(crate) struct KeySetMember {
    /// Its position in `keys`, from 0.
    pub index: usize,
    pub kid: Option<String>,
    pub alg: Option<String>,
    /// `use` (RFC 7517 §4.2).
    pub key_use: Option<String>,
    pub key_ops: Option<Vec<String>>,
    pub key: MemberKey,
    /// The private or secret parameters it carries, besides an `oct` key's `k`.
    pub private_parameters: Vec<&'static str>,
}

/// A member's key.
#[derive(Clone)]
pub(crate) enum MemberKey {
    /// An asymmetric key's public parameters, and the key, when vcrd can use it. Boxed,
    /// as it is many times the size of the other variant.
    Public(Box<Jwk>),
    /// A symmetric key (RFC 7518 §6.4). `k` is a secret, which vcrd does not yet use.
    Symmetric { k: ClaimValue },
}

/// A member RFC 7517 §5 says to ignore, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IgnoredMember {
    /// Its position in `keys`, from 0.
    pub index: usize,
    /// Its `kid`, when that is a string.
    pub kid: Option<String>,
    pub problem: KeySetMemberProblem,
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
    /// A JWK Set with problems, which [`KeySetChecks::Strict`] rejects: each, by the
    /// position of its first member.
    Rejected { problems: Vec<KeySetProblem> },
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
    /// `keys` appears more than once (RFC 7517 §5 applies §4's rule on parameter names).
    KeysRepeated,
}

impl KeySet {
    /// Reads a JWK Set, its size and depth checked against `limits` before it is
    /// parsed (ARCHITECTURE §4). With [`KeySetChecks::Strict`], a set with problems is
    /// rejected; with lenient, a member RFC 7517 §5 says to ignore is kept aside, and each
    /// problem is reported as a warning.
    pub fn parse(
        bytes: &[u8],
        limits: &Limits,
        checks: KeySetChecks,
    ) -> Result<KeySet, KeySetError> {
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
        // The JWK Set's own JSON members, which RFC 7517 §5 calls parameters.
        let Some(parameters) = json.members() else {
            return not_set(NotJwkSet::NotObject {
                found: json.type_name(),
            });
        };
        let keys: Vec<&Json> = parameters
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
        let mut set = KeySet {
            checks,
            ..KeySet::default()
        };
        for (index, item) in items.iter().enumerate() {
            match member(index, item) {
                Ok(member) => set.members.push(member),
                Err(ignored) => set.ignored.push(ignored),
            }
        }
        if checks == KeySetChecks::Strict {
            let problems = set.problems();
            if !problems.is_empty() {
                return Err(KeySetError::Rejected { problems });
            }
        }
        Ok(set)
    }

    /// The problems found in the set itself, by the position of each one's first member:
    /// each member RFC 7517 §5 says to ignore, each with private parameters, and each
    /// `kid` on two or more different keys of one key type (DEVELOPMENT-PLAN.md, milestone
    /// 2, decided 2026-11-24).
    fn problems(&self) -> Vec<KeySetProblem> {
        let ignored = self.ignored.iter().map(|ignored| {
            (
                ignored.index,
                KeySetProblem::MemberIgnored {
                    index: ignored.index,
                    kid: ignored.kid.clone(),
                    problem: ignored.problem.clone(),
                },
            )
        });
        let private = self
            .members
            .iter()
            .filter(|member| !member.private_parameters.is_empty())
            .map(|member| {
                (
                    member.index,
                    KeySetProblem::PrivateParameters {
                        index: member.index,
                        kid: member.kid.clone(),
                        parameters: member.private_parameters.clone(),
                    },
                )
            });
        let mut problems: Vec<(usize, KeySetProblem)> =
            ignored.chain(private).chain(self.kids_repeated()).collect();
        problems.sort_by_key(|(index, _)| *index);
        problems.into_iter().map(|(_, problem)| problem).collect()
    }

    /// Each `kid` that two or more different keys of one key type share, from its first
    /// member (RFC 7517 §4.5). Members that share a `kid` and differ in key type are
    /// alternatives, and members with one key repeat it, not the `kid`.
    ///
    /// Quadratic in the members, which `Limits::max_key_set_bytes` bounds
    /// (DEVELOPMENT-PLAN.md, milestone 3, noted 2026-11-24).
    fn kids_repeated(&self) -> Vec<(usize, KeySetProblem)> {
        let mut repeated = Vec::new();
        for (position, member) in self.members.iter().enumerate() {
            let Some(kid) = &member.kid else {
                continue;
            };
            let key_type = member.key_type();
            let alike = |m: &&KeySetMember| m.kid.as_ref() == Some(kid) && m.key_type() == key_type;
            if self.members.iter().take(position).any(|m| alike(&m)) {
                continue;
            }
            let group: Vec<&KeySetMember> = self.members.iter().filter(alike).collect();
            if group.iter().any(|m| !m.same_key(member)) {
                repeated.push((
                    member.index,
                    KeySetProblem::KidRepeated {
                        kid: kid.clone(),
                        kty: key_type.kty.to_owned(),
                        crv: key_type.crv.map(str::to_owned),
                        members: group.iter().map(|m| m.index).collect(),
                    },
                ));
            }
        }
        repeated
    }

    /// The warnings about the set itself, by the position of each one's first member,
    /// attributed to caller policy, the set being the caller's: with lenient checks, each
    /// problem, which strict checks reject; with either, each key in two or more members
    /// (DEVELOPMENT-PLAN.md, milestone 2, decided 2026-11-18 and 2026-11-24).
    pub(crate) fn findings(&self) -> Vec<Finding> {
        let problems = match self.checks {
            KeySetChecks::Strict => Vec::new(),
            KeySetChecks::Lenient => self.problems(),
        };
        let mut details: Vec<(usize, FindingDetail)> = problems
            .into_iter()
            .map(|problem| match problem {
                KeySetProblem::MemberIgnored {
                    index,
                    kid,
                    problem,
                } => (
                    index,
                    FindingDetail::KeySetMemberIgnored {
                        index,
                        kid,
                        problem,
                    },
                ),
                KeySetProblem::PrivateParameters {
                    index,
                    kid,
                    parameters,
                } => (
                    index,
                    FindingDetail::KeySetPrivateKey {
                        index,
                        kid,
                        parameters,
                    },
                ),
                KeySetProblem::KidRepeated {
                    kid,
                    kty,
                    crv,
                    members,
                } => (
                    members.first().copied().unwrap_or_default(),
                    FindingDetail::KeySetKidRepeated {
                        kid,
                        kty,
                        crv,
                        members: members.into(),
                    },
                ),
            })
            .collect();
        details.extend(self.keys_repeated());
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

    /// Each key that two or more members hold, from its first member.
    ///
    /// Quadratic in the members, which `Limits::max_key_set_bytes` bounds
    /// (DEVELOPMENT-PLAN.md, milestone 3, noted 2026-11-24).
    fn keys_repeated(&self) -> Vec<(usize, FindingDetail)> {
        let mut repeated = Vec::new();
        for (position, member) in self.members.iter().enumerate() {
            if self
                .members
                .iter()
                .take(position)
                .any(|m| m.same_key(member))
            {
                continue;
            }
            let holders: Vec<MemberRef> = self
                .members
                .iter()
                .filter(|m| m.same_key(member))
                .map(KeySetMember::reference)
                .collect();
            if holders.len() > 1 {
                let thumbprint = match &member.key {
                    MemberKey::Public(jwk) => Some(jwk.thumbprint.clone()),
                    MemberKey::Symmetric { .. } => None,
                };
                repeated.push((
                    member.index,
                    FindingDetail::KeySetKeyRepeated {
                        thumbprint,
                        members: holders,
                    },
                ));
            }
        }
        repeated
    }
}

impl KeySetMember {
    /// The member as the result names it.
    pub(crate) fn reference(&self) -> MemberRef {
        MemberRef {
            index: self.index,
            kid: self.kid.clone(),
        }
    }

    /// Whether the two members hold one key: by RFC 7638 thumbprint, or, for symmetric
    /// keys, by `k`.
    pub(crate) fn same_key(&self, other: &KeySetMember) -> bool {
        match (&self.key, &other.key) {
            (MemberKey::Public(a), MemberKey::Public(b)) => a.thumbprint == b.thumbprint,
            (MemberKey::Symmetric { k: a }, MemberKey::Symmetric { k: b }) => a == b,
            _ => false,
        }
    }

    /// The member's key type: its `kty`, and its `crv` where it has one.
    pub(crate) fn key_type(&self) -> KeyType<'_> {
        match &self.key {
            MemberKey::Public(jwk) => {
                let parameter = |name| {
                    jwk.public
                        .members
                        .iter()
                        .find(|(n, _)| *n == name)
                        .map(|(_, v)| v.as_str())
                };
                KeyType {
                    kty: parameter("kty").unwrap_or_default(),
                    crv: parameter("crv"),
                }
            }
            MemberKey::Symmetric { .. } => KeyType {
                kty: "oct",
                crv: None,
            },
        }
    }
}

/// One member of `keys`, or why RFC 7517 §5 says to ignore it. The member is a JWK,
/// whose own JSON members RFC 7517 §4 calls parameters.
fn member(index: usize, json: &Json) -> Result<KeySetMember, IgnoredMember> {
    let kid_text = json.get("kid").and_then(Json::as_str).map(str::to_owned);
    let ignored = |problem| IgnoredMember {
        index,
        kid: kid_text.clone(),
        problem,
    };
    let Some(parameters) = json.members() else {
        return Err(ignored(KeySetMemberProblem::NotObject));
    };
    // RFC 7517 §4 lets a parser reject a JWK whose parameter names repeat.
    if let Some(repeated) = parameters
        .iter()
        .enumerate()
        .find(|(i, p)| parameters.iter().skip(i + 1).any(|q| q.name == p.name))
        .map(|(_, p)| p.name.clone())
    {
        return Err(ignored(KeySetMemberProblem::ParameterRepeated {
            parameter: repeated,
        }));
    }
    let string = |parameter: &'static str| match json.get(parameter) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(|s| Some(s.to_owned()))
            .ok_or_else(|| ignored(KeySetMemberProblem::ParameterInvalid { parameter })),
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
                .ok_or_else(|| {
                    ignored(KeySetMemberProblem::ParameterInvalid {
                        parameter: "key_ops",
                    })
                })?,
        ),
        Some(_) => {
            return Err(ignored(KeySetMemberProblem::ParameterInvalid {
                parameter: "key_ops",
            }));
        }
    };
    let symmetric = json.get("kty").and_then(Json::as_str) == Some("oct");
    let key = if symmetric {
        match json.get("k") {
            Some(Json::Scalar(k)) if k.as_str().is_some() => MemberKey::Symmetric { k: k.clone() },
            _ => {
                return Err(ignored(KeySetMemberProblem::ParameterMissing {
                    parameter: "k",
                }));
            }
        }
    } else {
        MemberKey::Public(Box::new(Jwk::parse(json).map_err(|problem| {
            ignored(match problem {
                JwkProblem::NotObject => KeySetMemberProblem::NotObject,
                JwkProblem::KtyMissing => KeySetMemberProblem::KtyMissing,
                JwkProblem::KtyUnknown { kty } => KeySetMemberProblem::KtyUnknown { kty },
                JwkProblem::MemberMissing { member } => {
                    KeySetMemberProblem::ParameterMissing { parameter: member }
                }
                // `oct` is read above, so `Jwk::parse` does not see it.
                JwkProblem::Symmetric | JwkProblem::KeyInvalid => KeySetMemberProblem::KeyInvalid,
            })
        })?))
    };
    // An `oct` key's `k` is the key itself, not a private parameter beside it.
    let private_parameters = PRIVATE_MEMBERS
        .iter()
        .copied()
        .filter(|&parameter| !(symmetric && parameter == "k") && json.get(parameter).is_some())
        .collect();
    Ok(KeySetMember {
        index,
        kid,
        alg,
        key_use,
        key_ops,
        key,
        private_parameters,
    })
}

impl fmt::Debug for KeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeySet")
            .field("members", &self.members.len())
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
            KeySetError::Rejected { problems } => {
                write!(f, "rejected by --key-set-checks strict: ")?;
                for (i, problem) in problems.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{problem}")?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Display for KeySetProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let member = |index: &usize, kid: &Option<String>| match kid {
            Some(kid) => format!("member {index} (kid {kid})"),
            None => format!("member {index}"),
        };
        match self {
            KeySetProblem::MemberIgnored {
                index,
                kid,
                problem,
            } => {
                let why = match problem {
                    KeySetMemberProblem::NotObject => "not a JSON object".to_owned(),
                    KeySetMemberProblem::ParameterRepeated { parameter } => {
                        format!("parameter {parameter} repeated")
                    }
                    KeySetMemberProblem::KtyMissing => "no kty".to_owned(),
                    KeySetMemberProblem::KtyUnknown { kty } => format!("key type {kty} unknown"),
                    KeySetMemberProblem::ParameterMissing { parameter } => {
                        format!("parameter {parameter} missing")
                    }
                    KeySetMemberProblem::ParameterInvalid { parameter } => {
                        format!("parameter {parameter} invalid")
                    }
                    KeySetMemberProblem::KeyInvalid => "not a key".to_owned(),
                };
                write!(
                    f,
                    "{} is one RFC 7517 §5 says to ignore ({why})",
                    member(index, kid)
                )
            }
            KeySetProblem::PrivateParameters {
                index,
                kid,
                parameters,
            } => write!(
                f,
                "{} carries private parameters ({})",
                member(index, kid),
                parameters.join(", ")
            ),
            KeySetProblem::KidRepeated {
                kid,
                kty,
                crv,
                members,
            } => {
                let key_type = crv
                    .as_ref()
                    .map_or_else(|| kty.clone(), |crv| format!("{kty} {crv}"));
                let members: Vec<String> = members.iter().map(usize::to_string).collect();
                write!(
                    f,
                    "members {} share kid {kid} on different {key_type} keys (RFC 7517 §4.5)",
                    members.join(", ")
                )
            }
        }
    }
}

impl std::error::Error for KeySetError {}

impl fmt::Display for NotJwkSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const SET: &str = "a JWK Set is an object whose \"keys\" parameter is an array of \
                           JWKs, the set's members (RFC 7517 §5)";
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
            NotJwkSet::KeysMissing => write!(f, "an object with no \"keys\" parameter; {SET}"),
            NotJwkSet::KeysNotArray { found } => {
                write!(f, "\"keys\" is a JSON {found}, not an array; {SET}")
            }
            NotJwkSet::KeysRepeated => write!(
                f,
                "\"keys\" appears more than once, where parameter names must be unique \
                 (RFC 7517 §4, §5)"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8037 appendix A.1–A.2's key: its private and public parameters.
    const D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
    const X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    const K: &str = "c2VjcmV0IGtleSBtYXRlcmlhbA";

    fn parse(text: &str) -> Result<KeySet, KeySetError> {
        KeySet::parse(text.as_bytes(), &Limits::default(), KeySetChecks::Lenient)
    }

    fn not_jwk_set(found: NotJwkSet) -> Result<(), KeySetError> {
        Err(KeySetError::NotJwkSet(found))
    }

    /// RFC 7517 §5: a JWK Set is an object with a `keys` array, and nothing else is one,
    /// a single JWK included (DEVELOPMENT-PLAN.md, milestone 2, decided 2026-11-13).
    #[test]
    fn a_jwk_set_is_read_and_anything_else_is_named() {
        let empty = parse(r#"{"keys": []}"#).unwrap();
        assert!(empty.members.is_empty() && empty.ignored.is_empty());
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
            KeySet::parse(padded.as_bytes(), &limits, KeySetChecks::Lenient).map(|_| ()),
            Err(KeySetError::TooLarge {
                limit: limits.max_key_set_bytes,
                found: padded.len(),
            })
        );
        let raised = Limits {
            max_key_set_bytes: padded.len(),
            ..limits
        };
        assert!(KeySet::parse(padded.as_bytes(), &raised, KeySetChecks::Lenient).is_ok());
        let oversize_garbage = "x".repeat(limits.max_key_set_bytes + 1);
        assert!(matches!(
            KeySet::parse(oversize_garbage.as_bytes(), &limits, KeySetChecks::Lenient),
            Err(KeySetError::TooLarge { .. })
        ));
        let deep = "[".repeat(limits.max_depth + 1);
        assert_eq!(
            KeySet::parse(deep.as_bytes(), &limits, KeySetChecks::Lenient).map(|_| ()),
            Err(KeySetError::TooDeep {
                limit: limits.max_depth,
                found: deep.len(),
            })
        );
    }

    /// RFC 7517 §5: a member with a key type vcrd does not know, a required parameter
    /// missing, or a value out of range is ignored, and the set is still read. Each is
    /// kept aside with why, by its position in `keys`.
    #[test]
    fn an_ignored_member_says_why_and_the_rest_are_kept() {
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
        let ignored = |index, kid: Option<&str>, problem| IgnoredMember {
            index,
            kid: kid.map(str::to_owned),
            problem,
        };
        use KeySetMemberProblem::*;
        assert_eq!(
            set.ignored,
            [
                ignored(0, None, NotObject),
                ignored(1, None, ParameterMissing { parameter: "x" }),
                ignored(
                    2,
                    Some("k2"),
                    KtyUnknown {
                        kty: "XYZ".to_owned()
                    }
                ),
                ignored(3, Some("k3"), KtyMissing),
                ignored(4, None, KeyInvalid),
                ignored(5, None, ParameterInvalid { parameter: "kid" }),
                ignored(6, None, ParameterInvalid { parameter: "use" }),
                ignored(
                    7,
                    None,
                    ParameterInvalid {
                        parameter: "key_ops"
                    }
                ),
                ignored(8, None, ParameterInvalid { parameter: "alg" }),
                ignored(
                    9,
                    Some("k9"),
                    ParameterRepeated {
                        parameter: "x".to_owned()
                    }
                ),
            ]
        );
        let [member] = set.members.as_slice() else {
            panic!("one member kept: {set:?}")
        };
        assert_eq!(member.index, 10);
        assert_eq!(member.kid.as_deref(), Some("k10"));
        assert_eq!(member.alg.as_deref(), Some("Ed25519"));
        assert_eq!(member.key_use.as_deref(), Some("sig"));
        assert_eq!(member.key_ops, Some(vec!["verify".to_owned()]));
        assert!(member.private_parameters.is_empty());
        assert!(matches!(&member.key, MemberKey::Public(jwk) if jwk.key.is_some()));
    }

    /// An `oct` member is kept, though vcrd cannot yet use it (DEVELOPMENT-PLAN.md,
    /// milestone 2, decided 2026-11-16); its `k` is the key, not a private parameter. An
    /// asymmetric key's private parameters are noted, to be reported.
    #[test]
    fn an_oct_member_is_kept_and_private_parameters_are_noted() {
        let text = format!(
            r#"{{"keys": [
                {{"kty": "oct", "k": "{K}"}},
                {{"kty": "OKP", "crv": "Ed25519", "x": "{X}", "d": "{D}"}},
                {{"kty": "oct"}}
            ]}}"#
        );
        let set = parse(&text).unwrap();
        let [oct, private] = set.members.as_slice() else {
            panic!("two members kept: {set:?}")
        };
        assert!(matches!(&oct.key, MemberKey::Symmetric { k } if k.as_str() == Some(K)));
        assert!(oct.private_parameters.is_empty());
        assert_eq!(private.private_parameters, ["d"]);
        assert_eq!(
            set.ignored,
            [IgnoredMember {
                index: 2,
                kid: None,
                problem: KeySetMemberProblem::ParameterMissing { parameter: "k" },
            }]
        );
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
        assert_eq!(set.members.len(), 2);
        let debug = format!("{set:?}");
        for value in [K, X, D] {
            assert!(!debug.contains(value), "{debug}");
        }
    }
}
