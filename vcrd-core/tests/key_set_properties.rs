//! The caller's key set is a set (DEVELOPMENT-PLAN.md, milestone 2, decided 2026-11-24):
//! the order of its members never changes the result, and, with lenient checks, adding a
//! key that did not sign never turns a pass into a failure (monotonicity). Members are
//! drawn from keys that signed and keys that did not, with and without each parameter
//! that bears on eligibility.

#[cfg(test)]
mod support;

use helpers::{Key, any_key, checks, credential, lenient_passes, member, result, unused_key};
use proptest::prelude::*;

/// In a `#[cfg(test)]` module so that the workspace's panic lints exempt it, as they do
/// test functions (docs/reviews/milestone-0.md, gap 1).
#[cfg(test)]
mod helpers {
    use proptest::prelude::*;
    use serde_json::{Value, json};
    use vcrd_core::{KeyPolicy, KeySetChecks, KeySetError, KeySetProblem, Report, Severity};

    use super::support::{
        ed448_jwk, issuer_did_and_kid, issuer_jwk, oct_jwk, read, signed, unused_jwk, verified_with,
    };

    /// A member's key: the one that signed, or one that did not.
    #[derive(Clone, Copy, Debug)]
    pub enum Key {
        Signer,
        Unused(u8),
        Ed448,
        Oct,
    }

    /// A member: its key, and the parameters that bear on eligibility.
    #[derive(Clone, Debug)]
    pub struct Member {
        key: Key,
        /// `None`; `Some(None)` for the header's; `Some(Some(kid))` for another.
        kid: Option<Option<&'static str>>,
        key_use: Option<&'static str>,
        alg: Option<&'static str>,
    }

    impl Member {
        fn jwk(&self) -> Value {
            let mut jwk = match self.key {
                Key::Signer => issuer_jwk(),
                Key::Unused(n) => unused_jwk(n),
                Key::Ed448 => ed448_jwk(),
                Key::Oct => oct_jwk(),
            };
            match self.kid {
                None => {}
                Some(None) => jwk["kid"] = json!(issuer_did_and_kid().1),
                Some(Some(kid)) => jwk["kid"] = json!(kid),
            }
            if let Some(value) = self.key_use {
                jwk["use"] = json!(value);
            }
            if let Some(alg) = self.alg {
                jwk["alg"] = json!(alg);
            }
            jwk
        }
    }

    pub fn member(keys: impl Strategy<Value = Key>) -> impl Strategy<Value = Member> {
        (
            keys,
            prop_oneof![
                Just(None),
                Just(Some(None)),
                Just(Some(Some("k1"))),
                Just(Some(Some("k2")))
            ],
            prop_oneof![Just(None), Just(Some("sig")), Just(Some("enc"))],
            prop_oneof![
                Just(None),
                Just(Some("Ed25519")),
                Just(Some("EdDSA")),
                Just(Some("ES256"))
            ],
        )
            .prop_map(|(key, kid, key_use, alg)| Member {
                key,
                kid,
                key_use,
                alg,
            })
    }

    pub fn any_key() -> impl Strategy<Value = Key> {
        prop_oneof![
            Just(Key::Signer),
            (1u8..=3).prop_map(Key::Unused),
            Just(Key::Ed448),
            Just(Key::Oct),
        ]
    }

    /// A key that did not sign.
    pub fn unused_key() -> impl Strategy<Value = Key> {
        prop_oneof![
            (1u8..=3).prop_map(Key::Unused),
            Just(Key::Ed448),
            Just(Key::Oct),
        ]
    }

    pub fn checks() -> impl Strategy<Value = KeySetChecks> {
        prop_oneof![Just(KeySetChecks::Strict), Just(KeySetChecks::Lenient)]
    }

    fn key_set(members: &[Member]) -> Value {
        json!({"keys": members.iter().map(Member::jwk).collect::<Vec<_>>()})
    }

    /// The credential, signed by the signer's key, with the header's `kid` or without it.
    pub fn credential(with_kid: bool) -> Vec<u8> {
        signed(|h, _| {
            if !with_kid {
                h.as_object_mut().unwrap().remove("kid");
            }
        })
    }

    /// What the order of members must not change (DEVELOPMENT-PLAN.md, milestone 2,
    /// decided 2026-11-24): the problems a strict set is rejected for, or the verdict,
    /// the deciding key, each key's kinds, proof result, refusal and members' `kid`s, and
    /// the findings by code, attribution and severity. Not member positions, nor the order
    /// the keys that do not decide are listed in, which follow the file.
    pub fn result(credential: &[u8], members: &[Member], checks: KeySetChecks) -> Vec<String> {
        let key_set = key_set(members);
        if let Err(KeySetError::Rejected { problems }) = read(&key_set, checks) {
            let mut problems: Vec<String> = problems
                .iter()
                .map(|p| match p {
                    KeySetProblem::KidRepeated {
                        kid,
                        kty,
                        crv,
                        members,
                    } => format!("kid {kid} on {} {kty} {crv:?} keys", members.len()),
                    other => format!("{other:?}"),
                })
                .collect();
            problems.sort();
            return problems;
        }
        let report = verified_with(credential, &key_set, KeyPolicy::default(), checks);
        let verified = report.verify.output().expect("verify ran");
        let [proof] = verified.proofs.as_slice() else {
            panic!("one proof: {report:?}")
        };
        let provenance = &proof.key_provenance;
        let deciding = provenance.deciding.and_then(|d| provenance.keys.get(d));
        let mut keys: Vec<String> = provenance
            .keys
            .iter()
            .map(|k| {
                let mut kids: Vec<_> = k.members.iter().map(|m| m.kid.clone()).collect();
                kids.sort();
                format!(
                    "{:?} {:?} {:?} {:?} {kids:?}",
                    k.thumbprint, k.kinds, k.proof, k.refused
                )
            })
            .collect();
        keys.sort();
        let mut findings: Vec<String> = report
            .findings()
            .map(|f| format!("{} {:?} {:?}", f.code, f.attribution, f.severity))
            .collect();
        findings.sort();
        let mut result = vec![
            format!("passed: {}", passed(&report)),
            format!("outcome: {:?}", proof.outcome),
            format!(
                "deciding: {:?}",
                deciding.map(|k| (&k.thumbprint, &k.kinds, &k.refused))
            ),
        ];
        result.extend(keys);
        result.extend(findings);
        result
    }

    /// Whether verify passes with the members, checked leniently.
    pub fn lenient_passes(credential: &[u8], members: &[Member]) -> bool {
        passed(&verified_with(
            credential,
            &key_set(members),
            KeyPolicy::default(),
            KeySetChecks::Lenient,
        ))
    }

    fn passed(report: &Report) -> bool {
        report.findings().all(|f| f.severity != Severity::Error)
    }
}

proptest! {
    /// Any order of the members gives the same result.
    #[test]
    fn the_order_of_members_never_changes_the_result(
        (members, shuffled) in prop::collection::vec(member(any_key()), 0..6)
            .prop_flat_map(|members| (Just(members.clone()), Just(members).prop_shuffle())),
        with_kid in any::<bool>(),
        checks in checks(),
    ) {
        let credential = credential(with_kid);
        prop_assert_eq!(
            result(&credential, &members, checks),
            result(&credential, &shuffled, checks)
        );
    }

    /// With lenient checks, a set that passes still passes with members added whose keys
    /// did not sign.
    #[test]
    fn adding_a_key_that_did_not_sign_never_turns_a_pass_into_a_failure(
        base in prop::collection::vec(member(any_key()), 0..4),
        signer in member(Just(Key::Signer)),
        added in prop::collection::vec(member(unused_key()), 1..4),
        with_kid in any::<bool>(),
    ) {
        let credential = credential(with_kid);
        let mut base = base;
        base.push(signer);
        prop_assume!(lenient_passes(&credential, &base));
        let mut larger = added;
        larger.extend(base);
        prop_assert!(lenient_passes(&credential, &larger), "{:?}", larger);
    }
}
