//! The verify phase: the proof's own times (RFC 7519 §4.1.4–4.1.6; ARCHITECTURE §10
//! [S6]), the key a credential carries about itself (REQUIREMENTS §10; ARCHITECTURE §8),
//! and the caller's key set, on correctly signed inputs. The committed fixtures are
//! tested through the binary, in vcrd-cli/tests/verify.rs; the key set's properties, in
//! key_set_properties.rs.

use serde_json::json;
use time::macros::datetime;
use vcrd_core::{
    Attribution, FindingDetail, KeyReport, KeySecret, KeySetChecks, KeySetError,
    KeySetMemberProblem, KeySetProblem, KeySource, KeySourceKind, MemberExclusion, MemberRef,
    NotDeciding, ProofOutcome, PublicJwk, Refusal, Severity, Validity,
};

use support::{
    NOW, ed448_jwk, issuer_did_and_kid, issuer_jwk, oct_jwk, other_jwk, proof_of, read, signed,
    signed_by_other, unused_jwk, verified, verified_leniently, verified_opted_in,
    verified_overriding, verified_with_key_set, verified_with_skew,
};

#[cfg(test)]
mod support;

const NOT_YET_VALID: (&str, Attribution, Severity) = (
    "verify.proof_not_yet_valid",
    Attribution::Input,
    Severity::Error,
);
const EXPIRED: (&str, Attribution, Severity) =
    ("verify.proof_expired", Attribution::Input, Severity::Error);

/// RFC 7515 §4.1.1: `alg` MUST be present. Without it the signature is not checked.
#[test]
fn a_header_without_alg_is_not_verified() {
    let report = verified(&signed(|h, _| {
        h.as_object_mut().unwrap().remove("alg");
    }));
    let (proof, findings) = proof_of(&report);
    assert_eq!(
        findings,
        [(
            "verify.algorithm_missing",
            Attribution::Input,
            Severity::Error
        )]
    );
    assert!(matches!(proof.outcome, ProofOutcome::NotAttempted));
}

/// RFC 7519 §4.1.5: the current time must be after or equal to `nbf`.
#[test]
fn a_not_before_after_the_clock_fails_verify() {
    let report = verified(&signed(|_, p| p["nbf"] = json!(NOW + 1)));
    let (proof, findings) = proof_of(&report);
    assert_eq!(findings, [NOT_YET_VALID]);
    assert_eq!(proof.validity, Validity::NotYetValid);
    assert!(matches!(proof.outcome, ProofOutcome::Correct { .. }));

    let report = verified(&signed(|_, p| p["nbf"] = json!(NOW)));
    let (proof, findings) = proof_of(&report);
    assert_eq!(findings, []);
    assert_eq!(proof.validity, Validity::Current);
}

/// RFC 7519 §4.1.4: the current time must be before `exp`, so `exp` equal to the
/// clock has expired.
#[test]
fn exp_equal_to_the_clock_has_expired() {
    let report = verified(&signed(|_, p| p["exp"] = json!(NOW)));
    let (proof, findings) = proof_of(&report);
    assert_eq!(findings, [EXPIRED]);
    assert_eq!(proof.validity, Validity::Expired);

    let report = verified(&signed(|_, p| p["exp"] = json!(NOW + 1)));
    assert_eq!(proof_of(&report).0.validity, Validity::Current);
}

/// RFC 7519 §2: a NumericDate may have a fraction.
#[test]
fn a_fractional_numeric_date_compares_as_written() {
    let at = |offset: f64| {
        let exp = NOW as f64 + offset;
        verified(&signed(|_, p| p["exp"] = json!(exp)))
    };
    assert_eq!(proof_of(&at(0.5)).0.validity, Validity::Current);
    assert_eq!(proof_of(&at(-0.5)).0.validity, Validity::Expired);
}

/// A number far outside the years a date can represent still compares.
#[test]
fn a_numeric_date_beyond_any_calendar_compares() {
    let report = verified(&signed(|_, p| p["exp"] = json!(1e20)));
    let (proof, findings) = proof_of(&report);
    assert_eq!(findings, []);
    assert_eq!(proof.validity, Validity::Current);
}

/// The finding gives the time as a date-time too, for a reader, keeping a fraction of
/// a second, and none when the number is outside the years a date can represent.
#[test]
fn a_proof_time_finding_gives_the_date_time_when_there_is_one() {
    let value_date_time = |exp: serde_json::Value| {
        let report = verified(&signed(|_, p| p["exp"] = exp));
        match &report.verify.findings()[0].detail {
            FindingDetail::ProofExpired {
                value_date_time, ..
            } => *value_date_time,
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(
        value_date_time(json!(1780272000.25)),
        Some(datetime!(2026-06-01 0:00:00.25 UTC))
    );
    assert_eq!(value_date_time(json!(-1e20)), None);
}

/// RFC 7519 §4.1.4 and §4.1.5 allow a small leeway for clock skew.
#[test]
fn the_skew_applies_to_both_bounds() {
    let token = signed(|_, p| {
        p["nbf"] = json!(NOW + 30);
        p["exp"] = json!(NOW - 30);
    });
    let (_, findings) = proof_of(&verified(&token));
    assert_eq!(findings, [NOT_YET_VALID]);
    let report = verified_with_skew(&token, 60);
    let (proof, findings) = proof_of(&report);
    assert_eq!(findings, []);
    assert_eq!(proof.validity, Validity::Current);
}

/// RFC 7519 §4.1.6 sets no rule for `iat`, so a time after the clock is a warning
/// and leaves the proof's validity alone.
#[test]
fn iat_after_the_clock_is_a_warning() {
    let report = verified(&signed(|_, p| p["iat"] = json!(NOW + 3600)));
    let (proof, findings) = proof_of(&report);
    assert_eq!(
        findings,
        [(
            "verify.proof_issued_in_future",
            Attribution::Input,
            Severity::Warning
        )]
    );
    assert_eq!(proof.validity, Validity::Unbounded);
    assert!(!report.verify.is_failed());
}

/// A time that is not a number is inspect's error; verify cannot place the clock
/// against it, and adds nothing.
#[test]
fn a_time_that_is_not_a_number_leaves_the_proof_validity_unknown() {
    let report = verified(&signed(|_, p| p["exp"] = json!("2027-01-01T00:00:00Z")));
    let (proof, findings) = proof_of(&report);
    assert_eq!(
        findings,
        [(
            "inspect.numeric_date_invalid",
            Attribution::Input,
            Severity::Error
        )]
    );
    assert_eq!(proof.validity, Validity::Unknown);
}

/// ARCHITECTURE §8: an embedded key equal to the `did:key` is the same key as the
/// issuer key, and its proof the deciding proof's.
#[test]
fn an_embedded_key_equal_to_the_issuers_is_the_same_key_and_correct() {
    let report = verified(&signed(|h, _| h["jwk"] = issuer_jwk()));
    let (proof, findings) = proof_of(&report);
    assert_eq!(findings, []);
    let [key] = proof.key_provenance.keys.as_slice() else {
        panic!("one key: {proof:?}")
    };
    assert_eq!(
        key.kinds,
        [KeySource::IssuerIdentifier, KeySource::CredentialEmbedded]
    );
    assert_eq!(
        (key.method, key.location),
        (Some("did:key"), Some("header.jwk"))
    );
    assert!(matches!(key.proof, ProofOutcome::Correct { .. }));
    assert_eq!(proof.key_provenance.deciding, Some(0));
}

/// ARCHITECTURE §8, "Refused": a `did:key` whose key type vcrd names but cannot use is
/// a refused issuer key, with no thumbprint, since vcrd cannot decode it. It still
/// decides, so an embedded key beside it is not alone and is not refused; its correct
/// proof does not count, and says so. The two keys cannot be compared.
#[test]
fn a_did_key_vcrd_names_but_cannot_use_is_a_refused_issuer_key() {
    // ed448-pub (0x1203), which vcrd names and does not plan to implement.
    let multibase = format!(
        "z{}",
        bs58::encode([&[0x83, 0x24][..], &[9; 57][..]].concat()).into_string()
    );
    let issuer = format!("did:key:{multibase}");
    let report = verified(&signed(|h, p| {
        h["jwk"] = issuer_jwk();
        h["kid"] = json!(format!("{issuer}#{multibase}"));
        p["issuer"] = json!(issuer);
    }));
    let (proof, findings) = proof_of(&report);
    assert_eq!(
        findings,
        [
            (
                "verify.did_key_codec_unsupported",
                Attribution::Vcrd,
                Severity::Error
            ),
            (
                "verify.non_deciding_key_proof_correct",
                Attribution::Input,
                Severity::Warning
            ),
        ]
    );
    assert!(matches!(proof.outcome, ProofOutcome::NotAttempted));
    assert_eq!(proof.key_provenance.deciding, Some(0));
    let [issuer_key, embedded] = proof.key_provenance.keys.as_slice() else {
        panic!("two keys: {proof:?}")
    };
    assert_eq!(issuer_key.kinds, [KeySource::IssuerIdentifier]);
    assert_eq!(issuer_key.thumbprint, None);
    assert_eq!(issuer_key.refused, Some(Refusal::TypeUnsupported));
    assert_eq!(embedded.kinds, [KeySource::CredentialEmbedded]);
    assert_eq!(embedded.refused, None);
    assert!(matches!(embedded.proof, ProofOutcome::Correct { .. }));
    let uncounted = report
        .findings()
        .find(|f| f.code == "verify.non_deciding_key_proof_correct")
        .unwrap();
    assert!(
        matches!(
            uncounted.detail,
            FindingDetail::NonDecidingKeyProofCorrect {
                why: NotDeciding::AnotherKeyDecides,
                ..
            }
        ),
        "{uncounted:?}"
    );
}

/// RFC 7515 §4.1.3: `jwk` is a public key. Its private members are reported, and the
/// key is still compared.
#[test]
fn a_jwk_with_private_members_is_an_inspect_error() {
    let report = verified(&signed(|h, _| {
        h["jwk"] = issuer_jwk();
        h["jwk"]["d"] = json!("c2VjcmV0");
    }));
    let (proof, findings) = proof_of(&report);
    assert_eq!(
        findings,
        [(
            "inspect.jwk_private_key",
            Attribution::Input,
            Severity::Error
        )]
    );
    let detail = &report.inspect.findings()[0].detail;
    assert!(
        matches!(detail, vcrd_core::FindingDetail::JwkPrivateKey { members } if members == &["d"]),
        "{detail:?}"
    );
    let [key] = proof.key_provenance.keys.as_slice() else {
        panic!("one key, the issuer key and the embedded key: {proof:?}")
    };
    assert_eq!(
        key.kinds,
        [KeySource::IssuerIdentifier, KeySource::CredentialEmbedded]
    );
}

/// A `jwk` vcrd cannot read is reported, and verify goes ahead with the `did:key`.
#[test]
fn a_malformed_jwk_does_not_stop_verify() {
    let report = verified(&signed(|h, _| h["jwk"] = json!("not an object")));
    let (proof, findings) = proof_of(&report);
    assert_eq!(
        findings,
        [("inspect.jwk_invalid", Attribution::Input, Severity::Error)]
    );
    assert!(matches!(proof.outcome, ProofOutcome::Correct { .. }));
    let [key] = proof.key_provenance.keys.as_slice() else {
        panic!("the issuer key alone: {proof:?}")
    };
    assert_eq!(key.kinds, [KeySource::IssuerIdentifier]);
}

const HTTPS_ISSUER: &str = "https://issuer.example";

/// A `did:key` `kid`, when there is no issuer key, is a key the credential carries about
/// itself, at `header.kid`: refused alone without the caller's opt-in, and deciding with
/// it, the issuer key vcrd cannot obtain then a warning (DEVELOPMENT-PLAN.md, milestone
/// 2, decided 2026-11-16).
#[test]
fn a_did_key_kid_is_an_embedded_key_when_there_is_no_issuer_key() {
    let input = signed(|_, p| p["issuer"] = json!(HTTPS_ISSUER));
    let kid_without_thumbprint = (
        "inspect.kid_without_thumbprint",
        Attribution::Input,
        Severity::Warning,
    );

    let report = verified(&input);
    let (proof, findings) = proof_of(&report);
    assert_eq!(
        findings,
        [
            kid_without_thumbprint,
            (
                "verify.issuer_method_unsupported",
                Attribution::Vcrd,
                Severity::Error
            ),
            (
                "verify.embedded_key_refused",
                Attribution::Policy,
                Severity::Error
            ),
            (
                "verify.non_deciding_key_proof_correct",
                Attribution::Input,
                Severity::Warning
            ),
        ]
    );
    let [key] = proof.key_provenance.keys.as_slice() else {
        panic!("one key: {proof:?}")
    };
    assert_eq!(key.kinds, [KeySource::CredentialEmbedded]);
    assert_eq!(key.location, Some("header.kid"));
    assert_eq!(key.refused, Some(Refusal::EmbeddedKeyAlone));
    assert!(matches!(key.proof, ProofOutcome::Correct { .. }));

    let report = verified_opted_in(&input);
    let (proof, findings) = proof_of(&report);
    assert_eq!(
        findings,
        [
            kid_without_thumbprint,
            (
                "verify.issuer_key_not_obtained",
                Attribution::Vcrd,
                Severity::Warning
            ),
        ]
    );
    assert_eq!(proof.key_provenance.deciding, Some(0));
    assert!(matches!(proof.outcome, ProofOutcome::Correct { .. }));
}

/// A credential with no issuer that carries a `did:key` `kid` is not blocked for want
/// of key material: verify runs, and refuses the key without the caller's opt-in
/// (DEVELOPMENT-PLAN.md, milestone 2; docs/reviews/milestone-1.md, slice 5, N12).
#[test]
fn a_did_key_kid_lets_verify_run_without_an_issuer() {
    let report = verified(&signed(|_, p| {
        p.as_object_mut().unwrap().remove("issuer");
    }));
    let (proof, findings) = proof_of(&report);
    assert!(
        findings.contains(&(
            "verify.embedded_key_refused",
            Attribution::Policy,
            Severity::Error
        )),
        "{findings:?}"
    );
    let [key] = proof.key_provenance.keys.as_slice() else {
        panic!("one key: {proof:?}")
    };
    assert_eq!(key.location, Some("header.kid"));
    assert_eq!(key.refused, Some(Refusal::EmbeddedKeyAlone));
}

/// A `did:key` `kid` and a `jwk` of the same key are one embedded key, at `header.jwk`.
#[test]
fn a_did_key_kid_and_a_jwk_of_one_key_are_one_embedded_key() {
    let report = verified_opted_in(&signed(|h, p| {
        p["issuer"] = json!(HTTPS_ISSUER);
        h["jwk"] = issuer_jwk();
    }));
    let (proof, _) = proof_of(&report);
    let [key] = proof.key_provenance.keys.as_slice() else {
        panic!("one key: {proof:?}")
    };
    assert_eq!(key.kinds, [KeySource::CredentialEmbedded]);
    assert_eq!(key.location, Some("header.jwk"));
    assert_eq!(proof.key_provenance.deciding, Some(0));
    assert!(matches!(proof.outcome, ProofOutcome::Correct { .. }));
}

/// A credential that carries two embedded keys not known to be one key: neither
/// decides, even with the opt-in, and that is why no key decides.
#[test]
fn two_embedded_keys_that_differ_decide_nothing() {
    let report = verified_opted_in(&signed(|h, p| {
        p["issuer"] = json!(HTTPS_ISSUER);
        h["jwk"] = other_jwk();
    }));
    let (proof, findings) = proof_of(&report);
    assert!(
        findings.contains(&(
            "verify.embedded_keys_differ",
            Attribution::Input,
            Severity::Error
        )),
        "{findings:?}"
    );
    assert_eq!(proof.key_provenance.deciding, None);
    let locations: Vec<_> = proof
        .key_provenance
        .keys
        .iter()
        .map(|k| (k.location, k.refused))
        .collect();
    assert_eq!(
        locations,
        [
            (Some("header.jwk"), Some(Refusal::EmbeddedKeysDiffer)),
            (Some("header.kid"), Some(Refusal::EmbeddedKeysDiffer)),
        ]
    );
}

/// No key that may decide, and no finding of key resolution's to say why: here the only
/// key is an embedded key of a type vcrd cannot use, and the caller opted in. So that
/// verify never passes with no deciding proof key, `verify.no_key_material` says so.
#[test]
fn no_key_that_may_decide_is_no_key_material() {
    let report = verified_opted_in(&signed(|h, p| {
        p.as_object_mut().unwrap().remove("issuer");
        h.as_object_mut().unwrap().remove("kid");
        h["jwk"] = ed448_jwk();
    }));
    let (proof, _) = proof_of(&report);
    assert_eq!(proof.key_provenance.deciding, None);
    let no_key = report
        .verify
        .findings()
        .iter()
        .find(|f| f.code == "verify.no_key_material")
        .unwrap_or_else(|| panic!("no verify.no_key_material: {report:?}"));
    assert!(
        matches!(
            &no_key.detail,
            FindingDetail::NoKeyMaterial { consulted }
                if consulted == &[KeySourceKind::IssuerIdentifier, KeySourceKind::CredentialEmbedded]
        ),
        "{no_key:?}"
    );
    assert!(report.verify.is_failed(), "{report:?}");
}

/// A key type vcrd does not know may be one a later standard defines, so it is
/// attributed to vcrd, as a warning.
#[test]
fn a_jwk_of_an_unknown_key_type_is_a_warning_attributed_to_vcrd() {
    let report = verified(&signed(|h, _| h["jwk"] = json!({"kty": "AKP"})));
    let (_, findings) = proof_of(&report);
    assert_eq!(
        findings,
        [(
            "inspect.jwk_kty_unsupported",
            Attribution::Vcrd,
            Severity::Warning
        )]
    );
}

/// A symmetric key is secret: not a public key, and its `k` is private.
#[test]
fn an_oct_jwk_is_reported_as_symmetric_and_private() {
    let report = verified(&signed(|h, _| {
        h["jwk"] = json!({"kty": "oct", "k": "c2VjcmV0"});
    }));
    let codes: Vec<_> = report.inspect.findings().iter().map(|f| f.code).collect();
    assert_eq!(codes, ["inspect.jwk_invalid", "inspect.jwk_private_key"]);
}

/// A name RFC 7515 defines is no extension: inspect reports it in `crit`, and the
/// suite does not refuse it as unimplemented.
#[test]
fn a_registered_name_in_crit_is_not_an_extension() {
    let report = verified(&signed(|h, _| h["crit"] = json!(["alg"])));
    let (proof, findings) = proof_of(&report);
    assert_eq!(
        findings,
        [("inspect.crit_invalid", Attribution::Input, Severity::Error)]
    );
    assert!(matches!(proof.outcome, ProofOutcome::Correct { .. }));
}

/// With `--key-set-checks lenient`, a member of the caller's key set that RFC 7517 §5 says
/// to ignore, and one with private parameters, are warnings attributed to caller policy,
/// reported once, before the proof's findings, and only by verify (DEVELOPMENT-PLAN.md,
/// milestone 2, decided 2026-11-18 and 2026-11-24).
#[test]
fn key_set_warnings_come_once_before_the_proofs_findings() {
    let mut private = issuer_jwk();
    private["d"] = json!("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A");
    private["kid"] = json!("with-d");
    let key_set = json!({"keys": [{"kty": "XYZ", "kid": "unknown"}, private]});
    let report = verified_leniently(&signed(|_, _| {}), &key_set);
    assert!(
        report
            .inspect
            .findings()
            .iter()
            .all(|f| !f.code.starts_with("verify.")),
        "{report:?}"
    );
    let findings = report.verify.findings();
    let [ignored, private, ..] = findings else {
        panic!("two findings at least: {findings:?}")
    };
    for finding in [ignored, private] {
        assert_eq!(
            (finding.attribution, finding.severity),
            (Attribution::Policy, Severity::Warning),
            "{finding:?}"
        );
    }
    assert!(
        matches!(
            &ignored.detail,
            FindingDetail::KeySetMemberIgnored {
                index: 0,
                kid: Some(kid),
                problem: KeySetMemberProblem::KtyUnknown { kty },
            } if kid == "unknown" && kty == "XYZ"
        ),
        "{ignored:?}"
    );
    assert!(
        matches!(
            &private.detail,
            FindingDetail::KeySetPrivateKey {
                index: 1,
                kid: Some(kid),
                parameters,
            } if kid == "with-d" && parameters == &["d"]
        ),
        "{private:?}"
    );
    let codes: Vec<_> = findings.iter().map(|f| f.code).collect();
    for code in [
        "verify.key_set_member_ignored",
        "verify.key_set_private_key",
    ] {
        assert_eq!(codes.iter().filter(|&&c| c == code).count(), 1, "{codes:?}");
    }
}

/// With `--key-set-checks strict`, the default, a set with problems found when it is read
/// is rejected, each problem named by its members' positions: a member RFC 7517 §5 says
/// to ignore, private parameters, and one `kid` on two different keys of one key type
/// (RFC 7517 §4.5). Members that share a `kid` and differ in key type are alternatives,
/// and one key in two members is a warning in either mode (DEVELOPMENT-PLAN.md,
/// milestone 2, decided 2026-11-24).
#[test]
fn strict_checks_reject_a_set_with_problems_and_name_each() {
    let mut private = issuer_jwk();
    private["d"] = json!("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A");
    private["kid"] = json!("with-d");
    let mut first = other_jwk();
    first["kid"] = json!("shared");
    let mut second = unused_jwk(1);
    second["kid"] = json!("shared");
    let mut ed448 = ed448_jwk();
    ed448["kid"] = json!("shared");
    let key_set =
        json!({"keys": [{"kty": "XYZ", "kid": "unknown"}, private, first, second, ed448]});
    let Err(KeySetError::Rejected { problems }) = read(&key_set, KeySetChecks::Strict) else {
        panic!("rejected")
    };
    assert_eq!(
        problems,
        [
            KeySetProblem::MemberIgnored {
                index: 0,
                kid: Some("unknown".to_owned()),
                problem: KeySetMemberProblem::KtyUnknown {
                    kty: "XYZ".to_owned()
                },
            },
            KeySetProblem::PrivateParameters {
                index: 1,
                kid: Some("with-d".to_owned()),
                parameters: vec!["d"],
            },
            KeySetProblem::KidRepeated {
                kid: "shared".to_owned(),
                kty: "OKP".to_owned(),
                crv: Some("Ed25519".to_owned()),
                members: vec![2, 3],
            },
        ]
    );
    let report = verified_leniently(&signed(|_, _| {}), &key_set);
    assert!(
        report.verify.findings().iter().any(|f| matches!(
            &f.detail,
            FindingDetail::KeySetKidRepeated { kid, members, .. }
                if kid == "shared" && **members == [2, 3]
        ) && f.severity == Severity::Warning),
        "{report:?}"
    );
    // The same key twice, and a `kid` shared across key types, are not rejected.
    let mut ed25519 = issuer_jwk();
    ed25519["kid"] = json!("pair");
    let mut ed448 = ed448_jwk();
    ed448["kid"] = json!("pair");
    let accepted = json!({"keys": [issuer_jwk(), issuer_jwk(), ed25519, ed448]});
    assert!(read(&accepted, KeySetChecks::Strict).is_ok());
}

// The caller-supplied key: eligibility, the choice by proof, and the findings that say
// why (DEVELOPMENT-PLAN.md, milestone 2, decided 2026-11-24).

const KID_NOT_HEADER_KID: &str = "verify.key_set_kid_not_header_kid";
const KEY_REPEATED: (&str, Attribution, Severity) = (
    "verify.key_set_key_repeated",
    Attribution::Policy,
    Severity::Warning,
);

/// A key's members, as (position, `kid`).
fn members(key: &KeyReport) -> Vec<(usize, Option<&str>)> {
    key.members
        .iter()
        .map(|m| (m.index, m.kid.as_deref()))
        .collect()
}

/// The set is unordered, and a key that did not sign changes nothing: the issuer key
/// decides whether another key without a `kid` comes before it or after it.
#[test]
fn the_set_is_unordered_and_a_key_that_did_not_sign_changes_nothing() {
    for (key_set, issuer_index) in [
        (json!({"keys": [other_jwk(), issuer_jwk()]}), 1),
        (json!({"keys": [issuer_jwk(), other_jwk()]}), 0),
    ] {
        let report = verified_with_key_set(&signed(|_, _| {}), &key_set);
        let (proof, findings) = proof_of(&report);
        assert!(findings.is_empty(), "{key_set}: {findings:?}");
        let [key] = proof.key_provenance.keys.as_slice() else {
            panic!("one key: {:?}", proof.key_provenance)
        };
        assert_eq!(
            key.kinds,
            [KeySource::CallerSupplied, KeySource::IssuerIdentifier]
        );
        assert_eq!(members(key), [(issuer_index, None)], "{key_set}");
        assert!(matches!(proof.outcome, ProofOutcome::Correct { .. }));
    }
}

const NOT_FOUND: (&str, Attribution, Severity) = (
    "verify.caller_key_not_found",
    Attribution::Policy,
    Severity::Error,
);
const NOT_ISSUER_KEY: (&str, Attribution, Severity) = (
    "verify.caller_key_not_issuer_key",
    Attribution::Policy,
    Severity::Error,
);

/// A member whose key is the issuer key, with the header's `kid`, is one key with both
/// kinds, which names the member, and it decides (ARCHITECTURE §8, rule 1).
#[test]
fn a_member_whose_key_is_the_issuer_key_decides() {
    let (_, kid) = issuer_did_and_kid();
    let mut member = issuer_jwk();
    member["kid"] = json!(kid);
    let report = verified_with_key_set(&signed(|_, _| {}), &json!({"keys": [member]}));
    let (proof, findings) = proof_of(&report);
    assert!(findings.is_empty(), "{findings:?}");
    let provenance = &proof.key_provenance;
    assert_eq!(provenance.deciding, Some(0));
    let [key] = provenance.keys.as_slice() else {
        panic!("one key: {provenance:?}")
    };
    assert_eq!(
        key.kinds,
        [KeySource::CallerSupplied, KeySource::IssuerIdentifier]
    );
    assert_eq!(members(key), [(0, Some(kid.as_str()))]);
    assert!(matches!(key.proof, ProofOutcome::Correct { .. }), "{key:?}");
}

/// The header's `kid` is resolved as inspect resolves it, a relative DID URL against the
/// DID issuer (DID Core §3.2.2), before it is compared with a member's.
#[test]
fn a_relative_kid_is_resolved_against_the_did_issuer_before_it_is_compared() {
    let (issuer, kid) = issuer_did_and_kid();
    let fragment = kid.strip_prefix(&issuer).unwrap().to_owned();
    let mut member = issuer_jwk();
    member["kid"] = json!(kid);
    let credential = signed(|h, p| {
        h["kid"] = json!(fragment);
        p["iss"] = json!(issuer);
    });
    let report = verified_with_key_set(&credential, &json!({"keys": [member]}));
    let (proof, findings) = proof_of(&report);
    assert!(
        !findings
            .iter()
            .any(|(code, _, _)| *code == KID_NOT_HEADER_KID),
        "{findings:?}"
    );
    let key = &proof.key_provenance.keys[0];
    assert_eq!(members(key), [(0, Some(kid.as_str()))], "{key:?}");
    assert_eq!(proof.key_provenance.deciding, Some(0));
}

/// A member without a `kid` does not contradict the header's, so it is eligible in either
/// mode.
#[test]
fn a_member_without_a_kid_is_eligible() {
    let report = verified_with_key_set(&signed(|_, _| {}), &json!({"keys": [issuer_jwk()]}));
    let (proof, findings) = proof_of(&report);
    assert!(findings.is_empty(), "{findings:?}");
    let [key] = proof.key_provenance.keys.as_slice() else {
        panic!("one key: {:?}", proof.key_provenance)
    };
    assert_eq!(members(key), [(0, None)]);
}

/// A member whose key's proof is correct and whose `kid` is not the header's: with
/// strict checks, not eligible, an error while no eligible member's key gives a correct
/// proof, beside the refused caller-supplied key that stands in, never a fall back to the
/// issuer key alone; with lenient checks, eligible, and a warning. A member whose key did
/// not sign is not named.
#[test]
fn a_members_kid_that_is_not_the_headers_decides_eligibility_only_when_strict() {
    let (_, kid) = issuer_did_and_kid();
    let mut issuers = issuer_jwk();
    issuers["kid"] = json!("elsewhere");
    let mut other = other_jwk();
    other["kid"] = json!("other");
    let key_set = json!({"keys": [issuers, other]});
    let report = verified_with_key_set(&signed(|_, _| {}), &key_set);
    let (proof, findings) = proof_of(&report);
    assert_eq!(
        findings,
        [
            (KID_NOT_HEADER_KID, Attribution::Policy, Severity::Error),
            NOT_FOUND
        ]
    );
    let details: Vec<&FindingDetail> = report.verify.findings().iter().map(|f| &f.detail).collect();
    assert!(
        matches!(
            details.as_slice(),
            [
                FindingDetail::KeySetKidNotHeaderKid { key, member, header_kid },
                FindingDetail::CallerKeyNotFound { kid: Some(not_found) },
            ] if **member == MemberRef { index: 0, kid: Some("elsewhere".to_owned()) }
                && key.members.is_empty()
                && *header_kid == kid
                && *not_found == kid
        ),
        "{details:?}"
    );
    let provenance = &proof.key_provenance;
    let [stand_in, issuer] = provenance.keys.as_slice() else {
        panic!("two keys: {provenance:?}")
    };
    assert_eq!(stand_in.kinds, [KeySource::CallerSupplied]);
    assert_eq!(stand_in.refused, Some(Refusal::CallerKeyNotFound));
    assert_eq!(
        (stand_in.thumbprint.as_ref(), members(stand_in)),
        (None, vec![])
    );
    assert_eq!(
        issuer.kinds,
        [KeySource::CallerSupplied, KeySource::IssuerIdentifier]
    );
    assert_eq!(
        (members(issuer), issuer.refused),
        (vec![(0, Some("elsewhere"))], None)
    );
    assert!(matches!(issuer.proof, ProofOutcome::Correct { .. }));
    assert_eq!(provenance.deciding, Some(1));

    let report = verified_leniently(&signed(|_, _| {}), &key_set);
    let (proof, findings) = proof_of(&report);
    assert_eq!(
        findings,
        [(KID_NOT_HEADER_KID, Attribution::Policy, Severity::Warning)]
    );
    let [key] = proof.key_provenance.keys.as_slice() else {
        panic!("one key: {:?}", proof.key_provenance)
    };
    assert_eq!(members(key), [(0, Some("elsewhere"))]);

    // Strict, with another member holding the same key and no `kid`: that member is
    // eligible, so the `kid` is a warning, and the key lists both.
    let mut issuers = issuer_jwk();
    issuers["kid"] = json!("elsewhere");
    let report = verified_with_key_set(
        &signed(|_, _| {}),
        &json!({"keys": [issuers, issuer_jwk()]}),
    );
    let (proof, findings) = proof_of(&report);
    assert_eq!(
        findings,
        [
            KEY_REPEATED,
            (KID_NOT_HEADER_KID, Attribution::Policy, Severity::Warning)
        ]
    );
    assert_eq!(
        members(&proof.key_provenance.keys[0]),
        [(0, Some("elsewhere")), (1, None)]
    );
}

/// One `kid` on two different keys of one key type: rejected with strict checks; with
/// lenient checks, a warning, and the key whose proof is correct decides.
#[test]
fn one_kid_on_two_keys_of_one_type_is_rejected_unless_lenient() {
    let (_, kid) = issuer_did_and_kid();
    let mut issuers = issuer_jwk();
    issuers["kid"] = json!(kid);
    let mut other = other_jwk();
    other["kid"] = json!(kid);
    let key_set = json!({"keys": [other, issuers]});
    assert!(matches!(
        read(&key_set, KeySetChecks::Strict),
        Err(KeySetError::Rejected { .. })
    ));
    let report = verified_leniently(&signed(|_, _| {}), &key_set);
    let (proof, findings) = proof_of(&report);
    assert_eq!(
        findings,
        [(
            "verify.key_set_kid_repeated",
            Attribution::Policy,
            Severity::Warning
        )]
    );
    let [key] = proof.key_provenance.keys.as_slice() else {
        panic!("one key: {:?}", proof.key_provenance)
    };
    assert_eq!(members(key), [(1, Some(kid.as_str()))]);
}

/// Members that share a `kid` and differ in key type are alternatives (RFC 7517 §4.5):
/// the one whose key type the declared algorithm takes is eligible; `Ed25519` does not
/// take an Ed448 key (RFC 9864 §2.2), so no proof is made with that one.
#[test]
fn members_that_share_a_kid_and_differ_in_key_type_are_alternatives() {
    let (_, kid) = issuer_did_and_kid();
    let mut issuers = issuer_jwk();
    issuers["kid"] = json!(kid);
    let mut ed448 = ed448_jwk();
    ed448["kid"] = json!(kid);
    let report = verified_with_key_set(&signed(|_, _| {}), &json!({"keys": [ed448, issuers]}));
    let (proof, findings) = proof_of(&report);
    assert!(findings.is_empty(), "{findings:?}");
    let [key] = proof.key_provenance.keys.as_slice() else {
        panic!("one key: {:?}", proof.key_provenance)
    };
    assert_eq!(members(key), [(1, Some(kid.as_str()))]);
}

/// One key in two members is a warning in either mode, and the key lists both.
#[test]
fn one_key_in_two_members_is_a_warning_and_lists_both() {
    let mut signing = issuer_jwk();
    signing["use"] = json!("sig");
    let key_set = json!({"keys": [issuer_jwk(), signing]});
    for report in [
        verified_with_key_set(&signed(|_, _| {}), &key_set),
        verified_leniently(&signed(|_, _| {}), &key_set),
    ] {
        let (proof, findings) = proof_of(&report);
        assert_eq!(findings, [KEY_REPEATED]);
        let key = &proof.key_provenance.keys[0];
        assert_eq!(members(key), [(0, None), (1, None)]);
        assert!(
            report.verify.findings().iter().any(|f| matches!(
                &f.detail,
                FindingDetail::KeySetKeyRepeated { thumbprint, members }
                    if *thumbprint == key.thumbprint && members.len() == 2
            )),
            "{findings:?}"
        );
    }
}

/// With no eligible member's key giving a correct proof, verify fails whatever is chosen,
/// and the choice decides which finding explains it: the member holding the issuer key,
/// when eligible, so the signature is what fails; otherwise the sole eligible key, two
/// members holding one key being one; otherwise the refused key that stands in.
#[test]
fn with_no_correct_proof_the_choice_decides_which_finding_explains() {
    const INVALID: &str = "verify.signature_invalid";
    let report = verified_with_key_set(
        &signed_by_other(|_, _| {}),
        &json!({"keys": [unused_jwk(1), issuer_jwk()]}),
    );
    let (proof, findings) = proof_of(&report);
    assert!(
        findings.iter().any(|(code, _, _)| *code == INVALID),
        "{findings:?}"
    );
    assert!(!findings.contains(&NOT_FOUND), "{findings:?}");
    assert!(!findings.contains(&NOT_ISSUER_KEY), "{findings:?}");
    let deciding = &proof.key_provenance.keys[0];
    assert_eq!(
        deciding.kinds,
        [KeySource::CallerSupplied, KeySource::IssuerIdentifier]
    );
    assert_eq!(deciding.proof, ProofOutcome::Incorrect);

    let mut signing = unused_jwk(1);
    signing["use"] = json!("sig");
    let report = verified_with_key_set(
        &signed(|_, _| {}),
        &json!({"keys": [unused_jwk(1), signing]}),
    );
    let (_, findings) = proof_of(&report);
    assert_eq!(findings, [KEY_REPEATED, NOT_ISSUER_KEY]);

    let report = verified_with_key_set(
        &signed(|_, _| {}),
        &json!({"keys": [unused_jwk(1), unused_jwk(2)]}),
    );
    let (proof, findings) = proof_of(&report);
    assert_eq!(findings, [NOT_FOUND]);
    let provenance = &proof.key_provenance;
    let [stand_in, issuer] = provenance.keys.as_slice() else {
        panic!("two keys: {provenance:?}")
    };
    assert_eq!(stand_in.refused, Some(Refusal::CallerKeyNotFound));
    assert_eq!(issuer.kinds, [KeySource::IssuerIdentifier]);
    assert_eq!(provenance.deciding, Some(1));
}

/// A member's own `alg`, `use` and `key_ops` are the caller's policy: one that excludes the
/// declared algorithm makes the member not eligible (RFC 8725 §3.1). Its key's proof is
/// still made, so that a member whose key would verify is named: an error while no
/// eligible member's key gives a correct proof, and its key, refused, has no other finding
/// saying its proof is correct. One that allows the algorithm changes nothing.
#[test]
fn a_members_own_parameters_can_exclude_the_algorithm() {
    let https = |h: &mut serde_json::Value, p: &mut serde_json::Value| {
        h.as_object_mut().unwrap().remove("kid");
        p["issuer"] = json!("https://issuer.example");
    };
    for (parameter, value, expected) in [
        (
            "use",
            json!("enc"),
            MemberExclusion::Use {
                value: "enc".to_owned(),
            },
        ),
        (
            "key_ops",
            json!(["sign"]),
            MemberExclusion::KeyOps {
                ops: vec!["sign".to_owned()],
            },
        ),
        (
            "alg",
            json!("ES256"),
            MemberExclusion::Alg {
                alg: "ES256".to_owned(),
            },
        ),
    ] {
        let mut member = issuer_jwk();
        member[parameter] = value;
        let report = verified_with_key_set(&signed(https), &json!({"keys": [member]}));
        let (proof, findings) = proof_of(&report);
        assert!(
            findings.contains(&(
                "verify.caller_key_excluded",
                Attribution::Policy,
                Severity::Error
            )),
            "{parameter}: {findings:?}"
        );
        assert!(findings.contains(&NOT_FOUND), "{parameter}: {findings:?}");
        assert!(
            !findings
                .iter()
                .any(|(code, _, _)| *code == "verify.non_deciding_key_proof_correct"),
            "{parameter}: {findings:?}"
        );
        assert!(
            report.verify.findings().iter().any(|f| matches!(
                &f.detail,
                FindingDetail::CallerKeyExcluded { key, member, exclusion, algorithm }
                    if member.index == 0
                        && key.members.is_empty()
                        && *exclusion == expected
                        && algorithm == "Ed25519"
            )),
            "{parameter}: {findings:?}"
        );
        let provenance = &proof.key_provenance;
        let [stand_in, key] = provenance.keys.as_slice() else {
            panic!("{parameter}: two keys: {provenance:?}")
        };
        assert_eq!(stand_in.refused, Some(Refusal::CallerKeyNotFound));
        assert_eq!(provenance.deciding, Some(0), "{parameter}");
        assert_eq!(key.refused, Some(Refusal::ExcludedByMember), "{parameter}");
        assert!(
            matches!(key.proof, ProofOutcome::Correct { .. }),
            "{parameter}"
        );
    }
    // Another member holding the same key is eligible: the exclusion is a warning.
    let mut encrypting = issuer_jwk();
    encrypting["use"] = json!("enc");
    let report =
        verified_with_key_set(&signed(https), &json!({"keys": [encrypting, issuer_jwk()]}));
    let (proof, findings) = proof_of(&report);
    assert!(
        findings.contains(&(
            "verify.caller_key_excluded",
            Attribution::Policy,
            Severity::Warning
        )),
        "{findings:?}"
    );
    assert!(matches!(proof.outcome, ProofOutcome::Correct { .. }));
    let mut allowing = issuer_jwk();
    allowing["use"] = json!("sig");
    allowing["key_ops"] = json!(["verify"]);
    allowing["alg"] = json!("Ed25519");
    let report = verified_with_key_set(&signed(|_, _| {}), &json!({"keys": [allowing]}));
    let (_, findings) = proof_of(&report);
    assert!(findings.is_empty(), "{findings:?}");
}

/// With an Ed25519 key, `EdDSA` and `Ed25519` name one algorithm (RFC 8037 §3.1; RFC 9864
/// §2.2), which a verifier comparing the names would refuse. With lenient checks, the
/// member is eligible, with a warning; with strict checks, it is not, and the finding is
/// an error while no eligible member's key gives a correct proof. With an Ed448 key,
/// `EdDSA` is another algorithm, and `Ed25519` does not take the key at all.
#[test]
fn the_alg_alias_makes_a_member_ineligible_only_when_strict() {
    const ALIAS: &str = "verify.caller_key_alg_alias";
    for (declared, member_alg) in [("Ed25519", "EdDSA"), ("EdDSA", "Ed25519")] {
        let mut member = issuer_jwk();
        member["alg"] = json!(member_alg);
        let credential = signed(|h, _| h["alg"] = json!(declared));
        let key_set = json!({"keys": [member]});
        let report = verified_leniently(&credential, &key_set);
        let (proof, findings) = proof_of(&report);
        assert!(
            findings.contains(&(ALIAS, Attribution::Policy, Severity::Warning)),
            "{declared}: {findings:?}"
        );
        assert!(
            findings.iter().all(|(_, _, s)| *s != Severity::Error),
            "{declared}: {findings:?}"
        );
        assert!(
            report.verify.findings().iter().any(|f| matches!(
                &f.detail,
                FindingDetail::CallerKeyAlgAlias { key, member, alg, declared: d }
                    if member.index == 0
                        && key.members.is_empty()
                        && alg == member_alg
                        && d == declared
            )),
            "{declared}: {findings:?}"
        );
        assert!(matches!(proof.outcome, ProofOutcome::Correct { .. }));

        let report = verified_with_key_set(&credential, &key_set);
        let (_, findings) = proof_of(&report);
        assert!(
            findings.contains(&(ALIAS, Attribution::Policy, Severity::Error)),
            "{declared}: {findings:?}"
        );
        assert!(findings.contains(&NOT_FOUND), "{declared}: {findings:?}");
    }
    let mut ed448 = ed448_jwk();
    ed448["alg"] = json!("EdDSA");
    let report = verified_with_key_set(&signed(|_, _| {}), &json!({"keys": [ed448]}));
    let (_, findings) = proof_of(&report);
    assert_eq!(findings, [NOT_FOUND]);
}

/// The sole eligible key, which vcrd cannot use, is the caller-supplied key, refused, and
/// says why: `EdDSA` takes an Ed448 key. While the issuer key decides, the refusal is a
/// warning, and the key's being unlike the issuer key the error; with the override, the
/// refused caller-supplied key decides, and the refusal is the error (DEVELOPMENT-PLAN.md,
/// milestone 2, decided 2026-11-18).
#[test]
fn a_caller_key_of_a_type_vcrd_cannot_use_is_refused() {
    const UNSUPPORTED: &str = "verify.caller_key_type_unsupported";
    let credential = signed(|h, _| h["alg"] = json!("EdDSA"));
    let overridden = verified_overriding(&credential, &json!({"keys": [ed448_jwk()]}), true);
    let (proof, findings) = proof_of(&overridden);
    assert!(
        findings.contains(&(UNSUPPORTED, Attribution::Vcrd, Severity::Error)),
        "{findings:?}"
    );
    assert_eq!(proof.key_provenance.deciding, Some(0));
    let report = verified_with_key_set(&credential, &json!({"keys": [ed448_jwk()]}));
    let (proof, findings) = proof_of(&report);
    assert!(
        findings.contains(&(UNSUPPORTED, Attribution::Vcrd, Severity::Warning)),
        "{findings:?}"
    );
    assert!(findings.contains(&NOT_ISSUER_KEY), "{findings:?}");
    assert!(
        report.verify.findings().iter().any(|f| matches!(
            &f.detail,
            FindingDetail::CallerKeyTypeUnsupported { kty, crv: Some(crv), .. }
                if kty == "OKP" && crv == "Ed448"
        )),
        "{findings:?}"
    );
    let caller = &proof.key_provenance.keys[0];
    assert_eq!(caller.kinds, [KeySource::CallerSupplied]);
    assert_eq!(caller.refused, Some(Refusal::TypeUnsupported));
    assert_eq!(members(caller), [(0, None)]);
}

/// A caller-supplied key unlike the issuer key is an error attributed to caller policy;
/// without the override, the issuer key decides (ARCHITECTURE §8, rule 1).
#[test]
fn a_caller_key_unlike_the_issuer_key_is_a_policy_error() {
    let report = verified_with_key_set(&signed(|_, _| {}), &json!({"keys": [other_jwk()]}));
    let (proof, findings) = proof_of(&report);
    assert_eq!(findings, [NOT_ISSUER_KEY]);
    let provenance = &proof.key_provenance;
    let [caller, issuer] = provenance.keys.as_slice() else {
        panic!("two keys: {provenance:?}")
    };
    assert_eq!(caller.kinds, [KeySource::CallerSupplied]);
    assert_eq!(members(caller), [(0, None)]);
    assert_eq!(caller.proof, ProofOutcome::Incorrect);
    assert_eq!(issuer.kinds, [KeySource::IssuerIdentifier]);
    assert_eq!(provenance.deciding, Some(1));
    assert!(
        report.verify.findings().iter().any(|f| matches!(
            &f.detail,
            FindingDetail::CallerKeyNotIssuerKey { caller_key, issuer_key }
                if caller_key.thumbprint == caller.thumbprint
                    && issuer_key.thumbprint == issuer.thumbprint
        )),
        "{findings:?}"
    );
}

/// With an issuer key vcrd cannot obtain, a member whose key's proof is correct and whose
/// `kid` is not the header's: with strict checks, listed, refused, named by its own
/// finding, and the refused caller-supplied key that stands in decides; with lenient
/// checks, it decides, with a warning. The member whose key did not sign is not listed.
#[test]
fn with_no_issuer_key_a_member_with_another_kid_decides_only_when_lenient() {
    let mut signer = issuer_jwk();
    signer["kid"] = json!("k1");
    let mut other = other_jwk();
    other["kid"] = json!("k2");
    let credential = signed(|h, p| {
        h["kid"] = json!("https://issuer.example/keys#missing");
        p["issuer"] = json!("https://issuer.example");
    });
    let key_set = json!({"keys": [signer, other]});
    let report = verified_with_key_set(&credential, &key_set);
    let (proof, findings) = proof_of(&report);
    assert!(findings.contains(&NOT_FOUND), "{findings:?}");
    assert!(
        findings.contains(&(KID_NOT_HEADER_KID, Attribution::Policy, Severity::Error)),
        "{findings:?}"
    );
    assert!(
        !findings
            .iter()
            .any(|(code, _, _)| *code == "verify.non_deciding_key_proof_correct"),
        "{findings:?}"
    );
    let provenance = &proof.key_provenance;
    let [stand_in, signer] = provenance.keys.as_slice() else {
        panic!("two keys: {provenance:?}")
    };
    assert_eq!(stand_in.refused, Some(Refusal::CallerKeyNotFound));
    assert_eq!(provenance.deciding, Some(0));
    assert_eq!(signer.kinds, [KeySource::CallerSupplied]);
    assert_eq!(
        (members(signer), signer.refused),
        (vec![(0, Some("k1"))], Some(Refusal::KidNotHeaderKid))
    );
    assert!(matches!(signer.proof, ProofOutcome::Correct { .. }));

    let report = verified_leniently(&credential, &key_set);
    let (proof, findings) = proof_of(&report);
    assert!(
        findings.contains(&(KID_NOT_HEADER_KID, Attribution::Policy, Severity::Warning)),
        "{findings:?}"
    );
    assert!(
        findings.iter().all(|(_, _, s)| *s != Severity::Error),
        "{findings:?}"
    );
    let [signer] = proof.key_provenance.keys.as_slice() else {
        panic!("one key: {:?}", proof.key_provenance)
    };
    assert_eq!(members(signer), [(0, Some("k1"))]);
    assert!(matches!(proof.outcome, ProofOutcome::Correct { .. }));
}

/// An `oct` member is kept, and, as the sole eligible key of an `HS256` proof, refused
/// until slice 8: it has no thumbprint, and its `k` is masked unless the caller's
/// designations show secrets.
#[test]
fn an_oct_member_is_refused_and_its_secret_masked() {
    let report = verified_with_key_set(
        &signed(|h, _| h["alg"] = json!("HS256")),
        &json!({"keys": [oct_jwk()]}),
    );
    let (proof, findings) = proof_of(&report);
    assert!(
        report.verify.findings().iter().any(|f| matches!(
            &f.detail,
            FindingDetail::CallerKeyTypeUnsupported { kty, crv: None, .. } if kty == "oct"
        )),
        "{findings:?}"
    );
    let caller = &proof.key_provenance.keys[0];
    assert_eq!(caller.refused, Some(Refusal::TypeUnsupported));
    assert_eq!(members(caller), [(0, None)]);
    assert_eq!(caller.thumbprint, None);
    assert_eq!(
        caller.jwk,
        Some(PublicJwk {
            members: vec![("kty", "oct".to_owned())]
        })
    );
    assert_eq!(
        caller.secret,
        Some(KeySecret {
            parameter: "k",
            value: None
        })
    );
}

/// REQUIREMENTS §4 blocks verify for want of key material only when no source of keys
/// remains: the caller's key set is one, so a credential with no issuer is verified
/// with it, and inspect's error still fails the result.
#[test]
fn a_key_set_lets_verify_run_without_an_issuer() {
    let credential = signed(|h, p| {
        p.as_object_mut().unwrap().remove("issuer");
        h.as_object_mut().unwrap().remove("kid");
    });
    let report = verified_with_key_set(&credential, &json!({"keys": [issuer_jwk()]}));
    let (proof, findings) = proof_of(&report);
    assert!(
        findings.contains(&(
            "inspect.issuer_missing",
            Attribution::Input,
            Severity::Error
        )),
        "{findings:?}"
    );
    let provenance = &proof.key_provenance;
    assert_eq!(provenance.deciding, Some(0), "{provenance:?}");
    assert_eq!(members(&provenance.keys[0]), [(0, None)]);
    assert!(matches!(proof.outcome, ProofOutcome::Correct { .. }));
}

// The override (ARCHITECTURE §8, rule 1; DEVELOPMENT-PLAN.md, milestone 2, decided
// 2026-11-13 and 2026-11-18).

const OVERRIDDEN: (&str, Attribution, Severity) = (
    "verify.issuer_key_overridden",
    Attribution::Policy,
    Severity::Warning,
);

/// A caller-supplied key unlike the issuer key, with its proof correct: an error without
/// the override, and with it the deciding proof key, with a warning that names the issuer
/// key and its proof's result.
#[test]
fn the_override_lets_a_caller_key_unlike_the_issuer_key_decide() {
    let credential = signed_by_other(|_, _| {});
    let key_set = json!({"keys": [other_jwk()]});
    let report = verified_overriding(&credential, &key_set, false);
    let (proof, findings) = proof_of(&report);
    assert!(findings.contains(&NOT_ISSUER_KEY), "{findings:?}");
    assert!(!findings.contains(&OVERRIDDEN), "{findings:?}");
    assert_eq!(proof.key_provenance.deciding, Some(1));
    assert_eq!(proof.outcome, ProofOutcome::Incorrect);

    let report = verified_overriding(&credential, &key_set, true);
    let (proof, findings) = proof_of(&report);
    assert_eq!(findings, [OVERRIDDEN]);
    let provenance = &proof.key_provenance;
    assert_eq!(provenance.deciding, Some(0));
    assert!(matches!(proof.outcome, ProofOutcome::Correct { .. }));
    let issuer = &provenance.keys[1];
    assert!(
        report.verify.findings().iter().any(|f| matches!(
            &f.detail,
            FindingDetail::IssuerKeyOverridden { issuer_key, proof: ProofOutcome::Incorrect }
                if issuer_key.thumbprint == issuer.thumbprint
        )),
        "{findings:?}"
    );

    // With strict checks, a member whose `kid` is not the header's is not eligible: the
    // refused key that stands in decides with the override, the findings say why, and no
    // key overrides the issuer key.
    let mut elsewhere = other_jwk();
    elsewhere["kid"] = json!("elsewhere");
    let report = verified_overriding(&credential, &json!({"keys": [elsewhere]}), true);
    let (proof, findings) = proof_of(&report);
    assert!(findings.contains(&NOT_FOUND), "{findings:?}");
    assert!(
        findings.contains(&(KID_NOT_HEADER_KID, Attribution::Policy, Severity::Error)),
        "{findings:?}"
    );
    assert!(!findings.contains(&OVERRIDDEN), "{findings:?}");
    assert_eq!(proof.key_provenance.deciding, Some(0));
}

/// The overridden issuer key's correct proof is said once, by the warning that names it,
/// rather than again as a correct proof that does not count.
#[test]
fn an_overridden_issuer_keys_correct_proof_is_named_once() {
    let report = verified_overriding(&signed(|_, _| {}), &json!({"keys": [other_jwk()]}), true);
    let (proof, findings) = proof_of(&report);
    assert!(findings.contains(&OVERRIDDEN), "{findings:?}");
    assert!(
        !findings
            .iter()
            .any(|(code, _, _)| *code == "verify.non_deciding_key_proof_correct"),
        "{findings:?}"
    );
    assert!(
        report.verify.findings().iter().any(|f| matches!(
            &f.detail,
            FindingDetail::IssuerKeyOverridden {
                proof: ProofOutcome::Correct { .. },
                ..
            }
        )),
        "{findings:?}"
    );
    assert_eq!(proof.outcome, ProofOutcome::Incorrect);
}

/// A finding that refuses a key that does not decide is a warning, so that the outcome
/// follows the rules: an issuer key vcrd cannot use, set aside by the override, does not
/// fail verify; deciding, it does.
#[test]
fn a_refused_issuer_key_that_does_not_decide_is_a_warning() {
    // ed448-pub (0x1203), which vcrd names and does not plan to implement.
    let multibase = format!(
        "z{}",
        bs58::encode([&[0x83, 0x24][..], &[9; 57][..]].concat()).into_string()
    );
    let issuer = format!("did:key:{multibase}");
    let credential = signed(|h, p| {
        h["kid"] = json!(format!("{issuer}#{multibase}"));
        p["issuer"] = json!(issuer);
    });
    let key_set = json!({"keys": [issuer_jwk()]});
    const UNSUPPORTED: &str = "verify.did_key_codec_unsupported";
    let report = verified_overriding(&credential, &key_set, false);
    let (_, findings) = proof_of(&report);
    assert!(
        findings.contains(&(UNSUPPORTED, Attribution::Vcrd, Severity::Error)),
        "{findings:?}"
    );
    let report = verified_overriding(&credential, &key_set, true);
    let (proof, findings) = proof_of(&report);
    assert_eq!(
        findings,
        [
            (UNSUPPORTED, Attribution::Vcrd, Severity::Warning),
            OVERRIDDEN
        ]
    );
    assert_eq!(proof.key_provenance.deciding, Some(0));
    assert!(matches!(proof.outcome, ProofOutcome::Correct { .. }));
}
