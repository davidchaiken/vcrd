//! The verify phase: the proof's own times (RFC 7519 §4.1.4–4.1.6; ARCHITECTURE §10
//! [S6]) and the key a credential carries about itself (REQUIREMENTS §10;
//! ARCHITECTURE §8), on correctly signed inputs. The committed fixtures are tested
//! through the binary, in vcrd-cli/tests/verify.rs.

use serde_json::json;
use time::macros::datetime;
use vcrd_core::{
    Attribution, FindingDetail, KeySecret, KeySetMemberProblem, KeySource, KeySourceKind,
    MatchedBy, MemberExclusion, NotDeciding, ProofOutcome, PublicJwk, Refusal, Severity, Validity,
};

use support::{
    NOW, ed448_jwk, issuer_did_and_kid, issuer_jwk, other_jwk, proof_of, signed, signed_by_other,
    verified, verified_opted_in, verified_overriding, verified_with_key_set, verified_with_skew,
};

/// In a `#[cfg(test)]` module so that the workspace's panic lints exempt it, as
/// they do test functions (docs/reviews/milestone-0.md, gap 1).
#[cfg(test)]
mod support {
    use std::time::Duration;

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};
    use time::macros::datetime;
    use vcrd_core::{
        Attribution, Context, FixedClock, KeyPolicy, KeySet, Limits, ProofResult, Registry, Report,
        Severity, verify,
    };

    /// The tests' clock, 2026-10-01T00:00:00Z, in seconds since the Unix epoch.
    pub const NOW: i64 = 1790812800;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&Sha256::digest(b"vcrd-core verify tests: issuer").into())
    }

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// The issuer's key as a JWK (RFC 8037 §2).
    pub fn issuer_jwk() -> Value {
        json!({"kty": "OKP", "crv": "Ed25519", "x": b64(key().verifying_key().as_bytes())})
    }

    /// The issuer's `did:key`, and the `kid` [`signed`] gives the header: the DID URL of
    /// its one key.
    pub fn issuer_did_and_kid() -> (String, String) {
        let multibase = format!(
            "z{}",
            bs58::encode([&[0xed, 0x01][..], key().verifying_key().as_bytes()].concat())
                .into_string()
        );
        let issuer = format!("did:key:{multibase}");
        let kid = format!("{issuer}#{multibase}");
        (issuer, kid)
    }

    fn other_key() -> SigningKey {
        SigningKey::from_bytes(&Sha256::digest(b"vcrd-core verify tests: other").into())
    }

    /// Another key, which signs only what [`signed_by_other`] signs, as a JWK.
    pub fn other_jwk() -> Value {
        json!({"kty": "OKP", "crv": "Ed25519", "x": b64(other_key().verifying_key().as_bytes())})
    }

    /// An Ed448 public key as a JWK (RFC 8037 §2): a key type vcrd names and cannot use.
    pub fn ed448_jwk() -> Value {
        json!({"kty": "OKP", "crv": "Ed448", "x": b64(&[9; 57])})
    }

    /// A credential with a `did:key` issuer, its header and payload changed by `edit`,
    /// signed by the issuer's key. Its `alg` is `Ed25519`, not the deprecated `EdDSA`,
    /// so that each test's findings are those of its own condition (RFC 9864).
    pub fn signed(edit: impl FnOnce(&mut Value, &mut Value)) -> Vec<u8> {
        signed_by(&key(), edit)
    }

    /// As [`signed`], signed by the other key rather than the issuer's.
    pub fn signed_by_other(edit: impl FnOnce(&mut Value, &mut Value)) -> Vec<u8> {
        signed_by(&other_key(), edit)
    }

    fn signed_by(key: &SigningKey, edit: impl FnOnce(&mut Value, &mut Value)) -> Vec<u8> {
        let (issuer, kid) = issuer_did_and_kid();
        let mut header = json!({
            "alg": "Ed25519",
            "cty": "vc",
            "kid": kid,
            "typ": "vc+jwt",
        });
        let mut payload = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": issuer,
            "credentialSubject": {"id": "did:example:subject", "name": "a name"},
        });
        edit(&mut header, &mut payload);
        let signing_input = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(payload.to_string().as_bytes())
        );
        let signature = key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64(&signature.to_bytes())).into_bytes()
    }

    pub fn verified(bytes: &[u8]) -> Report {
        verified_with_skew(bytes, 0)
    }

    pub fn verified_with_skew(bytes: &[u8], skew_seconds: u64) -> Report {
        let ctx = Context::builder(FixedClock(datetime!(2026-10-01 0:00 UTC)))
            .clock_skew(Duration::from_secs(skew_seconds))
            .build();
        verify(bytes, &ctx, &Registry::builtin())
    }

    /// Verified with the caller's opt-in to an embedded key alone (ARCHITECTURE §8,
    /// rule 2).
    pub fn verified_opted_in(bytes: &[u8]) -> Report {
        let policy = KeyPolicy {
            allow_embedded_key_alone: true,
            ..KeyPolicy::default()
        };
        let ctx = Context::builder(FixedClock(datetime!(2026-10-01 0:00 UTC)))
            .key_policy(policy)
            .build();
        verify(bytes, &ctx, &Registry::builtin())
    }

    /// Verified with `key_set`, a JWK Set (RFC 7517 §5), as the caller's keys.
    pub fn verified_with_key_set(bytes: &[u8], key_set: &Value) -> Report {
        verified_with_key_set_and_policy(bytes, key_set, KeyPolicy::default())
    }

    /// Verified with the caller's opt-in to letting its key override the issuer key
    /// (ARCHITECTURE §8, rule 1), or without it.
    pub fn verified_overriding(bytes: &[u8], key_set: &Value, override_: bool) -> Report {
        let policy = KeyPolicy {
            allow_caller_key_override: override_,
            ..KeyPolicy::default()
        };
        verified_with_key_set_and_policy(bytes, key_set, policy)
    }

    fn verified_with_key_set_and_policy(
        bytes: &[u8],
        key_set: &Value,
        policy: KeyPolicy,
    ) -> Report {
        let limits = Limits::default();
        let key_set = KeySet::parse(key_set.to_string().as_bytes(), &limits).unwrap();
        let ctx = Context::builder(FixedClock(datetime!(2026-10-01 0:00 UTC)))
            .limits(limits)
            .key_set(key_set)
            .key_policy(policy)
            .build();
        verify(bytes, &ctx, &Registry::builtin())
    }

    /// The one proof's result, and every finding as (code, attribution, severity).
    pub fn proof_of(report: &Report) -> (&ProofResult, Vec<(&'static str, Attribution, Severity)>) {
        let verified = report.verify.output().expect("verify ran");
        let [proof] = verified.proofs.as_slice() else {
            panic!("one proof: {report:?}")
        };
        let findings = report
            .findings()
            .map(|f| (f.code, f.attribution, f.severity))
            .collect();
        (proof, findings)
    }
}

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

/// A member of the caller's key set that RFC 7517 §5 says to ignore, and one with
/// private parameters, are warnings attributed to caller policy, reported once, before the
/// proof's findings, and only by verify (DEVELOPMENT-PLAN.md, milestone 2, decided
/// 2026-11-18).
#[test]
fn key_set_warnings_come_once_before_the_proofs_findings() {
    let mut private = issuer_jwk();
    private["d"] = json!("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A");
    private["kid"] = json!("with-d");
    let key_set = json!({"keys": [{"kty": "XYZ", "kid": "unknown"}, private]});
    let report = verified_with_key_set(&signed(|_, _| {}), &key_set);
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

// The caller-supplied key: matching, refusals, and the findings that say why
// (DEVELOPMENT-PLAN.md, milestone 2, decided 2026-11-18).

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

/// A caller-supplied key that is the issuer key is one key with both kinds, and, matched
/// by the header's `kid`, it decides (ARCHITECTURE §8, rule 1).
#[test]
fn a_caller_key_matched_by_kid_that_is_the_issuer_key_decides() {
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
    assert_eq!(key.kid.as_deref(), Some(kid.as_str()));
    assert_eq!(key.matched_by, Some(MatchedBy::Kid));
    assert!(matches!(key.proof, ProofOutcome::Correct { .. }), "{key:?}");
}

/// The header's `kid` is resolved as inspect resolves it: a relative DID URL against the
/// DID issuer (DID Core §3.2.2).
#[test]
fn a_relative_kid_is_resolved_against_the_did_issuer_before_matching() {
    let (issuer, kid) = issuer_did_and_kid();
    let fragment = kid.strip_prefix(&issuer).unwrap().to_owned();
    let mut member = issuer_jwk();
    member["kid"] = json!(kid);
    let credential = signed(|h, p| {
        h["kid"] = json!(fragment);
        p["iss"] = json!(issuer);
    });
    let report = verified_with_key_set(&credential, &json!({"keys": [member]}));
    let (proof, _) = proof_of(&report);
    let key = &proof.key_provenance.keys[0];
    assert_eq!(key.matched_by, Some(MatchedBy::Kid), "{key:?}");
    assert_eq!(proof.key_provenance.deciding, Some(0));
}

/// The set's sole member matches when it, or the header, has no `kid`.
#[test]
fn the_sole_member_without_a_kid_matches() {
    let report = verified_with_key_set(&signed(|_, _| {}), &json!({"keys": [issuer_jwk()]}));
    let (proof, findings) = proof_of(&report);
    assert!(findings.is_empty(), "{findings:?}");
    let [key] = proof.key_provenance.keys.as_slice() else {
        panic!("one key: {:?}", proof.key_provenance)
    };
    assert_eq!(key.matched_by, Some(MatchedBy::SoleMember));
    assert_eq!(key.kid, None);
}

/// No member with the header's `kid` is a refused caller-supplied key, never a fall back to
/// the issuer key alone. Each member is then tried: one that is the issuer key joins it,
/// not matched; one whose proof is incorrect is not listed.
#[test]
fn a_kid_no_member_has_is_not_found_and_never_falls_back_to_the_issuer_key() {
    let (_, kid) = issuer_did_and_kid();
    let mut issuers = issuer_jwk();
    issuers["kid"] = json!("elsewhere");
    let mut other = other_jwk();
    other["kid"] = json!("other");
    let report = verified_with_key_set(&signed(|_, _| {}), &json!({"keys": [issuers, other]}));
    let (proof, findings) = proof_of(&report);
    assert!(findings.contains(&NOT_FOUND), "{findings:?}");
    assert!(!findings.contains(&NOT_ISSUER_KEY), "{findings:?}");
    assert!(
        report.verify.findings().iter().any(|f| matches!(
            &f.detail,
            FindingDetail::CallerKeyNotFound { kid: Some(k) } if *k == kid
        )),
        "{findings:?}"
    );
    let provenance = &proof.key_provenance;
    let [stand_in, issuer] = provenance.keys.as_slice() else {
        panic!("two keys: {provenance:?}")
    };
    assert_eq!(stand_in.kinds, [KeySource::CallerSupplied]);
    assert_eq!(stand_in.refused, Some(Refusal::CallerKeyNotFound));
    assert_eq!(
        (stand_in.thumbprint.as_ref(), stand_in.kid.as_ref()),
        (None, None)
    );
    assert_eq!(
        issuer.kinds,
        [KeySource::CallerSupplied, KeySource::IssuerIdentifier]
    );
    assert_eq!(
        (issuer.kid.as_deref(), issuer.matched_by, issuer.refused),
        (Some("elsewhere"), None, None)
    );
    assert!(matches!(issuer.proof, ProofOutcome::Correct { .. }));
    assert_eq!(provenance.deciding, Some(1));
}

/// Several members with the header's `kid`, of the key type the algorithm takes, leave
/// the caller-supplied key ambiguous.
#[test]
fn several_members_with_the_kid_are_ambiguous() {
    let (_, kid) = issuer_did_and_kid();
    let mut issuers = issuer_jwk();
    issuers["kid"] = json!(kid);
    let mut other = other_jwk();
    other["kid"] = json!(kid);
    let report = verified_with_key_set(&signed(|_, _| {}), &json!({"keys": [issuers, other]}));
    let (proof, findings) = proof_of(&report);
    assert!(
        findings.contains(&(
            "verify.caller_key_ambiguous",
            Attribution::Policy,
            Severity::Error
        )),
        "{findings:?}"
    );
    assert!(
        report.verify.findings().iter().any(|f| matches!(
            &f.detail,
            FindingDetail::CallerKeyAmbiguous { kid: Some(k), candidates }
                if *k == kid && candidates.len() == 2
        )),
        "{findings:?}"
    );
    let stand_in = &proof.key_provenance.keys[0];
    assert_eq!(stand_in.refused, Some(Refusal::CallerKeyAmbiguous));
}

/// Among members that share the `kid`, the key type the declared algorithm takes chooses:
/// `Ed25519` takes an Ed25519 key, not an Ed448 one (RFC 9864 §2.2).
#[test]
fn the_key_type_the_algorithm_takes_chooses_among_members_that_share_the_kid() {
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
    assert_eq!(key.matched_by, Some(MatchedBy::Kid));
}

/// A member's own `alg`, `use` and `key_ops` are the caller's policy: one that excludes the
/// declared algorithm refuses the key, and no proof is made with it (RFC 8725 §3.1). One
/// that allows it changes nothing.
#[test]
fn a_members_own_parameters_can_exclude_the_algorithm() {
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
        let report = verified_with_key_set(&signed(|_, _| {}), &json!({"keys": [member]}));
        let (proof, findings) = proof_of(&report);
        assert!(
            findings.contains(&(
                "verify.caller_key_excluded",
                Attribution::Policy,
                Severity::Error
            )),
            "{parameter}: {findings:?}"
        );
        assert!(
            report.verify.findings().iter().any(|f| matches!(
                &f.detail,
                FindingDetail::CallerKeyExcluded { exclusion, algorithm, .. }
                    if *exclusion == expected && algorithm == "Ed25519"
            )),
            "{parameter}: {findings:?}"
        );
        let [key] = proof.key_provenance.keys.as_slice() else {
            panic!("{parameter}: one key: {:?}", proof.key_provenance)
        };
        assert_eq!(key.refused, Some(Refusal::ExcludedByMember), "{parameter}");
        assert_eq!(key.proof, ProofOutcome::NotAttempted, "{parameter}");
    }
    let mut allowing = issuer_jwk();
    allowing["use"] = json!("sig");
    allowing["key_ops"] = json!(["verify"]);
    allowing["alg"] = json!("Ed25519");
    let report = verified_with_key_set(&signed(|_, _| {}), &json!({"keys": [allowing]}));
    let (_, findings) = proof_of(&report);
    assert!(findings.is_empty(), "{findings:?}");
}

/// With an Ed25519 key, `EdDSA` and `Ed25519` name one algorithm (RFC 8037 §3.1; RFC 9864
/// §2.2): the member is not excluded, and a warning says that a verifier comparing the
/// names would refuse it. With an Ed448 key, `EdDSA` is another algorithm.
#[test]
fn eddsa_and_ed25519_are_one_algorithm_for_an_ed25519_member() {
    const ALIAS: (&str, Attribution, Severity) = (
        "verify.caller_key_alg_alias",
        Attribution::Policy,
        Severity::Warning,
    );
    for (declared, member_alg) in [("Ed25519", "EdDSA"), ("EdDSA", "Ed25519")] {
        let mut member = issuer_jwk();
        member["alg"] = json!(member_alg);
        let credential = signed(|h, _| h["alg"] = json!(declared));
        let report = verified_with_key_set(&credential, &json!({"keys": [member]}));
        let (proof, findings) = proof_of(&report);
        assert!(findings.contains(&ALIAS), "{declared}: {findings:?}");
        assert!(
            findings.iter().all(|(_, _, s)| *s != Severity::Error),
            "{declared}: {findings:?}"
        );
        assert!(
            report.verify.findings().iter().any(|f| matches!(
                &f.detail,
                FindingDetail::CallerKeyAlgAlias { alg, declared: d, .. }
                    if alg == member_alg && d == declared
            )),
            "{declared}: {findings:?}"
        );
        assert!(matches!(proof.outcome, ProofOutcome::Correct { .. }));
    }
    // Excluded, though not the error while the issuer key decides: the key's being unlike
    // the issuer key is (DEVELOPMENT-PLAN.md, milestone 2, decided 2026-11-18).
    let mut ed448 = ed448_jwk();
    ed448["alg"] = json!("EdDSA");
    let report = verified_with_key_set(&signed(|_, _| {}), &json!({"keys": [ed448]}));
    let (_, findings) = proof_of(&report);
    assert_eq!(
        findings,
        [
            (
                "verify.caller_key_excluded",
                Attribution::Policy,
                Severity::Warning
            ),
            NOT_ISSUER_KEY,
        ]
    );
}

/// A matched key vcrd cannot use is refused, and says why. While the issuer key decides,
/// the refusal is a warning, and the key's being unlike the issuer key the error; with
/// the override, the refused caller-supplied key decides, and the refusal is the error
/// (DEVELOPMENT-PLAN.md, milestone 2, decided 2026-11-18).
#[test]
fn a_caller_key_of_a_type_vcrd_cannot_use_is_refused() {
    const UNSUPPORTED: &str = "verify.caller_key_type_unsupported";
    let overridden = verified_overriding(&signed(|_, _| {}), &json!({"keys": [ed448_jwk()]}), true);
    let (proof, findings) = proof_of(&overridden);
    assert!(
        findings.contains(&(UNSUPPORTED, Attribution::Vcrd, Severity::Error)),
        "{findings:?}"
    );
    assert_eq!(proof.key_provenance.deciding, Some(0));
    let report = verified_with_key_set(&signed(|_, _| {}), &json!({"keys": [ed448_jwk()]}));
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

/// A member tried because none matched, whose proof is correct, is listed, refused, with a
/// warning; the refused caller-supplied key decides, and verify fails.
#[test]
fn an_unmatched_member_whose_proof_is_correct_is_listed_and_refused() {
    let mut signer = issuer_jwk();
    signer["kid"] = json!("k1");
    let mut other = other_jwk();
    other["kid"] = json!("k2");
    let credential = signed(|h, p| {
        h["kid"] = json!("https://issuer.example/keys#missing");
        p["issuer"] = json!("https://issuer.example");
    });
    let report = verified_with_key_set(&credential, &json!({"keys": [signer, other]}));
    let (proof, findings) = proof_of(&report);
    assert!(findings.contains(&NOT_FOUND), "{findings:?}");
    assert!(
        findings.contains(&(
            "verify.non_deciding_key_proof_correct",
            Attribution::Input,
            Severity::Warning
        )),
        "{findings:?}"
    );
    let provenance = &proof.key_provenance;
    let [stand_in, unmatched] = provenance.keys.as_slice() else {
        panic!("two keys: {provenance:?}")
    };
    assert_eq!(stand_in.refused, Some(Refusal::CallerKeyNotFound));
    assert_eq!(provenance.deciding, Some(0));
    assert_eq!(unmatched.kinds, [KeySource::CallerSupplied]);
    assert_eq!(
        (
            unmatched.kid.as_deref(),
            unmatched.matched_by,
            unmatched.refused
        ),
        (Some("k1"), None, Some(Refusal::MemberNotMatched))
    );
    assert!(matches!(unmatched.proof, ProofOutcome::Correct { .. }));
}

/// An `oct` member is kept and, matched, refused until slice 8: it has no thumbprint, and
/// its `k` is masked unless the caller's designations show secrets.
#[test]
fn a_matched_oct_member_is_refused_and_its_secret_masked() {
    let report = verified_with_key_set(
        &signed(|_, _| {}),
        &json!({"keys": [{"kty": "oct", "k": "c2VjcmV0IGtleSBtYXRlcmlhbA"}]}),
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
    assert_eq!(caller.matched_by, Some(MatchedBy::SoleMember));
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
    assert_eq!(provenance.keys[0].matched_by, Some(MatchedBy::SoleMember));
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

    // A caller-supplied key that matching did not find decides with the override, refused;
    // its own finding says why, and no key overrides the issuer key.
    let mut unmatched = other_jwk();
    unmatched["kid"] = json!("elsewhere");
    let report = verified_overriding(&credential, &json!({"keys": [unmatched]}), true);
    let (proof, findings) = proof_of(&report);
    assert!(findings.contains(&NOT_FOUND), "{findings:?}");
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
