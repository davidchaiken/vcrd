//! The verify phase: the proof's own times (RFC 7519 §4.1.4–4.1.6; ARCHITECTURE §10
//! [S6]) and the key a credential carries about itself (REQUIREMENTS §10;
//! ARCHITECTURE §8), on correctly signed inputs. The committed fixtures are tested
//! through the binary, in vcrd-cli/tests/verify.rs.

use serde_json::json;
use vcrd_core::{Attribution, ProofOutcome, Severity, Validity};

use support::{NOW, issuer_jwk, proof_of, signed, verified, verified_with_skew};

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
        Attribution, Context, FixedClock, ProofResult, Registry, Report, Severity, verify,
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

    /// A credential with a `did:key` issuer, its header and payload changed by `edit`,
    /// signed by the issuer's key.
    pub fn signed(edit: impl FnOnce(&mut Value, &mut Value)) -> Vec<u8> {
        let key = key();
        let multibase = format!(
            "z{}",
            bs58::encode([&[0xed, 0x01][..], key.verifying_key().as_bytes()].concat())
                .into_string()
        );
        let issuer = format!("did:key:{multibase}");
        let mut header = json!({
            "alg": "EdDSA",
            "cty": "vc",
            "kid": format!("{issuer}#{multibase}"),
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

/// RFC 7519 §4.1.5: the current time must be after or equal to `nbf`.
#[test]
fn a_not_before_after_the_clock_fails_verify() {
    let report = verified(&signed(|_, p| p["nbf"] = json!(NOW + 1)));
    let (proof, findings) = proof_of(&report);
    assert_eq!(findings, [NOT_YET_VALID]);
    assert_eq!(proof.validity, Validity::NotYetValid);
    assert!(matches!(proof.outcome, ProofOutcome::Verified { .. }));

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

/// ARCHITECTURE §8: an embedded key equal to the `did:key` is `matched: true`.
#[test]
fn an_embedded_key_equal_to_the_issuers_matches_and_verifies() {
    let report = verified(&signed(|h, _| h["jwk"] = issuer_jwk()));
    let (proof, findings) = proof_of(&report);
    assert_eq!(findings, []);
    let key = proof.key_provenance.credential_key.as_ref().unwrap();
    assert_eq!(
        (key.location.as_str(), key.matched, key.verifies_signature),
        ("header.jwk", true, Some(true))
    );
    assert_eq!(
        Some(&key.thumbprint),
        proof.key_provenance.thumbprint.as_ref()
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
    assert!(
        proof
            .key_provenance
            .credential_key
            .as_ref()
            .unwrap()
            .matched
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
    assert!(matches!(proof.outcome, ProofOutcome::Verified { .. }));
    assert_eq!(proof.key_provenance.credential_key, None);
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
    assert!(matches!(proof.outcome, ProofOutcome::Verified { .. }));
}
