//! The verify phase through the binary: each negative fixture's finding code,
//! attribution and exit code, and what the proof's result says about it.

#[cfg(test)]
mod support;

use helpers::{finding, verify_fixture};
use serde_json::json;

/// In a `#[cfg(test)]` module so that the workspace's panic lints exempt it, as they
/// do test functions (docs/reviews/milestone-0.md, gap 1).
#[cfg(test)]
mod helpers {
    use serde_json::Value;

    use crate::support::{NOW, fixture, json, vcrd};

    /// Runs `vcrd verify` on a fixture and asserts the exit code.
    pub fn verify_fixture(name: &str, exit: i32) -> Value {
        json(vcrd().args(["verify", &fixture(name), "--now", NOW]), exit)
    }

    /// The one finding with this code, asserting its attribution and severity.
    pub fn finding<'a>(out: &'a Value, code: &str, attribution: &str, severity: &str) -> &'a Value {
        let found: Vec<&Value> = out["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["code"] == code)
            .collect();
        let [finding] = found[..] else {
            panic!("expected one {code}: {out}")
        };
        assert_eq!(finding["attribution"], attribution, "{out}");
        assert_eq!(finding["severity"], severity, "{out}");
        finding
    }
}

#[test]
fn a_claim_changed_after_signing_fails_the_signature() {
    let out = verify_fixture("tampered-claim.jwt", 4);
    finding(&out, "verify.signature_invalid", "input", "error");
    assert_eq!(out["phases"]["inspect"]["outcome"], "passed");
    assert_eq!(out["proofs"][0]["outcome"], "failed");
}

#[test]
fn alg_none_is_rejected() {
    let out = verify_fixture("alg-none.jwt", 4);
    finding(&out, "verify.algorithm_none", "input", "error");
    assert_eq!(out["proofs"][0]["outcome"], "not_attempted");
}

#[test]
fn an_algorithm_vcrd_does_not_implement_is_rejected_by_name() {
    let out = verify_fixture("alg-ed448.jwt", 6);
    let f = finding(&out, "verify.algorithm_unsupported", "vcrd", "error");
    assert_eq!(
        f["detail"],
        json!({"type": "algorithm_unsupported", "declared": "Ed448", "supported": ["EdDSA"]})
    );
    assert_eq!(out["proofs"][0]["outcome"], "not_attempted");
}

/// The signature would pass a verifier without the weak-key check
/// (vcrd-core/tests/fixtures.rs).
#[test]
fn a_weak_key_is_refused_at_resolution() {
    let out = verify_fixture("weak-key.jwt", 4);
    let weak = finding(&out, "verify.weak_key", "input", "error");
    let proof = &out["proofs"][0];
    assert_eq!(proof["outcome"], "not_attempted");
    assert_eq!(proof["key_provenance"]["source"], "issuer_identifier");
    // The identity point, as the issuer's `did:key` encodes it.
    assert_eq!(
        proof["key_provenance"]["jwk"]["x"],
        "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    assert_eq!(
        weak["detail"],
        json!({
            "type": "weak_key",
            "key": {
                "source": "issuer_identifier",
                "method": "did:key",
                "thumbprint": "eV9frzBXPTP92MWWMpoFOh0WI_kJLvGlhcNs15APU_s",
            },
            "criterion": "small_order",
        })
    );
}

/// The signature would pass a verifier without the small-order check
/// (vcrd-core/tests/fixtures.rs).
#[test]
fn a_small_order_r_is_named() {
    let out = verify_fixture("small-order-r.jwt", 4);
    let f = finding(&out, "verify.signature_small_order", "input", "error");
    assert_eq!(
        f["detail"],
        json!({"type": "signature_small_order", "algorithm": "EdDSA"})
    );
    assert_eq!(out["proofs"][0]["outcome"], "failed");
}

/// ARCHITECTURE §8: `matched: false` with `verifies_signature: true` is specific
/// evidence of key substitution.
#[test]
fn key_substitution_is_reported() {
    let out = verify_fixture("embedded-jwk.jwt", 4);
    finding(&out, "verify.signature_invalid", "input", "error");
    let mismatch = finding(&out, "verify.credential_key_mismatch", "input", "warning");
    let provenance = &out["proofs"][0]["key_provenance"];
    assert_eq!(provenance["source"], "issuer_identifier");
    let key = &provenance["credential_key"];
    assert_eq!(key["location"], "header.jwk");
    assert_eq!(key["matched"], false);
    assert_eq!(key["verifies_signature"], true);
    assert_ne!(key["thumbprint"], provenance["thumbprint"]);
    // Each thumbprint is shown with the key it names.
    assert_eq!(provenance["jwk"]["kty"], "OKP");
    assert_eq!(key["jwk"]["kty"], "OKP");
    assert_ne!(key["jwk"]["x"], provenance["jwk"]["x"]);
    // The finding says where each key came from.
    assert_eq!(
        mismatch["detail"],
        json!({
            "type": "credential_key_mismatch",
            "carried_key": {"location": "header.jwk", "thumbprint": key["thumbprint"]},
            "key": {
                "source": "issuer_identifier",
                "method": "did:key",
                "thumbprint": provenance["thumbprint"],
            },
        })
    );
}

/// REQUIREMENTS §10: the refusal is reported, not treated as "no key material", so
/// a credential carrying its own key is not blocked for want of an issuer.
#[test]
fn a_key_the_credential_asserts_alone_is_refused() {
    let out = verify_fixture("embedded-jwk-only.jwt", 5);
    finding(&out, "inspect.issuer_missing", "input", "error");
    let refused = finding(&out, "verify.embedded_key_refused", "policy", "error");
    assert_eq!(
        refused["detail"],
        json!({"type": "embedded_key_refused", "location": "header.jwk"})
    );
    assert_eq!(out["phases"]["verify"]["outcome"], "failed");
    assert!(out["phases"]["verify"].get("blocked_by").is_none(), "{out}");
    let proof = &out["proofs"][0];
    assert_eq!(proof["outcome"], "not_attempted");
    assert!(proof["key_provenance"].get("source").is_none(), "{out}");
    let key = &proof["key_provenance"]["credential_key"];
    assert_eq!(key["matched"], false);
    assert_eq!(key["verifies_signature"], true);
    assert_eq!(out["status"], "inspect_failed");
}

/// [S6]: the signature's own expiry, RFC 7519 §4.1.4, distinct from `validUntil`.
#[test]
fn an_expired_signature_fails_verify() {
    let out = verify_fixture("exp-past.jwt", 4);
    let f = finding(&out, "verify.proof_expired", "input", "error");
    assert_eq!(
        f["detail"],
        json!({
            "type": "proof_expired",
            "claim": "exp",
            "value": 1780272000,
            "value_date_time": "2026-06-01T00:00:00Z",
            "now": "2026-10-01T00:00:00Z",
            "skew_seconds": 0,
        })
    );
    assert_eq!(out["phases"]["inspect"]["outcome"], "passed");
    assert_eq!(out["credential"]["validity"], "current");
    let proof = &out["proofs"][0];
    assert_eq!(proof["outcome"], "verified");
    assert_eq!(proof["validity"], "expired");
}

/// RFC 7515 §4.1.11: an extension the recipient does not understand makes the JWS
/// invalid. vcrd names it, and still checks the signature, which verifies.
#[test]
fn a_critical_extension_vcrd_does_not_implement_fails_verify() {
    let out = verify_fixture("crit-unsupported.jwt", 6);
    let f = finding(&out, "verify.crit_unsupported", "vcrd", "error");
    assert_eq!(
        f["detail"],
        json!({
            "type": "crit_unsupported",
            "extensions": ["urn:example:unimplemented"],
            "supported": [],
        })
    );
    assert_eq!(out["phases"]["inspect"]["outcome"], "passed");
    assert_eq!(out["proofs"][0]["outcome"], "verified");
}

/// The example's JWT has no `exp` or `nbf`, so its signature has no validity
/// period of its own.
#[test]
fn a_proof_without_times_is_unbounded() {
    let out = support::json(
        support::vcrd().args(["verify", support::EXAMPLE, "--now", support::NOW]),
        0,
    );
    assert_eq!(out["proofs"][0]["validity"], "unbounded");
}

/// RFC 7515 §4.1: a registered Header Parameter whose value has the wrong JSON type is
/// reported as that, not as absent, and an `alg` that is not a string names no
/// algorithm (§4.1.1).
#[test]
fn a_header_member_of_the_wrong_type_is_reported() {
    let out = verify_fixture("header-member-types.jwt", 3);
    let findings = out["findings"].as_array().unwrap();
    let codes: Vec<&str> = findings
        .iter()
        .map(|f| f["code"].as_str().unwrap())
        .collect();
    for absent in [
        "inspect.kid_missing",
        "inspect.typ_unexpected",
        "inspect.cty_unexpected",
        "verify.algorithm_missing",
    ] {
        assert!(!codes.contains(&absent), "{absent}: {out}");
    }
    let members: Vec<(&str, &str)> = findings
        .iter()
        .filter(|f| f["code"] == "inspect.header_member_type")
        .map(|f| {
            assert_eq!(f["attribution"], "input", "{f}");
            assert_eq!(f["severity"], "error", "{f}");
            assert_eq!(f["detail"]["found"], "number", "{f}");
            (
                f["detail"]["member"].as_str().unwrap(),
                f["detail"]["expected"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        members,
        [
            ("alg", "string"),
            ("jku", "string"),
            ("kid", "string"),
            ("x5u", "string"),
            ("x5c", "array_of_strings"),
            ("x5t", "string"),
            ("x5t#S256", "string"),
            ("typ", "string"),
            ("cty", "string"),
        ]
    );
    let f = finding(&out, "verify.algorithm_invalid", "input", "error");
    assert_eq!(
        f["detail"],
        json!({"type": "algorithm_invalid", "found": "number"})
    );
    assert_eq!(out["proofs"][0]["outcome"], "not_attempted");
    assert_eq!(out["proofs"][0]["algorithm"], json!(null));
}

/// RFC 7519 §4.1.3: a processor not named in `aud` must reject the JWT. vcrd is not told
/// whom it verifies for until milestone 4, so it says the check was not made, without
/// failing. The example, with no `aud`, lists no such check (tests/example.rs).
#[test]
fn an_audience_is_listed_as_not_evaluated() {
    let out = verify_fixture("aud.jwt", 0);
    assert!(
        out["not_evaluated"]
            .as_array()
            .unwrap()
            .contains(&json!({"what": "audience", "why": "no_parameters_supplied"})),
        "{out}"
    );
}
