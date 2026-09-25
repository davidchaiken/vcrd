//! The curated example through the `vcrd` binary (DEVELOPMENT-PLAN.md, milestone 1).

#[cfg(test)]
mod support;

use serde_json::json;
use support::{EXAMPLE, NOW, json, vcrd};

#[test]
fn verify_exits_0_with_one_json_document() {
    let out = json(
        vcrd().args(["verify", EXAMPLE, "--now", NOW, "--format", "json"]),
        0,
    );
    assert_eq!(out["schema_version"], 0);
    assert_eq!(out["status"], "passed");
    assert_eq!(out["exit_code"], 0);
    assert_eq!(out["reveals"], json!([]));
    assert_eq!(out["contained"], json!([]));
    for phase in ["parse", "inspect", "verify"] {
        assert_eq!(out["phases"][phase]["outcome"], "passed", "{phase}");
    }
    assert_eq!(out["input"]["format"], "vc-jose");
    assert_eq!(out["format"]["profile"], "vc-jose-cose");
    assert_eq!(out["format"]["header"]["alg"], "EdDSA");
    let proof = &out["proofs"][0];
    assert_eq!(proof["outcome"], "verified");
    assert_eq!(proof["key_provenance"]["source"], "issuer_identifier");
    assert_eq!(proof["key_provenance"]["method"], "did:key");
    assert_eq!(out["credential"]["validity"], "current");
    assert_eq!(
        out["not_evaluated"],
        json!([{"what": "issuer_accreditation", "why": "out_of_scope"}])
    );
}

/// Claim values are masked by default; names, structure and metadata are shown
/// (REQUIREMENTS §8).
#[test]
fn claims_are_masked_and_metadata_shown() {
    let output = vcrd()
        .args(["verify", EXAMPLE, "--now", NOW])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    for claim in [
        "did:example:alice",
        "Bachelor of Science",
        "urn:uuid:0d4a1f3e",
    ] {
        assert!(!stdout.contains(claim), "{claim} leaked");
    }
    let out: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let subject_id = out["credential"]["claims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["path"] == "credentialSubject.id")
        .unwrap();
    assert_eq!(
        *subject_id,
        json!({"path": "credentialSubject.id", "type": "string", "treatment": "masked"})
    );
    let valid_from = out["credential"]["metadata"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["path"] == "validFrom")
        .unwrap();
    assert_eq!(valid_from["value"], "2026-01-01T00:00:00Z");
}

/// `vcrd <file>` and piped input default to `inspect` (REQUIREMENTS §8).
#[test]
fn no_subcommand_inspects_a_file_or_standard_input() {
    let from_file = json(vcrd().args([EXAMPLE, "--now", NOW]), 0);
    assert_eq!(from_file["phases"]["verify"]["outcome"], "not_requested");
    assert_eq!(from_file["proofs"][0]["outcome"], "not_attempted");
    let piped = json(vcrd().args(["--now", NOW]).pipe_stdin(EXAMPLE).unwrap(), 0);
    assert_eq!(piped["phases"]["inspect"]["outcome"], "passed");
    assert_eq!(piped["phases"]["verify"]["outcome"], "not_requested");
}

/// Expired and correctly signed: inspect fails, verify passes, exit 3.
#[test]
fn an_expired_credential_exits_3_with_verify_passed() {
    let out = json(
        vcrd().args(["verify", EXAMPLE, "--now", "2032-01-01T00:00:00Z"]),
        3,
    );
    assert_eq!(out["status"], "inspect_failed");
    assert_eq!(
        out["phases"]["inspect"]["findings"],
        json!(["inspect.expired"])
    );
    assert_eq!(out["phases"]["verify"]["outcome"], "passed");
    let finding = &out["findings"][0];
    assert_eq!(finding["attribution"], "input");
    assert_eq!(finding["detail"]["type"], "expired");
}

/// The skew tolerance moves the boundary (REQUIREMENTS §8).
#[test]
fn clock_skew_tolerates_a_bound_just_passed() {
    let after = "2031-01-01T00:00:30Z";
    json(vcrd().args(["verify", EXAMPLE, "--now", after]), 3);
    json(
        vcrd().args(["verify", EXAMPLE, "--now", after, "--clock-skew", "60"]),
        0,
    );
}
