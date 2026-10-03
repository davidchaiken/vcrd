//! The inspect phase through the binary: each negative fixture's finding code,
//! attribution and exit code, and the layout of a blocked verify (docs/output.md).

#[cfg(test)]
mod support;

use helpers::verify_fixture;
use serde_json::json;
use support::{json, vcrd};

/// In a `#[cfg(test)]` module so that the workspace's panic lints exempt it, as they
/// do test functions (docs/reviews/milestone-0.md, gap 1).
#[cfg(test)]
mod helpers {
    use serde_json::Value;

    use crate::support::{NOW, fixture, json, vcrd};

    /// Runs `vcrd verify` on a fixture and asserts its first finding, an error.
    pub fn verify_fixture(name: &str, code: &str, attribution: &str, exit: i32) -> Value {
        let out = json(vcrd().args(["verify", &fixture(name), "--now", NOW]), exit);
        let finding = &out["findings"][0];
        assert_eq!(finding["code"], code, "{out}");
        assert_eq!(finding["attribution"], attribution, "{out}");
        assert_eq!(finding["severity"], "error", "{out}");
        assert_eq!(out["phases"]["inspect"]["outcome"], "failed");
        out
    }
}

/// [S3]. The signature is sound, and verify says so.
#[test]
fn validity_reversed_exits_3() {
    let out = verify_fixture(
        "validity-reversed.jwt",
        "inspect.valid_until_before_valid_from",
        "input",
        3,
    );
    assert_eq!(
        out["findings"][0]["detail"],
        json!({
            "type": "valid_until_before_valid_from",
            "valid_from": "2031-01-01T00:00:00Z",
            "valid_until": "2026-01-01T00:00:00Z",
        })
    );
    assert_eq!(out["phases"]["verify"]["outcome"], "passed");
}

/// The first inspect failure that blocks verify (REQUIREMENTS §16 item 20).
#[test]
fn issuer_missing_blocks_verify_and_says_why() {
    let out = verify_fixture("issuer-missing.jwt", "inspect.issuer_missing", "input", 3);
    assert_eq!(
        out["phases"]["verify"],
        json!({
            "outcome": "not_reached",
            "blocked_by": {
                "phase": "inspect",
                "reason": "impossible",
                "missing": "key_material",
                "consulted": ["issuer_identifier"],
            },
            "findings": [],
        })
    );
    assert_eq!(out["proofs"][0]["outcome"], "not_attempted");
    assert_eq!(out["status"], "inspect_failed");
}

/// A parse failure's block names the document as what is missing, and points at the
/// parse phase for the findings.
#[test]
fn a_parse_block_is_missing_the_document() {
    let out = json(vcrd().arg("verify").write_stdin("not.a.jws"), 2);
    for phase in ["inspect", "verify"] {
        assert_eq!(
            out["phases"][phase],
            json!({
                "outcome": "not_reached",
                "blocked_by": {"phase": "parse", "reason": "impossible", "missing": "document"},
                "findings": [],
            })
        );
    }
}

/// A phase lists each kind of finding once; the top-level list has each occurrence,
/// with its segment and problem. Here the header and the payload fail to decode, and
/// the signature decodes.
#[test]
fn a_phase_lists_each_kind_of_finding_once() {
    let out = json(vcrd().arg("verify").write_stdin("not.a.jws"), 2);
    assert_eq!(
        out["phases"]["parse"]["findings"],
        json!(["parse.base64url_invalid"])
    );
    let findings: Vec<_> = out["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| json!({"code": f["code"], "detail": f["detail"]}))
        .collect();
    assert_eq!(
        findings,
        [
            // `not`: `t` leaves non-zero bits after two whole bytes.
            json!({
                "code": "parse.base64url_invalid",
                "detail": {"type": "base64url_invalid", "segment": "header", "problem": "nonzero_trailing_bits"},
            }),
            // `a`: one character cannot encode a byte.
            json!({
                "code": "parse.base64url_invalid",
                "detail": {"type": "base64url_invalid", "segment": "payload", "problem": "invalid_length"},
            }),
        ]
    );
}

#[test]
fn iss_mismatch_exits_3_and_shows_both_values() {
    let out = verify_fixture("iss-mismatch.jwt", "inspect.iss_mismatch", "input", 3);
    let detail = &out["findings"][0]["detail"];
    assert_eq!(detail["location"], "payload");
    assert_eq!(detail["iss"], "did:example:someone-else");
    assert!(
        detail["issuer"]
            .as_str()
            .unwrap()
            .starts_with("did:key:z6Mk")
    );
    assert_eq!(out["phases"]["verify"]["outcome"], "passed");
}

/// `kid` is a conformance check; it never chooses the key, so verify passes.
#[test]
fn kid_missing_exits_3_and_verify_passes() {
    let out = verify_fixture("kid-missing.jwt", "inspect.kid_missing", "input", 3);
    assert_eq!(out["phases"]["verify"]["outcome"], "passed");
    assert_eq!(out["proofs"][0]["outcome"], "verified");
}

/// Named and attributed to vcrd, which does not read it yet (ARCHITECTURE §10 [F2]).
#[test]
fn vcdm_1_1_encoding_exits_6() {
    let out = verify_fixture(
        "vcdm-1.1-encoding.jwt",
        "inspect.vcdm_1_1_jwt_encoding",
        "vcrd",
        6,
    );
    assert_eq!(out["findings"].as_array().unwrap().len(), 1, "{out}");
    assert_eq!(out["phases"]["verify"]["outcome"], "not_reached");
    assert!(out["format"].get("profile").is_none(), "{out}");
}
