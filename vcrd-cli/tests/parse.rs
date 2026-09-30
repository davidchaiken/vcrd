//! The parse phase through the binary: limits, what is tolerated, and what is named
//! (DEVELOPMENT-PLAN.md, milestone 1).

#[cfg(test)]
mod support;

use serde_json::json;
use support::{EXAMPLE, NOW, fixture, json, vcrd};

/// The default size limit (ARCHITECTURE §4, provisional).
const SIZE_LIMIT: u64 = 256 * 1024;

#[test]
fn reports_the_payload_depth() {
    let out = json(vcrd().args(["verify", EXAMPLE, "--now", NOW]), 0);
    assert_eq!(out["input"]["depth"], 3);
}

/// A trailing newline is ignored and reported; nothing else changes.
#[test]
fn a_trailing_newline_is_reported_for_information() {
    let mut bytes = std::fs::read(EXAMPLE).unwrap();
    bytes.push(b'\n');
    let out = json(vcrd().args(["verify", "--now", NOW]).write_stdin(bytes), 0);
    assert_eq!(out["status"], "passed");
    assert_eq!(
        out["phases"]["parse"]["findings"],
        json!(["parse.trailing_whitespace"])
    );
    let finding = &out["findings"][0];
    assert_eq!(finding["severity"], "info");
    assert_eq!(
        finding["detail"],
        json!({"type": "trailing_whitespace", "bytes": 1})
    );
}

/// Over the depth limit: caller policy, exit 5, found by the scan before parsing.
#[test]
fn deep_nesting_exits_5() {
    let out = json(vcrd().args(["verify", &fixture("deep-nesting.jwt")]), 5);
    assert_eq!(out["status"], "parse_failed");
    let finding = &out["findings"][0];
    assert_eq!(finding["code"], "parse.nesting_too_deep");
    assert_eq!(finding["attribution"], "policy");
    assert_eq!(
        finding["detail"],
        json!({"type": "nesting_too_deep", "segment": "payload", "limit": 32, "found": 42})
    );
    assert_eq!(out["input"]["depth"], 42);
    assert_eq!(out["phases"]["verify"]["blocked_by"]["phase"], "parse");
}

/// Recognized and named, not "no format matched": vcrd's limit, exit 6.
#[test]
fn jws_json_serialization_exits_6() {
    let out = json(
        vcrd().args(["verify", &fixture("jws-json-flattened.json")]),
        6,
    );
    let finding = &out["findings"][0];
    assert_eq!(finding["code"], "parse.jws_json_serialization");
    assert_eq!(finding["attribution"], "vcrd");
    assert_eq!(finding["detail"]["syntax"], "flattened");
}

/// Standard input over the limit: vcrd stops reading one byte past it, and says only
/// that the input is larger.
#[test]
fn oversized_standard_input_exits_5() {
    let bytes = vec![b'A'; 2 * SIZE_LIMIT as usize];
    let out = json(vcrd().arg("verify").write_stdin(bytes), 5);
    assert_eq!(out["input"]["bytes"], SIZE_LIMIT + 1);
    assert_eq!(
        out["findings"][0]["detail"],
        json!({"type": "input_too_large", "limit": SIZE_LIMIT, "read": SIZE_LIMIT + 1, "size": null})
    );
    assert_eq!(out["findings"][0]["attribution"], "policy");
}

/// A file over the limit: the same, with the file's size.
#[test]
fn an_oversized_file_reports_its_size() {
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("oversized.jwt");
    std::fs::write(&path, vec![b'A'; 4 * SIZE_LIMIT as usize]).unwrap();
    let out = json(vcrd().arg("verify").arg(&path), 5);
    let detail = &out["findings"][0]["detail"];
    assert_eq!(detail["read"], SIZE_LIMIT + 1);
    assert_eq!(detail["size"], 4 * SIZE_LIMIT);
}
