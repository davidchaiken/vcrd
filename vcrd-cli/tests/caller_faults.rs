//! Caller faults: exit 1, and one JSON document on stdout when JSON is the output
//! format (REQUIREMENTS §9; ARCHITECTURE §6).

#[cfg(test)]
mod support;

use predicates::prelude::*;
use support::{json, vcrd};

/// clap's own usage-error status is 2, which vcrd assigns to a parse failure
/// (docs/reviews/milestone-0.md, gap 3).
#[test]
fn an_unknown_flag_exits_1() {
    vcrd().arg("--no-such-flag").assert().code(1);
}

#[test]
fn a_usage_error_is_one_json_document_with_the_error_filled() {
    let out = json(vcrd().args(["--format", "json", "--no-such-flag"]), 1);
    assert_eq!(out["schema_version"], 0);
    assert_eq!(out["status"], "caller_fault");
    assert_eq!(out["exit_code"], 1);
    assert_eq!(out["error"]["code"], "usage");
    assert!(
        out["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--no-such-flag")
    );
    for key in [
        "reveals",
        "proofs",
        "findings",
        "not_evaluated",
        "contained",
    ] {
        assert_eq!(out[key], serde_json::json!([]), "{key}");
    }
    assert_eq!(out["phases"]["parse"]["outcome"], "not_reached");
}

#[test]
fn an_invalid_value_is_a_usage_error() {
    let out = json(
        vcrd().args(["verify", "--now", "yesterday", support::EXAMPLE]),
        1,
    );
    assert_eq!(out["error"]["code"], "usage");
}

#[test]
fn an_unreadable_file_is_a_caller_fault() {
    let out = json(vcrd().arg("no-such-file.jwt"), 1);
    assert_eq!(out["error"]["code"], "input_unreadable");
    assert!(
        out["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no-such-file.jwt")
    );
}

#[test]
fn verbosity_0_prints_nothing_and_keeps_the_code() {
    vcrd()
        .args(["--verbosity", "0", "--no-such-flag"])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::is_empty());
}

#[test]
fn help_and_version_exit_0() {
    vcrd()
        .arg("--help")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Usage: vcrd"));
    vcrd()
        .arg("--version")
        .assert()
        .code(0)
        .stdout(format!("vcrd {}\n", env!("CARGO_PKG_VERSION")));
}
