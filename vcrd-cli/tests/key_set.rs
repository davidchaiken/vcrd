//! `--key-set`: the caller's keys, a JWK Set (RFC 7517 §5). A file vcrd cannot use as
//! one is a caller error, exit 1, whichever subcommand runs (DEVELOPMENT-PLAN.md,
//! milestone 2, decided 2026-11-18).

#[cfg(test)]
mod support;

use std::path::PathBuf;

use helpers::{caller_error, example_issuer_key_and_kid, key_set_file, verified};
use serde_json::{Value, json};
use support::{EXAMPLE, NOW, json, vcrd};
use vcrd_core::Limits;

/// In a `#[cfg(test)]` module so that the workspace's panic lints exempt it, as
/// they do test functions (docs/reviews/milestone-0.md, gap 1).
#[cfg(test)]
mod helpers {
    use std::path::{Path, PathBuf};

    use serde_json::Value;

    use super::support::{EXAMPLE, NOW, json, vcrd};

    /// Writes `contents` to a file of this name in the tests' scratch directory, which
    /// Cargo provides, and returns its path.
    pub fn key_set_file(name: &str, contents: &[u8]) -> PathBuf {
        let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    /// `vcrd verify` of the curated example with `--key-set`, in the output format given,
    /// with any further arguments: standard output, whatever the exit code.
    pub fn verified(key_set: &Path, format: &str, extra: &[&str]) -> String {
        let output = vcrd()
            .args(["verify", EXAMPLE, "--now", NOW, "--format", format])
            .args(extra)
            .arg("--key-set")
            .arg(key_set)
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap()
    }

    /// The curated example's issuer key as a JWK, and its header's `kid`, as vcrd reports
    /// them.
    pub fn example_issuer_key_and_kid() -> (Value, String) {
        let out = json(vcrd().args(["verify", EXAMPLE, "--now", NOW]), 0);
        let jwk = out["proofs"][0]["key_provenance"]["keys"][0]["jwk"].clone();
        let kid = out["format"]["header"]
            .as_array()
            .unwrap()
            .iter()
            .find(|leaf| leaf["path"] == "kid")
            .unwrap()["value"]
            .as_str()
            .unwrap()
            .to_owned();
        (jwk, kid)
    }

    /// The caller error a command line with `--key-set` gives: its code and message.
    pub fn caller_error(subcommand: &str, key_set: &Path) -> (String, String) {
        let out = json(
            vcrd()
                .args([subcommand, EXAMPLE, "--now", NOW, "--key-set"])
                .arg(key_set),
            1,
        );
        assert_eq!(out["status"], "caller_error", "{out}");
        let error = &out["error"];
        (
            error["code"].as_str().unwrap().to_owned(),
            error["message"].as_str().unwrap().to_owned(),
        )
    }
}

#[test]
fn an_unreadable_key_set_is_a_caller_error_that_names_the_file() {
    let missing = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("no-such-key-set.json");
    let (code, message) = caller_error("verify", &missing);
    assert_eq!(code, "key_set_unreadable");
    assert!(message.contains("no-such-key-set.json"), "{message}");
}

/// RFC 7517 §5: a single JWK is not a JWK Set, and the message says what was found.
/// Read for inspect too, so that a bad file is always reported.
#[test]
fn a_single_jwk_is_a_caller_error_for_either_subcommand() {
    let jwk =
        json!({"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"});
    let path = key_set_file("single-jwk.json", jwk.to_string().as_bytes());
    for subcommand in ["verify", "inspect"] {
        let (code, message) = caller_error(subcommand, &path);
        assert_eq!(code, "key_set_invalid", "{subcommand}");
        assert!(message.contains("a single JWK"), "{subcommand}: {message}");
        assert!(
            message.contains("single-jwk.json"),
            "{subcommand}: {message}"
        );
    }
}

/// The key set's size is capped before it is parsed (ARCHITECTURE §4); the CLI has no
/// flag to raise the cap until milestone 3's configuration file. The oversize file is
/// generated here rather than committed.
#[test]
fn a_key_set_over_the_size_limit_is_a_caller_error() {
    let limit = Limits::default().max_key_set_bytes;
    let set = r#"{"keys": []}"#;
    // Padded with whitespace, which JSON allows, to one byte past the limit.
    let set = format!("{set}{}", " ".repeat(limit + 1 - set.len()));
    let path = key_set_file("oversize.json", set.as_bytes());
    let (code, message) = caller_error("verify", &path);
    assert_eq!(code, "key_set_too_large");
    assert!(message.contains(&limit.to_string()), "{message}");
}

/// A key set is consulted by verify alone: inspect runs as it does without one.
#[test]
fn inspect_reads_a_key_set_and_does_not_consult_it() {
    let path = key_set_file("one-unknown-entry.json", br#"{"keys": [{"kty": "XYZ"}]}"#);
    let out = json(
        vcrd()
            .args(["inspect", EXAMPLE, "--now", NOW, "--key-set"])
            .arg(&path),
        0,
    );
    assert_eq!(out["findings"], json!([]), "{out}");
}

/// An ignored entry is reported by verify, with its position and why (docs/findings.md).
#[test]
fn verify_reports_an_ignored_entry() {
    let path = key_set_file(
        "one-ignored-entry.json",
        br#"{"keys": [{"kty": "XYZ", "kid": "k0"}]}"#,
    );
    let output = vcrd()
        .args([
            "verify",
            EXAMPLE,
            "--now",
            NOW,
            "--format",
            "json",
            "--key-set",
        ])
        .arg(&path)
        .output()
        .unwrap();
    let out: Value = serde_json::from_slice(&output.stdout).unwrap();
    let ignored: Vec<&Value> = out["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"] == "verify.key_set_entry_ignored")
        .collect();
    assert_eq!(
        ignored,
        [&json!({
            "code": "verify.key_set_entry_ignored",
            "phase": "verify",
            "attribution": "policy",
            "severity": "warning",
            "detail": {
                "type": "key_set_entry_ignored",
                "index": 0,
                "kid": "k0",
                "problem": {"kty_unknown": "XYZ"},
            },
        })],
        "{out}"
    );
}

/// A matched caller-supplied key says which entry it is and how it was matched, in each
/// output format (docs/output.md).
#[test]
fn a_matched_caller_key_shows_its_kid_and_how_it_was_matched() {
    let (mut jwk, kid) = example_issuer_key_and_kid();
    jwk["kid"] = json!(kid);
    let set = json!({"keys": [jwk]}).to_string();
    let path = key_set_file("example-issuer-key.json", set.as_bytes());
    let out: Value = serde_json::from_str(&verified(&path, "json", &[])).unwrap();
    assert_eq!(out["exit_code"], 0, "{out}");
    let key = &out["proofs"][0]["key_provenance"]["keys"][0];
    assert_eq!(
        key["kinds"],
        json!(["caller_supplied", "issuer_identifier"]),
        "{out}"
    );
    assert_eq!(
        (&key["kid"], &key["matched_by"]),
        (&json!(kid), &json!("kid"))
    );
    let plain = verified(&path, "plain", &[]);
    for line in [
        format!("proofs[0].key_provenance.keys[0].kid: {kid}"),
        "proofs[0].key_provenance.keys[0].matched_by: kid".to_owned(),
    ] {
        assert!(plain.lines().any(|l| l == line), "{line}\n{plain}");
    }
    let text = verified(&path, "text", &[]);
    assert!(text.contains("matched by kid, and issuer key"), "{text}");
}

/// An `oct` key's `k` is a secret: left out of `jwk` and listed in `masked` below
/// `--unsafe=2`, shown and listed in `reveals` at it (DEVELOPMENT-PLAN.md, milestone 2,
/// decided 2026-11-16).
#[test]
fn an_oct_keys_secret_is_shown_only_at_unsafe_2() {
    const K: &str = "c2VjcmV0IGtleSBtYXRlcmlhbA";
    let set = json!({"keys": [{"kty": "oct", "k": K}]}).to_string();
    let path = key_set_file("oct.json", set.as_bytes());
    let key_reveal = json!({
        "path": "[0].key_provenance.keys[0].jwk.k",
        "location": "proofs",
        "visibility": "revealed",
    });
    for (unsafe_level, jwk, masked, revealed) in [
        ("--unsafe=1", json!({"kty": "oct"}), json!(["k"]), false),
        (
            "--unsafe=2",
            json!({"kty": "oct", "k": K}),
            Value::Null,
            true,
        ),
    ] {
        let out: Value = serde_json::from_str(&verified(&path, "json", &[unsafe_level])).unwrap();
        let key = &out["proofs"][0]["key_provenance"]["keys"][0];
        assert_eq!(
            (&key["jwk"], &key["masked"]),
            (&jwk, &masked),
            "{unsafe_level}: {out}"
        );
        let reveals = out["reveals"].as_array().unwrap();
        assert_eq!(
            reveals.contains(&key_reveal),
            revealed,
            "{unsafe_level}: {out}"
        );
    }
}
