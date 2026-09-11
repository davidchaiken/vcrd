//! Black-box tests over the real binary. Every assertion names a *specific* finding
//! code and exit code -- §6 makes diagnosability a testable property, so testing that
//! "something failed" would miss the entire point.

use assert_cmd::Command;
use serde_json::Value;

const NOW: &str = "2026-08-22T12:00:00Z";

/// Cargo runs integration tests with the crate directory as cwd, not the workspace
/// root, so fixture paths are resolved explicitly.
fn fx(name: &str) -> String {
    format!("{}/../fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn run(args: &[&str]) -> (i32, Value) {
    let mut cmd = Command::cargo_bin("vcrd").expect("binary builds");
    let out = cmd
        .args(args)
        .args(["--now", NOW, "--format", "json"])
        .output()
        .expect("binary runs");
    let code = out.status.code().unwrap_or(-1);
    let json: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("stdout was not JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    (code, json)
}

fn codes(v: &Value) -> Vec<String> {
    v["findings"]
        .as_array()
        .map(|a| a.iter().filter_map(|f| f["code"].as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

fn stage(v: &Value, name: &str) -> String {
    v["stages"][name]["status"].as_str().unwrap_or("?").to_string()
}

// --- algorithm confusion -------------------------------------------------

#[test]
fn alg_none_is_rejected_by_name() {
    let (code, v) = run(&["verify", &fx("alg-none.jwt")]);
    assert!(codes(&v).contains(&"verify.alg_none".to_string()), "{:?}", codes(&v));
    assert_eq!(code, 4);
}

#[test]
fn hmac_keyed_with_the_issuer_public_key_fails_on_key_type() {
    let (code, v) = run(&["verify", &fx("alg-confusion-hs256.jwt")]);
    // Not "unsupported": HS256 *is* supported. The defence is the key-type check.
    assert!(codes(&v).contains(&"verify.alg_key_type_mismatch".to_string()), "{:?}", codes(&v));
    let detail = v["findings"]
        .as_array()
        .and_then(|a| a.iter().find(|f| f["code"] == "verify.alg_key_type_mismatch"))
        .cloned()
        .unwrap_or_default();
    assert_eq!(detail["detail"]["key_kind"], "EC/P-256");
    assert_eq!(detail["detail"]["expects"], "oct");
    assert_eq!(code, 4);
}

// --- algorithm policy vs support -----------------------------------------

#[test]
fn unsupported_algorithm_names_itself_and_the_supported_set() {
    let (code, v) = run(&["verify", &fx("unsupported-alg.jwt")]);
    let f = v["findings"]
        .as_array()
        .and_then(|a| a.iter().find(|f| f["code"] == "verify.alg_unsupported"))
        .cloned()
        .expect("by-name unsupported finding");
    assert_eq!(f["detail"]["declared"], "ES256K");
    assert_eq!(f["blame"], "vcrd");
    let supported = f["detail"]["supported"].as_array().cloned().unwrap_or_default();
    assert!(supported.iter().any(|s| s == "ES256"), "supported set not named: {supported:?}");
    assert_eq!(code, 6, "unsupported must not share an exit code with a bad credential");
}

#[test]
fn allowlist_rejection_is_a_distinct_diagnosis() {
    let (code, v) = run(&["verify", &fx("happy-es256.jwt"), "--allow-alg", "EdDSA"]);
    let f = v["findings"]
        .as_array()
        .and_then(|a| a.iter().find(|f| f["code"] == "verify.alg_policy_rejected"))
        .cloned()
        .expect("policy rejection finding");
    assert_eq!(f["blame"], "policy");
    assert_eq!(f["detail"]["declared"], "ES256");
    assert_eq!(code, 5);
    // The same credential with no allowlist verifies, which is what makes this a
    // policy answer rather than a credential answer.
    let (ok, _) = run(&["verify", &fx("happy-es256.jwt")]);
    assert_eq!(ok, 0);
}

#[test]
fn unsupported_and_policy_rejected_are_both_reported() {
    let (_, v) = run(&["verify", &fx("unsupported-alg.jwt"), "--allow-alg", "EdDSA"]);
    let c = codes(&v);
    assert!(c.contains(&"verify.alg_unsupported".to_string()), "{c:?}");
    assert!(c.contains(&"verify.alg_policy_rejected".to_string()), "{c:?}");
}

// --- key provenance ------------------------------------------------------

#[test]
fn embedded_key_never_overrides_an_independently_resolved_one() {
    let (code, v) = run(&["verify", &fx("embedded-jwk.jwt")]);
    assert!(codes(&v).contains(&"verify.signature_invalid".to_string()), "{:?}", codes(&v));
    assert_eq!(code, 4);
}

#[test]
fn embedded_key_alone_is_refused_without_an_opt_in() {
    let (code, v) = run(&["verify", &fx("embedded-jwk-only.jwt")]);
    assert!(codes(&v).contains(&"key.embedded_untrusted".to_string()), "{:?}", codes(&v));
    assert_eq!(code, 4);
}

#[test]
fn opting_in_to_an_embedded_key_marks_the_result() {
    let (code, v) = run(&["verify", &fx("embedded-jwk-only.jwt"), "--trust-embedded-key"]);
    // FINDING: exit 0. The caller asked for this, and it succeeded under the policy
    // they set, so a non-zero code would make the flag useless. But that means the
    // exit code alone cannot distinguish "verified against an independently
    // established key" from "verified against a key the credential supplied about
    // itself" -- the two most different results this tool produces. Only
    // `key_provenance` carries it, which is the argument for it being a v1 field.
    assert_eq!(code, 0);
    let p = &v["proofs"][0];
    assert_eq!(p["outcome"], "verified");
    assert_eq!(p["key_provenance"]["kind"], "credential_supplied");
    assert_eq!(p["key_provenance"]["independently_resolved"], false);
    assert_eq!(p["key_provenance"]["accepted"], true);
}

#[test]
fn a_good_credential_reports_independent_provenance() {
    let (code, v) = run(&["verify", &fx("happy-ed25519.jwt")]);
    assert_eq!(code, 0);
    assert_eq!(v["proofs"][0]["key_provenance"]["independently_resolved"], true);
    assert_eq!(v["proofs"][0]["key_provenance"]["via"], "did:key");
}

// --- graduated success ---------------------------------------------------

#[test]
fn expired_credential_still_reports_its_signature_as_valid() {
    // The whole point of the graduated shape: two independent facts, both kept.
    let (code, v) = run(&["verify", &fx("expired.jwt")]);
    assert_eq!(stage(&v, "validate"), "failed");
    assert_eq!(stage(&v, "verify"), "passed");
    assert!(codes(&v).contains(&"validate.expired".to_string()));
    assert_eq!(code, 3);
    // ... and the single-word status cannot express it, which is why `stages` exists.
    assert_eq!(v["status"], "validate_failed");
}

#[test]
fn not_yet_valid_is_distinct_from_expired() {
    let (code, v) = run(&["verify", &fx("not-yet-valid.jwt")]);
    assert!(codes(&v).contains(&"validate.not_yet_valid".to_string()));
    assert_eq!(code, 3);
}

#[test]
fn clock_skew_can_rescue_a_marginally_expired_credential() {
    let mut cmd = Command::cargo_bin("vcrd").expect("binary");
    let out = cmd
        .args(["verify", &fx("expired.jwt"), "--now", "2020-01-01T00:00:30Z", "--format", "json"])
        .output()
        .expect("runs");
    assert_eq!(out.status.code(), Some(3), "30s past expiry with zero skew must fail");

    let mut cmd = Command::cargo_bin("vcrd").expect("binary");
    let out = cmd
        .args([
            "verify", &fx("expired.jwt"), "--now", "2020-01-01T00:00:30Z",
            "--skew-seconds", "60", "--format", "json",
        ])
        .output()
        .expect("runs");
    assert_eq!(out.status.code(), Some(0), "60s of leeway must rescue it");
}

#[test]
fn parse_failure_blocks_the_later_tiers_explicitly() {
    let (code, v) = run(&["verify", &fx("deep-nesting.jwt")]);
    assert_eq!(stage(&v, "parse"), "failed");
    assert_eq!(stage(&v, "validate"), "not_reached");
    assert_eq!(v["stages"]["validate"]["blocked_by"], "parse");
    assert!(codes(&v).contains(&"parse.nesting_too_deep".to_string()));
    assert_eq!(code, 2);
}

#[test]
fn tampering_is_caught_at_verify_not_validate() {
    let (code, v) = run(&["verify", &fx("tampered.jwt")]);
    assert_eq!(stage(&v, "validate"), "passed");
    assert_eq!(stage(&v, "verify"), "failed");
    assert!(codes(&v).contains(&"verify.signature_invalid".to_string()));
    assert_eq!(code, 4);
}

// --- profile -------------------------------------------------------------

#[test]
fn vcdm11_mapping_is_named_and_its_disagreement_reported() {
    let (code, v) = run(&["verify", &fx("vcdm11-mapping.jwt")]);
    let c = codes(&v);
    assert!(c.contains(&"validate.profile_not_implemented".to_string()), "{c:?}");
    assert!(c.contains(&"validate.claim_disagreement".to_string()), "{c:?}");
    // Blame is vcrd, not the credential: the credential is a legal VCDM 1.1 JWT.
    let f = v["findings"]
        .as_array()
        .and_then(|a| a.iter().find(|f| f["code"] == "validate.profile_not_implemented"))
        .cloned()
        .unwrap_or_default();
    assert_eq!(f["blame"], "vcrd");
    assert_eq!(f["detail"]["detected"], "vcdm-1.1-jwt-mapping");
    assert_eq!(code, 6);
    // The signature over the 1.1 payload is perfectly good, and the report says so.
    assert_eq!(stage(&v, "verify"), "passed");
}

// --- controls ------------------------------------------------------------

#[test]
fn every_supported_algorithm_verifies() {
    for (fixture, extra) in [
        (&fx("happy-ed25519.jwt"), vec![]),
        (&fx("happy-es256.jwt"), vec![]),
        (&fx("happy-es512.jwt"), vec![]),
        (&fx("happy-rs256.jwt"), vec!["--jwks", &fx("caller-jwks.json")]),
    ] {
        let mut args = vec!["verify", fixture];
        args.extend(extra);
        let (code, v) = run(&args);
        assert_eq!(code, 0, "{fixture} did not verify: {:?}", codes(&v));
        assert_eq!(v["proofs"][0]["outcome"], "verified", "{fixture}");
    }
}

// --- output contract -----------------------------------------------------

#[test]
fn redaction_is_on_by_default_in_json() {
    let (_, v) = run(&["inspect", &fx("happy-ed25519.jwt")]);
    assert_eq!(v["unsafe_cleartext"], false);
    let claims = v["credential"]["claims"].as_array().cloned().unwrap_or_default();
    assert!(!claims.is_empty());
    for c in &claims {
        assert!(c["cleartext"].is_null(), "cleartext leaked into default output: {c}");
        assert!(c["redacted"].is_string(), "claim not redacted: {c}");
    }
    let text = serde_json::to_string(&v).unwrap_or_default();
    assert!(!text.contains("Sam Rivera-Testcase"), "a claim value survived redaction");
    assert!(!text.contains("1985-03-14"), "a birth date survived redaction");
}

#[test]
fn unsafe_marks_the_payload_and_warns_on_stderr() {
    let mut cmd = Command::cargo_bin("vcrd").expect("binary");
    let out = cmd
        .args(["inspect", &fx("happy-ed25519.jwt"), "--now", NOW, "--format", "json", "--unsafe"])
        .output()
        .expect("runs");
    let v: Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["unsafe_cleartext"], true, "an agent must be able to detect unredacted output");
    assert!(serde_json::to_string(&v).unwrap_or_default().contains("Sam Rivera-Testcase"));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("UNREDACTED"), "no human-visible warning: {err}");
}

#[test]
fn subject_is_redacted_the_same_way_as_the_claim_it_duplicates() {
    // Regression for a leak the spike found: `subject` printed in cleartext while
    // the identical `credentialSubject.id` was hashed.
    let (_, v) = run(&["inspect", &fx("happy-ed25519.jwt")]);
    let subject = v["credential"]["subject"].as_str().unwrap_or("");
    assert!(subject.starts_with('#'), "subject is not redacted: {subject}");
    let claim = v["credential"]["claims"]
        .as_array()
        .and_then(|a| a.iter().find(|c| c["path"] == "credentialSubject.id"))
        .and_then(|c| c["redacted"].as_str().map(str::to_string))
        .unwrap_or_default();
    assert_eq!(subject, claim, "the same value must redact to the same token");
}

#[test]
fn json_envelope_survives_a_parse_failure() {
    let (code, v) = run(&["verify", &fx("caller-jwks.json")]);
    assert_eq!(v["schema_version"], 1);
    assert_eq!(stage(&v, "parse"), "failed");
    assert!(v["findings"].as_array().is_some_and(|a| !a.is_empty()));
    assert_eq!(code, 2);
}

#[test]
fn json_envelope_survives_a_caller_error() {
    let (code, v) = run(&["verify", &fx("definitely-not-here.jwt")]);
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["status"], "caller_error");
    assert_eq!(v["error"]["code"], "cli.input_unreadable");
    assert_eq!(stage(&v, "parse"), "not_reached");
    assert_eq!(code, 1);
}

#[test]
fn non_checks_are_always_enumerated() {
    let (_, v) = run(&["verify", &fx("happy-ed25519.jwt")]);
    let ne = v["not_evaluated"].as_array().cloned().unwrap_or_default();
    let names: Vec<&str> = ne.iter().filter_map(|n| n["what"].as_str()).collect();
    for required in ["revocation_status", "context_resolution", "holder_binding"] {
        assert!(names.contains(&required), "{required} missing from not_evaluated: {names:?}");
    }
}

#[test]
fn verbosity_zero_prints_nothing_and_relies_on_the_exit_code() {
    let mut cmd = Command::cargo_bin("vcrd").expect("binary");
    let out = cmd
        .args(["verify", &fx("expired.jwt"), "--now", NOW, "-v", "0"])
        .output()
        .expect("runs");
    assert!(out.stdout.is_empty(), "stdout was not silent: {:?}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn bare_invocation_defaults_to_inspect() {
    let mut cmd = Command::cargo_bin("vcrd").expect("binary");
    let out = cmd
        .args([&fx("happy-ed25519.jwt"), "--now", NOW, "--format", "json"])
        .output()
        .expect("runs");
    let v: Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["stages"]["verify"]["status"], "not_reached");
    assert_eq!(v["stages"]["validate"]["status"], "passed");
}

#[test]
fn stdin_works_with_no_arguments_at_all() {
    let token = std::fs::read(fx("happy-ed25519.jwt")).expect("fixture");
    let mut cmd = Command::cargo_bin("vcrd").expect("binary");
    let out = cmd.args(["--now", NOW, "--format", "json"]).write_stdin(token).output().expect("runs");
    let v: Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["stages"]["parse"]["status"], "passed");
}

#[test]
fn capability_probes_list_something() {
    let mut cmd = Command::cargo_bin("vcrd").expect("binary");
    let out = cmd.arg("formats").output().expect("runs");
    assert!(String::from_utf8_lossy(&out.stdout).contains("jwt-vc"));
    let mut cmd = Command::cargo_bin("vcrd").expect("binary");
    let out = cmd.arg("suites").output().expect("runs");
    assert!(String::from_utf8_lossy(&out.stdout).contains("jose-jws"));
}

#[test]
fn text_output_never_signals_pass_fail_by_colour_alone() {
    let mut cmd = Command::cargo_bin("vcrd").expect("binary");
    let out = cmd.args(["verify", &fx("expired.jwt"), "--now", NOW]).output().expect("runs");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("PASS") && s.contains("FAIL"), "no textual pass/fail markers");
}
