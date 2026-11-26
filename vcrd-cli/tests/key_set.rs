//! `--key-set`: the caller's keys, a JWK Set (RFC 7517 §5), read by verify. A file vcrd
//! cannot use as one, or one `--key-set-checks strict` rejects, is a caller error, exit 1
//! (DEVELOPMENT-PLAN.md, milestone 2, decided 2026-11-18 and 2026-11-24).

#[cfg(test)]
mod support;

use std::path::PathBuf;

use helpers::{
    caller_error, example_issuer_key_and_kid, example_with_header, key_set_file, verified,
    verified_file,
};
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
        verified_file(Path::new(EXAMPLE), key_set, format, extra)
    }

    /// As [`verified`], of the credential in the file given.
    pub fn verified_file(
        credential: &Path,
        key_set: &Path,
        format: &str,
        extra: &[&str],
    ) -> String {
        let output = vcrd()
            .arg("verify")
            .arg(credential)
            .args(["--now", NOW, "--format", format])
            .args(extra)
            .arg("--key-set")
            .arg(key_set)
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap()
    }

    /// The curated example with its header replaced by `header`, a base64url-encoded JOSE
    /// header, in a file of this name in the tests' scratch directory. The signature no
    /// longer matches, which only a test of what is not verified may use.
    pub fn example_with_header(name: &str, header: &str) -> PathBuf {
        let example = std::fs::read_to_string(EXAMPLE).unwrap();
        let (_, rest) = example.trim().split_once('.').unwrap();
        key_set_file(name, format!("{header}.{rest}").as_bytes())
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
#[test]
fn a_single_jwk_is_a_caller_error() {
    let jwk =
        json!({"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"});
    let path = key_set_file("single-jwk.json", jwk.to_string().as_bytes());
    let (code, message) = caller_error("verify", &path);
    assert_eq!(code, "key_set_invalid");
    assert!(message.contains("a single JWK"), "{message}");
    assert!(message.contains("single-jwk.json"), "{message}");
}

/// With `--key-set-checks strict`, the default, a key set with problems is a caller
/// error, `key_set_rejected`, whose message names each problem; `lenient` reports each as
/// a warning and uses the rest of the set. `strict` is accepted explicitly too.
#[test]
fn a_key_set_with_problems_is_rejected_unless_lenient() {
    let (issuer_key, _) = example_issuer_key_and_kid();
    let mut private = issuer_key.clone();
    private["d"] = json!("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A");
    let mut first =
        json!({"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"});
    first["kid"] = json!("shared");
    let mut second = issuer_key;
    second["kid"] = json!("shared");
    let set = json!({"keys": [{"kty": "XYZ"}, private, first, second]}).to_string();
    let path = key_set_file("problems.json", set.as_bytes());
    for extra in [&[][..], &["--key-set-checks", "strict"]] {
        let out: Value = serde_json::from_str(&verified(&path, "json", extra)).unwrap();
        assert_eq!(out["status"], "caller_error", "{extra:?}: {out}");
        assert_eq!(out["error"]["code"], "key_set_rejected", "{out}");
        let message = out["error"]["message"].as_str().unwrap();
        for part in [
            "problems.json",
            "member 0 is one RFC 7517 §5 says to ignore",
            "member 1 carries private parameters (d)",
            "members 2, 3 share kid shared",
        ] {
            assert!(message.contains(part), "{part}: {message}");
        }
    }
    let out: Value =
        serde_json::from_str(&verified(&path, "json", &["--key-set-checks", "lenient"])).unwrap();
    let codes: Vec<&Value> = out["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| &f["code"])
        .collect();
    for code in [
        "verify.key_set_member_ignored",
        "verify.key_set_private_key",
        "verify.key_set_kid_repeated",
    ] {
        assert!(codes.contains(&&json!(code)), "{code}: {out}");
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

/// Inspect does not read the key set, as it ignores the other key options: a file that
/// does not exist changes nothing (DEVELOPMENT-PLAN.md, milestone 2, decided 2026-11-24).
#[test]
fn inspect_does_not_read_the_key_set() {
    let missing = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("no-such-key-set.json");
    let out = json(
        vcrd()
            .args(["inspect", EXAMPLE, "--now", NOW, "--key-set"])
            .arg(&missing),
        0,
    );
    assert_eq!(out["findings"], json!([]), "{out}");
}

/// With `--key-set-checks lenient`, an ignored member is reported by verify, with its
/// position and why (docs/findings.md).
#[test]
fn verify_reports_an_ignored_member() {
    let path = key_set_file(
        "one-ignored-member.json",
        br#"{"keys": [{"kty": "XYZ", "kid": "k0"}]}"#,
    );
    let out: Value =
        serde_json::from_str(&verified(&path, "json", &["--key-set-checks", "lenient"])).unwrap();
    let ignored: Vec<&Value> = out["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"] == "verify.key_set_member_ignored")
        .collect();
    assert_eq!(
        ignored,
        [&json!({
            "code": "verify.key_set_member_ignored",
            "phase": "verify",
            "attribution": "policy",
            "severity": "warning",
            "detail": {
                "type": "key_set_member_ignored",
                "index": 0,
                "kid": "k0",
                "problem": {"kty_unknown": "XYZ"},
            },
        })],
        "{out}"
    );
}

/// A caller-supplied key names each key set member it came from, by position and `kid`,
/// in each output format (docs/output.md).
#[test]
fn a_caller_key_names_the_members_it_came_from() {
    let (jwk, kid) = example_issuer_key_and_kid();
    let mut with_kid = jwk.clone();
    with_kid["kid"] = json!(kid);
    let set = json!({"keys": [with_kid, jwk]}).to_string();
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
        key["members"],
        json!([{"index": 0, "kid": kid}, {"index": 1}]),
        "{out}"
    );
    let plain = verified(&path, "plain", &[]);
    for line in [
        "proofs[0].key_provenance.keys[0].members[0].index: 0".to_owned(),
        format!("proofs[0].key_provenance.keys[0].members[0].kid: {kid}"),
        "proofs[0].key_provenance.keys[0].members[1].index: 1".to_owned(),
    ] {
        assert!(plain.lines().any(|l| l == line), "{line}\n{plain}");
    }
    let text = verified(&path, "text", &[]);
    assert!(
        text.contains("caller-supplied key, from key set members 0"),
        "{text}"
    );
}

/// A key set made from a credential, as docs/output.md's "Making a key set from a
/// credential" makes it, verifies the credential with strict checks: the issuer key's
/// `jwk`, chosen by its kinds, with the header's `kid` (DEVELOPMENT-PLAN.md, milestone 2,
/// decided 2026-11-24).
#[test]
fn a_key_set_made_from_a_credential_verifies_it() {
    let out = json(vcrd().args(["verify", EXAMPLE, "--now", NOW]), 0);
    let kid = out["format"]["header"]
        .as_array()
        .unwrap()
        .iter()
        .find(|leaf| leaf["path"] == "kid")
        .map(|leaf| leaf["value"].clone());
    let keys: Vec<Value> = out["proofs"][0]["key_provenance"]["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|key| {
            key["kinds"]
                .as_array()
                .unwrap()
                .contains(&json!("issuer_identifier"))
        })
        .map(|key| {
            let mut jwk = key["jwk"].clone();
            if let Some(kid) = &kid {
                jwk["kid"] = kid.clone();
            }
            jwk
        })
        .collect();
    assert_eq!(keys.len(), 1, "{out}");
    let set = json!({"keys": keys}).to_string();
    let path = key_set_file("made-from-the-credential.json", set.as_bytes());
    let made: Value = serde_json::from_str(&verified(&path, "json", &[])).unwrap();
    assert_eq!(made["exit_code"], 0, "{made}");
    assert_eq!(
        made["proofs"][0]["key_provenance"]["keys"][0]["kinds"],
        json!(["caller_supplied", "issuer_identifier"]),
        "{made}"
    );
}

/// An `oct` key's `k` is a secret: left out of `jwk` and listed in `masked` below
/// `--unsafe=2`, shown and listed in `reveals` at it (DEVELOPMENT-PLAN.md, milestone 2,
/// decided 2026-11-16). `HS256` takes the key, so it is the caller-supplied key.
#[test]
fn an_oct_keys_secret_is_shown_only_at_unsafe_2() {
    const K: &str = "c2VjcmV0IGtleSBtYXRlcmlhbA";
    // base64url of {"alg":"HS256","typ":"vc+jwt"}.
    const HS256_HEADER: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6InZjK2p3dCJ9";
    let credential = example_with_header("hs256.jwt", HS256_HEADER);
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
        let out: Value =
            serde_json::from_str(&verified_file(&credential, &path, "json", &[unsafe_level]))
                .unwrap();
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

/// `--allow-key-override` lets a caller-supplied key unlike the issuer key decide. With a
/// key set holding another key, the example fails on caller policy without it (exit 5);
/// with it, the other key decides and its proof is incorrect (exit 4), and a warning
/// names the issuer key's correct proof.
#[test]
fn the_override_flag_lets_the_caller_key_decide() {
    // RFC 8037 appendix A.2's public key, not the example's.
    let jwk =
        json!({"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"});
    let set = json!({"keys": [jwk]}).to_string();
    let path = key_set_file("another-key.json", set.as_bytes());
    let without: Value = serde_json::from_str(&verified(&path, "json", &[])).unwrap();
    assert_eq!(without["exit_code"], 5, "{without}");
    assert_eq!(without["proofs"][0]["key_provenance"]["deciding"], 1);
    let with: Value =
        serde_json::from_str(&verified(&path, "json", &["--allow-key-override"])).unwrap();
    assert_eq!(with["exit_code"], 4, "{with}");
    assert_eq!(with["proofs"][0]["key_provenance"]["deciding"], 0);
    let overridden: Vec<&Value> = with["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"] == "verify.issuer_key_overridden")
        .collect();
    assert_eq!(overridden.len(), 1, "{with}");
    assert_eq!(overridden[0]["detail"]["proof"], "correct", "{with}");
}
