//! The committed examples of key sets in fixtures/, each a credential and the key set to
//! verify it with, which tests/support/generate.rs produces (DEVELOPMENT-PLAN.md,
//! milestone 2, decided 2026-11-18, 2026-11-24 and 2026-11-25). One test fails when a
//! committed file differs from what the generator produces, and another when an example
//! has no row in fixtures/README.md. The third, ignored by default, rewrites them:
//!
//! ```text
//! cargo test -p vcrd-cli --test key_set_examples -- --ignored regenerate
//! ```

#[cfg(test)]
mod support;

use std::fs;

use helpers::{codes, finding, header_kid, verified};
use serde_json::json;
use support::fixture;
use support::generate::{KEY_SET_EXAMPLES, KEY_SET_KID_SIGNER, key_set_example};

#[test]
fn committed_examples_match_the_generator() {
    for name in KEY_SET_EXAMPLES {
        let (credential, key_set) = key_set_example(name);
        for (file, generated) in [
            (format!("{name}.jwt"), credential),
            (format!("{name}.jwks.json"), key_set),
        ] {
            let committed = fs::read(fixture(&file))
                .unwrap_or_else(|e| panic!("fixtures/{file}: {e}; run the regenerate test"));
            assert!(
                committed == generated,
                "fixtures/{file} differs from the generator; run the regenerate test"
            );
        }
    }
}

/// fixtures/README.md is where a reader learns what each example shows, with one row for
/// the credential and its key set.
#[test]
fn every_example_is_in_the_readme_table() {
    let readme = fs::read_to_string(fixture("README.md")).unwrap();
    for name in KEY_SET_EXAMPLES {
        assert!(
            readme.contains(&format!("| `{name}.jwt`, `{name}.jwks.json` |")),
            "{name} has no row in fixtures/README.md"
        );
    }
}

#[test]
#[ignore = "rewrites the committed examples"]
fn regenerate() {
    for name in KEY_SET_EXAMPLES {
        let (credential, key_set) = key_set_example(name);
        fs::write(fixture(&format!("{name}.jwt")), credential).unwrap();
        fs::write(fixture(&format!("{name}.jwks.json")), key_set).unwrap();
    }
}

/// The generator repeats the curated example's header and payload, which vcrd-core's
/// generator produces: this example carries them, signed by another key.
#[test]
fn caller_key_unlike_issuer_is_the_curated_example_signed_by_another_key() {
    let example = fs::read_to_string(support::EXAMPLE).unwrap();
    let credential = fs::read_to_string(fixture("caller-key-unlike-issuer.jwt")).unwrap();
    let signing_input = |jws: &str| jws.trim().rsplit_once('.').unwrap().0.to_owned();
    assert_eq!(signing_input(&credential), signing_input(&example));
    assert_ne!(credential.trim(), example.trim());
}

/// A caller-supplied key unlike a `did:key` issuer key, with its proof correct: an error
/// attributed to caller policy without `--allow-key-override`, and with it the caller's
/// key decides, and a warning names the issuer key and its incorrect proof (milestone 2's
/// exit criteria).
#[test]
fn a_caller_key_unlike_the_issuer_key_decides_only_with_the_override() {
    let without = verified("caller-key-unlike-issuer", &[], 5);
    assert_eq!(
        codes(&without, "error"),
        [
            "verify.caller_key_not_issuer_key",
            "verify.signature_invalid"
        ],
        "{without}"
    );
    let with = verified("caller-key-unlike-issuer", &["--allow-key-override"], 0);
    let overridden = finding(&with, "verify.issuer_key_overridden");
    assert_eq!(overridden["severity"], "warning", "{with}");
    assert_eq!(overridden["detail"]["proof"], "incorrect", "{with}");
}

/// Of several members, the one whose key signed is the caller-supplied key, named by its
/// position and `kid`; the others' keys, whose proofs are incorrect, are not listed. The
/// generator's JWK Thumbprint URI, the `kid`, names the thumbprint vcrd computes.
#[test]
fn the_signers_member_is_chosen_among_several() {
    let out = verified("key-set-kid", &[], 0);
    let provenance = &out["proofs"][0]["key_provenance"];
    assert_eq!(provenance["deciding"], 0, "{out}");
    let key = &provenance["keys"][0];
    assert_eq!(provenance["keys"], json!([key]), "one key: {out}");
    let kid = header_kid(&out);
    assert_eq!(
        key["members"],
        json!([{"index": KEY_SET_KID_SIGNER, "kid": kid}]),
        "{out}"
    );
    let thumbprint = key["thumbprint"].as_str().unwrap();
    assert!(
        kid.as_str()
            .unwrap()
            .ends_with(&format!(":sha-256:{thumbprint}")),
        "{out}"
    );
    assert_eq!(
        codes(&out, "warning"),
        ["verify.issuer_key_not_obtained"],
        "{out}"
    );
}

/// The signer's member names its key by another `kid` than the header's: strict checks
/// make the member ineligible, and no key decides; lenient ones let it decide, with a
/// warning (DEVELOPMENT-PLAN.md, milestone 2, decided 2026-11-24).
#[test]
fn a_members_kid_unlike_the_headers_decides_only_when_lenient() {
    let name = "key-set-kid-not-header-kid";
    let strict = verified(name, &["--key-set-checks", "strict"], 5);
    assert_eq!(
        codes(&strict, "error"),
        [
            "verify.caller_key_not_found",
            "verify.key_set_kid_not_header_kid"
        ],
        "{strict}"
    );
    let lenient = verified(name, &["--key-set-checks", "lenient"], 0);
    assert_eq!(
        finding(&lenient, "verify.key_set_kid_not_header_kid")["severity"],
        "warning",
        "{lenient}"
    );
}

/// In a `#[cfg(test)]` module so that the workspace's panic lints exempt it, as they do
/// test functions (docs/reviews/milestone-0.md, gap 1).
#[cfg(test)]
mod helpers {
    use serde_json::Value;

    use super::support::{NOW, fixture, json, vcrd};

    /// `vcrd verify` of an example with its key set, at the tests' clock, with any
    /// further arguments: the JSON result, after asserting the exit code.
    pub fn verified(name: &str, extra: &[&str], code: i32) -> Value {
        json(
            vcrd()
                .arg("verify")
                .arg(fixture(&format!("{name}.jwt")))
                .args(["--now", NOW, "--key-set"])
                .arg(fixture(&format!("{name}.jwks.json")))
                .args(extra),
            code,
        )
    }

    /// The codes of the findings of this severity, sorted.
    pub fn codes(out: &Value, severity: &str) -> Vec<String> {
        let mut codes: Vec<String> = out["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["severity"] == severity)
            .map(|f| f["code"].as_str().unwrap().to_owned())
            .collect();
        codes.sort();
        codes
    }

    /// The one finding with this code.
    pub fn finding<'a>(out: &'a Value, code: &str) -> &'a Value {
        let found: Vec<&Value> = out["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["code"] == code)
            .collect();
        assert_eq!(found.len(), 1, "{code}: {out}");
        found[0]
    }

    /// The header's `kid`, as vcrd reports it.
    pub fn header_kid(out: &Value) -> Value {
        out["format"]["header"]
            .as_array()
            .unwrap()
            .iter()
            .find(|leaf| leaf["path"] == "kid")
            .unwrap()["value"]
            .clone()
    }
}
