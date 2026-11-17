//! The `text` and `plain` output, compared with the files in `tests/expected/`, one
//! per case below (docs/output.md). A test fails when the output differs; another,
//! ignored by default, rewrites the files after a deliberate change:
//!
//! ```text
//! cargo test -p vcrd-cli --test output -- --ignored regenerate
//! ```
//!
//! Read the diff of the rewritten files before committing them.

#[cfg(test)]
mod support;

use helpers::{CASES, expected_path, run, verify, words};

/// In a `#[cfg(test)]` module so that the workspace's panic lints exempt it, as they
/// do test functions (docs/reviews/milestone-0.md, gap 1).
#[cfg(test)]
mod helpers {
    use std::path::PathBuf;

    use crate::support::{EXAMPLE, NOW, fixture, vcrd};

    /// A case: its file's name, the arguments after the operation and input, and the
    /// input, a fixture's name or text on stdin.
    pub struct Case {
        pub name: &'static str,
        pub operation: &'static str,
        pub input: Input,
        pub args: &'static [&'static str],
    }

    pub enum Input {
        Example,
        Fixture(&'static str),
        Stdin(&'static str),
        /// No operation or input: the arguments alone.
        None,
    }

    const fn case(
        name: &'static str,
        operation: &'static str,
        input: Input,
        args: &'static [&'static str],
    ) -> Case {
        Case {
            name,
            operation,
            input,
            args,
        }
    }

    pub const CASES: &[Case] = &[
        case("example-verify-text-1", "verify", Input::Example, &[]),
        case(
            "example-verify-text-2",
            "verify",
            Input::Example,
            &["--verbosity", "2"],
        ),
        case(
            "example-verify-text-3",
            "verify",
            Input::Example,
            &["--verbosity", "3"],
        ),
        case(
            "example-verify-plain-1",
            "verify",
            Input::Example,
            &["--format", "plain"],
        ),
        case(
            "example-verify-plain-3",
            "verify",
            Input::Example,
            &["--format", "plain", "--verbosity", "3"],
        ),
        case("example-inspect-text-1", "inspect", Input::Example, &[]),
        case(
            "exp-past-verify-text-1",
            "verify",
            Input::Fixture("exp-past.jwt"),
            &[],
        ),
        case(
            "issuer-missing-verify-text-1",
            "verify",
            Input::Fixture("issuer-missing.jwt"),
            &[],
        ),
        // The embedded key, refused, and the proof with it, at
        // the default level (review of slice 5, N10).
        case(
            "embedded-jwk-only-verify-text-1",
            "verify",
            Input::Fixture("embedded-jwk-only.jwt"),
            &[],
        ),
        case(
            "embedded-jwk-verify-text-2",
            "verify",
            Input::Fixture("embedded-jwk.jwt"),
            &["--verbosity", "2"],
        ),
        case(
            "canary-verify-text-2-unsafe-2",
            "verify",
            Input::Fixture("canary.jwt"),
            &["--verbosity", "2", "--unsafe=2"],
        ),
        case(
            "canary-verify-plain-2-unsafe-2",
            "verify",
            Input::Fixture("canary.jwt"),
            &["--format", "plain", "--verbosity", "2", "--unsafe=2"],
        ),
        case(
            "not-a-jws-verify-text-1",
            "verify",
            Input::Stdin("not.a.jws"),
            &[],
        ),
        case(
            "usage-error-text-1",
            "",
            Input::None,
            &["--now", "yesterday", "credential.jwt"],
        ),
    ];

    pub fn expected_path(case: &Case) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/expected")
            .join(format!("{}.txt", case.name))
    }

    /// The case's stdout.
    pub fn run(case: &Case) -> String {
        let mut command = vcrd();
        if !case.operation.is_empty() {
            command.arg(case.operation);
        }
        match case.input {
            Input::Example => {
                command.arg(EXAMPLE);
            }
            Input::Fixture(name) => {
                command.arg(fixture(name));
            }
            Input::Stdin(text) => {
                command.write_stdin(text);
            }
            Input::None => {}
        }
        if !matches!(case.input, Input::None) {
            command.args(["--now", NOW]);
        }
        let output = command.args(case.args).output().unwrap();
        String::from_utf8(output.stdout).unwrap()
    }

    /// The stdout of `verify` on this input at [`NOW`], with these arguments added.
    pub fn verify(input: &str, args: &[&str]) -> String {
        let output = vcrd()
            .args(["verify", input, "--now", NOW])
            .args(args)
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap()
    }

    /// The text with every run of whitespace made one space, so that a phrase `text`
    /// wraps across lines can be found whole.
    pub fn words(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }
}

#[test]
fn output_matches_the_expected_files() {
    for case in CASES {
        let path = expected_path(case);
        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e}; run the regenerate test", path.display()));
        let actual = run(case);
        assert!(
            actual == expected,
            "{} differs; run the regenerate test and read the diff\n--- actual:\n{actual}",
            case.name
        );
    }
}

/// docs/output.md: level 1 lists the warnings and errors, and counts the info findings
/// it leaves out, which level 2 lists. The example has one, `verify.algorithm_deprecated`.
#[test]
fn level_1_counts_the_info_findings_that_level_2_lists() {
    let stdout = |args: &[&str]| {
        let output = support::vcrd()
            .args(["verify", support::EXAMPLE, "--now", support::NOW])
            .args(args)
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap()
    };
    let count = "1 info finding (see --verbosity 2)";

    let text = stdout(&[]);
    assert!(!text.contains("verify.algorithm_deprecated"), "{text}");
    assert!(
        text.lines()
            .any(|l| l.starts_with(" Not shown") && l.ends_with(count)),
        "{text}"
    );
    let plain = stdout(&["--format", "plain"]);
    assert!(!plain.contains("verify.algorithm_deprecated"), "{plain}");
    assert!(
        plain.lines().any(|l| l == format!("findings: {count}")),
        "{plain}"
    );

    for format in ["text", "plain"] {
        let full = stdout(&["--format", format, "--verbosity", "2"]);
        assert!(full.contains("verify.algorithm_deprecated"), "{full}");
        assert!(!full.contains(count), "{full}");
    }
}

/// docs/output.md: level 1 lists the checks not evaluated at the end, after the findings,
/// and `text` names the document and section that describe them; `plain` keeps the
/// identifiers alone.
#[test]
fn level_1_lists_the_checks_not_evaluated_and_where_they_are_described() {
    let text = verify(support::EXAMPLE, &[]);
    let (_, after_findings) = text.split_once("\nFindings\n").unwrap();
    let (_, not_evaluated) = after_findings.split_once("\nNot evaluated\n").unwrap();
    assert!(
        words(not_evaluated).contains("issuer_accreditation | not_implemented"),
        "{text}"
    );
    assert_eq!(
        not_evaluated.lines().last().map(words).as_deref(),
        Some(r#"Described in docs/findings.md, section "Checks not evaluated""#),
        "{text}"
    );
    let reference =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/findings.md"))
            .unwrap();
    assert!(
        reference.lines().any(|l| l == "## Checks not evaluated"),
        "docs/findings.md has no section named so"
    );

    let plain = verify(support::EXAMPLE, &["--format", "plain"]);
    let lines: Vec<&str> = plain.lines().collect();
    let findings = lines
        .iter()
        .rposition(|l| l.starts_with("findings"))
        .unwrap();
    assert_eq!(
        &lines[findings + 1..],
        [
            "not_evaluated.issuer_accreditation: reason=not_implemented",
            "not_evaluated.context_resolution: reason=not_implemented",
        ],
        "{plain}"
    );
}

/// docs/output.md: level 1 says which kind of key the deciding proof key is, and gives
/// the proof's own validity beside the credential's, and the credential's bounds. `text`
/// says it in a phrase; `plain` keeps `kinds` and `method`. Which key, by its
/// thumbprint, waits for level 2 (decided 2026-11-16).
#[test]
fn level_1_names_the_kind_of_key_and_both_validity_periods() {
    let thumbprint = "0kK-Zjs_vVav2Mgu9S8siRJe5kiAirSKcKbBklPk90c";
    let text = words(&verify(support::EXAMPLE, &[]));
    for phrase in [
        "Credential validity current, 2026-01-01T00:00:00Z to 2031-01-01T00:00:00Z",
        "Validity unbounded",
        "Deciding proof key issuer key, from did:key",
    ] {
        assert!(text.contains(phrase), "{phrase:?} not in {text}");
    }
    assert!(!text.contains("Key source"), "{text}");
    assert!(!text.contains(thumbprint), "{text}");
    let expired = words(&verify(&support::fixture("exp-past.jwt"), &[]));
    assert!(
        expired.contains("Outcome correct Validity expired"),
        "{expired}"
    );

    let plain = verify(support::EXAMPLE, &["--format", "plain"]);
    for line in [
        "credential.validity: current",
        "credential.valid_from: 2026-01-01T00:00:00Z",
        "credential.valid_until: 2031-01-01T00:00:00Z",
        "proofs[0].validity: unbounded",
        "proofs[0].key_provenance.deciding: 0",
        "proofs[0].key_provenance.keys[0].kinds: issuer_identifier",
        "proofs[0].key_provenance.keys[0].method: did:key",
    ] {
        assert!(plain.lines().any(|l| l == line), "{line:?} not in {plain}");
    }
    assert!(!plain.contains(thumbprint), "{plain}");
}

/// docs/output.md: level 2 names every key by its thumbprint, the deciding proof key
/// and the others alike, in `text` beneath each key's line and in `plain` as each key's
/// `thumbprint`.
#[test]
fn level_2_names_every_key_by_its_thumbprint() {
    let input = support::fixture("embedded-jwk.jwt");
    let thumbprints = [
        "0kK-Zjs_vVav2Mgu9S8siRJe5kiAirSKcKbBklPk90c",
        "_i3gzFWABuHlZnuT9FBtp8CVlJ57CcWpTPwviZ2m1ms",
    ];
    let text = words(&verify(&input, &["--verbosity", "2"]));
    let position = |s: &str| {
        text.find(s)
            .unwrap_or_else(|| panic!("{s:?} not in {text}"))
    };
    let order = [
        position("Deciding proof key issuer key"),
        position(&format!("Thumbprint {}", thumbprints[0])),
        position("Other key embedded key"),
        position(&format!("Thumbprint {}", thumbprints[1])),
    ];
    assert!(
        order.windows(2).all(|w| w[0] < w[1]),
        "each thumbprint beneath its key: {text}"
    );
    let plain = verify(&input, &["--format", "plain", "--verbosity", "2"]);
    for (index, thumbprint) in thumbprints.iter().enumerate() {
        let line = format!("proofs[0].key_provenance.keys[{index}].thumbprint: {thumbprint}");
        assert!(plain.lines().any(|l| l == line), "{line:?} not in {plain}");
    }
}

/// docs/output.md: `text` describes each key in a phrase, the deciding proof key first,
/// with the other keys' proofs' results and why a key is refused; `plain` keeps the
/// values. Level 1 shows no thumbprint.
#[test]
fn level_1_describes_each_key_in_a_phrase() {
    let provenance = "proofs[0].key_provenance";
    for (fixture, phrases, values) in [
        (
            "embedded-jwk-only.jwt",
            &[
                "Deciding proof key none",
                "Other key embedded key, at header.jwk; proof correct; refused: alone, without the opt-in",
            ][..],
            vec![
                "keys[0].kinds: credential_embedded",
                "keys[0].location: header.jwk",
                "keys[0].proof: correct",
                "keys[0].refused: embedded_key_alone",
            ],
        ),
        (
            "embedded-jwk.jwt",
            &[
                "Deciding proof key issuer key, from did:key",
                "Other key embedded key, at header.jwk; proof correct",
            ][..],
            vec![
                "deciding: 0",
                "keys[0].kinds: issuer_identifier",
                "keys[0].method: did:key",
                "keys[0].proof: incorrect",
                "keys[1].kinds: credential_embedded",
                "keys[1].location: header.jwk",
                "keys[1].proof: correct",
            ],
        ),
        (
            "embedded-jwk-same.jwt",
            &["Deciding proof key issuer key, from did:key, and embedded key, at header.jwk"][..],
            vec![
                "deciding: 0",
                "keys[0].kinds: issuer_identifier, credential_embedded",
                "keys[0].method: did:key",
                "keys[0].location: header.jwk",
                "keys[0].proof: correct",
            ],
        ),
    ] {
        let input = support::fixture(fixture);
        let text = verify(&input, &[]);
        for phrase in phrases {
            assert!(words(&text).contains(phrase), "{phrase:?} not in {text}");
        }
        assert!(
            !text
                .lines()
                .any(|l| l.starts_with(" Kinds") || l.starts_with(" Proof ")),
            "{text}"
        );

        let plain = verify(&input, &["--format", "plain"]);
        let lines: Vec<&str> = plain
            .lines()
            .filter(|l| l.starts_with(provenance))
            .collect();
        let expected: Vec<String> = values.iter().map(|v| format!("{provenance}.{v}")).collect();
        assert_eq!(lines, expected, "{plain}");
    }
}

#[test]
#[ignore = "rewrites the expected output"]
fn regenerate() {
    for case in CASES {
        std::fs::write(expected_path(case), run(case)).unwrap();
    }
}
