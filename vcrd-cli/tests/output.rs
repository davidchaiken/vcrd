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

use helpers::{CASES, expected_path, run};

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

#[test]
#[ignore = "rewrites the expected output"]
fn regenerate() {
    for case in CASES {
        std::fs::write(expected_path(case), run(case)).unwrap();
    }
}
