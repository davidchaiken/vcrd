//! The canary test (ARCHITECTURE §7): `fixtures/canary.jwt` holds a distinct canary
//! string in every claim leaf and one in a private member of the header's `jwk`. For
//! each format, verbosity level and `--unsafe` level, exactly the canaries that should
//! be printed are, on stdout, and none ever reaches stderr. Each canary is required
//! on stdout in some case, so a fixture that lost one would fail the test.

#[cfg(test)]
mod support;

use helpers::run;

/// One in each claim leaf.
const CLAIMS: [&str; 6] = [
    "CANARY-C1",
    "CANARY-C2",
    "CANARY-C3",
    "CANARY-C4",
    "CANARY-C5",
    "CANARY-C6",
];

/// In the header's `jwk`, as its private key `d`.
const SECRET: &str = "CANARY-S1";

/// In a `#[cfg(test)]` module so that the workspace's panic lints exempt it, as they
/// do test functions (docs/reviews/milestone-0.md, gap 1).
#[cfg(test)]
mod helpers {
    use crate::support::{NOW, fixture, vcrd};

    /// Runs `vcrd verify` on the canary fixture and returns stdout and stderr; the
    /// fixture exits 3, for its private key.
    pub fn run(format: &str, verbosity: u8, unsafe_level: u8) -> (String, String) {
        let output = vcrd()
            .args(["verify", &fixture("canary.jwt"), "--now", NOW])
            .args(["--format", format, "--verbosity", &verbosity.to_string()])
            .arg(format!("--unsafe={unsafe_level}"))
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(3),
            "{format} {verbosity} {unsafe_level}"
        );
        (
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap(),
        )
    }
}

#[test]
fn exactly_the_unmasked_canaries_are_printed() {
    for format in ["json", "text", "plain"] {
        for verbosity in 1..=3 {
            for unsafe_level in 0..=2 {
                let (stdout, stderr) = run(format, verbosity, unsafe_level);
                let case =
                    format!("--format {format} --verbosity {verbosity} --unsafe={unsafe_level}");
                // Claims are printed at every level and in every format.
                let claims_shown = unsafe_level >= 1;
                // `text` and `plain` print the header from level 2; JSON always.
                let secret_shown = unsafe_level == 2 && (format == "json" || verbosity >= 2);
                for canary in CLAIMS {
                    assert_eq!(stdout.contains(canary), claims_shown, "{canary}, {case}");
                }
                assert_eq!(stdout.contains(SECRET), secret_shown, "{SECRET}, {case}");
                for canary in CLAIMS.iter().chain([&SECRET]) {
                    assert!(!stderr.contains(canary), "{canary} on stderr, {case}");
                }
                // The warning is on stderr and, for a reader of stdout alone, in the
                // result too.
                let warned = unsafe_level > 0;
                assert_eq!(
                    stderr.contains("WARNING: --unsafe"),
                    warned,
                    "stderr, {case}"
                );
                // The message starts with the flag; `text` may wrap the rest.
                assert_eq!(
                    stdout.contains(&format!("--unsafe={unsafe_level}:")),
                    warned,
                    "stdout, {case}"
                );
            }
        }
    }
}

/// `--verbosity 0` prints nothing, so `--unsafe` unmasks nothing and warns of nothing,
/// and the exit code is the result's: neither level changes it.
#[test]
fn unsafe_with_verbosity_0_prints_nothing() {
    let output = support::vcrd()
        .args([
            "verify",
            &support::fixture("canary.jwt"),
            "--now",
            support::NOW,
        ])
        .args(["--verbosity", "0", "--unsafe", "2"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}
