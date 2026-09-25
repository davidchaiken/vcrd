//! The curated example through core's entry points, offline, with an injected clock
//! (REQUIREMENTS §11).

use time::macros::datetime;
use vcrd_core::{KeySource, PhaseOutcome, ProofOutcome, Registry, Validity, inspect, verify};

use support::{at, example};

/// In a `#[cfg(test)]` module so that the workspace's panic lints exempt it, as
/// they do test functions (docs/reviews/milestone-0.md, gap 1).
#[cfg(test)]
mod support {
    use time::OffsetDateTime;
    use vcrd_core::{Context, FixedClock};

    pub fn example() -> Vec<u8> {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../examples/ed25519.jwt"
        ))
        .unwrap()
    }

    pub fn at(now: OffsetDateTime) -> Context {
        Context::builder(FixedClock(now)).build()
    }
}

#[test]
fn verifies_when_current() {
    let report = verify(
        &example(),
        &at(datetime!(2026-10-01 0:00 UTC)),
        &Registry::builtin(),
    );
    assert!(
        matches!(report.parse, PhaseOutcome::Passed { .. }),
        "{report:?}"
    );
    let PhaseOutcome::Passed {
        output: inspected, ..
    } = &report.inspect
    else {
        panic!("{report:?}")
    };
    assert_eq!(inspected.validity, Validity::Current);
    let PhaseOutcome::Passed {
        output: verified, ..
    } = &report.verify
    else {
        panic!("{report:?}")
    };
    let [proof] = verified.proofs.as_slice() else {
        panic!("one proof")
    };
    assert!(matches!(proof.outcome, ProofOutcome::Verified { .. }));
    assert_eq!(proof.algorithm.as_deref(), Some("EdDSA"));
    assert_eq!(
        proof.key_provenance.source,
        Some(KeySource::IssuerIdentifier)
    );
    assert_eq!(proof.key_provenance.method, Some("did:key"));
    assert!(report.contained.is_empty());
}

/// Expired and correctly signed, as two distinct facts (REQUIREMENTS §4).
#[test]
fn reports_expiry_and_a_good_signature_separately() {
    let report = verify(
        &example(),
        &at(datetime!(2032-01-01 0:00 UTC)),
        &Registry::builtin(),
    );
    let PhaseOutcome::Failed { output, findings } = &report.inspect else {
        panic!("{report:?}")
    };
    assert_eq!(output.validity, Validity::Expired);
    assert_eq!(findings[0].code, "inspect.expired");
    assert!(
        matches!(report.verify, PhaseOutcome::Passed { .. }),
        "{report:?}"
    );
}

#[test]
fn inspect_does_not_verify() {
    let report = inspect(
        &example(),
        &at(datetime!(2026-10-01 0:00 UTC)),
        &Registry::builtin(),
    );
    assert!(matches!(report.inspect, PhaseOutcome::Passed { .. }));
    assert!(matches!(report.verify, PhaseOutcome::NotRequested));
}

/// A registry with no formats attributes the failure to vcrd, not the input
/// (ARCHITECTURE §2).
#[test]
fn an_empty_registry_is_vcrds_limit() {
    let report = inspect(
        &example(),
        &at(datetime!(2026-10-01 0:00 UTC)),
        &Registry::empty(),
    );
    let PhaseOutcome::Failed { findings, .. } = &report.parse else {
        panic!("{report:?}")
    };
    assert_eq!(findings[0].code, "parse.no_format_matched");
    assert_eq!(findings[0].attribution, vcrd_core::Attribution::Vcrd);
    assert!(matches!(report.inspect, PhaseOutcome::NotReached(_)));
}

/// The claims are masked in every `Debug` rendering of the report (ARCHITECTURE §7).
#[test]
fn debug_output_masks_every_claim() {
    let report = verify(
        &example(),
        &at(datetime!(2026-10-01 0:00 UTC)),
        &Registry::builtin(),
    );
    let debug = format!("{report:?}");
    for claim in [
        "did:example:alice",
        "Bachelor of Science",
        "urn:uuid:0d4a1f3e",
    ] {
        assert!(!debug.contains(claim), "{claim} in {debug}");
    }
}
