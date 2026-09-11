//! Exit-code taxonomy (§8: "distinct exit codes distinguish parse failure, validation
//! failure, and verification failure").
//!
//! The hypothesis under test: blame outranks tier. "vcrd cannot do this" and "your
//! policy said no" are different *kinds* of answer from "the credential is bad", and
//! a script branching on the exit code cares about that difference more than it cares
//! which tier noticed.

use vcrd_core::model::{Blame, Report, Severity};

pub const OK: i32 = 0;
pub const CALLER_ERROR: i32 = 1;
pub const PARSE_FAILED: i32 = 2;
pub const VALIDATE_FAILED: i32 = 3;
pub const VERIFY_FAILED: i32 = 4;
pub const POLICY_REJECTED: i32 = 5;
pub const UNSUPPORTED: i32 = 6;

/// Breakpoint anchor for the exit-code question.
#[inline(never)]
pub fn from_report(report: &Report) -> i32 {
    let errors: Vec<_> = report
        .all_findings()
        .into_iter()
        .filter(|f| f.severity == Severity::Error)
        .collect();

    // Blame first: these say something about vcrd or the caller, not the credential.
    if errors.iter().any(|f| f.blame == Blame::Vcrd) {
        return UNSUPPORTED;
    }
    if errors.iter().any(|f| f.blame == Blame::Policy) {
        return POLICY_REJECTED;
    }

    if report.parse.is_failed() {
        return PARSE_FAILED;
    }
    if report.validate.is_failed() {
        return VALIDATE_FAILED;
    }
    if report.verify.is_failed() {
        return VERIFY_FAILED;
    }
    OK
}
