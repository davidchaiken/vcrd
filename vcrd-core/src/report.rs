//! The result of an operation (ARCHITECTURE §3).

use crate::document::{ContainedInput, Document};
use crate::finding::{Finding, Severity};
use crate::keys::KeyProvenance;
use crate::registry::{FormatId, ProfileId, SuiteId};

/// The complete result of [`inspect`](crate::inspect) or [`verify`](crate::verify).
///
/// Never wrapped in a `Result`: a malformed, expired or forged credential is the
/// answer, not an error in vcrd's operation (ARCHITECTURE §3).
#[derive(Clone, Debug)]
pub struct Report {
    pub input: InputSummary,
    pub parse: PhaseOutcome<ParseOutput>,
    pub inspect: PhaseOutcome<InspectOutput>,
    pub verify: PhaseOutcome<VerifyOutput>,
    /// Checks not performed, each with the reason (REQUIREMENTS §12).
    pub not_evaluated: Vec<NotEvaluated>,
    /// One complete result per credential found inside this one. Empty for a bare
    /// credential; a presentation fills it.
    pub contained: Vec<Report>,
}

impl Report {
    /// This result's own findings, in phase order. Excludes `contained`.
    pub fn findings(&self) -> impl Iterator<Item = &Finding> {
        self.parse
            .findings()
            .iter()
            .chain(self.inspect.findings())
            .chain(self.verify.findings())
    }
}

/// The three phases, in the order they run (REQUIREMENTS §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    Parse,
    Inspect,
    Verify,
}

/// One phase's outcome: the four cases of REQUIREMENTS §6.
#[derive(Clone, Debug)]
pub enum PhaseOutcome<T> {
    /// The operation does not run this phase: `inspect` does not verify.
    NotRequested,
    /// An earlier phase prevented this one (REQUIREMENTS §4).
    NotReached(Blocked),
    /// Ran and found at least one error. `output` holds what the phase established
    /// before failing.
    Failed { output: T, findings: Vec<Finding> },
    /// Ran with no error. Warnings and informational findings ride along.
    Passed { output: T, findings: Vec<Finding> },
}

impl<T> PhaseOutcome<T> {
    /// `Failed` if any finding is an error, otherwise `Passed`: only error-severity
    /// findings fail a phase (ARCHITECTURE §3).
    pub fn from_findings(output: T, findings: Vec<Finding>) -> Self {
        if findings.iter().any(|f| f.severity == Severity::Error) {
            PhaseOutcome::Failed { output, findings }
        } else {
            PhaseOutcome::Passed { output, findings }
        }
    }

    /// What the phase established, whether it passed or failed.
    pub fn output(&self) -> Option<&T> {
        match self {
            PhaseOutcome::Failed { output, .. } | PhaseOutcome::Passed { output, .. } => {
                Some(output)
            }
            PhaseOutcome::NotRequested | PhaseOutcome::NotReached(_) => None,
        }
    }

    /// The phase's findings; empty if it did not run.
    pub fn findings(&self) -> &[Finding] {
        match self {
            PhaseOutcome::Failed { findings, .. } | PhaseOutcome::Passed { findings, .. } => {
                findings
            }
            PhaseOutcome::NotRequested | PhaseOutcome::NotReached(_) => &[],
        }
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, PhaseOutcome::Failed { .. })
    }
}

/// Why a requested phase did not run (REQUIREMENTS §4; §16 item 20).
#[derive(Clone, Debug)]
pub struct Blocked {
    /// The phase whose findings prevented this one.
    pub by: Phase,
    pub reason: BlockReason,
    /// The codes of the findings responsible.
    pub findings: Vec<&'static str>,
}

/// The two reasons REQUIREMENTS §4 allows for one phase to stop the next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockReason {
    /// The materials the phase needs are not available: nothing was parsed, or no
    /// key material can be found.
    Impossible,
    /// Running the phase could expose vcrd to an exploit, or would fetch material
    /// such as a key from a suspicious source.
    Dangerous,
}

/// What is known about the input before and during parsing.
#[derive(Clone, Debug, Default)]
pub struct InputSummary {
    /// The input's length in bytes.
    pub bytes: usize,
    /// The nesting depth of the decoded payload, once measured (ARCHITECTURE §4).
    pub depth: Option<usize>,
    /// The format detection chose.
    pub format: Option<FormatId>,
}

/// What parsing established. Every field is optional or may be empty, because a
/// failed parse carries whatever it got to (ARCHITECTURE §3).
#[derive(Clone, Debug, Default)]
pub struct ParseOutput {
    /// The format-neutral view.
    pub document: Option<Document>,
    /// What only this format has.
    pub detail: Option<FormatDetail>,
    /// The nesting depth of the decoded payload.
    pub depth: Option<usize>,
    /// Credentials found inside this one, for the runner to dispatch (ARCHITECTURE §4).
    pub contained: Vec<ContainedInput>,
}

/// One variant per format. Not `#[non_exhaustive]`: a new variant must break every
/// match on it, including the JSON mapping in `vcrd-cli` (ARCHITECTURE §3).
#[derive(Clone, Debug)]
pub enum FormatDetail {
    #[cfg(feature = "vc-jose")]
    VcJose(crate::formats::vc_jose::VcJoseDetail),
}

/// What inspection established.
#[derive(Clone, Debug, Default)]
pub struct InspectOutput {
    /// The profile of the format the input follows, when recognized.
    pub profile: Option<ProfileId>,
    /// The validity period against the injected clock.
    pub validity: Validity,
}

/// Where the injected clock falls relative to a validity period.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Validity {
    Current,
    Expired,
    NotYetValid,
    /// Neither bound is present.
    Unbounded,
    /// A bound is present but could not be read.
    #[default]
    Unknown,
}

/// What verification established.
#[derive(Clone, Debug, Default)]
pub struct VerifyOutput {
    pub proofs: Vec<ProofResult>,
}

/// One proof's result, reported whether verification succeeds or fails.
#[derive(Clone, Debug)]
pub struct ProofResult {
    pub suite: SuiteId,
    /// The algorithm the input declares, which is checked and never obeyed
    /// (ARCHITECTURE §8).
    pub algorithm: Option<String>,
    pub outcome: ProofOutcome,
    pub key_provenance: KeyProvenance,
}

/// Not `#[non_exhaustive]`, for the reason given on [`FormatDetail`].
#[derive(Clone, Debug)]
pub enum ProofOutcome {
    /// `disclosed` exists so that selective disclosure is not designed out
    /// (ARCHITECTURE §3).
    Verified {
        disclosed: Option<Disclosure>,
    },
    Failed,
    NotAttempted,
}

/// Which claims a selective-disclosure proof revealed.
#[derive(Clone, Debug)]
pub struct Disclosure {
    pub disclosed: Vec<String>,
    pub withheld: usize,
}

/// A check vcrd did not perform, and why (REQUIREMENTS §12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotEvaluated {
    pub what: Check,
    pub why: NotEvaluatedReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    RevocationStatus,
    ContextResolution,
    HolderBinding,
    ReplayBinding,
    IssuerAccreditation,
    SchemaConformance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotEvaluatedReason {
    RequiresNetwork,
    NoParametersSupplied,
    NotImplemented,
    OutOfScope,
    PhaseNotReached,
}
