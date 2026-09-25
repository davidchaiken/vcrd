//! Parse, inspect and verify verifiable credentials.
//!
//! The library behind the `vcrd` command. See `REQUIREMENTS.md` for what it does
//! and `ARCHITECTURE.md` for how it is built.
//!
//! [`inspect`] and [`verify`] take the input's bytes, a [`Context`] holding
//! everything injected, and a [`Registry`] of formats and proof suites. They return
//! a [`Report`], never a `Result`: a malformed, expired or forged credential is an
//! answer, not an error in vcrd's operation (ARCHITECTURE §3).

#![forbid(unsafe_code)]

mod context;
mod document;
mod finding;
pub mod formats;
mod json;
mod keys;
mod redact;
mod registry;
mod report;
mod runner;
pub mod suites;

#[cfg(feature = "std-clock")]
pub use context::SystemClock;
pub use context::{Clock, Context, ContextBuilder, FixedClock, Limits};
pub use document::{
    ContainedInput, ContextEntry, Document, DocumentKind, KeyHints, Leaf, LeafClass,
    ProofDescriptor, ProofMaterial, Timestamp,
};
pub use finding::{
    Attribution, DateField, DidKeyProblem, Finding, FindingDetail, JwsSegment, KeySourceKind,
    Severity,
};
pub use json::{Json, Member};
pub use keys::{CredentialKey, KeyProvenance, KeySource, PublicKey};
pub use redact::{
    ClaimValue, Designations, Rendered, RenderedLeaf, Reveal, Revealed, Treatment, ValueKind,
    render,
};
pub use registry::{
    CredentialFormat, Detection, FormatId, ProfileId, ProofInput, ProofSuite, Registry, SuiteId,
};
pub use report::{
    BlockReason, Blocked, Check, Disclosure, FormatDetail, InputSummary, InspectOutput,
    NotEvaluated, NotEvaluatedReason, ParseOutput, Phase, PhaseOutcome, ProofOutcome, ProofResult,
    Report, Validity, VerifyOutput,
};

/// Runs the parse and inspect phases (REQUIREMENTS §4, §8).
pub fn inspect(bytes: &[u8], ctx: &Context, registry: &Registry) -> Report {
    runner::run(bytes, ctx, registry, Phase::Inspect)
}

/// Runs the parse, inspect and verify phases (REQUIREMENTS §4, §8).
pub fn verify(bytes: &[u8], ctx: &Context, registry: &Registry) -> Report {
    runner::run(bytes, ctx, registry, Phase::Verify)
}
