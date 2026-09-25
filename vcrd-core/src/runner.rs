//! The phase runner (ARCHITECTURE §4): runs the phases in order, resolves keys,
//! dispatches proofs to suites, and lists what was not evaluated.

use crate::context::Context;
use crate::document::ProofMaterial;
use crate::finding::{Attribution, Finding, FindingDetail, Severity};
use crate::keys;
use crate::registry::{CredentialFormat, Detection, ProofInput, Registry};
use crate::report::{
    BlockReason, Blocked, Check, InputSummary, NotEvaluated, NotEvaluatedReason, ParseOutput,
    Phase, PhaseOutcome, ProofOutcome, ProofResult, Report, VerifyOutput,
};

pub(crate) fn run(bytes: &[u8], ctx: &Context, registry: &Registry, last: Phase) -> Report {
    let format = detect(registry, bytes);
    let parse = match format {
        Some(format) => format.parse(bytes, ctx),
        None => {
            // An empty registry is vcrd's limit; a non-empty one that matched
            // nothing is the input's (ARCHITECTURE §2).
            let registered: Vec<_> = registry.formats().map(|f| f.id()).collect();
            let attribution = if registered.is_empty() {
                Attribution::Vcrd
            } else {
                Attribution::Input
            };
            let finding = Finding::error(
                Phase::Parse,
                attribution,
                FindingDetail::NoFormatMatched { registered },
            );
            PhaseOutcome::Failed {
                output: ParseOutput::default(),
                findings: vec![finding],
            }
        }
    };
    let input = InputSummary {
        bytes: bytes.len(),
        depth: parse.output().and_then(|p| p.depth),
        format: format.map(|f| f.id()),
    };

    let (inspect, verify) = match (&parse, format) {
        (PhaseOutcome::Passed { output, .. }, Some(format)) => {
            let inspect = format.inspect(output, ctx);
            let verify = if last >= Phase::Verify {
                verify_proofs(output, ctx, registry)
            } else {
                PhaseOutcome::NotRequested
            };
            (inspect, verify)
        }
        // A parse failure leaves nothing to work on (REQUIREMENTS §4).
        _ => {
            let blocked = Blocked {
                by: Phase::Parse,
                reason: BlockReason::Impossible,
                findings: error_codes(parse.findings()),
            };
            let verify = if last >= Phase::Verify {
                PhaseOutcome::NotReached(blocked.clone())
            } else {
                PhaseOutcome::NotRequested
            };
            (PhaseOutcome::NotReached(blocked), verify)
        }
    };

    Report {
        input,
        parse,
        inspect,
        verify,
        // Trust evaluation is not a phase (REQUIREMENTS §4).
        not_evaluated: vec![NotEvaluated {
            what: Check::IssuerAccreditation,
            why: NotEvaluatedReason::OutOfScope,
        }],
        contained: Vec::new(),
    }
}

/// The most confident format; the first registered wins a tie.
fn detect<'r>(registry: &'r Registry, bytes: &[u8]) -> Option<&'r dyn CredentialFormat> {
    let mut best: Option<(Detection, &dyn CredentialFormat)> = None;
    for format in registry.formats() {
        let detection = format.detect(bytes);
        if detection > best.map_or(Detection::No, |(d, _)| d) {
            best = Some((detection, format));
        }
    }
    best.map(|(_, format)| format)
}

fn error_codes(findings: &[Finding]) -> Vec<&'static str> {
    findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .map(|f| f.code)
        .collect()
}

/// Resolves each proof's key and hands the proof to its suite. Key resolution
/// belongs to neither trait (ARCHITECTURE §4).
fn verify_proofs(
    parsed: &ParseOutput,
    ctx: &Context,
    registry: &Registry,
) -> PhaseOutcome<VerifyOutput> {
    let descriptors = parsed
        .document
        .as_ref()
        .map_or(&[][..], |d| d.proofs.as_slice());
    let mut findings = Vec::new();
    if descriptors.is_empty() {
        findings.push(Finding::error(
            Phase::Verify,
            Attribution::Input,
            FindingDetail::NoProof,
        ));
    }
    let mut proofs = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        let resolution = keys::resolve(&descriptor.key_hints);
        findings.extend(resolution.findings);
        let outcome = match registry.suite(descriptor.suite) {
            None => {
                findings.push(Finding::error(
                    Phase::Verify,
                    Attribution::Vcrd,
                    FindingDetail::SuiteUnavailable {
                        suite: descriptor.suite,
                    },
                ));
                ProofOutcome::NotAttempted
            }
            Some(suite) => {
                let input = match &descriptor.material {
                    ProofMaterial::Jws {
                        signing_input,
                        signature,
                    } => ProofInput::Jws {
                        algorithm: descriptor.algorithm.as_deref(),
                        signing_input,
                        signature,
                        key: resolution.key.as_ref(),
                    },
                };
                let (outcome, suite_findings) = suite.verify(&input, ctx);
                findings.extend(suite_findings);
                outcome
            }
        };
        proofs.push(ProofResult {
            suite: descriptor.suite,
            algorithm: descriptor.algorithm.clone(),
            outcome,
            key_provenance: resolution.provenance,
        });
    }
    PhaseOutcome::from_findings(VerifyOutput { proofs }, findings)
}
