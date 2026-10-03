//! The phase runner (ARCHITECTURE §4): runs the phases in order, resolves keys,
//! dispatches proofs to suites, and lists what was not evaluated.

use crate::context::Context;
use crate::document::ProofMaterial;
use crate::finding::{Attribution, Finding, FindingDetail, KeySourceKind};
use crate::keys;
use crate::registry::{CredentialFormat, Detection, ProofInput, Registry};
use crate::report::{
    BlockReason, Blocked, Check, InputSummary, InspectOutput, Missing, NotEvaluated,
    NotEvaluatedReason, ParseOutput, Phase, PhaseOutcome, ProofOutcome, ProofResult, Report,
    VerifyOutput,
};

pub(crate) fn run(bytes: &[u8], ctx: &Context, registry: &Registry, last: Phase) -> Report {
    // The size limit comes before anything else, detection included (ARCHITECTURE §4).
    let limit = ctx.limits().max_bytes;
    let too_large = bytes.len() > limit;
    let format = if too_large {
        None
    } else {
        detect(registry, bytes)
    };
    let parse = match format {
        Some(format) => format.parse(bytes, ctx),
        None if too_large => PhaseOutcome::Failed {
            output: ParseOutput::default(),
            findings: vec![Finding::error(
                Phase::Parse,
                Attribution::Policy,
                FindingDetail::InputTooLarge {
                    limit,
                    found: bytes.len(),
                },
            )],
        },
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
            let verify = if last < Phase::Verify {
                PhaseOutcome::NotRequested
            } else if let Some(blocked) = blocked_by_inspect(&inspect) {
                PhaseOutcome::NotReached(blocked)
            } else {
                verify_proofs(output, ctx, registry)
            };
            (inspect, verify)
        }
        // A parse failure leaves nothing to work on (REQUIREMENTS §4).
        _ => {
            let blocked = Blocked {
                by: Phase::Parse,
                reason: BlockReason::Impossible {
                    missing: Missing::Document,
                },
            };
            let verify = if last >= Phase::Verify {
                PhaseOutcome::NotReached(blocked.clone())
            } else {
                PhaseOutcome::NotRequested
            };
            (PhaseOutcome::NotReached(blocked), verify)
        }
    };

    // Trust evaluation is not a phase (REQUIREMENTS §4).
    let mut not_evaluated = vec![NotEvaluated {
        what: Check::IssuerAccreditation,
        why: NotEvaluatedReason::OutOfScope,
    }];
    if let Some(inspected) = inspect.output() {
        not_evaluated.extend_from_slice(&inspected.not_evaluated);
    }
    Report {
        input,
        parse,
        inspect,
        verify,
        not_evaluated,
        contained: Vec::new(),
    }
}

/// REQUIREMENTS §4's blocking rule for inspect: verify is impossible when the input
/// names no usable issuer identifier and no other source of key material remains.
/// Milestone 1 has no other source; milestone 2's caller-supplied keys are consulted
/// here, which is why the runner decides and not the format (ARCHITECTURE §4).
fn blocked_by_inspect(inspect: &PhaseOutcome<InspectOutput>) -> Option<Blocked> {
    if !inspect.output()?.no_issuer_identifier {
        return None;
    }
    Some(Blocked {
        by: Phase::Inspect,
        reason: BlockReason::Impossible {
            missing: Missing::KeyMaterial {
                consulted: vec![KeySourceKind::IssuerIdentifier],
            },
        },
    })
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
