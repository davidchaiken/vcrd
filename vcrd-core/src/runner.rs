//! The phase runner (ARCHITECTURE §4): runs the phases in order, resolves keys,
//! dispatches proofs to suites, and lists what was not evaluated.

use crate::context::Context;
use crate::document::{ProofDescriptor, ProofMaterial, ProofTime, ProofTimes};
use crate::finding::{Attribution, Finding, FindingDetail, KeySourceKind, Severity};
use crate::keys::{self, PublicKey};
use crate::registry::{CredentialFormat, Detection, ProofInput, Registry};
use crate::report::{
    BlockReason, Blocked, Check, InputSummary, InspectOutput, Missing, NotEvaluated,
    NotEvaluatedReason, ParseOutput, Phase, PhaseOutcome, ProofOutcome, ProofResult, Report,
    Validity, VerifyOutput,
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
            } else if let Some(blocked) = blocked_by_inspect(&inspect, output) {
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
/// Milestone 2's caller-supplied keys are consulted here, which is why the runner
/// decides and not the format (ARCHITECTURE §4).
fn blocked_by_inspect(
    inspect: &PhaseOutcome<InspectOutput>,
    parsed: &ParseOutput,
) -> Option<Blocked> {
    if !inspect.output()?.no_issuer_identifier {
        return None;
    }
    // A key the credential carries is a source, though one refused without the
    // caller's opt-in: verify runs, so that the refusal is reported rather than
    // treated as "no key material" (REQUIREMENTS §10).
    let carries_key = parsed
        .document
        .as_ref()
        .is_some_and(|d| d.proofs.iter().any(|p| p.key_hints.embedded.is_some()));
    if carries_key {
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
        let mut resolution = keys::resolve(&descriptor.key_hints);
        findings.append(&mut resolution.findings);
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
                let input = proof_input(descriptor, resolution.key.as_ref());
                let (outcome, suite_findings) = suite.verify(&input, ctx);
                findings.extend(suite_findings);
                // Additional information, under the same rules: it never changes the
                // verdict or the exit code (ARCHITECTURE §8).
                if let (Some(credential_key), Some(key)) = (
                    resolution.provenance.credential_key.as_mut(),
                    resolution.credential_key.as_ref(),
                ) {
                    let (outcome, _) = suite.verify(&proof_input(descriptor, Some(key)), ctx);
                    credential_key.verifies_signature = match outcome {
                        ProofOutcome::Verified { .. } => Some(true),
                        ProofOutcome::Failed => Some(false),
                        ProofOutcome::NotAttempted => None,
                    };
                }
                outcome
            }
        };
        let validity = proof_validity(&descriptor.times, ctx, &mut findings);
        proofs.push(ProofResult {
            suite: descriptor.suite,
            algorithm: descriptor.algorithm.clone(),
            outcome,
            key_provenance: resolution.provenance,
            validity,
        });
    }
    PhaseOutcome::from_findings(VerifyOutput { proofs }, findings)
}

fn proof_input<'a>(descriptor: &'a ProofDescriptor, key: Option<&'a PublicKey>) -> ProofInput<'a> {
    match &descriptor.material {
        ProofMaterial::Jws {
            signing_input,
            signature,
            critical,
        } => ProofInput::Jws {
            algorithm: descriptor.algorithm.as_deref(),
            signing_input,
            signature,
            critical,
            key,
        },
    }
}

/// The proof's own times against the clock and skew (RFC 7519 §4.1.4–4.1.6), in the
/// verify phase because they are the signature's, not the credential's (VC-JOSE-COSE
/// §3.1.3). Mirrors the credential's validity period: a bound that is not a number
/// leaves it unknown, and not yet valid is reported before expired.
fn proof_validity(times: &ProofTimes, ctx: &Context, findings: &mut Vec<Finding>) -> Validity {
    let now = ctx.now();
    let skew_seconds = ctx.clock_skew().as_secs();
    let skew = ctx.clock_skew().as_secs_f64();
    // Seconds as a float: a NumericDate may have a fraction, and may lie beyond the
    // years a date can represent (RFC 7519 §2).
    let now_seconds = now.unix_timestamp() as f64 + f64::from(now.nanosecond()) / 1e9;
    let read = |time: &Option<ProofTime>| match time {
        None => Ok(None),
        Some(ProofTime {
            claim,
            value: Some(date),
        }) => Ok(Some((
            *claim,
            date.text.clone(),
            date.date_time,
            date.seconds,
        ))),
        Some(ProofTime { value: None, .. }) => Err(()),
    };
    if let Ok(Some((claim, value, value_date_time, seconds))) = read(&times.issued_at)
        && seconds > now_seconds + skew
    {
        findings.push(Finding::new(
            Phase::Verify,
            Attribution::Input,
            Severity::Warning,
            FindingDetail::ProofIssuedInFuture {
                claim,
                value,
                value_date_time,
                now,
                skew_seconds,
            },
        ));
    }
    let (Ok(not_before), Ok(expires)) = (read(&times.not_before), read(&times.expires)) else {
        return Validity::Unknown;
    };
    if not_before.is_none() && expires.is_none() {
        return Validity::Unbounded;
    }
    if let Some((claim, value, value_date_time, seconds)) = not_before
        && seconds > now_seconds + skew
    {
        findings.push(Finding::error(
            Phase::Verify,
            Attribution::Input,
            FindingDetail::ProofNotYetValid {
                claim,
                value,
                value_date_time,
                now,
                skew_seconds,
            },
        ));
        return Validity::NotYetValid;
    }
    // The current time MUST be before `exp` (RFC 7519 §4.1.4).
    if let Some((claim, value, value_date_time, seconds)) = expires
        && now_seconds - skew >= seconds
    {
        findings.push(Finding::error(
            Phase::Verify,
            Attribution::Input,
            FindingDetail::ProofExpired {
                claim,
                value,
                value_date_time,
                now,
                skew_seconds,
            },
        ));
        return Validity::Expired;
    }
    Validity::Current
}
