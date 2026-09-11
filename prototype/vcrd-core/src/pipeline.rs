//! Tier sequencing. The load-bearing hypothesis: parse failure blocks everything
//! downstream, but a *validate* failure does not block verify. Validate and verify
//! answer independent questions about the same parsed bytes, so an expired credential
//! with a good signature should report both facts, not just the first one.

use crate::context::Context;
use crate::format::{ProofInput, Registry};
use crate::keys::{self, KeyProvenance};
use crate::limits;
use crate::model::*;

/// Breakpoint anchor: tier 1.
#[inline(never)]
pub fn run_parse(bytes: &[u8], ctx: &Context, registry: &Registry) -> (Stage<ParseOutput>, Option<FormatId>) {
    let Some(format) = registry.detect(bytes) else {
        // FINDING (feature-gate matrix): "no format matched" is the input's fault only
        // if there was a format to match against. With `--no-default-features` the
        // registry is empty, and blaming the credential for that would send a caller
        // hunting a bug in their own data.
        let blame = if registry.formats.is_empty() { Blame::Vcrd } else { Blame::Input };
        return (
            Stage::Failed {
                findings: vec![Finding::error(
                    "parse.no_format_matched",
                    Tier::Parse,
                    blame,
                    FindingDetail::NoFormatMatched { tried: registry.format_ids() },
                )],
            },
            None,
        );
    };
    let id = format.id();
    (format.parse(bytes, ctx), Some(id))
}

/// Breakpoint anchor: tier 2.
#[inline(never)]
pub fn run_validate(parsed: &ParseOutput, ctx: &Context, registry: &Registry) -> Stage<ValidateOutput> {
    match registry.formats.iter().find(|f| f.id() == parsed.format) {
        Some(f) => f.validate(parsed, ctx),
        None => Stage::NotReached { blocked_by: Tier::Parse },
    }
}

/// Breakpoint anchor: tier 3.
#[inline(never)]
pub fn run_verify(parsed: &ParseOutput, ctx: &Context, registry: &Registry) -> Stage<VerifyOutput> {
    let mut findings = Vec::new();
    let mut results = Vec::new();

    for descriptor in &parsed.document.proofs {
        let resolved = keys::resolve(&descriptor.key_hints, ctx.keys.as_ref(), ctx.trust_embedded_key);
        findings.extend(resolved.findings.iter().cloned());

        let Some(suite) = registry.suite(descriptor.suite) else {
            results.push(ProofResult {
                suite: descriptor.suite,
                declared_alg: descriptor.declared_alg.clone(),
                outcome: ProofOutcome::NotAttempted,
                key_provenance: resolved.provenance,
            });
            continue;
        };

        let input = ProofInput {
            suite: descriptor.suite,
            declared_alg: &descriptor.declared_alg,
            signing_input: &descriptor.signing_input,
            signature: &descriptor.signature,
            key: resolved.key.as_ref(),
            provenance: &resolved.provenance,
        };
        let (outcome, suite_findings) = suite.verify(&input, ctx);
        findings.extend(suite_findings);
        results.push(ProofResult {
            suite: descriptor.suite,
            declared_alg: descriptor.declared_alg.clone(),
            outcome,
            key_provenance: resolved.provenance,
        });
    }

    let all_verified = !results.is_empty()
        && results.iter().all(|r| matches!(r.outcome, ProofOutcome::Verified { .. }));

    if all_verified {
        Stage::Passed { output: VerifyOutput { proofs: results }, findings }
    } else {
        if findings.is_empty() {
            findings.push(Finding::error(
                "verify.no_proofs",
                Tier::Verify,
                Blame::Input,
                FindingDetail::MissingField { field: "proof" },
            ));
        }
        Stage::Failed { findings }
    }
}

/// What vcrd deliberately did not check, given how far it got and what it was told.
fn non_checks(ctx: &Context, reached_verify: bool) -> Vec<NotEvaluated> {
    let mut v = vec![
        NotEvaluated {
            what: NotEvaluatedKind::RevocationStatus,
            why: NotEvaluatedWhy::RequiresNetwork,
        },
        NotEvaluated {
            what: NotEvaluatedKind::ContextResolution,
            why: NotEvaluatedWhy::NotImplementedInSpike,
        },
        NotEvaluated {
            what: NotEvaluatedKind::SchemaConformance,
            why: NotEvaluatedWhy::NotImplementedInSpike,
        },
        NotEvaluated {
            what: NotEvaluatedKind::IssuerAccreditation,
            why: NotEvaluatedWhy::OutOfScope,
        },
    ];
    // A bare VC has no holder proof; the replay-binding entry still has to appear,
    // because "we did not check it" is the point.
    v.push(NotEvaluated {
        what: NotEvaluatedKind::HolderBinding,
        why: if reached_verify { NotEvaluatedWhy::OutOfScope } else { NotEvaluatedWhy::TierNotReached },
    });
    v.push(NotEvaluated {
        what: NotEvaluatedKind::ReplayBinding,
        why: if ctx.expected_challenge.is_none() && ctx.expected_domain.is_none() {
            NotEvaluatedWhy::NoParametersSupplied
        } else {
            NotEvaluatedWhy::OutOfScope
        },
    });
    v
}

fn summarize(bytes: &[u8], _ctx: &Context, format: Option<FormatId>) -> InputSummary {
    InputSummary {
        byte_len: bytes.len(),
        measured_depth: limits::measure_depth(bytes, usize::MAX).ok(),
        detected_format: format,
    }
}

/// `vcrd inspect`: parse, then validate. Never verify (§4/§8).
pub fn inspect(bytes: &[u8], ctx: &Context, registry: &Registry) -> Report {
    let (parse, format) = run_parse(bytes, ctx, registry);
    let validate = match parse.output() {
        Some(p) => run_validate(p, ctx, registry),
        None => Stage::NotReached { blocked_by: Tier::Parse },
    };
    Report {
        input: summarize(bytes, ctx, format),
        parse,
        validate,
        verify: Stage::NotReached { blocked_by: Tier::Validate },
        not_evaluated: non_checks(ctx, false),
    }
}

/// `vcrd verify`: all three tiers. Verify runs even when validate failed.
pub fn verify(bytes: &[u8], ctx: &Context, registry: &Registry) -> Report {
    let (parse, format) = run_parse(bytes, ctx, registry);
    let (validate, verify) = match parse.output() {
        Some(p) => (run_validate(p, ctx, registry), run_verify(p, ctx, registry)),
        None => (
            Stage::NotReached { blocked_by: Tier::Parse },
            Stage::NotReached { blocked_by: Tier::Parse },
        ),
    };
    let reached_verify = !matches!(verify, Stage::NotReached { .. });
    Report {
        input: summarize(bytes, ctx, format),
        parse,
        validate,
        verify,
        not_evaluated: non_checks(ctx, reached_verify),
    }
}

/// Provenance hoisted for callers that want one answer rather than a list.
pub fn overall_key_provenance(report: &Report) -> Option<&KeyProvenance> {
    report.verify.output().and_then(|v| v.proofs.first()).map(|p| &p.key_provenance)
}
