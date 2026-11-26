//! The phase runner (ARCHITECTURE §4): runs the phases in order, resolves keys,
//! dispatches proofs to suites, and lists what was not evaluated.

use crate::context::Context;
use crate::document::LeafClass;
use crate::document::{DeclaredAlgorithm, ProofDescriptor, ProofMaterial, ProofTime, ProofTimes};
use crate::finding::{
    Attribution, Finding, FindingDetail, IssuerKeyUnobtainable, KeySourceKind, NotDeciding,
    Severity,
};
use crate::json::{self, Json};
use crate::keys::{
    self, CallerPart, Condition, Decision, KeyAndProof, KeyProvenance, KeyReport, KeySource,
    ProofKey, PublicKey, Refusal, Resolution,
};
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
            let finding = match unread_credential(bytes, ctx) {
                Some((attribution, detail)) => Finding::error(Phase::Parse, attribution, detail),
                None => {
                    // An empty registry is vcrd's limit; a non-empty one that matched
                    // nothing is the input's (ARCHITECTURE §2).
                    let registered: Vec<_> = registry.formats().map(|f| f.id()).collect();
                    let attribution = if registered.is_empty() {
                        Attribution::Vcrd
                    } else {
                        Attribution::Input
                    };
                    Finding::error(
                        Phase::Parse,
                        attribution,
                        FindingDetail::NoFormatMatched { registered },
                    )
                }
            };
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
            } else if let Some(blocked) = blocked_by_inspect(&inspect, output, ctx) {
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

    // Trust evaluation is not a phase (REQUIREMENTS §4). Issuer accreditation is checked
    // against a trust anchor the caller supplies (REQUIREMENTS §9), an input not yet
    // designed (REQUIREMENTS §16 item 14); once it is, a caller who supplies none makes
    // this `NoParametersSupplied`.
    let mut not_evaluated = vec![NotEvaluated {
        what: Check::IssuerAccreditation,
        why: NotEvaluatedReason::NotImplemented,
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
/// The caller's key set is consulted here, which is why the runner decides and not the
/// format (ARCHITECTURE §4).
fn blocked_by_inspect(
    inspect: &PhaseOutcome<InspectOutput>,
    parsed: &ParseOutput,
    ctx: &Context,
) -> Option<Blocked> {
    let inspected = inspect.output()?;
    if !inspected.no_issuer_identifier {
        return None;
    }
    // The caller's key set is a source, and so is a key the credential carries, though
    // one refused without the caller's opt-in: verify runs, so that the refusal is
    // reported rather than treated as "no key material" (REQUIREMENTS §10). Not for a
    // document vcrd does not read, whose keys it cannot use either.
    let carries_key = ctx.key_set().is_some()
        || parsed.document.as_ref().is_some_and(|d| {
            d.proofs.iter().any(|p| {
                p.key_hints.embedded.is_some()
                    || p.key_hints
                        .kid
                        .as_deref()
                        .and_then(keys::did_key_kid)
                        .is_some()
            })
        });
    if carries_key && !inspected.unsupported_document {
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

/// A JSON credential or presentation that no registered format reads: an object with
/// `@context` and `type` (VCDM 2.0 §4.3, §4.5). With an embedded `proof`, as Data
/// Integrity secures one (§4.12), vcrd cannot read it until milestone 5; with none,
/// nothing secures it (§1.3). Parsed only within the depth limit, as a format parses
/// (ARCHITECTURE §4).
fn unread_credential(bytes: &[u8], ctx: &Context) -> Option<(Attribution, FindingDetail)> {
    if json::nesting_depth(bytes) > ctx.limits().max_depth {
        return None;
    }
    let json = Json::parse(bytes).ok()?;
    json.get("@context")?;
    json.get("type")?;
    Some(match json.get("proof") {
        Some(_) => (Attribution::Vcrd, FindingDetail::DataIntegrityUnsupported),
        None => (Attribution::Input, FindingDetail::NotSecured),
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
    // The caller's key set's own warnings, once, before any proof's findings.
    let mut findings = ctx.key_set().map_or_else(Vec::new, |set| set.findings());
    if descriptors.is_empty() {
        findings.push(Finding::error(
            Phase::Verify,
            Attribution::Input,
            FindingDetail::NoProof,
        ));
    }
    let mut proofs = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        let suite = registry.suite(descriptor.suite);
        let algorithm = descriptor
            .algorithm
            .as_ref()
            .and_then(DeclaredAlgorithm::name);
        let mut resolution = keys::resolve(&descriptor.key_hints);
        let caller = ctx.key_set().map(|set| keys::CallerKeys {
            set,
            algorithm,
            takes: move |key_type| {
                suite
                    .zip(algorithm)
                    .is_some_and(|(s, a)| s.takes_key(a, key_type))
            },
            show_secrets: ctx.designations().shows(LeafClass::Secret),
        });
        if let Some(caller) = &caller {
            keys::add_members(caller, &mut resolution);
        }
        // Each distinct key's proof, with the suite's findings for it. A refused key has
        // none, and without the suite no key has one.
        for key in &mut resolution.keys {
            key.proved = key
                .key
                .as_ref()
                .and_then(|k| Some(suite?.verify(&proof_input(descriptor, Some(k)), ctx)));
        }
        // The caller-supplied key is chosen by the members' proofs (DEVELOPMENT-PLAN.md,
        // milestone 2, decided 2026-11-24).
        if let Some(caller) = &caller {
            keys::choose_caller_key(&descriptor.key_hints, caller, &mut resolution);
        }
        let resolution_failed = resolution
            .findings
            .iter()
            .any(|f| f.severity == Severity::Error);
        let considered = keys_and_proofs(&resolution.keys);
        let decision = keys::decide(&considered, ctx.key_policy());
        let correct: Vec<bool> = considered.iter().map(|k| k.correct).collect();
        // A finding that refuses a key that does not decide is a warning, so that the
        // outcome follows the rules (DEVELOPMENT-PLAN.md, milestone 2, decided
        // 2026-11-18), as `verify.issuer_key_not_obtained` does.
        for (index, key) in resolution.keys.iter().enumerate() {
            if decision.deciding == Some(index) {
                continue;
            }
            for &refusal in &key.refusals {
                if let Some(finding) = resolution.findings.get_mut(refusal) {
                    finding.severity = Severity::Warning;
                }
            }
        }
        findings.append(&mut resolution.findings);
        findings.extend(decision_findings(
            &resolution,
            &decision,
            resolution_failed,
            &correct,
        ));
        let outcome = match suite {
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
                // The deciding proof's findings are the ones reported. Without a deciding
                // proof, the suite still checks what does not depend on a key, such as
                // the algorithm, so that those findings are reported too.
                let deciding = decision
                    .deciding
                    .and_then(|d| resolution.keys.get_mut(d))
                    .and_then(|k| k.proved.take());
                let (outcome, suite_findings) =
                    deciding.unwrap_or_else(|| suite.verify(&proof_input(descriptor, None), ctx));
                findings.extend(suite_findings);
                outcome
            }
        };
        let (key_provenance, key_findings) = key_reports(resolution.keys, &decision, &outcome);
        findings.extend(key_findings);
        let validity = proof_validity(&descriptor.times, ctx, &mut findings);
        proofs.push(ProofResult {
            suite: descriptor.suite,
            algorithm: algorithm.map(str::to_owned),
            outcome,
            key_provenance,
            validity,
        });
    }
    PhaseOutcome::from_findings(VerifyOutput { proofs }, findings)
}

/// The findings for the outcome of ARCHITECTURE §8's rules that no other finding states:
/// the issuer key vcrd cannot obtain, an error only when no other key decides, and each
/// unmet condition of the rules that key resolution, the suite or the proofs do not
/// already report, so that verify never passes without a deciding proof key.
fn decision_findings(
    resolution: &Resolution,
    decision: &Decision,
    resolution_failed: bool,
    correct: &[bool],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some(unobtained) = &resolution.unobtained {
        findings.push(match decision.deciding {
            // The table counts the issuer key as not present, so another key decides,
            // and the two are not compared (DEVELOPMENT-PLAN.md, milestone 2).
            Some(_) => Finding::new(
                Phase::Verify,
                Attribution::Vcrd,
                Severity::Warning,
                FindingDetail::IssuerKeyNotObtained {
                    issuer: unobtained.issuer.clone(),
                    method: unobtained.method.clone(),
                    reason: IssuerKeyUnobtainable::MethodUnsupported,
                },
            ),
            None => Finding::error(
                Phase::Verify,
                Attribution::Vcrd,
                FindingDetail::IssuerMethodUnsupported {
                    method: unobtained.method.clone(),
                },
            ),
        });
    }
    let embedded: Vec<&KeyReport> = resolution
        .keys
        .iter()
        .map(|k| &k.report)
        .filter(|r| r.kinds.contains(&KeySource::CredentialEmbedded))
        .collect();
    for condition in &decision.unmet {
        match condition {
            // Refused, and reported as such rather than as "no key material"
            // (REQUIREMENTS §10). The opt-in that would allow it is the caller's.
            Condition::EmbeddedKeyOptIn => {
                findings.extend(embedded.iter().filter_map(|r| {
                    Some(Finding::error(
                        Phase::Verify,
                        Attribution::Policy,
                        FindingDetail::EmbeddedKeyRefused {
                            location: r.location?,
                        },
                    ))
                }));
            }
            Condition::EmbeddedKeysAgree => findings.push(Finding::error(
                Phase::Verify,
                Attribution::Input,
                FindingDetail::EmbeddedKeysDiffer {
                    keys: embedded.iter().map(|r| *r.reference()).collect(),
                },
            )),
            // An issuer key vcrd cannot obtain, or one it cannot decode, already says
            // why there is no key.
            Condition::KeyPresent if !resolution_failed && resolution.unobtained.is_none() => {
                let mut consulted = vec![KeySourceKind::IssuerIdentifier];
                if !embedded.is_empty() {
                    consulted.push(KeySourceKind::CredentialEmbedded);
                }
                findings.push(Finding::error(
                    Phase::Verify,
                    Attribution::Environment,
                    FindingDetail::NoKeyMaterial { consulted },
                ));
            }
            // The caller-supplied key the rules consult, unless it is the refused key that
            // stands in, which its own finding already explains (DEVELOPMENT-PLAN.md,
            // milestone 2, decided 2026-11-18).
            Condition::CallerKeyIsIssuerKey => {
                let found = |k: &&ProofKey| {
                    k.caller == Some(CallerPart::Consulted)
                        && k.report.refused != Some(Refusal::CallerKeyNotFound)
                };
                let caller = resolution.keys.iter().find(found);
                let issuer = resolution
                    .keys
                    .iter()
                    .find(|k| k.report.kinds.contains(&KeySource::IssuerIdentifier));
                if let (Some(caller), Some(issuer)) = (caller, issuer) {
                    findings.push(Finding::error(
                        Phase::Verify,
                        Attribution::Policy,
                        FindingDetail::CallerKeyNotIssuerKey {
                            caller_key: caller.report.reference(),
                            issuer_key: issuer.report.reference(),
                        },
                    ));
                }
            }
            // Two different keys with correct proofs, whatever the opt-ins: each is named.
            Condition::OneKeyCorrect => findings.push(Finding::error(
                Phase::Verify,
                Attribution::Input,
                FindingDetail::DifferentKeysCorrect {
                    keys: resolution
                        .keys
                        .iter()
                        .zip(correct)
                        .filter(|(_, correct)| **correct)
                        .map(|(key, _)| *key.report.reference())
                        .collect(),
                },
            )),
            // Reported by key resolution's findings of a refused key, and by the suite's
            // of an incorrect proof.
            Condition::KeyPresent
            | Condition::DecidingKeyNotRefused
            | Condition::DecidingProofCorrect => {}
        }
    }
    findings
}

/// What ARCHITECTURE §8's rules consult about each key: its kinds, whether key
/// resolution refused it, and whether its proof is correct. A member's key listed for
/// information is not the caller-supplied key the rules consult.
fn keys_and_proofs(keys: &[ProofKey]) -> Vec<KeyAndProof> {
    keys.iter()
        .map(|key| KeyAndProof {
            kinds: key
                .report
                .kinds
                .iter()
                .copied()
                .filter(|&kind| {
                    kind != KeySource::CallerSupplied || key.caller != Some(CallerPart::Listed)
                })
                .collect(),
            refused: key.key.is_none(),
            correct: key.correct(),
        })
        .collect()
}

/// Each key's report, with its proof's result and, for an embedded key alone without the
/// caller's opt-in, its refusal; and the findings for proofs that are correct and do not
/// decide. The proofs with keys other than the deciding proof key are made for
/// information: they decide the outcome only as ARCHITECTURE §8's rules say, and only
/// the deciding proof's findings are reported. The same key gives the same result, so a
/// key that is the deciding proof key has the deciding proof's result.
///
/// An embedded key's correct proof, while the deciding proof is not correct and the two
/// keys are known to differ, is key substitution. An issuer key that the caller-supplied
/// key overrides is named by a warning of its own, with its proof's result, and so is a
/// member's key that is not eligible. Any other correct proof that does not decide is a
/// warning of its own, with the reason.
fn key_reports(
    keys: Vec<ProofKey>,
    decision: &Decision,
    outcome: &ProofOutcome,
) -> (KeyProvenance, Vec<Finding>) {
    // The issuer key, when a caller-supplied key from the key set decides in its place,
    // which only the caller's opt-in to the override allows (ARCHITECTURE §8, rule 1).
    let caller_decides = decision
        .deciding
        .and_then(|d| keys.get(d))
        .is_some_and(|k| {
            k.caller == Some(CallerPart::Consulted)
                && k.report.refused != Some(Refusal::CallerKeyNotFound)
        });
    let overridden = keys
        .iter()
        .position(|k| k.report.kinds.contains(&KeySource::IssuerIdentifier))
        .filter(|&i| caller_decides && decision.deciding != Some(i));
    let embedded_refusal = if decision.unmet.contains(&Condition::EmbeddedKeyOptIn) {
        Some(Refusal::EmbeddedKeyAlone)
    } else if decision.unmet.contains(&Condition::EmbeddedKeysAgree) {
        Some(Refusal::EmbeddedKeysDiffer)
    } else {
        None
    };
    let reports: Vec<KeyReport> = keys
        .into_iter()
        .enumerate()
        .map(|(index, key)| {
            let mut report = key.report;
            report.proof = match key.proved {
                _ if decision.deciding == Some(index) => outcome.clone(),
                Some((proof, _)) => proof,
                None => ProofOutcome::NotAttempted,
            };
            if report.refused.is_none() && report.kinds.contains(&KeySource::CredentialEmbedded) {
                report.refused = embedded_refusal;
            }
            report
        })
        .collect();
    let correct = |o: &ProofOutcome| matches!(o, ProofOutcome::Correct { .. });
    let deciding = decision.deciding.and_then(|d| reports.get(d));
    let mut findings = Vec::new();
    for (index, report) in reports.iter().enumerate() {
        if Some(index) == overridden {
            findings.push(Finding::new(
                Phase::Verify,
                Attribution::Policy,
                Severity::Warning,
                FindingDetail::IssuerKeyOverridden {
                    issuer_key: report.reference(),
                    proof: report.proof.clone(),
                },
            ));
        }
        if decision.deciding == Some(index) || !correct(&report.proof) {
            continue;
        }
        let substituted = deciding.filter(|d| {
            !correct(&d.proof)
                && d.thumbprint.is_some()
                && report.kinds.contains(&KeySource::CredentialEmbedded)
        });
        let detail = match substituted {
            Some(d) => FindingDetail::EmbeddedKeyProofCorrect {
                embedded_key: report.reference(),
                key: d.reference(),
            },
            // Its warning above already gives its proof's result.
            None if Some(index) == overridden => continue,
            // A member that is not eligible: its own finding says its proof is correct
            // (DEVELOPMENT-PLAN.md, milestone 2, decided 2026-11-24).
            None if matches!(
                report.refused,
                Some(Refusal::ExcludedByMember | Refusal::KidNotHeaderKid | Refusal::AlgAlias)
            ) =>
            {
                continue;
            }
            None => FindingDetail::NonDecidingKeyProofCorrect {
                key: report.reference(),
                why: report
                    .refused
                    .map_or(NotDeciding::AnotherKeyDecides, NotDeciding::Refused),
            },
        };
        findings.push(Finding::new(
            Phase::Verify,
            Attribution::Input,
            Severity::Warning,
            detail,
        ));
    }
    let provenance = KeyProvenance {
        deciding: decision.deciding,
        keys: reports,
    };
    (provenance, findings)
}

fn proof_input<'a>(descriptor: &'a ProofDescriptor, key: Option<&'a PublicKey>) -> ProofInput<'a> {
    match &descriptor.material {
        ProofMaterial::Jws {
            signing_input,
            signature,
            critical,
        } => ProofInput::Jws {
            algorithm: descriptor.algorithm.as_ref(),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// No Ed25519 input gives two different keys correct proofs; ECDSA public-key recovery
    /// does, and slice 6 has that fixture. Until then, a decision with the condition unmet
    /// shows the finding: an error attributed to the input, naming each key whose proof
    /// is correct (DEVELOPMENT-PLAN.md, milestone 2, decided 2026-11-13).
    #[test]
    fn two_different_keys_correct_is_an_input_error_naming_both() {
        let key = |kind, thumbprint: &str| ProofKey {
            report: KeyReport {
                thumbprint: Some(thumbprint.to_owned()),
                ..KeyReport::new(kind)
            },
            key: None,
            caller: None,
            refusals: Vec::new(),
            proved: None,
        };
        let resolution = Resolution {
            keys: vec![
                key(KeySource::IssuerIdentifier, "issuer"),
                key(KeySource::CredentialEmbedded, "embedded"),
            ],
            ..Resolution::default()
        };
        let decision = Decision {
            deciding: Some(0),
            unmet: vec![Condition::OneKeyCorrect],
        };
        let findings = decision_findings(&resolution, &decision, false, &[true, true]);
        let [finding] = findings.as_slice() else {
            panic!("one finding: {findings:?}")
        };
        assert_eq!(
            (finding.code, finding.attribution, finding.severity),
            (
                "verify.different_keys_correct",
                Attribution::Input,
                Severity::Error
            )
        );
        let FindingDetail::DifferentKeysCorrect { keys } = &finding.detail else {
            panic!("{finding:?}")
        };
        let thumbprints: Vec<_> = keys.iter().map(|k| k.thumbprint.as_deref()).collect();
        assert_eq!(thumbprints, [Some("issuer"), Some("embedded")]);
    }
}
