//! The output schema, and the mapping from core's types into it (ARCHITECTURE §6).
//!
//! Core's types are not serializable. Each schema object here is filled by an
//! explicit function, so renaming something in core breaks this mapping's
//! compilation instead of silently changing what a consumer parses (REQUIREMENTS §9).

use serde::Serialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use vcrd_core::{
    Attribution, BlockReason, Check, Context, DateField, DidKeyProblem, Document, DocumentKind,
    Finding, FindingDetail, FormatDetail, JwsSegment, KeySourceKind, LeafClass, NotEvaluatedReason,
    Phase, PhaseOutcome, ProofOutcome, Rendered, Report, Revealed, Severity, Validity, render,
};

/// `0` until the schema is declared stable (REQUIREMENTS §9).
pub const SCHEMA_VERSION: u32 = 0;

/// The one JSON document an invocation prints.
#[derive(Debug, Serialize)]
pub struct Envelope {
    pub schema_version: u32,
    /// The earliest failed phase, or `passed`. Lossy; read `phases`.
    pub status: &'static str,
    pub exit_code: u8,
    /// Every claim path shown in cleartext (ARCHITECTURE §7).
    pub reveals: Vec<RevealView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorView>,
    #[serde(flatten)]
    pub result: ResultView,
}

/// A caller fault: code and message (ARCHITECTURE §6).
#[derive(Debug, Serialize)]
pub struct ErrorView {
    pub code: &'static str,
    pub message: String,
}

/// One result: the enclosing document's, or a contained credential's.
#[derive(Debug, Serialize)]
pub struct ResultView {
    pub input: InputView,
    pub phases: PhasesView,
    pub proofs: Vec<ProofView>,
    pub findings: Vec<FindingView>,
    pub not_evaluated: Vec<NotEvaluatedView>,
    pub contained: Vec<ResultView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<FormatView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<CredentialView>,
}

#[derive(Debug, Serialize)]
pub struct RevealView {
    pub path: String,
    pub treatment: &'static str,
}

#[derive(Debug, Serialize)]
pub struct InputView {
    pub bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct PhasesView {
    pub parse: PhaseView,
    pub inspect: PhaseView,
    pub verify: PhaseView,
}

#[derive(Debug, Serialize)]
pub struct PhaseView {
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_by: Option<BlockedView>,
    /// The codes of this phase's findings.
    pub findings: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct BlockedView {
    pub phase: &'static str,
    pub reason: &'static str,
    /// The codes of the findings responsible.
    pub findings: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct ProofView {
    pub suite: &'static str,
    pub algorithm: Option<String>,
    pub outcome: &'static str,
    pub key_provenance: ProvenanceView,
}

#[derive(Debug, Serialize)]
pub struct ProvenanceView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_key: Option<CredentialKeyView>,
}

#[derive(Debug, Serialize)]
pub struct CredentialKeyView {
    pub location: String,
    pub thumbprint: String,
    pub matched: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifies_signature: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct FindingView {
    pub code: &'static str,
    pub phase: &'static str,
    pub attribution: &'static str,
    pub severity: &'static str,
    pub detail: Value,
}

#[derive(Debug, Serialize)]
pub struct NotEvaluatedView {
    pub what: &'static str,
    pub why: &'static str,
}

#[derive(Debug, Serialize)]
pub struct FormatView {
    pub id: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<&'static str>,
    /// The format's own fields, such as the JOSE header.
    pub header: Value,
}

#[derive(Debug, Serialize)]
pub struct CredentialView {
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    pub types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validity: Option<&'static str>,
    /// Always shown (REQUIREMENTS §8).
    pub metadata: Vec<LeafView>,
    /// Masked unless revealed (REQUIREMENTS §8).
    pub claims: Vec<LeafView>,
}

#[derive(Debug, Serialize)]
pub struct LeafView {
    pub path: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub treatment: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

/// The envelope for a report.
pub fn envelope(report: &Report, ctx: &Context) -> Envelope {
    let (exit_code, status) = crate::exit::exit_code(report);
    let rendered = report
        .parse
        .output()
        .and_then(|p| p.document.as_ref())
        .map(|document| (document, render(document, ctx)));
    let reveals = rendered.as_ref().map_or_else(Vec::new, |(_, r)| {
        r.reveals
            .iter()
            .map(|r| RevealView {
                path: r.path.clone(),
                treatment: "shown",
            })
            .collect()
    });
    Envelope {
        schema_version: SCHEMA_VERSION,
        status,
        exit_code,
        reveals,
        error: None,
        result: result(report, rendered.as_ref()),
    }
}

/// The envelope for a caller fault: no phase ran (ARCHITECTURE §4, `vcrd-cli`).
pub fn fault(code: &'static str, message: String) -> Envelope {
    let not_run = || PhaseView {
        outcome: "not_reached",
        blocked_by: None,
        findings: Vec::new(),
    };
    Envelope {
        schema_version: SCHEMA_VERSION,
        status: "caller_fault",
        exit_code: crate::exit::CALLER_FAULT,
        reveals: Vec::new(),
        error: Some(ErrorView { code, message }),
        result: ResultView {
            input: InputView {
                bytes: 0,
                depth: None,
                format: None,
            },
            phases: PhasesView {
                parse: not_run(),
                inspect: not_run(),
                verify: not_run(),
            },
            proofs: Vec::new(),
            findings: Vec::new(),
            not_evaluated: Vec::new(),
            contained: Vec::new(),
            format: None,
            credential: None,
        },
    }
}

fn result(report: &Report, rendered: Option<&(&Document, Rendered)>) -> ResultView {
    let validity = report.inspect.output().map(|i| i.validity);
    ResultView {
        input: InputView {
            bytes: report.input.bytes,
            depth: report.input.depth,
            format: report.input.format.map(|f| f.0),
        },
        phases: PhasesView {
            parse: phase(&report.parse),
            inspect: phase(&report.inspect),
            verify: phase(&report.verify),
        },
        proofs: proofs(report),
        findings: report.findings().map(finding).collect(),
        not_evaluated: report
            .not_evaluated
            .iter()
            .map(|n| NotEvaluatedView {
                what: check(n.what),
                why: reason(n.why),
            })
            .collect(),
        // A contained credential's claims are rendered with its own result, once
        // presentations exist (DEVELOPMENT-PLAN.md, milestone 4).
        contained: report.contained.iter().map(|c| result(c, None)).collect(),
        format: format(report),
        credential: rendered.map(|(document, rendered)| credential(document, rendered, validity)),
    }
}

fn phase<T>(outcome: &PhaseOutcome<T>) -> PhaseView {
    let codes = outcome.findings().iter().map(|f| f.code).collect();
    match outcome {
        PhaseOutcome::NotRequested => PhaseView {
            outcome: "not_requested",
            blocked_by: None,
            findings: codes,
        },
        PhaseOutcome::NotReached(blocked) => PhaseView {
            outcome: "not_reached",
            blocked_by: Some(BlockedView {
                phase: phase_name(blocked.by),
                reason: match blocked.reason {
                    BlockReason::Impossible => "impossible",
                    BlockReason::Dangerous => "dangerous",
                },
                findings: blocked.findings.clone(),
            }),
            findings: codes,
        },
        PhaseOutcome::Failed { .. } => PhaseView {
            outcome: "failed",
            blocked_by: None,
            findings: codes,
        },
        PhaseOutcome::Passed { .. } => PhaseView {
            outcome: "passed",
            blocked_by: None,
            findings: codes,
        },
    }
}

pub fn phase_name(phase: Phase) -> &'static str {
    match phase {
        Phase::Parse => "parse",
        Phase::Inspect => "inspect",
        Phase::Verify => "verify",
    }
}

/// Verified proofs when verify ran; otherwise the proofs parse found, not attempted.
fn proofs(report: &Report) -> Vec<ProofView> {
    if let Some(verified) = report.verify.output() {
        return verified
            .proofs
            .iter()
            .map(|p| ProofView {
                suite: p.suite.0,
                algorithm: p.algorithm.clone(),
                outcome: match p.outcome {
                    ProofOutcome::Verified { .. } => "verified",
                    ProofOutcome::Failed => "failed",
                    ProofOutcome::NotAttempted => "not_attempted",
                },
                key_provenance: ProvenanceView {
                    source: p.key_provenance.source.map(|s| s.as_str()),
                    method: p.key_provenance.method,
                    thumbprint: p.key_provenance.thumbprint.clone(),
                    credential_key: p.key_provenance.credential_key.as_ref().map(|k| {
                        CredentialKeyView {
                            location: k.location.clone(),
                            thumbprint: k.thumbprint.clone(),
                            matched: k.matched,
                            verifies_signature: k.verifies_signature,
                        }
                    }),
                },
            })
            .collect();
    }
    let descriptors = report.parse.output().and_then(|p| p.document.as_ref());
    descriptors.map_or_else(Vec::new, |d| {
        d.proofs
            .iter()
            .map(|p| ProofView {
                suite: p.suite.0,
                algorithm: p.algorithm.clone(),
                outcome: "not_attempted",
                key_provenance: ProvenanceView {
                    source: None,
                    method: None,
                    thumbprint: None,
                    credential_key: None,
                },
            })
            .collect()
    })
}

fn finding(f: &Finding) -> FindingView {
    FindingView {
        code: f.code,
        phase: phase_name(f.phase),
        attribution: match f.attribution {
            Attribution::Input => "input",
            Attribution::Policy => "policy",
            Attribution::Vcrd => "vcrd",
            Attribution::Environment => "environment",
        },
        severity: match f.severity {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        },
        detail: detail(&f.detail),
    }
}

/// One arm per variant, tagged by `type` (ARCHITECTURE §6).
fn detail(detail: &FindingDetail) -> Value {
    match detail {
        FindingDetail::NoFormatMatched { registered } => json!({
            "type": "no_format_matched",
            "registered": registered.iter().map(|f| f.0).collect::<Vec<_>>(),
        }),
        FindingDetail::NotCompactJws { segments } => {
            json!({"type": "not_compact_jws", "segments": segments})
        }
        FindingDetail::Base64urlInvalid { segment, offset } => json!({
            "type": "base64url_invalid",
            "segment": jws_segment(*segment),
            "offset": offset,
        }),
        FindingDetail::JsonInvalid {
            segment,
            line,
            column,
        } => json!({
            "type": "json_invalid",
            "segment": jws_segment(*segment),
            "line": line,
            "column": column,
        }),
        FindingDetail::JsonNotObject { segment } => {
            json!({"type": "json_not_object", "segment": jws_segment(*segment)})
        }
        FindingDetail::DateTimeInvalid { field } => {
            json!({"type": "date_time_invalid", "field": date_field(*field)})
        }
        FindingDetail::Expired {
            valid_until,
            now,
            skew_seconds,
        } => json!({
            "type": "expired",
            "valid_until": rfc3339(*valid_until),
            "now": rfc3339(*now),
            "skew_seconds": skew_seconds,
        }),
        FindingDetail::NotYetValid {
            valid_from,
            now,
            skew_seconds,
        } => json!({
            "type": "not_yet_valid",
            "valid_from": rfc3339(*valid_from),
            "now": rfc3339(*now),
            "skew_seconds": skew_seconds,
        }),
        FindingDetail::NoProof => json!({"type": "no_proof"}),
        FindingDetail::SuiteUnavailable { suite } => {
            json!({"type": "suite_unavailable", "suite": suite.0})
        }
        FindingDetail::AlgorithmMissing => json!({"type": "algorithm_missing"}),
        FindingDetail::AlgorithmNone => json!({"type": "algorithm_none"}),
        FindingDetail::AlgorithmUnsupported {
            declared,
            supported,
        } => json!({
            "type": "algorithm_unsupported",
            "declared": declared,
            "supported": supported,
        }),
        FindingDetail::SignatureLength {
            algorithm,
            expected,
            found,
        } => json!({
            "type": "signature_length",
            "algorithm": algorithm,
            "expected": expected,
            "found": found,
        }),
        FindingDetail::SignatureInvalid { algorithm } => {
            json!({"type": "signature_invalid", "algorithm": algorithm})
        }
        FindingDetail::NoKeyMaterial { consulted } => json!({
            "type": "no_key_material",
            "consulted": consulted.iter().map(|k| key_source_kind(*k)).collect::<Vec<_>>(),
        }),
        FindingDetail::IssuerMethodUnsupported { method } => {
            json!({"type": "issuer_method_unsupported", "method": method})
        }
        FindingDetail::DidKeyUndecodable { problem } => {
            json!({"type": "did_key_undecodable", "problem": did_key_problem(*problem)})
        }
        FindingDetail::DidKeyCodecUnsupported { codec, name } => json!({
            "type": "did_key_codec_unsupported",
            "codec": format!("0x{codec:x}"),
            "name": name,
        }),
        FindingDetail::WeakKey { thumbprint } => {
            json!({"type": "weak_key", "thumbprint": thumbprint})
        }
    }
}

fn jws_segment(segment: JwsSegment) -> &'static str {
    match segment {
        JwsSegment::Header => "header",
        JwsSegment::Payload => "payload",
        JwsSegment::Signature => "signature",
    }
}

fn date_field(field: DateField) -> &'static str {
    match field {
        DateField::ValidFrom => "validFrom",
        DateField::ValidUntil => "validUntil",
    }
}

fn key_source_kind(kind: KeySourceKind) -> &'static str {
    match kind {
        KeySourceKind::CallerSupplied => "caller_supplied",
        KeySourceKind::IssuerIdentifier => "issuer_identifier",
        KeySourceKind::CredentialEmbedded => "credential_embedded",
    }
}

fn did_key_problem(problem: DidKeyProblem) -> Value {
    match problem {
        DidKeyProblem::NotBase58btc => json!("not_base58btc"),
        DidKeyProblem::Base58Invalid => json!("base58_invalid"),
        DidKeyProblem::CodecInvalid => json!("codec_invalid"),
        DidKeyProblem::KeyLength { expected, found } => {
            json!({"key_length": {"expected": expected, "found": found}})
        }
        DidKeyProblem::PointInvalid => json!("point_invalid"),
    }
}

fn check(check: Check) -> &'static str {
    match check {
        Check::RevocationStatus => "revocation_status",
        Check::ContextResolution => "context_resolution",
        Check::HolderBinding => "holder_binding",
        Check::ReplayBinding => "replay_binding",
        Check::IssuerAccreditation => "issuer_accreditation",
        Check::SchemaConformance => "schema_conformance",
    }
}

fn reason(reason: NotEvaluatedReason) -> &'static str {
    match reason {
        NotEvaluatedReason::RequiresNetwork => "requires_network",
        NotEvaluatedReason::NoParametersSupplied => "no_parameters_supplied",
        NotEvaluatedReason::NotImplemented => "not_implemented",
        NotEvaluatedReason::OutOfScope => "out_of_scope",
        NotEvaluatedReason::PhaseNotReached => "phase_not_reached",
    }
}

fn rfc3339(t: OffsetDateTime) -> Value {
    t.format(&Rfc3339).map_or(Value::Null, Value::String)
}

fn format(report: &Report) -> Option<FormatView> {
    let id = report.input.format?.0;
    let profile = report.inspect.output().and_then(|i| i.profile).map(|p| p.0);
    let header = match report.parse.output().and_then(|p| p.detail.as_ref()) {
        None => Value::Null,
        #[cfg(feature = "vc-jose")]
        Some(FormatDetail::VcJose(detail)) => json!({
            "alg": detail.header.alg,
            "kid": detail.header.kid,
            "typ": detail.header.typ,
            "cty": detail.header.cty,
        }),
    };
    Some(FormatView {
        id,
        profile,
        header,
    })
}

fn credential(
    document: &Document,
    rendered: &Rendered,
    validity: Option<Validity>,
) -> CredentialView {
    let leaf = |l: &vcrd_core::RenderedLeaf| LeafView {
        path: l.path.clone(),
        kind: l.kind.as_str(),
        treatment: if l.value.is_some() { "shown" } else { "masked" },
        value: l.value.as_ref().map(revealed),
    };
    let of_class = |class| {
        rendered
            .leaves
            .iter()
            .filter(|l| l.class == class)
            .map(leaf)
            .collect()
    };
    CredentialView {
        kind: match document.kind {
            DocumentKind::Credential => "credential",
            DocumentKind::Presentation => "presentation",
        },
        issuer: document.issuer.clone(),
        types: document.types.clone(),
        valid_from: document.valid_from.as_ref().map(|t| t.lexical.clone()),
        valid_until: document.valid_until.as_ref().map(|t| t.lexical.clone()),
        validity: validity.map(|v| match v {
            Validity::Current => "current",
            Validity::Expired => "expired",
            Validity::NotYetValid => "not_yet_valid",
            Validity::Unbounded => "unbounded",
            Validity::Unknown => "unknown",
        }),
        metadata: of_class(LeafClass::Metadata),
        claims: of_class(LeafClass::Claim),
    }
}

fn revealed(value: &Revealed) -> Value {
    match value {
        Revealed::Null => Value::Null,
        Revealed::Bool(b) => Value::Bool(*b),
        // The number's own JSON text, so it prints as written.
        Revealed::Number(n) => serde_json::from_str(n).unwrap_or(Value::Null),
        Revealed::String(s) => Value::String(s.clone()),
    }
}
