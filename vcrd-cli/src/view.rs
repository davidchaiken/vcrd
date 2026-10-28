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
    Attribution, Base64urlProblem, BlockReason, Check, ClaimLocation, Context, CritProblem,
    DateField, DeclaredAlgorithm, DidKeyProblem, Document, DocumentKind, EmbeddedKeyRef, Finding,
    FindingDetail, IssuerProblem, JwkProblem, JwsJsonSyntax, JwsSegment, KeyRef, KeySourceKind,
    LanguageValueProblem, LeafClass, Missing, NotEvaluatedReason, Phase, PhaseOutcome,
    ProofOutcome, PublicJwk, Rendered, RenderedJson, Report, RevealLocation, Revealed, Severity,
    Treatment, Validity, ValueKind, WeakKeyCriterion, render,
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
    /// What vcrd also writes to standard error as a warning, repeated here for a
    /// reader of standard output alone.
    pub warnings: Vec<WarningView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorView>,
    #[serde(flatten)]
    pub result: ResultView,
}

impl Envelope {
    pub fn with_warnings(mut self, warnings: Vec<WarningView>) -> Self {
        self.warnings = warnings;
        self
    }
}

/// A warning: code and message (docs/output.md).
#[derive(Clone, Debug, Serialize)]
pub struct WarningView {
    pub code: &'static str,
    pub message: String,
}

/// The warning `--unsafe` gives, at level 1 or 2 (REQUIREMENTS §8).
pub fn unsafe_warning(level: u8) -> WarningView {
    let shown = if level >= 2 {
        "claim values and cryptographic secrets, such as private keys,"
    } else {
        "claim values"
    };
    WarningView {
        code: "unsafe",
        message: format!(
            "--unsafe={level}: {shown} are printed in cleartext. Treat this output as sensitive."
        ),
    }
}

/// A caller error: code and message (ARCHITECTURE §6).
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
    /// The key the path is relative to: `credential.claims` or `format.header`.
    pub location: &'static str,
    /// As on the value itself: `revealed`. Milestone 3's hashed designation adds
    /// `hashed` (REQUIREMENTS §8).
    pub visibility: &'static str,
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
    /// The kinds of condition this phase found: each code once, in the order first
    /// found. The top-level `findings` list has each occurrence and its detail.
    pub findings: Vec<&'static str>,
}

/// Why a phase did not run. docs/output.md documents every key and value.
#[derive(Debug, Serialize)]
pub struct BlockedView {
    pub phase: &'static str,
    pub reason: &'static str,
    /// What an impossible phase lacks, when the blocking phase's name does not already
    /// say: `key_material`. A block by parse means only that parse failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing: Option<&'static str>,
    /// The key sources considered, when `missing` is `key_material`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consulted: Option<Vec<&'static str>>,
}

#[derive(Debug, Serialize)]
pub struct ProofView {
    pub suite: &'static str,
    pub algorithm: Option<String>,
    pub outcome: &'static str,
    pub key_provenance: ProvenanceView,
    /// The clock against the proof's own times, such as a JWT's `nbf` and `exp`.
    /// Absent when verify did not run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validity: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct ProvenanceView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<&'static str>,
    /// The deciding proof key, as an RFC 7638 thumbprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    /// The deciding proof key, as a JWK: the members the thumbprint covers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedded_key: Option<EmbeddedKeyView>,
}

#[derive(Debug, Serialize)]
pub struct EmbeddedKeyView {
    pub location: String,
    pub thumbprint: String,
    /// The embedded key's public members, which its thumbprint covers.
    pub jwk: Value,
    /// Absent when there is no issuer key to compare it with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub same_as_issuer_key: Option<bool>,
    /// The proof's result with it as the proof key.
    pub proof: &'static str,
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
    /// The securing mechanism's header, such as the JOSE header: one entry per value,
    /// in input order, as for the claims; empty when there is none or it did not
    /// decode.
    pub header: Vec<LeafView>,
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

/// One value, with whether it is sensitive and whether it is shown.
#[derive(Debug, Serialize)]
pub struct LeafView {
    pub path: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// `non_sensitive`: metadata, always shown; `masked`: a claim or secret, not shown;
    /// `revealed`: a claim or secret shown because `--unsafe` asked for it.
    pub visibility: &'static str,
    /// Absent where the value is masked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

/// A value's visibility, from its class and whether rendering showed it.
fn leaf_view(path: &str, class: LeafClass, kind: ValueKind, value: Option<&Revealed>) -> LeafView {
    LeafView {
        path: path.to_owned(),
        kind: kind.as_str(),
        visibility: match (class, value) {
            (LeafClass::Metadata, _) => "non_sensitive",
            (LeafClass::Claim | LeafClass::Secret, None) => "masked",
            (LeafClass::Claim | LeafClass::Secret, Some(_)) => "revealed",
        },
        value: value.map(revealed),
    }
}

/// The envelope for a report. `size` is the input file's size, when the frontend
/// knows it; it may exceed what core was given (ARCHITECTURE §4).
pub fn envelope(report: &Report, ctx: &Context, size: Option<u64>) -> Envelope {
    let (exit_code, status) = crate::exit::exit_code(report);
    let rendered = report.parse.output().map(|parsed| render(parsed, ctx));
    let reveals = rendered.as_ref().map_or_else(Vec::new, |r| {
        r.reveals
            .iter()
            .map(|r| RevealView {
                path: r.path.clone(),
                location: match r.location {
                    RevealLocation::Leaves => "credential.claims",
                    RevealLocation::Header => "format.header",
                },
                visibility: match r.treatment {
                    Treatment::Shown => "revealed",
                },
            })
            .collect()
    });
    Envelope {
        schema_version: SCHEMA_VERSION,
        status,
        exit_code,
        reveals,
        warnings: Vec::new(),
        error: None,
        result: result(report, rendered.as_ref(), size),
    }
}

/// The envelope for a caller error: no phase ran (ARCHITECTURE §4, `vcrd-cli`).
pub fn caller_error(code: &'static str, message: String) -> Envelope {
    let not_run = || PhaseView {
        outcome: "not_reached",
        blocked_by: None,
        findings: Vec::new(),
    };
    Envelope {
        schema_version: SCHEMA_VERSION,
        status: "caller_error",
        exit_code: crate::exit::CALLER_ERROR,
        reveals: Vec::new(),
        warnings: Vec::new(),
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

fn result(report: &Report, rendered: Option<&Rendered>, size: Option<u64>) -> ResultView {
    let validity = report.inspect.output().map(|i| i.validity);
    let document = report.parse.output().and_then(|p| p.document.as_ref());
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
        findings: report.findings().map(|f| finding(f, size)).collect(),
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
        contained: report
            .contained
            .iter()
            .map(|c| result(c, None, None))
            .collect(),
        format: format(report, rendered),
        credential: document
            .zip(rendered)
            .map(|(document, rendered)| credential(document, rendered, validity)),
    }
}

fn phase<T>(outcome: &PhaseOutcome<T>) -> PhaseView {
    let mut codes: Vec<&'static str> = Vec::new();
    for finding in outcome.findings() {
        if !codes.contains(&finding.code) {
            codes.push(finding.code);
        }
    }
    match outcome {
        PhaseOutcome::NotRequested => PhaseView {
            outcome: "not_requested",
            blocked_by: None,
            findings: codes,
        },
        PhaseOutcome::NotReached(blocked) => {
            let (reason, missing, consulted) = match &blocked.reason {
                BlockReason::Impossible {
                    missing: Missing::Document,
                } => ("impossible", None, None),
                BlockReason::Impossible {
                    missing: Missing::KeyMaterial { consulted },
                } => (
                    "impossible",
                    Some("key_material"),
                    Some(consulted.iter().map(|k| key_source_kind(*k)).collect()),
                ),
                BlockReason::Dangerous => ("dangerous", None, None),
            };
            PhaseView {
                outcome: "not_reached",
                blocked_by: Some(BlockedView {
                    phase: phase_name(blocked.by),
                    reason,
                    missing,
                    consulted,
                }),
                findings: codes,
            }
        }
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
                outcome: proof_outcome(&p.outcome),
                key_provenance: ProvenanceView {
                    source: p.key_provenance.source.map(|s| s.as_str()),
                    method: p.key_provenance.method,
                    thumbprint: p.key_provenance.thumbprint.clone(),
                    jwk: p.key_provenance.jwk.as_ref().map(jwk),
                    embedded_key: p
                        .key_provenance
                        .embedded_key
                        .as_ref()
                        .map(|k| EmbeddedKeyView {
                            location: k.location.clone(),
                            thumbprint: k.thumbprint.clone(),
                            jwk: jwk(&k.jwk),
                            same_as_issuer_key: k.same_as_issuer_key,
                            proof: proof_outcome(&k.proof),
                        }),
                },
                validity: Some(validity_name(p.validity)),
            })
            .collect();
    }
    let descriptors = report.parse.output().and_then(|p| p.document.as_ref());
    descriptors.map_or_else(Vec::new, |d| {
        d.proofs
            .iter()
            .map(|p| ProofView {
                suite: p.suite.0,
                algorithm: p
                    .algorithm
                    .as_ref()
                    .and_then(DeclaredAlgorithm::name)
                    .map(str::to_owned),
                outcome: "not_attempted",
                key_provenance: ProvenanceView {
                    source: None,
                    method: None,
                    thumbprint: None,
                    jwk: None,
                    embedded_key: None,
                },
                validity: None,
            })
            .collect()
    })
}

/// A proof's result with one proof key (ARCHITECTURE §8).
fn proof_outcome(outcome: &ProofOutcome) -> &'static str {
    match outcome {
        ProofOutcome::Correct { .. } => "correct",
        ProofOutcome::Incorrect => "incorrect",
        ProofOutcome::NotAttempted => "not_attempted",
    }
}

fn finding(f: &Finding, size: Option<u64>) -> FindingView {
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
        detail: detail(&f.detail, size),
    }
}

/// One arm per variant, tagged by `type` (ARCHITECTURE §6). A `segment` of `null`
/// means the input as a whole.
fn detail(detail: &FindingDetail, size: Option<u64>) -> Value {
    match detail {
        // `read` is what core was given; `size` is the file's size, `null` when the
        // input is not a file, which means more than `limit`.
        FindingDetail::InputTooLarge { limit, found } => json!({
            "type": "input_too_large",
            "limit": limit,
            "read": found,
            "size": size,
        }),
        FindingDetail::NestingTooDeep {
            segment,
            limit,
            found,
        } => json!({
            "type": "nesting_too_deep",
            "segment": segment.map(jws_segment),
            "limit": limit,
            "found": found,
        }),
        FindingDetail::TooManyClaims { limit } => {
            json!({"type": "too_many_claims", "limit": limit})
        }
        FindingDetail::TrailingWhitespace { bytes } => {
            json!({"type": "trailing_whitespace", "bytes": bytes})
        }
        FindingDetail::JwsJsonSerialization { syntax } => json!({
            "type": "jws_json_serialization",
            "syntax": match syntax {
                JwsJsonSyntax::General => "general",
                JwsJsonSyntax::Flattened => "flattened",
            },
        }),
        FindingDetail::JsonNotJws => json!({"type": "json_not_jws"}),
        FindingDetail::DataIntegrityUnsupported => json!({"type": "data_integrity_unsupported"}),
        FindingDetail::NotSecured => json!({"type": "not_secured"}),
        FindingDetail::NoFormatMatched { registered } => json!({
            "type": "no_format_matched",
            "registered": registered.iter().map(|f| f.0).collect::<Vec<_>>(),
        }),
        FindingDetail::NotCompactJws { segments } => {
            json!({"type": "not_compact_jws", "segments": segments})
        }
        FindingDetail::Base64urlInvalid { segment, problem } => json!({
            "type": "base64url_invalid",
            "segment": jws_segment(*segment),
            "problem": match problem {
                Base64urlProblem::InvalidSymbol => "invalid_symbol",
                Base64urlProblem::NonzeroTrailingBits => "nonzero_trailing_bits",
                Base64urlProblem::InvalidLength => "invalid_length",
                Base64urlProblem::Padding => "padding",
            },
        }),
        FindingDetail::JsonInvalid {
            segment,
            line,
            column,
        } => json!({
            "type": "json_invalid",
            "segment": segment.map(jws_segment),
            "line": line,
            "column": column,
        }),
        FindingDetail::JsonNotObject { segment } => {
            json!({"type": "json_not_object", "segment": jws_segment(*segment)})
        }
        FindingDetail::DuplicateName {
            segment,
            path,
            count,
        } => json!({
            "type": "duplicate_name",
            "segment": segment.map(jws_segment),
            "path": path,
            "count": count,
        }),
        FindingDetail::CritInvalid { problem } => {
            json!({"type": "crit_invalid", "problem": crit_problem(problem)})
        }
        FindingDetail::HeaderMemberType {
            member,
            expected,
            found,
        } => json!({
            "type": "header_member_type",
            "member": member,
            "expected": expected,
            "found": found,
        }),
        FindingDetail::JwkInvalid { problem } => {
            json!({"type": "jwk_invalid", "problem": jwk_problem(problem)})
        }
        FindingDetail::JwkKtyUnsupported { kty } => {
            json!({"type": "jwk_kty_unsupported", "kty": kty})
        }
        FindingDetail::JwkPrivateKey { members } => {
            json!({"type": "jwk_private_key", "members": members})
        }
        FindingDetail::NumericDateInvalid { claim } => {
            json!({"type": "numeric_date_invalid", "claim": claim})
        }
        FindingDetail::ContextMissing => json!({"type": "context_missing"}),
        FindingDetail::ContextFirstInvalid { found } => {
            json!({"type": "context_first_invalid", "found": found})
        }
        FindingDetail::ContextEntryInvalid { path } => {
            json!({"type": "context_entry_invalid", "path": path})
        }
        FindingDetail::TypeMissing { path } => json!({"type": "type_missing", "path": path}),
        FindingDetail::TypeNotString { path } => {
            json!({"type": "type_not_string", "path": path})
        }
        FindingDetail::TypeLacksVerifiableCredential => {
            json!({"type": "type_lacks_verifiable_credential"})
        }
        FindingDetail::IssuerMissing => json!({"type": "issuer_missing"}),
        FindingDetail::IssuerInvalid { problem } => json!({
            "type": "issuer_invalid",
            "problem": match problem {
                IssuerProblem::WrongType => json!("wrong_type"),
                IssuerProblem::NoId => json!("no_id"),
                IssuerProblem::NotUrl { error } => json!({"not_url": error}),
            },
        }),
        FindingDetail::CredentialSubjectMissing => json!({"type": "credential_subject_missing"}),
        FindingDetail::CredentialSubjectInvalid { path } => {
            json!({"type": "credential_subject_invalid", "path": path})
        }
        FindingDetail::CredentialSubjectEmpty { path } => {
            json!({"type": "credential_subject_empty", "path": path})
        }
        FindingDetail::CredentialSubjectNoClaims { path } => {
            json!({"type": "credential_subject_no_claims", "path": path})
        }
        FindingDetail::UrlInvalid { path, error } => {
            json!({"type": "url_invalid", "path": path, "error": error})
        }
        FindingDetail::UrlNonconforming { path, violations } => json!({
            "type": "url_nonconforming",
            "path": path,
            "violations": violations,
        }),
        FindingDetail::IdMissing { path } => json!({"type": "id_missing", "path": path}),
        FindingDetail::LanguageValueInvalid { path, problem } => json!({
            "type": "language_value_invalid",
            "path": path,
            "problem": match problem {
                LanguageValueProblem::WrongType => json!("wrong_type"),
                LanguageValueProblem::ValueMissing => json!("value_missing"),
                LanguageValueProblem::OtherMember { name } => json!({"other_member": name}),
            },
        }),
        FindingDetail::DateTimeInvalid {
            field,
            valid_rfc3339,
        } => json!({
            "type": "date_time_invalid",
            "field": date_field(*field),
            "valid_rfc3339": valid_rfc3339,
        }),
        FindingDetail::DateTimeUnrepresentable { field } => {
            json!({"type": "date_time_unrepresentable", "field": date_field(*field)})
        }
        FindingDetail::ValidUntilBeforeValidFrom {
            valid_from,
            valid_until,
        } => json!({
            "type": "valid_until_before_valid_from",
            "valid_from": rfc3339(*valid_from),
            "valid_until": rfc3339(*valid_until),
        }),
        FindingDetail::TypUnexpected { found, expected } => {
            json!({"type": "typ_unexpected", "found": found, "expected": expected})
        }
        FindingDetail::CtyUnexpected { found, expected } => {
            json!({"type": "cty_unexpected", "found": found, "expected": expected})
        }
        FindingDetail::VcdmV1JwtEncoding { claim } => {
            json!({"type": "vcdm_1_1_jwt_encoding", "claim": claim})
        }
        FindingDetail::PresentationUnsupported => json!({"type": "presentation_unsupported"}),
        FindingDetail::JwtClaimForbidden { claim } => {
            json!({"type": "jwt_claim_forbidden", "claim": claim})
        }
        FindingDetail::IssMismatch {
            location,
            iss,
            issuer,
        } => json!({
            "type": "iss_mismatch",
            "location": claim_location(*location),
            "iss": iss,
            "issuer": issuer,
        }),
        FindingDetail::JwtClaimConflict { claim, property } => {
            json!({"type": "jwt_claim_conflict", "claim": claim, "property": property})
        }
        FindingDetail::JwtClaimType {
            location,
            claim,
            expected,
            found,
        } => json!({
            "type": "jwt_claim_type",
            "location": claim_location(*location),
            "claim": claim,
            "expected": expected,
            "found": found,
        }),
        FindingDetail::ReplicatedClaimMismatch { claim } => {
            json!({"type": "replicated_claim_mismatch", "claim": claim})
        }
        FindingDetail::KidMissing => json!({"type": "kid_missing"}),
        FindingDetail::KidNotAbsolute { kid } => {
            json!({"type": "kid_not_absolute", "kid": kid})
        }
        FindingDetail::KidForeign {
            kid,
            issuer,
            expected,
        } => json!({
            "type": "kid_foreign",
            "kid": kid,
            "issuer": issuer,
            "expected": expected,
        }),
        FindingDetail::KidWithoutThumbprint { kid } => {
            json!({"type": "kid_without_thumbprint", "kid": kid})
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
        FindingDetail::AlgorithmInvalid { found } => {
            json!({"type": "algorithm_invalid", "found": found})
        }
        FindingDetail::AlgorithmNone => json!({"type": "algorithm_none"}),
        FindingDetail::AlgorithmDeprecated {
            declared,
            replacement,
        } => json!({
            "type": "algorithm_deprecated",
            "declared": declared,
            "replacement": replacement,
        }),
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
        FindingDetail::SignatureSmallOrder { algorithm } => {
            json!({"type": "signature_small_order", "algorithm": algorithm})
        }
        FindingDetail::SignatureScalarOutOfRange { algorithm } => {
            json!({"type": "signature_scalar_out_of_range", "algorithm": algorithm})
        }
        FindingDetail::CritUnsupported {
            extensions,
            supported,
        } => json!({
            "type": "crit_unsupported",
            "extensions": extensions,
            "supported": supported,
        }),
        FindingDetail::ProofExpired {
            claim,
            value,
            value_date_time,
            now,
            skew_seconds,
        } => proof_time(
            "proof_expired",
            claim,
            value,
            *value_date_time,
            *now,
            *skew_seconds,
        ),
        FindingDetail::ProofNotYetValid {
            claim,
            value,
            value_date_time,
            now,
            skew_seconds,
        } => proof_time(
            "proof_not_yet_valid",
            claim,
            value,
            *value_date_time,
            *now,
            *skew_seconds,
        ),
        FindingDetail::ProofIssuedInFuture {
            claim,
            value,
            value_date_time,
            now,
            skew_seconds,
        } => proof_time(
            "proof_issued_in_future",
            claim,
            value,
            *value_date_time,
            *now,
            *skew_seconds,
        ),
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
        FindingDetail::DidKeyNotForSigning { codec, name } => json!({
            "type": "did_key_not_for_signing",
            "codec": format!("0x{codec:x}"),
            "name": name,
        }),
        FindingDetail::WeakKey { key, criterion } => json!({
            "type": "weak_key",
            "key": key_ref(key),
            "criterion": match criterion {
                WeakKeyCriterion::SmallOrder => "small_order",
            },
        }),
        FindingDetail::EmbeddedKeyRefused { location } => {
            json!({"type": "embedded_key_refused", "location": location})
        }
        FindingDetail::EmbeddedKeyMismatch { embedded_key, key } => json!({
            "type": "embedded_key_mismatch",
            "embedded_key": embedded_key_ref(embedded_key),
            "key": key_ref(key),
        }),
        FindingDetail::EmbeddedKeyProofCorrect { embedded_key, key } => json!({
            "type": "embedded_key_proof_correct",
            "embedded_key": embedded_key_ref(embedded_key),
            "key": key_ref(key),
        }),
    }
}

/// The embedded key as a finding names it: where it was, and its thumbprint.
fn embedded_key_ref(key: &EmbeddedKeyRef) -> Value {
    json!({"location": key.location, "thumbprint": key.thumbprint})
}

/// A key as a finding names it: where it came from, as `key_provenance` says, and its
/// thumbprint.
fn key_ref(key: &KeyRef) -> Value {
    json!({"source": key.source.as_str(), "method": key.method, "thumbprint": key.thumbprint})
}

/// A public key's JWK members as a JSON object.
fn jwk(jwk: &PublicJwk) -> Value {
    Value::Object(
        jwk.members
            .iter()
            .map(|(name, value)| ((*name).to_owned(), Value::String(value.clone())))
            .collect(),
    )
}

/// A proof's time and the clock it was compared with. `value` is the JSON number as
/// written; `value_date_time` is the same instant in RFC 3339, `null` when it is outside
/// the years -9999 to 9999.
fn proof_time(
    kind: &str,
    claim: &str,
    value: &str,
    value_date_time: Option<OffsetDateTime>,
    now: OffsetDateTime,
    skew_seconds: u64,
) -> Value {
    json!({
        "type": kind,
        "claim": claim,
        "value": serde_json::from_str::<Value>(value).unwrap_or(Value::Null),
        "value_date_time": value_date_time.map_or(Value::Null, rfc3339),
        "now": rfc3339(now),
        "skew_seconds": skew_seconds,
    })
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

fn crit_problem(problem: &CritProblem) -> Value {
    match problem {
        CritProblem::NotArray => json!("not_array"),
        CritProblem::Empty => json!("empty"),
        CritProblem::NotString { index } => json!({"not_string": index}),
        CritProblem::Duplicate { name } => json!({"duplicate": name}),
        CritProblem::Registered { name } => json!({"registered": name}),
        CritProblem::NotInHeader { name } => json!({"not_in_header": name}),
    }
}

fn jwk_problem(problem: &JwkProblem) -> Value {
    match problem {
        JwkProblem::NotObject => json!("not_object"),
        JwkProblem::KtyMissing => json!("kty_missing"),
        JwkProblem::Symmetric => json!("symmetric"),
        // Reported as `jwk_kty_unsupported`; kept here so that the mapping is total.
        JwkProblem::KtyUnknown { kty } => json!({"kty_unknown": kty}),
        JwkProblem::MemberMissing { member } => json!({"member_missing": member}),
        JwkProblem::KeyInvalid => json!("key_invalid"),
    }
}

fn key_source_kind(kind: KeySourceKind) -> &'static str {
    match kind {
        KeySourceKind::CallerSupplied => "caller_supplied",
        KeySourceKind::IssuerIdentifier => "issuer_identifier",
        KeySourceKind::CredentialEmbedded => "credential_embedded",
    }
}

fn claim_location(location: ClaimLocation) -> &'static str {
    match location {
        ClaimLocation::Header => "header",
        ClaimLocation::Payload => "payload",
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
        DidKeyProblem::PointNotCanonical => json!("point_not_canonical"),
        DidKeyProblem::VersionPresent => json!("version_present"),
    }
}

fn check(check: Check) -> &'static str {
    match check {
        Check::RevocationStatus => "revocation_status",
        Check::ContextResolution => "context_resolution",
        Check::Audience => "audience",
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

fn format(report: &Report, rendered: Option<&Rendered>) -> Option<FormatView> {
    let id = report.input.format?.0;
    let profile = report.inspect.output().and_then(|i| i.profile).map(|p| p.0);
    let mut header = Vec::new();
    if let Some(rendered) = rendered.and_then(|r| r.header.as_ref()) {
        header_leaves(rendered, &mut header);
    }
    Some(FormatView {
        id,
        profile,
        header,
    })
}

/// The header's scalars in input order, as the claims are listed. A repeated member
/// name lists each occurrence, as the input has them.
fn header_leaves(json: &RenderedJson, out: &mut Vec<LeafView>) {
    match json {
        RenderedJson::Scalar {
            path,
            class,
            kind,
            value,
        } => out.push(leaf_view(path, *class, *kind, value.as_ref())),
        RenderedJson::Array(items) => items.iter().for_each(|i| header_leaves(i, out)),
        RenderedJson::Object(members) => members.iter().for_each(|(_, v)| header_leaves(v, out)),
    }
}

fn credential(
    document: &Document,
    rendered: &Rendered,
    validity: Option<Validity>,
) -> CredentialView {
    let leaf = |l: &vcrd_core::RenderedLeaf| leaf_view(&l.path, l.class, l.kind, l.value.as_ref());
    let of_class = |wanted: fn(LeafClass) -> bool| {
        rendered
            .leaves
            .iter()
            .filter(|l| wanted(l.class))
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
        valid_from: document.valid_from.as_ref().and_then(|t| t.lexical.clone()),
        valid_until: document
            .valid_until
            .as_ref()
            .and_then(|t| t.lexical.clone()),
        validity: validity.map(validity_name),
        metadata: of_class(|c| c == LeafClass::Metadata),
        // A secret among a document's leaves is masked with the claims; formats
        // class header members, not leaves, as secrets today.
        claims: of_class(|c| c != LeafClass::Metadata),
    }
}

fn validity_name(validity: Validity) -> &'static str {
    match validity {
        Validity::Current => "current",
        Validity::Expired => "expired",
        Validity::NotYetValid => "not_yet_valid",
        Validity::Unbounded => "unbounded",
        Validity::Unknown => "unknown",
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
