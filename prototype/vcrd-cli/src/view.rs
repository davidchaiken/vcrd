//! The CLI's own wire schema (prototype question 2).
//!
//! `vcrd-core` derives `Serialize` on nothing. Everything an agent sees is defined
//! here, in one file, with an explicit `schema_version`. The cost of that decision is
//! this file's length -- which is the measurement the question was asking for.

use serde::Serialize;
use serde_json::{Value, json};
use vcrd_core::keys::KeyProvenance;
use vcrd_core::model::*;
use vcrd_core::redact::CleartextGrant;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
pub struct Envelope {
    pub schema_version: u32,
    /// A lossy convenience. `stages` is the real answer; see the findings.
    pub status: &'static str,
    pub exit_code: i32,
    /// Set only under `--unsafe`, so a consumer can refuse to persist the output.
    pub unsafe_cleartext: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<CallerError>,
    pub input: InputView,
    pub stages: StagesView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<FormatView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<CredentialView>,
    pub proofs: Vec<ProofView>,
    pub findings: Vec<FindingView>,
    pub not_evaluated: Vec<NotEvaluatedView>,
}

/// Caller faults have no home in `Report` by design, so the envelope needs its own
/// slot for them. An agent still gets JSON on stdout when the file does not exist.
#[derive(Serialize)]
pub struct CallerError {
    pub code: &'static str,
    pub message: String,
}

#[derive(Serialize)]
pub struct InputView {
    pub byte_len: usize,
    pub measured_depth: Option<usize>,
    pub detected_format: Option<&'static str>,
}

#[derive(Serialize)]
pub struct StagesView {
    pub parse: StageView,
    pub validate: StageView,
    pub verify: StageView,
}

#[derive(Serialize)]
pub struct StageView {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_by: Option<&'static str>,
    pub finding_codes: Vec<&'static str>,
}

#[derive(Serialize)]
pub struct FormatView {
    pub id: &'static str,
    pub profile: &'static str,
    pub typ: Option<String>,
    pub cty: Option<String>,
    pub kid: Option<String>,
    pub header_alg: String,
}

#[derive(Serialize)]
pub struct CredentialView {
    pub id: Option<String>,
    pub issuer: Option<String>,
    /// Redacted like any other claim value; see the note on `Document::subject`.
    pub subject: Option<String>,
    pub types: Vec<String>,
    pub contexts: Vec<String>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub temporal_status: Option<&'static str>,
    pub claims: Vec<ClaimView>,
}

#[derive(Serialize)]
pub struct ClaimView {
    pub path: String,
    pub value_type: &'static str,
    /// Present unless `--unsafe`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted: Option<String>,
    /// Which redaction rule fired. Only emitted with `--explain-redaction`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redaction_rule: Option<&'static str>,
    /// Present only under `--unsafe`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleartext: Option<Value>,
}

#[derive(Serialize)]
pub struct ProofView {
    pub suite: &'static str,
    pub declared_alg: String,
    pub outcome: &'static str,
    pub key_provenance: KeyProvenanceView,
}

#[derive(Serialize)]
pub struct KeyProvenanceView {
    pub kind: &'static str,
    /// The single field a risk layer above vcrd would branch on.
    pub independently_resolved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
}

#[derive(Serialize)]
pub struct FindingView {
    pub code: &'static str,
    pub tier: &'static str,
    pub blame: &'static str,
    pub severity: &'static str,
    pub detail: Value,
}

#[derive(Serialize)]
pub struct NotEvaluatedView {
    pub what: &'static str,
    pub why: &'static str,
}

// ---------------------------------------------------------------------------
// Mapping. Every line below exists because core does not derive `Serialize`.
// ---------------------------------------------------------------------------

pub struct ViewOptions {
    pub cleartext: bool,
    pub explain_redaction: bool,
}

pub fn from_report(report: &Report, opts: &ViewOptions, exit_code: i32) -> Envelope {
    Envelope {
        schema_version: SCHEMA_VERSION,
        status: status_of(report),
        exit_code,
        unsafe_cleartext: opts.cleartext,
        error: None,
        input: InputView {
            byte_len: report.input.byte_len,
            measured_depth: report.input.measured_depth,
            detected_format: report.input.detected_format.map(|f| f.0),
        },
        stages: StagesView {
            parse: stage_view(&report.parse),
            validate: stage_view(&report.validate),
            verify: stage_view(&report.verify),
        },
        format: report.parse.output().map(format_view),
        credential: report.parse.output().map(|p| credential_view(p, report, opts)),
        proofs: report
            .verify
            .output()
            .map(|v| v.proofs.iter().map(proof_view).collect())
            .unwrap_or_default(),
        findings: report.all_findings().into_iter().map(finding_view).collect(),
        not_evaluated: report
            .not_evaluated
            .iter()
            .map(|n| NotEvaluatedView { what: n.what.as_str(), why: n.why.as_str() })
            .collect(),
    }
}

pub fn caller_error(code: &'static str, message: String) -> Envelope {
    Envelope {
        schema_version: SCHEMA_VERSION,
        status: "caller_error",
        exit_code: 1,
        unsafe_cleartext: false,
        error: Some(CallerError { code, message }),
        input: InputView { byte_len: 0, measured_depth: None, detected_format: None },
        stages: StagesView {
            parse: StageView { status: "not_reached", blocked_by: None, finding_codes: vec![] },
            validate: StageView { status: "not_reached", blocked_by: None, finding_codes: vec![] },
            verify: StageView { status: "not_reached", blocked_by: None, finding_codes: vec![] },
        },
        format: None,
        credential: None,
        proofs: vec![],
        findings: vec![],
        not_evaluated: vec![],
    }
}

/// The `_` arm `#[non_exhaustive]` forces. It costs a decision -- what does a
/// renderer show for a format it was compiled before? -- but it is the decision that
/// keeps adding SD-JWT from being a breaking change for every consumer.
fn format_view(p: &ParseOutput) -> FormatView {
    match &p.detail {
        FormatDetail::JwtVc(d) => FormatView {
            id: p.format.0,
            profile: d.profile.as_str(),
            typ: d.typ.clone(),
            cty: d.cty.clone(),
            kid: d.kid.clone(),
            header_alg: d.header_alg.clone(),
        },
        _ => FormatView {
            id: p.format.0,
            profile: "unrecognised-by-this-frontend",
            typ: None,
            cty: None,
            kid: None,
            header_alg: String::new(),
        },
    }
}

fn stage_view<T>(s: &Stage<T>) -> StageView {
    StageView {
        status: s.status(),
        blocked_by: match s {
            Stage::NotReached { blocked_by } => Some(blocked_by.as_str()),
            _ => None,
        },
        finding_codes: s.findings().iter().map(|f| f.code).collect(),
    }
}

fn credential_view(p: &ParseOutput, report: &Report, opts: &ViewOptions) -> CredentialView {
    let grant = opts.cleartext.then(CleartextGrant::i_understand_this_reveals_plaintext);
    CredentialView {
        id: p.document.id.clone(),
        issuer: p.document.issuer.clone(),
        subject: p.document.subject.as_ref().map(|s| match &grant {
            Some(g) => s.reveal(g).as_str().map(str::to_string).unwrap_or_else(|| s.reveal(g).to_string()),
            None => s.redact("credentialSubject.id").to_string(),
        }),
        types: p.document.types.clone(),
        contexts: p.document.contexts.clone(),
        valid_from: p.document.valid_from.clone(),
        valid_until: p.document.valid_until.clone(),
        temporal_status: report.validate.output().map(|v| v.temporal.as_str()),
        claims: p
            .document
            .claims
            .iter()
            .map(|c| {
                let redacted = c.value.redact(&c.path);
                let (text, rule) = match &redacted {
                    vcrd_core::redact::Redacted::Masked { rule, .. } => (redacted.to_string(), rule.as_str()),
                    vcrd_core::redact::Redacted::Hashed { rule, .. } => (redacted.to_string(), rule.as_str()),
                };
                ClaimView {
                    path: c.path.clone(),
                    value_type: c.value.type_tag(),
                    redacted: grant.is_none().then_some(text),
                    redaction_rule: opts.explain_redaction.then_some(rule),
                    cleartext: grant.as_ref().map(|g| c.value.reveal(g).clone()),
                }
            })
            .collect(),
    }
}

fn proof_view(p: &ProofResult) -> ProofView {
    ProofView {
        suite: p.suite.0,
        declared_alg: p.declared_alg.clone(),
        outcome: p.outcome.as_str(),
        key_provenance: provenance_view(&p.key_provenance),
    }
}

fn provenance_view(kp: &KeyProvenance) -> KeyProvenanceView {
    match kp {
        KeyProvenance::IndependentlyResolved { via, thumbprint } => KeyProvenanceView {
            kind: kp.as_str(),
            independently_resolved: true,
            via: Some(via.as_str()),
            location: None,
            accepted: None,
            thumbprint: Some(thumbprint.clone()),
        },
        KeyProvenance::CredentialSupplied { location, thumbprint, accepted } => KeyProvenanceView {
            kind: kp.as_str(),
            independently_resolved: false,
            via: None,
            location: Some(location.as_str()),
            accepted: Some(*accepted),
            thumbprint: Some(thumbprint.clone()),
        },
        KeyProvenance::None => KeyProvenanceView {
            kind: kp.as_str(),
            independently_resolved: false,
            via: None,
            location: None,
            accepted: None,
            thumbprint: None,
        },
    }
}

fn finding_view(f: &Finding) -> FindingView {
    FindingView {
        code: f.code,
        tier: f.tier.as_str(),
        blame: f.blame.as_str(),
        severity: f.severity.as_str(),
        detail: detail_json(&f.detail),
    }
}

/// The tedious half of the view-model decision, written out in full so its cost is
/// visible rather than hypothetical.
fn detail_json(d: &FindingDetail) -> Value {
    use FindingDetail as D;
    match d {
        D::NoFormatMatched { tried } => json!({"type":"no_format_matched","tried":tried}),
        D::NotCompactJws { segments } => json!({"type":"not_compact_jws","segments":segments}),
        D::Base64Invalid { segment } => json!({"type":"base64_invalid","segment":segment}),
        D::JsonInvalid { segment, message } => json!({"type":"json_invalid","segment":segment,"message":message}),
        D::InputTooLarge { limit, found } => json!({"type":"input_too_large","limit":limit,"found":found}),
        D::NestingTooDeep { limit, found } => json!({"type":"nesting_too_deep","limit":limit,"found":found}),
        D::ProfileNotImplemented { detected, implemented, marker } =>
            json!({"type":"profile_not_implemented","detected":detected,"implemented":implemented,"marker":marker}),
        D::MissingField { field } => json!({"type":"missing_field","field":field}),
        D::FieldWrongType { field, expected } => json!({"type":"field_wrong_type","field":field,"expected":expected}),
        D::DateTimeUnparseable { field, value } => json!({"type":"datetime_unparseable","field":field,"value":value}),
        D::Expired { valid_until, now, skew_seconds } =>
            json!({"type":"expired","valid_until":valid_until,"now":now,"skew_seconds":skew_seconds}),
        D::NotYetValid { valid_from, now, skew_seconds } =>
            json!({"type":"not_yet_valid","valid_from":valid_from,"now":now,"skew_seconds":skew_seconds}),
        D::ClaimDisagreement { jwt_claim, vc_field, jwt_value, vc_value } =>
            json!({"type":"claim_disagreement","jwt_claim":jwt_claim,"vc_field":vc_field,
                   "jwt_value":jwt_value,"vc_value":vc_value}),
        D::TooManyClaims { limit, found } => json!({"type":"too_many_claims","limit":limit,"found":found}),
        D::AlgorithmNone => json!({"type":"algorithm_none"}),
        D::AlgorithmUnsupported { declared, supported } =>
            json!({"type":"algorithm_unsupported","declared":declared,"supported":supported}),
        D::AlgorithmPolicyRejected { declared, allowed } =>
            json!({"type":"algorithm_policy_rejected","declared":declared,"allowed":allowed}),
        D::AlgorithmKeyTypeMismatch { declared, key_kind, expects } =>
            json!({"type":"algorithm_key_type_mismatch","declared":declared,"key_kind":key_kind,"expects":expects}),
        D::NoKeyMaterial { looked_at } => json!({"type":"no_key_material","looked_at":looked_at}),
        D::EmbeddedKeyUntrusted { location, thumbprint } =>
            json!({"type":"embedded_key_untrusted","location":location,"thumbprint":thumbprint}),
        D::EmbeddedKeyAcceptedByFlag { location, thumbprint } =>
            json!({"type":"embedded_key_accepted_by_flag","location":location,"thumbprint":thumbprint}),
        D::EmbeddedKeyPinned { location, thumbprint } =>
            json!({"type":"embedded_key_pinned","location":location,"thumbprint":thumbprint}),
        D::DidKeyUndecodable { did, reason } => json!({"type":"did_key_undecodable","did":did,"reason":reason}),
        D::DidKeyCodecUnsupported { did, codec, codec_name } =>
            json!({"type":"did_key_codec_unsupported","did":did,"codec":codec,"codec_name":codec_name}),
        D::JwkUnsupported { reason } => json!({"type":"jwk_unsupported","reason":reason}),
        D::SignatureInvalid { alg } => json!({"type":"signature_invalid","alg":alg}),
    }
}

/// One word for the whole result. Deliberately reports the *earliest* failure, which
/// is why it cannot express "expired but correctly signed" -- `stages` can.
fn status_of(r: &Report) -> &'static str {
    if r.parse.is_failed() {
        return "parse_failed";
    }
    if r.validate.is_failed() {
        return "validate_failed";
    }
    if r.verify.is_failed() {
        return "verify_failed";
    }
    if r.verify.is_passed() {
        return "verified";
    }
    if r.validate.is_passed() {
        return "validated";
    }
    "parsed"
}
