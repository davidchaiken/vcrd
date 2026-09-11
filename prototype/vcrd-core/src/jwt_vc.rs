//! VC-JOSE-COSE (VCDM 2.0) as the implemented JWT VC profile, with the VCDM 1.1 JWT
//! mapping detected but deliberately not implemented (prototype question 7).
//!
//! The 1.1 mapping duplicates `exp`/`nbf`/`iss`/`jti` between the registered JWT
//! claims and the inner `vc` object, and the two can disagree. Rather than guess at
//! an authority rule, the spike detects that shape, names it, and reports the
//! disagreement it found -- which is the evidence the real decision needs.

use crate::context::Context;
use crate::format::{CredentialFormat, Detection};
use crate::jws;
use crate::keys::KeyHints;
use crate::limits;
use crate::model::*;
use crate::redact::{ClaimValue, flatten_claims};
use crate::validate;
use serde_json::Value;

pub const FORMAT_ID: FormatId = FormatId("jwt-vc");
pub const SUITE_ID: SuiteId = SuiteId("jose-jws");

#[derive(Debug)]
pub struct JwtVcFormat;

impl CredentialFormat for JwtVcFormat {
    fn id(&self) -> FormatId {
        FORMAT_ID
    }

    fn description(&self) -> &'static str {
        "W3C VC secured with JOSE (VC-JOSE-COSE); compact JWS serialization"
    }

    fn suites(&self) -> Vec<SuiteId> {
        vec![SUITE_ID]
    }

    fn detect(&self, bytes: &[u8]) -> Detection {
        let Ok(text) = core::str::from_utf8(bytes) else {
            return Detection::No;
        };
        let text = text.trim();
        let segments: Vec<&str> = text.split('.').collect();
        if segments.len() != 3 {
            return Detection::No;
        }
        // A three-segment dotted base64url blob whose first segment decodes to JSON
        // with an `alg` is a JWS; that is as far as detection should commit.
        match jws::parse_compact(bytes) {
            Ok(parts) => {
                if parts.header.typ.as_deref().is_some_and(|t| t.contains("vc")) {
                    Detection::Yes
                } else {
                    Detection::Maybe
                }
            }
            Err(_) => Detection::Maybe,
        }
    }

    #[inline(never)]
    fn parse(&self, bytes: &[u8], ctx: &Context) -> Stage<ParseOutput> {
        let mut findings = Vec::new();

        if bytes.len() > ctx.limits.max_bytes {
            findings.push(Finding::error(
                "parse.too_large",
                Tier::Parse,
                Blame::Input,
                FindingDetail::InputTooLarge { limit: ctx.limits.max_bytes, found: bytes.len() },
            ));
            return Stage::Failed { findings };
        }

        let parts = match jws::parse_compact(bytes) {
            Ok(p) => p,
            Err(e) => {
                findings.push(match e {
                    jws::JwsParseError::NotCompact { segments } => Finding::error(
                        "parse.not_compact_jws",
                        Tier::Parse,
                        Blame::Input,
                        FindingDetail::NotCompactJws { segments },
                    ),
                    jws::JwsParseError::Base64 { segment } => Finding::error(
                        "parse.base64_invalid",
                        Tier::Parse,
                        Blame::Input,
                        FindingDetail::Base64Invalid { segment },
                    ),
                    jws::JwsParseError::Json { segment, message } => Finding::error(
                        "parse.json_invalid",
                        Tier::Parse,
                        Blame::Input,
                        FindingDetail::JsonInvalid { segment, message },
                    ),
                    jws::JwsParseError::HeaderAlgMissing => Finding::error(
                        "parse.header_alg_missing",
                        Tier::Parse,
                        Blame::Input,
                        FindingDetail::MissingField { field: "header.alg" },
                    ),
                });
                return Stage::Failed { findings };
            }
        };

        // Structural depth is checked against the decoded payload, not the token, so
        // the base64 wrapper does not hide a nesting bomb.
        match limits::measure_depth(&parts.payload_bytes, ctx.limits.max_depth) {
            Ok(_) => {}
            Err(limits::DepthError::TooDeep { limit, found }) => {
                findings.push(Finding::error(
                    "parse.nesting_too_deep",
                    Tier::Parse,
                    Blame::Input,
                    FindingDetail::NestingTooDeep { limit, found },
                ));
                return Stage::Failed { findings };
            }
        }

        let profile = detect_profile(&parts.payload_json, parts.header.typ.as_deref());
        let credential: &Value = match profile {
            JwtVcProfile::Vcdm11Mapping => parts.payload_json.get("vc").unwrap_or(&parts.payload_json),
            _ => &parts.payload_json,
        };

        let mut claims = Vec::new();
        if let Some(subject) = credential.get("credentialSubject") {
            flatten_claims("credentialSubject", subject, &mut claims, ctx.limits.max_claims);
        }
        if claims.len() >= ctx.limits.max_claims {
            findings.push(Finding::warn(
                "parse.too_many_claims",
                Tier::Parse,
                Blame::Input,
                FindingDetail::TooManyClaims { limit: ctx.limits.max_claims, found: claims.len() },
            ));
        }

        let issuer = string_or_id(credential.get("issuer"))
            .or_else(|| parts.payload_json.get("iss").and_then(Value::as_str).map(str::to_string));

        let document = Document {
            issuer,
            subject: credential
                .get("credentialSubject")
                .and_then(|s| s.get("id"))
                .or_else(|| parts.payload_json.get("sub"))
                .map(|v| ClaimValue::new(v.clone())),
            id: string_or_id(credential.get("id")),
            types: string_list(credential.get("type")),
            contexts: string_list(credential.get("@context")),
            valid_from: credential
                .get("validFrom")
                .or_else(|| credential.get("issuanceDate"))
                .and_then(Value::as_str)
                .map(str::to_string),
            valid_until: credential
                .get("validUntil")
                .or_else(|| credential.get("expirationDate"))
                .and_then(Value::as_str)
                .map(str::to_string),
            claims,
            proofs: vec![ProofDescriptor {
                suite: SUITE_ID,
                declared_alg: parts.header.alg.clone(),
                key_hints: KeyHints {
                    kid: parts.header.kid.clone(),
                    issuer: string_or_id(credential.get("issuer"))
                        .or_else(|| parts.payload_json.get("iss").and_then(Value::as_str).map(str::to_string)),
                    embedded_jwk: parts.header.jwk.clone(),
                    embedded_x5c: parts.header.x5c.is_some(),
                },
                signing_input: parts.signing_input.clone(),
                signature: parts.signature.clone(),
            }],
        };

        let detail = FormatDetail::JwtVc(JwtVcDetail {
            typ: parts.header.typ.clone(),
            cty: parts.header.cty.clone(),
            kid: parts.header.kid.clone(),
            header_alg: parts.header.alg.clone(),
            profile,
            registered: RegisteredClaims {
                iss: parts.payload_json.get("iss").and_then(Value::as_str).map(str::to_string),
                sub: parts.payload_json.get("sub").and_then(Value::as_str).map(str::to_string),
                jti: parts.payload_json.get("jti").and_then(Value::as_str).map(str::to_string),
                exp: parts.payload_json.get("exp").and_then(Value::as_i64),
                nbf: parts.payload_json.get("nbf").and_then(Value::as_i64),
                iat: parts.payload_json.get("iat").and_then(Value::as_i64),
            },
        });

        Stage::Passed { output: ParseOutput { format: FORMAT_ID, document, detail }, findings }
    }

    fn validate(&self, parsed: &ParseOutput, ctx: &Context) -> Stage<ValidateOutput> {
        validate::validate_jwt_vc(parsed, ctx)
    }
}

/// Which VC-JWT shape the payload looks like. `typ` is a hint, not proof.
pub fn detect_profile(payload: &Value, typ: Option<&str>) -> JwtVcProfile {
    if payload.get("vc").is_some() {
        return JwtVcProfile::Vcdm11Mapping;
    }
    let has_context = payload.get("@context").is_some();
    let has_subject = payload.get("credentialSubject").is_some();
    if has_context && has_subject {
        return JwtVcProfile::VcJoseCose;
    }
    if typ.is_some_and(|t| t.contains("vc+jwt")) {
        return JwtVcProfile::VcJoseCose;
    }
    JwtVcProfile::Unknown
}

fn string_or_id(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Object(o)) => o.get("id").and_then(Value::as_str).map(str::to_string),
        _ => None,
    }
}

fn string_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => items.iter().filter_map(|i| i.as_str().map(str::to_string)).collect(),
        _ => Vec::new(),
    }
}
