//! Tier 2 (§4): data-model conformance and temporal validity. No cryptography, no
//! network -- which is exactly the argument for putting `validFrom`/`validUntil`
//! here rather than in verify (prototype question 7).

use crate::context::Context;
use crate::model::*;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Breakpoint anchor for prototype question 7.
#[inline(never)]
pub fn validate_jwt_vc(parsed: &ParseOutput, ctx: &Context) -> Stage<ValidateOutput> {
    let mut findings: Vec<Finding> = Vec::new();

    let FormatDetail::JwtVc(detail) = &parsed.detail;

    // The 1.1 mapping is detected, named, and refused. Guessing at an authority rule
    // between duplicated claims would be worse than saying vcrd does not do this yet.
    if detail.profile == JwtVcProfile::Vcdm11Mapping {
        findings.push(Finding::error(
            "validate.profile_not_implemented",
            Tier::Validate,
            Blame::Vcrd,
            FindingDetail::ProfileNotImplemented {
                detected: JwtVcProfile::Vcdm11Mapping.as_str(),
                implemented: JwtVcProfile::VcJoseCose.as_str(),
                marker: "payload.vc".to_string(),
            },
        ));

        // Report the concrete disagreement, because it is the evidence for deciding
        // which side would have to be authoritative.
        if let (Some(exp), Some(until)) = (detail.registered.exp, parsed.document.valid_until.as_deref())
            && let Ok(parsed_until) = OffsetDateTime::parse(until, &Rfc3339)
                && parsed_until.unix_timestamp() != exp {
                    findings.push(Finding::error(
                        "validate.claim_disagreement",
                        Tier::Validate,
                        Blame::Input,
                        FindingDetail::ClaimDisagreement {
                            jwt_claim: "exp",
                            vc_field: "expirationDate",
                            jwt_value: exp.to_string(),
                            vc_value: until.to_string(),
                        },
                    ));
                }
        return Stage::Failed { findings };
    }

    if detail.profile == JwtVcProfile::Unknown {
        findings.push(Finding::error(
            "validate.profile_not_implemented",
            Tier::Validate,
            Blame::Input,
            FindingDetail::ProfileNotImplemented {
                detected: JwtVcProfile::Unknown.as_str(),
                implemented: JwtVcProfile::VcJoseCose.as_str(),
                marker: "payload".to_string(),
            },
        ));
        return Stage::Failed { findings };
    }

    // VC-JOSE-COSE requires the media type on the token.
    match detail.typ.as_deref() {
        Some(t) if t == "vc+jwt" || t == "application/vc+jwt" => {}
        Some(_) | None => findings.push(Finding::warn(
            "validate.typ_not_vc_jwt",
            Tier::Validate,
            Blame::Input,
            FindingDetail::FieldWrongType { field: "header.typ", expected: "vc+jwt" },
        )),
    }

    // Required data-model fields.
    if parsed.document.contexts.is_empty() {
        findings.push(required("@context"));
    } else if parsed.document.contexts.first().map(String::as_str) != Some("https://www.w3.org/ns/credentials/v2") {
        findings.push(Finding::error(
            "validate.context_first_entry",
            Tier::Validate,
            Blame::Input,
            FindingDetail::FieldWrongType {
                field: "@context[0]",
                expected: "https://www.w3.org/ns/credentials/v2",
            },
        ));
    }
    if !parsed.document.types.iter().any(|t| t == "VerifiableCredential") {
        findings.push(Finding::error(
            "validate.type_missing_verifiable_credential",
            Tier::Validate,
            Blame::Input,
            FindingDetail::FieldWrongType { field: "type", expected: "VerifiableCredential" },
        ));
    }
    if parsed.document.issuer.is_none() {
        findings.push(required("issuer"));
    }
    if parsed.document.claims.is_empty() {
        findings.push(required("credentialSubject"));
    }

    let temporal = check_temporal(parsed, ctx, &mut findings);

    let failed = findings.iter().any(|f| f.severity == Severity::Error);
    let output = ValidateOutput { profile: detail.profile, temporal };
    if failed {
        Stage::Failed { findings }
    } else {
        Stage::Passed { output, findings }
    }
}

fn required(field: &'static str) -> Finding {
    Finding::error(
        "validate.missing_field",
        Tier::Validate,
        Blame::Input,
        FindingDetail::MissingField { field },
    )
}

/// Breakpoint anchor: temporal semantics and clock skew (§16 item 17).
#[inline(never)]
pub fn check_temporal(parsed: &ParseOutput, ctx: &Context, findings: &mut Vec<Finding>) -> TemporalStatus {
    let now = ctx.clock.now();
    let skew = time::Duration::seconds(ctx.skew_seconds);
    let mut status = TemporalStatus::Unbounded;

    if let Some(from) = parsed.document.valid_from.as_deref() {
        match OffsetDateTime::parse(from, &Rfc3339) {
            Ok(t) => {
                if now + skew < t {
                    status = TemporalStatus::NotYetValid;
                    findings.push(Finding::error(
                        "validate.not_yet_valid",
                        Tier::Validate,
                        Blame::Input,
                        FindingDetail::NotYetValid {
                            valid_from: from.to_string(),
                            now: fmt(now),
                            skew_seconds: ctx.skew_seconds,
                        },
                    ));
                } else {
                    status = TemporalStatus::Current;
                }
            }
            Err(_) => findings.push(bad_date("validFrom", from)),
        }
    }

    if let Some(until) = parsed.document.valid_until.as_deref() {
        match OffsetDateTime::parse(until, &Rfc3339) {
            Ok(t) => {
                if now - skew > t {
                    status = TemporalStatus::Expired;
                    findings.push(Finding::error(
                        "validate.expired",
                        Tier::Validate,
                        Blame::Input,
                        FindingDetail::Expired {
                            valid_until: until.to_string(),
                            now: fmt(now),
                            skew_seconds: ctx.skew_seconds,
                        },
                    ));
                } else if status != TemporalStatus::NotYetValid {
                    status = TemporalStatus::Current;
                }
            }
            Err(_) => findings.push(bad_date("validUntil", until)),
        }
    }

    status
}

fn bad_date(field: &'static str, value: &str) -> Finding {
    Finding::error(
        "validate.datetime_unparseable",
        Tier::Validate,
        Blame::Input,
        FindingDetail::DateTimeUnparseable { field, value: value.to_string() },
    )
}

fn fmt(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_else(|_| t.unix_timestamp().to_string())
}
