//! `text` and `plain` rendering. Both consume the same view model the JSON does, so
//! there is exactly one place where core's types become presentation.

use crate::view::Envelope;
use tabled::builder::Builder;
use tabled::settings::Style;

/// Pass/fail is never colour alone (§8 accessibility).
fn mark(status: &str) -> &'static str {
    match status {
        "passed" => "PASS",
        "failed" => "FAIL",
        "not_reached" => "----",
        _ => "  ? ",
    }
}

pub fn text(e: &Envelope, verbosity: u8) -> String {
    let mut out = String::new();

    if let Some(err) = &e.error {
        out.push_str(&format!("ERROR  {}\n       {}\n", err.code, err.message));
        return out;
    }

    out.push_str(&format!("{}  ({})\n\n", e.status.to_uppercase(), pretty_exit(e.exit_code)));

    let mut b = Builder::default();
    b.push_record(["TIER", "RESULT", "DETAIL"]);
    for (name, s) in [("parse", &e.stages.parse), ("validate", &e.stages.validate), ("verify", &e.stages.verify)] {
        let detail = match s.blocked_by {
            Some(t) => format!("blocked by {t}"),
            None if s.finding_codes.is_empty() => "-".to_string(),
            None => s.finding_codes.join(", "),
        };
        b.push_record([name.to_string(), mark(s.status).to_string(), detail]);
    }
    out.push_str(&b.build().with(Style::rounded()).to_string());
    out.push_str("\n\n");

    if let Some(c) = &e.credential {
        let mut b = Builder::default();
        b.push_record(["FIELD", "VALUE"]);
        push_opt(&mut b, "issuer", c.issuer.as_deref());
        push_opt(&mut b, "subject", c.subject.as_deref());
        push_opt(&mut b, "id", c.id.as_deref());
        if !c.types.is_empty() {
            b.push_record(["type".to_string(), c.types.join(", ")]);
        }
        push_opt(&mut b, "validFrom", c.valid_from.as_deref());
        push_opt(&mut b, "validUntil", c.valid_until.as_deref());
        push_opt(&mut b, "temporal", c.temporal_status);
        if let Some(f) = &e.format {
            b.push_record(["format".to_string(), format!("{} / {}", f.id, f.profile)]);
            b.push_record(["header alg".to_string(), f.header_alg.clone()]);
        }
        out.push_str(&b.build().with(Style::rounded()).to_string());
        out.push_str("\n\n");

        if !c.claims.is_empty() {
            let mut b = Builder::default();
            if e.unsafe_cleartext {
                b.push_record(["CLAIM", "TYPE", "CLEARTEXT"]);
            } else {
                b.push_record(["CLAIM", "TYPE", "REDACTED"]);
            }
            for cl in &c.claims {
                let shown = match (&cl.cleartext, &cl.redacted) {
                    (Some(v), _) => v.to_string(),
                    (None, Some(r)) => match cl.redaction_rule {
                        Some(rule) => format!("{r}  [{rule}]"),
                        None => r.clone(),
                    },
                    _ => String::new(),
                };
                b.push_record([cl.path.clone(), cl.value_type.to_string(), shown]);
            }
            out.push_str(&b.build().with(Style::rounded()).to_string());
            out.push_str("\n\n");
        }
    }

    if !e.proofs.is_empty() {
        let mut b = Builder::default();
        b.push_record(["SUITE", "ALG", "OUTCOME", "KEY PROVENANCE"]);
        for p in &e.proofs {
            let prov = if p.key_provenance.independently_resolved {
                format!("independent ({})", p.key_provenance.via.unwrap_or("?"))
            } else {
                format!(
                    "CREDENTIAL-SUPPLIED ({}, accepted={})",
                    p.key_provenance.location.unwrap_or("?"),
                    p.key_provenance.accepted.unwrap_or(false)
                )
            };
            b.push_record([
                p.suite.to_string(),
                p.declared_alg.clone(),
                p.outcome.to_uppercase(),
                prov,
            ]);
        }
        out.push_str(&b.build().with(Style::rounded()).to_string());
        out.push_str("\n\n");
    }

    if !e.findings.is_empty() {
        let mut b = Builder::default();
        b.push_record(["SEVERITY", "TIER", "BLAME", "CODE", "DETAIL"]);
        for f in &e.findings {
            b.push_record([
                f.severity.to_uppercase(),
                f.tier.to_string(),
                f.blame.to_string(),
                f.code.to_string(),
                hard_wrap(&describe(&f.detail), 64),
            ]);
        }
        out.push_str(&b.build().with(Style::rounded()).to_string());
        out.push_str("\n\n");
    }

    // Non-checks get the same prominence as passes (§12), not a footnote.
    if verbosity >= 1 && !e.not_evaluated.is_empty() {
        out.push_str("NOT EVALUATED (absence of a failure here is not a pass)\n");
        let mut b = Builder::default();
        b.push_record(["CHECK", "WHY"]);
        for n in &e.not_evaluated {
            b.push_record([n.what.to_string(), n.why.to_string()]);
        }
        out.push_str(&b.build().with(Style::rounded()).to_string());
        out.push('\n');
    }

    out
}

/// tabled's `Width::wrap` shares one budget across every column, which shreds the
/// narrow ones. Wrapping the single wide cell by hand is more predictable, and keeps
/// the black-box tests stable.
fn hard_wrap(s: &str, width: usize) -> String {
    let mut out = String::new();
    let mut line = 0usize;
    for word in s.split_whitespace() {
        if line > 0 && line + 1 + word.len() > width {
            out.push('\n');
            line = 0;
        } else if line > 0 {
            out.push(' ');
            line += 1;
        }
        out.push_str(word);
        line += word.len();
    }
    out
}

fn push_opt(b: &mut Builder, name: &str, v: Option<&str>) {
    if let Some(v) = v {
        b.push_record([name.to_string(), v.to_string()]);
    }
}

fn pretty_exit(code: i32) -> &'static str {
    match code {
        0 => "exit 0: all attempted tiers passed",
        1 => "exit 1: caller error",
        2 => "exit 2: parse failed",
        3 => "exit 3: validate failed",
        4 => "exit 4: verify failed",
        5 => "exit 5: rejected by caller policy",
        6 => "exit 6: not supported by vcrd",
        _ => "exit ?",
    }
}

/// Rendering a structured detail into English. This lives here, not in core (§6).
fn describe(d: &serde_json::Value) -> String {
    let t = d.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let get = |k: &str| d.get(k).map(render_scalar).unwrap_or_default();
    match t {
        "algorithm_none" => "token declares alg: none -- unsigned".to_string(),
        "algorithm_unsupported" => format!("{} is not supported; vcrd supports {}", get("declared"), get("supported")),
        "algorithm_policy_rejected" => format!("{} is supported but your allowlist permits only {}", get("declared"), get("allowed")),
        "algorithm_key_type_mismatch" => format!("{} needs a {} key; the resolved key is {}", get("declared"), get("expects"), get("key_kind")),
        "embedded_key_untrusted" => format!("key from {} is not independently established (thumbprint {})", get("location"), get("thumbprint")),
        "embedded_key_accepted_by_flag" => format!("key from {} accepted only because you asked (thumbprint {})", get("location"), get("thumbprint")),
        "embedded_key_pinned" => format!("embedded key matches the independently-resolved one ({})", get("thumbprint")),
        "no_key_material" => format!("no key material found; looked at {}", get("looked_at")),
        "signature_invalid" => format!("{} signature does not verify", get("alg")),
        "expired" => format!("validUntil {} is before now {} (skew {}s)", get("valid_until"), get("now"), get("skew_seconds")),
        "not_yet_valid" => format!("validFrom {} is after now {} (skew {}s)", get("valid_from"), get("now"), get("skew_seconds")),
        "profile_not_implemented" => format!("detected {}, vcrd implements {} (marker: {})", get("detected"), get("implemented"), get("marker")),
        "claim_disagreement" => format!("{}={} disagrees with {}={}", get("jwt_claim"), get("jwt_value"), get("vc_field"), get("vc_value")),
        "nesting_too_deep" => format!("nesting depth {} exceeds the limit of {}", get("found"), get("limit")),
        "input_too_large" => format!("{} bytes exceeds the limit of {}", get("found"), get("limit")),
        "not_compact_jws" => format!("expected 3 dot-separated segments, found {}", get("segments")),
        "base64_invalid" => format!("{} segment is not valid base64url", get("segment")),
        "json_invalid" => format!("{} segment is not valid JSON: {}", get("segment"), get("message")),
        "missing_field" => format!("required field {} is absent", get("field")),
        "field_wrong_type" => format!("{} should be {}", get("field"), get("expected")),
        "did_key_undecodable" => format!("{} could not be decoded: {}", get("did"), get("reason")),
        "did_key_codec_unsupported" => format!("{} uses multicodec {} ({}), which vcrd cannot verify with", get("did"), get("codec"), get("codec_name")),
        "no_format_matched" => format!("no format recognised these bytes; tried {}", get("tried")),
        _ => d.to_string(),
    }
}

fn render_scalar(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(items) => items.iter().map(render_scalar).collect::<Vec<_>>().join(", "),
        other => other.to_string(),
    }
}

/// `plain`: one `key=value` per line, nothing to parse around. Deliberately not a
/// table, and deliberately not JSON.
pub fn plain(e: &Envelope) -> String {
    let mut out = String::new();
    if let Some(err) = &e.error {
        out.push_str(&format!("error={}\nmessage={}\n", err.code, err.message));
        return out;
    }
    out.push_str(&format!("status={}\nexit_code={}\n", e.status, e.exit_code));
    out.push_str(&format!("unsafe_cleartext={}\n", e.unsafe_cleartext));
    out.push_str(&format!("parse={}\nvalidate={}\nverify={}\n", e.stages.parse.status, e.stages.validate.status, e.stages.verify.status));
    if let Some(c) = &e.credential {
        if let Some(i) = &c.issuer {
            out.push_str(&format!("issuer={i}\n"));
        }
        for cl in &c.claims {
            match (&cl.cleartext, &cl.redacted) {
                (Some(v), _) => out.push_str(&format!("claim.{}={}\n", cl.path, v)),
                (None, Some(r)) => out.push_str(&format!("claim.{}={}\n", cl.path, r)),
                _ => {}
            }
        }
    }
    for p in &e.proofs {
        out.push_str(&format!("proof.{}.outcome={}\n", p.declared_alg, p.outcome));
        out.push_str(&format!("proof.{}.key_independent={}\n", p.declared_alg, p.key_provenance.independently_resolved));
    }
    for f in &e.findings {
        out.push_str(&format!("finding={} tier={} blame={} severity={}\n", f.code, f.tier, f.blame, f.severity));
    }
    for n in &e.not_evaluated {
        out.push_str(&format!("not_evaluated.{}={}\n", n.what, n.why));
    }
    out
}
