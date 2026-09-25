//! VC-JOSE-COSE: a VCDM 2.0 credential secured as a JWS in compact serialization
//! (VC-JOSE-COSE §3.1.1; RFC 7515 §7.1).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::context::Context;
use crate::document::{
    ContextEntry, Document, DocumentKind, KeyHints, Leaf, LeafClass, ProofDescriptor,
    ProofMaterial, Timestamp,
};
use crate::finding::{Attribution, DateField, Finding, FindingDetail, JwsSegment};
use crate::json::Json;
use crate::registry::{CredentialFormat, Detection, FormatId, ProfileId};
use crate::report::{FormatDetail, InspectOutput, ParseOutput, Phase, PhaseOutcome, Validity};

/// The format.
#[derive(Clone, Copy, Debug, Default)]
pub struct VcJose;

pub const ID: FormatId = FormatId("vc-jose");

/// VCDM 2.0 as the JWT payload (VC-JOSE-COSE §3.1.1).
pub const PROFILE: ProfileId = ProfileId("vc-jose-cose");

/// What only this format has.
#[derive(Clone, Debug)]
pub struct VcJoseDetail {
    pub header: JoseHeader,
    /// The payload as parsed, every member kept.
    pub payload: Json,
}

/// The JOSE header members vcrd reads (RFC 7515 §4.1). Header values are metadata,
/// shown in full.
#[derive(Clone, Debug)]
pub struct JoseHeader {
    /// Algorithm (§4.1.1).
    pub alg: Option<String>,
    /// Key ID (§4.1.4).
    pub kid: Option<String>,
    /// Type (§4.1.9).
    pub typ: Option<String>,
    /// Content Type (§4.1.10).
    pub cty: Option<String>,
    /// The whole header, every member kept.
    pub parsed: Json,
}

impl CredentialFormat for VcJose {
    fn id(&self) -> FormatId {
        ID
    }

    /// Base64url segments separated by dots look like a JOSE compact serialization;
    /// parsing says what is wrong with one that is not a VC-JOSE-COSE credential.
    fn detect(&self, bytes: &[u8]) -> Detection {
        let jose_shaped = bytes.contains(&b'.')
            && bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
        if jose_shaped {
            Detection::Maybe
        } else {
            Detection::No
        }
    }

    fn parse(&self, bytes: &[u8], _ctx: &Context) -> PhaseOutcome<ParseOutput> {
        match parse_jws(bytes) {
            Ok(output) => PhaseOutcome::from_findings(output, Vec::new()),
            Err(finding) => PhaseOutcome::Failed {
                output: ParseOutput::default(),
                findings: vec![finding],
            },
        }
    }

    fn inspect(&self, parsed: &ParseOutput, ctx: &Context) -> PhaseOutcome<InspectOutput> {
        let mut findings = Vec::new();
        let validity = match &parsed.document {
            Some(document) => validity(document, ctx, &mut findings),
            None => Validity::Unknown,
        };
        PhaseOutcome::from_findings(
            InspectOutput {
                profile: Some(PROFILE),
                validity,
            },
            findings,
        )
    }
}

fn parse_error(detail: FindingDetail) -> Finding {
    Finding::error(Phase::Parse, Attribution::Input, detail)
}

fn parse_jws(bytes: &[u8]) -> Result<ParseOutput, Finding> {
    let segments: Vec<&[u8]> = bytes.split(|b| *b == b'.').collect();
    let &[header_b64, payload_b64, signature_b64] = segments.as_slice() else {
        return Err(parse_error(FindingDetail::NotCompactJws {
            segments: segments.len(),
        }));
    };
    let header = decode_object(header_b64, JwsSegment::Header)?;
    let payload = decode_object(payload_b64, JwsSegment::Payload)?;
    let signature = decode(signature_b64, JwsSegment::Signature)?;

    let header = JoseHeader {
        alg: string(header.get("alg")),
        kid: string(header.get("kid")),
        typ: string(header.get("typ")),
        cty: string(header.get("cty")),
        parsed: header,
    };
    // The signing input is the two encoded segments as they arrived (RFC 7515 §5.1).
    let signing_input = [header_b64, b".", payload_b64].concat();
    let document = document(&payload, &header, signing_input, signature);
    Ok(ParseOutput {
        document: Some(document),
        detail: Some(FormatDetail::VcJose(VcJoseDetail { header, payload })),
        depth: None,
        contained: Vec::new(),
    })
}

/// Strict base64url: no padding, no characters outside the alphabet, and no
/// non-zero trailing bits (RFC 7515 §2).
fn decode(segment: &[u8], which: JwsSegment) -> Result<Vec<u8>, Finding> {
    URL_SAFE_NO_PAD.decode(segment).map_err(|e| {
        let offset = match e {
            base64::DecodeError::InvalidByte(offset, _)
            | base64::DecodeError::InvalidLastSymbol { offset, .. } => Some(offset),
            _ => None,
        };
        parse_error(FindingDetail::Base64urlInvalid {
            segment: which,
            offset,
        })
    })
}

fn decode_object(segment: &[u8], which: JwsSegment) -> Result<Json, Finding> {
    let json = Json::parse(&decode(segment, which)?).map_err(|e| {
        parse_error(FindingDetail::JsonInvalid {
            segment: which,
            line: e.line(),
            column: e.column(),
        })
    })?;
    match json {
        Json::Object(_) => Ok(json),
        Json::Scalar(_) | Json::Array(_) => {
            Err(parse_error(FindingDetail::JsonNotObject { segment: which }))
        }
    }
}

fn string(json: Option<&Json>) -> Option<String> {
    json.and_then(Json::as_str).map(str::to_owned)
}

fn document(
    payload: &Json,
    header: &JoseHeader,
    signing_input: Vec<u8>,
    signature: Vec<u8>,
) -> Document {
    // A URL, or an object whose `id` is one (VCDM 2.0 §4.7).
    let issuer = match payload.get("issuer") {
        Some(object @ Json::Object(_)) => string(object.get("id")),
        other => string(other),
    };
    let mut leaves = Vec::new();
    flatten(payload, &mut Vec::new(), &mut leaves);
    Document {
        kind: DocumentKind::Credential,
        contexts: contexts(payload.get("@context")),
        types: strings(payload.get("type")),
        issuer: issuer.clone(),
        valid_from: timestamp(payload.get("validFrom")),
        valid_until: timestamp(payload.get("validUntil")),
        leaves,
        proofs: vec![ProofDescriptor {
            suite: crate::suites::JWS,
            algorithm: header.alg.clone(),
            key_hints: KeyHints {
                issuer,
                kid: header.kid.clone(),
            },
            material: ProofMaterial::Jws {
                signing_input,
                signature,
            },
        }],
    }
}

fn contexts(json: Option<&Json>) -> Vec<ContextEntry> {
    let entry = |item: &Json| match item {
        Json::Object(_) => ContextEntry::Object,
        other => other
            .as_str()
            .map_or(ContextEntry::Other, |s| ContextEntry::Url(s.to_owned())),
    };
    match json {
        None => Vec::new(),
        Some(Json::Array(items)) => items.iter().map(entry).collect(),
        Some(single) => vec![entry(single)],
    }
}

fn strings(json: Option<&Json>) -> Vec<String> {
    match json {
        Some(Json::Array(items)) => items.iter().filter_map(|i| string(Some(i))).collect(),
        other => string(other).into_iter().collect(),
    }
}

fn timestamp(json: Option<&Json>) -> Option<Timestamp> {
    let lexical = string(json)?;
    let parsed = OffsetDateTime::parse(&lexical, &Rfc3339).ok();
    Some(Timestamp { lexical, parsed })
}

/// The payload members whose values are metadata, shown in full (REQUIREMENTS §8).
/// Everything else is a claim, masked by default, including every member vcrd does
/// not recognize. `id`, `jti` (JWT ID) and `sub` (Subject) are claims: each is unique
/// to the credential or its subject.
const METADATA: &[&str] = &[
    "@context",
    "type",
    "issuer",
    "name",
    "description",
    "validFrom",
    "validUntil",
    // Registered JWT claims (RFC 7519 §4.1): Issuer, Audience, Issued At, Not
    // Before, Expiration Time.
    "iss",
    "aud",
    "iat",
    "nbf",
    "exp",
];

enum Segment<'a> {
    Name(&'a str),
    Index(usize),
}

fn classify(path: &[Segment<'_>]) -> LeafClass {
    let mut names = path.iter().filter_map(|s| match s {
        Segment::Name(name) => Some(*name),
        Segment::Index(_) => None,
    });
    match names.next() {
        Some(first) if METADATA.contains(&first) => LeafClass::Metadata,
        // The status entry's type, but not the rest of the entry (VCDM 2.0 §4.10).
        Some("credentialStatus") if names.next() == Some("type") && names.next().is_none() => {
            LeafClass::Metadata
        }
        _ => LeafClass::Claim,
    }
}

fn flatten<'a>(json: &'a Json, path: &mut Vec<Segment<'a>>, leaves: &mut Vec<Leaf>) {
    match json {
        Json::Scalar(value) => leaves.push(Leaf {
            path: path_string(path),
            class: classify(path),
            value: value.clone(),
        }),
        Json::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(Segment::Index(index));
                flatten(item, path, leaves);
                path.pop();
            }
        }
        Json::Object(members) => {
            for member in members {
                path.push(Segment::Name(&member.name));
                flatten(&member.value, path, leaves);
                path.pop();
            }
        }
    }
}

/// `credentialSubject.degree.name`, `type[1]`; a name that is not a plain identifier
/// is quoted as a JSON string: `a["b.c"]`.
fn path_string(path: &[Segment<'_>]) -> String {
    let mut out = String::new();
    for segment in path {
        match segment {
            Segment::Index(index) => out.push_str(&format!("[{index}]")),
            Segment::Name(name) if is_plain(name) => {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(name);
            }
            Segment::Name(name) => {
                out.push('[');
                push_json_string(&mut out, name);
                out.push(']');
            }
        }
    }
    out
}

fn is_plain(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '@' | '$'))
}

fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The validity period against the clock and skew (VCDM 2.0 §4.9).
fn validity(document: &Document, ctx: &Context, findings: &mut Vec<Finding>) -> Validity {
    let now = ctx.now();
    let skew_seconds = ctx.clock_skew().as_secs();
    let skew = time::Duration::try_from(ctx.clock_skew()).unwrap_or(time::Duration::MAX);
    let mut bound = |timestamp: &Option<Timestamp>, field| match timestamp {
        None => Ok(None),
        Some(Timestamp {
            parsed: Some(t), ..
        }) => Ok(Some(*t)),
        Some(Timestamp { parsed: None, .. }) => {
            findings.push(Finding::error(
                Phase::Inspect,
                Attribution::Input,
                FindingDetail::DateTimeInvalid { field },
            ));
            Err(())
        }
    };
    let from = bound(&document.valid_from, DateField::ValidFrom);
    let until = bound(&document.valid_until, DateField::ValidUntil);
    let (Ok(from), Ok(until)) = (from, until) else {
        return Validity::Unknown;
    };
    if from.is_none() && until.is_none() {
        return Validity::Unbounded;
    }
    // Checked arithmetic: a skew past the end of time makes every bound current.
    if let Some(valid_from) = from
        && now
            .checked_add(skew)
            .is_some_and(|latest| valid_from > latest)
    {
        findings.push(Finding::error(
            Phase::Inspect,
            Attribution::Input,
            FindingDetail::NotYetValid {
                valid_from,
                now,
                skew_seconds,
            },
        ));
        return Validity::NotYetValid;
    }
    if let Some(valid_until) = until
        && now
            .checked_sub(skew)
            .is_some_and(|earliest| valid_until < earliest)
    {
        findings.push(Finding::error(
            Phase::Inspect,
            Attribution::Input,
            FindingDetail::Expired {
                valid_until,
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

    fn leaves(payload: &str) -> Vec<(String, LeafClass)> {
        let json = Json::parse(payload.as_bytes()).unwrap();
        let mut leaves = Vec::new();
        flatten(&json, &mut Vec::new(), &mut leaves);
        leaves.into_iter().map(|l| (l.path, l.class)).collect()
    }

    #[test]
    fn classifies_claims_and_metadata() {
        use LeafClass::{Claim, Metadata};
        let got = leaves(
            r#"{"@context": ["a"], "id": "urn:x", "issuer": {"id": "did:x", "name": "n"},
                "credentialSubject": {"id": "did:s", "degree": {"name": "BSc"}},
                "credentialStatus": [{"type": "T", "statusListIndex": "7"}],
                "sub": "did:s", "jti": "urn:x", "exp": 1, "unknown": true}"#,
        );
        let want = [
            ("@context[0]", Metadata),
            ("id", Claim),
            ("issuer.id", Metadata),
            ("issuer.name", Metadata),
            ("credentialSubject.id", Claim),
            ("credentialSubject.degree.name", Claim),
            ("credentialStatus[0].type", Metadata),
            ("credentialStatus[0].statusListIndex", Claim),
            ("sub", Claim),
            ("jti", Claim),
            ("exp", Metadata),
            ("unknown", Claim),
        ];
        let want: Vec<(String, LeafClass)> =
            want.into_iter().map(|(p, c)| (p.to_owned(), c)).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn quotes_names_that_are_not_plain() {
        let got = leaves(r#"{"a.b": {"c\"d": 1}}"#);
        assert_eq!(got[0].0, r#"["a.b"]["c\"d"]"#);
    }

    #[test]
    fn rejects_padding_and_non_canonical_trailing_bits() {
        // "YQ" is the canonical encoding of "a"; "YR" differs only in bits the
        // decoder would discard.
        assert!(decode(b"YQ", JwsSegment::Payload).is_ok());
        assert!(decode(b"YQ==", JwsSegment::Payload).is_err());
        assert!(decode(b"YR", JwsSegment::Payload).is_err());
        assert!(decode(b"Y Q", JwsSegment::Payload).is_err());
    }
}
