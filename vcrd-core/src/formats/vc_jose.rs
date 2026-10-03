//! VC-JOSE-COSE: a VCDM 2.0 credential secured as a JWS in compact serialization
//! (VC-JOSE-COSE §3.1.1; RFC 7515 §7.1).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::context::{Context, Limits};
use crate::document::{
    ContextEntry, DateTimeProblem, Document, DocumentKind, KeyHints, Leaf, LeafClass,
    ProofDescriptor, ProofMaterial, Timestamp,
};
use crate::finding::{
    Attribution, Base64urlProblem, CritProblem, Finding, FindingDetail, IssLocation, JwsJsonSyntax,
    JwsSegment, Severity,
};
use crate::json::{Json, Step, nesting_depth, path_string};
use crate::registry::{CredentialFormat, Detection, FormatId, ProfileId};
use crate::report::{
    Check, FormatDetail, InspectOutput, NotEvaluated, NotEvaluatedReason, ParseOutput, Phase,
    PhaseOutcome, Validity,
};
use crate::vcdm;

/// The format.
#[derive(Clone, Copy, Debug, Default)]
pub struct VcJose;

pub const ID: FormatId = FormatId("vc-jose");

/// VCDM 2.0 as the JWT payload (VC-JOSE-COSE §3.1.1).
pub const PROFILE: ProfileId = ProfileId("vc-jose-cose");

/// What only this format has. A failed parse keeps whichever segments decoded.
#[derive(Clone, Debug)]
pub struct VcJoseDetail {
    pub header: Option<JoseHeader>,
    /// The payload as parsed, every member kept.
    pub payload: Option<Json>,
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

impl JoseHeader {
    fn new(parsed: Json) -> Self {
        JoseHeader {
            alg: string(parsed.get("alg")),
            kid: string(parsed.get("kid")),
            typ: string(parsed.get("typ")),
            cty: string(parsed.get("cty")),
            parsed,
        }
    }
}

impl CredentialFormat for VcJose {
    fn id(&self) -> FormatId {
        ID
    }

    /// Recognizes the shapes of both JWS serializations, so that parsing can say what
    /// is wrong with an input rather than detection failing on it.
    fn detect(&self, bytes: &[u8]) -> Detection {
        if compact_shaped(bytes.trim_ascii_end()) || json_serialization_shaped(bytes) {
            Detection::Maybe
        } else {
            Detection::No
        }
    }

    fn parse(&self, bytes: &[u8], ctx: &Context) -> PhaseOutcome<ParseOutput> {
        let mut findings = Vec::new();
        let output = if bytes.trim_ascii_start().first() == Some(&b'{') {
            parse_json_serialization(bytes, ctx.limits(), &mut findings)
        } else {
            parse_compact(bytes, ctx.limits(), &mut findings)
        };
        PhaseOutcome::from_findings(output, findings)
    }

    /// VCDM 2.0's checks on the payload, then VC-JOSE-COSE's on the header and the
    /// JWT claims, and RFC 7515's and RFC 7519's unique member names on both.
    fn inspect(&self, parsed: &ParseOutput, ctx: &Context) -> PhaseOutcome<InspectOutput> {
        let mut findings = Vec::new();
        let mut output = InspectOutput {
            profile: Some(PROFILE),
            validity: Validity::Unknown,
            ..InspectOutput::default()
        };
        let Some(FormatDetail::VcJose(detail)) = &parsed.detail else {
            return PhaseOutcome::from_findings(output, findings);
        };
        let header = detail.header.as_ref();
        if let Some(header) = header {
            duplicates(&header.parsed, JwsSegment::Header, &mut findings);
            header_members(header, &mut findings);
        }
        if let (Some(payload), Some(document)) = (&detail.payload, &parsed.document) {
            duplicates(payload, JwsSegment::Payload, &mut findings);
            inspect_payload(payload, document, header, ctx, &mut output, &mut findings);
        }
        PhaseOutcome::from_findings(output, findings)
    }
}

fn inspect_error(detail: FindingDetail) -> Finding {
    Finding::error(Phase::Inspect, Attribution::Input, detail)
}

fn inspect_warning(detail: FindingDetail) -> Finding {
    Finding::new(
        Phase::Inspect,
        Attribution::Input,
        Severity::Warning,
        detail,
    )
}

/// Repeated member names, which the parse resolved by keeping the last (RFC 7515 §4;
/// RFC 7519 §4).
fn duplicates(json: &Json, segment: JwsSegment, findings: &mut Vec<Finding>) {
    for duplicate in json.duplicate_names() {
        findings.push(inspect_error(FindingDetail::DuplicateName {
            segment: Some(segment),
            path: duplicate.path,
            count: duplicate.count,
        }));
    }
}

/// `typ` and `cty` (VC-JOSE-COSE §3.1.1), and the form of `crit` (RFC 7515 §4.1.11).
fn header_members(header: &JoseHeader, findings: &mut Vec<Finding>) {
    if header.typ.as_deref().map(media_type).as_deref() != Some("application/vc+jwt") {
        findings.push(inspect_warning(FindingDetail::TypUnexpected {
            found: header.typ.clone(),
        }));
    }
    if let Some(cty) = &header.cty
        && media_type(cty) != "application/vc"
    {
        findings.push(inspect_warning(FindingDetail::CtyUnexpected {
            found: cty.clone(),
        }));
    }
    if let Some(crit) = header.parsed.get("crit") {
        check_crit(crit, &header.parsed, findings);
    }
}

/// RFC 7515 §4.1.9: media types are case-insensitive, and `application/` is implied
/// before a value with no `/`.
fn media_type(value: &str) -> String {
    let value = value.to_ascii_lowercase();
    if value.contains('/') {
        value
    } else {
        format!("application/{value}")
    }
}

/// The Header Parameters RFC 7515 §4.1 defines for JWS, which `crit` MUST NOT list.
/// RFC 7518 defines none for JWS.
const REGISTERED_HEADER_PARAMETERS: &[&str] = &[
    "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit",
];

/// RFC 7515 §4.1.11's rules for the value of `crit`. Whether vcrd implements the
/// extensions a well-formed `crit` lists is verify's question (DEVELOPMENT-PLAN.md,
/// milestone 1).
fn check_crit(crit: &Json, header: &Json, findings: &mut Vec<Finding>) {
    let mut invalid =
        |problem| findings.push(inspect_error(FindingDetail::CritInvalid { problem }));
    let Json::Array(items) = crit else {
        invalid(CritProblem::NotArray);
        return;
    };
    if items.is_empty() {
        invalid(CritProblem::Empty);
    }
    let mut seen: Vec<&str> = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let Some(name) = item.as_str() else {
            invalid(CritProblem::NotString { index });
            continue;
        };
        let owned = || name.to_owned();
        if seen.contains(&name) {
            invalid(CritProblem::Duplicate { name: owned() });
            continue;
        }
        seen.push(name);
        if REGISTERED_HEADER_PARAMETERS.contains(&name) {
            invalid(CritProblem::Registered { name: owned() });
        } else if header.get(name).is_none() {
            invalid(CritProblem::NotInHeader { name: owned() });
        }
    }
}

/// The payload: VCDM 1.1's encoding is named and goes no further; anything else is
/// checked as VCDM 2.0, then against the header and JWT claims.
fn inspect_payload(
    payload: &Json,
    document: &Document,
    header: Option<&JoseHeader>,
    ctx: &Context,
    output: &mut InspectOutput,
    findings: &mut Vec<Finding>,
) {
    let v1_claim = ["vc", "vp"].into_iter().find(|c| payload.get(c).is_some());
    if let Some(claim) = v1_claim
        && payload.get("@context").is_none()
    {
        // VCDM 2.0's checks would each fail by construction, attributed to the input,
        // when the cause is that vcrd does not read this encoding (ARCHITECTURE §10
        // [F2]). Its issuer is in `iss`, which key resolution does not read.
        let finding = Finding::error(
            Phase::Inspect,
            Attribution::Vcrd,
            FindingDetail::VcdmV1JwtEncoding { claim },
        );
        output.profile = None;
        output.no_issuer_identifier = true;
        findings.push(finding);
        return;
    }
    if let Some(claim) = v1_claim {
        findings.push(inspect_error(FindingDetail::JwtClaimForbidden { claim }));
    }
    let inspected = vcdm::inspect(payload, document, ctx, findings);
    output.validity = inspected.validity;
    // The JOSE format reads `@context` values without JSON-LD processing.
    output.not_evaluated.push(NotEvaluated {
        what: Check::ContextResolution,
        why: NotEvaluatedReason::NotImplemented,
    });
    output.not_evaluated.extend(inspected.not_evaluated);
    output.no_issuer_identifier = inspected.no_issuer_identifier;

    let issuer = document
        .issuer
        .as_deref()
        .filter(|_| !output.no_issuer_identifier);
    jwt_claims(payload, header, issuer, findings);
    if let (Some(header), Some(issuer)) = (header, issuer) {
        check_kid(header, payload, issuer, findings);
    }
}

/// The JWT claims that duplicate credential properties: `iss` MUST match the issuer
/// (VC-JOSE-COSE §4.1.2); `jti` and `id`, and `sub` and `credentialSubject.id`, SHOULD
/// NOT conflict (§3.1.3). Compared exactly, as RFC 7519 §2 compares StringOrURI
/// values. `issuer` is `None` when inspect found it unusable.
fn jwt_claims(
    payload: &Json,
    header: Option<&JoseHeader>,
    issuer: Option<&str>,
    findings: &mut Vec<Finding>,
) {
    if let Some(issuer) = issuer {
        let header_iss = header.and_then(|h| h.parsed.get("iss"));
        for (location, iss) in [
            (IssLocation::Payload, payload.get("iss")),
            (IssLocation::Header, header_iss),
        ] {
            if let Some(iss) = iss.map(Json::as_str)
                && iss != Some(issuer)
            {
                findings.push(inspect_error(FindingDetail::IssMismatch {
                    location,
                    iss: iss.map(str::to_owned),
                    issuer: issuer.to_owned(),
                }));
            }
        }
    }
    if let (Some(jti), Some(id)) = (payload.get("jti"), payload.get("id"))
        && jti != id
    {
        findings.push(inspect_warning(FindingDetail::JwtClaimConflict {
            claim: "jti",
            property: "id",
        }));
    }
    if let Some(sub) = payload.get("sub") {
        let ids: Vec<&Json> = match payload.get("credentialSubject") {
            Some(Json::Array(subjects)) => subjects.iter().filter_map(|s| s.get("id")).collect(),
            Some(subject) => subject.get("id").into_iter().collect(),
            None => Vec::new(),
        };
        if !ids.is_empty() && !ids.contains(&sub) {
            findings.push(inspect_warning(FindingDetail::JwtClaimConflict {
                claim: "sub",
                property: "credentialSubject.id",
            }));
        }
    }
}

/// VC-JOSE-COSE §4.1.1 and §4.2: when `kid` must be present and absolute, and whether
/// it names one of the issuer's keys. A conformance check: it never changes which
/// key verify uses (DEVELOPMENT-PLAN.md, milestone 1, known input 4).
fn check_kid(header: &JoseHeader, payload: &Json, issuer: &str, findings: &mut Vec<Finding>) {
    let iss_present = payload.get("iss").is_some() || header.parsed.get("iss").is_some();
    let did = issuer.starts_with("did:");
    let Some(kid) = header.kid.as_deref() else {
        // A DID issuer's key is a DID URL (§4.1.1); a URL issuer with `iss` absent
        // needs an absolute `kid` (§4.2).
        if did || !iss_present {
            findings.push(inspect_error(FindingDetail::KidMissing));
        }
        return;
    };
    if !iss_present && url::Url::parse(kid).is_err() {
        findings.push(inspect_error(FindingDetail::KidNotAbsolute {
            kid: kid.to_owned(),
        }));
    }
    if did {
        // A relative DID URL is resolved against the DID (DID Core §3.2.2).
        let resolved = match kid.strip_prefix('#') {
            Some(_) => format!("{issuer}{kid}"),
            None => kid.to_owned(),
        };
        // `did:key` names its one key by the method-specific identifier.
        let expected = issuer
            .strip_prefix("did:key:")
            .map(|identifier| format!("{issuer}#{identifier}"));
        let names_issuers_key = match &expected {
            Some(expected) => resolved == *expected,
            None => resolved
                .strip_prefix(issuer)
                .is_some_and(|rest| rest.starts_with('#')),
        };
        if !names_issuers_key {
            findings.push(inspect_error(FindingDetail::KidForeign {
                kid: kid.to_owned(),
                issuer: issuer.to_owned(),
                expected,
            }));
        }
    } else if !kid.contains(JWK_THUMBPRINT_URI) {
        findings.push(inspect_warning(FindingDetail::KidWithoutThumbprint {
            kid: kid.to_owned(),
        }));
    }
}

/// The prefix of a JWK Thumbprint URI (RFC 9278), whose value is an RFC 7638
/// thumbprint.
const JWK_THUMBPRINT_URI: &str = "urn:ietf:params:oauth:jwk-thumbprint:";

/// Printable ASCII with a dot in it, not starting with `{`. Deliberately loose: a
/// segment in standard base64, or with padding, is still recognized, so that parsing
/// can name the offending byte instead of detection failing on it. The `{` keeps
/// minified JSON, whose URLs have dots, from being taken for a compact JWS.
fn compact_shaped(bytes: &[u8]) -> bool {
    bytes.first() != Some(&b'{') && bytes.contains(&b'.') && bytes.iter().all(u8::is_ascii_graphic)
}

/// A JSON object that names `payload` and a signature. A byte search rather than a
/// parse, because detection has no limits to parse under.
fn json_serialization_shaped(bytes: &[u8]) -> bool {
    let contains = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    bytes.trim_ascii_start().first() == Some(&b'{')
        && contains(b"\"payload\"")
        && contains(b"\"signature")
}

fn parse_error(detail: FindingDetail) -> Finding {
    Finding::error(Phase::Parse, Attribution::Input, detail)
}

/// A structural limit exceeded: the caller's policy, which the caller can change
/// (ARCHITECTURE §4).
fn limit_exceeded(detail: FindingDetail) -> Finding {
    Finding::error(Phase::Parse, Attribution::Policy, detail)
}

fn parse_compact(bytes: &[u8], limits: &Limits, findings: &mut Vec<Finding>) -> ParseOutput {
    // A file often ends with a newline, which RFC 7515 §7.1 does not provide for.
    let trimmed = bytes.trim_ascii_end();
    let trailing = bytes.len().saturating_sub(trimmed.len());
    if trailing > 0 {
        findings.push(Finding::new(
            Phase::Parse,
            Attribution::Input,
            Severity::Info,
            FindingDetail::TrailingWhitespace { bytes: trailing },
        ));
    }
    let segments: Vec<&[u8]> = trimmed.split(|b| *b == b'.').collect();
    let &[header_b64, payload_b64, signature_b64] = segments.as_slice() else {
        findings.push(parse_error(FindingDetail::NotCompactJws {
            segments: segments.len(),
        }));
        return ParseOutput::default();
    };

    // Each segment is decoded on its own, so that one bad segment does not hide what
    // the others hold (REQUIREMENTS §6, graduated results).
    let mut depth = None;
    let header = decode_object(header_b64, JwsSegment::Header, limits, &mut depth, findings)
        .map(JoseHeader::new);
    let payload = decode_object(
        payload_b64,
        JwsSegment::Payload,
        limits,
        &mut depth,
        findings,
    );
    let signature = match decode(signature_b64, JwsSegment::Signature) {
        Ok(signature) => Some(signature),
        Err(finding) => {
            findings.push(finding);
            None
        }
    };

    let mut document = payload.as_ref().map(|p| document(p, limits, findings));
    if let (Some(document), Some(header), Some(signature)) =
        (document.as_mut(), header.as_ref(), signature)
    {
        document.proofs.push(ProofDescriptor {
            suite: crate::suites::JWS,
            algorithm: header.alg.clone(),
            key_hints: KeyHints {
                issuer: document.issuer.clone(),
                kid: header.kid.clone(),
            },
            // The two encoded segments as they arrived (RFC 7515 §5.1).
            material: ProofMaterial::Jws {
                signing_input: [header_b64, b".", payload_b64].concat(),
                signature,
            },
        });
    }
    ParseOutput {
        document,
        detail: Some(FormatDetail::VcJose(VcJoseDetail { header, payload })),
        depth,
        contained: Vec::new(),
    }
}

/// RFC 7515 §7.2. Recognized and named, not yet read (ARCHITECTURE §10 [F1]).
fn parse_json_serialization(
    bytes: &[u8],
    limits: &Limits,
    findings: &mut Vec<Finding>,
) -> ParseOutput {
    let found = nesting_depth(bytes);
    let output = ParseOutput {
        depth: Some(found),
        ..ParseOutput::default()
    };
    if found > limits.max_depth {
        findings.push(limit_exceeded(FindingDetail::NestingTooDeep {
            segment: None,
            limit: limits.max_depth,
            found,
        }));
        return output;
    }
    let json = match Json::parse(bytes) {
        Ok(json) => json,
        Err(e) => {
            findings.push(parse_error(FindingDetail::JsonInvalid {
                segment: None,
                line: e.line(),
                column: e.column(),
            }));
            return output;
        }
    };
    let syntax = match (
        json.get("payload"),
        json.get("signatures"),
        json.get("signature"),
    ) {
        (Some(_), Some(_), _) => Some(JwsJsonSyntax::General),
        (Some(_), None, Some(_)) => Some(JwsJsonSyntax::Flattened),
        _ => None,
    };
    findings.push(match syntax {
        Some(syntax) => Finding::error(
            Phase::Parse,
            Attribution::Vcrd,
            FindingDetail::JwsJsonSerialization { syntax },
        ),
        None => parse_error(FindingDetail::JsonNotJws),
    });
    output
}

/// Strict base64url: no padding, no characters outside the alphabet, and no
/// non-zero trailing bits (RFC 7515 §2).
fn decode(segment: &[u8], which: JwsSegment) -> Result<Vec<u8>, Finding> {
    URL_SAFE_NO_PAD.decode(segment).map_err(|e| {
        let problem = match e {
            base64::DecodeError::InvalidByte(..) => Base64urlProblem::InvalidSymbol,
            base64::DecodeError::InvalidLastSymbol { .. } => Base64urlProblem::NonzeroTrailingBits,
            base64::DecodeError::InvalidLength(_) => Base64urlProblem::InvalidLength,
            base64::DecodeError::InvalidPadding => Base64urlProblem::Padding,
        };
        parse_error(FindingDetail::Base64urlInvalid {
            segment: which,
            problem,
        })
    })
}

/// Decodes a segment and parses it as a JSON object, checking its depth first
/// (ARCHITECTURE §4). Records the depth, and a finding for anything wrong.
fn decode_object(
    segment: &[u8],
    which: JwsSegment,
    limits: &Limits,
    depth: &mut Option<usize>,
    findings: &mut Vec<Finding>,
) -> Option<Json> {
    let decoded = match decode(segment, which) {
        Ok(decoded) => decoded,
        Err(finding) => {
            findings.push(finding);
            return None;
        }
    };
    let found = nesting_depth(&decoded);
    *depth = Some(depth.map_or(found, |d| d.max(found)));
    if found > limits.max_depth {
        findings.push(limit_exceeded(FindingDetail::NestingTooDeep {
            segment: Some(which),
            limit: limits.max_depth,
            found,
        }));
        return None;
    }
    match Json::parse(&decoded) {
        Ok(json @ Json::Object(_)) => Some(json),
        Ok(Json::Scalar(_) | Json::Array(_)) => {
            findings.push(parse_error(FindingDetail::JsonNotObject { segment: which }));
            None
        }
        Err(e) => {
            findings.push(parse_error(FindingDetail::JsonInvalid {
                segment: Some(which),
                line: e.line(),
                column: e.column(),
            }));
            None
        }
    }
}

fn string(json: Option<&Json>) -> Option<String> {
    json.and_then(Json::as_str).map(str::to_owned)
}

/// The payload's projection. Its proof is added by the caller, once the header and
/// signature have decoded too.
fn document(payload: &Json, limits: &Limits, findings: &mut Vec<Finding>) -> Document {
    // A URL, or an object whose `id` is one (VCDM 2.0 §4.7).
    let issuer = match payload.get("issuer") {
        Some(object @ Json::Object(_)) => string(object.get("id")),
        other => string(other),
    };
    let mut leaves = Vec::new();
    if !flatten(payload, &mut Vec::new(), &mut leaves, limits.max_claims) {
        findings.push(limit_exceeded(FindingDetail::TooManyClaims {
            limit: limits.max_claims,
        }));
    }
    Document {
        kind: DocumentKind::Credential,
        contexts: contexts(payload.get("@context")),
        types: strings(payload.get("type")),
        issuer,
        valid_from: timestamp(payload.get("validFrom")),
        valid_until: timestamp(payload.get("validUntil")),
        leaves,
        proofs: Vec::new(),
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

/// A validity bound, read as an XML Schema `dateTimeStamp` (VCDM 2.0 §4.9).
fn timestamp(json: Option<&Json>) -> Option<Timestamp> {
    let json = json?;
    Some(match json.as_str() {
        Some(lexical) => Timestamp {
            lexical: Some(lexical.to_owned()),
            parsed: vcdm::date_time_stamp(lexical),
        },
        None => Timestamp {
            lexical: None,
            parsed: Err(DateTimeProblem::NotString),
        },
    })
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

fn classify(path: &[Step<'_>]) -> LeafClass {
    let mut names = path.iter().filter_map(|s| match s {
        Step::Name(name) => Some(*name),
        Step::Index(_) => None,
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

/// Appends every scalar in `json` to `leaves`, stopping at `limit` leaves in all,
/// the claim-count limit applied while flattening (ARCHITECTURE §4). Returns
/// whether it finished.
fn flatten<'a>(
    json: &'a Json,
    path: &mut Vec<Step<'a>>,
    leaves: &mut Vec<Leaf>,
    limit: usize,
) -> bool {
    match json {
        Json::Scalar(value) => {
            if leaves.len() >= limit {
                return false;
            }
            leaves.push(Leaf {
                path: path_string(path),
                class: classify(path),
                value: value.clone(),
            });
            true
        }
        Json::Array(items) => items.iter().enumerate().all(|(index, item)| {
            path.push(Step::Index(index));
            let finished = flatten(item, path, leaves, limit);
            path.pop();
            finished
        }),
        Json::Object(members) => members.iter().all(|member| {
            path.push(Step::Name(&member.name));
            let finished = flatten(&member.value, path, leaves, limit);
            path.pop();
            finished
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(payload: &str) -> Vec<(String, LeafClass)> {
        let json = Json::parse(payload.as_bytes()).unwrap();
        let mut leaves = Vec::new();
        assert!(flatten(&json, &mut Vec::new(), &mut leaves, usize::MAX));
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

    use proptest::strategy::Strategy as _;

    /// The base64url alphabet (RFC 4648 §5).
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    proptest::proptest! {
        #[test]
        fn base64url_round_trips(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64)) {
            let encoded = URL_SAFE_NO_PAD.encode(&bytes);
            proptest::prop_assert_eq!(decode(encoded.as_bytes(), JwsSegment::Payload).ok(), Some(bytes));
        }

        /// A byte outside the alphabet, anywhere, is rejected; `=` is one.
        #[test]
        fn rejects_a_byte_outside_the_alphabet(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64),
            at in proptest::prelude::any::<proptest::sample::Index>(),
            bad in proptest::prelude::any::<u8>().prop_filter("outside the alphabet", |b| !ALPHABET.contains(b)),
        ) {
            let mut encoded = URL_SAFE_NO_PAD.encode(&bytes).into_bytes();
            let at = at.index(encoded.len() + 1);
            encoded.insert(at, bad);
            proptest::prop_assert!(decode(&encoded, JwsSegment::Payload).is_err());
        }

        /// Padding is rejected: base64url in JWS has none (RFC 7515 §2).
        #[test]
        fn rejects_padding(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64)) {
            proptest::prop_assume!(bytes.len() % 3 != 0);
            let padded = base64::engine::general_purpose::URL_SAFE.encode(&bytes);
            proptest::prop_assert!(padded.ends_with('='));
            proptest::prop_assert!(decode(padded.as_bytes(), JwsSegment::Payload).is_err());
        }

        /// When the input is not a multiple of three bytes, the last character carries
        /// bits the decoder discards (four or two of them). A canonical encoding has
        /// them zero; any other is rejected.
        #[test]
        fn rejects_non_zero_discarded_bits(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..64),
            noise in 1u8..16,
        ) {
            proptest::prop_assume!(bytes.len() % 3 != 0);
            let discarded = if bytes.len() % 3 == 1 { 4 } else { 2 };
            let noise = noise & ((1 << discarded) - 1);
            proptest::prop_assume!(noise != 0);
            let mut encoded = URL_SAFE_NO_PAD.encode(&bytes).into_bytes();
            let last = encoded.last_mut().unwrap();
            let value = ALPHABET.iter().position(|a| a == last).unwrap() as u8;
            *last = ALPHABET[usize::from(value | noise)];
            proptest::prop_assert!(decode(&encoded, JwsSegment::Payload).is_err());
        }
    }

    /// Each decoding failure names its problem.
    #[test]
    fn names_each_decoding_problem() {
        let problem = |bytes: &[u8]| match decode(bytes, JwsSegment::Payload) {
            Err(Finding {
                detail: FindingDetail::Base64urlInvalid { problem, .. },
                ..
            }) => problem,
            other => panic!("{other:?}"),
        };
        // `t` is in the alphabet, but leaves the bits 01 after two whole bytes.
        assert_eq!(problem(b"not"), Base64urlProblem::NonzeroTrailingBits);
        assert_eq!(problem(b"a"), Base64urlProblem::InvalidLength);
        assert_eq!(problem(b"a+b"), Base64urlProblem::InvalidSymbol);
        assert_eq!(problem(b"YQ=="), Base64urlProblem::Padding);
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
