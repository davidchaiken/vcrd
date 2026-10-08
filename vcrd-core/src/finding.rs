//! Findings: one structured condition each, with no prose (REQUIREMENTS §6).

use time::OffsetDateTime;

use crate::registry::{FormatId, SuiteId};
use crate::report::Phase;

/// One condition a phase found.
#[derive(Clone, Debug)]
pub struct Finding {
    /// A stable machine identifier, `<phase>.<condition>`.
    pub code: &'static str,
    pub phase: Phase,
    pub attribution: Attribution,
    pub severity: Severity,
    pub detail: FindingDetail,
}

impl Finding {
    /// A finding whose code is its detail's.
    pub fn new(
        phase: Phase,
        attribution: Attribution,
        severity: Severity,
        detail: FindingDetail,
    ) -> Self {
        Finding {
            code: detail.code(),
            phase,
            attribution,
            severity,
            detail,
        }
    }

    pub fn error(phase: Phase, attribution: Attribution, detail: FindingDetail) -> Self {
        Finding::new(phase, attribution, Severity::Error, detail)
    }
}

/// The most probable origin of a finding (REQUIREMENTS §6). It decides the exit code
/// before the phase does (REQUIREMENTS §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attribution {
    /// The input does not conform.
    Input,
    /// The caller's policy rejected something vcrd could otherwise do.
    Policy,
    /// vcrd cannot do this.
    Vcrd,
    /// Something outside the input and vcrd, such as missing key material.
    Environment,
}

/// Only an error fails a phase (ARCHITECTURE §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

/// One variant per condition, carrying the facts a caller needs to act on it. No
/// variant carries a claim value (ARCHITECTURE §7).
///
/// Not `#[non_exhaustive]`: a new variant must break the JSON mapping in `vcrd-cli`,
/// so that someone decides how it appears (ARCHITECTURE §3).
#[derive(Clone, Debug)]
pub enum FindingDetail {
    // Parse.
    /// The input is larger than the size limit, checked before anything else. `found`
    /// is the number of bytes core was given; a frontend that stops reading at the
    /// limit passes one more than it (ARCHITECTURE §4). Attributed to caller policy.
    InputTooLarge { limit: usize, found: usize },
    /// A JSON document nests deeper than the depth limit, found by a scan before any
    /// JSON is parsed (ARCHITECTURE §4). `segment` is `None` when the input as a whole
    /// is the JSON document. Attributed to caller policy.
    NestingTooDeep {
        segment: Option<JwsSegment>,
        limit: usize,
        found: usize,
    },
    /// More scalar values than the claim-count limit; flattening stopped at the limit.
    /// Attributed to caller policy.
    TooManyClaims { limit: usize },
    /// Whitespace after the last segment, which a compact JWS does not have (RFC 7515
    /// §7.1) but a file often ends with. Ignored, and reported for information.
    TrailingWhitespace { bytes: usize },
    /// No registered format recognized the input. With an empty registry, this is
    /// attributed to vcrd; otherwise to the input (ARCHITECTURE §2).
    NoFormatMatched { registered: Vec<FormatId> },
    /// A compact JWS has three segments separated by dots (RFC 7515 §7.1).
    NotCompactJws { segments: usize },
    /// A JWS in JSON serialization (RFC 7515 §7.2), which vcrd does not read yet
    /// (ARCHITECTURE §10 [F1]). Attributed to vcrd.
    JwsJsonSerialization { syntax: JwsJsonSyntax },
    /// A JSON object that is not a JWS in JSON serialization: it lacks `payload`, or
    /// both `signature` and `signatures`.
    JsonNotJws,
    /// A segment is not strict base64url (RFC 7515 §2, §5.2); `problem` says how.
    Base64urlInvalid {
        segment: JwsSegment,
        problem: Base64urlProblem,
    },
    /// A JSON document is not valid JSON. `segment` is `None` when the input as a
    /// whole is the JSON document.
    JsonInvalid {
        segment: Option<JwsSegment>,
        line: usize,
        column: usize,
    },
    /// A decoded segment is JSON but not an object.
    JsonNotObject { segment: JwsSegment },

    // Inspect: JSON, JOSE and JWT (RFC 7515, RFC 7519).
    /// A member name appears more than once in one object. RFC 7515 §4 and RFC 7519
    /// §4 require unique names, and permit a parser that keeps the last, as vcrd's
    /// does; inspect reports each.
    DuplicateName {
        segment: Option<JwsSegment>,
        path: String,
        count: usize,
    },
    /// `crit` (Critical) breaks one of RFC 7515 §4.1.11's rules for its value.
    CritInvalid { problem: CritProblem },
    /// The header's `jwk` is not a public key in a form RFC 7517, RFC 7518 §6 and
    /// RFC 8037 §2 define; `problem` says how. It does not block verify, which takes
    /// the issuer's key from elsewhere.
    JwkInvalid { problem: JwkProblem },
    /// The header's `jwk` has a key type vcrd cannot read, so it has no thumbprint
    /// to compare. Attributed to vcrd; a warning.
    JwkKtyUnsupported { kty: String },
    /// The header's `jwk` carries private-key members, which a public key does not
    /// (RFC 7515 §4.1.3): whoever has the credential has the private key.
    JwkPrivateKey { members: Vec<&'static str> },
    /// `exp`, `nbf` or `iat` is not a number, which RFC 7519 §4.1.4–4.1.6 require.
    NumericDateInvalid { claim: &'static str },

    // Inspect: VCDM 2.0 (the Verifiable Credentials Data Model).
    /// No `@context` (VCDM 2.0 §4.3).
    ContextMissing,
    /// The first `@context` item is not `https://www.w3.org/ns/credentials/v2` (VCDM 2.0
    /// §4.3). `found` is that item when it is a string.
    ContextFirstInvalid { found: Option<String> },
    /// A later `@context` item is neither a string nor an object (VCDM 2.0 §4.3).
    ContextEntryInvalid { path: String },
    /// An object VCDM 2.0 §4.5 requires to have a `type` has none.
    TypeMissing { path: String },
    /// A `type` value is not a string (VCDM 2.0 §4.5).
    TypeNotString { path: String },
    /// The credential's `type` does not include `VerifiableCredential` (VCDM 2.0 §4.5).
    TypeLacksVerifiableCredential,
    /// No `issuer` (VCDM 2.0 §4.7). With no issuer identifier, no key can be derived
    /// from one, which blocks verify unless the caller supplied key material.
    IssuerMissing,
    /// `issuer` is neither a URL nor an object whose `id` is a URL (VCDM 2.0 §4.7). It
    /// blocks verify as `IssuerMissing` does.
    IssuerInvalid { problem: IssuerProblem },
    /// No `credentialSubject` (VCDM 2.0 §4.8).
    CredentialSubjectMissing,
    /// A subject is not an object (VCDM 2.0 §4.8).
    CredentialSubjectInvalid { path: String },
    /// An empty subject object, or an empty set of subjects: present, and the subject
    /// of no claim (VCDM 2.0 §4.8; ARCHITECTURE §10 [S5]).
    CredentialSubjectEmpty { path: String },
    /// A subject with an identifier and nothing else. VCDM 2.0 §4.8 requires each
    /// subject to be the subject of one or more claims; whether its `id` counts is
    /// arguable, so this is a warning.
    CredentialSubjectNoClaims { path: String },
    /// A value VCDM 2.0 requires to be a URL is not one under the WHATWG URL Standard,
    /// which VCDM 2.0 §2 cites. `error` names the parser's error; the value itself may
    /// be a claim, so it is not carried.
    UrlInvalid { path: String, error: String },
    /// A URL that parses only after the parser corrected it: the URL Standard calls
    /// each correction a validation error, and asks conformance checkers to report
    /// them. A warning.
    UrlNonconforming {
        path: String,
        violations: Vec<String>,
    },
    /// A validity bound is not an XML Schema 1.1 `dateTimeStamp` (VCDM 2.0 §4.9).
    /// `valid_rfc3339` says whether RFC 3339 would accept it, so that such values can
    /// be noticed where they occur (ARCHITECTURE §4).
    DateTimeInvalid {
        field: DateField,
        valid_rfc3339: bool,
    },
    /// A `dateTimeStamp` outside the years vcrd can represent, -9999 to 9999.
    /// Attributed to vcrd.
    DateTimeUnrepresentable { field: DateField },
    /// `validUntil` is earlier than `validFrom` (VCDM 2.0 §4.9; ARCHITECTURE §10 [S3]).
    ValidUntilBeforeValidFrom {
        valid_from: OffsetDateTime,
        valid_until: OffsetDateTime,
    },

    // Inspect: VC-JOSE-COSE.
    /// `typ` (Type) is absent or not `vc+jwt`, which VC-JOSE-COSE §3.1.1 says it
    /// SHOULD be. A warning.
    TypUnexpected { found: Option<String> },
    /// `cty` (Content Type) is present and not `vc`, which VC-JOSE-COSE §3.1.1 says it
    /// SHOULD be. A warning.
    CtyUnexpected { found: String },
    /// The payload follows VCDM 1.1's JWT encoding: the credential inside a `vc` claim,
    /// or a presentation inside `vp`, with no VCDM 2.0 `@context`. vcrd does not read
    /// it yet (ARCHITECTURE §10 [F2]). Attributed to vcrd; it blocks verify, since the
    /// encoding names the issuer in `iss`, which vcrd does not resolve.
    VcdmV1JwtEncoding { claim: &'static str },
    /// A `vc` or `vp` claim beside a VCDM 2.0 payload, which VC-JOSE-COSE §3.1.3 says
    /// MUST NOT be present.
    JwtClaimForbidden { claim: &'static str },
    /// `iss` (Issuer) does not match `issuer`, or `issuer.id` (VC-JOSE-COSE §4.1.2, a
    /// MUST). Both are metadata, so both are carried. `iss` is `None` when it is not a
    /// string.
    IssMismatch {
        location: IssLocation,
        iss: Option<String>,
        issuer: String,
    },
    /// A JWT claim and the credential property for the same thing are both present
    /// and differ, which VC-JOSE-COSE §3.1.3 says issuers SHOULD avoid: `jti` (JWT
    /// ID) and `id`, or `sub` (Subject) and `credentialSubject.id`. A warning. The
    /// values are claims, so they are not carried.
    JwtClaimConflict {
        claim: &'static str,
        property: &'static str,
    },
    /// No `kid` (Key ID) where VC-JOSE-COSE requires one: the issuer is a DID (§4.1.1),
    /// or `iss` is absent and the issuer is a URL (§4.2).
    KidMissing,
    /// `kid` is not an absolute URL, with `iss` absent and the issuer a URL
    /// (VC-JOSE-COSE §4.2).
    KidNotAbsolute { kid: String },
    /// `kid`, resolved against the issuer when relative, does not identify one of the
    /// issuer's keys. `expected` is the key's identifier when the DID method
    /// determines it, as `did:key` does.
    KidForeign {
        kid: String,
        issuer: String,
        expected: Option<String>,
    },
    /// The issuer is a URL that is not a DID, and `kid` does not include a JWK
    /// Thumbprint URI (RFC 7638), which VC-JOSE-COSE §4.2 recommends. A warning.
    KidWithoutThumbprint { kid: String },

    // Inspect: the validity period.
    /// `validUntil` is earlier than the clock, less the skew (VCDM 2.0 §4.9).
    Expired {
        valid_until: OffsetDateTime,
        now: OffsetDateTime,
        skew_seconds: u64,
    },
    /// `validFrom` is later than the clock, plus the skew (VCDM 2.0 §4.9).
    NotYetValid {
        valid_from: OffsetDateTime,
        now: OffsetDateTime,
        skew_seconds: u64,
    },

    // Verify.
    /// The input carries nothing to verify.
    NoProof,
    /// A proof names a suite no registered suite implements.
    SuiteUnavailable { suite: SuiteId },
    /// The JWS header has no `alg` (Algorithm) member (RFC 7515 §4.1.1).
    AlgorithmMissing,
    /// `alg` is `none`, which is always rejected (ARCHITECTURE §8).
    AlgorithmNone,
    /// vcrd does not implement the declared algorithm (REQUIREMENTS §10).
    AlgorithmUnsupported {
        declared: String,
        supported: Vec<&'static str>,
    },
    /// The signature has the wrong length for its algorithm.
    SignatureLength {
        algorithm: &'static str,
        expected: usize,
        found: usize,
    },
    /// The signature does not verify under the resolved key.
    SignatureInvalid { algorithm: &'static str },
    /// The R of an Ed25519 signature has small order. A verifier that checks only
    /// [s]B = R + [k]A can accept such a signature; vcrd rejects it (ARCHITECTURE §8).
    SignatureSmallOrder { algorithm: &'static str },
    /// `crit` lists extensions the suite does not implement, so the JWS is invalid
    /// (RFC 7515 §4.1.11). The signature is still checked, and its outcome reported,
    /// for the information. Attributed to vcrd.
    CritUnsupported {
        extensions: Vec<String>,
        supported: Vec<&'static str>,
    },
    /// `exp` is not later than the clock, less the skew (RFC 7519 §4.1.4): the proof
    /// has expired, whatever the credential's validity period says.
    ProofExpired {
        claim: &'static str,
        /// The JSON number as written.
        value: String,
        /// The same instant as a date-time, when it is within the years -9999 to 9999.
        value_date_time: Option<OffsetDateTime>,
        now: OffsetDateTime,
        skew_seconds: u64,
    },
    /// `nbf` is later than the clock, plus the skew (RFC 7519 §4.1.5).
    ProofNotYetValid {
        claim: &'static str,
        value: String,
        value_date_time: Option<OffsetDateTime>,
        now: OffsetDateTime,
        skew_seconds: u64,
    },
    /// `iat` is later than the clock, plus the skew. RFC 7519 §4.1.6 sets no rule for
    /// it, so this is a warning.
    ProofIssuedInFuture {
        claim: &'static str,
        value: String,
        value_date_time: Option<OffsetDateTime>,
        now: OffsetDateTime,
        skew_seconds: u64,
    },
    /// No key material was found; `consulted` lists where vcrd looked (ARCHITECTURE §8).
    NoKeyMaterial { consulted: Vec<KeySourceKind> },
    /// The issuer identifier uses a scheme or DID method vcrd cannot resolve.
    IssuerMethodUnsupported { method: String },
    /// The issuer is a `did:key` that cannot be decoded.
    DidKeyUndecodable { problem: DidKeyProblem },
    /// The `did:key` names a key type vcrd cannot use (ARCHITECTURE §8).
    DidKeyCodecUnsupported {
        codec: u64,
        name: Option<&'static str>,
    },
    /// The key cannot bind a signature to a message (REQUIREMENTS §10).
    WeakKey { thumbprint: String },
    /// The only key on offer is one the credential carries about itself, which vcrd
    /// uses only on the caller's opt-in (REQUIREMENTS §10). Attributed to caller
    /// policy.
    EmbeddedKeyRefused { location: &'static str },
    /// The key the credential carries about itself is not the key derived from its
    /// issuer, though RFC 7515 §4.1.3 makes `jwk` the key that signed. A warning:
    /// it never changes which key is used (ARCHITECTURE §8).
    CredentialKeyMismatch {
        location: &'static str,
        /// The carried key's RFC 7638 thumbprint.
        credential_key: String,
        /// The thumbprint of the key derived from the issuer.
        key: String,
    },
}

impl FindingDetail {
    /// The stable code for this condition.
    pub fn code(&self) -> &'static str {
        match self {
            FindingDetail::InputTooLarge { .. } => "parse.input_too_large",
            FindingDetail::NestingTooDeep { .. } => "parse.nesting_too_deep",
            FindingDetail::TooManyClaims { .. } => "parse.too_many_claims",
            FindingDetail::TrailingWhitespace { .. } => "parse.trailing_whitespace",
            FindingDetail::NoFormatMatched { .. } => "parse.no_format_matched",
            FindingDetail::NotCompactJws { .. } => "parse.not_compact_jws",
            FindingDetail::JwsJsonSerialization { .. } => "parse.jws_json_serialization",
            FindingDetail::JsonNotJws => "parse.json_not_jws",
            FindingDetail::Base64urlInvalid { .. } => "parse.base64url_invalid",
            FindingDetail::JsonInvalid { .. } => "parse.json_invalid",
            FindingDetail::JsonNotObject { .. } => "parse.json_not_object",
            FindingDetail::DuplicateName { .. } => "inspect.duplicate_name",
            FindingDetail::CritInvalid { .. } => "inspect.crit_invalid",
            FindingDetail::JwkInvalid { .. } => "inspect.jwk_invalid",
            FindingDetail::JwkKtyUnsupported { .. } => "inspect.jwk_kty_unsupported",
            FindingDetail::JwkPrivateKey { .. } => "inspect.jwk_private_key",
            FindingDetail::NumericDateInvalid { .. } => "inspect.numeric_date_invalid",
            FindingDetail::ContextMissing => "inspect.context_missing",
            FindingDetail::ContextFirstInvalid { .. } => "inspect.context_first_invalid",
            FindingDetail::ContextEntryInvalid { .. } => "inspect.context_entry_invalid",
            FindingDetail::TypeMissing { .. } => "inspect.type_missing",
            FindingDetail::TypeNotString { .. } => "inspect.type_not_string",
            FindingDetail::TypeLacksVerifiableCredential => {
                "inspect.type_lacks_verifiable_credential"
            }
            FindingDetail::IssuerMissing => "inspect.issuer_missing",
            FindingDetail::IssuerInvalid { .. } => "inspect.issuer_invalid",
            FindingDetail::CredentialSubjectMissing => "inspect.credential_subject_missing",
            FindingDetail::CredentialSubjectInvalid { .. } => "inspect.credential_subject_invalid",
            FindingDetail::CredentialSubjectEmpty { .. } => "inspect.credential_subject_empty",
            FindingDetail::CredentialSubjectNoClaims { .. } => {
                "inspect.credential_subject_no_claims"
            }
            FindingDetail::UrlInvalid { .. } => "inspect.url_invalid",
            FindingDetail::UrlNonconforming { .. } => "inspect.url_nonconforming",
            FindingDetail::DateTimeInvalid { .. } => "inspect.date_time_invalid",
            FindingDetail::DateTimeUnrepresentable { .. } => "inspect.date_time_unrepresentable",
            FindingDetail::ValidUntilBeforeValidFrom { .. } => {
                "inspect.valid_until_before_valid_from"
            }
            FindingDetail::TypUnexpected { .. } => "inspect.typ_unexpected",
            FindingDetail::CtyUnexpected { .. } => "inspect.cty_unexpected",
            FindingDetail::VcdmV1JwtEncoding { .. } => "inspect.vcdm_1_1_jwt_encoding",
            FindingDetail::JwtClaimForbidden { .. } => "inspect.jwt_claim_forbidden",
            FindingDetail::IssMismatch { .. } => "inspect.iss_mismatch",
            FindingDetail::JwtClaimConflict { .. } => "inspect.jwt_claim_conflict",
            FindingDetail::KidMissing => "inspect.kid_missing",
            FindingDetail::KidNotAbsolute { .. } => "inspect.kid_not_absolute",
            FindingDetail::KidForeign { .. } => "inspect.kid_foreign",
            FindingDetail::KidWithoutThumbprint { .. } => "inspect.kid_without_thumbprint",
            FindingDetail::Expired { .. } => "inspect.expired",
            FindingDetail::NotYetValid { .. } => "inspect.not_yet_valid",
            FindingDetail::NoProof => "verify.no_proof",
            FindingDetail::SuiteUnavailable { .. } => "verify.suite_unavailable",
            FindingDetail::AlgorithmMissing => "verify.algorithm_missing",
            FindingDetail::AlgorithmNone => "verify.algorithm_none",
            FindingDetail::AlgorithmUnsupported { .. } => "verify.algorithm_unsupported",
            FindingDetail::SignatureLength { .. } => "verify.signature_length",
            FindingDetail::SignatureInvalid { .. } => "verify.signature_invalid",
            FindingDetail::SignatureSmallOrder { .. } => "verify.signature_small_order",
            FindingDetail::CritUnsupported { .. } => "verify.crit_unsupported",
            FindingDetail::ProofExpired { .. } => "verify.proof_expired",
            FindingDetail::ProofNotYetValid { .. } => "verify.proof_not_yet_valid",
            FindingDetail::ProofIssuedInFuture { .. } => "verify.proof_issued_in_future",
            FindingDetail::NoKeyMaterial { .. } => "verify.no_key_material",
            FindingDetail::IssuerMethodUnsupported { .. } => "verify.issuer_method_unsupported",
            FindingDetail::DidKeyUndecodable { .. } => "verify.did_key_undecodable",
            FindingDetail::DidKeyCodecUnsupported { .. } => "verify.did_key_codec_unsupported",
            FindingDetail::WeakKey { .. } => "verify.weak_key",
            FindingDetail::EmbeddedKeyRefused { .. } => "verify.embedded_key_refused",
            FindingDetail::CredentialKeyMismatch { .. } => "verify.credential_key_mismatch",
        }
    }
}

/// The segments of a compact JWS (RFC 7515 §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JwsSegment {
    Header,
    Payload,
    Signature,
}

/// Why a segment is not strict base64url (RFC 7515 §2), as the decoder reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base64urlProblem {
    /// A byte outside the base64url alphabet, such as standard base64's `+` and `/`.
    InvalidSymbol,
    /// The last symbol leaves non-zero bits after the last whole byte; strict
    /// base64url requires them to be zero.
    NonzeroTrailingBits,
    /// A length no unpadded base64url text has: one more than a multiple of four.
    InvalidLength,
    /// Padding (`=`), which JWS omits.
    Padding,
}

/// The two syntaxes of JWS JSON serialization (RFC 7515 §7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JwsJsonSyntax {
    /// A `signatures` array: one or more signatures (§7.2.1).
    General,
    /// `signature` beside `payload`: exactly one (§7.2.2).
    Flattened,
}

/// The validity bounds of VCDM 2.0 §4.9.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DateField {
    ValidFrom,
    ValidUntil,
}

/// The rules RFC 7515 §4.1.11 sets for the value of `crit`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CritProblem {
    /// Not an array.
    NotArray,
    /// The empty array, which producers MUST NOT use.
    Empty,
    /// An item that is not a string; `index` is its position.
    NotString { index: usize },
    /// A name listed more than once.
    Duplicate { name: String },
    /// A name RFC 7515 defines for JWS, which producers MUST NOT list.
    Registered { name: String },
    /// A name that is not a member of the header.
    NotInHeader { name: String },
}

/// Why a `jwk` is not a public key vcrd can read (RFC 7517 §4; RFC 7518 §6; RFC 8037
/// §2; RFC 7638 §3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JwkProblem {
    /// Not a JSON object.
    NotObject,
    /// No `kty`, or one that is not a string.
    KtyMissing,
    /// `kty` is `oct`: a symmetric key, which is secret, where RFC 7515 §4.1.3
    /// requires a public key.
    Symmetric,
    /// A key type vcrd does not know. Reported as [`FindingDetail::JwkKtyUnsupported`],
    /// attributed to vcrd, not as an invalid key.
    KtyUnknown { kty: String },
    /// A member the key type requires, and its thumbprint covers, is absent or not a
    /// string.
    MemberMissing { member: &'static str },
    /// An Ed25519 key's `x` is not 32 bytes of strict base64url, or not a point.
    KeyInvalid,
}

/// Why `issuer` is not an issuer identifier (VCDM 2.0 §4.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IssuerProblem {
    /// Neither a string nor an object. VCDM 2.0 §6 makes `issuer` a single value, so an
    /// array is this case too.
    WrongType,
    /// An object without a string `id`.
    NoId,
    /// A string, or an object's `id`, that is not a URL; `error` names the parser's
    /// error.
    NotUrl { error: String },
}

/// Where an `iss` was found. VC-JOSE-COSE §4.1.2 reads it from the JWT claims or the
/// JOSE header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssLocation {
    Header,
    Payload,
}

/// The sources of key material, in precedence order (REQUIREMENTS §10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySourceKind {
    CallerSupplied,
    IssuerIdentifier,
    CredentialEmbedded,
}

/// Why a `did:key` could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DidKeyProblem {
    /// The method-specific identifier does not start with `z`, the multibase prefix
    /// for base58btc.
    NotBase58btc,
    /// Not valid base58btc.
    Base58Invalid,
    /// The multicodec prefix is not a valid unsigned varint.
    CodecInvalid,
    /// The key bytes have the wrong length for their codec.
    KeyLength { expected: usize, found: usize },
    /// The key bytes are not a point on the curve.
    PointInvalid,
}
