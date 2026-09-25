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

/// Whose side a finding is on (REQUIREMENTS §6). It decides the exit code before the
/// phase does (REQUIREMENTS §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attribution {
    /// The input is at fault.
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
    /// No registered format recognized the input. With an empty registry, this is
    /// attributed to vcrd; otherwise to the input (ARCHITECTURE §2).
    NoFormatMatched { registered: Vec<FormatId> },
    /// A compact JWS has three segments separated by dots (RFC 7515 §7.1).
    NotCompactJws { segments: usize },
    /// A segment is not strict base64url (RFC 7515 §2, §5.2). `offset` is the first
    /// offending byte within the segment, when the decoder names one.
    Base64urlInvalid {
        segment: JwsSegment,
        offset: Option<usize>,
    },
    /// A decoded segment is not JSON.
    JsonInvalid {
        segment: JwsSegment,
        line: usize,
        column: usize,
    },
    /// A decoded segment is JSON but not an object.
    JsonNotObject { segment: JwsSegment },

    // Inspect.
    /// A validity bound is not an RFC 3339 date-time.
    DateTimeInvalid { field: DateField },
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
}

impl FindingDetail {
    /// The stable code for this condition.
    pub fn code(&self) -> &'static str {
        match self {
            FindingDetail::NoFormatMatched { .. } => "parse.no_format_matched",
            FindingDetail::NotCompactJws { .. } => "parse.not_compact_jws",
            FindingDetail::Base64urlInvalid { .. } => "parse.base64url_invalid",
            FindingDetail::JsonInvalid { .. } => "parse.json_invalid",
            FindingDetail::JsonNotObject { .. } => "parse.json_not_object",
            FindingDetail::DateTimeInvalid { .. } => "inspect.date_time_invalid",
            FindingDetail::Expired { .. } => "inspect.expired",
            FindingDetail::NotYetValid { .. } => "inspect.not_yet_valid",
            FindingDetail::NoProof => "verify.no_proof",
            FindingDetail::SuiteUnavailable { .. } => "verify.suite_unavailable",
            FindingDetail::AlgorithmMissing => "verify.algorithm_missing",
            FindingDetail::AlgorithmNone => "verify.algorithm_none",
            FindingDetail::AlgorithmUnsupported { .. } => "verify.algorithm_unsupported",
            FindingDetail::SignatureLength { .. } => "verify.signature_length",
            FindingDetail::SignatureInvalid { .. } => "verify.signature_invalid",
            FindingDetail::NoKeyMaterial { .. } => "verify.no_key_material",
            FindingDetail::IssuerMethodUnsupported { .. } => "verify.issuer_method_unsupported",
            FindingDetail::DidKeyUndecodable { .. } => "verify.did_key_undecodable",
            FindingDetail::DidKeyCodecUnsupported { .. } => "verify.did_key_codec_unsupported",
            FindingDetail::WeakKey { .. } => "verify.weak_key",
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

/// The validity bounds of VCDM 2.0 §4.9.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DateField {
    ValidFrom,
    ValidUntil,
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
