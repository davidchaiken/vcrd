//! The format-neutral view of an input (ARCHITECTURE §3).

use std::fmt;

use time::OffsetDateTime;

use crate::keys::Jwk;
use crate::redact::ClaimValue;
use crate::registry::SuiteId;

/// What every frontend renders, whatever the format.
#[derive(Clone, Debug)]
pub struct Document {
    pub kind: DocumentKind,
    pub contexts: Vec<ContextEntry>,
    pub types: Vec<String>,
    /// The issuer identifier: `issuer`, or `issuer.id` (VCDM 2.0 §4.7).
    pub issuer: Option<String>,
    pub valid_from: Option<Timestamp>,
    pub valid_until: Option<Timestamp>,
    /// Every scalar value in the document, flattened to a path. The format decides
    /// which are claims and which are metadata (REQUIREMENTS §8).
    pub leaves: Vec<Leaf>,
    pub proofs: Vec<ProofDescriptor>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DocumentKind {
    Credential,
    Presentation,
}

/// One item of `@context` (VCDM 2.0 §4.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextEntry {
    Url(String),
    /// An inline context definition.
    Object,
    /// Neither a string nor an object.
    Other,
}

/// A date-time as written, and as read or why it could not be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timestamp {
    /// The value as written; `None` when it is not a string.
    pub lexical: Option<String>,
    pub parsed: Result<OffsetDateTime, DateTimeProblem>,
}

/// Why a date-time could not be read (VCDM 2.0 §4.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DateTimeProblem {
    /// Not a JSON string.
    NotString,
    /// Not in XML Schema 1.1's `dateTimeStamp` lexical space. `valid_rfc3339` says
    /// whether RFC 3339 would accept it.
    NotDateTimeStamp { valid_rfc3339: bool },
    /// A `dateTimeStamp` outside the years vcrd can represent, -9999 to 9999.
    Unrepresentable,
}

/// One scalar value and where it is.
#[derive(Clone, Debug)]
pub struct Leaf {
    /// Dotted path from the document root, e.g. `credentialSubject.degree.name`.
    pub path: String,
    pub class: LeafClass,
    pub value: ClaimValue,
}

/// Claims are masked by default; metadata is always shown (REQUIREMENTS §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafClass {
    Claim,
    Metadata,
}

/// Where a proof is and what it covers. Carries hints about key material, never a
/// resolved key (ARCHITECTURE §3).
#[derive(Clone, Debug)]
pub struct ProofDescriptor {
    pub suite: SuiteId,
    /// The algorithm the input declares.
    pub algorithm: Option<String>,
    pub key_hints: KeyHints,
    pub material: ProofMaterial,
    /// The proof's own times, which the runner compares with the clock.
    pub times: ProofTimes,
}

/// Where key material may be found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyHints {
    /// The issuer identifier, which may encode the key (`did:key`).
    pub issuer: Option<String>,
    /// The key identifier the proof names.
    pub kid: Option<String>,
    /// A key the credential carries about itself, used only as REQUIREMENTS §10
    /// allows.
    pub embedded: Option<EmbeddedKey>,
}

/// A key the credential carries about itself, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmbeddedKey {
    /// Where it was, e.g. `header.jwk`.
    pub location: &'static str,
    pub jwk: Jwk,
}

/// What the suite verifies. One variant per kind of suite (ARCHITECTURE §5).
#[derive(Clone)]
pub enum ProofMaterial {
    /// The JWS signing input, `header.payload` as encoded, and the decoded signature.
    Jws {
        signing_input: Vec<u8>,
        signature: Vec<u8>,
        /// The extensions `crit` lists, which the suite must implement or reject the
        /// JWS (RFC 7515 §4.1.11). Empty when `crit` is absent or lists none.
        critical: Vec<String>,
    },
}

/// Lengths only: the signing input encodes the claims.
impl fmt::Debug for ProofMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofMaterial::Jws {
                signing_input,
                signature,
                critical,
            } => f
                .debug_struct("Jws")
                .field("signing_input_len", &signing_input.len())
                .field("signature_len", &signature.len())
                .field("critical", critical)
                .finish(),
        }
    }
}

/// A proof's own times, distinct from the credential's validity period. Under
/// VC-JOSE-COSE they are the JWT's `nbf`, `exp` and `iat`, "the issuance and
/// expiration time of the signature" (§3.1.3).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProofTimes {
    /// Not valid before this time (`nbf`, RFC 7519 §4.1.5).
    pub not_before: Option<ProofTime>,
    /// Not valid at or after this time (`exp`, RFC 7519 §4.1.4).
    pub expires: Option<ProofTime>,
    /// When the proof was made (`iat`, RFC 7519 §4.1.6).
    pub issued_at: Option<ProofTime>,
}

/// One of a proof's times, and the member it was read from.
#[derive(Clone, Debug, PartialEq)]
pub struct ProofTime {
    /// The member, e.g. `exp`.
    pub claim: &'static str,
    /// `None` when the value is not a number, which inspect reports.
    pub value: Option<NumericDate>,
}

/// Seconds since 1970-01-01T00:00:00Z UTC, ignoring leap seconds (RFC 7519 §2). Compared
/// as a number, so that every value compares, however far from the present.
#[derive(Clone, Debug, PartialEq)]
pub struct NumericDate {
    /// The JSON number as written.
    pub text: String,
    pub seconds: f64,
    /// The same instant as a date-time, for a reader; `None` outside the years
    /// -9999 to 9999. A fraction of a second is kept to the nanosecond.
    pub date_time: Option<OffsetDateTime>,
}

impl NumericDate {
    #[cfg_attr(not(feature = "vc-jose"), allow(dead_code))]
    pub(crate) fn new(text: String, seconds: f64) -> Self {
        let whole = seconds.floor();
        // A cast saturates, and a saturated value is outside the range `time` accepts.
        let date_time = OffsetDateTime::from_unix_timestamp(whole as i64)
            .ok()
            .and_then(|t| {
                t.checked_add(time::Duration::nanoseconds(
                    ((seconds - whole) * 1e9).round() as i64,
                ))
            });
        NumericDate {
            text,
            seconds,
            date_time,
        }
    }
}

/// A credential found inside another, handed back for the runner to dispatch
/// (ARCHITECTURE §4).
#[derive(Clone)]
pub struct ContainedInput {
    pub bytes: Vec<u8>,
    /// The media type from the `data:` URL, as a detection hint.
    pub media_type: Option<String>,
    /// Where it was found, e.g. `verifiableCredential[1]`.
    pub location: String,
}

/// Length only: the bytes are a credential.
impl fmt::Debug for ContainedInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContainedInput")
            .field("bytes_len", &self.bytes.len())
            .field("media_type", &self.media_type)
            .field("location", &self.location)
            .finish()
    }
}
