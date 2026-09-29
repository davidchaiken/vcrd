//! The format-neutral view of an input (ARCHITECTURE §3).

use std::fmt;

use time::OffsetDateTime;

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

/// A date-time as written, and as read when it could be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timestamp {
    pub lexical: String,
    pub parsed: Option<OffsetDateTime>,
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
}

/// Where key material may be found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyHints {
    /// The issuer identifier, which may encode the key (`did:key`).
    pub issuer: Option<String>,
    /// The key identifier the proof names.
    pub kid: Option<String>,
}

/// What the suite verifies. One variant per kind of suite (ARCHITECTURE §5).
#[derive(Clone)]
pub enum ProofMaterial {
    /// The JWS signing input, `header.payload` as encoded, and the decoded signature.
    Jws {
        signing_input: Vec<u8>,
        signature: Vec<u8>,
    },
}

/// Lengths only: the signing input encodes the claims.
impl fmt::Debug for ProofMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofMaterial::Jws {
                signing_input,
                signature,
            } => f
                .debug_struct("Jws")
                .field("signing_input_len", &signing_input.len())
                .field("signature_len", &signature.len())
                .finish(),
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
