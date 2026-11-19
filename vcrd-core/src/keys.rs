//! Key resolution and provenance (REQUIREMENTS §10; ARCHITECTURE §8).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::context::KeyPolicy;
use crate::document::{EmbeddedKey, KeyHints};
use crate::finding::{
    Attribution, DidKeyProblem, Finding, FindingDetail, JwkProblem, KeyRef, Severity,
    WeakKeyCriterion,
};
use crate::json::Json;
use crate::report::{Phase, ProofOutcome};

/// A resolved public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519(VerifyingKey),
}

impl PublicKey {
    /// The key as a JWK: the members its thumbprint covers.
    pub fn jwk(&self) -> PublicJwk {
        match self {
            // The required members of an OKP key (RFC 8037 §2).
            PublicKey::Ed25519(key) => PublicJwk {
                members: vec![
                    ("crv", "Ed25519".to_owned()),
                    ("kty", "OKP".to_owned()),
                    ("x", URL_SAFE_NO_PAD.encode(key.as_bytes())),
                ],
            },
        }
    }

    /// The RFC 7638 JWK thumbprint, base64url-encoded.
    pub fn thumbprint(&self) -> String {
        self.jwk().thumbprint()
    }
}

/// A public key as a JWK (RFC 7517): the members its RFC 7638 thumbprint covers, in
/// that RFC's lexicographic order, each value as written. Shown beside a thumbprint,
/// so that a reader can see which key it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicJwk {
    pub members: Vec<(&'static str, String)>,
}

impl PublicJwk {
    /// The RFC 7638 thumbprint, base64url-encoded: SHA-256 over the members as a JSON
    /// object with no whitespace (RFC 7638 §3.2–3.3).
    pub fn thumbprint(&self) -> String {
        let quote = |s: &str| serde_json::Value::String(s.to_owned()).to_string();
        let members: Vec<String> = self
            .members
            .iter()
            .map(|(name, value)| format!("{}:{}", quote(name), quote(value)))
            .collect();
        let canonical = format!("{{{}}}", members.join(","));
        URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
    }
}

/// A public key a credential carries about itself as a JWK (RFC 7517), parsed at the
/// parse boundary rather than kept as JSON (ARCHITECTURE §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jwk {
    /// Its public members, which the thumbprint covers.
    pub public: PublicJwk,
    /// The RFC 7638 thumbprint, base64url-encoded, by which it is compared with the
    /// key resolution establishes (ARCHITECTURE §8).
    pub thumbprint: String,
    /// The key, when vcrd can use it: in milestone 1, an Ed25519 key (RFC 8037 §2).
    pub key: Option<PublicKey>,
}

/// For each key type, the members it requires, which are the members its RFC 7638
/// thumbprint covers, in lexicographic order (RFC 7638 §3.2; RFC 8037 §2). `oct` is
/// absent: its one required member is the secret.
const REQUIRED_MEMBERS: &[(&str, &[&str])] = &[
    ("EC", &["crv", "kty", "x", "y"]),
    ("OKP", &["crv", "kty", "x"]),
    ("RSA", &["e", "kty", "n"]),
];

/// The members that hold private or secret key material (RFC 7518 §6.2.2, §6.3.2,
/// §6.4.1; RFC 8037 §2).
pub(crate) const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

impl Jwk {
    /// Reads a JWK's public members. Whether it also carries private ones is
    /// inspect's question, or the key set's ([`PRIVATE_MEMBERS`]).
    pub(crate) fn parse(json: &Json) -> Result<Jwk, JwkProblem> {
        if json.members().is_none() {
            return Err(JwkProblem::NotObject);
        }
        let kty = json
            .get("kty")
            .and_then(Json::as_str)
            .ok_or(JwkProblem::KtyMissing)?;
        if kty == "oct" {
            return Err(JwkProblem::Symmetric);
        }
        let required = REQUIRED_MEMBERS
            .iter()
            .find(|(k, _)| *k == kty)
            .map(|(_, members)| *members)
            .ok_or_else(|| JwkProblem::KtyUnknown {
                kty: kty.to_owned(),
            })?;
        let mut members = Vec::with_capacity(required.len());
        for &member in required {
            let value = json
                .get(member)
                .and_then(Json::as_str)
                .ok_or(JwkProblem::MemberMissing { member })?;
            members.push((member, value.to_owned()));
        }
        let public = PublicJwk { members };
        let key = match (kty, json.get("crv").and_then(Json::as_str)) {
            ("OKP", Some("Ed25519")) => {
                let x = json.get("x").and_then(Json::as_str).unwrap_or_default();
                Some(ed25519_jwk(x).ok_or(JwkProblem::KeyInvalid)?)
            }
            _ => None,
        };
        Ok(Jwk {
            thumbprint: public.thumbprint(),
            public,
            key,
        })
    }
}

/// An Ed25519 key's `x`: 32 bytes of strict base64url that decode to a point.
fn ed25519_jwk(x: &str) -> Option<PublicKey> {
    let bytes = URL_SAFE_NO_PAD.decode(x).ok()?;
    let bytes: &[u8; 32] = bytes.as_slice().try_into().ok()?;
    ed25519_key(bytes).ok().map(PublicKey::Ed25519)
}

/// An Ed25519 public key, decoded as RFC 8032 §5.1.3 decodes one. `curve25519-dalek`
/// also decodes y at or above p, and x = 0 with the sign bit set, so the point is
/// encoded again and compared with the bytes.
fn ed25519_key(bytes: &[u8; 32]) -> Result<VerifyingKey, DidKeyProblem> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| DidKeyProblem::PointInvalid)?;
    if key.to_edwards().compress().as_bytes() != bytes {
        return Err(DidKeyProblem::PointNotCanonical);
    }
    Ok(key)
}

/// Each key for one proof, the kinds of key it is, its proof's result, and which key
/// decides (ARCHITECTURE §8). Reported whether verification succeeds or fails.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyProvenance {
    /// The deciding proof key, as an index into `keys`; absent when no key may decide.
    /// A refused issuer key still decides, so that no other key can.
    pub deciding: Option<usize>,
    /// Each distinct key once, by RFC 7638 thumbprint, with every kind of key it is.
    pub keys: Vec<KeyReport>,
}

/// One distinct key: the kinds of key it is, where each came from, and its proof's
/// result (ARCHITECTURE §8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyReport {
    /// In the order of precedence: caller-supplied, issuer, embedded.
    pub kinds: Vec<KeySource>,
    /// How the issuer key was derived from the issuer identifier, e.g. `did:key`;
    /// present when the key is the issuer key.
    pub method: Option<&'static str>,
    /// Where the credential carries it, e.g. `header.jwk`; present when the key is an
    /// embedded key.
    pub location: Option<&'static str>,
    /// The RFC 7638 thumbprint; absent for a key vcrd names but cannot decode.
    pub thumbprint: Option<String>,
    /// The key as a JWK: what the thumbprint is of.
    pub jwk: Option<PublicJwk>,
    /// The proof's result with it as the proof key.
    pub proof: ProofOutcome,
    /// Why it may not decide the outcome, when it may not.
    pub refused: Option<Refusal>,
}

impl KeyReport {
    /// The key as a finding names it, boxed so that a finding naming two keys stays
    /// small.
    pub(crate) fn reference(&self) -> Box<KeyRef> {
        Box::new(KeyRef {
            kinds: self.kinds.clone(),
            method: self.method,
            location: self.location,
            thumbprint: self.thumbprint.clone(),
        })
    }

    fn new(kind: KeySource) -> Self {
        KeyReport {
            kinds: vec![kind],
            method: None,
            location: None,
            thumbprint: None,
            jwk: None,
            proof: ProofOutcome::NotAttempted,
            refused: None,
        }
    }
}

/// Why a key may not decide the outcome (ARCHITECTURE §8, "Refused"). One reason: the
/// key's own property comes before its being an embedded key alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A weak key (ARCHITECTURE §8, "Weak keys").
    WeakKey,
    /// A key-agreement key, which no verifier may use for a signature (RFC 8037 §3.2).
    NotForSigning,
    /// A key of a type vcrd cannot use.
    TypeUnsupported,
    /// An embedded key alone, without the caller's opt-in (ARCHITECTURE §8, rule 2).
    EmbeddedKeyAlone,
    /// One of two embedded keys not known to be the same key, which may not decide even
    /// with the opt-in.
    EmbeddedKeysDiffer,
}

/// An open set: consumers must accept values they do not recognize (ARCHITECTURE §8).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySource {
    /// Key material the caller passed in.
    CallerSupplied,
    /// Derived from the issuer identifier the credential names.
    IssuerIdentifier,
    /// A key the credential carries about itself, used only on the caller's opt-in.
    CredentialEmbedded,
}

impl KeySource {
    /// The stable name, so that a frontend need not match on this enumeration.
    pub fn as_str(self) -> &'static str {
        match self {
            KeySource::CallerSupplied => "caller_supplied",
            KeySource::IssuerIdentifier => "issuer_identifier",
            KeySource::CredentialEmbedded => "credential_embedded",
        }
    }
}

#[derive(Default)]
pub(crate) struct Resolution {
    pub findings: Vec<Finding>,
    /// Each distinct key, by RFC 7638 thumbprint, once, with every kind of key it is.
    pub keys: Vec<ProofKey>,
    /// An issuer identifier whose key vcrd cannot obtain, such as an `https:` URL: the
    /// table counts that issuer key as not present (ARCHITECTURE §8).
    pub unobtained: Option<UnobtainedIssuer>,
}

/// An issuer identifier whose key vcrd cannot obtain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnobtainedIssuer {
    pub issuer: String,
    /// The DID method or URL scheme, e.g. `did:web` or `https`.
    pub method: String,
}

impl Resolution {
    fn failed(finding: Finding) -> Self {
        Resolution {
            findings: vec![finding],
            ..Resolution::default()
        }
    }
}

/// A distinct key, as the result reports it, and the key itself (ARCHITECTURE §8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofKey {
    /// The kinds of key it is and where each came from; the runner adds its proof's
    /// result.
    pub report: KeyReport,
    /// The key, when it may be a proof key; `None` when key resolution refused it for a
    /// property of its own, as `report.refused` says.
    pub key: Option<PublicKey>,
}

/// What ARCHITECTURE §8's rules consult about one distinct key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeyAndProof {
    pub kinds: Vec<KeySource>,
    /// Refused by key resolution for a property of its own (ARCHITECTURE §8, "Refused").
    pub refused: bool,
    /// Whether the proof with it as the proof key is correct.
    pub correct: bool,
}

/// A condition ARCHITECTURE §8's rules set for success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Condition {
    /// Some key may decide: a caller-supplied key, an issuer key, or an embedded key the
    /// caller has opted in to.
    KeyPresent,
    /// The embedded key decides alone only with the caller's opt-in (rule 2).
    EmbeddedKeyOptIn,
    /// The credential carries one embedded key, or embedded keys known to be one key.
    EmbeddedKeysAgree,
    /// A caller-supplied key and an issuer key are the same key, unless the caller has
    /// opted in to the override (rule 1).
    CallerKeyIsIssuerKey,
    /// The deciding proof key is not refused.
    DecidingKeyNotRefused,
    /// The deciding proof is correct (rule 3).
    DecidingProofCorrect,
    /// No two different keys give correct proofs.
    OneKeyCorrect,
}

/// The outcome of ARCHITECTURE §8's rules for one proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Decision {
    /// The deciding proof key, as an index into the keys; `None` when no key may decide.
    pub deciding: Option<usize>,
    /// The conditions for success that are not met; empty when the rules permit success.
    pub unmet: Vec<Condition>,
}

/// ARCHITECTURE §8's rules, which together make its key and proof table: which key is the
/// deciding proof key, and which conditions for success are unmet. `keys` holds each
/// distinct key once, with every kind of key it is.
pub(crate) fn decide(keys: &[KeyAndProof], policy: KeyPolicy) -> Decision {
    let find = |kind| keys.iter().position(|k| k.kinds.contains(&kind));
    let caller = find(KeySource::CallerSupplied);
    let issuer = find(KeySource::IssuerIdentifier);
    let embedded: Vec<usize> = (0..keys.len())
        .filter(|&i| {
            keys.get(i)
                .is_some_and(|k| k.kinds.contains(&KeySource::CredentialEmbedded))
        })
        .collect();
    let mut unmet = Vec::new();
    // Rule 1: a caller-supplied key and an issuer key are the same key, unless the caller
    // has opted in to letting its key override the issuer key.
    let differ = matches!((caller, issuer), (Some(c), Some(i)) if c != i);
    if differ && !policy.allow_caller_key_override {
        unmet.push(Condition::CallerKeyIsIssuerKey);
    }
    // Rule 2: the issuer key decides when it is present, and the caller-supplied key when
    // it is not or the caller has opted in to the override; the embedded key, only when
    // neither is present and the caller has opted in, and only when the credential
    // carries one embedded key. A refused embedded key is treated as not present.
    let deciding = match (caller, issuer) {
        (Some(c), Some(_)) if differ && policy.allow_caller_key_override => Some(c),
        (_, Some(i)) => Some(i),
        (Some(c), None) => Some(c),
        (None, None) => match embedded[..] {
            [] => None,
            [..] if !policy.allow_embedded_key_alone => {
                unmet.push(Condition::EmbeddedKeyOptIn);
                None
            }
            [e] => Some(e).filter(|&e| keys.get(e).is_some_and(|k| !k.refused)),
            [..] => {
                unmet.push(Condition::EmbeddedKeysAgree);
                None
            }
        },
    };
    // Rule 3: the deciding proof is correct.
    let explained = [Condition::EmbeddedKeyOptIn, Condition::EmbeddedKeysAgree];
    match deciding.and_then(|d| keys.get(d)) {
        None if !unmet.iter().any(|c| explained.contains(c)) => {
            unmet.push(Condition::KeyPresent);
        }
        None => {}
        Some(key) if key.refused => unmet.push(Condition::DecidingKeyNotRefused),
        Some(key) if !key.correct => unmet.push(Condition::DecidingProofCorrect),
        Some(_) => {}
    }
    // Two different keys that both give correct proofs (ARCHITECTURE §8).
    if keys.iter().filter(|k| k.correct).count() > 1 {
        unmet.push(Condition::OneKeyCorrect);
    }
    Decision { deciding, unmet }
}

/// Finds the keys for one proof (REQUIREMENTS §10): the issuer key, when the issuer
/// identifier is a `did:key`, and the keys the credential carries, compared with it. A
/// `did:key` `kid` is one of those only when there is no issuer key. Which key decides
/// is [`decide`]'s question.
pub(crate) fn resolve(hints: &KeyHints) -> Resolution {
    let mut resolution = match hints.issuer.as_deref() {
        Some(issuer) => from_issuer(issuer),
        None => Resolution::default(),
    };
    if let Some(embedded) = &hints.embedded {
        compare_embedded(embedded, &mut resolution);
    }
    let issuer_key = resolution
        .keys
        .iter()
        .any(|k| k.report.kinds.contains(&KeySource::IssuerIdentifier));
    if !issuer_key && let Some(identifier) = hints.kid.as_deref().and_then(did_key_kid) {
        add_kid_key(identifier, &mut resolution);
    }
    resolution
}

/// The method-specific identifier of a `kid` that is a `did:key` DID URL, such as
/// `did:key:z6Mk…#z6Mk…`: the key is the DID's, whatever the fragment.
pub(crate) fn did_key_kid(kid: &str) -> Option<&str> {
    kid.strip_prefix("did:key:")?.split('#').next()
}

/// A `did:key` `kid` as an embedded key, at `header.kid` (DEVELOPMENT-PLAN.md, milestone
/// 2, decided 2026-11-16): one key with the `jwk` when their thumbprints are equal,
/// another embedded key otherwise. A `did:key` that does not decode gives no key.
fn add_kid_key(identifier: &str, resolution: &mut Resolution) {
    let (key, jwk, refused) = match decode_did_key(identifier) {
        Err(_) => return,
        Ok(DidKey::Usable(key, weak)) => {
            let jwk = key.jwk();
            let refused = weak.then_some(Refusal::WeakKey);
            ((!weak).then_some(key), Some(jwk), refused)
        }
        Ok(DidKey::Unusable { .. }) => (None, None, Some(Refusal::TypeUnsupported)),
        Ok(DidKey::NotForSigning { .. }) => (None, None, Some(Refusal::NotForSigning)),
    };
    let thumbprint = jwk.as_ref().map(PublicJwk::thumbprint);
    let same_as_jwk = resolution.keys.iter().any(|k| {
        k.report.kinds.contains(&KeySource::CredentialEmbedded)
            && k.report.thumbprint.is_some()
            && k.report.thumbprint == thumbprint
    });
    if same_as_jwk {
        return;
    }
    resolution.keys.push(ProofKey {
        report: KeyReport {
            location: Some("header.kid"),
            thumbprint,
            jwk,
            refused,
            ..KeyReport::new(KeySource::CredentialEmbedded)
        },
        key,
    });
}

/// Records the embedded key (ARCHITECTURE §8): one key with the issuer key when their
/// thumbprints are equal, and a warning when the two differ. An issuer key vcrd cannot
/// decode has no thumbprint to compare. The runner adds its proof's result.
fn compare_embedded(embedded: &EmbeddedKey, resolution: &mut Resolution) {
    let report = KeyReport {
        location: Some(embedded.location),
        thumbprint: Some(embedded.jwk.thumbprint.clone()),
        jwk: Some(embedded.jwk.public.clone()),
        refused: embedded
            .jwk
            .key
            .is_none()
            .then_some(Refusal::TypeUnsupported),
        ..KeyReport::new(KeySource::CredentialEmbedded)
    };
    let issuer_key = resolution
        .keys
        .iter_mut()
        .find(|k| k.report.kinds.contains(&KeySource::IssuerIdentifier))
        .filter(|k| k.report.thumbprint.is_some());
    match issuer_key {
        Some(issuer) if issuer.report.thumbprint == report.thumbprint => {
            issuer.report.kinds.push(KeySource::CredentialEmbedded);
            issuer.report.location = report.location;
        }
        issuer => {
            if let Some(issuer) = issuer {
                resolution.findings.push(Finding::new(
                    Phase::Verify,
                    Attribution::Input,
                    Severity::Warning,
                    FindingDetail::EmbeddedKeyMismatch {
                        embedded_key: report.reference(),
                        key: issuer.report.reference(),
                    },
                ));
            }
            resolution.keys.push(ProofKey {
                report,
                key: embedded.jwk.key.clone(),
            });
        }
    }
}

/// The key the issuer identifier encodes, when it is a `did:key`. An issuer whose key
/// vcrd cannot obtain is recorded, not reported: whether that is an error depends on
/// whether another key decides, which is the runner's to say.
fn from_issuer(issuer: &str) -> Resolution {
    let Some(identifier) = issuer.strip_prefix("did:key:") else {
        return Resolution {
            unobtained: Some(UnobtainedIssuer {
                issuer: issuer.to_owned(),
                method: method_of(issuer),
            }),
            ..Resolution::default()
        };
    };
    match decode_did_key(identifier) {
        Err(problem) => Resolution::failed(Finding::error(
            Phase::Verify,
            Attribution::Input,
            FindingDetail::DidKeyUndecodable { problem },
        )),
        // A key vcrd names, or does not know, but cannot use is still the issuer key:
        // refused, with no thumbprint, since vcrd does not decode it (ARCHITECTURE §8).
        Ok(DidKey::Unusable { codec, name }) => refused_did_key(
            Refusal::TypeUnsupported,
            Finding::error(
                Phase::Verify,
                Attribution::Vcrd,
                FindingDetail::DidKeyCodecUnsupported { codec, name },
            ),
        ),
        Ok(DidKey::NotForSigning { codec, name }) => refused_did_key(
            Refusal::NotForSigning,
            Finding::error(
                Phase::Verify,
                Attribution::Input,
                FindingDetail::DidKeyNotForSigning { codec, name },
            ),
        ),
        Ok(DidKey::Usable(key, weak)) => {
            let jwk = key.jwk();
            let report = KeyReport {
                method: Some("did:key"),
                thumbprint: Some(jwk.thumbprint()),
                jwk: Some(jwk),
                refused: weak.then_some(Refusal::WeakKey),
                ..KeyReport::new(KeySource::IssuerIdentifier)
            };
            if weak {
                // Checked at resolution, not left to the verifier (ARCHITECTURE §8).
                let finding = Finding::error(
                    Phase::Verify,
                    Attribution::Input,
                    FindingDetail::WeakKey {
                        key: report.reference(),
                        criterion: WeakKeyCriterion::SmallOrder,
                    },
                );
                Resolution {
                    findings: vec![finding],
                    keys: vec![ProofKey { report, key: None }],
                    unobtained: None,
                }
            } else {
                Resolution {
                    findings: Vec::new(),
                    keys: vec![ProofKey {
                        report,
                        key: Some(key),
                    }],
                    unobtained: None,
                }
            }
        }
    }
}

/// A `did:key` issuer key refused for its type, with the finding that says why.
fn refused_did_key(refusal: Refusal, finding: Finding) -> Resolution {
    Resolution {
        findings: vec![finding],
        keys: vec![ProofKey {
            report: KeyReport {
                method: Some("did:key"),
                refused: Some(refusal),
                ..KeyReport::new(KeySource::IssuerIdentifier)
            },
            key: None,
        }],
        unobtained: None,
    }
}

/// `did:web` for a DID, the scheme for any other URL.
fn method_of(identifier: &str) -> String {
    let mut parts = identifier.splitn(3, ':');
    match (parts.next(), parts.next()) {
        (Some("did"), Some(method)) => format!("did:{method}"),
        (Some(scheme), Some(_)) => scheme.to_owned(),
        _ => identifier.to_owned(),
    }
}

enum DidKey {
    /// The key, and whether it is weak.
    Usable(PublicKey, bool),
    /// A key type vcrd can name, or not, but cannot use.
    Unusable {
        codec: u64,
        name: Option<&'static str>,
    },
    /// A key-agreement key, which no verifier may use for a signature.
    NotForSigning { codec: u64, name: &'static str },
}

/// The multicodec key types ARCHITECTURE §8 lists that vcrd cannot yet use.
const NAMED_CODECS: &[(u64, &str)] = &[
    (0x1200, "p256-pub"),
    (0x1201, "p384-pub"),
    (0x1202, "p521-pub"),
    (0xe7, "secp256k1-pub"),
    (0x1205, "rsa-pub"),
    (0x1203, "ed448-pub"),
];

/// The multicodec key types for key agreement, which RFC 8037 §3.2 forbids for signing.
const KEY_AGREEMENT_CODECS: &[(u64, &str)] = &[(0xec, "x25519-pub"), (0x1204, "x448-pub")];

const ED25519_PUB: u64 = 0xed;

/// Decodes the method-specific identifier of a `did:key`: multibase base58btc
/// (prefix `z`), then an unsigned-varint multicodec prefix naming the key type
/// (ARCHITECTURE §8).
fn decode_did_key(identifier: &str) -> Result<DidKey, DidKeyProblem> {
    // did:key v0.9's Create algorithm reads the component before the multibase value
    // as a version; its syntax has none.
    if identifier.contains(':') {
        return Err(DidKeyProblem::VersionPresent);
    }
    let encoded = identifier
        .strip_prefix('z')
        .ok_or(DidKeyProblem::NotBase58btc)?;
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| DidKeyProblem::Base58Invalid)?;
    let (codec, key) =
        unsigned_varint::decode::u64(&bytes).map_err(|_| DidKeyProblem::CodecInvalid)?;
    if let Some(&(codec, name)) = KEY_AGREEMENT_CODECS.iter().find(|(c, _)| *c == codec) {
        return Ok(DidKey::NotForSigning { codec, name });
    }
    if codec != ED25519_PUB {
        let name = NAMED_CODECS
            .iter()
            .find(|(c, _)| *c == codec)
            .map(|(_, n)| *n);
        return Ok(DidKey::Unusable { codec, name });
    }
    let key: &[u8; 32] = key.try_into().map_err(|_| DidKeyProblem::KeyLength {
        expected: 32,
        found: key.len(),
    })?;
    let key = ed25519_key(key)?;
    Ok(DidKey::Usable(PublicKey::Ed25519(key), key.is_weak()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8037 appendix A.2's public key.
    const RFC8037_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

    fn did_key(codec_prefix: &[u8], key: &[u8]) -> String {
        let bytes = [codec_prefix, key].concat();
        format!("did:key:z{}", bs58::encode(bytes).into_string())
    }

    fn rfc8037_key() -> [u8; 32] {
        URL_SAFE_NO_PAD
            .decode(RFC8037_X)
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn thumbprint_matches_rfc8037_a3() {
        let key = PublicKey::Ed25519(VerifyingKey::from_bytes(&rfc8037_key()).unwrap());
        assert_eq!(
            key.thumbprint(),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    #[test]
    fn resolves_an_ed25519_did_key() {
        let hints = KeyHints {
            issuer: Some(did_key(&[0xed, 0x01], &rfc8037_key())),
            kid: None,
            embedded: None,
        };
        let resolution = resolve(&hints);
        assert!(resolution.findings.is_empty(), "{:?}", resolution.findings);
        assert_eq!(
            kinds(&resolution),
            [(vec![KeySource::IssuerIdentifier], true)]
        );
        let report = &resolution.keys[0].report;
        assert_eq!(report.method, Some("did:key"));
        assert_eq!(
            report.thumbprint.as_deref(),
            Some("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k")
        );
        assert_eq!(report.refused, None);
    }

    /// ARCHITECTURE §8, "Refused": a `did:key` of a key type vcrd names but cannot use,
    /// or of a key-agreement key, is a refused issuer key. vcrd does not decode it, so
    /// it has no thumbprint.
    #[test]
    fn a_did_key_vcrd_cannot_use_is_a_refused_issuer_key() {
        for (prefix, length, refusal) in [
            (&[0x83, 0x24][..], 57, Refusal::TypeUnsupported),
            (&[0xec, 0x01][..], 32, Refusal::NotForSigning),
        ] {
            let resolution = resolve_issuer(&did_key(prefix, &vec![9; length]));
            assert_eq!(resolution.findings.len(), 1, "{:?}", resolution.findings);
            let [key] = resolution.keys.as_slice() else {
                panic!("one key: {:?}", resolution.keys)
            };
            assert_eq!(key.key, None);
            assert_eq!(
                key.report,
                KeyReport {
                    method: Some("did:key"),
                    refused: Some(refusal),
                    ..KeyReport::new(KeySource::IssuerIdentifier)
                }
            );
        }
    }

    /// Each distinct key resolution found: its kinds, and whether it may be a proof key.
    fn kinds(resolution: &Resolution) -> Vec<(Vec<KeySource>, bool)> {
        resolution
            .keys
            .iter()
            .map(|k| (k.report.kinds.clone(), k.key.is_some()))
            .collect()
    }

    /// The table's key columns, in its order: E, I and C.
    const KINDS: [KeySource; 3] = [
        KeySource::CredentialEmbedded,
        KeySource::IssuerIdentifier,
        KeySource::CallerSupplied,
    ];

    /// The table's columns E=I, E=C and I=C, as pairs of indexes into [`KINDS`].
    const PAIRS: [(usize, usize); 3] = [(0, 1), (0, 2), (1, 2)];

    /// A cell for a key, or a pair of keys, that is not present.
    const ABSENT: &str = "—";

    /// ARCHITECTURE §8's key and proof table: its header's cells, and each row's.
    fn key_and_proof_table(architecture: &str) -> (Vec<&str>, Vec<Vec<&str>>) {
        fn cells(line: &str) -> Vec<&str> {
            line.trim_matches('|').split('|').map(str::trim).collect()
        }
        let mut lines = architecture
            .lines()
            .skip_while(|l| !l.starts_with("| EIC |"));
        let header = cells(lines.next().unwrap());
        let rows = lines
            .take_while(|l| l.starts_with('|'))
            .filter(|l| !l.starts_with("|---"))
            .map(cells)
            .collect();
        (header, rows)
    }

    /// ARCHITECTURE §8's key and proof table against `decide`: its rows are every
    /// combination its preamble describes, once each, and each row's S? is what
    /// `decide` gives with each setting of the two opt-ins. The test reads the table, so
    /// that the table and the rules cannot disagree unnoticed.
    #[test]
    fn decide_agrees_with_every_row_of_the_key_and_proof_table() {
        let architecture =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../ARCHITECTURE.md"))
                .unwrap();
        let (header, rows) = key_and_proof_table(&architecture);
        // The cells before S? say which keys are present, which are the same key, and
        // which proofs are correct.
        let combination = header.iter().position(|&c| c == "S?").unwrap();
        let mut described: Vec<Vec<String>> = rows
            .iter()
            .map(|row| row[..combination].iter().map(|&c| c.to_owned()).collect())
            .collect();
        let mut expected = every_combination();
        described.sort();
        expected.sort();
        let missing: Vec<_> = expected.iter().filter(|c| !described.contains(c)).collect();
        let repeated: Vec<_> = described.windows(2).filter(|w| w[0] == w[1]).collect();
        let unexpected: Vec<_> = described.iter().filter(|c| !expected.contains(c)).collect();
        // `every_combination` gives each combination once, so these three lists are
        // empty exactly when the rows and the combinations are equal.
        assert!(
            missing.is_empty() && repeated.is_empty() && unexpected.is_empty(),
            "missing: {missing:?}; repeated: {repeated:?}; not described: {unexpected:?}"
        );
        for row in &rows {
            let [
                eic,
                e_i,
                e_c,
                i_c,
                e_proof,
                i_proof,
                c_proof,
                success,
                situation,
            ] = row[..]
            else {
                panic!("a row of nine cells: {row:?}")
            };
            let keys = row_keys(eic, [e_i, e_c, i_c], [e_proof, i_proof, c_proof]);
            for (allow_embedded_key_alone, allow_caller_key_override) in
                [(false, false), (true, false), (false, true), (true, true)]
            {
                let policy = KeyPolicy {
                    allow_embedded_key_alone,
                    allow_caller_key_override,
                };
                let permitted = match success {
                    "Y" => true,
                    "N" => false,
                    "E" => allow_embedded_key_alone,
                    "C" => allow_caller_key_override,
                    other => panic!("S? is {other}: {row:?}"),
                };
                let decision = decide(&keys, policy);
                let cells = row[..combination].join(" ");
                let context =
                    format!("row {cells} {success} ({situation}), {policy:?}: {decision:?}");
                assert_eq!(decision.unmet.is_empty(), permitted, "{context}");
                if permitted {
                    assert!(decision.deciding.is_some(), "{context}");
                }
            }
        }
    }

    /// Every combination the table's preamble describes, as the cells before S?: at most
    /// one key of each kind; which present keys are the same key, equality being
    /// transitive; and each distinct key's proof, no two different keys both correct.
    fn every_combination() -> Vec<Vec<String>> {
        let yes_no = |b: bool| if b { "Y" } else { "N" };
        let mut combinations = Vec::new();
        for mask in 0..1usize << KINDS.len() {
            let present: Vec<usize> = (0..KINDS.len()).filter(|k| mask & 1 << k != 0).collect();
            for groups in groupings(present.len()) {
                // Each present kind's distinct key, by index into `groups`.
                let key = |kind: usize| present.iter().position(|&p| p == kind).map(|i| groups[i]);
                let distinct = groups.iter().max().map_or(0, |m| m + 1);
                // No key's proof correct, or one distinct key's.
                for correct in std::iter::once(None).chain((0..distinct).map(Some)) {
                    let eic = (0..KINDS.len())
                        .map(|k| if key(k).is_some() { '1' } else { '0' })
                        .collect::<String>();
                    let same = PAIRS.iter().map(|&(a, b)| match (key(a), key(b)) {
                        (Some(x), Some(y)) => yes_no(x == y),
                        _ => ABSENT,
                    });
                    let proofs = (0..KINDS.len())
                        .map(|k| key(k).map_or(ABSENT, |g| yes_no(Some(g) == correct)));
                    let cells = std::iter::once(eic.as_str()).chain(same).chain(proofs);
                    combinations.push(cells.map(str::to_owned).collect());
                }
            }
        }
        combinations
    }

    /// Every way to group `n` present keys into distinct keys, each once, as the distinct
    /// key of each present key: the restricted growth strings of length `n`.
    fn groupings(n: usize) -> Vec<Vec<usize>> {
        let mut all = vec![Vec::new()];
        for _ in 0..n {
            all = all
                .into_iter()
                .flat_map(|groups: Vec<usize>| {
                    let new = groups.iter().max().map_or(0, |m| m + 1);
                    (0..=new).map(move |g| [groups.clone(), vec![g]].concat())
                })
                .collect();
        }
        all
    }

    /// The distinct keys a row of the table describes: E, I and C, each present key once,
    /// joined with an earlier one where the row says the two are the same key.
    fn row_keys(eic: &str, same: [&str; 3], proofs: [&str; 3]) -> Vec<KeyAndProof> {
        let present: Vec<bool> = eic.chars().map(|c| c == '1').collect();
        let mut keys: Vec<(Vec<usize>, bool)> = Vec::new();
        for kind in (0..KINDS.len()).filter(|&k| present[k]) {
            let correct = proofs[kind] == "Y";
            let earlier = PAIRS
                .iter()
                .zip(same)
                .find(|((a, b), cell)| *b == kind && *cell == "Y" && present[*a])
                .map(|((a, _), _)| *a);
            match earlier.and_then(|a| keys.iter_mut().find(|(kinds, _)| kinds.contains(&a))) {
                Some((kinds, earlier_correct)) => {
                    assert_eq!(*earlier_correct, correct, "the same key's proofs: {eic}");
                    kinds.push(kind);
                }
                None => keys.push((vec![kind], correct)),
            }
        }
        keys.into_iter()
            .map(|(kinds, correct)| KeyAndProof {
                // In the order of precedence: caller-supplied, issuer, embedded.
                kinds: kinds.iter().rev().map(|&k| KINDS[k]).collect(),
                refused: false,
                correct,
            })
            .collect()
    }

    /// What the table leaves out, or cannot show: no key, a refused key, and two
    /// different keys whose proofs are both correct (ARCHITECTURE §8).
    #[test]
    fn decide_beyond_the_table() {
        use Condition::*;
        use KeySource::*;
        let key = |kinds: &[KeySource], refused, correct| KeyAndProof {
            kinds: kinds.to_vec(),
            refused,
            correct,
        };
        let decision = |deciding, unmet: &[Condition]| Decision {
            deciding,
            unmet: unmet.to_vec(),
        };
        let neither = KeyPolicy::default();
        let both = KeyPolicy {
            allow_embedded_key_alone: true,
            allow_caller_key_override: true,
        };
        assert_eq!(decide(&[], both), decision(None, &[KeyPresent]));
        // A refused issuer key decides, and prevents success.
        assert_eq!(
            decide(&[key(&[IssuerIdentifier], true, false)], neither),
            decision(Some(0), &[DecidingKeyNotRefused])
        );
        // A refused embedded key is treated as not present, even with the opt-in.
        assert_eq!(
            decide(&[key(&[CredentialEmbedded], true, false)], both),
            decision(None, &[KeyPresent])
        );
        // Without the opt-in, an embedded key alone is refused for that reason.
        assert_eq!(
            decide(&[key(&[CredentialEmbedded], true, false)], neither),
            decision(None, &[EmbeddedKeyOptIn])
        );
        // Two different keys with correct proofs: the issuer key and the embedded key.
        let issuer_and_embedded = [
            key(&[IssuerIdentifier], false, true),
            key(&[CredentialEmbedded], false, true),
        ];
        assert_eq!(
            decide(&issuer_and_embedded, both),
            decision(Some(0), &[OneKeyCorrect])
        );
        // A caller-supplied key and an issuer key, with the override and without it.
        let caller_and_issuer = [
            key(&[CallerSupplied], false, true),
            key(&[IssuerIdentifier], false, true),
        ];
        assert_eq!(
            decide(&caller_and_issuer, both),
            decision(Some(0), &[OneKeyCorrect])
        );
        assert_eq!(
            decide(&caller_and_issuer, neither),
            decision(Some(1), &[CallerKeyIsIssuerKey, OneKeyCorrect])
        );
        // Two embedded keys not known to be one key: neither decides, even with the
        // opt-in; without it, both are refused alone.
        let two_embedded = [
            key(&[CredentialEmbedded], false, true),
            key(&[CredentialEmbedded], false, false),
        ];
        assert_eq!(
            decide(&two_embedded, both),
            decision(None, &[EmbeddedKeysAgree])
        );
        assert_eq!(
            decide(&two_embedded, neither),
            decision(None, &[EmbeddedKeyOptIn])
        );
        // Beside an issuer key, the embedded keys never decide, so it does not matter
        // whether they agree.
        let issuer_and_two_embedded = [
            key(&[IssuerIdentifier], false, true),
            key(&[CredentialEmbedded], false, false),
            key(&[CredentialEmbedded], false, false),
        ];
        assert_eq!(
            decide(&issuer_and_two_embedded, both),
            decision(Some(0), &[])
        );
    }

    #[test]
    fn names_a_key_type_it_cannot_use() {
        let hints = KeyHints {
            issuer: Some(did_key(&[0x80, 0x24], &[2; 33])),
            kid: None,
            embedded: None,
        };
        let resolution = resolve(&hints);
        let [finding] = resolution.findings.as_slice() else {
            panic!("one finding")
        };
        assert_eq!(finding.attribution, Attribution::Vcrd);
        assert!(matches!(
            finding.detail,
            FindingDetail::DidKeyCodecUnsupported {
                codec: 0x1200,
                name: Some("p256-pub")
            }
        ));
    }

    /// Each way the did:key v0.9 decoding can fail is named: the multibase prefix
    /// (Create, step 3), the base58btc and the multicodec header (Decode Public Key),
    /// the key's length and its encoding (Signature Method Creation, steps 3 and 4).
    #[test]
    fn names_what_is_wrong_with_a_did_key() {
        let key = rfc8037_key();
        // y = 2, which no point on the curve has.
        let mut not_a_point = [0; 32];
        not_a_point[0] = 2;
        assert_eq!(undecodable("did:key:u7QE"), DidKeyProblem::NotBase58btc);
        assert_eq!(undecodable("did:key:z0OIl"), DidKeyProblem::Base58Invalid);
        assert_eq!(
            undecodable(&did_key(&[0x80], &[])),
            DidKeyProblem::CodecInvalid
        );
        assert_eq!(
            undecodable(&did_key(&[0xed, 0x01], &key[..31])),
            DidKeyProblem::KeyLength {
                expected: 32,
                found: 31
            }
        );
        assert_eq!(
            undecodable(&did_key(&[0xed, 0x01], &not_a_point)),
            DidKeyProblem::PointInvalid
        );
    }

    /// RFC 8032 §5.1.3: decoding fails for y at or above p (step 1), and for x = 0 with
    /// the sign bit set (step 4). `curve25519-dalek` decodes both. y = p + 3 is the
    /// point whose y is 3, which is not weak.
    #[test]
    fn rejects_a_key_not_encoded_as_rfc8032_requires() {
        assert_eq!(
            undecodable(&did_key(&[0xed, 0x01], &y_above_p(3))),
            DidKeyProblem::PointNotCanonical
        );
        let mut y_is_3 = [0; 32];
        y_is_3[0] = 3;
        let resolution = resolve_issuer(&did_key(&[0xed, 0x01], &y_is_3));
        assert!(resolution.findings.is_empty(), "{:?}", resolution.findings);
        // The identity point, whose x is 0, with the sign bit set.
        let mut identity = [0; 32];
        identity[0] = 1;
        identity[31] = 0x80;
        assert_eq!(
            undecodable(&did_key(&[0xed, 0x01], &identity)),
            DidKeyProblem::PointNotCanonical
        );
        let x = URL_SAFE_NO_PAD.encode(y_above_p(3));
        assert_eq!(
            jwk(&format!(
                r#"{{"kty": "OKP", "crv": "Ed25519", "x": "{x}"}}"#
            )),
            Err(JwkProblem::KeyInvalid)
        );
    }

    /// RFC 8037 §3.2: X25519 and X448 keys MUST NOT be used for signing, so a `did:key`
    /// holding one is the input's error, not a key type vcrd lacks. An Ed448 key is one
    /// vcrd lacks, and is named.
    #[test]
    fn a_key_agreement_key_is_not_for_signing() {
        for (prefix, length, expected_codec, expected_name) in [
            (&[0xec, 0x01][..], 32, 0xec, "x25519-pub"),
            (&[0x84, 0x24][..], 56, 0x1204, "x448-pub"),
        ] {
            let finding = one_finding(&did_key(prefix, &vec![9; length]));
            assert_eq!(finding.attribution, Attribution::Input, "{finding:?}");
            assert!(
                matches!(
                    finding.detail,
                    FindingDetail::DidKeyNotForSigning { codec, name }
                        if codec == expected_codec && name == expected_name
                ),
                "{finding:?}"
            );
        }
        let finding = one_finding(&did_key(&[0x83, 0x24], &[9; 57]));
        assert_eq!(finding.attribution, Attribution::Vcrd);
        assert!(
            matches!(
                finding.detail,
                FindingDetail::DidKeyCodecUnsupported {
                    codec: 0x1203,
                    name: Some("ed448-pub")
                }
            ),
            "{finding:?}"
        );
    }

    /// did:key v0.9's Create algorithm reads a version before the multibase value; its
    /// syntax has none. The version is named, rather than taken for the value.
    #[test]
    fn names_a_version_before_the_multibase_value() {
        let issuer = did_key(&[0xed, 0x01], &rfc8037_key());
        let versioned = issuer.replacen("did:key:", "did:key:1:", 1);
        assert_eq!(undecodable(&versioned), DidKeyProblem::VersionPresent);
    }

    fn resolve_issuer(issuer: &str) -> Resolution {
        resolve(&KeyHints {
            issuer: Some(issuer.to_owned()),
            kid: None,
            embedded: None,
        })
    }

    /// The one finding resolving this issuer reports.
    fn one_finding(issuer: &str) -> Finding {
        let resolution = resolve_issuer(issuer);
        let [finding] = resolution.findings.as_slice() else {
            panic!("{issuer}: {:?}", resolution.findings)
        };
        finding.clone()
    }

    /// Why this issuer's `did:key` does not decode, a problem of the input's.
    fn undecodable(issuer: &str) -> DidKeyProblem {
        match one_finding(issuer) {
            Finding {
                detail: FindingDetail::DidKeyUndecodable { problem },
                attribution: Attribution::Input,
                ..
            } => problem,
            other => panic!("{issuer}: {other:?}"),
        }
    }

    /// y = p + `excess`, at or above p = 2^255 - 19, with the sign bit clear.
    fn y_above_p(excess: u8) -> [u8; 32] {
        let mut bytes = [0xff; 32];
        bytes[0] = 0xed + excess;
        bytes[31] = 0x7f;
        bytes
    }

    fn jwk(text: &str) -> Result<Jwk, JwkProblem> {
        Jwk::parse(&Json::parse(text.as_bytes()).unwrap())
    }

    /// RFC 7638 §3.1's example, whose `alg` and `kid` the thumbprint leaves out.
    #[test]
    fn jwk_thumbprint_matches_rfc7638_3_1() {
        let n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
        let key = jwk(&format!(
            r#"{{"kty": "RSA", "n": "{n}", "e": "AQAB", "alg": "RS256", "kid": "2011-04-29"}}"#
        ))
        .unwrap();
        assert_eq!(
            key.thumbprint,
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
        assert_eq!(key.key, None);
    }

    /// The same thumbprint whether the key arrives as a JWK or a `did:key`.
    #[test]
    fn ed25519_jwk_matches_rfc8037_a3() {
        let key = jwk(&format!(
            r#"{{"kty": "OKP", "crv": "Ed25519", "x": "{RFC8037_X}"}}"#
        ))
        .unwrap();
        assert_eq!(
            key.thumbprint,
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
        assert_eq!(key.key.unwrap().thumbprint(), key.thumbprint);
    }

    #[test]
    fn names_what_is_wrong_with_a_jwk() {
        assert_eq!(jwk("[]"), Err(JwkProblem::NotObject));
        assert_eq!(jwk(r#"{"kty": 1}"#), Err(JwkProblem::KtyMissing));
        assert_eq!(
            jwk(r#"{"kty": "oct", "k": "c2VjcmV0"}"#),
            Err(JwkProblem::Symmetric)
        );
        assert_eq!(
            jwk(r#"{"kty": "AKP"}"#),
            Err(JwkProblem::KtyUnknown { kty: "AKP".into() })
        );
        assert_eq!(
            jwk(r#"{"kty": "EC", "crv": "P-256", "x": "AA"}"#),
            Err(JwkProblem::MemberMissing { member: "y" })
        );
        assert_eq!(
            jwk(r#"{"kty": "OKP", "crv": "Ed25519", "x": "AAAA"}"#),
            Err(JwkProblem::KeyInvalid)
        );
    }

    fn with_embedded(issuer: Option<String>, x: &str) -> Resolution {
        let jwk = jwk(&format!(
            r#"{{"kty": "OKP", "crv": "Ed25519", "x": "{x}"}}"#
        ))
        .unwrap();
        resolve(&KeyHints {
            issuer,
            kid: None,
            embedded: Some(EmbeddedKey {
                location: "header.jwk",
                jwk,
            }),
        })
    }

    #[test]
    fn an_embedded_key_equal_to_the_did_key_is_the_same_key() {
        let issuer = did_key(&[0xed, 0x01], &rfc8037_key());
        let resolution = with_embedded(Some(issuer), RFC8037_X);
        assert!(resolution.findings.is_empty(), "{:?}", resolution.findings);
        assert_eq!(
            kinds(&resolution),
            [(
                vec![KeySource::IssuerIdentifier, KeySource::CredentialEmbedded],
                true
            )]
        );
        let report = &resolution.keys[0].report;
        assert_eq!(
            (report.method, report.location),
            (Some("did:key"), Some("header.jwk"))
        );
    }

    #[test]
    fn an_embedded_key_unlike_the_did_key_is_a_warning() {
        let issuer = did_key(&[0xed, 0x01], &rfc8037_key());
        let other = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let other = URL_SAFE_NO_PAD.encode(other.as_bytes());
        let resolution = with_embedded(Some(issuer), &other);
        let [finding] = resolution.findings.as_slice() else {
            panic!("one finding: {:?}", resolution.findings)
        };
        assert_eq!(finding.code, "verify.embedded_key_mismatch");
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(
            kinds(&resolution),
            [
                (vec![KeySource::IssuerIdentifier], true),
                (vec![KeySource::CredentialEmbedded], true)
            ]
        );
        assert_eq!(resolution.keys[1].report.location, Some("header.jwk"));
    }

    /// Resolution reports an embedded key alone, and refuses nothing: the rules refuse it
    /// without the caller's opt-in (ARCHITECTURE §8, rule 2), and the runner reports the
    /// refusal, `verify.embedded_key_refused`.
    #[test]
    fn an_embedded_key_alone_decides_only_with_the_opt_in() {
        let resolution = with_embedded(None, RFC8037_X);
        assert!(resolution.findings.is_empty(), "{:?}", resolution.findings);
        assert_eq!(
            kinds(&resolution),
            [(vec![KeySource::CredentialEmbedded], true)]
        );
        let embedded = [KeyAndProof {
            kinds: vec![KeySource::CredentialEmbedded],
            refused: false,
            correct: true,
        }];
        assert_eq!(
            decide(&embedded, KeyPolicy::default()).unmet,
            [Condition::EmbeddedKeyOptIn]
        );
        let opted_in = KeyPolicy {
            allow_embedded_key_alone: true,
            ..KeyPolicy::default()
        };
        assert_eq!(
            decide(&embedded, opted_in),
            Decision {
                deciding: Some(0),
                unmet: Vec::new()
            }
        );
    }

    #[test]
    fn names_the_method_of_an_issuer_it_cannot_resolve() {
        assert_eq!(method_of("did:web:example.com"), "did:web");
        assert_eq!(method_of("https://example.com/issuer"), "https");
    }
}
