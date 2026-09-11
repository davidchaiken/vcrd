//! The graduated-result shape (prototype question 1).
//!
//! The load-bearing claim being tested here: credential-level problems are *never*
//! `Err`. `Report` is returned by value and carries a per-tier outcome plus an
//! enumeration of what was deliberately not evaluated. `Result` is reserved for
//! caller faults (unreadable file, nonsense config), which live in `vcrd-cli`.

use crate::redact::ClaimValue;

/// Which stage of the pipeline a finding belongs to (REQUIREMENTS §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Parse,
    Validate,
    Verify,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Parse => "parse",
            Tier::Validate => "validate",
            Tier::Verify => "verify",
        }
    }
}

/// "Whose side is it on" (REQUIREMENTS §6 diagnosability).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blame {
    /// The credential/input is at fault.
    Input,
    /// The caller's own policy rejected something vcrd could otherwise do.
    Policy,
    /// vcrd cannot do this yet. Not the input's fault.
    Vcrd,
    /// Something outside both (missing key material, unreachable resolver).
    Environment,
}

impl Blame {
    pub fn as_str(self) -> &'static str {
        match self {
            Blame::Input => "input",
            Blame::Policy => "policy",
            Blame::Vcrd => "vcrd",
            Blame::Environment => "environment",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

/// One structured, locale-independent diagnostic. No pre-formatted English (§6).
#[derive(Clone, Debug)]
pub struct Finding {
    pub code: &'static str,
    pub tier: Tier,
    pub blame: Blame,
    pub severity: Severity,
    pub detail: FindingDetail,
}

impl Finding {
    pub fn error(code: &'static str, tier: Tier, blame: Blame, detail: FindingDetail) -> Self {
        Finding { code, tier, blame, severity: Severity::Error, detail }
    }
    pub fn warn(code: &'static str, tier: Tier, blame: Blame, detail: FindingDetail) -> Self {
        Finding { code, tier, blame, severity: Severity::Warning, detail }
    }
}

/// The typed payload of a finding. Every variant carries the facts a caller needs to
/// act without re-decoding the credential themselves.
#[derive(Clone, Debug)]
pub enum FindingDetail {
    // --- parse tier ---
    NoFormatMatched { tried: Vec<&'static str> },
    NotCompactJws { segments: usize },
    Base64Invalid { segment: &'static str },
    JsonInvalid { segment: &'static str, message: String },
    InputTooLarge { limit: usize, found: usize },
    NestingTooDeep { limit: usize, found: usize },

    // --- validate tier ---
    ProfileNotImplemented { detected: &'static str, implemented: &'static str, marker: String },
    MissingField { field: &'static str },
    FieldWrongType { field: &'static str, expected: &'static str },
    DateTimeUnparseable { field: &'static str, value: String },
    Expired { valid_until: String, now: String, skew_seconds: i64 },
    NotYetValid { valid_from: String, now: String, skew_seconds: i64 },
    ClaimDisagreement { jwt_claim: &'static str, vc_field: &'static str, jwt_value: String, vc_value: String },
    TooManyClaims { limit: usize, found: usize },

    // --- verify tier: algorithm policy (§10) ---
    AlgorithmNone,
    AlgorithmUnsupported { declared: String, supported: Vec<&'static str> },
    AlgorithmPolicyRejected { declared: String, allowed: Vec<String> },
    AlgorithmKeyTypeMismatch { declared: String, key_kind: &'static str, expects: &'static str },

    // --- verify tier: key provenance (§6/§12) ---
    NoKeyMaterial { looked_at: Vec<&'static str> },
    EmbeddedKeyUntrusted { location: &'static str, thumbprint: String },
    EmbeddedKeyAcceptedByFlag { location: &'static str, thumbprint: String },
    EmbeddedKeyPinned { location: &'static str, thumbprint: String },
    DidKeyUndecodable { did: String, reason: String },
    DidKeyCodecUnsupported { did: String, codec: u64, codec_name: &'static str },
    JwkUnsupported { reason: String },

    // --- verify tier: signature ---
    SignatureInvalid { alg: String },
}

/// A single tier's outcome. The three-way split is what `Result<T, E>` cannot express:
/// "we never got here" is materially different from "we got here and it failed".
#[derive(Clone, Debug)]
pub enum Stage<T> {
    NotReached { blocked_by: Tier },
    Failed { findings: Vec<Finding> },
    Passed { output: T, findings: Vec<Finding> },
}

impl<T> Stage<T> {
    pub fn findings(&self) -> &[Finding] {
        match self {
            Stage::NotReached { .. } => &[],
            Stage::Failed { findings } | Stage::Passed { findings, .. } => findings,
        }
    }
    pub fn output(&self) -> Option<&T> {
        match self {
            Stage::Passed { output, .. } => Some(output),
            _ => None,
        }
    }
    pub fn is_passed(&self) -> bool {
        matches!(self, Stage::Passed { .. })
    }
    pub fn is_failed(&self) -> bool {
        matches!(self, Stage::Failed { .. })
    }
    pub fn status(&self) -> &'static str {
        match self {
            Stage::NotReached { .. } => "not_reached",
            Stage::Failed { .. } => "failed",
            Stage::Passed { .. } => "passed",
        }
    }
}

/// Something vcrd deliberately did not check, carried with the same prominence as
/// what passed (REQUIREMENTS §12 result-contract non-checks).
#[derive(Clone, Debug)]
pub struct NotEvaluated {
    pub what: NotEvaluatedKind,
    pub why: NotEvaluatedWhy,
}

#[derive(Clone, Copy, Debug)]
pub enum NotEvaluatedKind {
    RevocationStatus,
    ContextResolution,
    HolderBinding,
    ReplayBinding,
    IssuerAccreditation,
    SchemaConformance,
}

impl NotEvaluatedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            NotEvaluatedKind::RevocationStatus => "revocation_status",
            NotEvaluatedKind::ContextResolution => "context_resolution",
            NotEvaluatedKind::HolderBinding => "holder_binding",
            NotEvaluatedKind::ReplayBinding => "replay_binding",
            NotEvaluatedKind::IssuerAccreditation => "issuer_accreditation",
            NotEvaluatedKind::SchemaConformance => "schema_conformance",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum NotEvaluatedWhy {
    RequiresNetwork,
    NoParametersSupplied,
    NotImplementedInSpike,
    OutOfScope,
    TierNotReached,
}

impl NotEvaluatedWhy {
    pub fn as_str(self) -> &'static str {
        match self {
            NotEvaluatedWhy::RequiresNetwork => "requires_network",
            NotEvaluatedWhy::NoParametersSupplied => "no_parameters_supplied",
            NotEvaluatedWhy::NotImplementedInSpike => "not_implemented",
            NotEvaluatedWhy::OutOfScope => "out_of_scope",
            NotEvaluatedWhy::TierNotReached => "tier_not_reached",
        }
    }
}

#[derive(Clone, Debug)]
pub struct InputSummary {
    pub byte_len: usize,
    pub measured_depth: Option<usize>,
    pub detected_format: Option<FormatId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FormatId(pub &'static str);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuiteId(pub &'static str);

/// Format-neutral projection of a credential. Every frontend renders this; the
/// format-specific parts hang off `FormatDetail`.
#[derive(Clone, Debug)]
pub struct Document {
    pub issuer: Option<String>,
    /// FINDING (question 3): this was a plain `String` at first, and the CLI printed
    /// it in cleartext while hashing the identical value under
    /// `credentialSubject.id`. The newtype protects only what is routed through it,
    /// so anything derived from the credential subject has to be wrapped by default.
    pub subject: Option<ClaimValue>,
    pub id: Option<String>,
    pub types: Vec<String>,
    pub contexts: Vec<String>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    /// Leaf claims, flattened to dotted paths. Names are public, values are not (§8).
    pub claims: Vec<Claim>,
    pub proofs: Vec<ProofDescriptor>,
}

#[derive(Clone, Debug)]
pub struct Claim {
    pub path: String,
    pub value: ClaimValue,
}

#[derive(Clone, Debug)]
pub struct ProofDescriptor {
    pub suite: SuiteId,
    pub declared_alg: String,
    pub key_hints: crate::keys::KeyHints,
    /// The bytes the signature is over, and the signature itself. This is the
    /// `CredentialFormat` -> `ProofSuite` seam (prototype question 4).
    pub signing_input: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ParseOutput {
    pub format: FormatId,
    pub document: Document,
    pub detail: FormatDetail,
}

/// The format-specific extension point.
///
/// MEASURED (question 1): adding a second variant to a plain enum broke exactly two
/// irrefutable `let` bindings -- one in core, one in `vcrd-cli`. With
/// `#[non_exhaustive]`, the *downstream* break disappears, but every external
/// consumer is forced to write a `_ =>` arm on day one and decide what it renders.
/// Core's own matches break either way; `#[non_exhaustive]` has no effect inside the
/// defining crate.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum FormatDetail {
    JwtVc(JwtVcDetail),
}

#[derive(Clone, Debug)]
pub struct JwtVcDetail {
    pub typ: Option<String>,
    pub cty: Option<String>,
    pub kid: Option<String>,
    pub header_alg: String,
    /// Which VC-JWT profile the bytes look like.
    pub profile: JwtVcProfile,
    /// Registered JWT claims, kept separately from the data-model fields precisely
    /// because the 1.1 mapping lets the two disagree.
    pub registered: RegisteredClaims,
}

#[derive(Clone, Debug, Default)]
pub struct RegisteredClaims {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub jti: Option<String>,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JwtVcProfile {
    /// VCDM 2.0 / VC-JOSE-COSE: the JWT payload *is* the credential.
    VcJoseCose,
    /// VCDM 1.1 JWT mapping: credential under a `vc` claim, duplicated registered claims.
    Vcdm11Mapping,
    Unknown,
}

impl JwtVcProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            JwtVcProfile::VcJoseCose => "vc-jose-cose",
            JwtVcProfile::Vcdm11Mapping => "vcdm-1.1-jwt-mapping",
            JwtVcProfile::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ValidateOutput {
    pub profile: JwtVcProfile,
    pub temporal: TemporalStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemporalStatus {
    Current,
    Expired,
    NotYetValid,
    Unbounded,
}

impl TemporalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            TemporalStatus::Current => "current",
            TemporalStatus::Expired => "expired",
            TemporalStatus::NotYetValid => "not_yet_valid",
            TemporalStatus::Unbounded => "unbounded",
        }
    }
}

#[derive(Clone, Debug)]
pub struct VerifyOutput {
    pub proofs: Vec<ProofResult>,
}

#[derive(Clone, Debug)]
pub struct ProofResult {
    pub suite: SuiteId,
    pub declared_alg: String,
    pub outcome: ProofOutcome,
    /// Prototype question 6: does provenance need to be a distinct v1 field?
    pub key_provenance: crate::keys::KeyProvenance,
}

#[derive(Clone, Debug)]
pub enum ProofOutcome {
    /// `disclosed` exists so selective disclosure is not designed *out*. The spike
    /// makes no claim about whether it is sufficient.
    Verified { disclosed: Option<DisclosureSet> },
    Failed,
    NotAttempted,
}

impl ProofOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProofOutcome::Verified { .. } => "verified",
            ProofOutcome::Failed => "failed",
            ProofOutcome::NotAttempted => "not_attempted",
        }
    }
}

#[derive(Clone, Debug)]
pub struct DisclosureSet {
    pub disclosed_paths: Vec<String>,
    pub withheld_count: usize,
}

/// The whole answer. Returned by value; never wrapped in `Result`.
#[derive(Clone, Debug)]
pub struct Report {
    pub input: InputSummary,
    pub parse: Stage<ParseOutput>,
    pub validate: Stage<ValidateOutput>,
    pub verify: Stage<VerifyOutput>,
    pub not_evaluated: Vec<NotEvaluated>,
}

impl Report {
    /// Every finding across every tier, in tier order.
    pub fn all_findings(&self) -> Vec<&Finding> {
        let mut v: Vec<&Finding> = Vec::new();
        v.extend(self.parse.findings());
        v.extend(self.validate.findings());
        v.extend(self.verify.findings());
        v
    }
}
