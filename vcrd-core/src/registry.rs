//! The extension points: formats and proof suites (ARCHITECTURE §5).

use crate::context::Context;
use crate::finding::Finding;
use crate::keys::PublicKey;
use crate::report::{InspectOutput, ParseOutput, PhaseOutcome, ProofOutcome};

/// A format's stable identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FormatId(pub &'static str);

/// A proof suite's stable identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuiteId(pub &'static str);

/// A profile of a format, such as the data-model version a JWT-secured credential
/// follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfileId(pub &'static str);

/// How confident a format is that an input is its own. The most confident format
/// wins (ARCHITECTURE §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Detection {
    No,
    Maybe,
    Yes,
}

/// A credential format. Detects its input, parses it, and inspects it; never resolves
/// keys or decides trust (ARCHITECTURE §5).
pub trait CredentialFormat {
    fn id(&self) -> FormatId;
    fn detect(&self, bytes: &[u8]) -> Detection;
    fn parse(&self, bytes: &[u8], ctx: &Context) -> PhaseOutcome<ParseOutput>;
    fn inspect(&self, parsed: &ParseOutput, ctx: &Context) -> PhaseOutcome<InspectOutput>;
}

/// A proof suite. Checks the declared algorithm, binds it to the key type, and calls
/// the primitives; never sees where the key came from (ARCHITECTURE §5).
pub trait ProofSuite {
    fn id(&self) -> SuiteId;
    /// The algorithms this suite implements, named in an unsupported-algorithm
    /// finding (REQUIREMENTS §10).
    fn algorithms(&self) -> &'static [&'static str];
    fn verify(&self, input: &ProofInput<'_>, ctx: &Context) -> (ProofOutcome, Vec<Finding>);
}

/// What a suite verifies. Not `#[non_exhaustive]` (ARCHITECTURE §5).
#[derive(Debug)]
pub enum ProofInput<'a> {
    Jws {
        algorithm: Option<&'a str>,
        signing_input: &'a [u8],
        signature: &'a [u8],
        /// `None` when resolution found no usable key; the suite still checks the
        /// algorithm, so that its findings are reported too.
        key: Option<&'a PublicKey>,
    },
}

/// The formats and suites available to an operation.
pub struct Registry {
    formats: Vec<Box<dyn CredentialFormat>>,
    suites: Vec<Box<dyn ProofSuite>>,
}

impl Registry {
    /// No formats and no suites.
    pub fn empty() -> Self {
        Registry {
            formats: Vec::new(),
            suites: Vec::new(),
        }
    }

    /// The formats and suites this build of vcrd-core has.
    pub fn builtin() -> Self {
        Registry {
            formats: vec![
                #[cfg(feature = "vc-jose")]
                Box::new(crate::formats::vc_jose::VcJose),
            ],
            suites: vec![
                #[cfg(feature = "jws")]
                Box::new(crate::suites::jws::Jws),
            ],
        }
    }

    pub fn register_format(&mut self, format: Box<dyn CredentialFormat>) {
        self.formats.push(format);
    }

    pub fn register_suite(&mut self, suite: Box<dyn ProofSuite>) {
        self.suites.push(suite);
    }

    pub fn formats(&self) -> impl Iterator<Item = &dyn CredentialFormat> {
        self.formats.iter().map(|f| f.as_ref())
    }

    pub fn suites(&self) -> impl Iterator<Item = &dyn ProofSuite> {
        self.suites.iter().map(|s| s.as_ref())
    }

    pub fn suite(&self, id: SuiteId) -> Option<&dyn ProofSuite> {
        self.suites().find(|s| s.id() == id)
    }
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field(
                "formats",
                &self.formats().map(|x| x.id()).collect::<Vec<_>>(),
            )
            .field("suites", &self.suites().map(|x| x.id()).collect::<Vec<_>>())
            .finish()
    }
}
