//! The `CredentialFormat` / `ProofSuite` seam (prototype question 4).
//!
//! Both traits are used through `dyn` because `vcrd formats` / `vcrd suites` imply a
//! runtime registry. That is deliberate: object safety is forced by the design rather
//! than left as something to remember, and whatever it costs shows up immediately.

use crate::context::Context;
use crate::keys::{KeyProvenance, VerifyKey};
use crate::model::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Detection {
    No,
    /// Structurally plausible but not confirmed.
    Maybe,
    Yes,
}

pub trait CredentialFormat: std::fmt::Debug {
    fn id(&self) -> FormatId;
    fn description(&self) -> &'static str;
    fn suites(&self) -> Vec<SuiteId>;

    fn detect(&self, bytes: &[u8]) -> Detection;
    fn parse(&self, bytes: &[u8], ctx: &Context) -> Stage<ParseOutput>;
    fn validate(&self, parsed: &ParseOutput, ctx: &Context) -> Stage<ValidateOutput>;
}

/// What a format hands a suite. For VC-JWT this is a detached signing input plus a
/// signature -- so the format does *not* own verification, which is the thing the
/// spike set out to test.
#[derive(Clone, Debug)]
pub struct ProofInput<'a> {
    pub suite: SuiteId,
    pub declared_alg: &'a str,
    pub signing_input: &'a [u8],
    pub signature: &'a [u8],
    pub key: Option<&'a VerifyKey>,
    pub provenance: &'a KeyProvenance,
}

pub trait ProofSuite: std::fmt::Debug {
    fn id(&self) -> SuiteId;
    fn description(&self) -> &'static str;
    fn verify(&self, input: &ProofInput<'_>, ctx: &Context) -> (ProofOutcome, Vec<Finding>);
}

#[derive(Debug, Default)]
pub struct Registry {
    pub formats: Vec<Box<dyn CredentialFormat>>,
    pub suites: Vec<Box<dyn ProofSuite>>,
}

impl Registry {
    pub fn with_enabled_features() -> Self {
        let mut r = Registry::default();
        #[cfg(feature = "jwt-vc")]
        {
            r.formats.push(Box::new(crate::jwt_vc::JwtVcFormat));
            r.suites.push(Box::new(crate::jose_suite::JoseSuite));
        }
        r
    }

    pub fn detect(&self, bytes: &[u8]) -> Option<&dyn CredentialFormat> {
        let mut best: Option<(Detection, &dyn CredentialFormat)> = None;
        for f in &self.formats {
            let d = f.detect(bytes);
            if d == Detection::No {
                continue;
            }
            if best.as_ref().map(|(bd, _)| d > *bd).unwrap_or(true) {
                best = Some((d, f.as_ref()));
            }
        }
        best.map(|(_, f)| f)
    }

    pub fn suite(&self, id: SuiteId) -> Option<&dyn ProofSuite> {
        self.suites.iter().find(|s| s.id() == id).map(|s| s.as_ref())
    }

    pub fn format_ids(&self) -> Vec<&'static str> {
        self.formats.iter().map(|f| f.id().0).collect()
    }
}
