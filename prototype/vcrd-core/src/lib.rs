//! vcrd-core -- THROWAWAY SPIKE.
//!
//! This crate exists to answer the design questions in `prototype-goals.md`, not to
//! be a foundation. It is deliberately narrow: one credential format (VC-JOSE-COSE),
//! one proof suite (JOSE/JWS), five algorithms, no network, no JSON-LD.
//!
//! Read `PROTOTYPE-FINDINGS.md` for the answers. Read this only for the evidence.

#![forbid(unsafe_code)]

pub mod context;
pub mod format;
pub mod jws;
pub mod keys;
pub mod limits;
pub mod model;
pub mod pipeline;
pub mod redact;
pub mod validate;

#[cfg(feature = "jwt-vc")]
pub mod jose_suite;
#[cfg(feature = "jwt-vc")]
pub mod jwt_vc;

#[cfg(feature = "josekit-probe")]
pub mod josekit_probe;

pub use context::{Clock, Context, ContextBuilder, FixedClock, RedactionPolicy};
pub use format::{CredentialFormat, ProofSuite, Registry};
pub use model::*;
pub use pipeline::{inspect, verify};

/// Deliberately not a `Default`: a caller has to state what "now" is.
pub fn registry() -> Registry {
    Registry::with_enabled_features()
}
