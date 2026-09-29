//! Proof suites, one Cargo feature each (ARCHITECTURE §2).

use crate::registry::SuiteId;

/// The JWS suite's identifier. Always compiled: a format names the suite its proofs
/// need whether or not this build has it.
pub const JWS: SuiteId = SuiteId("jws");

#[cfg(feature = "jws")]
pub mod jws;
