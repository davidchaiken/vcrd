//! Everything injected into an operation (REQUIREMENTS §6; ARCHITECTURE §3).

use std::time::Duration;

use time::OffsetDateTime;

use crate::redact::Designations;

/// The current time. Core has no default clock (REQUIREMENTS §6).
pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}

/// A clock that always reads the same time: `--now`, and tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedClock(pub OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

/// The system clock. Behind the `std-clock` feature, which `vcrd-core` does not
/// enable by default (ARCHITECTURE §2).
#[cfg(feature = "std-clock")]
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

#[cfg(feature = "std-clock")]
impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Structural limits on untrusted input, each applied before the work it bounds
/// (REQUIREMENTS §6; ARCHITECTURE §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Size of the encoded input, in bytes.
    pub max_bytes: usize,
    /// Nesting depth of each decoded JSON document.
    pub max_depth: usize,
    /// Number of claim leaves.
    pub max_claims: usize,
    /// Levels of credentials inside credentials.
    pub max_containment_depth: usize,
    /// Credentials inside one credential or presentation.
    pub max_contained: usize,
}

impl Default for Limits {
    /// Provisional: the prototype's values, until defaults are measured on a real
    /// corpus (ARCHITECTURE §10 [T6]).
    fn default() -> Self {
        Limits {
            max_bytes: 256 * 1024,
            max_depth: 32,
            max_claims: 512,
            max_containment_depth: 1,
            max_contained: 64,
        }
    }
}

/// The caller's opt-ins to ARCHITECTURE §8's rules of keys and proofs. Neither is on by
/// default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyPolicy {
    /// The embedded key may decide when there is neither a caller-supplied key nor an
    /// issuer key (rule 2).
    pub allow_embedded_key_alone: bool,
    /// A caller-supplied key unlike the issuer key decides in its place (rule 1).
    pub allow_caller_key_override: bool,
}

/// Everything an operation consults that is not its input.
pub struct Context {
    clock: Box<dyn Clock>,
    clock_skew: Duration,
    limits: Limits,
    designations: Designations,
    key_policy: KeyPolicy,
}

impl Context {
    /// The clock is positional because it has no default.
    pub fn builder(clock: impl Clock + 'static) -> ContextBuilder {
        ContextBuilder {
            context: Context {
                clock: Box::new(clock),
                clock_skew: Duration::ZERO,
                limits: Limits::default(),
                designations: Designations::default(),
                key_policy: KeyPolicy::default(),
            },
        }
    }

    pub fn now(&self) -> OffsetDateTime {
        self.clock.now()
    }

    /// Tolerance applied to validity periods; zero by default (REQUIREMENTS §16
    /// item 17).
    pub fn clock_skew(&self) -> Duration {
        self.clock_skew
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn designations(&self) -> &Designations {
        &self.designations
    }

    pub fn key_policy(&self) -> KeyPolicy {
        self.key_policy
    }
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("now", &self.clock.now())
            .field("clock_skew", &self.clock_skew)
            .field("limits", &self.limits)
            .field("designations", &self.designations)
            .field("key_policy", &self.key_policy)
            .finish()
    }
}

pub struct ContextBuilder {
    context: Context,
}

impl ContextBuilder {
    pub fn clock_skew(mut self, skew: Duration) -> Self {
        self.context.clock_skew = skew;
        self
    }

    pub fn limits(mut self, limits: Limits) -> Self {
        self.context.limits = limits;
        self
    }

    pub fn designations(mut self, designations: Designations) -> Self {
        self.context.designations = designations;
        self
    }

    pub fn key_policy(mut self, key_policy: KeyPolicy) -> Self {
        self.context.key_policy = key_policy;
        self
    }

    pub fn build(self) -> Context {
        self.context
    }
}
