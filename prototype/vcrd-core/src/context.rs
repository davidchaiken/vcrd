//! Everything `vcrd-core` refuses to reach for on its own (§6), gathered in one place.
//!
//! Counting what has to be injected: clock, algorithm policy, key store, structural
//! limits, clock skew, embedded-key opt-in, expected challenge, expected domain.
//! That is eight, and the ergonomics of eight is itself one of the questions.

use crate::jws::AlgPolicy;
use crate::keys::{EmptyKeyStore, KeyStore};
use crate::limits::Limits;
use time::OffsetDateTime;

/// No default implementation ships in core by default: a frontend must supply one.
pub trait Clock: std::fmt::Debug {
    fn now(&self) -> OffsetDateTime;
}

#[derive(Clone, Copy, Debug)]
pub struct FixedClock(pub OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

/// Behind a feature flag on purpose, so "core never calls `SystemTime::now()`" is a
/// property of the default build rather than a convention.
#[cfg(feature = "std-clock")]
#[derive(Clone, Copy, Debug)]
pub struct SystemClock;

#[cfg(feature = "std-clock")]
impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedactionPolicy {
    Redact,
    /// Only reachable through `--unsafe`, and the result says so.
    Cleartext,
}

#[derive(Debug)]
pub struct Context {
    pub clock: Box<dyn Clock>,
    pub alg_policy: AlgPolicy,
    pub keys: Box<dyn KeyStore>,
    pub limits: Limits,
    /// §16 item 17. Default zero; the fixtures get to argue for something else.
    pub skew_seconds: i64,
    pub trust_embedded_key: bool,
    pub expected_challenge: Option<String>,
    pub expected_domain: Option<String>,
    pub redaction: RedactionPolicy,
}

impl Context {
    pub fn builder(clock: Box<dyn Clock>) -> ContextBuilder {
        ContextBuilder {
            ctx: Context {
                clock,
                alg_policy: AlgPolicy::allow_all(),
                keys: Box::new(EmptyKeyStore),
                limits: Limits::default(),
                skew_seconds: 0,
                trust_embedded_key: false,
                expected_challenge: None,
                expected_domain: None,
                redaction: RedactionPolicy::Redact,
            },
        }
    }
}

pub struct ContextBuilder {
    ctx: Context,
}

impl ContextBuilder {
    pub fn alg_policy(mut self, p: AlgPolicy) -> Self {
        self.ctx.alg_policy = p;
        self
    }
    pub fn keys(mut self, k: Box<dyn KeyStore>) -> Self {
        self.ctx.keys = k;
        self
    }
    pub fn limits(mut self, l: Limits) -> Self {
        self.ctx.limits = l;
        self
    }
    pub fn skew_seconds(mut self, s: i64) -> Self {
        self.ctx.skew_seconds = s;
        self
    }
    pub fn trust_embedded_key(mut self, t: bool) -> Self {
        self.ctx.trust_embedded_key = t;
        self
    }
    pub fn expected_challenge(mut self, c: Option<String>) -> Self {
        self.ctx.expected_challenge = c;
        self
    }
    pub fn expected_domain(mut self, d: Option<String>) -> Self {
        self.ctx.expected_domain = d;
        self
    }
    pub fn redaction(mut self, r: RedactionPolicy) -> Self {
        self.ctx.redaction = r;
        self
    }
    pub fn build(self) -> Context {
        self.ctx
    }
}
