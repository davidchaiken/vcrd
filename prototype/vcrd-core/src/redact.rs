//! Redaction as a type property, not a discipline (prototype question 3).
//!
//! `ClaimValue` deliberately implements neither `Serialize` nor a revealing `Display`.
//! Getting plaintext back out requires a `CleartextGrant`, which has exactly one
//! constructor with a name a reviewer will notice. The intent is that a frontend
//! *cannot* leak a claim value by forgetting to redact; it can only leak by asking.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;

/// Capability token for reading claim plaintext. One constructor, deliberately loud.
#[derive(Clone, Copy, Debug)]
pub struct CleartextGrant(());

impl CleartextGrant {
    /// The only way to obtain a grant. `vcrd-cli` calls this exactly once, behind
    /// `--unsafe`, and marks the output.
    pub fn i_understand_this_reveals_plaintext() -> Self {
        CleartextGrant(())
    }
}

/// A claim value that is redacted unless explicitly revealed.
#[derive(Clone, PartialEq)]
pub struct ClaimValue(Value);

impl ClaimValue {
    pub fn new(v: Value) -> Self {
        ClaimValue(v)
    }

    /// Plaintext access. Requires a grant; there is no other accessor.
    pub fn reveal(&self, _grant: &CleartextGrant) -> &Value {
        &self.0
    }

    /// The JSON type name. Not sensitive; needed for rendering and for the
    /// low-entropy heuristic.
    pub fn type_tag(&self) -> &'static str {
        type_tag(&self.0)
    }

    /// How this value should appear in output, given its claim path.
    pub fn redact(&self, path: &str) -> Redacted {
        let c = classify(path, &self.0);
        match c.entropy {
            Entropy::Low => Redacted::Masked { type_tag: self.type_tag(), rule: c.rule },
            Entropy::High => Redacted::Hashed { short: short_hash(&self.0), rule: c.rule },
        }
    }
}

/// `Debug` must not leak either -- derived `Debug` on any containing struct would
/// otherwise be a bypass.
impl fmt::Debug for ClaimValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClaimValue(<{}>)", self.type_tag())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entropy {
    /// An unsalted hash would not protect this; mask it instead (§8).
    Low,
    High,
}

/// Which candidate rule decided. Reported by `--explain-redaction` so the heuristic
/// can be judged against real fixtures instead of argued about in the abstract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// Booleans, nulls, and small integers cannot be protected by a hash.
    JsonType,
    /// The claim name is known to be low-cardinality regardless of its value.
    KnownLowCardinalityName,
    /// Short strings have too few plausible values to survive a hash.
    ShortString,
    /// A date or date-time. Added *after* the first fixture run showed a birthDate
    /// being hashed: a hash over ~40k plausible dates is a lookup table, not
    /// protection. The first three rules all missed it.
    DateLike,
    /// Nothing fired; treat as high-entropy and hash.
    Default,
}

impl Rule {
    pub fn as_str(self) -> &'static str {
        match self {
            Rule::JsonType => "json_type",
            Rule::KnownLowCardinalityName => "known_low_cardinality_name",
            Rule::ShortString => "short_string",
            Rule::DateLike => "date_like",
            Rule::Default => "default",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Classification {
    pub entropy: Entropy,
    pub rule: Rule,
}

#[derive(Clone, Debug)]
pub enum Redacted {
    Masked { type_tag: &'static str, rule: Rule },
    Hashed { short: String, rule: Rule },
}

impl fmt::Display for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Redacted::Masked { type_tag, .. } => write!(f, "<{type_tag}>"),
            Redacted::Hashed { short, .. } => write!(f, "#{short}"),
        }
    }
}

/// Claim names whose value space is small enough that a hash is a lookup table.
/// There is no schema to consult, so this list is the honest admission of that.
const LOW_CARDINALITY_NAMES: &[&str] = &[
    "type",
    "status",
    "gender",
    "sex",
    "nationality",
    "country",
    "countrycode",
    "issuingcountry",
    "age_over_18",
    "age_over_21",
    "over18",
    "isactive",
    "active",
    "degreetype",
    "licenseclass",
    "vehiclecategory",
    "birthyear",
    "yearofbirth",
];

/// Breakpoint anchor for prototype question 3.
#[inline(never)]
pub fn classify(path: &str, value: &Value) -> Classification {
    // Rule 1: the JSON type alone can rule out any hash-based protection.
    match value {
        Value::Bool(_) | Value::Null => {
            return Classification { entropy: Entropy::Low, rule: Rule::JsonType };
        }
        Value::Number(n) => {
            // Small integers live in a space a caller can brute-force instantly.
            if let Some(i) = n.as_i64()
                && i.abs() < 10_000 {
                    return Classification { entropy: Entropy::Low, rule: Rule::JsonType };
                }
        }
        _ => {}
    }

    // Rule 2: a known low-cardinality claim name, regardless of the value.
    let leaf = path.rsplit('.').next().unwrap_or(path).to_ascii_lowercase();
    let leaf_norm: String = leaf.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
    if LOW_CARDINALITY_NAMES.contains(&leaf_norm.as_str()) {
        return Classification { entropy: Entropy::Low, rule: Rule::KnownLowCardinalityName };
    }

    // Rule 3: a short string ("M", "US", "A+", "1985") has too little entropy.
    if let Value::String(s) = value {
        if s.chars().count() <= 4 {
            return Classification { entropy: Entropy::Low, rule: Rule::ShortString };
        }
        // Rule 4: dates. Long enough to look high-entropy, small enough to enumerate.
        if looks_like_date(s) {
            return Classification { entropy: Entropy::Low, rule: Rule::DateLike };
        }
    }

    Classification { entropy: Entropy::High, rule: Rule::Default }
}

/// `YYYY-MM-DD`, optionally with a time component. Cheap and deliberately narrow.
fn looks_like_date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 10 {
        return false;
    }
    let digits_at = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
    let dash_at = |i: usize| b.get(i) == Some(&b'-');
    (0..4).all(digits_at) && dash_at(4) && (5..7).all(digits_at) && dash_at(7) && (8..10).all(digits_at)
}

fn type_tag(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Deterministic, truncated, and stable across runs, so a caller can tell whether
/// two credentials carry the same value without seeing it (§8).
fn short_hash(v: &Value) -> String {
    let canonical = canonical_bytes(v);
    let digest = Sha256::digest(&canonical);
    digest.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// Minimal canonicalization: enough for a stable hash across equal values.
fn canonical_bytes(v: &Value) -> Vec<u8> {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = b"{".to_vec();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(format!("{k:?}:").as_bytes());
                if let Some(child) = map.get(*k) {
                    out.extend_from_slice(&canonical_bytes(child));
                }
            }
            out.push(b'}');
            out
        }
        Value::Array(items) => {
            let mut out = b"[".to_vec();
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(&canonical_bytes(item));
            }
            out.push(b']');
            out
        }
        other => other.to_string().into_bytes(),
    }
}

/// Flatten a JSON object into dotted leaf paths, so claim *names* stay visible
/// while every leaf *value* is wrapped.
pub fn flatten_claims(prefix: &str, value: &Value, out: &mut Vec<crate::model::Claim>, limit: usize) {
    if out.len() >= limit {
        return;
    }
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                flatten_claims(&path, v, out, limit);
            }
        }
        Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                let path = format!("{prefix}[{i}]");
                flatten_claims(&path, v, out, limit);
            }
        }
        leaf => {
            out.push(crate::model::Claim {
                path: prefix.to_string(),
                value: ClaimValue::new(leaf.clone()),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn debug_never_leaks() {
        let v = ClaimValue::new(json!("Alexandra Chaiken-Testcase"));
        let dbg = format!("{v:?}");
        assert!(!dbg.contains("Alexandra"), "Debug leaked plaintext: {dbg}");
    }

    #[test]
    fn bools_are_masked_not_hashed() {
        let c = classify("credentialSubject.over18", &json!(true));
        assert_eq!(c.entropy, Entropy::Low);
        assert_eq!(c.rule, Rule::JsonType);
    }

    #[test]
    fn long_strings_are_hashed_and_stable() {
        let a = ClaimValue::new(json!("Sam Rivera-Testcase"));
        let b = ClaimValue::new(json!("Sam Rivera-Testcase"));
        let ra = a.redact("credentialSubject.name").to_string();
        let rb = b.redact("credentialSubject.name").to_string();
        assert_eq!(ra, rb);
        assert!(ra.starts_with('#'));
    }

    #[test]
    fn dates_are_masked_not_hashed() {
        // The rule the first fixture run proved was missing.
        assert_eq!(classify("credentialSubject.birthDate", &json!("1985-03-14")).rule, Rule::DateLike);
        assert_eq!(classify("credentialSubject.issued", &json!("2024-01-01T00:00:00Z")).rule, Rule::DateLike);
        assert_eq!(classify("credentialSubject.note", &json!("not a date at all")).rule, Rule::Default);
    }

    #[test]
    fn known_low_cardinality_name_wins_over_length() {
        let c = classify("credentialSubject.nationality", &json!("Netherlands"));
        assert_eq!(c.rule, Rule::KnownLowCardinalityName);
    }
}
