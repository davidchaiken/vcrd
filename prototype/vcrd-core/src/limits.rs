//! Structural resource limits (REQUIREMENTS §6), and the measurement that is supposed
//! to produce their defaults.

use serde_json::Value;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_claims: usize,
}

impl Default for Limits {
    /// Provisional. `vcrd measure` prints what the fixtures actually need, and the
    /// findings record whether these numbers survived contact with them.
    fn default() -> Self {
        Limits { max_bytes: 256 * 1024, max_depth: 32, max_claims: 512 }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum DepthError {
    TooDeep { limit: usize, found: usize },
}

/// Byte-level prescan: count structural nesting without building a `Value` first.
///
/// This exists because `serde_json` has a *fixed* recursion limit (128) that is not
/// configurable through its public API without the `unbounded_depth` feature, which
/// only turns it off. A caller-configurable cap therefore needs its own mechanism.
/// String-awareness matters: braces inside string literals are not structure.
#[inline(never)]
pub fn measure_depth(bytes: &[u8], limit: usize) -> Result<usize, DepthError> {
    let mut depth: usize = 0;
    let mut max: usize = 0;
    let mut in_string = false;
    let mut escaped = false;

    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    max = depth;
                }
                if depth > limit {
                    return Err(DepthError::TooDeep { limit, found: depth });
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(max)
}

/// Depth of an already-built `Value`, used only for measurement reporting.
pub fn value_depth(v: &Value) -> usize {
    match v {
        Value::Object(map) => 1 + map.values().map(value_depth).max().unwrap_or(0),
        Value::Array(items) => 1 + items.iter().map(value_depth).max().unwrap_or(0),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prescan_ignores_braces_inside_strings() {
        let d = measure_depth(br#"{"a":"{{{{{{{{"}"#, 32);
        assert!(matches!(d, Ok(1)), "got {d:?}");
    }

    #[test]
    fn prescan_rejects_beyond_limit() {
        let deep = "[".repeat(40);
        assert!(measure_depth(deep.as_bytes(), 32).is_err());
    }

    /// Records the actual serde_json behaviour the findings cite.
    #[test]
    fn serde_json_has_its_own_fixed_recursion_limit() {
        let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
        let r: Result<Value, _> = serde_json::from_str(&deep);
        assert!(r.is_err(), "serde_json accepted 200 levels of nesting");
        let shallow = format!("{}{}", "[".repeat(100), "]".repeat(100));
        let r2: Result<Value, _> = serde_json::from_str(&shallow);
        assert!(r2.is_ok(), "serde_json rejected 100 levels of nesting");
    }
}
