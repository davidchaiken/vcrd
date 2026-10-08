//! JSON as vcrd holds it (ARCHITECTURE §3).
//!
//! `serde_json::Value` is not used for anything kept: its objects cannot be read in
//! a debugger, it keeps only one of a set of duplicate member names, and its scalars
//! print in cleartext. [`Json`] keeps every member in order, duplicates included,
//! and wraps every scalar in a [`ClaimValue`].

use std::fmt;

use serde::Deserialize;
use serde::de::{self, MapAccess, SeqAccess, Visitor};

use crate::redact::ClaimValue;

/// A parsed JSON value.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Scalar(ClaimValue),
    Array(Vec<Json>),
    /// Every member, in input order, duplicates included.
    Object(Vec<Member>),
}

/// One member of a JSON object.
#[derive(Clone, Debug, PartialEq)]
pub struct Member {
    pub name: String,
    pub value: Json,
}

impl Json {
    /// Parses one JSON document. `serde_json`'s nesting limit of 128 applies.
    pub fn parse(bytes: &[u8]) -> Result<Json, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// The value of the last member with this name, which is the one RFC 7515 §4 and
    /// RFC 7519 §4 permit a parser to return when names repeat.
    pub fn get(&self, name: &str) -> Option<&Json> {
        match self {
            Json::Object(members) => members
                .iter()
                .rev()
                .find(|m| m.name == name)
                .map(|m| &m.value),
            Json::Scalar(_) | Json::Array(_) => None,
        }
    }

    pub fn members(&self) -> Option<&[Member]> {
        match self {
            Json::Object(members) => Some(members),
            Json::Scalar(_) | Json::Array(_) => None,
        }
    }

    /// A string scalar's plaintext, for checks inside core. Not public
    /// (ARCHITECTURE §7). Only formats call it, and a core built with none has none.
    #[cfg_attr(not(feature = "vc-jose"), allow(dead_code))]
    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Json::Scalar(value) => value.as_str(),
            Json::Array(_) | Json::Object(_) => None,
        }
    }

    /// A number scalar's JSON text and value, for checks inside core. Not public,
    /// for the reason given on [`Json::as_str`].
    #[cfg_attr(not(feature = "vc-jose"), allow(dead_code))]
    pub(crate) fn as_number(&self) -> Option<(String, f64)> {
        match self {
            Json::Scalar(value) => value.as_number(),
            Json::Array(_) | Json::Object(_) => None,
        }
    }

    /// Every member name that repeats within one object, with its path and how many
    /// times it appears, in the order the names first appear.
    pub fn duplicate_names(&self) -> Vec<DuplicateName> {
        let mut found = Vec::new();
        self.collect_duplicates(&mut Vec::new(), &mut found);
        found
    }

    fn collect_duplicates<'a>(&'a self, path: &mut Vec<Step<'a>>, found: &mut Vec<DuplicateName>) {
        match self {
            Json::Scalar(_) => {}
            Json::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    path.push(Step::Index(index));
                    item.collect_duplicates(path, found);
                    path.pop();
                }
            }
            Json::Object(members) => {
                let mut counted: Vec<(&str, usize)> = Vec::new();
                for member in members {
                    match counted.iter_mut().find(|(name, _)| *name == member.name) {
                        Some((_, count)) => *count = count.saturating_add(1),
                        None => counted.push((&member.name, 1)),
                    }
                }
                for (name, count) in counted.into_iter().filter(|(_, count)| *count > 1) {
                    path.push(Step::Name(name));
                    found.push(DuplicateName {
                        path: path_string(path),
                        count,
                    });
                    path.pop();
                }
                for member in members {
                    path.push(Step::Name(&member.name));
                    member.value.collect_duplicates(path, found);
                    path.pop();
                }
            }
        }
    }
}

/// A member name that appears more than once in one object. RFC 7515 §4 and RFC
/// 7519 §4 require names to be unique, and permit a parser that keeps the last.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateName {
    /// The path to the member, in the notation of [`path_string`].
    pub path: String,
    pub count: usize,
}

/// One step of a path from a document's root.
pub(crate) enum Step<'a> {
    Name(&'a str),
    Index(usize),
}

/// `credentialSubject.degree.name`, `type[1]`. A name that is not a plain identifier
/// is quoted as a JSON string: `a["b.c"]`.
pub(crate) fn path_string(path: &[Step<'_>]) -> String {
    let mut out = String::new();
    for step in path {
        match step {
            Step::Index(index) => out.push_str(&format!("[{index}]")),
            Step::Name(name) if is_plain(name) => {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(name);
            }
            Step::Name(name) => {
                out.push('[');
                push_json_string(&mut out, name);
                out.push(']');
            }
        }
    }
    out
}

fn is_plain(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '@' | '$'))
}

fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The deepest nesting of arrays and objects in JSON text: 0 for a scalar, 1 for
/// `{}` or `[]`. A byte scan that skips strings, so that a depth limit can be applied
/// before any parser runs (ARCHITECTURE §4). Linear in the input and allocates
/// nothing; on text that is not JSON it returns some number and never fails.
pub fn nesting_depth(bytes: &[u8]) -> usize {
    let (mut depth, mut deepest) = (0usize, 0usize);
    let (mut in_string, mut escaped) = (false, false);
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
            b'[' | b'{' => {
                depth = depth.saturating_add(1);
                deepest = deepest.max(depth);
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    deepest
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JsonVisitor)
    }
}

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Json;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Json, E> {
        Ok(Json::Scalar(ClaimValue::null()))
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Json, E> {
        Ok(Json::Scalar(ClaimValue::bool(v)))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Json, E> {
        Ok(Json::Scalar(ClaimValue::number(v.into())))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Json, E> {
        Ok(Json::Scalar(ClaimValue::number(v.into())))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Json, E> {
        // JSON text cannot express NaN or an infinity, so this does not fail on a
        // successful parse.
        serde_json::Number::from_f64(v)
            .map(|n| Json::Scalar(ClaimValue::number(n)))
            .ok_or_else(|| E::custom("number is not finite"))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Json, E> {
        Ok(Json::Scalar(ClaimValue::string(v.to_owned())))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Json, E> {
        Ok(Json::Scalar(ClaimValue::string(v)))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Json::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
        let mut members = Vec::new();
        while let Some((name, value)) = map.next_entry::<String, Json>()? {
            members.push(Member { name, value });
        }
        Ok(Json::Object(members))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::ValueKind;

    #[test]
    fn keeps_duplicate_members_and_returns_the_last() {
        let json = Json::parse(br#"{"a": "first", "b": 1, "a": "second"}"#).unwrap();
        let names: Vec<&str> = json
            .members()
            .unwrap()
            .iter()
            .map(|m| m.name.as_str())
            .collect();
        assert_eq!(names, ["a", "b", "a"]);
        assert_eq!(json.get("a").unwrap().as_str(), Some("second"));
    }

    #[test]
    fn scalars_are_wrapped_and_debug_shows_only_their_kind() {
        let json = Json::parse(br#"["secret", 3, 2.5, true, null]"#).unwrap();
        let debug = format!("{json:?}");
        assert!(!debug.contains("secret"), "{debug}");
        let Json::Array(items) = json else {
            panic!("not an array")
        };
        let kinds: Vec<ValueKind> = items
            .iter()
            .map(|item| match item {
                Json::Scalar(v) => v.kind(),
                _ => panic!("not a scalar"),
            })
            .collect();
        assert_eq!(
            kinds,
            [
                ValueKind::String,
                ValueKind::Number,
                ValueKind::Number,
                ValueKind::Bool,
                ValueKind::Null
            ]
        );
    }

    #[test]
    fn rejects_trailing_characters() {
        assert!(Json::parse(br#"{"a": 1} x"#).is_err());
    }

    #[test]
    fn lists_each_repeated_name_once_with_its_path_and_count() {
        let json = Json::parse(
            br#"{"a": 1, "b": {"c": 1, "c": 2, "c": 3}, "a": 2, "d": [{"e": 1, "e": 2}]}"#,
        )
        .unwrap();
        let found = json.duplicate_names();
        let want = [("a", 2), ("b.c", 3), ("d[0].e", 2)];
        let found: Vec<(&str, usize)> = found.iter().map(|d| (d.path.as_str(), d.count)).collect();
        assert_eq!(found, want);
    }

    #[test]
    fn nesting_depth_skips_strings_and_escapes() {
        assert_eq!(nesting_depth(b"3"), 0);
        assert_eq!(nesting_depth(b"{}"), 1);
        // object, array, object, array
        assert_eq!(nesting_depth(br#"{"a": [[1], {"b": []}]}"#), 4);
        assert_eq!(nesting_depth(br#"["[[[", "\"[{", "\\"]"#), 1);
        // Not JSON: some answer, no panic.
        assert_eq!(nesting_depth(b"]]]{"), 1);
    }

    /// Depth as the parsed structure has it.
    fn depth(value: &serde_json::Value) -> usize {
        match value {
            serde_json::Value::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
            serde_json::Value::Object(members) => {
                1 + members.values().map(depth).max().unwrap_or(0)
            }
            _ => 0,
        }
    }

    fn json_value() -> impl proptest::strategy::Strategy<Value = serde_json::Value> {
        use proptest::prelude::*;
        // Strings of any characters, so that quotes, backslashes and brackets inside
        // strings are exercised.
        let leaf = prop_oneof![
            Just(serde_json::Value::Null),
            any::<bool>().prop_map(serde_json::Value::Bool),
            any::<i64>().prop_map(serde_json::Value::from),
            any::<String>().prop_map(serde_json::Value::String),
        ];
        leaf.prop_recursive(12, 128, 4, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..4).prop_map(serde_json::Value::Array),
                proptest::collection::vec((any::<String>(), inner), 0..4)
                    .prop_map(|members| serde_json::Value::Object(members.into_iter().collect())),
            ]
        })
    }

    /// Depth as vcrd's own tree has it, duplicate members included: the text nests as
    /// deep as its deepest member, even one a parser that keeps the last would drop.
    fn tree_depth(json: &Json) -> usize {
        match json {
            Json::Scalar(_) => 0,
            Json::Array(items) => 1 + items.iter().map(tree_depth).max().unwrap_or(0),
            Json::Object(members) => {
                1 + members
                    .iter()
                    .map(|m| tree_depth(&m.value))
                    .max()
                    .unwrap_or(0)
            }
        }
    }

    /// One character of a JSON string's contents, spelled any way JSON allows: as
    /// itself, as a short escape, or as `\uXXXX` (a surrogate pair beyond the Basic
    /// Multilingual Plane) in either case of hex digit. The characters the scan
    /// cares about, the quote, the backslash and the brackets, come up often.
    fn string_char() -> impl proptest::strategy::Strategy<Value = String> {
        use proptest::prelude::*;
        let character = prop_oneof![
            3 => prop::sample::select(vec!['"', '\\', '[', ']', '{', '}', '/', ',', ':']),
            1 => any::<char>(),
        ];
        (character, 0..4u8, any::<bool>()).prop_map(|(c, spelling, lower)| match (c, spelling) {
            ('"', 0) => "\\\"".to_owned(),
            ('\\', 0) => "\\\\".to_owned(),
            ('/', 1) => "\\/".to_owned(),
            (c, 2) => {
                let mut units = [0u16; 2];
                c.encode_utf16(&mut units)
                    .iter()
                    .map(|u| {
                        if lower {
                            format!("\\u{u:04x}")
                        } else {
                            format!("\\u{u:04X}")
                        }
                    })
                    .collect()
            }
            // As itself, when JSON allows that.
            (c, _) if c != '"' && c != '\\' && !c.is_control() => c.to_string(),
            (c, _) => {
                let mut units = [0u16; 2];
                c.encode_utf16(&mut units)
                    .iter()
                    .map(|u| format!("\\u{u:04x}"))
                    .collect()
            }
        })
    }

    /// JSON text written directly rather than by `serde_json`, so that it includes
    /// spellings `serde_json` never produces: whitespace of every kind between tokens,
    /// escaped characters of every kind, fractions and exponents, and repeated member
    /// names.
    fn json_text() -> impl proptest::strategy::Strategy<Value = String> {
        use proptest::prelude::*;
        let space = || {
            prop::collection::vec(prop::sample::select(vec![" ", "\t", "\n", "\r"]), 0..3)
                .prop_map(|s| s.concat())
        };
        let string = || {
            prop::collection::vec(string_char(), 0..6).prop_map(|s| format!("\"{}\"", s.concat()))
        };
        let number = prop_oneof![
            any::<i64>().prop_map(|n| n.to_string()),
            (
                any::<i32>(),
                0..1000u32,
                prop::sample::select(vec!["e", "E", "e+", "E-"]),
                0..20u32
            )
                .prop_map(|(i, f, e, x)| format!("{i}.{f}{e}{x}")),
        ];
        let leaf = prop_oneof![
            Just("null".to_owned()),
            Just("true".to_owned()),
            Just("false".to_owned()),
            number,
            string(),
        ];
        let text = leaf.prop_recursive(12, 128, 4, move |inner| {
            prop_oneof![
                prop::collection::vec((space(), inner.clone(), space()), 0..4).prop_map(|items| {
                    let items: Vec<String> = items
                        .into_iter()
                        .map(|(a, v, b)| format!("{a}{v}{b}"))
                        .collect();
                    format!("[{}]", items.join(","))
                }),
                // Names from a small set as well as arbitrary ones, so that names repeat.
                prop::collection::vec(
                    (
                        space(),
                        prop_oneof![
                            prop::sample::select(vec!["\"a\"", "\"b\"", "\"\\u0061\""])
                                .prop_map(str::to_owned),
                            string()
                        ],
                        space(),
                        space(),
                        inner,
                        space()
                    ),
                    0..4
                )
                .prop_map(|members| {
                    let members: Vec<String> = members
                        .into_iter()
                        .map(|(a, name, b, c, v, d)| format!("{a}{name}{b}:{c}{v}{d}"))
                        .collect();
                    format!("{{{}}}", members.join(","))
                }),
            ]
        });
        (space(), text, space()).prop_map(|(a, t, b)| format!("{a}{t}{b}"))
    }

    proptest::proptest! {
        /// The byte scan agrees with the parsed structure on JSON text in any
        /// spelling. `serde_json` parses each document, which also confirms the
        /// generator wrote valid JSON.
        #[test]
        fn nesting_depth_matches_the_parsed_structure_in_any_spelling(text in json_text()) {
            let parsed = Json::parse(text.as_bytes());
            proptest::prop_assert!(parsed.is_ok(), "not JSON: {text:?}");
            proptest::prop_assert_eq!(nesting_depth(text.as_bytes()), tree_depth(&parsed.unwrap()));
        }

        /// The byte scan agrees with the parsed structure on every JSON document,
        /// compact or pretty-printed.
        #[test]
        fn nesting_depth_matches_the_parsed_structure(value in json_value()) {
            let compact = serde_json::to_vec(&value).unwrap();
            let pretty = serde_json::to_vec_pretty(&value).unwrap();
            proptest::prop_assert_eq!(nesting_depth(&compact), depth(&value));
            proptest::prop_assert_eq!(nesting_depth(&pretty), depth(&value));
        }

        #[test]
        fn nesting_depth_never_fails_on_arbitrary_bytes(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)) {
            let _ = nesting_depth(&bytes);
        }
    }
}
