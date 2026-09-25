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
}
