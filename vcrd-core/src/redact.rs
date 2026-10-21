//! Redaction (REQUIREMENTS §8; ARCHITECTURE §7).
//!
//! Every value taken from an input is a [`ClaimValue`]. It has no `Display`, no
//! `Serialize`, and a `Debug` that prints only its kind. Outside this crate the one
//! way to read its plaintext is [`render`], which records every claim it shows.

use std::fmt;

use crate::context::Context;
use crate::document::{ClassedJson, LeafClass};
use crate::json::{Step, path_string};
use crate::report::ParseOutput;

/// One scalar value taken from an input.
#[derive(Clone, PartialEq)]
pub struct ClaimValue(Scalar);

#[derive(Clone, PartialEq)]
enum Scalar {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
}

/// A value's JSON type: what a masked value renders as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueKind {
    Null,
    Bool,
    Number,
    String,
}

impl ValueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ValueKind::Null => "null",
            ValueKind::Bool => "bool",
            ValueKind::Number => "number",
            ValueKind::String => "string",
        }
    }
}

impl ClaimValue {
    pub(crate) fn null() -> Self {
        ClaimValue(Scalar::Null)
    }

    pub(crate) fn bool(v: bool) -> Self {
        ClaimValue(Scalar::Bool(v))
    }

    pub(crate) fn number(v: serde_json::Number) -> Self {
        ClaimValue(Scalar::Number(v))
    }

    pub(crate) fn string(v: String) -> Self {
        ClaimValue(Scalar::String(v))
    }

    pub fn kind(&self) -> ValueKind {
        match &self.0 {
            Scalar::Null => ValueKind::Null,
            Scalar::Bool(_) => ValueKind::Bool,
            Scalar::Number(_) => ValueKind::Number,
            Scalar::String(_) => ValueKind::String,
        }
    }

    /// Plaintext, for checks inside core. Not public (ARCHITECTURE §7). Only formats
    /// call it, and a core built with none has none.
    #[cfg_attr(not(feature = "vc-jose"), allow(dead_code))]
    pub(crate) fn as_str(&self) -> Option<&str> {
        match &self.0 {
            Scalar::String(s) => Some(s),
            Scalar::Null | Scalar::Bool(_) | Scalar::Number(_) => None,
        }
    }

    /// A number's JSON text and value, for checks inside core. Not public
    /// (ARCHITECTURE §7), for the reason given on [`ClaimValue::as_str`].
    #[cfg_attr(not(feature = "vc-jose"), allow(dead_code))]
    pub(crate) fn as_number(&self) -> Option<(String, f64)> {
        match &self.0 {
            Scalar::Number(n) => Some((n.to_string(), n.as_f64()?)),
            Scalar::Null | Scalar::Bool(_) | Scalar::String(_) => None,
        }
    }

    fn reveal(&self) -> Revealed {
        match &self.0 {
            Scalar::Null => Revealed::Null,
            Scalar::Bool(b) => Revealed::Bool(*b),
            Scalar::Number(n) => Revealed::Number(n.to_string()),
            Scalar::String(s) => Revealed::String(s.clone()),
        }
    }
}

/// Written by hand: a derived `Debug` would print the value, and so would a derived
/// `Debug` on everything that contains one (ARCHITECTURE §7).
impl fmt::Debug for ClaimValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}>", self.kind().as_str())
    }
}

/// Which values to show. Milestone 1 has the three settings below, one for each level
/// of `--unsafe`; per-path designations come later (DEVELOPMENT-PLAN.md).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Designations {
    show_claims: bool,
    show_secrets: bool,
}

impl Designations {
    /// Every claim and every secret masked: the default.
    pub fn mask_claims() -> Self {
        Designations::default()
    }

    /// Every claim shown, and every cryptographic secret still masked.
    pub fn show_claims() -> Self {
        Designations {
            show_claims: true,
            show_secrets: false,
        }
    }

    /// Every claim and every cryptographic secret shown.
    pub fn show_claims_and_secrets() -> Self {
        Designations {
            show_claims: true,
            show_secrets: true,
        }
    }

    fn shows(self, class: LeafClass) -> bool {
        match class {
            LeafClass::Metadata => true,
            LeafClass::Claim => self.show_claims,
            LeafClass::Secret => self.show_secrets,
        }
    }
}

/// A document's values as they may be shown, and the record of every claim or secret
/// shown.
#[derive(Clone, Debug)]
pub struct Rendered {
    pub leaves: Vec<RenderedLeaf>,
    /// The securing mechanism's header, whole, when the format has one.
    pub header: Option<RenderedJson>,
    /// Every claim or secret shown, leaves first, then the header. Metadata is always
    /// shown and not listed.
    pub reveals: Vec<Reveal>,
}

#[derive(Clone, Debug)]
pub struct RenderedLeaf {
    pub path: String,
    pub class: LeafClass,
    pub kind: ValueKind,
    /// The plaintext, or `None` where the value is masked.
    pub value: Option<Revealed>,
}

/// A JSON structure as it may be shown: every member and item kept, each scalar shown
/// or masked.
#[derive(Clone, Debug)]
pub enum RenderedJson {
    Scalar {
        /// Where it is, in the notation of [`RenderedLeaf::path`].
        path: String,
        class: LeafClass,
        kind: ValueKind,
        /// The plaintext, or `None` where the value is masked.
        value: Option<Revealed>,
    },
    Array(Vec<RenderedJson>),
    /// Members in input order, duplicate names included.
    Object(Vec<(String, RenderedJson)>),
}

/// A shown value.
#[derive(Clone, Debug, PartialEq)]
pub enum Revealed {
    Null,
    Bool(bool),
    /// The number's JSON text.
    Number(String),
    String(String),
}

/// One claim or secret shown in cleartext; the output's `reveals` key (ARCHITECTURE §6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reveal {
    pub path: String,
    pub location: RevealLocation,
    pub treatment: Treatment,
}

/// Which part of the document a revealed path is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevealLocation {
    /// The document's leaves, such as a credential's claims.
    Leaves,
    /// The securing mechanism's header.
    Header,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Treatment {
    Shown,
}

/// Renders what parsing found under the context's designations: the document's leaves
/// and the header, metadata shown, claims and secrets masked unless designated. The
/// only way to their plaintext outside this crate, and it records every one it shows.
pub fn render(parsed: &ParseOutput, ctx: &Context) -> Rendered {
    let designations = *ctx.designations();
    let document_leaves = parsed
        .document
        .as_ref()
        .map_or(&[][..], |d| d.leaves.as_slice());
    let mut leaves = Vec::with_capacity(document_leaves.len());
    let mut reveals = Vec::new();
    for leaf in document_leaves {
        let shown = designations.shows(leaf.class);
        if shown && leaf.class != LeafClass::Metadata {
            reveals.push(Reveal {
                path: leaf.path.clone(),
                location: RevealLocation::Leaves,
                treatment: Treatment::Shown,
            });
        }
        leaves.push(RenderedLeaf {
            path: leaf.path.clone(),
            class: leaf.class,
            kind: leaf.value.kind(),
            value: shown.then(|| leaf.value.reveal()),
        });
    }
    let header = parsed
        .header
        .as_ref()
        .map(|h| render_json(h, designations, &mut Vec::new(), &mut reveals));
    Rendered {
        leaves,
        header,
        reveals,
    }
}

fn render_json<'a>(
    json: &'a ClassedJson,
    designations: Designations,
    path: &mut Vec<Step<'a>>,
    reveals: &mut Vec<Reveal>,
) -> RenderedJson {
    match json {
        ClassedJson::Scalar(class, value) => {
            let shown = designations.shows(*class);
            let path = path_string(path);
            if shown && *class != LeafClass::Metadata {
                reveals.push(Reveal {
                    path: path.clone(),
                    location: RevealLocation::Header,
                    treatment: Treatment::Shown,
                });
            }
            RenderedJson::Scalar {
                path,
                class: *class,
                kind: value.kind(),
                value: shown.then(|| value.reveal()),
            }
        }
        ClassedJson::Array(items) => RenderedJson::Array(
            items
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    path.push(Step::Index(index));
                    let rendered = render_json(item, designations, path, reveals);
                    path.pop();
                    rendered
                })
                .collect(),
        ),
        ClassedJson::Object(members) => RenderedJson::Object(
            members
                .iter()
                .map(|(name, value)| {
                    path.push(Step::Name(name));
                    let rendered = render_json(value, designations, path, reveals);
                    path.pop();
                    (name.clone(), rendered)
                })
                .collect(),
        ),
    }
}
