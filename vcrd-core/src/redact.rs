//! Redaction (REQUIREMENTS §8; ARCHITECTURE §7).
//!
//! Every value taken from an input is a [`ClaimValue`]. It has no `Display`, no
//! `Serialize`, and a `Debug` that prints only its kind. Outside this crate the one
//! way to read its plaintext is [`render`], which records every claim it shows.

use std::fmt;

use crate::context::Context;
use crate::document::{Document, LeafClass};

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

/// Which claims to show. Milestone 1 has the two settings below; per-path
/// designations come later (DEVELOPMENT-PLAN.md).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Designations {
    show_all_claims: bool,
}

impl Designations {
    /// Every claim masked: the default.
    pub fn mask_claims() -> Self {
        Designations {
            show_all_claims: false,
        }
    }

    /// Every claim shown, as `--unsafe` asks.
    pub fn show_all() -> Self {
        Designations {
            show_all_claims: true,
        }
    }
}

/// A document's leaves as they may be shown, and the record of every claim shown.
#[derive(Clone, Debug)]
pub struct Rendered {
    pub leaves: Vec<RenderedLeaf>,
    /// Every claim shown, in leaf order. Metadata is always shown and not listed.
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

/// A shown value.
#[derive(Clone, Debug, PartialEq)]
pub enum Revealed {
    Null,
    Bool(bool),
    /// The number's JSON text.
    Number(String),
    String(String),
}

/// One claim shown in cleartext; the output's `reveals` key (ARCHITECTURE §6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reveal {
    pub path: String,
    pub treatment: Treatment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Treatment {
    Shown,
}

/// Renders a document's leaves under the context's designations: metadata shown,
/// claims masked unless designated. The only way to a claim's plaintext outside
/// this crate, and it records every claim it shows.
pub fn render(document: &Document, ctx: &Context) -> Rendered {
    let designations = ctx.designations();
    let mut leaves = Vec::with_capacity(document.leaves.len());
    let mut reveals = Vec::new();
    for leaf in &document.leaves {
        let shown = match leaf.class {
            LeafClass::Metadata => true,
            LeafClass::Claim => designations.show_all_claims,
        };
        if shown && leaf.class == LeafClass::Claim {
            reveals.push(Reveal {
                path: leaf.path.clone(),
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
    Rendered { leaves, reveals }
}
