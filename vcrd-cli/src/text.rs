//! The `text` and `plain` output (REQUIREMENTS §8; docs/output.md).
//!
//! Both print the same sections, chosen by the verbosity level from the envelope that
//! JSON prints whole, so that neither shows what the other lacks (ARCHITECTURE §6).
//! `text` lays each section out as a table; `plain` prints one `name: value` line per
//! item. Every string taken from the input is escaped before it is printed, so that a
//! credential cannot move the cursor, recolor the terminal or reorder what follows.

use std::fmt::Write as _;

use serde_json::Value;
use tabled::builder::Builder;
use tabled::settings::object::{Cell as TableCell, Columns};
use tabled::settings::{Style, Width};

use crate::view::{Envelope, LeafView, PhaseView, ProofView, ResultView};

/// The `text` output at this verbosity, 1 to 3.
pub fn text(envelope: &Envelope, verbosity: u8) -> String {
    let mut out = String::new();
    for (index, section) in sections(envelope, verbosity).iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        if let Some(title) = section.title {
            out.push_str(title);
            out.push('\n');
        }
        let mut builder = Builder::default();
        let table = match &section.body {
            Body::Fields(fields) => {
                for field in fields {
                    builder.push_record([field.label.to_owned(), printable(&field.value)]);
                }
                let mut table = builder.build();
                table.with(Style::blank());
                for (row, field) in fields.iter().enumerate() {
                    if field.prose {
                        table.modify(TableCell::new(row, 1), wrap());
                    }
                }
                table.to_string()
            }
            Body::Table { columns, rows, .. } => {
                builder.push_record(columns.iter().map(|c| c.label.to_owned()));
                for row in rows {
                    builder.push_record(row.cells.iter().map(Cell::text));
                }
                let mut table = builder.build();
                table.with(Style::psql());
                for (index, column) in columns.iter().enumerate() {
                    if column.prose {
                        table.modify(Columns::one(index), wrap());
                    }
                }
                table.to_string()
            }
        };
        // tabled pads every cell, the last included.
        for line in table.lines() {
            out.push_str(line.trim_end());
            out.push('\n');
        }
    }
    out
}

/// The `plain` output at this verbosity, 1 to 3: a field as `name: value`, a table
/// row as `name: column=value …`, with a value quoted as a JSON string where it has
/// spaces, `=` or quotes, or is empty.
pub fn plain(envelope: &Envelope, verbosity: u8) -> String {
    let mut out = String::new();
    for section in sections(envelope, verbosity) {
        match section.body {
            Body::Fields(fields) => {
                for field in fields {
                    let name = join(&section.name, &field.name);
                    let _ = writeln!(out, "{}: {}", printable(&name), printable(&field.value));
                }
            }
            Body::Table {
                columns,
                rows,
                named_by_first,
            } => {
                for row in rows {
                    let mut line = format!("{}:", printable(&join(&section.name, &row.name)));
                    let skip = usize::from(named_by_first);
                    for (column, cell) in columns.iter().zip(&row.cells).skip(skip) {
                        cell.plain(column.key, &mut line);
                    }
                    out.push_str(&line);
                    out.push('\n');
                }
            }
        }
    }
    out
}

/// One part of the output.
struct Section {
    /// The JSON key it comes from, which names its lines in `plain`; empty for the
    /// top-level fields.
    name: String,
    /// Its heading in `text`; none for the summary at the top.
    title: Option<&'static str>,
    body: Body,
}

enum Body {
    Fields(Vec<Field>),
    Table {
        columns: Vec<Column>,
        rows: Vec<Row>,
        /// Whether the first column holds the row's name, which `plain` then prints
        /// once, before the colon.
        named_by_first: bool,
    },
}

struct Field {
    /// The JSON path, relative to the section's.
    name: String,
    label: &'static str,
    value: String,
    /// Wrapped at word boundaries in `text`; see [`PROSE_WIDTH`].
    prose: bool,
}

struct Column {
    label: &'static str,
    /// The name in `plain`.
    key: &'static str,
    /// Wrapped at word boundaries in `text`; see [`PROSE_WIDTH`].
    prose: bool,
}

/// The width at which `text` wraps prose, such as a warning. Values are never wrapped:
/// an identifier split across lines is hard to copy or search for.
const PROSE_WIDTH: usize = 72;

fn wrap() -> tabled::settings::width::Wrap<usize> {
    Width::wrap(PROSE_WIDTH).keep_words(true)
}

struct Row {
    /// The JSON path of the row, relative to the section's: a name or `[index]`.
    name: String,
    /// One per column.
    cells: Vec<Cell>,
}

enum Cell {
    Text(String),
    /// A finding's detail: one `name: value` line each in `text`, `name=value` in
    /// `plain`.
    Pairs(Vec<(String, String)>),
    /// One value on several lines in `text`, and on one in `plain`.
    Lines(Vec<String>),
}

impl Cell {
    fn text(&self) -> String {
        match self {
            Cell::Text(s) => printable(s),
            Cell::Pairs(pairs) => pairs
                .iter()
                .map(|(k, v)| format!("{}: {}", printable(k), printable(v)))
                .collect::<Vec<_>>()
                .join("\n"),
            Cell::Lines(lines) => lines
                .iter()
                .map(|l| printable(l))
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }

    fn plain(&self, key: &str, line: &mut String) {
        match self {
            Cell::Text(s) if s.is_empty() => {}
            Cell::Text(s) => {
                let _ = write!(line, " {key}={}", quoted(s));
            }
            Cell::Pairs(pairs) => {
                for (k, v) in pairs {
                    let _ = write!(line, " {}={}", quoted(k), quoted(v));
                }
            }
            Cell::Lines(lines) => {
                let _ = write!(line, " {key}={}", quoted(&lines.concat()));
            }
        }
    }
}

fn field(name: &str, label: &'static str, value: impl Into<String>) -> Field {
    Field {
        name: name.to_owned(),
        label,
        value: value.into(),
        prose: false,
    }
}

fn prose_field(name: &str, label: &'static str, value: impl Into<String>) -> Field {
    Field {
        prose: true,
        ..field(name, label, value)
    }
}

fn column(label: &'static str, key: &'static str) -> Column {
    Column {
        label,
        key,
        prose: false,
    }
}

fn prose_column(label: &'static str, key: &'static str) -> Column {
    Column {
        prose: true,
        ..column(label, key)
    }
}

fn text_cell(value: impl Into<String>) -> Cell {
    Cell::Text(value.into())
}

/// The sections a verbosity level prints. Level 1 answers "did it pass, and what is
/// it"; level 2 adds everything else except the credential's metadata, which level 3
/// adds.
fn sections(envelope: &Envelope, verbosity: u8) -> Vec<Section> {
    let full = verbosity >= 2;
    let result = &envelope.result;
    let mut sections = Vec::new();
    sections.push(Section {
        name: String::new(),
        title: None,
        body: Body::Fields(summary(envelope, full)),
    });
    // No phase ran: the error says why.
    if envelope.error.is_some() && !full {
        sections.extend(warnings(envelope));
        return sections;
    }
    let verify_requested = result.phases.verify.outcome != "not_requested";
    sections.push(phases(result, full, verify_requested));
    if full || verify_requested {
        for (index, proof) in result.proofs.iter().enumerate() {
            sections.push(proof_section(index, proof, full));
        }
    }
    if full
        && let Some(format) = &result.format
        && !format.header.is_empty()
    {
        sections.push(leaves("format.header", "Header", &format.header));
    }
    if let Some(credential) = &result.credential {
        if !credential.claims.is_empty() {
            sections.push(leaves("credential.claims", "Claims", &credential.claims));
        }
        if verbosity >= 3 && !credential.metadata.is_empty() {
            sections.push(leaves(
                "credential.metadata",
                "Metadata",
                &credential.metadata,
            ));
        }
    }
    if !result.findings.is_empty() {
        sections.push(findings(result));
    }
    // After the findings: the status is always the first line.
    sections.extend(warnings(envelope));
    if !result.not_evaluated.is_empty() {
        let rows = result
            .not_evaluated
            .iter()
            .map(|n| Row {
                name: n.what.to_owned(),
                cells: vec![text_cell(n.what), text_cell(n.why)],
            })
            .collect();
        sections.push(Section {
            name: "not_evaluated".to_owned(),
            title: Some("Not evaluated"),
            body: Body::Table {
                columns: vec![column("Check", "check"), column("Reason", "reason")],
                rows,
                named_by_first: true,
            },
        });
    }
    // Always empty until presentations (DEVELOPMENT-PLAN.md, milestone 4); counted
    // here so that nothing is dropped silently before then.
    if full && !result.contained.is_empty() {
        sections.push(Section {
            name: String::new(),
            title: Some("Contained"),
            body: Body::Fields(vec![field(
                "contained",
                "Results",
                format!("{} (see --format json)", result.contained.len()),
            )]),
        });
    }
    sections
}

/// What vcrd also wrote to stderr as a warning, such as `--unsafe`'s.
fn warnings(envelope: &Envelope) -> Option<Section> {
    if envelope.warnings.is_empty() {
        return None;
    }
    let rows = envelope
        .warnings
        .iter()
        .enumerate()
        .map(|(index, w)| Row {
            name: format!("[{index}]"),
            cells: vec![text_cell(w.code), text_cell(w.message.clone())],
        })
        .collect();
    Some(Section {
        name: "warnings".to_owned(),
        title: Some("Warnings"),
        body: Body::Table {
            columns: vec![column("Code", "code"), prose_column("Message", "message")],
            rows,
            named_by_first: false,
        },
    })
}

fn summary(envelope: &Envelope, full: bool) -> Vec<Field> {
    let result = &envelope.result;
    let mut fields = vec![field("status", "Status", envelope.status)];
    if let Some(error) = &envelope.error {
        fields.push(field("error.code", "Error", error.code));
        // On one line: clap's messages span several, which stderr shows as written.
        let message = error
            .message
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        fields.push(prose_field("error.message", "Message", message));
    }
    if full {
        fields.push(field(
            "exit_code",
            "Exit code",
            envelope.exit_code.to_string(),
        ));
        fields.push(field(
            "input.bytes",
            "Bytes",
            result.input.bytes.to_string(),
        ));
        if let Some(depth) = result.input.depth {
            fields.push(field("input.depth", "Depth", depth.to_string()));
        }
        if let Some(format) = &result.format {
            fields.push(field("format.id", "Format", format.id));
            if let Some(profile) = format.profile {
                fields.push(field("format.profile", "Profile", profile));
            }
        }
    }
    if let Some(credential) = &result.credential {
        fields.push(field("credential.kind", "Kind", credential.kind));
        if let Some(issuer) = &credential.issuer {
            fields.push(field("credential.issuer", "Issuer", issuer.clone()));
        }
        if !credential.types.is_empty() {
            fields.push(field(
                "credential.types",
                "Types",
                credential.types.join(", "),
            ));
        }
        if let Some(validity) = credential.validity {
            fields.push(field("credential.validity", "Validity", validity));
        }
        if full {
            if let Some(from) = &credential.valid_from {
                fields.push(field("credential.valid_from", "Valid from", from.clone()));
            }
            if let Some(until) = &credential.valid_until {
                fields.push(field(
                    "credential.valid_until",
                    "Valid until",
                    until.clone(),
                ));
            }
        }
    }
    fields
}

/// Level 1 leaves out parse, whose failure the other phases' `blocked_by` reports,
/// and verify when it was not requested.
fn phases(result: &ResultView, full: bool, verify_requested: bool) -> Section {
    let phases = &result.phases;
    let mut rows = Vec::new();
    for (name, phase, shown) in [
        ("parse", &phases.parse, full),
        ("inspect", &phases.inspect, true),
        ("verify", &phases.verify, full || verify_requested),
    ] {
        if shown {
            rows.push(phase_row(name, phase));
        }
    }
    Section {
        name: "phases".to_owned(),
        title: Some("Phases"),
        body: Body::Table {
            columns: vec![
                column("Phase", "phase"),
                column("Outcome", "outcome"),
                column("Findings", "findings"),
                column("Blocked by", "blocked_by"),
            ],
            rows,
            named_by_first: true,
        },
    }
}

fn phase_row(name: &str, phase: &PhaseView) -> Row {
    // In the reader's terms: what failed, or what is lacking and where vcrd looked.
    let blocked =
        phase
            .blocked_by
            .as_ref()
            .map_or_else(String::new, |b| match (b.phase, b.missing) {
                ("parse", _) => "parse failed".to_owned(),
                (by, Some("key_material")) => {
                    let mut text = format!("{by}: no key for verify");
                    if let Some(consulted) = &b.consulted {
                        let places: Vec<String> =
                            consulted.iter().map(|c| c.replace('_', " ")).collect();
                        let _ = write!(text, "; looked in: {}", places.join(", "));
                    }
                    text
                }
                (by, _) => format!("{by} ({})", b.reason),
            });
    Row {
        name: name.to_owned(),
        cells: vec![
            text_cell(name),
            text_cell(phase.outcome),
            text_cell(phase.findings.join(", ")),
            text_cell(blocked),
        ],
    }
}

/// A proof as fields rather than a table row: at level 2 it has too many values for
/// a terminal's width.
fn proof_section(index: usize, proof: &ProofView, full: bool) -> Section {
    let name = format!("proofs[{index}]");
    let mut fields = vec![
        field("suite", "Suite", proof.suite),
        field(
            "algorithm",
            "Algorithm",
            proof
                .algorithm
                .clone()
                .unwrap_or_else(|| "none declared".to_owned()),
        ),
        field("outcome", "Outcome", proof.outcome),
    ];
    let provenance = &proof.key_provenance;
    if let Some(source) = provenance.source {
        fields.push(field("key_provenance.source", "Key source", source));
    }
    if let Some(method) = provenance.method {
        fields.push(field("key_provenance.method", "Method", method));
    }
    if full {
        if let Some(validity) = proof.validity {
            fields.push(field("validity", "Validity", validity));
        }
        if let Some(thumbprint) = &provenance.thumbprint {
            fields.push(field(
                "key_provenance.thumbprint",
                "Thumbprint",
                thumbprint.clone(),
            ));
        }
        if let Some(jwk) = &provenance.jwk {
            fields.push(field("key_provenance.jwk", "Key JWK", jwk.to_string()));
        }
    }
    // The key the credential carries, and whether the signature verifies under it,
    // at every level: without them a refused key reads as if nothing was tried.
    if let Some(key) = &provenance.credential_key {
        let carried = "key_provenance.credential_key";
        fields.push(field(
            &format!("{carried}.location"),
            "Carried key",
            key.location.clone(),
        ));
        if full {
            fields.push(field(
                &format!("{carried}.thumbprint"),
                "Carried thumbprint",
                key.thumbprint.clone(),
            ));
            fields.push(field(
                &format!("{carried}.jwk"),
                "Carried key JWK",
                key.jwk.to_string(),
            ));
        }
        fields.push(field(
            &format!("{carried}.matched"),
            "Matched",
            key.matched.to_string(),
        ));
        if let Some(verifies) = key.verifies_signature {
            fields.push(field(
                &format!("{carried}.verifies_signature"),
                "Verifies signature",
                verifies.to_string(),
            ));
        }
    }
    Section {
        name,
        title: Some("Proof"),
        body: Body::Fields(fields),
    }
}

/// Values: the claims, the metadata or the header. The Visibility column says
/// whether each is sensitive and, if so, whether it is shown, which is how `text` and
/// `plain` report a reveal.
fn leaves(name: &'static str, title: &'static str, leaves: &[LeafView]) -> Section {
    let columns = vec![
        column("Path", "path"),
        column("Type", "type"),
        column("Value", "value"),
        column("Visibility", "visibility"),
    ];
    let rows = leaves
        .iter()
        .map(|leaf| Row {
            name: leaf.path.clone(),
            cells: vec![
                text_cell(leaf.path.clone()),
                text_cell(leaf.kind),
                value_cell(name, leaf),
                text_cell(leaf.visibility),
            ],
        })
        .collect();
    Section {
        name: name.to_owned(),
        title: Some(title),
        body: Body::Table {
            columns,
            rows,
            named_by_first: true,
        },
    }
}

fn findings(result: &ResultView) -> Section {
    let rows = result
        .findings
        .iter()
        .enumerate()
        .map(|(index, f)| Row {
            name: format!("[{index}]"),
            cells: vec![
                text_cell(f.code),
                text_cell(f.attribution),
                text_cell(f.severity),
                Cell::Pairs(detail_pairs(&f.detail)),
            ],
        })
        .collect();
    Section {
        name: "findings".to_owned(),
        title: Some("Findings"),
        body: Body::Table {
            columns: vec![
                column("Code", "code"),
                column("Attribution", "attribution"),
                column("Severity", "severity"),
                column("Detail", "detail"),
            ],
            rows,
            named_by_first: false,
        },
    }
}

/// A finding's detail as name and value pairs, nested objects flattened to dotted
/// names. `type` is left out: the code already says it.
fn detail_pairs(detail: &Value) -> Vec<(String, String)> {
    fn walk(prefix: &str, value: &Value, out: &mut Vec<(String, String)>) {
        match value {
            Value::Object(members) => {
                for (name, value) in members {
                    let name = if prefix.is_empty() {
                        name.clone()
                    } else {
                        format!("{prefix}.{name}")
                    };
                    walk(&name, value, out);
                }
            }
            other => out.push((prefix.to_owned(), show(other))),
        }
    }
    let mut out = Vec::new();
    if let Value::Object(members) = detail {
        for (name, value) in members {
            if name != "type" {
                walk(name, value, &mut out);
            }
        }
    } else {
        walk("", detail, &mut out);
    }
    out
}

/// A value's cell. The header's `kid` breaks before its fragment, at `#`: a DID URL
/// such as a `did:key` key's repeats the DID after it, and on one line it widens the
/// Header table past a terminal's width. `plain` keeps it on one line.
fn value_cell(section: &str, leaf: &LeafView) -> Cell {
    let value = leaf.value.as_ref().map_or_else(|| MASKED.to_owned(), show);
    if section == "format.header"
        && leaf.path == "kid"
        && let Some((did, fragment)) = value.split_once('#')
    {
        return Cell::Lines(vec![did.to_owned(), format!("#{fragment}")]);
    }
    text_cell(value)
}

/// How a masked value prints.
const MASKED: &str = "(masked)";

/// A JSON value for display: a string as its text, an array as its items separated
/// by commas, anything else as JSON.
fn show(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(show).collect::<Vec<_>>().join(", "),
        other => other.to_string(),
    }
}

/// Joins a section's name and a row's or field's, as JSON paths join.
fn join(section: &str, name: &str) -> String {
    if section.is_empty() {
        name.to_owned()
    } else if name.starts_with('[') {
        format!("{section}{name}")
    } else {
        format!("{section}.{name}")
    }
}

/// The string with every control character, and every character that reorders
/// bidirectional text, written as a `\u{…}` escape, so that printing it cannot act on
/// the terminal or disguise what surrounds it.
fn printable(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let reorders = matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
        if c.is_control() || reorders {
            let _ = write!(out, "\\u{{{:04x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

/// A `plain` value: printable, and quoted as a JSON string where a reader splitting
/// on spaces and `=` would otherwise misread it.
fn quoted(s: &str) -> String {
    let s = printable(s);
    if s.is_empty() || s.contains(|c: char| c.is_whitespace() || c == '=' || c == '"') {
        Value::String(s).to_string()
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A credential's strings cannot act on the terminal: an escape sequence, a
    /// newline that would fake a line of output, and a right-to-left override that
    /// would reorder what follows are all written as escapes.
    #[test]
    fn escapes_what_would_act_on_the_terminal() {
        assert_eq!(printable("a\u{1b}[31mb"), "a\\u{001b}[31mb");
        assert_eq!(printable("a\nstatus: passed"), "a\\u{000a}status: passed");
        assert_eq!(printable("a\u{202e}b"), "a\\u{202e}b");
        assert_eq!(printable("did:example:é"), "did:example:é");
    }

    #[test]
    fn quotes_a_plain_value_only_where_it_would_be_misread() {
        assert_eq!(quoted("passed"), "passed");
        assert_eq!(quoted("a b"), r#""a b""#);
        assert_eq!(quoted("a=b"), r#""a=b""#);
        assert_eq!(quoted(""), r#""""#);
        assert_eq!(quoted("a\u{1b}b"), "a\\u{001b}b");
    }
}
