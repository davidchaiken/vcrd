//! VCDM 2.0 (the Verifiable Credentials Data Model): the inspect checks for any format
//! whose payload is a VCDM 2.0 credential (VCDM 2.0 §4), and the value types they
//! read: URLs (§2) and XML Schema `dateTimeStamp` values (§4.9).
//!
//! Compiled with the formats that call it. The `cfg` on its declaration in `lib.rs`
//! becomes `any(...)` when a second such format arrives (ARCHITECTURE §2).

use std::cell::RefCell;
use std::sync::LazyLock;

use regex::Regex;
use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime, Time, UtcOffset};

use crate::context::Context;
use crate::document::{DateTimeProblem, Document, Timestamp};
use crate::finding::{Attribution, DateField, Finding, FindingDetail, IssuerProblem, Severity};
use crate::json::{Json, Step, path_string};
use crate::report::{Check, NotEvaluated, NotEvaluatedReason, Phase, Validity};

/// The base context, which VCDM 2.0 §4.3 requires as the first `@context` item.
pub(crate) const BASE_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";

/// The objects other than the credential that VCDM 2.0 §4.5's table requires to have
/// a `type`. Presentations are not read yet.
const TYPED_PROPERTIES: &[&str] = &[
    "credentialStatus",
    "termsOfUse",
    "evidence",
    "refreshService",
    "credentialSchema",
];

/// What the VCDM 2.0 checks established.
pub(crate) struct Inspected {
    pub validity: Validity,
    pub not_evaluated: Vec<NotEvaluated>,
    /// Whether a finding showed that the credential names no usable issuer
    /// identifier.
    pub no_issuer_identifier: bool,
}

/// Checks a VCDM 2.0 credential, given as parsed and as projected.
pub(crate) fn inspect(
    payload: &Json,
    document: &Document,
    ctx: &Context,
    findings: &mut Vec<Finding>,
) -> Inspected {
    contexts(payload.get("@context"), findings);
    types(payload, findings);
    let no_issuer_identifier = issuer(payload.get("issuer"), findings);
    if let Some(id) = payload.get("id") {
        identifier(String::from("id"), id, findings);
    }
    subjects(payload.get("credentialSubject"), findings);
    let validity = validity(document, ctx, findings);

    // Status and schemas are checked against material fetched from their URLs, which
    // vcrd does not do yet.
    let mut not_evaluated = Vec::new();
    for (property, what) in [
        ("credentialStatus", Check::RevocationStatus),
        ("credentialSchema", Check::SchemaConformance),
    ] {
        if payload.get(property).is_some() {
            not_evaluated.push(NotEvaluated {
                what,
                why: NotEvaluatedReason::NotImplemented,
            });
        }
    }
    Inspected {
        validity,
        not_evaluated,
        no_issuer_identifier,
    }
}

fn error(detail: FindingDetail) -> Finding {
    Finding::error(Phase::Inspect, Attribution::Input, detail)
}

fn warning(detail: FindingDetail) -> Finding {
    Finding::new(
        Phase::Inspect,
        Attribution::Input,
        Severity::Warning,
        detail,
    )
}

/// The items of a property that may be one value or an array of values (VCDM 2.0
/// §6), each with its path.
fn items<'a>(name: &'a str, json: &'a Json) -> Vec<(String, &'a Json)> {
    match json {
        Json::Array(items) => items
            .iter()
            .enumerate()
            .map(|(index, item)| (path_string(&[Step::Name(name), Step::Index(index)]), item))
            .collect(),
        Json::Scalar(_) | Json::Object(_) => vec![(path_string(&[Step::Name(name)]), json)],
    }
}

/// VCDM 2.0 §4.3: the base context first, then URLs and objects.
fn contexts(json: Option<&Json>, findings: &mut Vec<Finding>) {
    let Some(json) = json else {
        findings.push(error(FindingDetail::ContextMissing));
        return;
    };
    let items = items("@context", json);
    let mut items = items.into_iter();
    match items.next() {
        Some((_, first)) if first.as_str() == Some(BASE_CONTEXT) => {}
        first => findings.push(error(FindingDetail::ContextFirstInvalid {
            found: first.and_then(|(_, f)| f.as_str()).map(str::to_owned),
        })),
    }
    for (path, item) in items {
        match (item, item.as_str()) {
            (Json::Object(_), _) => {}
            (_, Some(url)) => check_url(path, url, findings),
            (_, None) => findings.push(error(FindingDetail::ContextEntryInvalid { path })),
        }
    }
}

/// VCDM 2.0 §4.5: the credential's type includes `VerifiableCredential`, and each
/// object the table names has a type.
fn types(payload: &Json, findings: &mut Vec<Finding>) {
    let values = payload.get("type").map(|t| items("type", t));
    match values {
        None => findings.push(error(FindingDetail::TypeMissing {
            path: String::from("type"),
        })),
        Some(values) if values.is_empty() => findings.push(error(FindingDetail::TypeMissing {
            path: String::from("type"),
        })),
        Some(values) => {
            let mut verifiable_credential = false;
            for (path, value) in values {
                match value.as_str() {
                    Some(name) => verifiable_credential |= name == "VerifiableCredential",
                    None => findings.push(error(FindingDetail::TypeNotString { path })),
                }
            }
            if !verifiable_credential {
                findings.push(error(FindingDetail::TypeLacksVerifiableCredential));
            }
        }
    }
    for name in TYPED_PROPERTIES {
        let Some(json) = payload.get(name) else {
            continue;
        };
        for (path, item) in items(name, json) {
            if matches!(item, Json::Object(_)) && item.get("type").is_none() {
                findings.push(error(FindingDetail::TypeMissing {
                    path: format!("{path}.type"),
                }));
            }
        }
    }
}

/// VCDM 2.0 §4.7: a URL, or an object whose `id` is a URL. Returns whether a finding
/// left no usable issuer identifier.
fn issuer(json: Option<&Json>, findings: &mut Vec<Finding>) -> bool {
    let (path, url) = match json {
        None => return unusable(error(FindingDetail::IssuerMissing), findings),
        Some(object @ Json::Object(_)) => match object.get("id").and_then(Json::as_str) {
            Some(id) => ("issuer.id", id),
            None => {
                let problem = IssuerProblem::NoId;
                return unusable(error(FindingDetail::IssuerInvalid { problem }), findings);
            }
        },
        Some(other) => match other.as_str() {
            Some(url) => ("issuer", url),
            None => {
                let problem = IssuerProblem::WrongType;
                return unusable(error(FindingDetail::IssuerInvalid { problem }), findings);
            }
        },
    };
    match parse_url(url) {
        Ok(violations) => {
            nonconforming(String::from(path), violations, findings);
            false
        }
        Err(error_name) => {
            let problem = IssuerProblem::NotUrl { error: error_name };
            unusable(error(FindingDetail::IssuerInvalid { problem }), findings)
        }
    }
}

fn unusable(finding: Finding, findings: &mut Vec<Finding>) -> bool {
    findings.push(finding);
    true
}

/// VCDM 2.0 §4.8: present, and each subject an object that is the subject of at
/// least one claim.
fn subjects(json: Option<&Json>, findings: &mut Vec<Finding>) {
    let path = String::from("credentialSubject");
    match json {
        None => findings.push(error(FindingDetail::CredentialSubjectMissing)),
        Some(Json::Array(items)) if items.is_empty() => {
            findings.push(error(FindingDetail::CredentialSubjectEmpty { path }));
        }
        Some(json) => {
            for (path, subject) in items("credentialSubject", json) {
                check_subject(path, subject, findings);
            }
        }
    }
}

fn check_subject(path: String, subject: &Json, findings: &mut Vec<Finding>) {
    let Some(members) = subject.members() else {
        findings.push(error(FindingDetail::CredentialSubjectInvalid { path }));
        return;
    };
    if members.is_empty() {
        findings.push(error(FindingDetail::CredentialSubjectEmpty {
            path: path.clone(),
        }));
    } else if members.iter().all(|m| m.name == "id") {
        findings.push(warning(FindingDetail::CredentialSubjectNoClaims {
            path: path.clone(),
        }));
    }
    if let Some(id) = subject.get("id") {
        identifier(format!("{path}.id"), id, findings);
    }
}

/// VCDM 2.0 §4.4: an `id` is a single URL.
fn identifier(path: String, json: &Json, findings: &mut Vec<Finding>) {
    match json.as_str() {
        Some(url) => check_url(path, url, findings),
        None => findings.push(error(FindingDetail::UrlInvalid {
            path,
            error: String::from("not_a_string"),
        })),
    }
}

fn check_url(path: String, value: &str, findings: &mut Vec<Finding>) {
    match parse_url(value) {
        Ok(violations) => nonconforming(path, violations, findings),
        Err(error_name) => findings.push(error(FindingDetail::UrlInvalid {
            path,
            error: error_name,
        })),
    }
}

fn nonconforming(path: String, violations: Vec<String>, findings: &mut Vec<Finding>) {
    if !violations.is_empty() {
        findings.push(warning(FindingDetail::UrlNonconforming {
            path,
            violations,
        }));
    }
}

/// Parses a URL under the WHATWG URL Standard, which VCDM 2.0 §2 cites. Returns the
/// validation errors the parser corrected on the way, or the error that stopped it,
/// each as the `url` crate names it, in snake case.
pub(crate) fn parse_url(value: &str) -> Result<Vec<String>, String> {
    let violations = RefCell::new(Vec::new());
    let record = |violation: url::SyntaxViolation| {
        let name = snake_case(&format!("{violation:?}"));
        let mut violations = violations.borrow_mut();
        if !violations.contains(&name) {
            violations.push(name);
        }
    };
    let parsed = url::Url::options()
        .syntax_violation_callback(Some(&record))
        .parse(value);
    match parsed {
        Ok(_) => Ok(violations.into_inner()),
        Err(error) => Err(snake_case(&format!("{error:?}"))),
    }
}

/// `RelativeUrlWithoutBase` → `relative_url_without_base`.
fn snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    let mut after_lower_or_digit = false;
    for c in name.chars() {
        if c.is_ascii_uppercase() {
            if after_lower_or_digit {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
            after_lower_or_digit = false;
        } else {
            out.push(c);
            after_lower_or_digit = c.is_ascii_lowercase() || c.is_ascii_digit();
        }
    }
    out
}

/// The validity period (VCDM 2.0 §4.9): each bound readable, `validUntil` not
/// earlier than `validFrom`, and both against the clock and skew.
fn validity(document: &Document, ctx: &Context, findings: &mut Vec<Finding>) -> Validity {
    let now = ctx.now();
    let skew_seconds = ctx.clock_skew().as_secs();
    let skew = time::Duration::try_from(ctx.clock_skew()).unwrap_or(time::Duration::MAX);
    let mut bound = |timestamp: &Option<Timestamp>, field| match timestamp {
        None => Ok(None),
        Some(Timestamp { parsed: Ok(t), .. }) => Ok(Some(*t)),
        Some(Timestamp {
            parsed: Err(problem),
            ..
        }) => {
            findings.push(match *problem {
                DateTimeProblem::Unrepresentable => Finding::error(
                    Phase::Inspect,
                    Attribution::Vcrd,
                    FindingDetail::DateTimeUnrepresentable { field },
                ),
                DateTimeProblem::NotString => error(FindingDetail::DateTimeInvalid {
                    field,
                    valid_rfc3339: false,
                }),
                DateTimeProblem::NotDateTimeStamp { valid_rfc3339 } => {
                    error(FindingDetail::DateTimeInvalid {
                        field,
                        valid_rfc3339,
                    })
                }
            });
            Err(())
        }
    };
    let from = bound(&document.valid_from, DateField::ValidFrom);
    let until = bound(&document.valid_until, DateField::ValidUntil);
    let (Ok(from), Ok(until)) = (from, until) else {
        return Validity::Unknown;
    };
    if from.is_none() && until.is_none() {
        return Validity::Unbounded;
    }
    if let (Some(valid_from), Some(valid_until)) = (from, until)
        && valid_until < valid_from
    {
        findings.push(error(FindingDetail::ValidUntilBeforeValidFrom {
            valid_from,
            valid_until,
        }));
    }
    // Checked arithmetic: a skew past the end of time makes every bound current.
    if let Some(valid_from) = from
        && now
            .checked_add(skew)
            .is_some_and(|latest| valid_from > latest)
    {
        findings.push(error(FindingDetail::NotYetValid {
            valid_from,
            now,
            skew_seconds,
        }));
        return Validity::NotYetValid;
    }
    if let Some(valid_until) = until
        && now
            .checked_sub(skew)
            .is_some_and(|earliest| valid_until < earliest)
    {
        findings.push(error(FindingDetail::Expired {
            valid_until,
            now,
            skew_seconds,
        }));
        return Validity::Expired;
    }
    Validity::Current
}

/// XML Schema 1.1 Part 2 §3.4.28's `dateTimeStampLexicalRep`, assembled from the
/// fragment rules it names, numbered as there. Its Day-of-month Representations
/// constraint is checked after the match, by building the date.
const DATE_TIME_STAMP: &str = concat!(
    r"^(?P<year>-?(?:[1-9][0-9]{3,}|0[0-9]{3}))", // [56] yearFrag
    r"-(?P<month>0[1-9]|1[0-2])",                 // [57] monthFrag
    r"-(?P<day>0[1-9]|[12][0-9]|3[01])",          // [58] dayFrag
    r"T(?:",
    r"(?P<hour>[01][0-9]|2[0-3])", // [59] hourFrag
    r":(?P<minute>[0-5][0-9])",    // [60] minuteFrag
    r":(?P<second>[0-5][0-9])(?:\.(?P<fraction>[0-9]+))?", // [61] secondFrag
    r"|(?P<end_of_day>24:00:00(?:\.0+)?)", // [62] endOfDayFrag
    r")",
    r"(?P<timezone>Z|[+-](?:(?:0[0-9]|1[0-3]):[0-5][0-9]|14:00))$", // [63] timezoneFrag
);

/// `None` only if the pattern does not compile, which a unit test rules out.
static DATE_TIME_STAMP_PATTERN: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(DATE_TIME_STAMP).ok());

/// Reads an XML Schema 1.1 `dateTimeStamp`, which VCDM 2.0 §4.9 requires of the
/// validity bounds (decided 2026-10-01; ARCHITECTURE §4). Fractional seconds beyond
/// nanoseconds are truncated; the lexical form is kept beside the result.
pub(crate) fn date_time_stamp(lexical: &str) -> Result<OffsetDateTime, DateTimeProblem> {
    let not_lexical = || DateTimeProblem::NotDateTimeStamp {
        valid_rfc3339: OffsetDateTime::parse(lexical, &Rfc3339).is_ok(),
    };
    let captures = DATE_TIME_STAMP_PATTERN
        .as_ref()
        .and_then(|pattern| pattern.captures(lexical))
        .ok_or_else(not_lexical)?;
    let group = |name| captures.name(name).map(|m| m.as_str());
    let field = |name| group(name).and_then(|s| s.parse::<u8>().ok());

    let year = group("year")
        .and_then(|y| y.parse::<i32>().ok())
        .filter(|y| (Date::MIN.year()..=Date::MAX.year()).contains(y))
        .ok_or(DateTimeProblem::Unrepresentable)?;
    let month = field("month")
        .and_then(|m| Month::try_from(m).ok())
        .ok_or_else(not_lexical)?;
    // Fails for a day the month does not have: the Day-of-month constraint.
    let date = field("day")
        .and_then(|day| Date::from_calendar_date(year, month, day).ok())
        .ok_or_else(not_lexical)?;

    let (date, time) = if group("end_of_day").is_some() {
        // [62]: the first instant of the next day.
        let next = date.next_day().ok_or(DateTimeProblem::Unrepresentable)?;
        (next, Time::MIDNIGHT)
    } else {
        let nanoseconds = group("fraction").map_or(0, |digits| {
            digits
                .bytes()
                .chain(std::iter::repeat(b'0'))
                .take(9)
                .fold(0u32, |n, d| n * 10 + u32::from(d.saturating_sub(b'0')))
        });
        let time = match (field("hour"), field("minute"), field("second")) {
            (Some(hour), Some(minute), Some(second)) => {
                Time::from_hms_nano(hour, minute, second, nanoseconds).ok()
            }
            _ => None,
        };
        (date, time.ok_or_else(not_lexical)?)
    };

    let offset = match group("timezone") {
        Some("Z") => UtcOffset::UTC,
        Some(zone) => {
            let (negative, unsigned) = match zone.strip_prefix('-') {
                Some(unsigned) => (true, unsigned),
                None => (false, zone.strip_prefix('+').unwrap_or(zone)),
            };
            let parsed = unsigned.split_once(':').and_then(|(hours, minutes)| {
                Some((hours.parse::<i8>().ok()?, minutes.parse::<i8>().ok()?))
            });
            let (hours, minutes) = parsed.ok_or_else(not_lexical)?;
            let sign = if negative { -1 } else { 1 };
            UtcOffset::from_hms(sign * hours, sign * minutes, 0).map_err(|_| not_lexical())?
        }
        None => return Err(not_lexical()),
    };
    Ok(OffsetDateTime::new_in_offset(date, time, offset))
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    #[test]
    fn the_date_time_stamp_pattern_compiles() {
        assert!(DATE_TIME_STAMP_PATTERN.is_some());
    }

    /// XML Schema's lexical space against RFC 3339's, one difference per case
    /// (DEVELOPMENT-PLAN.md, milestone 1, known input 5). `time`'s RFC 3339 parser
    /// is the reference for `valid_rfc3339`.
    #[test]
    fn follows_xml_schema_where_it_differs_from_rfc_3339() {
        let rfc3339_only = |s| DateTimeProblem::NotDateTimeStamp {
            valid_rfc3339: OffsetDateTime::parse(s, &Rfc3339).is_ok(),
        };
        for (lexical, expected) in [
            // Both accept.
            ("2026-01-01T00:00:00Z", Ok(datetime!(2026-01-01 0:00 UTC))),
            (
                "2026-01-01T00:00:00.5+14:00",
                Ok(datetime!(2026-01-01 0:00:00.5 +14:00)),
            ),
            ("0000-01-01T00:00:00Z", Ok(datetime!(0000-01-01 0:00 UTC))),
            // RFC 3339 accepts, XML Schema does not.
            (
                "2026-01-01t00:00:00z",
                Err(rfc3339_only("2026-01-01t00:00:00z")),
            ),
            (
                "2026-01-01 00:00:00Z",
                Err(rfc3339_only("2026-01-01 00:00:00Z")),
            ),
            (
                "2016-12-31T23:59:60Z",
                Err(rfc3339_only("2016-12-31T23:59:60Z")),
            ),
            (
                "2026-01-01T00:00:00+23:59",
                Err(rfc3339_only("2026-01-01T00:00:00+23:59")),
            ),
            // XML Schema accepts, RFC 3339 does not.
            ("2026-12-31T24:00:00Z", Ok(datetime!(2027-01-01 0:00 UTC))),
            ("-0001-01-01T00:00:00Z", Ok(datetime!(-0001-01-01 0:00 UTC))),
            (
                "12026-01-01T00:00:00Z",
                Err(DateTimeProblem::Unrepresentable),
            ),
            // Neither accepts.
            (
                "2026-02-30T00:00:00Z",
                Err(DateTimeProblem::NotDateTimeStamp {
                    valid_rfc3339: false,
                }),
            ),
            (
                "2026-01-01T00:00:00",
                Err(DateTimeProblem::NotDateTimeStamp {
                    valid_rfc3339: false,
                }),
            ),
            (
                "02026-01-01T00:00:00Z",
                Err(DateTimeProblem::NotDateTimeStamp {
                    valid_rfc3339: false,
                }),
            ),
        ] {
            assert_eq!(date_time_stamp(lexical), expected, "{lexical}");
        }
    }

    #[test]
    fn the_rfc_3339_only_cases_are_valid_rfc_3339() {
        for lexical in [
            "2026-01-01t00:00:00z",
            "2026-01-01 00:00:00Z",
            "2016-12-31T23:59:60Z",
            "2026-01-01T00:00:00+23:59",
        ] {
            assert_eq!(
                date_time_stamp(lexical),
                Err(DateTimeProblem::NotDateTimeStamp {
                    valid_rfc3339: true
                }),
                "{lexical}"
            );
        }
    }

    #[test]
    fn keeps_nanoseconds_and_truncates_beyond() {
        assert_eq!(
            date_time_stamp("2026-01-01T00:00:00.1234567891Z"),
            Ok(datetime!(2026-01-01 0:00:00.123456789 UTC))
        );
    }

    #[test]
    fn names_url_errors_and_corrections() {
        assert_eq!(
            parse_url("acme"),
            Err(String::from("relative_url_without_base"))
        );
        assert_eq!(parse_url("did:key:z6Mk"), Ok(Vec::new()));
        assert_eq!(
            parse_url(" https://example.com"),
            Ok(vec![String::from("c0_space_ignored")])
        );
        assert_eq!(
            parse_url("https:example.com"),
            Ok(vec![String::from("expected_double_slash")])
        );
    }
}
