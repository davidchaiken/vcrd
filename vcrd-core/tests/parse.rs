//! The parse phase: limits before the work they bound, strict segments, and what a
//! failed parse still reports (ARCHITECTURE §3, §4).

use vcrd_core::{
    Attribution, FindingDetail, FormatDetail, JwsJsonSyntax, JwsSegment, Limits, PhaseOutcome,
    Registry, Report, Severity, inspect,
};

use support::{at, b64, example, with_payload};

#[cfg(test)]
mod support {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use time::macros::datetime;
    use vcrd_core::{Context, FixedClock, Limits, Registry, Report, inspect};

    pub fn example() -> Vec<u8> {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../examples/ed25519.jwt"
        ))
        .unwrap()
    }

    pub fn b64(s: &str) -> String {
        URL_SAFE_NO_PAD.encode(s)
    }

    /// The example's header, with this payload and the example's signature.
    pub fn with_payload(payload: &str) -> Vec<u8> {
        let example = String::from_utf8(example()).unwrap();
        let [header, _, signature] = example.split('.').collect::<Vec<_>>()[..] else {
            panic!("three segments")
        };
        format!("{header}.{}.{signature}", b64(payload)).into_bytes()
    }

    pub fn at(limits: Limits, bytes: &[u8]) -> Report {
        let ctx = Context::builder(FixedClock(datetime!(2026-10-01 0:00 UTC)))
            .limits(limits)
            .build();
        inspect(bytes, &ctx, &Registry::builtin())
    }
}

fn parse_findings(report: &Report) -> Vec<(&'static str, Attribution, Severity)> {
    report
        .parse
        .findings()
        .iter()
        .map(|f| (f.code, f.attribution, f.severity))
        .collect()
}

#[test]
fn reports_the_payload_depth() {
    let report = at(Limits::default(), &example());
    // The example's payload: object, credentialSubject, degree.
    assert_eq!(report.input.depth, Some(3));
}

/// A file that ends with a newline parses, and the result says what was ignored.
#[test]
fn accepts_trailing_whitespace_and_reports_it() {
    let mut bytes = example();
    bytes.extend_from_slice(b"\r\n \t");
    let report = at(Limits::default(), &bytes);
    assert!(
        matches!(report.parse, PhaseOutcome::Passed { .. }),
        "{report:?}"
    );
    assert_eq!(
        parse_findings(&report),
        [(
            "parse.trailing_whitespace",
            Attribution::Input,
            Severity::Info
        )]
    );
    assert!(matches!(
        report.parse.findings()[0].detail,
        FindingDetail::TrailingWhitespace { bytes: 4 }
    ));
}

#[test]
fn leading_whitespace_is_not_a_jws() {
    let mut bytes = b"\n".to_vec();
    bytes.extend(example());
    let report = at(Limits::default(), &bytes);
    assert_eq!(
        parse_findings(&report),
        [(
            "parse.no_format_matched",
            Attribution::Input,
            Severity::Error
        )]
    );
}

/// Checked before anything else, and attributed to the caller's policy.
#[test]
fn input_over_the_size_limit() {
    let bytes = example();
    let limits = Limits {
        max_bytes: bytes.len() - 1,
        ..Limits::default()
    };
    let report = at(limits, &bytes);
    assert_eq!(
        parse_findings(&report),
        [(
            "parse.input_too_large",
            Attribution::Policy,
            Severity::Error
        )]
    );
    assert!(matches!(
        report.parse.findings()[0].detail,
        FindingDetail::InputTooLarge { found, .. } if found == bytes.len()
    ));
    assert_eq!(report.input.format, None, "not detected");
    // One byte under the limit is accepted.
    let limits = Limits {
        max_bytes: bytes.len(),
        ..Limits::default()
    };
    assert!(matches!(
        at(limits, &bytes).parse,
        PhaseOutcome::Passed { .. }
    ));
}

#[test]
fn payload_over_the_depth_limit() {
    let report = at(
        Limits {
            max_depth: 2,
            ..Limits::default()
        },
        &example(),
    );
    assert_eq!(
        parse_findings(&report),
        [(
            "parse.nesting_too_deep",
            Attribution::Policy,
            Severity::Error
        )]
    );
    assert!(matches!(
        report.parse.findings()[0].detail,
        FindingDetail::NestingTooDeep {
            segment: Some(JwsSegment::Payload),
            limit: 2,
            found: 3
        }
    ));
    assert_eq!(report.input.depth, Some(3));
}

/// Flattening stops at the limit; what it reached is kept.
#[test]
fn more_claims_than_the_limit() {
    let report = at(
        Limits {
            max_claims: 3,
            ..Limits::default()
        },
        &example(),
    );
    assert_eq!(
        parse_findings(&report),
        [(
            "parse.too_many_claims",
            Attribution::Policy,
            Severity::Error
        )]
    );
    let document = report.parse.output().unwrap().document.as_ref().unwrap();
    assert_eq!(document.leaves.len(), 3);
}

#[test]
fn two_segments_is_not_a_compact_jws() {
    let report = at(
        Limits::default(),
        format!("{}.{}", b64("{}"), b64("{}")).as_bytes(),
    );
    assert!(matches!(
        report.parse.findings()[0].detail,
        FindingDetail::NotCompactJws { segments: 2 }
    ));
}

/// A bad payload does not hide the header, and every bad segment is reported.
#[test]
fn reports_every_bad_segment_and_keeps_the_good_ones() {
    let report = at(Limits::default(), &with_payload("not json"));
    assert_eq!(
        parse_findings(&report),
        [("parse.json_invalid", Attribution::Input, Severity::Error)]
    );
    let Some(FormatDetail::VcJose(detail)) = &report.parse.output().unwrap().detail else {
        panic!("{report:?}")
    };
    assert_eq!(
        detail.header.as_ref().unwrap().alg.as_deref(),
        Some("EdDSA")
    );
    assert!(detail.payload.is_none());

    let bytes = format!("{}.{}.{}", b64("[1]"), b64("\"s\""), "a=");
    let codes: Vec<_> = at(Limits::default(), bytes.as_bytes())
        .parse
        .findings()
        .iter()
        .map(|f| f.code)
        .collect();
    assert_eq!(
        codes,
        [
            "parse.json_not_object",
            "parse.json_not_object",
            "parse.base64url_invalid"
        ]
    );
}

/// Recognized and named rather than "no format matched" (VC-JOSE-COSE §3.1.1;
/// ARCHITECTURE §10 [F1]).
#[test]
fn jws_json_serialization_is_named_and_attributed_to_vcrd() {
    for (bytes, syntax) in [
        (
            r#"{"payload": "e30", "protected": "e30", "signature": "AA"}"#,
            JwsJsonSyntax::Flattened,
        ),
        (
            r#" {"payload": "e30", "signatures": [{"protected": "e30", "signature": "AA"}]}"#,
            JwsJsonSyntax::General,
        ),
    ] {
        let report = at(Limits::default(), bytes.as_bytes());
        assert_eq!(
            parse_findings(&report),
            [(
                "parse.jws_json_serialization",
                Attribution::Vcrd,
                Severity::Error
            )]
        );
        assert!(matches!(
            report.parse.findings()[0].detail,
            FindingDetail::JwsJsonSerialization { syntax: s } if s == syntax
        ));
    }
}

#[test]
fn json_that_merely_mentions_payload_and_signature_is_not_a_jws() {
    let report = at(
        Limits::default(),
        br#"{"credentialSubject": {"payload": 1, "signature": 2}}"#,
    );
    assert_eq!(
        parse_findings(&report),
        [("parse.json_not_jws", Attribution::Input, Severity::Error)]
    );
}

/// Minified JSON has no spaces, and its URLs have dots, but a compact JWS never
/// starts with `{`: a JSON credential is not mistaken for one.
#[test]
fn minified_json_is_not_taken_for_a_compact_jws() {
    let report = at(
        Limits::default(),
        br#"{"@context":["https://www.w3.org/ns/credentials/v2"],"type":"VerifiableCredential"}"#,
    );
    assert_eq!(
        parse_findings(&report),
        [(
            "parse.no_format_matched",
            Attribution::Input,
            Severity::Error
        )]
    );
}

#[test]
fn a_parse_failure_blocks_inspect() {
    let report = inspect(
        b"not a credential",
        &vcrd_core::Context::builder(vcrd_core::FixedClock(time::OffsetDateTime::UNIX_EPOCH))
            .build(),
        &Registry::builtin(),
    );
    let PhaseOutcome::NotReached(blocked) = &report.inspect else {
        panic!("{report:?}")
    };
    assert_eq!(blocked.by, vcrd_core::Phase::Parse);
}
