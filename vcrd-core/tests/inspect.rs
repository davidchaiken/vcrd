//! The inspect phase: conformance to VCDM 2.0 (the Verifiable Credentials Data Model)
//! and VC-JOSE-COSE, without cryptography (REQUIREMENTS §4), and the one inspect
//! failure that blocks verify (REQUIREMENTS §4, §16 item 20).

use serde_json::{Value, json};
use vcrd_core::{
    Attribution, BlockReason, Blocked, Check, CritProblem, FindingDetail, IssLocation,
    KeySourceKind, Missing, NotEvaluated, NotEvaluatedReason, Phase, PhaseOutcome, Severity,
    Validity,
};

use support::{
    codes, example_parts, inspect_token, inspected, token, token_text, verify_token, with_header,
    with_member, with_payload,
};

/// In a `#[cfg(test)]` module so that the workspace's panic lints exempt it, as
/// they do test functions (docs/reviews/milestone-0.md, gap 1).
#[cfg(test)]
mod support {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::Value;
    use time::macros::datetime;
    use vcrd_core::{
        Attribution, Context, FixedClock, Registry, Report, Severity, inspect, verify,
    };

    fn example() -> String {
        std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../examples/ed25519.jwt"
        ))
        .unwrap()
    }

    /// The curated example's header and payload, decoded.
    pub fn example_parts() -> (Value, Value) {
        let example = example();
        let [header, payload, _] = example.split('.').collect::<Vec<_>>()[..] else {
            panic!("three segments")
        };
        let decode = |s: &str| serde_json::from_slice(&URL_SAFE_NO_PAD.decode(s).unwrap());
        (decode(header).unwrap(), decode(payload).unwrap())
    }

    /// A compact JWS with this header and payload and the example's signature, which
    /// no longer verifies; inspect does not look at it.
    pub fn token(header: &Value, payload: &Value) -> Vec<u8> {
        token_text(&header.to_string(), &payload.to_string())
    }

    /// As [`token`], from JSON text, which can repeat a member name.
    pub fn token_text(header: &str, payload: &str) -> Vec<u8> {
        let example = example();
        let signature = example.rsplit('.').next().unwrap();
        let encode = |s: &str| URL_SAFE_NO_PAD.encode(s);
        format!("{}.{}.{signature}", encode(header), encode(payload)).into_bytes()
    }

    fn ctx() -> Context {
        Context::builder(FixedClock(datetime!(2026-10-01 0:00 UTC))).build()
    }

    pub fn inspect_token(bytes: &[u8]) -> Report {
        inspect(bytes, &ctx(), &Registry::builtin())
    }

    pub fn verify_token(bytes: &[u8]) -> Report {
        verify(bytes, &ctx(), &Registry::builtin())
    }

    /// Inspect's findings as (code, attribution, severity).
    pub fn inspected(report: &Report) -> Vec<(&'static str, Attribution, Severity)> {
        report
            .inspect
            .findings()
            .iter()
            .map(|f| (f.code, f.attribution, f.severity))
            .collect()
    }

    /// The example with one payload member replaced, or removed when `value` is `None`.
    pub fn with_member(name: &str, value: Option<Value>) -> Vec<u8> {
        let (header, mut payload) = example_parts();
        match value {
            Some(value) => payload[name] = value,
            None => {
                payload.as_object_mut().unwrap().remove(name);
            }
        }
        token(&header, &payload)
    }

    /// Inspect's finding codes.
    pub fn codes(report: &Report) -> Vec<&'static str> {
        report.inspect.findings().iter().map(|f| f.code).collect()
    }

    /// The example with its header changed by `edit`.
    pub fn with_header(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
        let (mut header, payload) = example_parts();
        edit(&mut header);
        token(&header, &payload)
    }

    /// The example with its payload changed by `edit`.
    pub fn with_payload(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
        let (header, mut payload) = example_parts();
        edit(&mut payload);
        token(&header, &payload)
    }
}

const ISSUER_INVALID: (&str, Attribution, Severity) = (
    "inspect.issuer_invalid",
    Attribution::Input,
    Severity::Error,
);

// [S3]: VCDM 2.0 §4.9 requires validUntil to be the same as or later than validFrom.
#[test]
fn valid_until_before_valid_from_is_an_error() {
    let (header, mut payload) = example_parts();
    payload["validFrom"] = json!("2027-01-01T00:00:00Z");
    payload["validUntil"] = json!("2026-01-01T00:00:00Z");
    let report = inspect_token(&token(&header, &payload));
    assert!(
        inspected(&report).contains(&(
            "inspect.valid_until_before_valid_from",
            Attribution::Input,
            Severity::Error
        )),
        "{:?}",
        inspected(&report)
    );
}

// [S4]: VCDM 2.0 §4.7 requires the issuer to be a URL, or an object whose `id` is a
// URL. Each malformed form is attributed to the input, and blocks verify: there is
// no issuer identifier to derive a key from.
#[test]
fn an_issuer_that_is_not_a_url_is_an_input_error_that_blocks_verify() {
    for issuer in [
        json!("acme"),
        json!({"name": "Acme"}),
        json!({"id": "acme"}),
        json!(42),
        json!(["did:example:issuer"]),
    ] {
        let report = verify_token(&with_member("issuer", Some(issuer.clone())));
        assert!(
            inspected(&report).contains(&ISSUER_INVALID),
            "{issuer}: {:?}",
            inspected(&report)
        );
        assert!(
            matches!(report.verify, PhaseOutcome::NotReached(_)),
            "{issuer}: {:?}",
            report.verify
        );
    }
}

/// A well-formed issuer vcrd cannot resolve is not an inspect finding: verify runs,
/// and fails attributed to vcrd.
#[test]
fn a_url_issuer_vcrd_cannot_resolve_reaches_verify() {
    let report = verify_token(&with_member(
        "issuer",
        Some(json!("https://university.example/issuers/565049")),
    ));
    assert!(
        !inspected(&report)
            .iter()
            .any(|(code, ..)| code.contains("issuer"))
    );
    let codes: Vec<_> = report.verify.findings().iter().map(|f| f.code).collect();
    assert!(
        codes.contains(&"verify.issuer_method_unsupported"),
        "{codes:?}"
    );
}

/// VCDM 2.0 §4.7: a credential MUST have an issuer. Attributed to the input, not to
/// the environment, and verify is blocked rather than failed.
#[test]
fn a_missing_issuer_is_an_input_error_that_blocks_verify() {
    let report = verify_token(&with_member("issuer", None));
    assert!(
        inspected(&report).contains(&(
            "inspect.issuer_missing",
            Attribution::Input,
            Severity::Error
        )),
        "{:?}",
        inspected(&report)
    );
    assert!(
        matches!(report.verify, PhaseOutcome::NotReached(_)),
        "{:?}",
        report.verify
    );
}

// [S5]: VCDM 2.0 §4.8 requires each subject to be the subject of one or more claims.
// An empty subject is present, so it is not reported as missing.
#[test]
fn an_empty_subject_is_its_own_error() {
    for subject in [json!({}), json!([])] {
        let report = inspect_token(&with_member("credentialSubject", Some(subject.clone())));
        let found = inspected(&report);
        assert!(
            found.contains(&(
                "inspect.credential_subject_empty",
                Attribution::Input,
                Severity::Error
            )),
            "{subject}: {found:?}"
        );
        assert!(
            !found
                .iter()
                .any(|(code, ..)| *code == "inspect.credential_subject_missing"),
            "{subject}: {found:?}"
        );
    }
}

/// The curated example conforms: no inspect finding of any severity.
#[test]
fn the_example_conforms() {
    let (header, payload) = example_parts();
    let report = inspect_token(&token(&header, &payload));
    assert_eq!(inspected(&report), [], "{report:?}");
    assert_eq!(
        report.not_evaluated,
        [
            NotEvaluated {
                what: Check::IssuerAccreditation,
                why: NotEvaluatedReason::OutOfScope,
            },
            NotEvaluated {
                what: Check::ContextResolution,
                why: NotEvaluatedReason::NotImplemented,
            },
        ]
    );
}

/// The structure of a block (REQUIREMENTS §16 item 20): which phase, which reason,
/// what is missing, and where vcrd looked. The findings are the blocking phase's own.
#[test]
fn a_block_names_what_is_missing_and_why() {
    let report = verify_token(&with_member("issuer", None));
    let PhaseOutcome::NotReached(blocked) = &report.verify else {
        panic!("{:?}", report.verify)
    };
    let Blocked { by, reason } = blocked;
    assert_eq!(*by, Phase::Inspect);
    assert_eq!(
        *reason,
        BlockReason::Impossible {
            missing: Missing::KeyMaterial {
                consulted: vec![KeySourceKind::IssuerIdentifier]
            }
        }
    );
    assert!(report.inspect.is_failed());
}

#[test]
fn a_parse_failure_blocks_for_want_of_a_document() {
    let report = verify_token(b"not.a.jws");
    let PhaseOutcome::NotReached(blocked) = &report.verify else {
        panic!("{:?}", report.verify)
    };
    assert_eq!(blocked.by, Phase::Parse);
    assert_eq!(
        blocked.reason,
        BlockReason::Impossible {
            missing: Missing::Document
        }
    );
}

/// An inspect failure that leaves the issuer usable does not block verify
/// (REQUIREMENTS §4): the signature is still reported.
#[test]
fn other_inspect_failures_do_not_block_verify() {
    let report = verify_token(&with_member("credentialSubject", Some(json!({}))));
    assert!(report.inspect.is_failed());
    assert!(
        matches!(report.verify, PhaseOutcome::Failed { .. }),
        "{:?}",
        report.verify
    );
}

/// VCDM 2.0 §4.3.
#[test]
fn checks_contexts() {
    let cases = [
        (None, vec!["inspect.context_missing"]),
        (
            Some(json!(["https://www.w3.org/2018/credentials/v1"])),
            vec!["inspect.context_first_invalid"],
        ),
        (Some(json!([])), vec!["inspect.context_first_invalid"]),
        (
            Some(json!(["https://www.w3.org/ns/credentials/v2", 7])),
            vec!["inspect.context_entry_invalid"],
        ),
        (
            Some(json!(["https://www.w3.org/ns/credentials/v2", "examples"])),
            vec!["inspect.url_invalid"],
        ),
        // One value, or an array (VCDM 2.0 §6); objects are allowed after the first.
        (Some(json!("https://www.w3.org/ns/credentials/v2")), vec![]),
        (
            Some(
                json!(["https://www.w3.org/ns/credentials/v2", {"@vocab": "https://example.org/#"}]),
            ),
            vec![],
        ),
    ];
    for (context, expected) in cases {
        let report = inspect_token(&with_member("@context", context.clone()));
        assert_eq!(codes(&report), expected, "{context:?}");
    }
}

#[test]
fn the_first_context_is_shown_when_it_is_wrong() {
    let report = inspect_token(&with_member(
        "@context",
        Some(json!(["https://www.w3.org/2018/credentials/v1"])),
    ));
    let detail = &report.inspect.findings()[0].detail;
    assert!(
        matches!(detail, FindingDetail::ContextFirstInvalid { found: Some(f) }
            if f == "https://www.w3.org/2018/credentials/v1"),
        "{detail:?}"
    );
}

/// VCDM 2.0 §4.5, including the other objects its table requires to have a type.
#[test]
fn checks_types() {
    for (edit, expected) in [
        (
            json!({"type": null}),
            vec![
                "inspect.type_not_string",
                "inspect.type_lacks_verifiable_credential",
            ],
        ),
        (json!({"type": []}), vec!["inspect.type_missing"]),
        (
            json!({"type": ["ExampleDegreeCredential"]}),
            vec!["inspect.type_lacks_verifiable_credential"],
        ),
        (json!({"type": "VerifiableCredential"}), vec![]),
        (
            json!({"credentialStatus": {"id": "https://example.org/status/1"}}),
            vec!["inspect.type_missing"],
        ),
        (
            json!({"evidence": [{"type": "Evidence"}, {"id": "https://example.org/e/2"}]}),
            vec!["inspect.type_missing"],
        ),
    ] {
        let report = inspect_token(&with_payload(|p| {
            for (name, value) in edit.as_object().unwrap() {
                p[name] = value.clone();
            }
        }));
        assert_eq!(codes(&report), expected, "{edit}");
    }
    let report = inspect_token(&with_member("type", None));
    assert_eq!(codes(&report), ["inspect.type_missing"]);
    let report = inspect_token(&with_member(
        "evidence",
        Some(json!([{"type": "Evidence"}, {"id": "https://example.org/e/2"}])),
    ));
    let detail = &report.inspect.findings()[0].detail;
    assert!(
        matches!(detail, FindingDetail::TypeMissing { path } if path == "evidence[1].type"),
        "{detail:?}"
    );
}

/// A URL the parser had to correct is usable, with a warning; the issuer still
/// reaches verify. (The example's `did:key` `kid` also draws `kid_without_thumbprint`
/// under an issuer that is not a DID.)
#[test]
fn a_nonconforming_issuer_url_is_a_warning() {
    let report = verify_token(&with_member(
        "issuer",
        Some(json!(" https://university.example/issuers/565049")),
    ));
    assert!(!report.inspect.is_failed(), "{:?}", inspected(&report));
    assert_eq!(
        inspected(&report)[0],
        (
            "inspect.url_nonconforming",
            Attribution::Input,
            Severity::Warning
        )
    );
    let detail = &report.inspect.findings()[0].detail;
    assert!(
        matches!(detail, FindingDetail::UrlNonconforming { path, violations }
            if path == "issuer" && violations == &["c0_space_ignored"]),
        "{detail:?}"
    );
    assert!(!matches!(report.verify, PhaseOutcome::NotReached(_)));
}

/// VCDM 2.0 §4.4 and §4.8. The values are claims, so findings carry paths only.
#[test]
fn checks_subjects_and_identifiers() {
    for (name, value, expected) in [
        (
            "credentialSubject",
            None,
            vec!["inspect.credential_subject_missing"],
        ),
        (
            "credentialSubject",
            Some(json!("did:example:alice")),
            vec!["inspect.credential_subject_invalid"],
        ),
        (
            "credentialSubject",
            Some(json!({"id": "did:example:alice"})),
            vec!["inspect.credential_subject_no_claims"],
        ),
        (
            "credentialSubject",
            Some(json!({"id": "alice", "name": "Alice"})),
            vec!["inspect.url_invalid"],
        ),
        (
            "credentialSubject",
            Some(json!([{"name": "Alice"}, {"name": "Bob"}])),
            vec![],
        ),
        ("id", Some(json!("0d4a1f3e")), vec!["inspect.url_invalid"]),
        ("id", Some(json!(7)), vec!["inspect.url_invalid"]),
    ] {
        let report = inspect_token(&with_member(name, value.clone()));
        assert_eq!(codes(&report), expected, "{name}: {value:?}");
    }
    let report = inspect_token(&with_member(
        "credentialSubject",
        Some(json!({"id": "did:example:alice"})),
    ));
    assert_eq!(report.inspect.findings()[0].severity, Severity::Warning);
    let report = inspect_token(&with_member("id", Some(json!(7))));
    let detail = &report.inspect.findings()[0].detail;
    assert!(
        matches!(detail, FindingDetail::UrlInvalid { path, error } if path == "id" && error == "not_a_string"),
        "{detail:?}"
    );
}

/// VCDM 2.0 §4.9: XML Schema `dateTimeStamp` values (ARCHITECTURE §4).
#[test]
fn checks_validity_bounds_as_date_time_stamps() {
    let report = inspect_token(&with_member(
        "validFrom",
        Some(json!("2026-01-01t00:00:00z")),
    ));
    assert_eq!(
        inspected(&report),
        [(
            "inspect.date_time_invalid",
            Attribution::Input,
            Severity::Error
        )]
    );
    assert!(matches!(
        report.inspect.findings()[0].detail,
        FindingDetail::DateTimeInvalid {
            valid_rfc3339: true,
            ..
        }
    ));
    let PhaseOutcome::Failed { output, .. } = &report.inspect else {
        panic!()
    };
    assert_eq!(output.validity, Validity::Unknown);

    let report = inspect_token(&with_member(
        "validUntil",
        Some(json!("12031-01-01T00:00:00Z")),
    ));
    assert_eq!(
        inspected(&report),
        [(
            "inspect.date_time_unrepresentable",
            Attribution::Vcrd,
            Severity::Error
        )]
    );

    let report = inspect_token(&with_member("validFrom", Some(json!(1767225600))));
    assert!(matches!(
        report.inspect.findings()[0].detail,
        FindingDetail::DateTimeInvalid {
            valid_rfc3339: false,
            ..
        }
    ));
}

/// VC-JOSE-COSE §3.1.1, compared as RFC 7515 §4.1.9 compares media types.
#[test]
fn checks_typ_and_cty() {
    for (typ, expected) in [
        (Some(json!("application/VC+JWT")), vec![]),
        (Some(json!("JWT")), vec!["inspect.typ_unexpected"]),
        (None, vec!["inspect.typ_unexpected"]),
    ] {
        let report = inspect_token(&with_header(|h| match &typ {
            Some(typ) => h["typ"] = typ.clone(),
            None => {
                h.as_object_mut().unwrap().remove("typ");
            }
        }));
        assert_eq!(codes(&report), expected, "{typ:?}");
    }
    let report = inspect_token(&with_header(|h| h["cty"] = json!("json")));
    assert_eq!(
        inspected(&report),
        [(
            "inspect.cty_unexpected",
            Attribution::Input,
            Severity::Warning
        )]
    );
    let report = inspect_token(&with_header(|h| {
        h.as_object_mut().unwrap().remove("cty");
    }));
    assert_eq!(codes(&report), Vec::<&str>::new());
}

/// RFC 7515 §4.1.11's rules for the value of `crit`.
#[test]
fn checks_the_form_of_crit() {
    let problem = |crit: Value, extra: Option<(&str, Value)>| {
        let report = inspect_token(&with_header(|h| {
            h["crit"] = crit;
            if let Some((name, value)) = extra {
                h[name] = value;
            }
        }));
        report
            .inspect
            .findings()
            .iter()
            .map(|f| match &f.detail {
                FindingDetail::CritInvalid { problem } => problem.clone(),
                other => panic!("{other:?}"),
            })
            .collect::<Vec<_>>()
    };
    let name = |s: &str| s.to_owned();
    assert_eq!(problem(json!("b64"), None), [CritProblem::NotArray]);
    assert_eq!(problem(json!([]), None), [CritProblem::Empty]);
    assert_eq!(
        problem(json!([1]), None),
        [CritProblem::NotString { index: 0 }]
    );
    assert_eq!(
        problem(json!(["alg"]), None),
        [CritProblem::Registered { name: name("alg") }]
    );
    assert_eq!(
        problem(json!(["exp"]), None),
        [CritProblem::NotInHeader { name: name("exp") }]
    );
    assert_eq!(
        problem(json!(["b64", "b64"]), Some(("b64", json!(false)))),
        [CritProblem::Duplicate { name: name("b64") }]
    );
    // Well-formed: whether vcrd implements `b64` is verify's question.
    assert_eq!(problem(json!(["b64"]), Some(("b64", json!(false)))), []);
}

/// RFC 7515 §4 and RFC 7519 §4: each repeated name is an error, in either segment.
#[test]
fn reports_each_duplicate_member_name() {
    let (header, payload) = example_parts();
    let header = header.to_string().replacen('{', r#"{"alg":"none","#, 1);
    let payload = payload
        .to_string()
        .replacen('{', r#"{"type":"Other","type":"Another","#, 1);
    let report = verify_token(&token_text(&header, &payload));
    let duplicates: Vec<_> = report
        .inspect
        .findings()
        .iter()
        .filter_map(|f| match &f.detail {
            FindingDetail::DuplicateName {
                segment,
                path,
                count,
            } => Some((*segment, path.as_str(), *count)),
            _ => None,
        })
        .collect();
    assert_eq!(
        duplicates,
        [
            (Some(vcrd_core::JwsSegment::Header), "alg", 2),
            (Some(vcrd_core::JwsSegment::Payload), "type", 3),
        ]
    );
    // The last value is the one used: verify runs with `EdDSA`, not `none`.
    assert!(
        !matches!(report.verify, PhaseOutcome::NotReached(_)),
        "{:?}",
        report.verify
    );
    assert_eq!(
        report.verify.output().unwrap().proofs[0]
            .algorithm
            .as_deref(),
        Some("EdDSA")
    );
}

/// VCDM 1.1's JWT encoding is named and attributed to vcrd (ARCHITECTURE §10 [F2]);
/// VCDM 2.0's checks, which it fails by construction, are not run.
#[test]
fn names_the_vcdm_1_1_jwt_encoding() {
    let (header, payload) = example_parts();
    let issuer = payload["issuer"].clone();
    let v1 = json!({
        "iss": issuer,
        "nbf": 1767225600,
        "jti": "urn:uuid:0d4a1f3e-6c2b-4e8a-9b1d-2f7c5a3e8b90",
        "sub": "did:example:alice",
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "credentialSubject": {"degree": {"type": "ExampleBachelorDegree"}},
        },
    });
    let report = verify_token(&token(&header, &v1));
    assert_eq!(
        inspected(&report),
        [(
            "inspect.vcdm_1_1_jwt_encoding",
            Attribution::Vcrd,
            Severity::Error
        )]
    );
    assert_eq!(report.inspect.output().unwrap().profile, None);
    let PhaseOutcome::NotReached(blocked) = &report.verify else {
        panic!("{:?}", report.verify)
    };
    assert_eq!(blocked.by, Phase::Inspect);
}

/// VC-JOSE-COSE §3.1.3: `vc` beside a VCDM 2.0 payload is the input's error.
#[test]
fn a_vc_claim_beside_a_vcdm_2_0_payload_is_forbidden() {
    let report = inspect_token(&with_member("vc", Some(json!({}))));
    assert_eq!(
        inspected(&report),
        [(
            "inspect.jwt_claim_forbidden",
            Attribution::Input,
            Severity::Error
        )]
    );
}

/// VC-JOSE-COSE §4.1.2: `iss`, in the claims or the header, MUST match the issuer.
#[test]
fn iss_must_match_the_issuer() {
    let (header, payload) = example_parts();
    let issuer = payload["issuer"].as_str().unwrap().to_owned();

    let report = inspect_token(&with_member("iss", Some(json!(issuer.clone()))));
    assert_eq!(codes(&report), Vec::<&str>::new());

    let report = inspect_token(&with_member("iss", Some(json!("did:example:other"))));
    let detail = &report.inspect.findings()[0].detail;
    assert!(
        matches!(detail, FindingDetail::IssMismatch { location: IssLocation::Payload, iss: Some(iss), issuer: i }
            if iss == "did:example:other" && *i == issuer),
        "{detail:?}"
    );

    let mut header = header;
    header["iss"] = json!("did:example:other");
    let report = inspect_token(&token(&header, &payload));
    assert!(matches!(
        report.inspect.findings()[0].detail,
        FindingDetail::IssMismatch {
            location: IssLocation::Header,
            ..
        }
    ));
    assert_eq!(report.inspect.findings()[0].severity, Severity::Error);
}

/// VC-JOSE-COSE §3.1.3: a SHOULD, so warnings. The values are claims and stay out
/// of the finding and of `Debug`.
#[test]
fn jti_and_sub_should_not_conflict() {
    let report = inspect_token(&with_payload(|p| {
        p["jti"] = json!("urn:uuid:canary-jti-0001");
        p["sub"] = json!("did:example:canary-sub");
    }));
    assert_eq!(
        inspected(&report),
        [
            (
                "inspect.jwt_claim_conflict",
                Attribution::Input,
                Severity::Warning
            ),
            (
                "inspect.jwt_claim_conflict",
                Attribution::Input,
                Severity::Warning
            ),
        ]
    );
    let debug = format!("{report:?}");
    assert!(!debug.contains("canary"), "{debug}");

    // Equal values, and `sub` naming one of several subjects, agree.
    let report = inspect_token(&with_payload(|p| {
        p["jti"] = p["id"].clone();
        p["sub"] = json!("did:example:bob");
        p["credentialSubject"] = json!([
            {"id": "did:example:alice", "name": "Alice"},
            {"id": "did:example:bob", "name": "Bob"},
        ]);
    }));
    assert_eq!(codes(&report), Vec::<&str>::new());
}

/// VC-JOSE-COSE §4.1.1 and §4.2 for a `did:key` issuer.
#[test]
fn checks_kid_for_a_did_key_issuer() {
    let (_, payload) = example_parts();
    let issuer = payload["issuer"].as_str().unwrap().to_owned();
    let fragment = issuer.strip_prefix("did:key:").unwrap().to_owned();

    let report = inspect_token(&with_header(|h| {
        h.as_object_mut().unwrap().remove("kid");
    }));
    assert_eq!(
        inspected(&report),
        [("inspect.kid_missing", Attribution::Input, Severity::Error)]
    );

    // Relative, with `iss` absent: not absolute (§4.2), though it names the key.
    let report = inspect_token(&with_header(|h| h["kid"] = json!(format!("#{fragment}"))));
    assert_eq!(codes(&report), ["inspect.kid_not_absolute"]);

    // Relative, with `iss` present: resolved against the issuer, and accepted.
    let (mut header, mut payload) = example_parts();
    header["kid"] = json!(format!("#{fragment}"));
    payload["iss"] = json!(issuer.clone());
    let report = inspect_token(&token(&header, &payload));
    assert_eq!(codes(&report), Vec::<&str>::new());

    // Another key: foreign, with the expected identifier.
    let report = inspect_token(&with_header(|h| {
        h["kid"] = json!(format!("{issuer}#key-1"))
    }));
    let detail = &report.inspect.findings()[0].detail;
    assert!(
        matches!(detail, FindingDetail::KidForeign { expected: Some(e), .. }
            if *e == format!("{issuer}#{fragment}")),
        "{detail:?}"
    );
}

/// VC-JOSE-COSE §4.2 for an issuer whose URL is not a DID.
#[test]
fn checks_kid_for_a_url_issuer() {
    let url_issuer =
        |p: &mut Value| p["issuer"] = json!("https://university.example/issuers/565049");

    let report = inspect_token(&{
        let (mut header, mut payload) = example_parts();
        header.as_object_mut().unwrap().remove("kid");
        url_issuer(&mut payload);
        token(&header, &payload)
    });
    assert_eq!(codes(&report), ["inspect.kid_missing"]);

    let report = inspect_token(&{
        let (mut header, mut payload) = example_parts();
        header["kid"] = json!("https://university.example/issuers/565049#key-123");
        url_issuer(&mut payload);
        token(&header, &payload)
    });
    assert_eq!(
        inspected(&report),
        [(
            "inspect.kid_without_thumbprint",
            Attribution::Input,
            Severity::Warning
        )]
    );

    let report = inspect_token(&{
        let (mut header, mut payload) = example_parts();
        header["kid"] = json!(
            "https://vendor.example/issuers/42/keys/urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
        url_issuer(&mut payload);
        token(&header, &payload)
    });
    assert_eq!(codes(&report), Vec::<&str>::new());
}

/// Status and schemas are listed as not evaluated when present (REQUIREMENTS §12).
#[test]
fn lists_status_and_schema_as_not_evaluated() {
    let report = inspect_token(&with_payload(|p| {
        p["credentialStatus"] = json!({"type": "BitstringStatusListEntry"});
        p["credentialSchema"] = json!({"id": "https://example.org/schema", "type": "JsonSchema"});
    }));
    let not_evaluated: Vec<_> = report
        .not_evaluated
        .iter()
        .map(|n| (n.what, n.why))
        .collect();
    assert_eq!(
        not_evaluated,
        [
            (Check::IssuerAccreditation, NotEvaluatedReason::OutOfScope),
            (Check::ContextResolution, NotEvaluatedReason::NotImplemented),
            (Check::RevocationStatus, NotEvaluatedReason::NotImplemented),
            (Check::SchemaConformance, NotEvaluatedReason::NotImplemented),
        ]
    );
}
