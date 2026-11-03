//! docs/findings.md documents every code `FindingDetail::code` returns, and no other
//! (DEVELOPMENT-PLAN.md, milestone 1).

use std::collections::BTreeSet;
use std::fs;

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
const PHASES: [&str; 3] = ["parse.", "inspect.", "verify."];

#[test]
fn the_finding_reference_documents_every_code_and_no_other() {
    let source = fs::read_to_string(format!("{ROOT}/vcrd-core/src/finding.rs")).unwrap();
    // The body of `FindingDetail::code`, whose string literals are the codes.
    let body = source
        .split_once("pub fn code(&self)")
        .unwrap()
        .1
        .split_once("\n    }\n")
        .unwrap()
        .0;
    let codes: BTreeSet<&str> = body.split('"').skip(1).step_by(2).collect();
    // Guards against reading the wrong text: two empty sets would agree.
    assert!(!codes.is_empty(), "no codes found in FindingDetail::code");
    for code in &codes {
        assert!(
            PHASES.iter().any(|p| code.starts_with(p)),
            "not a code: {code:?}"
        );
    }

    let reference = fs::read_to_string(format!("{ROOT}/docs/findings.md")).unwrap();
    let anchors: Vec<&str> = reference
        .split("<a id=\"")
        .skip(1)
        .filter_map(|rest| rest.split_once('"').map(|(id, _)| id))
        .filter(|id| PHASES.iter().any(|p| id.starts_with(p)))
        .collect();
    let documented: BTreeSet<&str> = anchors.iter().copied().collect();
    assert_eq!(anchors.len(), documented.len(), "a code documented twice");

    let missing: Vec<_> = codes.difference(&documented).collect();
    let absent: Vec<_> = documented.difference(&codes).collect();
    assert!(
        missing.is_empty() && absent.is_empty(),
        "add to docs/findings.md: {missing:?}; remove from it: {absent:?}"
    );
}
