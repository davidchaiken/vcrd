//! docs/findings.md documents every check and every reason `not_evaluated` can name, and
//! no other: the names `vcrd-cli/src/view.rs` gives them, which JSON and `plain` print.

use std::collections::BTreeSet;
use std::fs;

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
const CHECK: &str = "not_evaluated.";
const REASON: &str = "not_evaluated.reason.";

#[test]
fn the_reference_documents_every_check_and_reason_and_no_other() {
    let source = fs::read_to_string(format!("{ROOT}/vcrd-cli/src/view.rs")).unwrap();
    // The string literals in the body of the function that begins so.
    let names = |signature: &str| {
        let body = source
            .split_once(signature)
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;
        let names: BTreeSet<&str> = body.split('"').skip(1).step_by(2).collect();
        // Guards against reading the wrong text: two empty sets would agree.
        assert!(!names.is_empty(), "no names found after {signature:?}");
        names
    };
    let checks = names("fn check(check: Check)");
    let reasons = names("fn reason(reason: NotEvaluatedReason)");

    let reference = fs::read_to_string(format!("{ROOT}/docs/findings.md")).unwrap();
    let anchors: Vec<&str> = reference
        .split("<a id=\"")
        .skip(1)
        .filter_map(|rest| rest.split_once('"').map(|(id, _)| id))
        .filter(|id| id.starts_with(CHECK))
        .collect();
    assert_eq!(
        anchors.len(),
        anchors.iter().collect::<BTreeSet<_>>().len(),
        "a name documented twice"
    );
    let documented_reasons: BTreeSet<&str> = anchors
        .iter()
        .filter_map(|id| id.strip_prefix(REASON))
        .collect();
    let documented_checks: BTreeSet<&str> = anchors
        .iter()
        .filter(|id| !id.starts_with(REASON))
        .filter_map(|id| id.strip_prefix(CHECK))
        .collect();

    for (kind, names, documented) in [
        ("check", &checks, &documented_checks),
        ("reason", &reasons, &documented_reasons),
    ] {
        let missing: Vec<_> = names.difference(documented).collect();
        let absent: Vec<_> = documented.difference(names).collect();
        assert!(
            missing.is_empty() && absent.is_empty(),
            "add to docs/findings.md, as a {kind}: {missing:?}; remove from it: {absent:?}"
        );
    }
}
