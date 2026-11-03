//! ARCHITECTURE §8's key and proof table against vcrd, for the rows milestone 1 can
//! produce: those without a caller-supplied key. The test reads the table, so that the
//! table and vcrd cannot disagree unnoticed, and names an input for each such row.

#[cfg(test)]
mod support;

use std::fs;

use serde_json::Value;

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");

/// The input for each row milestone 1 can produce, by the row's EIC, E=I, E? and I?.
const INPUTS: &[(&str, &str)] = &[
    ("000 — — —", "fixtures/issuer-missing.jwt"),
    ("010 — — Y", "examples/ed25519.jwt"),
    ("010 — — N", "fixtures/tampered-claim.jwt"),
    ("100 — Y —", "fixtures/embedded-jwk-only.jwt"),
    ("100 — N —", "fixtures/embedded-jwk-only-tampered.jwt"),
    ("110 Y Y Y", "fixtures/embedded-jwk-same.jwt"),
    ("110 Y N N", "fixtures/embedded-jwk-same-tampered.jwt"),
    ("110 N Y N", "fixtures/embedded-jwk.jwt"),
    ("110 N N Y", "fixtures/embedded-jwk-issuer-signed.jwt"),
    ("110 N N N", "fixtures/embedded-jwk-tampered.jwt"),
];

#[test]
fn vcrd_agrees_with_every_row_milestone_1_can_produce() {
    let architecture = fs::read_to_string(format!("{ROOT}/ARCHITECTURE.md")).unwrap();
    let rows: Vec<Vec<&str>> = architecture
        .split_once("| EIC | E=I |")
        .unwrap()
        .1
        .lines()
        // The rest of the header row, then the delimiter row.
        .skip(2)
        .take_while(|l| l.starts_with('|'))
        .map(|l| l.trim_matches('|').split('|').map(str::trim).collect())
        .collect();
    assert_eq!(rows.len(), 37, "the table's rows");
    let produced: Vec<&Vec<&str>> = rows.iter().filter(|r| r[0].ends_with('0')).collect();
    assert_eq!(
        produced.len(),
        INPUTS.len(),
        "rows without a caller-supplied key"
    );

    let correct = |cell: &str| if cell == "Y" { "correct" } else { "incorrect" };
    let has = |out: &Value, code: &str| {
        out["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["code"] == code && f["severity"] == "warning")
    };
    for row in produced {
        let [
            eic,
            same,
            _,
            _,
            embedded_proof,
            issuer_proof,
            _,
            success,
            situation,
        ] = row[..]
        else {
            panic!("a row of nine cells: {row:?}")
        };
        let key = format!("{eic} {same} {embedded_proof} {issuer_proof}");
        let (_, input) = INPUTS
            .iter()
            .find(|(k, _)| *k == key)
            .unwrap_or_else(|| panic!("no input for the row {key} ({situation})"));
        let output = support::vcrd()
            .args(["verify", &format!("{ROOT}/{input}"), "--now", support::NOW])
            .args(["--format", "json"])
            .output()
            .unwrap();
        let out: Value = serde_json::from_slice(&output.stdout).unwrap();
        let context = format!("row {key} ({situation}), {input}: {out}");
        let proof = &out["proofs"][0];
        let provenance = &proof["key_provenance"];
        let embedded = provenance.get("embedded_key");
        let present = |i: usize| eic.chars().nth(i) == Some('1');
        let (has_embedded, has_issuer) = (present(0), present(1));

        assert_eq!(embedded.is_some(), has_embedded, "{context}");
        if let Some(embedded) = embedded {
            assert_eq!(embedded["proof"], correct(embedded_proof), "{context}");
            assert_eq!(
                embedded.get("same_as_issuer_key"),
                has_issuer.then(|| Value::Bool(same == "Y")).as_ref(),
                "{context}"
            );
        }
        if has_issuer {
            assert_eq!(provenance["source"], "issuer_identifier", "{context}");
            assert_eq!(proof["outcome"], correct(issuer_proof), "{context}");
        } else {
            assert!(provenance.get("source").is_none(), "{context}");
            assert_eq!(proof["outcome"], "not_attempted", "{context}");
        }
        // Milestone 1 has no opt-in, so P does not succeed either.
        assert_eq!(output.status.code() == Some(0), success == "Y", "{context}");

        // The findings that say what the keys and proofs show (docs/findings.md).
        let different = has_embedded && has_issuer && same == "N";
        assert_eq!(
            has(&out, "verify.embedded_key_mismatch"),
            different,
            "{context}"
        );
        let substituted = has_issuer && embedded_proof == "Y" && issuer_proof == "N";
        assert_eq!(
            has(&out, "verify.embedded_key_proof_correct"),
            substituted,
            "{context}"
        );
    }
}
