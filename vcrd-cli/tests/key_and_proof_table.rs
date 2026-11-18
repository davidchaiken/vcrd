//! ARCHITECTURE §8's key and proof table against vcrd, for the rows without a
//! caller-supplied key, each without the embedded key's opt-in and with it. The test
//! reads the table, so that the table and vcrd cannot disagree unnoticed, and names an
//! input for each such row.

#[cfg(test)]
mod support;

use std::fs;

use serde_json::{Value, json};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");

/// The input for each row without a caller-supplied key, by the row's EIC, E=I, E? and
/// I?. The row whose embedded proof is correct names an issuer whose key vcrd cannot
/// obtain, so that with the opt-in nothing else stops verify from passing.
const INPUTS: &[(&str, &str)] = &[
    ("000 — — —", "fixtures/issuer-missing.jwt"),
    ("010 — — Y", "examples/ed25519.jwt"),
    ("010 — — N", "fixtures/tampered-claim.jwt"),
    ("100 — Y —", "fixtures/embedded-jwk-https-issuer.jwt"),
    ("100 — N —", "fixtures/embedded-jwk-only-tampered.jwt"),
    ("110 Y Y Y", "fixtures/embedded-jwk-same.jwt"),
    ("110 Y N N", "fixtures/embedded-jwk-same-tampered.jwt"),
    ("110 N Y N", "fixtures/embedded-jwk.jwt"),
    ("110 N N Y", "fixtures/embedded-jwk-issuer-signed.jwt"),
    ("110 N N N", "fixtures/embedded-jwk-tampered.jwt"),
];

#[test]
fn vcrd_agrees_with_every_row_without_a_caller_supplied_key() {
    let architecture = fs::read_to_string(format!("{ROOT}/ARCHITECTURE.md")).unwrap();
    // The rows after the header, less the delimiter row. That the rows are every
    // combination the table describes is `vcrd-core`'s test of `keys::decide`.
    let rows: Vec<Vec<&str>> = architecture
        .lines()
        .skip_while(|l| !l.starts_with("| EIC |"))
        .skip(1)
        .take_while(|l| l.starts_with('|'))
        .filter(|l| !l.starts_with("|---"))
        .map(|l| l.trim_matches('|').split('|').map(str::trim).collect())
        .collect();
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
        for opt_in in [false, true] {
            let mut command = support::vcrd();
            command
                .args(["verify", &format!("{ROOT}/{input}"), "--now", support::NOW])
                .args(["--format", "json"]);
            if opt_in {
                command.arg("--allow-embedded-key");
            }
            let output = command.output().unwrap();
            let out: Value = serde_json::from_slice(&output.stdout).unwrap();
            let context = format!("row {key} ({situation}), {input}, opt-in {opt_in}: {out}");
            let proof = &out["proofs"][0];
            let provenance = &proof["key_provenance"];
            let keys = provenance["keys"].as_array().unwrap();
            let with = |kind: &str| {
                keys.iter()
                    .position(|k| k["kinds"].as_array().unwrap().contains(&json!(kind)))
            };
            let (embedded, issuer) = (with("credential_embedded"), with("issuer_identifier"));
            let present = |i: usize| eic.chars().nth(i) == Some('1');
            let (has_embedded, has_issuer) = (present(0), present(1));

            assert_eq!(embedded.is_some(), has_embedded, "{context}");
            assert_eq!(issuer.is_some(), has_issuer, "{context}");
            // Two kinds that are the same key are one entry.
            if has_embedded && has_issuer {
                assert_eq!(embedded == issuer, same == "Y", "{context}");
            }
            if let Some(e) = embedded {
                assert_eq!(keys[e]["proof"], correct(embedded_proof), "{context}");
            }
            // Without a caller-supplied key or the override, the issuer key decides,
            // and the embedded key alone only with the opt-in.
            let embedded_decides = !has_issuer && opt_in;
            let deciding = if has_issuer {
                issuer
            } else {
                embedded.filter(|_| embedded_decides)
            };
            assert_eq!(
                provenance.get("deciding"),
                deciding.map(Value::from).as_ref(),
                "{context}"
            );
            let outcome = match (has_issuer, embedded.filter(|_| embedded_decides)) {
                (true, _) => correct(issuer_proof),
                (false, Some(_)) => correct(embedded_proof),
                (false, None) => "not_attempted",
            };
            assert_eq!(proof["outcome"], outcome, "{context}");
            if let Some(e) = embedded.filter(|_| !has_issuer && !opt_in) {
                assert_eq!(keys[e]["refused"], "embedded_key_alone", "{context}");
            }
            let permitted = success == "Y" || (success == "E" && opt_in);
            assert_eq!(output.status.code() == Some(0), permitted, "{context}");

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
            // An embedded key that does not decide, with a correct proof.
            let uncounted =
                has_embedded && embedded != issuer && !embedded_decides && embedded_proof == "Y";
            assert_eq!(
                has(&out, "verify.non_deciding_key_proof_correct"),
                uncounted && !substituted,
                "{context}"
            );
        }
    }
}
