//! ARCHITECTURE §8's key and proof table against vcrd: every row, with each setting of the
//! two opt-ins, from inputs tests/support/generate.rs builds at run time
//! (DEVELOPMENT-PLAN.md, milestone 2, decided 2026-11-18 and 2026-11-25). The test reads
//! the table, so that the table and vcrd cannot disagree unnoticed.
//!
//! What it expects comes from the table's cells and from the rules, each written once
//! below with its source. Where the rules make an opt-in irrelevant to a row, it expects
//! the output with the opt-in to be the output without it, byte for byte.

#[cfg(test)]
mod support;

use helpers::{SETTINGS, check, rows, run, write_inputs};

#[test]
fn vcrd_agrees_with_every_row_of_the_key_and_proof_table() {
    let rows = rows();
    assert!(
        !rows.is_empty(),
        "no rows in ARCHITECTURE §8's key and proof table"
    );
    for (index, row) in rows.iter().enumerate() {
        let inputs = write_inputs(index, row);
        let runs: Vec<_> = SETTINGS.iter().map(|&o| run(&inputs, o)).collect();
        for (&opt_ins, output) in SETTINGS.iter().zip(&runs) {
            let context = format!(
                "row {} {} ({}), opt-ins {opt_ins:?}: {}",
                row.cells,
                row.success,
                row.situation,
                String::from_utf8_lossy(&output.stdout)
            );
            assert_eq!(output.code == 0, row.permitted(opt_ins), "{context}");
            let relevant = row.relevant(opt_ins);
            if relevant == opt_ins {
                check(row, opt_ins, output, &context);
                continue;
            }
            // The opt-in the rules make irrelevant to this row changes nothing.
            let without = SETTINGS.iter().position(|&o| o == relevant).unwrap();
            assert!(
                output.code == runs[without].code && output.stdout == runs[without].stdout,
                "{context}\ndiffers from the run with opt-ins {relevant:?}: {}",
                String::from_utf8_lossy(&runs[without].stdout)
            );
        }
    }
}

/// In a `#[cfg(test)]` module so that the workspace's panic lints exempt it, as they do
/// test functions (docs/reviews/milestone-0.md, gap 1).
#[cfg(test)]
mod helpers {
    use std::fs;
    use std::path::PathBuf;

    use serde_json::{Value, json};

    use super::support::generate::{TableRow, table_inputs};
    use super::support::{NOW, vcrd};

    const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");

    /// The settings of the opt-ins, as (`--allow-embedded-key`, `--allow-key-override`).
    pub type OptIns = (bool, bool);
    pub const SETTINGS: [OptIns; 4] = [(false, false), (true, false), (false, true), (true, true)];

    /// The kinds of key, in the order of the table's columns: E, I and C.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Kind {
        Embedded,
        Issuer,
        Caller,
    }

    const KINDS: [Kind; 3] = [Kind::Embedded, Kind::Issuer, Kind::Caller];

    /// The pairs of kinds whose equality the columns E=I, E=C and I=C give, in that order.
    const PAIRS: [(Kind, Kind); 3] = [
        (Kind::Embedded, Kind::Issuer),
        (Kind::Embedded, Kind::Caller),
        (Kind::Issuer, Kind::Caller),
    ];

    impl Kind {
        fn index(self) -> usize {
            match self {
                Kind::Embedded => 0,
                Kind::Issuer => 1,
                Kind::Caller => 2,
            }
        }

        /// Its value in `kinds` (docs/output.md).
        fn name(self) -> &'static str {
            match self {
                Kind::Embedded => "credential_embedded",
                Kind::Issuer => "issuer_identifier",
                Kind::Caller => "caller_supplied",
            }
        }
    }

    /// One row of the table: the distinct key each kind of key is, by index, when the row
    /// has it, and the distinct key whose proof is correct, if any.
    pub struct Row {
        /// The cells before S?, for messages.
        pub cells: String,
        pub success: String,
        pub situation: String,
        keys: [Option<usize>; 3],
        distinct: usize,
        correct: Option<usize>,
    }

    /// The table's rows, after its header and less the delimiter row. That they are every
    /// combination the table describes is `vcrd-core`'s test of `keys::decide`.
    pub fn rows() -> Vec<Row> {
        let architecture = fs::read_to_string(format!("{ROOT}/ARCHITECTURE.md")).unwrap();
        architecture
            .lines()
            .skip_while(|l| !l.starts_with("| EIC |"))
            .skip(1)
            .take_while(|l| l.starts_with('|'))
            .filter(|l| !l.starts_with("|---"))
            .map(|l| {
                let cells: Vec<&str> = l.trim_matches('|').split('|').map(str::trim).collect();
                row(&cells)
            })
            .collect()
    }

    fn row(cells: &[&str]) -> Row {
        let [
            eic,
            e_i,
            e_c,
            i_c,
            e_proof,
            i_proof,
            c_proof,
            success,
            situation,
        ] = cells[..]
        else {
            panic!("a row of nine cells: {cells:?}")
        };
        let present = |kind: Kind| eic.chars().nth(kind.index()) == Some('1');
        let same = [e_i, e_c, i_c];
        // Each present kind is an earlier kind's key when the row says the two are the
        // same key, and a new distinct key otherwise.
        let mut keys = [None; 3];
        let mut distinct = 0;
        for kind in KINDS.into_iter().filter(|&k| present(k)) {
            let earlier = PAIRS
                .iter()
                .zip(same)
                .find(|((a, b), cell)| *b == kind && *cell == "Y" && present(*a))
                .and_then(|((a, _), _)| keys[a.index()]);
            keys[kind.index()] = Some(earlier.unwrap_or_else(|| {
                distinct += 1;
                distinct - 1
            }));
        }
        let proofs = [e_proof, i_proof, c_proof];
        let correct = KINDS
            .into_iter()
            .find(|k| proofs[k.index()] == "Y")
            .and_then(|k| keys[k.index()]);
        Row {
            cells: cells[..cells.len() - 2].join(" "),
            success: success.to_owned(),
            situation: situation.to_owned(),
            keys,
            distinct,
            correct,
        }
    }

    impl Row {
        fn key(&self, kind: Kind) -> Option<usize> {
            self.keys[kind.index()]
        }

        /// Whether the row has both kinds and they are different keys.
        fn differ(&self, a: Kind, b: Kind) -> bool {
            matches!((self.key(a), self.key(b)), (Some(x), Some(y)) if x != y)
        }

        /// Whether the embedded key is the only key.
        fn embedded_alone(&self) -> bool {
            self.key(Kind::Embedded).is_some()
                && self.key(Kind::Issuer).is_none()
                && self.key(Kind::Caller).is_none()
        }

        /// Whether S? permits success with these opt-ins: Y, or E with the embedded
        /// key's opt-in, or C with the override (ARCHITECTURE §8).
        pub fn permitted(&self, (embedded, overriding): OptIns) -> bool {
            match self.success.as_str() {
                "Y" => true,
                "N" => false,
                "E" => embedded,
                "C" => overriding,
                other => panic!("S? is {other}"),
            }
        }

        /// The opt-ins that can matter to this row: the embedded key's only when that key
        /// is the only one (rule 2), and the override only when the caller-supplied key
        /// and the issuer key differ (rule 1). The rules read neither otherwise.
        pub fn relevant(&self, (embedded, overriding): OptIns) -> OptIns {
            (
                embedded && self.embedded_alone(),
                overriding && self.differ(Kind::Caller, Kind::Issuer),
            )
        }

        /// Rule 2 (ARCHITECTURE §8): the issuer key decides when it is present, and the
        /// caller-supplied key when the issuer key is not present or the caller has opted
        /// in to the override; the embedded key only when neither is present, and then
        /// only with the caller's opt-in.
        fn deciding(&self, (embedded, overriding): OptIns) -> Option<Kind> {
            match (self.key(Kind::Caller), self.key(Kind::Issuer)) {
                (Some(c), Some(i)) if c != i && overriding => Some(Kind::Caller),
                (_, Some(_)) => Some(Kind::Issuer),
                (Some(_), None) => Some(Kind::Caller),
                (None, None) => self
                    .key(Kind::Embedded)
                    .filter(|_| embedded)
                    .map(|_| Kind::Embedded),
            }
        }

        /// The error findings, as (code, attribution, phase): one for each condition the
        /// rules leave unmet (docs/findings.md). An issuer that is not a `did:key` is one
        /// whose key vcrd cannot obtain.
        fn errors(&self, opt_ins: OptIns) -> Vec<(String, String, String)> {
            let deciding = self.deciding(opt_ins).and_then(|k| self.key(k));
            let mut errors = Vec::new();
            // `verify.issuer_method_unsupported`: no key decides in its place.
            if self.key(Kind::Issuer).is_none() && deciding.is_none() {
                errors.push(("verify.issuer_method_unsupported", "vcrd"));
            }
            // `verify.embedded_key_refused`: alone, without the caller's opt-in.
            if self.embedded_alone() && !opt_ins.0 {
                errors.push(("verify.embedded_key_refused", "policy"));
            }
            // `verify.caller_key_not_issuer_key`: without the override (rule 1).
            if self.differ(Kind::Caller, Kind::Issuer) && !opt_ins.1 {
                errors.push(("verify.caller_key_not_issuer_key", "policy"));
            }
            // `verify.signature_invalid`: the deciding proof is incorrect (rule 3).
            if deciding.is_some() && deciding != self.correct {
                errors.push(("verify.signature_invalid", "input"));
            }
            let mut errors: Vec<_> = errors
                .into_iter()
                .map(|(code, attribution)| {
                    (code.to_owned(), attribution.to_owned(), "verify".to_owned())
                })
                .collect();
            errors.sort();
            errors
        }

        /// The warnings' codes (docs/findings.md).
        fn warnings(&self, opt_ins: OptIns) -> Vec<String> {
            let deciding = self.deciding(opt_ins).and_then(|k| self.key(k));
            let overridden = self.deciding(opt_ins) == Some(Kind::Caller)
                && self.differ(Kind::Caller, Kind::Issuer);
            let mut warnings = Vec::new();
            // `verify.embedded_key_mismatch`: the embedded key is not the issuer key.
            if self.differ(Kind::Embedded, Kind::Issuer) {
                warnings.push("verify.embedded_key_mismatch");
            }
            // `verify.issuer_key_overridden`: a caller-supplied key decides in its place.
            if overridden {
                warnings.push("verify.issuer_key_overridden");
            }
            // `verify.issuer_key_not_obtained`: another key decides.
            if self.key(Kind::Issuer).is_none() && deciding.is_some() {
                warnings.push("verify.issuer_key_not_obtained");
            }
            // A correct proof with a key that does not decide: key substitution when the
            // key is embedded and the deciding proof is incorrect; otherwise its own
            // warning, unless it is the overridden issuer key, whose warning gives it.
            if let Some(key) = self.correct.filter(|&k| Some(k) != deciding) {
                if self.key(Kind::Embedded) == Some(key) && deciding.is_some() {
                    warnings.push("verify.embedded_key_proof_correct");
                } else if !(overridden && self.key(Kind::Issuer) == Some(key)) {
                    warnings.push("verify.non_deciding_key_proof_correct");
                }
            }
            let mut warnings: Vec<String> = warnings.into_iter().map(str::to_owned).collect();
            warnings.sort();
            warnings
        }
    }

    /// A row's credential, and its key set when it has one, in the tests' scratch
    /// directory, which Cargo provides.
    pub struct Inputs {
        credential: PathBuf,
        key_set: Option<PathBuf>,
    }

    pub fn write_inputs(index: usize, row: &Row) -> Inputs {
        let (credential, key_set) = table_inputs(&TableRow {
            embedded: row.key(Kind::Embedded),
            issuer: row.key(Kind::Issuer),
            caller: row.key(Kind::Caller),
            signer: row.correct,
        });
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        let path = |extension: &str| dir.join(format!("key-and-proof-table-{index}.{extension}"));
        fs::write(path("jwt"), credential).unwrap();
        let key_set = key_set.map(|bytes| {
            fs::write(path("jwks.json"), bytes).unwrap();
            path("jwks.json")
        });
        Inputs {
            credential: path("jwt"),
            key_set,
        }
    }

    /// vcrd's exit code and standard output.
    pub struct Output {
        pub code: i32,
        pub stdout: Vec<u8>,
    }

    /// `vcrd verify` of a row's inputs, at the tests' clock, with these opt-ins.
    pub fn run(inputs: &Inputs, (embedded, overriding): OptIns) -> Output {
        let mut command = vcrd();
        command
            .arg("verify")
            .arg(&inputs.credential)
            .args(["--now", NOW, "--format", "json"]);
        if let Some(key_set) = &inputs.key_set {
            command.arg("--key-set").arg(key_set);
        }
        if embedded {
            command.arg("--allow-embedded-key");
        }
        if overriding {
            command.arg("--allow-key-override");
        }
        let output = command.output().unwrap();
        Output {
            code: output.status.code().unwrap(),
            stdout: output.stdout,
        }
    }

    /// ARCHITECTURE §6: an error attributed to vcrd gives 6; otherwise one attributed to
    /// the caller's policy, 5; otherwise the earliest failed phase, 2, 3 or 4; 0 when
    /// nothing failed.
    fn exit_code(errors: &[(String, String, String)]) -> i32 {
        const UNSUPPORTED: i32 = 6;
        const POLICY: i32 = 5;
        let phase = |name: &str| match name {
            "parse" => 2,
            "inspect" => 3,
            "verify" => 4,
            other => panic!("phase {other}"),
        };
        if errors.iter().any(|(_, a, _)| a == "vcrd") {
            UNSUPPORTED
        } else if errors.iter().any(|(_, a, _)| a == "policy") {
            POLICY
        } else {
            errors.iter().map(|(_, _, p)| phase(p)).min().unwrap_or(0)
        }
    }

    /// Checks one run against the row: the keys and their proofs by the table's cells,
    /// the deciding proof key by rule 2, and the findings and exit code by the rules.
    pub fn check(row: &Row, opt_ins: OptIns, output: &Output, context: &str) {
        let out: Value = serde_json::from_slice(&output.stdout).unwrap();
        let proof = &out["proofs"][0];
        let provenance = &proof["key_provenance"];
        let keys = provenance["keys"].as_array().unwrap();

        // Each kind of key the row has is in one entry of `keys`, the kinds that are one
        // key share an entry, and there is no other entry.
        let entries = KINDS.map(|kind| {
            let with: Vec<usize> = (0..keys.len())
                .filter(|&i| {
                    keys[i]["kinds"]
                        .as_array()
                        .unwrap()
                        .contains(&json!(kind.name()))
                })
                .collect();
            assert!(with.len() <= 1, "{kind:?} in several keys: {context}");
            with.first().copied()
        });
        let entry = |kind: Kind| entries[kind.index()];
        for kind in KINDS {
            assert_eq!(
                entry(kind).is_some(),
                row.key(kind).is_some(),
                "{kind:?}: {context}"
            );
        }
        for (a, b) in PAIRS {
            if entry(a).is_some() && entry(b).is_some() {
                assert_eq!(
                    entry(a) == entry(b),
                    row.key(a) == row.key(b),
                    "{a:?}, {b:?}: {context}"
                );
            }
        }
        assert_eq!(keys.len(), row.distinct, "{context}");
        // Each key's proof is the row's, and the caller-supplied key came from the key
        // set's one member, which has no `kid`.
        for kind in KINDS {
            if let (Some(e), Some(key)) = (entry(kind), row.key(kind)) {
                let proof = if row.correct == Some(key) {
                    "correct"
                } else {
                    "incorrect"
                };
                assert_eq!(keys[e]["proof"], proof, "{kind:?}: {context}");
            }
        }
        if let Some(c) = entry(Kind::Caller) {
            assert_eq!(keys[c]["members"], json!([{"index": 0}]), "{context}");
        }
        // The embedded key alone, without the opt-in, is refused (ARCHITECTURE §8,
        // "Refused"); no other key is.
        for (i, key) in keys.iter().enumerate() {
            let refused = row.embedded_alone() && !opt_ins.0 && Some(i) == entry(Kind::Embedded);
            let expected = if refused {
                json!("embedded_key_alone")
            } else {
                Value::Null
            };
            assert_eq!(
                key.get("refused").unwrap_or(&Value::Null),
                &expected,
                "{context}"
            );
        }

        // The deciding proof key, by rule 2, and its proof's result.
        let deciding = row.deciding(opt_ins);
        assert_eq!(
            provenance.get("deciding"),
            deciding.and_then(entry).map(Value::from).as_ref(),
            "{context}"
        );
        let outcome = match deciding.and_then(|k| row.key(k)) {
            Some(key) if row.correct == Some(key) => "correct",
            Some(_) => "incorrect",
            None => "not_attempted",
        };
        assert_eq!(proof["outcome"], outcome, "{context}");

        // The findings. The exit code is what the run's own errors give, which needs no
        // expected value; the errors and warnings are what the rules give.
        let findings = |severity: &str| {
            let mut found: Vec<(String, String, String)> = out["findings"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|f| f["severity"] == severity)
                .map(|f| {
                    let text = |field: &str| f[field].as_str().unwrap().to_owned();
                    (text("code"), text("attribution"), text("phase"))
                })
                .collect();
            found.sort();
            found
        };
        let errors = findings("error");
        assert_eq!(output.code, exit_code(&errors), "{context}");
        assert_eq!(errors, row.errors(opt_ins), "{context}");
        let warnings: Vec<String> = findings("warning")
            .into_iter()
            .map(|(code, _, _)| code)
            .collect();
        assert_eq!(warnings, row.warnings(opt_ins), "{context}");
    }
}
