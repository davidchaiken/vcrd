//! The debugging guide (docs/debugging.md; ARCHITECTURE §10 [G1]) and the launch
//! configuration it uses, checked against the repository, so that a new fixture, a
//! renamed function or an edited script cannot leave them behind.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use helpers::{ROOT, configured_tables, guide, launch, picked, tables};

/// In a `#[cfg(test)]` module so that the workspace's panic lints exempt it, as they
/// do test functions (docs/reviews/milestone-0.md, gap 1).
#[cfg(test)]
mod helpers {
    use std::collections::BTreeSet;
    use std::fs;

    use serde_json::Value;

    pub const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");

    pub fn guide() -> String {
        fs::read_to_string(format!("{ROOT}/docs/debugging.md")).unwrap()
    }

    pub fn launch() -> Value {
        serde_json::from_str(&fs::read_to_string(format!("{ROOT}/.vscode/launch.json")).unwrap())
            .unwrap()
    }

    /// The inputs the input picker offers.
    pub fn picked(launch: &Value) -> BTreeSet<String> {
        let input = launch["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|input| input["id"] == "input")
            .unwrap();
        input["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|option| option.as_str().unwrap().to_owned())
            .collect()
    }

    /// The rows of every table in the guide's section `heading`, its subsections
    /// included, each as its cells with the backticks removed. Header rows, which a
    /// delimiter row follows, are left out.
    pub fn tables(guide: &str, heading: &str) -> Vec<Vec<String>> {
        let section = guide.split_once(&format!("\n## {heading}\n")).unwrap().1;
        let section = section.split_once("\n## ").map_or(section, |(s, _)| s);
        let lines: Vec<&str> = section.lines().collect();
        lines
            .iter()
            .zip(lines.iter().skip(1).map(Some).chain([None]))
            .filter(|(line, next)| {
                line.starts_with('|')
                    && !line.starts_with("|---")
                    && !next.is_some_and(|n| n.starts_with("|---"))
            })
            .map(|(line, _)| cells(line))
            .collect()
    }

    fn cells(line: &str) -> Vec<String> {
        line.trim_matches('|')
            .split('|')
            .map(|cell| cell.trim().replace('`', ""))
            .collect()
    }

    /// Each table in the guide's section `heading`, its subsections included: the launch
    /// configuration the line before it names in bold, if it names one alone, and its
    /// rows, as [`tables`] gives them.
    pub fn configured_tables(
        guide: &str,
        heading: &str,
    ) -> Vec<(Option<String>, Vec<Vec<String>>)> {
        let section = guide.split_once(&format!("\n## {heading}\n")).unwrap().1;
        let section = section.split_once("\n## ").map_or(section, |(s, _)| s);
        let mut found = Vec::new();
        let mut before = "";
        let mut lines = section.lines().peekable();
        while let Some(line) = lines.next() {
            if !line.starts_with('|') {
                if !line.trim().is_empty() {
                    before = line;
                }
                continue;
            }
            // A header row, which the delimiter row follows; then the rows.
            lines.next();
            let mut rows = Vec::new();
            while let Some(row) = lines.next_if(|l| l.starts_with('|')) {
                rows.push(cells(row));
            }
            let named: Vec<&str> = before
                .split("**")
                .skip(1)
                .step_by(2)
                .filter(|span| span.starts_with("vcrd: "))
                .collect();
            let configuration = match named[..] {
                [one] => Some(one.to_owned()),
                _ => None,
            };
            found.push((configuration, rows));
        }
        found
    }
}

/// Each example and fixture is offered by the input picker, or named by a configuration
/// of its own. A key set, and a credential with its key set beside it, are named by a
/// configuration of their own only: the picker cannot pass `--key-set`
/// (DEVELOPMENT-PLAN.md, milestone 2, decided 2026-11-25).
#[test]
fn the_launch_configurations_offer_every_example_and_fixture() {
    let launch = launch();
    let picked = picked(&launch);
    let dirs = ["examples", "fixtures"];
    let named: BTreeSet<String> = launch["configurations"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|c| c["args"].as_array().unwrap())
        .map(|arg| arg.as_str().unwrap())
        .filter(|arg| dirs.iter().any(|d| arg.starts_with(&format!("{d}/"))))
        .map(str::to_owned)
        .collect();

    let mut inputs = BTreeSet::new();
    for dir in dirs {
        for entry in fs::read_dir(format!("{ROOT}/{dir}")).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            if name != "README.md" {
                inputs.insert(format!("{dir}/{name}"));
            }
        }
    }
    let with_key_set = |path: &str| {
        path.ends_with(".jwks.json")
            || path
                .strip_suffix(".jwt")
                .is_some_and(|stem| inputs.contains(&format!("{stem}.jwks.json")))
    };
    let missing: Vec<_> = inputs
        .iter()
        .filter(|p| !picked.contains(*p) && !named.contains(*p))
        .collect();
    let absent: Vec<_> = picked
        .union(&named)
        .filter(|p| !inputs.contains(*p))
        .collect();
    let misplaced: Vec<_> = picked.iter().filter(|p| with_key_set(p)).collect();
    assert!(
        missing.is_empty() && absent.is_empty() && misplaced.is_empty(),
        "offer in .vscode/launch.json: {missing:?}; remove from it, as they do not exist: \
         {absent:?}; take out of the input picker, which cannot pass --key-set: {misplaced:?}"
    );
}

/// Each function the guide says to break in is defined in the file it names.
#[test]
fn the_guide_breaks_in_functions_that_exist() {
    let guide = guide();
    let rows = tables(&guide, "Where to break");
    assert!(
        !rows.is_empty(),
        "docs/debugging.md: no rows in \"Where to break\""
    );
    for row in rows {
        let [_, _, function, _, file] = &row[..] else {
            panic!("a row of five cells: {row:?}")
        };
        let source = fs::read_to_string(format!("{ROOT}/{file}")).unwrap();
        assert!(
            ['(', '<']
                .iter()
                .any(|c| source.contains(&format!("fn {function}{c}"))),
            "docs/debugging.md: no function {function} in {file}"
        );
    }
}

/// The line before each table of where to break names, alone, the launch configuration
/// to run its rows with, and that configuration offers each row's input: in the input
/// picker, or in its own arguments (DEVELOPMENT-PLAN.md, milestone 2, decided
/// 2026-11-25).
#[test]
fn each_table_names_a_configuration_that_offers_its_inputs() {
    let guide = guide();
    let launch = launch();
    let picked = picked(&launch);
    let tables = configured_tables(&guide, "Where to break");
    assert!(
        !tables.is_empty(),
        "docs/debugging.md: no tables in \"Where to break\""
    );
    for (configuration, rows) in tables {
        let Some(configuration) = configuration else {
            panic!(
                "docs/debugging.md: the line before the table of {rows:?} names no one configuration in bold"
            )
        };
        let found = launch["configurations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == configuration.as_str())
            .unwrap_or_else(|| {
                panic!("docs/debugging.md: no configuration {configuration} in .vscode/launch.json")
            });
        let args: Vec<&str> = found["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|arg| arg.as_str().unwrap())
            .collect();
        for row in rows {
            let input = &row[1];
            let offered = if args.contains(&"${input:input}") {
                picked.contains(input)
            } else {
                args.contains(&input.as_str())
            };
            assert!(
                offered,
                "docs/debugging.md: {configuration} does not offer {input}"
            );
        }
    }
}

/// Each launch configuration that runs a committed input, one that its arguments name or
/// the input picker offers, is the configuration of a table of where to break, so that a
/// new configuration cannot be left out of the guide (DEVELOPMENT-PLAN.md, milestone 2,
/// decided 2026-11-25).
#[test]
fn every_configuration_for_a_committed_input_has_a_table() {
    let guide = guide();
    let used: BTreeSet<String> = configured_tables(&guide, "Where to break")
        .into_iter()
        .filter_map(|(configuration, _)| configuration)
        .collect();
    let committed = |arg: &str| {
        arg == "${input:input}"
            || ["examples/", "fixtures/"]
                .iter()
                .any(|d| arg.starts_with(d))
    };
    let launch = launch();
    let missing: Vec<&str> = launch["configurations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| {
            c["args"]
                .as_array()
                .unwrap()
                .iter()
                .any(|arg| committed(arg.as_str().unwrap()))
        })
        .map(|c| c["name"].as_str().unwrap())
        .filter(|name| !used.contains(*name))
        .collect();
    assert!(
        missing.is_empty(),
        "docs/debugging.md: no table of where to break runs {missing:?}"
    );
}

/// Each path in the repository that the guide's text names, outside its code blocks,
/// exists.
#[test]
fn the_guide_names_paths_that_exist() {
    let guide = guide();
    let mut fenced = false;
    let text: Vec<&str> = guide
        .lines()
        .filter(|l| {
            if l.trim_start().starts_with("```") {
                fenced = !fenced;
            }
            !fenced && !l.trim_start().starts_with("```")
        })
        .collect();
    let text = text.join("\n");
    let prefixes = [
        ".vscode/",
        "docs/",
        "examples/",
        "fixtures/",
        "scripts/",
        "vcrd-cli/",
        "vcrd-core/",
    ];
    let named: Vec<&str> = text
        .split('`')
        .skip(1)
        .step_by(2)
        .filter(|span| prefixes.iter().any(|p| span.starts_with(p)) && !span.contains(' '))
        .collect();
    assert!(!named.is_empty(), "docs/debugging.md names no paths");
    let missing: Vec<&&str> = named
        .iter()
        .filter(|path| !Path::new(&format!("{ROOT}/{path}")).exists())
        .collect();
    assert!(
        missing.is_empty(),
        "docs/debugging.md names paths that do not exist: {missing:?}"
    );
}

/// Each helper script is quoted in full in the guide, so that the two cannot differ.
#[test]
fn the_guide_quotes_every_helper_script() {
    let guide = guide();
    let dir = format!("{ROOT}/scripts/debugging");
    let mut quoted = 0;
    for entry in fs::read_dir(&dir).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if !name.ends_with(".sh") {
            continue;
        }
        let script = fs::read_to_string(format!("{dir}/{name}")).unwrap();
        assert!(
            guide.contains(&format!(
                "`scripts/debugging/{name}`:\n\n```bash\n{script}```\n"
            )),
            "docs/debugging.md does not quote scripts/debugging/{name} as it is"
        );
        quoted += 1;
    }
    assert!(quoted > 0, "no scripts in scripts/debugging");
}
