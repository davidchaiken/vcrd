//! The debugging guide (docs/debugging.md; ARCHITECTURE §10 [G1]) and the launch
//! configuration it uses, checked against the repository, so that a new fixture, a
//! renamed function or an edited script cannot leave them behind.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde_json::Value;

use helpers::{ROOT, guide, tables};

/// In a `#[cfg(test)]` module so that the workspace's panic lints exempt it, as they
/// do test functions (docs/reviews/milestone-0.md, gap 1).
#[cfg(test)]
mod helpers {
    use std::fs;

    pub const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");

    pub fn guide() -> String {
        fs::read_to_string(format!("{ROOT}/docs/debugging.md")).unwrap()
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
            .map(|(line, _)| {
                line.trim_matches('|')
                    .split('|')
                    .map(|cell| cell.trim().replace('`', ""))
                    .collect()
            })
            .collect()
    }
}

#[test]
fn the_launch_configuration_offers_every_example_and_fixture() {
    let launch: Value =
        serde_json::from_str(&fs::read_to_string(format!("{ROOT}/.vscode/launch.json")).unwrap())
            .unwrap();
    let input = launch["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|input| input["id"] == "input")
        .unwrap();
    let offered: BTreeSet<String> = input["options"]
        .as_array()
        .unwrap()
        .iter()
        .map(|option| option.as_str().unwrap().to_owned())
        .collect();

    let mut inputs = BTreeSet::new();
    for dir in ["examples", "fixtures"] {
        for entry in fs::read_dir(format!("{ROOT}/{dir}")).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            if name != "README.md" {
                inputs.insert(format!("{dir}/{name}"));
            }
        }
    }
    let missing: Vec<_> = inputs.difference(&offered).collect();
    let absent: Vec<_> = offered.difference(&inputs).collect();
    assert!(
        missing.is_empty() && absent.is_empty(),
        "add to .vscode/launch.json: {missing:?}; remove from it: {absent:?}"
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
