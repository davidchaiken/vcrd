//! The launch configuration the debugging guide uses (ARCHITECTURE §10 [G1]) offers
//! every committed input, so that a new fixture cannot be left off its list.

use std::collections::BTreeSet;
use std::fs;

use serde_json::Value;

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");

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
