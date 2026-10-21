//! The exit code is the result's alone: no output setting changes it. For the curated
//! example, every committed fixture and an input that does not parse, `vcrd verify`
//! exits with the same code in every format, at every verbosity level and every
//! `--unsafe` level, and that code is the one the JSON envelope reports.

#[cfg(test)]
mod support;

use helpers::{Input, exit_code, inputs};

/// In a `#[cfg(test)]` module so that the workspace's panic lints exempt it, as they
/// do test functions (docs/reviews/milestone-0.md, gap 1).
#[cfg(test)]
mod helpers {
    use crate::support::{EXAMPLE, NOW, vcrd};

    pub enum Input {
        File(String),
        Stdin(&'static str),
    }

    /// The example, every file under fixtures/ but its README, and text that is not a
    /// compact JWS.
    pub fn inputs() -> Vec<Input> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures");
        let mut files: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.file_name().is_some_and(|n| n != "README.md"))
            .map(|path| path.to_str().unwrap().to_owned())
            .collect();
        files.sort();
        let mut inputs = vec![Input::File(EXAMPLE.to_owned())];
        inputs.extend(files.into_iter().map(Input::File));
        inputs.push(Input::Stdin("not.a.jws"));
        inputs
    }

    /// The exit code of `vcrd verify` on the input with these settings, and stdout.
    pub fn exit_code(input: &Input, settings: &[String]) -> (i32, Vec<u8>) {
        let mut command = vcrd();
        command.arg("verify");
        match input {
            Input::File(path) => {
                command.arg(path);
            }
            Input::Stdin(text) => {
                command.write_stdin(*text);
            }
        }
        let output = command
            .args(["--now", NOW])
            .args(settings)
            .output()
            .unwrap();
        (output.status.code().unwrap(), output.stdout)
    }
}

#[test]
fn no_output_setting_changes_the_exit_code() {
    for input in inputs() {
        let name = match &input {
            Input::File(path) => path.rsplit('/').next().unwrap_or(path).to_owned(),
            Input::Stdin(text) => format!("stdin {text:?}"),
        };
        let (expected, stdout) = exit_code(&input, &["--format".to_owned(), "json".to_owned()]);
        let envelope: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(
            envelope["exit_code"], expected,
            "{name}: exit_code in the result"
        );
        for format in ["json", "text", "plain"] {
            for verbosity in 0..=3 {
                for unsafe_level in 0..=2 {
                    let settings = [
                        "--format".to_owned(),
                        format.to_owned(),
                        "--verbosity".to_owned(),
                        verbosity.to_string(),
                        format!("--unsafe={unsafe_level}"),
                    ];
                    let (code, _) = exit_code(&input, &settings);
                    assert_eq!(code, expected, "{name}: {}", settings.join(" "));
                }
            }
        }
    }
}
