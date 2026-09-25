//! Helpers shared by the black-box tests. Each test file declares this module under
//! `#[cfg(test)]`, so that the workspace's panic lints exempt it as they do test
//! functions (docs/reviews/milestone-0.md, gap 1).

// Each test file uses a subset of these helpers.
#![allow(dead_code)]

use assert_cmd::Command;
use serde_json::Value;

/// The curated example (REQUIREMENTS §11).
pub const EXAMPLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../examples/ed25519.jwt");

/// Inside the example's validity period.
pub const NOW: &str = "2026-10-01T00:00:00Z";

pub fn vcrd() -> Command {
    Command::cargo_bin("vcrd").unwrap()
}

/// Runs vcrd, asserts the exit code, and parses stdout as the one JSON document.
pub fn json(command: &mut Command, code: i32) -> Value {
    let output = command.output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
