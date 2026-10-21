//! Command-line arguments (REQUIREMENTS §8).

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Parse, inspect and verify verifiable credentials.
///
/// With no subcommand, runs `inspect`. With no file, reads standard input.
#[derive(Debug, Parser)]
#[command(name = "vcrd", version, args_conflicts_with_subcommands = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    /// The credential to inspect; standard input when absent.
    pub file: Option<PathBuf>,
    #[command(flatten)]
    pub options: Options,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Parse the input and inspect it against its data model and validity period.
    Inspect {
        /// The credential; standard input when absent.
        file: Option<PathBuf>,
    },
    /// Parse, inspect, and verify the proof offline.
    Verify {
        /// The credential; standard input when absent.
        file: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
pub struct Options {
    /// Output format.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
    /// Evaluate validity periods at this RFC 3339 date-time instead of the system clock.
    #[arg(long, global = true, value_name = "DATE-TIME", value_parser = rfc3339)]
    pub now: Option<OffsetDateTime>,
    /// Tolerance applied to validity periods.
    #[arg(long, global = true, value_name = "SECONDS", default_value_t = 0)]
    pub clock_skew: u64,
    /// Detail in `text` and `plain` output, 0 to 3; JSON is always complete. At 0
    /// nothing is printed in any format and the exit code is the whole answer.
    #[arg(
        long,
        global = true,
        default_value_t = 1,
        value_parser = clap::value_parser!(u8).range(0..=3)
    )]
    pub verbosity: u8,
    /// Show masked values in cleartext: 1, or the flag alone, shows every claim; 2
    /// also shows cryptographic secrets, such as a private key the credential carries.
    /// Write the level as `--unsafe=2` or `--unsafe 2`. A warning says so, on standard
    /// error and in the result.
    #[arg(
        long = "unsafe",
        global = true,
        value_name = "LEVEL",
        num_args = 0..=1,
        require_equals = true,
        default_value_t = 0,
        default_missing_value = "1",
        value_parser = clap::value_parser!(u8).range(0..=2)
    )]
    pub unsafe_level: u8,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Tables, for a reader at a terminal.
    #[default]
    Text,
    /// One `name: value` line per item, for line-oriented tools.
    Plain,
    /// The complete result as one JSON document (docs/output.md).
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Inspect,
    Verify,
}

impl Cli {
    /// `vcrd <file>` and `vcrd` with piped input run `inspect` (REQUIREMENTS §8).
    pub fn operation(&self) -> (Operation, Option<&PathBuf>) {
        match &self.command {
            None => (Operation::Inspect, self.file.as_ref()),
            Some(Command::Inspect { file }) => (Operation::Inspect, file.as_ref()),
            Some(Command::Verify { file }) => (Operation::Verify, file.as_ref()),
        }
    }
}

fn rfc3339(s: &str) -> Result<OffsetDateTime, time::error::Parse> {
    OffsetDateTime::parse(s, &Rfc3339)
}

/// Joins `--unsafe 2` into `--unsafe=2`, so that both spellings work. clap reads the
/// optional level only after `=`, and would take a separate `2` for the file. Only `0`,
/// `1` or `2` is joined, so `vcrd --unsafe file.jwt` still means level 1; a file that
/// has one of those names is written `./2`. Nothing after `--` is changed.
pub fn normalize(args: Vec<OsString>) -> Vec<OsString> {
    let mut out = Vec::with_capacity(args.len());
    let mut args = args.into_iter().peekable();
    while let Some(arg) = args.next() {
        if arg == "--" {
            out.push(arg);
            out.extend(args);
            break;
        }
        if arg == "--unsafe"
            && let Some(level) = args.next_if(|next| matches!(next.to_str(), Some("0" | "1" | "2")))
        {
            let mut joined = OsString::from("--unsafe=");
            joined.push(level);
            out.push(joined);
            continue;
        }
        out.push(arg);
    }
    out
}

/// The output format and verbosity a command line asks for, read without clap. Used
/// only when clap has rejected the command line, so that the error is still reported
/// in the format asked for. Unreadable values fall back to the defaults.
pub fn prescan(args: &[OsString]) -> (OutputFormat, u8) {
    let format = last_value(args, "format")
        .and_then(|v| OutputFormat::from_str(&v, false).ok())
        .unwrap_or_default();
    let verbosity = last_value(args, "verbosity")
        .and_then(|v| v.parse().ok())
        .filter(|v| *v <= 3)
        .unwrap_or(1);
    (format, verbosity)
}

/// The last value given as `--name value` or `--name=value`, before any `--`.
fn last_value(args: &[OsString], name: &str) -> Option<String> {
    let flag = format!("--{name}");
    let prefix = format!("--{name}=");
    let mut found = None;
    let mut args = args.iter().skip(1).filter_map(|a| a.to_str());
    while let Some(arg) = args.next() {
        if arg == "--" {
            break;
        } else if arg == flag {
            found = args.next().map(str::to_owned);
        } else if let Some(value) = arg.strip_prefix(&prefix) {
            found = Some(value.to_owned());
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(line: &str) -> Vec<OsString> {
        line.split(' ').map(OsString::from).collect()
    }

    #[test]
    fn joins_a_level_given_after_a_space() {
        assert_eq!(
            normalize(args("vcrd verify f.jwt --unsafe 2")),
            args("vcrd verify f.jwt --unsafe=2")
        );
        // A file name is not a level.
        assert_eq!(
            normalize(args("vcrd --unsafe f.jwt")),
            args("vcrd --unsafe f.jwt")
        );
        assert_eq!(
            normalize(args("vcrd --unsafe=1 2")),
            args("vcrd --unsafe=1 2")
        );
        assert_eq!(
            normalize(args("vcrd -- --unsafe 2")),
            args("vcrd -- --unsafe 2")
        );
    }

    #[test]
    fn prescan_reads_both_spellings_and_stops_at_double_dash() {
        assert_eq!(
            prescan(&args("vcrd --bogus --format json --verbosity 0")),
            (OutputFormat::Json, 0)
        );
        assert_eq!(
            prescan(&args("vcrd --verbosity=2")),
            (OutputFormat::Text, 2)
        );
        assert_eq!(
            prescan(&args("vcrd -- --verbosity 0")),
            (OutputFormat::Text, 1)
        );
        assert_eq!(
            prescan(&args("vcrd --verbosity 9 --format plain")),
            (OutputFormat::Plain, 1)
        );
    }
}
