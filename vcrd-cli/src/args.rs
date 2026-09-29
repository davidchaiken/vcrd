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
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Json)]
    pub format: OutputFormat,
    /// Evaluate validity periods at this RFC 3339 date-time instead of the system clock.
    #[arg(long, global = true, value_name = "DATE-TIME", value_parser = rfc3339)]
    pub now: Option<OffsetDateTime>,
    /// Tolerance applied to validity periods.
    #[arg(long, global = true, value_name = "SECONDS", default_value_t = 0)]
    pub clock_skew: u64,
    /// Diagnostic detail, 0 to 3. At 0 nothing is printed and the exit code is the
    /// whole answer.
    #[arg(
        long,
        global = true,
        default_value_t = 1,
        value_parser = clap::value_parser!(u8).range(0..=3)
    )]
    pub verbosity: u8,
}

/// Milestone 1 renders JSON only; `text` and `plain` follow (DEVELOPMENT-PLAN.md).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    #[default]
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

/// The output format and verbosity a command line asks for, read without clap. Used
/// only when clap has rejected the command line, so that the fault is still reported
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
    fn prescan_reads_both_spellings_and_stops_at_double_dash() {
        assert_eq!(
            prescan(&args("vcrd --bogus --format json --verbosity 0")),
            (OutputFormat::Json, 0)
        );
        assert_eq!(
            prescan(&args("vcrd --verbosity=2")),
            (OutputFormat::Json, 2)
        );
        assert_eq!(
            prescan(&args("vcrd -- --verbosity 0")),
            (OutputFormat::Json, 1)
        );
        assert_eq!(
            prescan(&args("vcrd --verbosity 9")),
            (OutputFormat::Json, 1)
        );
    }
}
