//! The `vcrd` command.

#![forbid(unsafe_code)]

// A vcrd binary that can read no credential cannot do its job (ARCHITECTURE §2).
// Add each new format feature to this list.
#[cfg(not(any(feature = "vc-jose")))]
compile_error!("vcrd-cli needs at least one credential format feature, such as `vc-jose`");

// Nor can one that verifies no proof. Add each new proof-suite feature to this list.
#[cfg(not(any(feature = "jws")))]
compile_error!("vcrd-cli needs at least one proof suite feature, such as `jws`");

mod args;
mod exit;
mod view;

use std::ffi::OsString;
use std::io::{IsTerminal, Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use clap::error::ErrorKind;
use vcrd_core::{Context, Designations, FixedClock, Registry, SystemClock};

use args::{Cli, Operation, OutputFormat};
use view::Envelope;

fn main() -> ExitCode {
    let raw: Vec<OsString> = std::env::args_os().collect();
    // The fallible entry point: clap's own exit would use status 2, which vcrd
    // assigns to a parse failure (ARCHITECTURE §6).
    let cli = match Cli::try_parse_from(&raw) {
        Ok(cli) => cli,
        Err(error) => return usage_error(&error, &raw),
    };
    let format = cli.options.format;
    let verbosity = cli.options.verbosity;
    let (operation, file) = cli.operation();

    let bytes = match read_input(file) {
        Ok(bytes) => bytes,
        Err((code, message)) => {
            eprintln_unless_quiet(verbosity, &message);
            return emit(&view::fault(code, message), format, verbosity);
        }
    };

    let skew = Duration::from_secs(cli.options.clock_skew);
    let designations = Designations::mask_claims();
    let ctx = match cli.options.now {
        Some(now) => Context::builder(FixedClock(now)),
        None => Context::builder(SystemClock),
    }
    .clock_skew(skew)
    .designations(designations)
    .build();
    let registry = Registry::builtin();
    let report = match operation {
        Operation::Inspect => vcrd_core::inspect(&bytes, &ctx, &registry),
        Operation::Verify => vcrd_core::verify(&bytes, &ctx, &registry),
    };
    emit(&view::envelope(&report, &ctx), format, verbosity)
}

/// `--help` and `--version` are answered as clap renders them, and exit 0. Any other
/// rejected command line is a caller fault: exit 1, the message on stderr, and with
/// JSON output the envelope on stdout (ARCHITECTURE §6).
fn usage_error(error: &clap::Error, raw: &[OsString]) -> ExitCode {
    if matches!(
        error.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
    ) {
        return match error.print() {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(exit::CALLER_FAULT),
        };
    }
    let (format, verbosity) = args::prescan(raw);
    let message = error.render().to_string();
    eprintln_unless_quiet(verbosity, message.trim_end());
    emit(
        &view::fault("usage", message.trim_end().to_owned()),
        format,
        verbosity,
    )
}

/// Reads the file, or standard input when there is none. Never waits on a terminal
/// for input that is not coming (REQUIREMENTS §6).
fn read_input(file: Option<&std::path::PathBuf>) -> Result<Vec<u8>, (&'static str, String)> {
    let mut bytes = Vec::new();
    match file {
        Some(path) => {
            bytes = std::fs::read(path).map_err(|e| unreadable(path, &e))?;
        }
        None => {
            let stdin = std::io::stdin();
            if stdin.is_terminal() {
                return Err((
                    "no_input",
                    "no input: name a file, or pipe the credential to standard input".to_owned(),
                ));
            }
            stdin
                .lock()
                .read_to_end(&mut bytes)
                .map_err(|e| unreadable(Path::new("-"), &e))?;
        }
    }
    Ok(bytes)
}

fn unreadable(path: &Path, error: &std::io::Error) -> (&'static str, String) {
    ("input_unreadable", format!("{}: {error}", path.display()))
}

fn eprintln_unless_quiet(verbosity: u8, message: &str) {
    if verbosity > 0 {
        eprintln!("vcrd: {message}");
    }
}

/// Prints the envelope unless `--verbosity 0` asks for silence, and returns its exit
/// code. Pretty-printed whether or not stdout is a terminal.
fn emit(envelope: &Envelope, format: OutputFormat, verbosity: u8) -> ExitCode {
    if verbosity > 0 {
        match format {
            OutputFormat::Json => {
                let mut stdout = std::io::stdout().lock();
                let written = serde_json::to_writer_pretty(&mut stdout, envelope)
                    .map_err(std::io::Error::from)
                    .and_then(|()| writeln!(stdout));
                if let Err(error) = written {
                    eprintln!("vcrd: cannot write the result: {error}");
                    return ExitCode::from(exit::CALLER_FAULT);
                }
            }
        }
    }
    ExitCode::from(envelope.exit_code)
}
