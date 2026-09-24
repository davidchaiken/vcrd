//! The `vcrd` command.

#![forbid(unsafe_code)]

// A vcrd binary that can read no credential cannot do its job (ARCHITECTURE §2).
// Add each new format feature to this list.
#[cfg(not(any(feature = "vc-jose")))]
compile_error!("vcrd-cli needs at least one credential format feature, such as `vc-jose`");

use clap::Parser;

/// Parse, inspect and verify verifiable credentials.
#[derive(Parser)]
#[command(name = "vcrd", version)]
struct Cli {}

fn main() {
    let Cli {} = Cli::parse();
}
