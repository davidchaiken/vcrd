//! vcrd -- THROWAWAY SPIKE. See PROTOTYPE-FINDINGS.md.

#![forbid(unsafe_code)]

mod exit_code;
mod render;
mod view;

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use vcrd_core::context::{Context, RedactionPolicy};
use vcrd_core::jws::AlgPolicy;
use vcrd_core::keys::JwkSetStore;
use vcrd_core::limits::Limits;

#[derive(Parser, Debug)]
#[command(name = "vcrd", version, about = "Read, validate, and verify verifiable credentials (SPIKE)")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Credential file; `-` or absent reads stdin.
    file: Option<PathBuf>,

    #[command(flatten)]
    global: GlobalArgs,
}

#[derive(Args, Debug, Clone)]
struct GlobalArgs {
    #[arg(long, value_enum, default_value_t = Format::Text, global = true)]
    format: Format,

    /// 0 suppresses all output and relies on the exit code alone.
    #[arg(long, short = 'v', default_value_t = 1, global = true)]
    verbosity: u8,

    /// Print full cleartext claim values. Marks the output as unredacted.
    #[arg(long = "unsafe", global = true)]
    unsafe_cleartext: bool,

    /// Show which redaction rule fired for each claim.
    #[arg(long, global = true)]
    explain_redaction: bool,

    /// The current time, RFC 3339. Required unless built with the std-clock feature.
    #[arg(long, global = true)]
    now: Option<String>,

    /// Clock-skew tolerance for validFrom/validUntil.
    #[arg(long, default_value_t = 0, global = true)]
    skew_seconds: i64,

    /// Algorithms this verification will accept. Repeatable. Default: vcrd's full set.
    #[arg(long = "allow-alg", global = true)]
    allow_alg: Vec<String>,

    /// A JWK Set of caller-supplied issuer keys.
    #[arg(long, global = true)]
    jwks: Option<PathBuf>,

    /// Accept a public key the credential supplies about itself. Almost never right.
    #[arg(long, global = true)]
    trust_embedded_key: bool,

    #[arg(long, default_value_t = 32, global = true)]
    max_depth: usize,

    #[arg(long, default_value_t = 262_144, global = true)]
    max_bytes: usize,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Format {
    Text,
    Json,
    Plain,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Parse and validate. Never verifies.
    Inspect {
        file: Option<PathBuf>,
        #[command(flatten)]
        global: GlobalArgs,
    },
    /// Parse, validate, and check the cryptographic proof.
    Verify {
        file: Option<PathBuf>,
        #[command(flatten)]
        global: GlobalArgs,
    },
    /// List supported credential formats.
    Formats,
    /// List supported proof suites.
    Suites,
    /// Report size and nesting depth across inputs, for setting structural limits.
    Measure { files: Vec<PathBuf> },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let code = run(cli);
    ExitCode::from(code as u8)
}

fn run(cli: Cli) -> i32 {
    match cli.command {
        Some(Command::Formats) => {
            let r = vcrd_core::registry();
            for f in &r.formats {
                println!("{}\t{}", f.id().0, f.description());
            }
            exit_code::OK
        }
        Some(Command::Suites) => {
            let r = vcrd_core::registry();
            for s in &r.suites {
                println!("{}\t{}", s.id().0, s.description());
            }
            exit_code::OK
        }
        Some(Command::Measure { files }) => measure(&files),
        Some(Command::Inspect { file, global }) => {
            let g = merge(&cli.global, &global);
            one(file.or(cli.file), &g, false)
        }
        Some(Command::Verify { file, global }) => {
            let g = merge(&cli.global, &global);
            one(file.or(cli.file), &g, true)
        }
        // Bare `vcrd <file>` and piped stdin both default to inspect (§8).
        None => one(cli.file, &cli.global, false),
    }
}

/// Subcommand-level flags win over the ones given before the subcommand.
fn merge(outer: &GlobalArgs, inner: &GlobalArgs) -> GlobalArgs {
    let d = GlobalArgs::default_like();
    GlobalArgs {
        format: if inner.format != d.format { inner.format } else { outer.format },
        verbosity: if inner.verbosity != d.verbosity { inner.verbosity } else { outer.verbosity },
        unsafe_cleartext: inner.unsafe_cleartext || outer.unsafe_cleartext,
        explain_redaction: inner.explain_redaction || outer.explain_redaction,
        now: inner.now.clone().or_else(|| outer.now.clone()),
        skew_seconds: if inner.skew_seconds != d.skew_seconds { inner.skew_seconds } else { outer.skew_seconds },
        allow_alg: if inner.allow_alg.is_empty() { outer.allow_alg.clone() } else { inner.allow_alg.clone() },
        jwks: inner.jwks.clone().or_else(|| outer.jwks.clone()),
        trust_embedded_key: inner.trust_embedded_key || outer.trust_embedded_key,
        max_depth: if inner.max_depth != d.max_depth { inner.max_depth } else { outer.max_depth },
        max_bytes: if inner.max_bytes != d.max_bytes { inner.max_bytes } else { outer.max_bytes },
    }
}

impl GlobalArgs {
    fn default_like() -> GlobalArgs {
        GlobalArgs {
            format: Format::Text,
            verbosity: 1,
            unsafe_cleartext: false,
            explain_redaction: false,
            now: None,
            skew_seconds: 0,
            allow_alg: Vec::new(),
            jwks: None,
            trust_embedded_key: false,
            max_depth: 32,
            max_bytes: 262_144,
        }
    }
}

fn one(file: Option<PathBuf>, g: &GlobalArgs, do_verify: bool) -> i32 {
    let bytes = match read_input(file.as_deref()) {
        Ok(b) => b,
        Err(e) => return emit_caller_error(g, "cli.input_unreadable", e),
    };
    let ctx = match build_context(g) {
        Ok(c) => c,
        Err((code, msg)) => return emit_caller_error(g, code, msg),
    };

    let registry = vcrd_core::registry();
    let report = if do_verify {
        vcrd_core::verify(&bytes, &ctx, &registry)
    } else {
        vcrd_core::inspect(&bytes, &ctx, &registry)
    };

    let code = exit_code::from_report(&report);
    let opts = view::ViewOptions {
        cleartext: g.unsafe_cleartext,
        explain_redaction: g.explain_redaction,
    };
    let envelope = view::from_report(&report, &opts, code);

    if g.unsafe_cleartext {
        // Human-visible on stderr; the structured marker rides in the payload (§8).
        let _ = writeln!(
            std::io::stderr(),
            "!! --unsafe: claim values below are UNREDACTED cleartext. Do not paste into shared logs."
        );
    }
    emit(g, &envelope);
    code
}

fn emit(g: &GlobalArgs, envelope: &view::Envelope) {
    if g.verbosity == 0 {
        return;
    }
    let out = match g.format {
        Format::Json => serde_json::to_string_pretty(envelope).unwrap_or_else(|e| format!("{{\"serialize_error\":\"{e}\"}}")),
        Format::Text => render::text(envelope, g.verbosity),
        Format::Plain => render::plain(envelope),
    };
    let mut stdout = std::io::stdout();
    let _ = writeln!(stdout, "{}", out.trim_end());
}

/// A caller fault still produces a full envelope on stdout when JSON was asked for --
/// an agent should never have to parse a bare stderr string.
fn emit_caller_error(g: &GlobalArgs, code: &'static str, message: String) -> i32 {
    let envelope = view::caller_error(code, message.clone());
    if g.verbosity > 0 {
        match g.format {
            Format::Json => {
                let s = serde_json::to_string_pretty(&envelope).unwrap_or_default();
                let _ = writeln!(std::io::stdout(), "{s}");
            }
            _ => {
                let _ = writeln!(std::io::stderr(), "vcrd: {code}: {message}");
            }
        }
    }
    exit_code::CALLER_ERROR
}

fn read_input(file: Option<&std::path::Path>) -> Result<Vec<u8>, String> {
    match file {
        Some(p) if p.as_os_str() != "-" => {
            std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))
        }
        _ => {
            if std::io::stdin().is_terminal() {
                return Err("no input file given and stdin is a terminal".to_string());
            }
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf).map_err(|e| format!("stdin: {e}"))?;
            Ok(buf)
        }
    }
}

fn build_context(g: &GlobalArgs) -> Result<Context, (&'static str, String)> {
    let clock = resolve_clock(g.now.as_deref())?;

    let policy = if g.allow_alg.is_empty() {
        AlgPolicy::allow_all()
    } else {
        AlgPolicy::allow(g.allow_alg.clone())
    };

    let keys: Box<dyn vcrd_core::keys::KeyStore> = match &g.jwks {
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .map_err(|e| ("cli.jwks_unreadable", format!("{}: {e}", p.display())))?;
            let v: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| ("cli.jwks_invalid", format!("{}: {e}", p.display())))?;
            let keys = v
                .get("keys")
                .and_then(|k| k.as_array())
                .cloned()
                .unwrap_or_else(|| vec![v.clone()]);
            Box::new(JwkSetStore { keys })
        }
        None => Box::new(vcrd_core::keys::EmptyKeyStore),
    };

    Ok(Context::builder(clock)
        .alg_policy(policy)
        .keys(keys)
        .skew_seconds(g.skew_seconds)
        .trust_embedded_key(g.trust_embedded_key)
        .limits(Limits { max_bytes: g.max_bytes, max_depth: g.max_depth, max_claims: 512 })
        .redaction(if g.unsafe_cleartext { RedactionPolicy::Cleartext } else { RedactionPolicy::Redact })
        .build())
}

/// The cost of core having no default clock, made concrete. With `std-clock` off,
/// `--now` is mandatory and the error has to say so.
fn resolve_clock(now: Option<&str>) -> Result<Box<dyn vcrd_core::Clock>, (&'static str, String)> {
    if let Some(s) = now {
        let t = OffsetDateTime::parse(s, &Rfc3339)
            .map_err(|e| ("cli.now_unparseable", format!("--now {s}: {e}")))?;
        return Ok(Box::new(vcrd_core::FixedClock(t)));
    }
    #[cfg(feature = "std-clock")]
    {
        Ok(Box::new(vcrd_core::context::SystemClock))
    }
    #[cfg(not(feature = "std-clock"))]
    {
        Err((
            "cli.no_clock",
            "vcrd-core was built without the std-clock feature, so --now is required".to_string(),
        ))
    }
}

/// §6 wants structural-limit defaults "derived from measurement, not guessed".
fn measure(files: &[PathBuf]) -> i32 {
    println!("{:<28} {:>8} {:>12} {:>8}", "FILE", "BYTES", "PAYLOAD B", "DEPTH");
    let mut worst_bytes = 0usize;
    let mut worst_depth = 0usize;
    for f in files {
        let Ok(bytes) = std::fs::read(f) else {
            continue;
        };
        let name = f.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let (payload_len, depth) = match vcrd_core::jws::parse_compact(&bytes) {
            Ok(p) => {
                let d = vcrd_core::limits::measure_depth(&p.payload_bytes, usize::MAX).unwrap_or(0);
                (p.payload_bytes.len(), d)
            }
            Err(_) => (0, 0),
        };
        worst_bytes = worst_bytes.max(bytes.len());
        worst_depth = worst_depth.max(depth);
        println!("{name:<28} {:>8} {payload_len:>12} {depth:>8}", bytes.len());
    }
    println!("\nobserved maxima: {worst_bytes} bytes, depth {worst_depth}");
    exit_code::OK
}
