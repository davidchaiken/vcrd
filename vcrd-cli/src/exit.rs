//! Exit codes (REQUIREMENTS §8; ARCHITECTURE §6).

use vcrd_core::{Attribution, Phase, Report, Severity};

pub const PASSED: u8 = 0;
pub const CALLER_FAULT: u8 = 1;
pub const POLICY: u8 = 5;
pub const UNSUPPORTED: u8 = 6;

/// The exit code and `status` for a report. Over the error findings of the whole
/// result, `contained` included: any attributed to vcrd gives 6; otherwise any
/// attributed to the caller's policy gives 5; otherwise the earliest failed phase
/// anywhere gives 2, 3 or 4. `status` names the earliest failed phase.
pub fn exit_code(report: &Report) -> (u8, &'static str) {
    let mut vcrd = false;
    let mut policy = false;
    let mut earliest: Option<Phase> = None;
    visit(report, &mut |r| {
        for f in r.findings().filter(|f| f.severity == Severity::Error) {
            vcrd |= f.attribution == Attribution::Vcrd;
            policy |= f.attribution == Attribution::Policy;
        }
        let failed = [
            (Phase::Parse, r.parse.is_failed()),
            (Phase::Inspect, r.inspect.is_failed()),
            (Phase::Verify, r.verify.is_failed()),
        ];
        if let Some((phase, _)) = failed.into_iter().find(|(_, failed)| *failed) {
            earliest = Some(earliest.map_or(phase, |e| e.min(phase)));
        }
    });
    let status = match earliest {
        None => "passed",
        Some(Phase::Parse) => "parse_failed",
        Some(Phase::Inspect) => "inspect_failed",
        Some(Phase::Verify) => "verify_failed",
    };
    let code = if vcrd {
        UNSUPPORTED
    } else if policy {
        POLICY
    } else {
        match earliest {
            None => PASSED,
            Some(Phase::Parse) => 2,
            Some(Phase::Inspect) => 3,
            Some(Phase::Verify) => 4,
        }
    };
    (code, status)
}

fn visit(report: &Report, f: &mut impl FnMut(&Report)) {
    f(report);
    for contained in &report.contained {
        visit(contained, f);
    }
}
