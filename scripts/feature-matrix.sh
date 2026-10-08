#!/usr/bin/env bash
# Lints, checks and tests the supported feature builds (ARCHITECTURE §2;
# REQUIREMENTS §13), then checks that vcrd-cli refuses to build with no format or
# no proof suite. With --powerset, vcrd-core runs in every combination of its
# features instead: the check that ARCHITECTURE §2's rules hold, which CI runs on
# every change and `make ci-ok` leaves out.
#
# vcrd-core's builds come from cargo-hack, which reads the features from
# vcrd-core/Cargo.toml. --each-feature is: no features, each feature alone, the
# default set, and all features. cargo-hack prints each build's cargo command
# before running it; that is the command to rerun one build on its own, with a
# test name added to narrow it further. Every step runs even when an earlier one
# fails, and the failures are listed at the end.
#
# Each build selects one package (cargo-hack passes vcrd-core's manifest path;
# the vcrd-cli steps pass -p), never the workspace: cargo merges the features of
# every package selected in one invocation, so a workspace build would turn vc-jose
# on in vcrd-core through vcrd-cli.
#
# Runs with whatever toolchain rustup selects: rust-toolchain.toml's, or
# RUSTUP_TOOLCHAIN's when set. Needs bash (3.2 or later), git, and cargo-hack in
# target/tools (`make tools-hack`).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
export PATH="$PWD/target/tools/bin:$PATH"

case "${1-}" in
  "") builds=(--each-feature) ;;
  # `default` is a feature to cargo-hack; excluding it leaves the 2^n combinations
  # of the others, without duplicates.
  --powerset) builds=(--feature-powerset --exclude-features default) ;;
  *)
    echo "usage: $0 [--powerset]" >&2
    exit 2
    ;;
esac

failed=()

# step NAME COMMAND...: runs COMMAND, and records NAME if it fails.
step() {
  local name=$1
  shift
  echo "==> $name"
  if ! "$@"; then failed+=("$name"); fi
}

# must_fail FEATURES MESSAGE: vcrd-cli must refuse to build with only these
# features, and for the reason its compile_error! gives.
must_fail() {
  local features=$1 message=$2 out
  # --color never: the message is searched, whatever CARGO_TERM_COLOR says.
  if out=$(cargo build --color never -p vcrd-cli --no-default-features ${features:+--features "$features"} --locked 2>&1); then
    echo "FAIL: vcrd-cli built with features '$features'" >&2
    return 1
  fi
  if ! grep -q -F "$message" <<<"$out"; then
    printf 'FAIL: vcrd-cli failed to build for a reason other than its compile_error!\n%s\n' "$out" >&2
    return 1
  fi
  echo "ok: refused to build, with the compile_error! message"
}

# No code may depend on two features at once (ARCHITECTURE §2). This finds a cfg
# that names two features inside all(...) on one line; `any` is allowed. A cfg
# wrapped across lines escapes it.
no_combined_cfg() {
  if git grep --untracked -n -E 'cfg(_attr)?\(.*all\(.*feature.*feature' -- '*.rs'; then
    echo "FAIL: the cfg above combines features with all(...)" >&2
    return 1
  fi
  echo "ok: no cfg combines features with all(...)"
}

hack=(cargo hack -p vcrd-core "${builds[@]}" --keep-going)

step "no cfg combines features" no_combined_cfg
step "vcrd-core: clippy" "${hack[@]}" clippy --all-targets --locked -- -D warnings
# The library alone, so that dev-dependencies' features are off: resolver 3 turns
# them on for tests, examples and --all-targets, which is every step above and
# below, so a library that relied on one of them would pass those.
step "vcrd-core: library without dev-dependency features" "${hack[@]}" check --lib --locked
step "vcrd-core: tests" "${hack[@]}" test --locked --no-fail-fast
step "vcrd-cli: clippy" cargo clippy -p vcrd-cli --all-targets --locked -- -D warnings
step "vcrd-cli: tests" cargo test -p vcrd-cli --locked --no-fail-fast
step "vcrd-cli with no format (must fail)" \
  must_fail "" "vcrd-cli needs at least one credential format feature"
step "vcrd-cli with no proof suite (must fail)" \
  must_fail "vc-jose" "vcrd-cli needs at least one proof suite feature"

if [ ${#failed[@]} -gt 0 ]; then
  echo >&2
  echo "FAILED:" >&2
  printf '  %s\n' "${failed[@]}" >&2
  exit 1
fi
echo "Every build passed."
