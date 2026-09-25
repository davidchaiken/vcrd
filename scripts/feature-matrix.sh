#!/usr/bin/env bash
# Lints and tests every supported feature combination (REQUIREMENTS §13;
# DEVELOPMENT-PLAN.md, milestones 0 and 1): vcrd-core in every combination of its
# three features, and vcrd-cli with its defaults. Then checks that vcrd-cli refuses
# to build with no format or no proof suite, and that the built `vcrd` answers
# --help and --version.
#
# Each combination is its own cargo invocation with -p, not --workspace: cargo
# merges the features of every package selected in one invocation, so a
# workspace build would turn vc-jose on in vcrd-core through vcrd-cli.
#
# Runs with whatever toolchain rustup selects: rust-toolchain.toml's, or
# RUSTUP_TOOLCHAIN's when set. Needs bash (3.2 or later), git, jq and cargo.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# vcrd-core's features: vc-jose (a format), jws (a proof suite) and std-clock.
combinations=(
  "-p vcrd-core --no-default-features"
  "-p vcrd-core --no-default-features --features std-clock"
  "-p vcrd-core --no-default-features --features vc-jose"
  "-p vcrd-core --no-default-features --features vc-jose,std-clock"
  "-p vcrd-core --no-default-features --features jws"
  "-p vcrd-core --no-default-features --features jws,std-clock"
  "-p vcrd-core --no-default-features --features vc-jose,jws"
  "-p vcrd-core --no-default-features --features vc-jose,jws,std-clock"
  "-p vcrd-cli"
)

for combination in "${combinations[@]}"; do
  echo "==> $combination"
  # shellcheck disable=SC2086 # each combination is several arguments
  cargo clippy $combination --all-targets --locked -- -D warnings
  # shellcheck disable=SC2086
  cargo test $combination --locked
done

# must_fail <features> <message>: vcrd-cli must refuse to build with only these
# features, and for the reason its compile_error! gives.
must_fail() {
  local features=$1 message=$2 out status
  echo "==> -p vcrd-cli --no-default-features${features:+ --features $features} (must fail)"
  set +e
  # --color never: the message is searched below, whatever CARGO_TERM_COLOR says.
  out=$(cargo build --color never -p vcrd-cli --no-default-features ${features:+--features "$features"} --locked 2>&1)
  status=$?
  set -e
  if [ $status -eq 0 ]; then
    echo "FAIL: vcrd-cli built with features '$features'" >&2
    exit 1
  fi
  if ! grep -q -F "$message" <<<"$out"; then
    printf 'FAIL: vcrd-cli failed to build for a reason other than its compile_error!\n%s\n' "$out" >&2
    exit 1
  fi
  echo "ok: refused to build, with the compile_error! message"
}

must_fail "" "vcrd-cli needs at least one credential format feature"
must_fail "vc-jose" "vcrd-cli needs at least one proof suite feature"

echo "==> vcrd --help and vcrd --version"
cargo build -p vcrd-cli --locked
# Ask cargo where it built the binary, which CARGO_TARGET_DIR can move.
metadata=$(cargo metadata --no-deps --format-version 1 --locked)
vcrd="$(jq -r .target_directory <<<"$metadata")/debug/vcrd"
"$vcrd" --help >/dev/null
version=$("$vcrd" --version)
expected="vcrd $(jq -r '.packages[] | select(.name == "vcrd-cli") | .version' <<<"$metadata")"
if [ "$version" != "$expected" ]; then
  echo "FAIL: vcrd --version printed '$version', expected '$expected'" >&2
  exit 1
fi
echo "ok: $version"

echo "Every feature combination passed."
