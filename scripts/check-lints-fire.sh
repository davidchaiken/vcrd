#!/usr/bin/env bash
# Checks that the workspace lint policy (Cargo.toml, clippy.toml) fires, rather
# than being silently unconfigured (DEVELOPMENT-PLAN.md, milestone 0). Each case
# plants one fault in a throwaway copy of the repository and runs clippy on it,
# the prototype's method made repeatable:
#
#   1. The unmodified copy passes, so every later failure is caused by the fault
#      planted for it.
#   2. In the non-test code of every crate root, each denied clippy lint fails
#      the build, and so does an `unsafe` block.
#   3. In test code, the lints clippy.toml exempts pass, and the others still
#      fail.
#   4. Each crate root carries #![forbid(unsafe_code)] and Cargo.toml forbids
#      unsafe_code. Case 2 passes while either one remains, so it cannot see one
#      of them removed.
#
# Not covered: a helper function in tests/*.rs, outside any #[test] function,
# gets no exemption from clippy (0.1.98), so it is held to the non-test rules.
#
# The working tree is never modified. Needs bash (3.2 or later), git, tar, jq
# and cargo.
set -euo pipefail

repo=$(git rev-parse --show-toplevel)
work=$(mktemp -d "${TMPDIR:-/tmp}/vcrd-lints-fire.XXXXXX")
orig=$(mktemp -d "${TMPDIR:-/tmp}/vcrd-lints-fire-orig.XXXXXX")
trap 'rm -rf "$work" "$orig"' EXIT
export CARGO_TARGET_DIR="$repo/target/lints-fire"

# Copy the files git sees, tracked or untracked but not ignored, as they are on
# disk now, so uncommitted edits are checked too.
(
  cd "$repo"
  git ls-files -z --cached --others --exclude-standard |
    while IFS= read -r -d '' f; do
      if [ -e "$f" ]; then printf '%s\0' "$f"; fi
    done |
    tar -cf - --null -T -
) | tar -xf - -C "$work"
cd "$work"

# The crate roots come from [workspace.metadata.lints-fire] in Cargo.toml, one
# path per line; crate paths contain no whitespace. Every workspace member must
# have one.
metadata=$(cargo metadata --no-deps --format-version 1 --locked)
# shellcheck disable=SC2207
roots=($(jq -r '.metadata["lints-fire"].roots[]?' <<<"$metadata"))
if [ ${#roots[@]} -eq 0 ]; then
  echo "FAIL: no roots in [workspace.metadata.lints-fire] in Cargo.toml" >&2
  exit 1
fi
members=$(jq -r '.workspace_root as $top | .packages[].manifest_path
                 | ltrimstr($top + "/") | rtrimstr("/Cargo.toml")' <<<"$metadata")
for m in $members; do
  covered=no
  for root in "${roots[@]}"; do
    case $root in "$m"/*) covered=yes ;; esac
  done
  if [ "$covered" = no ]; then
    echo "FAIL: workspace member $m has no root in [workspace.metadata.lints-fire]" >&2
    exit 1
  fi
done

for i in "${!roots[@]}"; do cp "${roots[$i]}" "$orig/$i"; done

clippy_out=""
run_clippy() {
  local status
  set +e
  clippy_out=$(cargo clippy --workspace --all-targets --all-features --locked -- -D warnings 2>&1)
  status=$?
  set -e
  return $status
}

fail() {
  echo "FAIL: $*" >&2
  printf '%s\n' "$clippy_out" >&2
  exit 1
}

restore() {
  local i root
  for i in "${!roots[@]}"; do cp "$orig/$i" "${roots[$i]}"; done
  for root in "${roots[@]}"; do rm -f "${root%%/src/*}/tests/lint_canary.rs"; done
}

# Appends Rust source to a file.
plant() {
  printf '\n%s\n' "$2" >>"$1"
}

# Wraps statements in a #[test] function inside a #[cfg(test)] module.
test_module() {
  printf '#[cfg(test)]\nmod lint_canary_tests {\n    #[test]\n    fn lint_canary() {\n        %s\n    }\n}' "$1"
}

# expect_fail LINT FILE CASE: clippy must fail, naming LINT at FILE. The lint is
# named by clippy's help link, by the level set from Cargo.toml's lint tables
# (`-D clippy::unwrap-used`, `-F unsafe-code`), or by a crate attribute.
expect_fail() {
  local lint=$1 file=$2 case=$3 dashed=${1//_/-}
  if run_clippy; then fail "$case: clippy passed"; fi
  if ! grep -q -F -e "index.html#$lint" -e "clippy::$dashed\`" \
    -e "-D $dashed\`" -e "-F $dashed\`" -e "forbid($lint)" <<<"$clippy_out"; then
    fail "$case: clippy failed without naming $lint"
  fi
  if ! grep -q -F -e "--> $file:" <<<"$clippy_out"; then
    fail "$case: clippy failed without pointing at $file"
  fi
  echo "ok: $case"
}

expect_pass() {
  local case=$1
  if ! run_clippy; then fail "$case: clippy failed"; fi
  echo "ok: $case"
}

denied=(unwrap_used expect_used indexing_slicing string_slice panic todo unimplemented unreachable)
non_test=(
  'pub fn lint_canary(x: Option<u8>) -> u8 { x.unwrap() }'
  'pub fn lint_canary(x: Option<u8>) -> u8 { x.expect("canary") }'
  'pub fn lint_canary(v: &[u8]) -> u8 { v[0] }'
  'pub fn lint_canary(s: &str) -> &str { &s[1..] }'
  'pub fn lint_canary() { panic!("canary") }'
  'pub fn lint_canary() { todo!() }'
  'pub fn lint_canary() { unimplemented!() }'
  'pub fn lint_canary() { unreachable!() }'
)

# Lints clippy.toml exempts in tests, all in one test body.
exempt_body='let x: Option<u8> = std::hint::black_box(Some(1));
        let v: &[u8] = std::hint::black_box(&[1]);
        assert_eq!(x.unwrap() + x.expect("canary") + v[0], 3);
        if v.is_empty() {
            panic!("canary");
        }'

# Lints that stay denied in tests, one test body each.
not_exempt=(string_slice todo unimplemented unreachable)
not_exempt_body=(
  'let s: &str = std::hint::black_box("ab"); assert_eq!(&s[1..], "b");'
  'todo!()'
  'unimplemented!()'
  'unreachable!()'
)

# 1. Baseline.
expect_pass "unmodified workspace"

# 2. Non-test code.
for root in "${roots[@]}"; do
  for i in "${!denied[@]}"; do
    restore
    plant "$root" "#[allow(dead_code)]
${non_test[$i]}"
    expect_fail "${denied[$i]}" "$root" "${denied[$i]} denied in $root"
  done
  restore
  plant "$root" '#[allow(dead_code)]
pub fn lint_canary() { unsafe {} }'
  expect_fail unsafe_code "$root" "unsafe block rejected in $root"
done

# 3. Test code.
restore
for root in "${roots[@]}"; do
  plant "$root" "$(test_module "$exempt_body")"
  mkdir -p "${root%%/src/*}/tests"
  printf '#[test]\nfn lint_canary() {\n        %s\n}\n' "$exempt_body" >"${root%%/src/*}/tests/lint_canary.rs"
done
expect_pass "unwrap, expect, indexing and panic exempt in #[cfg(test)] modules and tests/*.rs"

for root in "${roots[@]}"; do
  for i in "${!not_exempt[@]}"; do
    restore
    plant "$root" "$(test_module "${not_exempt_body[$i]}")"
    expect_fail "${not_exempt[$i]}" "$root" "${not_exempt[$i]} still denied in tests in $root"
  done
done
restore

# 4. Both unsafe_code settings present.
for root in "${roots[@]}"; do
  grep -q -x -F '#![forbid(unsafe_code)]' "$root" || {
    echo "FAIL: $root lacks #![forbid(unsafe_code)]" >&2
    exit 1
  }
done
grep -q -x -F 'unsafe_code = "forbid"' Cargo.toml || {
  echo 'FAIL: Cargo.toml lacks unsafe_code = "forbid"' >&2
  exit 1
}
echo "ok: #![forbid(unsafe_code)] in every crate root, and forbidden in Cargo.toml"

echo "All lint checks fired as expected."
