# The CI jobs. Each job in .github/workflows/ci.yml runs one of these targets,
# so the commands and tool versions live only here.
#
#   make ci-ok          the jobs ci-ok requires except test-powerset, in order,
#                       stopping at the first failure
#   make -k ci-ok       the same, but running every job and reporting each failure
#   make latest-stable  the non-blocking job, on the latest stable toolchain
#   make test-powerset  every combination of vcrd-core's features: required in CI,
#                       left out of make ci-ok
#   make clean          our crates' build output; dependencies and tools stay
#   make clean-build    all build output, lints-fire's included; tools stay
#   make clean-all      everything, the tools included
#
# Runs the toolchain named in rust-toolchain.toml. cargo-hack, cargo-deny and
# cargo-audit are built into target/tools rather than ~/.cargo/bin, at the versions
# below; the first build takes a few minutes. Needs GNU make 3.81 or later (macOS
# ships 3.81).

CARGO_HACK_VERSION := 0.6.45
CARGO_DENY_VERSION := 0.20.2
CARGO_AUDIT_VERSION := 0.22.2
TOOLS := target/tools

.PHONY: help ci-ok fmt test lints-fire supply-chain latest-stable test-powerset \
	tools-hack tools-supply-chain clean clean-build clean-all

help:
	@echo "make ci-ok          fmt, test, lints-fire and supply-chain, as CI's ci-ok requires"
	@echo "make -k ci-ok       the same, continuing past failures"
	@echo "make fmt | test | lints-fire | supply-chain    one job"
	@echo "make latest-stable  the non-blocking job, on the latest stable toolchain"
	@echo "make test-powerset  every combination of vcrd-core's features (CI requires it; ci-ok here does not run it)"
	@echo "make tools-hack | tools-supply-chain    build the tools into $(TOOLS)"
	@echo "make clean          our crates' build output; dependencies and tools stay"
	@echo "make clean-build    all build output, lints-fire's included; tools stay"
	@echo "make clean-all      everything, the tools included"

# Keep equal to the needs of the ci-ok job in ci.yml, less test-powerset: locally,
# the supported builds are enough, and `make test-powerset` runs the rest on demand.
ci-ok: fmt test lints-fire supply-chain
	@echo "ci-ok: every required job passed; CI also requires test-powerset"

fmt:
	cargo fmt --all --check

# The supported feature builds (ARCHITECTURE §2).
test: tools-hack
	scripts/feature-matrix.sh

lints-fire:
	scripts/check-lints-fire.sh

# -D unmatched-skip: a [bans] skip entry in deny.toml that no longer matches fails,
# so that it is removed when the duplicate it excuses goes away.
supply-chain: tools-supply-chain
	$(TOOLS)/bin/cargo-deny deny --locked check -D unmatched-skip
	$(TOOLS)/bin/cargo-audit audit --deny warnings

latest-stable: tools-hack
	RUSTUP_TOOLCHAIN=stable scripts/feature-matrix.sh

test-powerset: tools-hack
	scripts/feature-matrix.sh --powerset

# cargo install does nothing when the version asked for is already installed.
tools-hack:
	cargo install --locked --root $(TOOLS) cargo-hack@$(CARGO_HACK_VERSION)

tools-supply-chain:
	cargo install --locked --root $(TOOLS) cargo-deny@$(CARGO_DENY_VERSION) cargo-audit@$(CARGO_AUDIT_VERSION)

# Three levels of clean, from the quickest rebuild to the slowest. Plain `cargo
# clean` deletes all of target/, the tools with it. clean-all does the same, and
# also removes the tools and lints-fire's build when CARGO_TARGET_DIR points
# elsewhere.
clean:
	cargo clean -p vcrd-core -p vcrd-cli

# The dev and release profiles, the docs, the scratch directory cargo gives
# integration tests (CARGO_TARGET_TMPDIR, the target directory's tmp/), and the
# target directory scripts/check-lints-fire.sh builds in.
clean-build:
	cargo clean --profile dev
	cargo clean --release
	cargo clean --doc
	rm -rf "$${CARGO_TARGET_DIR:-target}/tmp"
	CARGO_TARGET_DIR=target/lints-fire cargo clean

clean-all: clean-build
	cargo clean
	rm -rf $(TOOLS)
