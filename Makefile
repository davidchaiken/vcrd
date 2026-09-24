# The CI jobs. Each job in .github/workflows/ci.yml runs one of these targets,
# so the commands and tool versions live only here.
#
#   make ci-ok          the four jobs ci-ok requires, in order, stopping at the
#                       first failure
#   make -k ci-ok       the same, but running every job and reporting each failure
#   make latest-stable  the non-blocking job, on the latest stable toolchain
#
# Runs the toolchain named in rust-toolchain.toml. cargo-deny and cargo-audit are
# built into target/tools rather than ~/.cargo/bin, at the versions below; the
# first build takes a few minutes. Needs GNU make 3.81 or later (macOS ships 3.81).

CARGO_DENY_VERSION := 0.20.2
CARGO_AUDIT_VERSION := 0.22.2
TOOLS := target/tools

.PHONY: help ci-ok fmt test lints-fire supply-chain latest-stable tools

help:
	@echo "make ci-ok          fmt, test, lints-fire and supply-chain, as CI's ci-ok requires"
	@echo "make -k ci-ok       the same, continuing past failures"
	@echo "make fmt | test | lints-fire | supply-chain    one job"
	@echo "make latest-stable  the non-blocking job, on the latest stable toolchain"
	@echo "make tools          build cargo-deny and cargo-audit into $(TOOLS)"

# Keep equal to the needs of the ci-ok job in ci.yml.
ci-ok: fmt test lints-fire supply-chain
	@echo "ci-ok: every required job passed"

fmt:
	cargo fmt --all --check

test:
	scripts/feature-matrix.sh

lints-fire:
	scripts/check-lints-fire.sh

supply-chain: tools
	$(TOOLS)/bin/cargo-deny deny --locked check
	$(TOOLS)/bin/cargo-audit audit --deny warnings

latest-stable:
	RUSTUP_TOOLCHAIN=stable scripts/feature-matrix.sh

tools:
	cargo install --locked --root $(TOOLS) cargo-deny@$(CARGO_DENY_VERSION) cargo-audit@$(CARGO_AUDIT_VERSION)
