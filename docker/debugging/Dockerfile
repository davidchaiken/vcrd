# The Linux environment of the debugging guide (docs/debugging.md, "From the command
# line"; ARCHITECTURE §10 [G2]): Ubuntu 26.04, CodeLLDB's lldb, and the
# toolchain that rust-toolchain.toml pins, for rust-lldb on the command line. It holds
# no source: the guide mounts the repository, read-only. Build it from the repository's
# root; Dockerfile.dockerignore, beside this file, lets only rust-toolchain.toml into
# the build:
#
#   docker build -f docker/debugging/Dockerfile -t vcrd-debug .

# The platform being built, arm64 or amd64, which picks CodeLLDB's package below.
ARG TARGETARCH

# ubuntu:26.04, by the digest of its multi-arch index, so that one line serves arm64
# and x86_64. Read from Docker Hub on 2026-11-25; the tag was last updated on
# 2026-11-16.
FROM docker.io/library/ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db AS base

# Ubuntu's archive as it was at one time (snapshot.ubuntu.com), so that apt installs
# the same packages whenever the image is built: 00:00 UTC on 2026-11-25, the day this
# file was written, after the base image's last update. The time moves with the base
# image's digest when the guide is run again. From 24.04 on, apt reads snapshots of
# Ubuntu's own archive without other configuration. It reads them over HTTPS, and the
# base image has no certificate authorities to verify the server with: ca-certificates,
# and openssl, which it needs, come first, from the archive as it is at the build. Each
# step that runs apt-get update removes the package lists it downloaded, so that they
# stay out of the image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && echo 'APT::Snapshot "20261125T000000Z";' > /etc/apt/apt.conf.d/50snapshot

# - rustup: Ubuntu's package. Its proxies, cargo, rustc and rust-lldb among them, run
#   the toolchain a rust-toolchain.toml names.
# - gcc and libc6-dev: the linker rustc calls.
# - unzip: to unpack CodeLLDB's package, below.
# - jq, bc, xxd and openssl, beside the base image's bash and base64: what the scripts
#   in scripts/debugging need.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      rustup gcc libc6-dev unzip jq bc xxd openssl \
 && rm -rf /var/lib/apt/lists/*

# The lldb: CodeLLDB 1.12.3's, 22.1.8-codelldb, from its package for Linux on the
# platform being built. With Rust 1.99.1's formatters, Ubuntu's lldb, LLVM's own and
# Apple's show some enums that carry data as a variant they do not hold; CodeLLDB's
# shows them correctly (docs/debugging.md). If a stock lldb comes to show them
# correctly, the image takes its lldb from Ubuntu's archive again (DEVELOPMENT-PLAN.md,
# milestone 2, the Rust 1.101 task). Each package is pinned by the SHA-256 its
# release page gives, and ADD fails if the download differs. BuildKit, Docker's
# builder, runs only the stages the last one depends on, so only the package for the
# platform being built is downloaded. It is mounted where it is unpacked, so that it
# stays out of the image. (Docker's older builder would run every stage, but it cannot
# build this file: it has neither ADD --checksum nor RUN --mount.)
FROM scratch AS codelldb-arm64
ADD --checksum=sha256:0887f67d440554617894266f80706b700907c36b95e6e49d23b95a0e05318101 \
    https://github.com/vadimcn/codelldb/releases/download/v1.12.3/codelldb-linux-arm64.vsix \
    /codelldb.vsix

FROM scratch AS codelldb-amd64
ADD --checksum=sha256:1cd7f386598022b51a5b93b9ffa23e812b23f519cfe1833384ec4bef4bfd1be1 \
    https://github.com/vadimcn/codelldb/releases/download/v1.12.3/codelldb-linux-x64.vsix \
    /codelldb.vsix

FROM codelldb-${TARGETARCH} AS codelldb

FROM base

# The package's extension/ directory holds lldb, lldb-server, and the Python that lldb
# runs scripts with. rust-lldb runs the first lldb on PATH, with the toolchain's
# formatters.
RUN --mount=type=bind,from=codelldb,source=/codelldb.vsix,target=/tmp/codelldb.vsix \
    unzip -q /tmp/codelldb.vsix 'extension/*' -d /opt/codelldb \
 && chmod -R a+rX /opt/codelldb \
 && chmod a+x /opt/codelldb/extension/lldb/bin/*
ENV PATH=/opt/codelldb/extension/lldb/bin:$PATH

# The base image's unprivileged user, ubuntu, runs everything from here on. The guide
# mounts named volumes on cargo's directory and on the build's; made here, they are the
# user's.
ENV CARGO_TARGET_DIR=/home/ubuntu/target
RUN mkdir -p /home/ubuntu/.cargo /home/ubuntu/target \
 && chown -R ubuntu:ubuntu /home/ubuntu
USER ubuntu

# lldb starts a program with address-space randomization turned off, by personality(2),
# which Docker's default seccomp profile refuses: without this setting, run fails with
# "personality set failed: Operation not permitted" (checked 2026-11-27). Leaving it on
# lets lldb trace the program without seccomp relaxed or a capability added.
RUN echo 'settings set target.disable-aslr false' > /home/ubuntu/.lldbinit

# Ubuntu's rustup, 1.27, installs the toolchain a rust-toolchain.toml names, with its
# components, the first time a proxy runs in the file's directory. The last command
# shows that lldb's Python runs.
WORKDIR /home/ubuntu/toolchain
COPY rust-toolchain.toml .
RUN cargo --version && rustc --print sysroot && rust-lldb --version \
 && lldb --batch -o 'script import sys; print(sys.version)'

WORKDIR /src
