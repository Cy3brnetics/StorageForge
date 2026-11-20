#!/bin/sh
# Builds the agent's two programs, static, for x86_64 and arm64 (roadmap section 11.1, "Language" and "Base image").
#
#   agent/build.sh [out-folder]     out/x86_64/storageforge-agent, out/x86_64/storageforge-agentctl, the same under out/aarch64,
#                                   and out/SHA256SUMS
#   agent/build.sh --test           the Rust unit tests, in the same container
#
# Built in the container the key enclave is built in, pinned by digest, from Cargo.lock, with the time and the paths that would
# differ between two builds fixed: anyone can build it again and compare SHA256SUMS. CI builds twice and compares.
# STORAGEFORGE_RELEASE_SIGNERS=FILE compiles in another signers file than agent/release_signers, for a build of one's own: the
# lab builds with a key it made, and a release with the owner's. Needs docker.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
WS=$(cd "$HERE/.." && pwd)
RUST_IMAGE=rust@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33      # rust 1.100.0 on Alpine 3.24, as enclave/image/build.sh
EPOCH=1794960000
JOBS=${JOBS:-4}
SIGNERS=${STORAGEFORGE_RELEASE_SIGNERS:-$HERE/release_signers}

run() { docker run --rm -v "$WS/Cargo.toml":/ws/Cargo.toml:ro -v "$WS/Cargo.lock":/ws/Cargo.lock:ro -v "$WS/wire":/ws/wire:ro -v "$WS/agent":/ws/agent:ro \
        -v "$WS/enclave":/ws/enclave:ro -v "$SIGNERS":/release_signers:ro -e STORAGEFORGE_RELEASE_SIGNERS=/release_signers \
        -e WORKSPACE=/ws -e EPOCH=$EPOCH -e CARGO_BUILD_JOBS="$JOBS" "$@"; }

if [ "${1:-}" = --test ]; then
  run "$RUST_IMAGE" sh /ws/agent/inside.sh test
  exit 0
fi
OUT=${1:-$HERE/out}
mkdir -p "$OUT"
for arch in x86_64 aarch64; do
  echo "== the agent and storageforge-agentctl, static, $arch"
  run -v "$OUT":/out "$RUST_IMAGE" sh -euc 'sh /ws/agent/inside.sh "$1"; chown -R "$2" /out' sh "$arch" "$(id -u):$(id -g)"
done
OUT="$OUT" sh "$HERE/inside.sh" sums
