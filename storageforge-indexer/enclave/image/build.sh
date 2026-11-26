#!/bin/sh
# Builds the key enclave's image: a kernel and an initramfs holding one static program (roadmap section 14, "The image").
#
#   image/build.sh [out-folder]        out/vmlinux, out/bzImage, out/initramfs.cpio.gz, out/SHA256SUMS
#   ARCH=arm64 image/build.sh [out]    the same for arm64, cross-compiled: out/Image, out/initramfs.cpio.gz, out/SHA256SUMS
#
# image/SHA256SUMS and image/SHA256SUMS.arm64 record what the build gives for the sources as they are committed: CI builds and
# compares, and whoever changes the program or the kernel list builds, looks, and commits the new lines with the change.
# image/sign.sh signs a built image with the release key.
#
# Everything is built in containers pinned by digest, from sources pinned by checksum, with the timestamps and names that would differ
# between two builds fixed, so that anyone can build it again and compare SHA256SUMS. Needs docker. Takes about ten minutes, most of
# it the kernel.
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd)
ARCH=${ARCH:-x86_64}
OUT=${1:-$HERE/image/out$([ "$ARCH" = x86_64 ] || echo "-$ARCH")}
RUST_IMAGE=rust@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33      # rust 1.100.0 on Alpine 3.24: musl, so the program is static
KERNEL=6.18.65
KERNEL_SHA256=c92606f956f09dc50b5a0e2af9e86763fce27ada1647de97f8d1ac8cfc95801d
EPOCH=1794960000                 # 2026-11-17: every file in the image carries this time
JOBS=${JOBS:-4}
mkdir -p "$OUT"

# The enclave is one member of the Cargo workspace in the folder above: the build sees that workspace's manifest, its lock file
# and its members, and nothing else of the repository.
WS=$(cd "$HERE/.." && pwd)
run() { docker run --rm -v "$WS/Cargo.toml":/ws/Cargo.toml:ro -v "$WS/Cargo.lock":/ws/Cargo.lock:ro -v "$WS/wire":/ws/wire:ro -v "$WS/agent":/ws/agent:ro \
        -v "$HERE":/ws/enclave:ro -e SRC=/ws/enclave -e WORKSPACE=/ws -v "$OUT":/out -e EPOCH=$EPOCH -e KERNEL=$KERNEL -e KERNEL_SHA256=$KERNEL_SHA256 -e JOBS="$JOBS" -e IMAGE_ARCH="$ARCH" "$RUST_IMAGE" \
        sh -euc 'sh /ws/enclave/image/inside.sh "$1"; chown -R "$2" /out' sh "$1" "$(id -u):$(id -g)"; }

# The steps themselves are in image/inside.sh, which the Dockerfile's `enclave` stage runs too. The versions and the time above
# are repeated there as build arguments: change them in both.
echo "== the program, static";    run program
echo "== the initramfs: one file"; run initramfs
echo "== the kernel $KERNEL";      run kernel
OUT="$OUT" IMAGE_ARCH="$ARCH" sh "$HERE/image/inside.sh" sums
