#!/bin/sh
# Builds the key enclave's image: a kernel and an initramfs holding one static program (roadmap section 14, "The image").
#
#   image/build.sh [out-folder]        out/vmlinux, out/bzImage, out/initramfs.cpio.gz, out/SHA256SUMS
#
# Everything is built in containers pinned by digest, from sources pinned by checksum, with the timestamps and names that would differ
# between two builds fixed, so that anyone can build it again and compare SHA256SUMS. Needs docker. Takes about ten minutes, most of
# it the kernel.
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$HERE/image/out}
RUST_IMAGE=rust@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33      # rust 1.100.0 on Alpine 3.24: musl, so the program is static
KERNEL=6.18.64
KERNEL_SHA256=020d45510c539972e6f14c5c71566878d3b7ef56fb082b3e09134f2ebaade562
EPOCH=1794960000                 # 2026-11-17: every file in the image carries this time
JOBS=${JOBS:-4}
mkdir -p "$OUT"

run() { docker run --rm -v "$HERE":/src:ro -v "$OUT":/out -e EPOCH=$EPOCH -e KERNEL=$KERNEL -e KERNEL_SHA256=$KERNEL_SHA256 -e JOBS="$JOBS" "$RUST_IMAGE" \
        sh -euc 'sh /src/image/inside.sh "$1"; chown -R "$2" /out' sh "$1" "$(id -u):$(id -g)"; }

# The steps themselves are in image/inside.sh, which the Dockerfile's `enclave` stage runs too. The versions and the time above
# are repeated there as build arguments: change them in both.
echo "== the program, static";    run program
echo "== the initramfs: one file"; run initramfs
echo "== the kernel $KERNEL";      run kernel
OUT="$OUT" sh "$HERE/image/inside.sh" sums
