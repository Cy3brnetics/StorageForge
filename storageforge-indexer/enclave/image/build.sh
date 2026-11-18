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

echo "== the program, static"
docker run --rm -v "$HERE":/src:ro -v "$OUT":/out -e SOURCE_DATE_EPOCH=$EPOCH "$RUST_IMAGE" sh -euc '
  cp -r /src /build && cd /build && rm -rf target image/out
  RUSTFLAGS="-C target-feature=+crt-static --remap-path-prefix=/build=. --remap-path-prefix=/usr/local/cargo=cargo" cargo build --release --locked --quiet --target x86_64-unknown-linux-musl
  file=target/x86_64-unknown-linux-musl/release/storageforge-enclave
  ! ( readelf -d "$file" 2>/dev/null | grep -q NEEDED ) || { echo "the program is not static" >&2; exit 1; }
  cp "$file" /out/init && chown '"$(id -u):$(id -g)"' /out/init'

echo "== the initramfs: one file"
docker run --rm -v "$OUT":/out -e EPOCH=$EPOCH "$RUST_IMAGE" sh -euc '
  apk add --no-cache -q cpio gzip >/dev/null
  mkdir /root/fs && cp /out/init /root/fs/init && chmod 0555 /root/fs/init && touch -d "@$EPOCH" /root/fs/init /root/fs
  cd /root/fs && printf "init\n" | cpio --quiet -o -H newc --owner 0:0 --reproducible | gzip -n -9 > /out/initramfs.cpio.gz
  chown '"$(id -u):$(id -g)"' /out/initramfs.cpio.gz'

echo "== the kernel $KERNEL"
docker run --rm -v "$HERE/image/kernel.config":/kernel.config:ro -v "$OUT":/out -e KERNEL=$KERNEL -e KERNEL_SHA256=$KERNEL_SHA256 -e EPOCH=$EPOCH -e JOBS="$JOBS" "$RUST_IMAGE" sh -euc '
  apk add --no-cache -q bash build-base bc bison flex elfutils-dev openssl-dev perl linux-headers xz curl findutils diffutils >/dev/null
  cd /root && curl -fsSL -o linux.tar.xz "https://cdn.kernel.org/pub/linux/kernel/v${KERNEL%%.*}.x/linux-$KERNEL.tar.xz"
  echo "$KERNEL_SHA256  linux.tar.xz" | sha256sum -c - >/dev/null
  tar -xf linux.tar.xz && cd "linux-$KERNEL"
  export KBUILD_BUILD_TIMESTAMP="@$EPOCH" KBUILD_BUILD_USER=storageforge KBUILD_BUILD_HOST=enclave KBUILD_BUILD_VERSION=1 SOURCE_DATE_EPOCH=$EPOCH
  make -s tinyconfig
  grep -v "^#" /kernel.config | grep . | while IFS="=" read -r name value; do
    case $value in y) scripts/config --enable "$name" ;; n) scripts/config --disable "$name" ;; *) scripts/config --set-val "$name" "$value" ;; esac
  done
  make -s olddefconfig
  # every line asked for has to have taken: a dependency that is missing drops an option without a word
  grep -v "^#" /kernel.config | grep . | while IFS="=" read -r name value; do
    case $value in
      n) ! grep -q "^$name=" .config || { echo "$name is still set" >&2; touch /root/refused; } ;;
      *) grep -q "^$name=$value\$" .config || { echo "$name=$value did not take" >&2; touch /root/refused; } ;;
    esac
  done
  [ ! -e /root/refused ]
  make -s -j"$JOBS" bzImage vmlinux
  cp arch/x86/boot/bzImage /out/bzImage && cp vmlinux /out/vmlinux && cp .config /out/kernel.config.full
  chown '"$(id -u):$(id -g)"' /out/bzImage /out/vmlinux /out/kernel.config.full'

cd "$OUT" && sha256sum init initramfs.cpio.gz bzImage vmlinux > SHA256SUMS && cat SHA256SUMS
