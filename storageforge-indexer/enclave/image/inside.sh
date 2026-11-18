#!/bin/sh
# The three steps of the enclave image, as they run inside the pinned build container. image/build.sh runs them with docker,
# and the Dockerfile's `enclave` stage runs the same file, so both make the same bytes.
#
#   inside.sh program|initramfs|kernel|sums      SRC (the enclave folder, read-only), OUT, EPOCH, KERNEL, KERNEL_SHA256, JOBS
set -eu
: "${OUT:=/out}" "${SRC:=/src}"
case $1 in
program)
  rm -rf /build && cp -r "$SRC" /build && cd /build && rm -rf target image/out
  SOURCE_DATE_EPOCH=$EPOCH RUSTFLAGS="-C target-feature=+crt-static --remap-path-prefix=/build=. --remap-path-prefix=/usr/local/cargo=cargo" \
    cargo build --release --locked --quiet --target x86_64-unknown-linux-musl
  file=target/x86_64-unknown-linux-musl/release/storageforge-enclave
  ! ( readelf -d "$file" 2>/dev/null | grep -q NEEDED ) || { echo "the program is not static" >&2; exit 1; }
  cp "$file" "$OUT/init"
  ;;
initramfs)
  apk add --no-cache -q cpio gzip >/dev/null
  rm -rf /root/fs && mkdir /root/fs && cp "$OUT/init" /root/fs/init && chmod 0555 /root/fs/init && touch -d "@$EPOCH" /root/fs/init /root/fs
  cd /root/fs && printf "init\n" | cpio --quiet -o -H newc --owner 0:0 --reproducible | gzip -n -9 > "$OUT/initramfs.cpio.gz"
  ;;
kernel)
  apk add --no-cache -q bash build-base bc bison flex elfutils-dev openssl-dev perl linux-headers xz curl findutils diffutils >/dev/null
  cd /root && curl -fsSL -o linux.tar.xz "https://cdn.kernel.org/pub/linux/kernel/v${KERNEL%%.*}.x/linux-$KERNEL.tar.xz"
  echo "$KERNEL_SHA256  linux.tar.xz" | sha256sum -c - >/dev/null
  tar -xf linux.tar.xz && cd "linux-$KERNEL"
  export KBUILD_BUILD_TIMESTAMP="@$EPOCH" KBUILD_BUILD_USER=storageforge KBUILD_BUILD_HOST=enclave KBUILD_BUILD_VERSION=1 SOURCE_DATE_EPOCH=$EPOCH
  make -s tinyconfig
  grep -v "^#" "$SRC/image/kernel.config" | grep . | while IFS="=" read -r name value; do
    case $value in y) scripts/config --enable "$name" ;; n) scripts/config --disable "$name" ;; *) scripts/config --set-val "$name" "$value" ;; esac
  done
  make -s olddefconfig
  # every line asked for has to have taken: a dependency that is missing drops an option without a word
  rm -f /root/refused
  grep -v "^#" "$SRC/image/kernel.config" | grep . | while IFS="=" read -r name value; do
    case $value in
      n) ! grep -q "^$name=" .config || { echo "$name is still set" >&2; touch /root/refused; } ;;
      *) grep -q "^$name=$value\$" .config || { echo "$name=$value did not take" >&2; touch /root/refused; } ;;
    esac
  done
  [ ! -e /root/refused ]
  make -s -j"${JOBS:-4}" bzImage vmlinux
  cp arch/x86/boot/bzImage "$OUT/bzImage" && cp vmlinux "$OUT/vmlinux" && cp .config "$OUT/kernel.config.full"
  ;;
sums)
  cd "$OUT" && sha256sum init initramfs.cpio.gz bzImage vmlinux > SHA256SUMS && cat SHA256SUMS
  ;;
*) echo "usage: inside.sh program|initramfs|kernel|sums" >&2; exit 1 ;;
esac
