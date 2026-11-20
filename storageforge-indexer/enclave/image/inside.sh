#!/bin/sh
# The three steps of the enclave image, as they run inside the pinned build container. image/build.sh runs them with docker,
# and the Dockerfile's `enclave` stage runs the same file, so both make the same bytes.
#
#   inside.sh program|initramfs|kernel|sums      SRC (the enclave folder, read-only), OUT, EPOCH, KERNEL, KERNEL_SHA256, JOBS, IMAGE_ARCH
#
# The program is one member of the Cargo workspace above the enclave folder (Cargo.toml, Cargo.lock, wire, agent), so SRC has to
# sit in a copy of that workspace: WORKSPACE, which is SRC/.. unless it is given. Only the enclave and what it depends on is built.
#
# IMAGE_ARCH is x86_64 (the default) or arm64. The arm64 image is cross-compiled in the same container: the program with the Rust
# target for it and Rust's own linker, the kernel with a bare-metal aarch64 gcc. Its kernel is `Image`, which is what an arm64 VMM
# boots. It is not called ARCH: the kernel's own build reads a variable of that name from the environment, and an x86_64 kernel
# built with it set is other bytes than one built without.
set -eu
: "${OUT:=/out}" "${SRC:=/src}" "${IMAGE_ARCH:=x86_64}"
: "${WORKSPACE:=$SRC/..}"
case $IMAGE_ARCH in
  x86_64) TARGET=x86_64-unknown-linux-musl; KARCH=x86;   CROSS=;                  KCONFIG=kernel.config;       KFILES="bzImage vmlinux" ;;
  arm64)  TARGET=aarch64-unknown-linux-musl; KARCH=arm64; CROSS=aarch64-none-elf-; KCONFIG=kernel.config.arm64; KFILES="Image" ;;
  *) echo "IMAGE_ARCH is x86_64 or arm64" >&2; exit 1 ;;
esac
case $1 in
program)
  rm -rf /build && mkdir /build && cp "$WORKSPACE/Cargo.toml" "$WORKSPACE/Cargo.lock" /build/
  for member in wire agent; do cp -r "$WORKSPACE/$member" "/build/$member"; done
  cp -r "$SRC" /build/enclave && cd /build && rm -rf target enclave/target enclave/image/out*
  flags="-C target-feature=+crt-static --remap-path-prefix=/build=. --remap-path-prefix=/usr/local/cargo=cargo"
  if [ "$IMAGE_ARCH" = arm64 ]; then
    # no C compiler for arm64 is needed: every crate is Rust, the target brings its own C runtime, and rust-lld links it
    rustup target add "$TARGET" >/dev/null 2>&1
    flags="$flags -C linker-flavor=ld.lld -C linker=rust-lld"
  fi
  SOURCE_DATE_EPOCH=$EPOCH RUSTFLAGS="$flags" cargo build --release --locked --quiet --target "$TARGET" -p storageforge-enclave
  file=target/$TARGET/release/storageforge-enclave
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
  [ -z "$CROSS" ] || apk add --no-cache -q gcc-aarch64-none-elf binutils-aarch64-none-elf >/dev/null
  cd /root && curl -fsSL -o linux.tar.xz "https://cdn.kernel.org/pub/linux/kernel/v${KERNEL%%.*}.x/linux-$KERNEL.tar.xz"
  echo "$KERNEL_SHA256  linux.tar.xz" | sha256sum -c - >/dev/null
  tar -xf linux.tar.xz && cd "linux-$KERNEL"
  export KBUILD_BUILD_TIMESTAMP="@$EPOCH" KBUILD_BUILD_USER=storageforge KBUILD_BUILD_HOST=enclave KBUILD_BUILD_VERSION=1 SOURCE_DATE_EPOCH=$EPOCH
  # for every make below, the kernel's own names for them. Only when cross-compiling: the x86_64 build has neither set, as before
  unset ARCH CROSS_COMPILE
  if [ -n "$CROSS" ]; then export ARCH="$KARCH" CROSS_COMPILE="$CROSS"; fi
  make -s tinyconfig
  grep -v "^#" "$SRC/image/$KCONFIG" | grep . | while IFS="=" read -r name value; do
    case $value in y) scripts/config --enable "$name" ;; n) scripts/config --disable "$name" ;; *) scripts/config --set-val "$name" "$value" ;; esac
  done
  make -s olddefconfig
  # every line asked for has to have taken: a dependency that is missing drops an option without a word
  rm -f /root/refused
  grep -v "^#" "$SRC/image/$KCONFIG" | grep . | while IFS="=" read -r name value; do
    case $value in
      n) ! grep -q "^$name=" .config || { echo "$name is still set" >&2; touch /root/refused; } ;;
      *) grep -q "^$name=$value\$" .config || { echo "$name=$value did not take" >&2; touch /root/refused; } ;;
    esac
  done
  [ ! -e /root/refused ]
  if [ "$KARCH" = arm64 ]; then
    make -s -j"${JOBS:-4}" Image
    cp arch/arm64/boot/Image "$OUT/Image"
  else
    make -s -j"${JOBS:-4}" bzImage vmlinux
    cp arch/x86/boot/bzImage "$OUT/bzImage" && cp vmlinux "$OUT/vmlinux"
  fi
  cp .config "$OUT/kernel.config.full"
  ;;
sums)
  # shellcheck disable=SC2086  # KFILES is a list of names
  cd "$OUT" && sha256sum init initramfs.cpio.gz $KFILES > SHA256SUMS && cat SHA256SUMS
  ;;
*) echo "usage: inside.sh program|initramfs|kernel|sums" >&2; exit 1 ;;
esac
