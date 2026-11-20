#!/bin/sh
# Builds storageforge-agent and storageforge-agentctl as static programs, as it runs inside the pinned build container.
# agent/build.sh runs it with docker and the Dockerfile's `agent-build` stage runs the same file, so both make the same bytes.
#
#   inside.sh x86_64|aarch64|sums|test     WORKSPACE (the folder with Cargo.toml, read-only), OUT, EPOCH
#
# out/ARCH/storageforge-agent and out/ARCH/storageforge-agentctl, then out/SHA256SUMS over all four. The container is x86_64:
# aarch64 is cross-compiled with the Rust target for it and Rust's own linker, since every crate is Rust and the target brings
# its own C runtime. STORAGEFORGE_RELEASE_SIGNERS names another signers file to compile in than agent/release_signers (build.rs).
set -eu
: "${OUT:=/out}" "${WORKSPACE:=/ws}" "${EPOCH:=1794960000}"
copy() {
  rm -rf /build && mkdir /build && cp "$WORKSPACE/Cargo.toml" "$WORKSPACE/Cargo.lock" /build/
  for member in wire agent enclave; do cp -r "$WORKSPACE/$member" "/build/$member"; done
  cd /build && rm -rf target enclave/target enclave/image/out* agent/out
}
case $1 in
x86_64|aarch64)
  copy
  target=$1-unknown-linux-musl
  flags="-C target-feature=+crt-static --remap-path-prefix=/build=. --remap-path-prefix=/usr/local/cargo=cargo"
  if [ "$1" = aarch64 ]; then
    rustup target add "$target" >/dev/null 2>&1
    flags="$flags -C linker-flavor=ld.lld -C linker=rust-lld"
  fi
  SOURCE_DATE_EPOCH=$EPOCH RUSTFLAGS="$flags" cargo build --release --locked --quiet --target "$target" -p storageforge-agent --bins
  mkdir -p "$OUT/$1"
  for program in storageforge-agent storageforge-agentctl; do
    file=target/$target/release/$program
    ! ( readelf -d "$file" 2>/dev/null | grep -q NEEDED ) || { echo "$program is not static" >&2; exit 1; }
    cp "$file" "$OUT/$1/$program"
  done
  # the same folder under Docker's name for the machine, which is what a Dockerfile stage is told (TARGETARCH)
  case $1 in x86_64) ln -sfn x86_64 "$OUT/amd64" ;; aarch64) ln -sfn aarch64 "$OUT/arm64" ;; esac
  ;;
sums)
  cd "$OUT" && sha256sum x86_64/storageforge-agent x86_64/storageforge-agentctl aarch64/storageforge-agent aarch64/storageforge-agentctl > SHA256SUMS && cat SHA256SUMS
  ;;
test)
  # the unit tests of the workspace's own crates, in the container the programs are built in
  copy
  cargo test --locked --quiet -p storageforge-wire -p storageforge-agent
  ;;
*) echo "usage: inside.sh x86_64|aarch64|sums|test" >&2; exit 1 ;;
esac
