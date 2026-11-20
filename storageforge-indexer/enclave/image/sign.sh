#!/bin/sh
# Signs the key enclave's image, and checks a signature (roadmap section 14, "The image").
#
#   image/sign.sh OUT KEY                       writes OUT/SHA256SUMS.sig, made with the SSH private key KEY (the release key)
#   image/sign.sh --verify OUT SIGNERS [NAME]   checks OUT/SHA256SUMS.sig against an allowed-signers file, and every file against SHA256SUMS
#
# What is signed is SHA256SUMS, which names the kernel, the initramfs and the program by their hashes: one signature for the image.
# The signature is ssh-keygen's, as release tags have (docs/operations.md, "Updates"), in a namespace of its own, so it counts for
# nothing else and nothing else counts for it. An allowed-signers line for it:  storageforge namespaces="storageforge-enclave" ssh-ed25519 AAAA...
# The server checks the same signature before it starts the image when STORAGEFORGE_ENCLAVE_SIGNERS names that file.
set -eu
NAMESPACE=storageforge-enclave
if [ "${1:-}" = --verify ]; then
  out=${2:?the image folder} signers=${3:?an allowed-signers file} name=${4:-storageforge}
  ( cd "$out" && sha256sum -c SHA256SUMS >/dev/null ) || { echo "a file in $out is not the one SHA256SUMS lists" >&2; exit 1; }
  ssh-keygen -Y verify -f "$signers" -I "$name" -n "$NAMESPACE" -s "$out/SHA256SUMS.sig" < "$out/SHA256SUMS" >/dev/null \
    || { echo "$out/SHA256SUMS is not signed by $name of $signers" >&2; exit 1; }
  echo "$out: signed by $name, and every file is the one that was signed"
  exit 0
fi
out=${1:?the image folder} key=${2:?the SSH private key to sign with}
rm -f "$out/SHA256SUMS.sig"
ssh-keygen -Y sign -q -f "$key" -n "$NAMESPACE" "$out/SHA256SUMS"
echo "$out/SHA256SUMS.sig written"
