#!/bin/sh
# Lays out the official plugins (roadmap section 11.4, docs/agent.md) the way the controller serves them, and signs them.
#
#   plugins.sh lay BUILT ARCH OUT    BUILT holds the storageforge-plugin-NAME programs for ARCH (x86_64 or aarch64): OUT/ARCH/NAME.plugin
#                                    and OUT/ARCH/NAME.plugin.json, the descriptor naming the program by its sha256 and size
#   plugins.sh sign OUT KEY          signs every descriptor under OUT with KEY, as ssh-keygen -Y sign does in the namespace
#                                    storageforge-plugin: OUT/ARCH/NAME.plugin.sig. The release is signed with the release key, by
#                                    its holder; the unit tests and the lab sign with a key they made
#
# What each plugin declares is here, and nowhere else: the descriptor is what is signed, and the agent and storageforge-agentctl give
# a plugin exactly what its signed descriptor declares and nothing more.
set -eu
VERSION=0.5.7
PLUGINS="heartbeat logs health network disks files"
needs() {
  case $1 in
    heartbeat) printf '{}' ;;
    logs) printf '{"mounts":["/etc/machine-id","/run/log/journal","/var/log/journal"],"groups":["systemd-journal"]}' ;;
    health) printf '{"mounts":["/proc","/sys"],"namespaces":["pid"]}' ;;
    network) printf '{"namespaces":["net"]}' ;;
    disks) printf '{"mounts":["/etc/machine-id","/run/log/journal","/sys","/var/log/journal"],"capabilities":["SYS_RAWIO"],"devices":["disks"],"groups":["systemd-journal"]}' ;;
    # root on the host in effect (SYS_ADMIN): the UI and docs/agent.md say so where it is switched on, and only an admin can
    files) printf '{"mounts":["/proc"],"capabilities":["DAC_READ_SEARCH","SYS_ADMIN","SYS_PTRACE"],"namespaces":["pid"]}' ;;
    *) echo "no plugin $1" >&2; exit 1 ;;
  esac
}
case ${1:-} in
lay)
  built=$2 arch=$3 out=$4
  mkdir -p "$out/$arch"
  for name in $PLUGINS; do
    program=$built/storageforge-plugin-$name
    cp "$program" "$out/$arch/$name.plugin"
    sha=$(sha256sum <"$program" | cut -c1-64)
    size=$(wc -c <"$program" | tr -d " ")
    printf '{"format":1,"name":"%s","version":"%s","arch":"%s","sha256":"%s","size":%s,"protocol":1,"needs":%s}' \
      "$name" "$VERSION" "$arch" "$sha" "$size" "$(needs "$name")" >"$out/$arch/$name.plugin.json"
  done
  ;;
sign)
  out=$2 key=$3
  for descriptor in "$out"/*/*.plugin.json; do
    ssh-keygen -Y sign -q -f "$key" -n storageforge-plugin "$descriptor"
    mv "$descriptor.sig" "${descriptor%.json}.sig"
  done
  ;;
*) echo "usage: plugins.sh lay BUILT ARCH OUT | sign OUT KEY" >&2; exit 2 ;;
esac
