"""The runtime-install plan step (roadmap section 5; infrastructure-platform-roadmap.md 7.1): Docker, Podman, Incus or plain LXC, or
KVM with libvirt, on the distribution families StorageForge scans (apt, dnf and yum, zypper, pacman), with rootless setup where it
applies.

The report is the preflight, and it changes nothing: for the runtime it says present (with its version), installable (which packages,
from where) or blocked (and why), and around it what matters before installing: hardware virtualization and nested virtualization for
libvirt, cgroup v2 and user namespaces for containers, kernel modules, a Docker beside a Podman, an existing br0, room under /var/lib,
copy-on-write advice for VM images on btrfs, and the storage driver on btrfs or ZFS.

Where packages come from: the distribution's own repositories, the default; EPEL on the RHEL family for what only EPEL has; or, for
Docker alone, Docker's own repository, whose signing key is downloaded and installed only when its fingerprint is the one pinned
here. No install script is ever fetched and run (no curl | sh).

Rootless: Podman and plain LXC get subordinate ids, lingering and (Podman) the user's podman.socket; Incus adds the user to the incus
group, which gives a project of their own and not the daemon; libvirt adds the user to kvm, for qemu:///session. Rootless Docker is not
set up by this step: it is refused in the check, and Podman is the runtime that runs rootless as it comes.

Paths the script reads and writes are under $RT_ROOT (empty on a host), so the tests run it against a folder.
"""
from __future__ import annotations

import re
import shlex

from . import changes
from .changes import F

RUNTIMES = ['docker', 'podman', 'incus', 'lxc', 'libvirt']
SOURCES = ['distro', 'vendor']
USER = re.compile(r'[a-z_][a-z0-9_.-]{0,31}')
ARGS = ('runtime', 'source', 'rootless', 'user')
# Docker's release signing keys, as Docker publishes them (docs.docker.com/engine/install): the apt one for Debian and Ubuntu, the
# rpm one for Fedora, RHEL and CentOS. A key file with any other primary key in it is not installed.
DOCKER_APT_FPR = '9DC858229FC7DD38854AE2D88D81803C0EBFCD88'
DOCKER_RPM_FPR = '060A61C51B558A7F742B77AAC52FEB6B621E9F35'
RHEL_LIKE = ('rhel', 'centos', 'rocky', 'almalinux', 'ol')

# No apostrophes: the script text is checked for values that could end a quoted word.
BASH = r"""
RT_DOCKER_APT_FPR=@APT_FPR@ RT_DOCKER_RPM_FPR=@RPM_FPR@
rt_os() { # what this host is: RT_ID RT_VER RT_LIKE RT_CODENAME RT_PM RT_MODE RT_ARCH
  local root=${RT_ROOT:-} m
  RT_ID= RT_VER= RT_LIKE= RT_CODENAME= RT_PM=none RT_MODE=normal RT_ARCH=$(uname -m)
  if [[ -r $root/etc/os-release ]]; then
    IFS=$'\t' read -r RT_ID RT_VER RT_LIKE RT_CODENAME < <(. "$root/etc/os-release"; printf "%s\t%s\t%s\t%s\n" "${ID:-}" "${VERSION_ID:-}" "${ID_LIKE:-}" "${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}")
  fi
  for m in apt-get dnf yum zypper pacman; do command -v $m >/dev/null && { RT_PM=$m; break; }; done
  [[ -e $root/run/ostree-booted ]] && RT_MODE=image
  if command -v transactional-update >/dev/null && findmnt -no OPTIONS / 2>/dev/null | grep -qE "(^|,)ro(,|$)"; then RT_MODE=transactional; fi
  return 0
}
rt_rhel_like() { local w; [[ $RT_ID == fedora ]] && return 1
  for w in $RT_ID $RT_LIKE; do case $w in rhel|centos|rocky|almalinux|ol) return 0 ;; esac; done; return 1; }
rt_apt_lists() { compgen -G "${RT_ROOT:-}/var/lib/apt/lists/*Packages*" >/dev/null; }
rt_avail() { # package -> 0 it can be installed (or is), 1 it cannot, 2 not known without refreshing the package lists
  local c
  case $RT_PM in
    apt-get) rt_apt_lists || return 2
      c=$(apt-cache policy "$1" 2>/dev/null | awk "/Candidate:/ {print \$2; exit}"); [[ -n $c && $c != "(none)" ]] ;;
    dnf|yum) "$RT_PM" -q -C list --available "$1" >/dev/null 2>&1 && return 0
      "$RT_PM" -q -C list --installed "$1" >/dev/null 2>&1 && return 0
      "$RT_PM" -q -C repolist >/dev/null 2>&1 && return 1; return 2 ;;
    zypper) zypper -n --no-refresh -q info "$1" 2>/dev/null | grep -q "^Name *: *$1\$" ;;
    pacman) pacman -Si "$1" >/dev/null 2>&1 || pacman -Qi "$1" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}
rt_install() { # packages... with this host package manager
  case $RT_PM in
    apt-get) DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y -qq "$@" 2>&1 ;;
    dnf|yum) "$RT_PM" install -y -q "$@" 2>&1 ;;
    zypper) zypper -n -q install "$@" 2>&1 ;;
    pacman) pacman -S --needed --noconfirm "$@" 2>&1 || { echo "(the pacman package lists may be out of date: run pacman -Syu on the host, reboot if the kernel changed, then run this again)"; return 1; } ;;
  esac
}
rt_present() { # runtime -> its version on stdout when it is there
  local v
  case $1 in
    docker) command -v docker >/dev/null || return 1
      v=$(docker --version 2>/dev/null | head -n 1); [[ $v == *podman* ]] && return 1; echo "${v:-docker}" ;;
    podman) command -v podman >/dev/null || return 1; podman --version 2>/dev/null | head -n 1 ;;
    incus) command -v incus >/dev/null || return 1; echo "incus $(incus --version 2>/dev/null | head -n 1)" ;;
    lxc) command -v lxc-create >/dev/null || return 1; echo "lxc $(lxc-create --version 2>/dev/null | head -n 1)" ;;
    libvirt) command -v virsh >/dev/null || return 1
      command -v virtqemud >/dev/null || command -v libvirtd >/dev/null || return 1; echo "libvirt $(virsh --version 2>/dev/null | head -n 1)" ;;
  esac
}
rt_plan() { # runtime source -> RT_PKGS (all needed), RT_OPT (each when there; a|b: the first there), RT_REPO, RT_EPEL, RT_FROM; or RT_WHY and 1
  local rt=$1 src=$2 p rc unknown=()
  RT_PKGS=() RT_OPT=() RT_REPO= RT_EPEL=0 RT_WHY= RT_FROM="the ${RT_ID:-distribution} repositories"
  case $RT_MODE in
    image) RT_WHY="an image-based system (rpm-ostree): layer the packages with rpm-ostree install and reboot, or run the runtime in a toolbox"; return 1 ;;
    transactional) RT_WHY="a transactional system with a read-only root: install with transactional-update pkg install, then reboot"; return 1 ;;
  esac
  case $RT_PM in apt-get|dnf|yum|zypper|pacman) ;; *) RT_WHY="no package manager StorageForge knows here (apt, dnf, yum, zypper, pacman)"; return 1 ;; esac
  case $RT_ARCH in x86_64|aarch64) ;; *) [[ $rt == libvirt ]] && { RT_WHY="libvirt is set up here for x86_64 and aarch64, and this is $RT_ARCH"; return 1; } ;; esac
  if [[ $src == vendor ]]; then
    [[ $rt == docker ]] || { RT_WHY="only Docker is installed from a repository of its own; $rt comes from the distribution"; return 1; }
    case $RT_PM:$RT_ID in
      apt-get:debian|apt-get:ubuntu) RT_REPO=apt
        [[ -n $RT_CODENAME ]] || { RT_WHY="/etc/os-release has no VERSION_CODENAME, which the Docker repository is chosen by"; return 1; } ;;
      dnf:fedora|yum:fedora) RT_REPO=fedora ;;
      dnf:rhel|yum:rhel) RT_REPO=rhel ;;
      dnf:*|yum:*) rt_rhel_like && RT_REPO=centos || { RT_WHY="Docker publishes no repository for $RT_ID"; return 1; } ;;
      *) RT_WHY="Docker publishes no repository for $RT_ID: choose the distribution as the source"; return 1 ;;
    esac
    if [[ $RT_REPO != apt ]] && rpm -q podman-docker >/dev/null 2>&1; then RT_WHY="podman-docker is installed and conflicts with docker-ce: remove it first (dnf remove podman-docker), or use Podman"; return 1; fi
    RT_PKGS=(docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin)
    RT_FROM="the Docker repository (download.docker.com), with its signing key pinned by fingerprint"
    return 0
  fi
  case $rt:$RT_PM in
    docker:apt-get) RT_PKGS=(docker.io); RT_OPT=("docker-compose-v2|docker-compose") ;;
    docker:dnf|docker:yum)
      if [[ $RT_ID == fedora ]]; then RT_PKGS=(moby-engine); RT_OPT=(docker-compose)
      else RT_WHY="$RT_ID carries Podman and not Docker: choose the Docker repository as the source, or Podman"; return 1; fi ;;
    docker:zypper|docker:pacman) RT_PKGS=(docker); RT_OPT=(docker-compose) ;;
    podman:apt-get) RT_PKGS=(podman buildah skopeo uidmap); RT_OPT=(passt) ;;
    podman:dnf|podman:yum) RT_PKGS=(podman buildah skopeo container-selinux); RT_OPT=(passt) ;;
    podman:zypper) RT_PKGS=(podman buildah skopeo) ;;
    podman:pacman) RT_PKGS=(podman buildah skopeo); RT_OPT=(passt) ;;
    incus:*) RT_PKGS=(incus) ;;
    lxc:apt-get) RT_PKGS=(lxc uidmap) ;;
    lxc:dnf|lxc:yum) RT_PKGS=(lxc); RT_OPT=(lxc-templates) ;;
    lxc:*) RT_PKGS=(lxc) ;;
    libvirt:apt-get) RT_PKGS=(libvirt-daemon-system virtinst); RT_OPT=(swtpm)
      if [[ $RT_ARCH == x86_64 ]]; then RT_PKGS+=(qemu-system-x86 ovmf); else RT_PKGS+=(qemu-system-arm qemu-efi-aarch64); fi ;;
    libvirt:dnf|libvirt:yum) RT_PKGS=(qemu-kvm libvirt virt-install); RT_OPT=(swtpm)
      if [[ $RT_ARCH == x86_64 ]]; then RT_PKGS+=(edk2-ovmf); else RT_PKGS+=(edk2-aarch64); fi ;;
    libvirt:zypper) RT_PKGS=(qemu-kvm libvirt virt-install); RT_OPT=(swtpm); [[ $RT_ARCH == x86_64 ]] && RT_PKGS+=(qemu-ovmf-x86_64) ;;
    libvirt:pacman) RT_PKGS=(qemu-base libvirt virt-install dnsmasq); RT_OPT=(swtpm)
      if [[ $RT_ARCH == x86_64 ]]; then RT_PKGS+=(edk2-ovmf); else RT_PKGS+=(edk2-aarch64); fi ;;
  esac
  for p in "${RT_PKGS[@]}"; do
    rc=0; rt_avail "$p" || rc=$?
    ((rc == 0)) && continue
    if ((rc == 2)); then unknown+=("$p"); continue; fi
    if [[ $RT_PM == dnf || $RT_PM == yum ]] && rt_rhel_like && [[ $p == incus || $p == lxc ]]; then
      if rpm -q epel-release >/dev/null 2>&1; then RT_WHY="$p is in neither $RT_ID nor EPEL as this host has them: choose another runtime"; return 1; fi
      RT_EPEL=1; RT_FROM="the $RT_ID repositories and EPEL, which it enables (epel-release, from $RT_ID itself)"; continue
    fi
    case $rt:$RT_ID in
      incus:debian) RT_WHY="incus is not in the repositories this host has: Debian 12 has it in bookworm-backports (enable backports and run this again), Debian 13 has it in main; or choose lxc" ;;
      *) RT_WHY="$p is not in the repositories this host has: choose another runtime, or add the repository that has it and run this again" ;;
    esac
    return 1
  done
  ((${#unknown[@]})) && RT_FROM="$RT_FROM (the package lists are not here to check ${unknown[*]} against: they are refreshed before installing)"
  return 0
}
rt_free_mib() { df -Pk "${RT_ROOT:-}/var/lib" 2>/dev/null | awk "NR == 2 {print int(\$4 / 1024)}"; }
rt_fs() { findmnt -no FSTYPE -T "${RT_ROOT:-}$1" 2>/dev/null | head -n 1; }
rt_preflight() { # runtime rootless user -> notes, and 1 when something blocks it
  local rt=$1 rootless=$2 user=$3 root=${RT_ROOT:-} n free fs blocked=0
  free=$(rt_free_mib)
  if [[ -n $free ]] && ((free < 2048)); then conflict "blocked: only $free MiB free under /var/lib: the runtime and its first images need 2 GiB or more"; blocked=1; fi
  case $rt in
    docker|podman|incus|lxc)
      if [[ -e $root/sys/fs/cgroup/cgroup.controllers ]]; then ok "cgroup v2"; else info "cgroup v1 here: rootless containers and resource limits are limited until the host boots with cgroup v2"; fi
      if modprobe -n overlay >/dev/null 2>&1 || grep -qw overlay "$root/proc/filesystems" 2>/dev/null; then ok "kernel module overlay"; else info "no overlay module: images fall back to a slower storage driver"; fi
      if [[ $rt == docker || $rt == incus ]] && ! modprobe -n br_netfilter >/dev/null 2>&1; then info "no br_netfilter module: firewall rules do not see bridged container traffic"; fi ;;
  esac
  if ((rootless)); then
    n=$(cat "$root/proc/sys/user/max_user_namespaces" 2>/dev/null || echo 1)
    if [[ $n == 0 ]]; then conflict "blocked: user namespaces are turned off (user.max_user_namespaces is 0): rootless containers cannot run"; blocked=1; fi
    if [[ $(cat "$root/proc/sys/kernel/unprivileged_userns_clone" 2>/dev/null || echo 1) == 0 ]]; then conflict "blocked: kernel.unprivileged_userns_clone is 0: rootless containers cannot run until it is 1"; blocked=1; fi
    if [[ -n $user ]] && ! id -u "$user" >/dev/null 2>&1; then conflict "blocked: there is no account $user on this host for the rootless setup"; blocked=1; fi
  fi
  case $rt in
    docker)
      command -v podman >/dev/null && info "Podman is here too: both can run, each with its own images and containers"
      if command -v docker >/dev/null && [[ $(docker --version 2>/dev/null) == *podman* ]]; then conflict "blocked: docker here is the Podman shim (podman-docker): remove it first"; blocked=1; fi
      fs=$(rt_fs /var/lib)
      [[ $fs == btrfs ]] && info "/var/lib is on btrfs: overlay2 works there, and the btrfs storage driver is the other choice"
      [[ $fs == zfs ]] && info "/var/lib is on ZFS: overlay2 needs OpenZFS 2.2 or later, and the zfs storage driver is the other choice" ;;
    podman) command -v docker >/dev/null && [[ $(docker --version 2>/dev/null) != *podman* ]] && info "Docker is here too: both can run, each with its own images and containers" ;;
    incus|lxc) [[ -e $root/sys/class/net/br0 ]] && info "br0 exists: the runtime makes a bridge of its own and leaves br0 alone" ;;
    libvirt)
      if [[ -e $root/dev/kvm ]]; then ok "hardware virtualization: /dev/kvm is there"
      elif grep -qwE "vmx|svm" "$root/proc/cpuinfo" 2>/dev/null; then info "the CPU has VT-x or AMD-V and there is no /dev/kvm yet: the kvm module loads with the packages, or turn it on in the firmware"
      else info "no hardware virtualization here (no vmx or svm, no /dev/kvm): VMs would run emulated, many times slower. Turn on VT-x or AMD-V in the firmware, or nested virtualization on the host this runs on"; fi
      for n in "$root"/sys/module/kvm_intel/parameters/nested "$root"/sys/module/kvm_amd/parameters/nested; do
        [[ -r $n ]] && case $(cat "$n") in Y|1) info "nested virtualization is on: VMs here can run VMs" ;; *) info "nested virtualization is off" ;; esac
      done
      grep -qw vboxdrv "$root/proc/modules" 2>/dev/null && info "VirtualBox is loaded: it and KVM cannot both run VMs at the same time"
      [[ -e $root/sys/class/net/br0 ]] && info "br0 exists: libvirt makes virbr0 for its default network and leaves br0 alone"
      fs=$(rt_fs /var/lib)
      [[ $fs == btrfs ]] && info "/var/lib is on btrfs: VM images do better with copy-on-write off (chattr +C on /var/lib/libvirt/images before the first image)" ;;
  esac
  return $blocked
}
rt_docker_repo() { # the Docker repository, its key checked against the pinned fingerprint before anything trusts it
  local root=${RT_ROOT:-} tmp fpr want url keyfile pubs
  if [[ $RT_REPO == apt ]]; then want=$RT_DOCKER_APT_FPR url=https://download.docker.com/linux/$RT_ID/gpg keyfile=$root/etc/apt/keyrings/docker.asc
  else want=$RT_DOCKER_RPM_FPR url=https://download.docker.com/linux/$RT_REPO/gpg keyfile=$root/etc/pki/rpm-gpg/docker-ce.asc; fi
  command -v gpg >/dev/null || { doing "install gnupg, to check the key"; rt_install gnupg2 >/dev/null 2>&1 || rt_install gnupg >/dev/null 2>&1 || true; }
  command -v gpg >/dev/null || { conflict "gpg is not here and could not be installed: the Docker key cannot be checked"; return 1; }
  tmp=$(mktemp) || { conflict "could not make a temporary file"; return 1; }
  if ! curl -fsSL --proto =https --tlsv1.2 --retry 3 -o "$tmp" "$url"; then rm -f "$tmp"; conflict "could not download $url"; return 1; fi
  pubs=$(gpg --batch --show-keys --with-colons "$tmp" 2>/dev/null | grep -c "^pub:")
  fpr=$(gpg --batch --show-keys --with-colons "$tmp" 2>/dev/null | awk -F: "/^pub:/ {p = 1; next} p && /^fpr:/ {print \$10; exit}")
  if [[ $pubs != 1 || $fpr != "$want" ]]; then rm -f "$tmp"; conflict "the key at $url is not the pinned one (fingerprint ${fpr:-none}, ${pubs:-0} keys; want $want): nothing was installed"; return 1; fi
  install -D -m 0644 "$tmp" "$keyfile"; rm -f "$tmp"
  ok "Docker signing key $want installed at ${keyfile#$root}"
  if [[ $RT_REPO == apt ]]; then
    printf "%s\n" "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$RT_ID $RT_CODENAME stable" >"$root/etc/apt/sources.list.d/docker.list"
    apt-get -o DPkg::Lock::Timeout=120 update -qq >/dev/null 2>&1 || { conflict "apt-get update failed after adding the Docker repository"; return 1; }
  else
    mkdir -p "$root/etc/yum.repos.d"
    printf "%s\n" "[docker-ce-stable]" "name=Docker CE Stable (added by StorageForge)" "baseurl=https://download.docker.com/linux/$RT_REPO/\$releasever/\$basearch/stable" \
      "enabled=1" "gpgcheck=1" "gpgkey=file:///etc/pki/rpm-gpg/docker-ce.asc" >"$root/etc/yum.repos.d/docker-ce.repo"
  fi
  ok "Docker repository added"
}
rt_unit() { systemctl cat "$1" >/dev/null 2>&1; }
rt_enable() { # units...: enabled and started, each once
  local u
  for u; do
    if systemctl is-enabled --quiet "$u" 2>/dev/null && systemctl is-active --quiet "$u" 2>/dev/null; then ok "$u is enabled and running"; continue; fi
    act "systemctl enable --now $u" && { try systemctl enable --now "$u" >/dev/null 2>&1 && ok "$u enabled and started"; }
  done
}
rt_subids() { # user: subordinate uids and gids, a range after the last one given out
  local user=$1 root=${RT_ROOT:-} f start
  for f in subuid subgid; do
    if grep -q "^$user:" "$root/etc/$f" 2>/dev/null; then ok "$user has subordinate ids in /etc/$f"; continue; fi
    start=$(awk -F: "{e = \$2 + \$3; if (e > m) m = e} END {print (m > 100000 ? m : 100000)}" "$root/etc/$f" 2>/dev/null || echo 100000)
    act "give $user 65536 subordinate ids from $start in /etc/$f" && printf "%s:%s:65536\n" "$user" "${start:-100000}" >>"$root/etc/$f"
  done
}
rt_linger() {
  local user=$1
  if [[ -e ${RT_ROOT:-}/var/lib/systemd/linger/$user ]]; then ok "$user lingers: their services run without a login"; return 0; fi
  act "loginctl enable-linger $user, so their containers run without a login" && try loginctl enable-linger "$user"
}
rt_group() { # user group
  if id -nG "$1" 2>/dev/null | tr " " "\n" | grep -qx "$2"; then ok "$1 is in the group $2"; return 0; fi
  getent group "$2" >/dev/null || { ((APPLY)) && conflict "there is no group $2"; return 0; }
  act "add $1 to the group $2" && try usermod -aG "$2" "$1"
}
rt_after() { # runtime rootless user: what makes it usable, each looked at before it is done
  local rt=$1 rootless=$2 user=$3 root=${RT_ROOT:-} pools
  case $rt in
    docker)
      if [[ -e $root/etc/docker/daemon.json ]]; then ok "/etc/docker/daemon.json is there and left as it is"
      elif act "write /etc/docker/daemon.json: container logs kept to 3 files of 10 MB"; then
        mkdir -p "$root/etc/docker"
        printf "%s\n" "{" "  \"log-driver\": \"json-file\"," "  \"log-opts\": {\"max-size\": \"10m\", \"max-file\": \"3\"}" "}" >"$root/etc/docker/daemon.json"
        durable "$root/etc/docker/daemon.json"
      fi
      rt_enable docker.service ;;
    podman)
      if ((rootless)); then
        rt_subids "$user"; rt_linger "$user"
        if systemctl --user -M "$user@" is-enabled --quiet podman.socket 2>/dev/null; then ok "the podman.socket of $user is enabled"
        elif act "systemctl --user -M $user@ enable --now podman.socket"; then
          try systemctl --user -M "$user@" enable --now podman.socket >/dev/null 2>&1 && ok "the podman.socket of $user is enabled and started"
        fi
      else rt_enable podman.socket; fi ;;
    incus)
      if rt_unit incus.socket; then rt_enable incus.socket; elif rt_unit incus.service; then rt_enable incus.service; fi
      pools=$(incus storage list -f csv 2>/dev/null | wc -l)
      if command -v incus >/dev/null && ((pools > 0)); then ok "incus has a storage pool"
      else act "incus admin init --minimal: a storage pool in a folder and the bridge incusbr0" && try incus admin init --minimal; fi
      ((rootless)) && rt_group "$user" incus ;;
    lxc)
      rt_unit lxc-net.service && rt_enable lxc-net.service
      if ((rootless)); then
        rt_subids "$user"
        if grep -q "^$user veth" "$root/etc/lxc/lxc-usernet" 2>/dev/null; then ok "$user may make up to its share of veth devices"
        elif act "let $user make 10 veth devices on lxcbr0 (/etc/lxc/lxc-usernet)"; then mkdir -p "$root/etc/lxc"; printf "%s veth lxcbr0 10\n" "$user" >>"$root/etc/lxc/lxc-usernet"; fi
      fi ;;
    libvirt)
      if rt_unit virtqemud.socket; then rt_enable virtqemud.socket virtnetworkd.socket virtstoragued.socket
      else rt_enable libvirtd.service; fi
      ((rootless)) && rt_group "$user" kvm ;;
  esac
  return 0
}
t_runtime_install() { local rt=$1 src=${2:-distro} rootless=${3:-} user=${4:-} have p q out want=() opt=() nr=0
  [[ -n $rootless ]] && nr=1
  rt_os
  info "$RT_ID $RT_VER ($RT_ARCH), packages with $RT_PM"
  if have=$(rt_present "$rt"); then
    ok "present: $have"
    rt_preflight "$rt" "$nr" "$user" || true
  else
    if ! rt_plan "$rt" "$src"; then conflict "blocked: $RT_WHY"; return 0; fi
    rt_preflight "$rt" "$nr" "$user" || return 0
    if ((!APPLY)); then
      missing "installable: ${RT_PKGS[*]}${RT_OPT[*]:+, and when there ${RT_OPT[*]//|/ or }}, from $RT_FROM"
      rt_after "$rt" "$nr" "$user"          # what would follow the install, said and not done
      return 0
    fi
    doing "install ${RT_PKGS[*]} from $RT_FROM"
    if [[ -n $RT_REPO ]]; then rt_docker_repo || return 0; fi
    if ((RT_EPEL)); then rt_install epel-release >/dev/null || { conflict "could not enable EPEL"; return 0; }; fi
    if [[ $RT_PM == apt-get ]] && ! rt_apt_lists; then apt-get -o DPkg::Lock::Timeout=120 update -qq >/dev/null 2>&1 || true; fi
    want=("${RT_PKGS[@]}")
    for p in "${RT_OPT[@]}"; do
      for q in ${p//|/ }; do rt_avail "$q" && { want+=("$q"); break; }; done
    done
    if ! out=$(rt_install "${want[@]}"); then
      if [[ $RT_PM == apt-get ]]; then apt-get -o DPkg::Lock::Timeout=120 update -qq >/dev/null 2>&1 && out=$(rt_install "${want[@]}") && out=; fi
      [[ -n $out ]] && { conflict "could not install ${want[*]}: $(tail -n 3 <<<"$out" | tr "\n" " ")"; return 0; }
    fi
    have=$(rt_present "$rt") || { conflict "the packages installed, and $rt is still not there"; return 0; }
    ok "installed: $have"
  fi
  rt_after "$rt" "$nr" "$user"
}
""".replace('@APT_FPR@', DOCKER_APT_FPR).replace('@RPM_FPR@', DOCKER_RPM_FPR)


def _check(conn, c, h, p, say):
    from .pkglist import for_host
    rt, src = p.get('runtime'), p.get('source') or 'distro'
    if rt not in RUNTIMES:
        say('crit', f'the runtime is one of {", ".join(RUNTIMES)}')
        return
    if src not in SOURCES:
        say('crit', 'the source is distro or vendor')
        return
    if src == 'vendor' and rt != 'docker':
        say('crit', f'only Docker is installed from a repository of its own: {rt} comes from the distribution')
    if p.get('rootless'):
        if rt == 'docker':
            say('crit', 'rootless Docker is not set up by this step: use Podman, which runs rootless as it comes, or install Docker rootful')
        if not USER.fullmatch(p.get('user') or ''):
            say('crit', 'rootless setup is for one account: give its login name')
    elif p.get('user'):
        say('note', 'the account is used only for rootless setup, which is off')
    pk = for_host(conn, h['name']) or {}
    pm, distro, mode = pk.get('pm'), pk.get('distro'), pk.get('mode')
    if not pm:
        say('note', f'rescan {h["name"]} to see here which packages it would get; the report on the host says present, installable or blocked')
    elif mode in ('image', 'transactional', 'readonly'):
        say('crit', f'{h["name"]} is an {"image-based" if mode == "image" else "read-only" if mode == "readonly" else "transactional"} system: packages are not installed on it this way')
    elif pm not in ('apt-get', 'dnf', 'yum', 'zypper', 'pacman'):
        say('crit', f'{h["name"]} has no package manager this step knows (apt, dnf, yum, zypper, pacman)')
    elif rt == 'docker' and src == 'distro' and pm in ('dnf', 'yum') and distro != 'fedora':
        say('crit', f'{distro or "this host"} carries Podman and not Docker: choose the Docker repository as the source, or Podman')
    elif rt == 'docker' and src == 'vendor' and not (pm == 'apt-get' and distro in ('debian', 'ubuntu') or pm in ('dnf', 'yum') and (distro == 'fedora' or distro in RHEL_LIKE)):
        say('crit', f'Docker publishes no repository for {distro or "this distribution"}: choose the distribution as the source')
    if rt == 'docker' and src == 'vendor':
        say('note', f'adds the Docker repository; its signing key is installed only if its fingerprint is the pinned one ({DOCKER_APT_FPR if pm == "apt-get" else DOCKER_RPM_FPR})')
    if rt == 'libvirt':
        say('note', 'VMs need hardware virtualization: the report says whether /dev/kvm is there and whether nested virtualization is on')
    if rt == 'incus':
        say('note', 'a new Incus gets incus admin init --minimal: a storage pool in a folder and the bridge incusbr0')
    say('note', 'the report changes nothing and says present, installable or blocked, with why. Nothing is installed by a script fetched from the network')


def _title(p) -> str:
    name = {'docker': 'Docker', 'podman': 'Podman', 'incus': 'Incus', 'lxc': 'LXC', 'libvirt': 'KVM and libvirt'}.get(p['runtime'], p['runtime'])
    return f'Install {name}' + (' from its own repository' if p.get('source') == 'vendor' else '') + (f', rootless for {p["user"]}' if p.get('rootless') else '')


def _ansible(t, conn=None):
    q = shlex.quote
    p = t['params']
    head = ('APPLY=1; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { :; }\n'
            'doing() { echo "changed: $*"; }; act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }; durable() { sync; }\n')
    words = [p['runtime'], p.get('source') or 'distro', '1' if p.get('rootless') else '', p.get('user') or '']
    return {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': head + BASH + '\nt_runtime_install ' + ' '.join(q(w) for w in words) + '\n', 'executable': '/bin/bash'},
            'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"}


changes.register('runtime-install', {'group': 'Workloads', 'label': 'Install a container or VM runtime', 'fields': [
    F('runtime', 'choice', 'Runtime', options=RUNTIMES, default='podman', required=True),
    F('source', 'choice', 'Packages from', options=SOURCES, default='distro'),
    F('rootless', 'bool', 'Rootless, for one account'),
    F('user', 'user', 'The account (rootless only)', placeholder='alice')],
    'help': 'Installs Docker, Podman, Incus, LXC or KVM with libvirt from the distribution, or Docker from its own repository with its key pinned. '
            'The report says present, installable or blocked, with why, and changes nothing.'},
    ARGS, _title, _check, _ansible)
changes.EXTRA_BASH.append(BASH)
