"""virtiofs shares: a KVM host shares a folder with its own virtual machines, which StorageForge manages as hosts too.

Server (the libvirt host): for each client mount, which names the libvirt domain of the VM (the mount setting `domain`), the persistent
definition of that domain gets a virtiofs filesystem device whose tag is sf-<share name> and shared memory backing, which virtiofsd
needs. virt-xml adds them when the host has it; otherwise a short python3 program edits the domain XML that `virsh dumpxml` wrote (never
sed on XML) and `virsh define` takes it back. Devices of StorageForge (a virtiofs filesystem whose tag starts with sf-) that the design
no longer asks for are taken out of the definitions the same way. A VM is never restarted: a device added to or taken out of a running
VM takes effect when it is next shut down and started (a reboot is not enough), and the script says so.

Client (inside the VM): a unit, storageforge-share-SERVER.<target>.service, that mounts the tag with `mount -t virtiofs`. When the VM
does not have the tag yet because it has not been power cycled since the server side ran, the unit is enabled and the script says that
plainly instead of failing.
"""
from __future__ import annotations

import re

from . import netshares
from .netshares import Driver, Field

DOMAIN = re.compile(r'[A-Za-z0-9_.-]{1,64}')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,32}')          # sf- and this make a tag of at most 36 characters
TARGET = re.compile(r'/[A-Za-z0-9_./-]*')

# The domain XML editor. Modes: check (what is missing or stale, one word per line) and edit (does it, rewriting the file).
# Arguments after the file are tag=path for each device the domain should have.
PY = r'''
import sys
import xml.etree.ElementTree as ET

mode, path = sys.argv[1], sys.argv[2]
want = dict(a.split("=", 1) for a in sys.argv[3:])
for prefix, uri in (("qemu", "http://libvirt.org/schemas/domain/qemu/1.0"), ("libosinfo", "http://libosinfo.org/xmlns/libvirt/domain/1.0")):
    ET.register_namespace(prefix, uri)
tree = ET.parse(path)
root = tree.getroot()
todo = []
mb = root.find("memoryBacking")
if want and (mb is None or not any(a.get("mode") == "shared" for a in mb.findall("access"))):
    todo.append("mem")
devices = root.find("devices")
if devices is None:
    devices = ET.SubElement(root, "devices")
have = {}
for fs in devices.findall("filesystem"):
    drv, tgt = fs.find("driver"), fs.find("target")
    tag = tgt.get("dir", "") if tgt is not None else ""
    if drv is not None and drv.get("type") == "virtiofs" and tag.startswith("sf-"):
        have[tag] = fs
for tag, src in want.items():
    fs = have.get(tag)
    if fs is None:
        todo.append("add " + tag)
    else:
        s = fs.find("source")
        if s is None or s.get("dir") != src or fs.get("accessmode", "passthrough") != "passthrough":
            todo.append("fix " + tag)
for tag in have:
    if tag not in want:
        todo.append("drop " + tag)
if mode == "check":
    print("\n".join(todo))
    sys.exit(0)
if "mem" in todo:
    if mb is None:
        mb = ET.Element("memoryBacking")
        root.insert(list(root).index(root.find("memory")) + 1 if root.find("memory") is not None else 0, mb)
    if mb.find("source") is None:
        ET.SubElement(mb, "source").set("type", "memfd")
    for a in mb.findall("access"):
        mb.remove(a)
    ET.SubElement(mb, "access").set("mode", "shared")
for item in todo:
    what, _, tag = item.partition(" ")
    if what in ("drop", "fix"):
        devices.remove(have[tag])
    if what in ("add", "fix"):
        fs = ET.SubElement(devices, "filesystem", {"type": "mount", "accessmode": "passthrough"})
        ET.SubElement(fs, "driver").set("type", "virtiofs")
        ET.SubElement(fs, "source").set("dir", want[tag])
        ET.SubElement(fs, "target").set("dir", tag)
tree.write(path)
'''

BASH = r"""
VFS_SYS=${SF_VFS_SYS:-/sys/fs/virtiofs}
vfs_daemon() { # is virtiofsd here? It is not on PATH on most distributions
  local p
  for p in "${SF_VIRTIOFSD:-}" "$(command -v virtiofsd || true)" /usr/libexec/virtiofsd /usr/lib/virtiofsd /usr/lib/qemu/virtiofsd /usr/libexec/qemu/virtiofsd; do
    [[ -n $p && -x $p ]] && return 0
  done
  return 1
}
vfs_need_daemon() {
  local m; m=$(pm)
  if vfs_daemon; then ok "virtiofsd installed"; return 0; fi
  if ((!APPLY)); then missing "virtiofsd (would install $([[ $m == dnf || $m == yum ]] && echo qemu-virtiofsd or virtiofsd || echo virtiofsd) with $m)"; return 0; fi
  case $m in
    apt-get|pacman|zypper) doing "install virtiofsd with $m"; install_pkg "$m" virtiofsd >/dev/null 2>&1 || true ;;
    dnf|yum) doing "install qemu-virtiofsd or virtiofsd with $m"; install_pkg "$m" qemu-virtiofsd >/dev/null 2>&1 || install_pkg "$m" virtiofsd >/dev/null 2>&1 || true ;;
    *) conflict "virtiofsd is missing and this host has no package manager I know: install it yourself"; return 0 ;;
  esac
  vfs_daemon && ok "virtiofsd installed" || conflict "could not install virtiofsd: libvirt cannot start a VM with a virtiofs device without it"
}
vfs_py() { python3 -I - "$@" <<"PY"
@@PY@@
PY
}
vfs_domain() { # DOMAIN TAG=PATH... -> the persistent definition of the domain holds exactly the devices of StorageForge
  local dom=$1 xml need line state quiet=0 simple=1 w tag src; shift
  ((!$#)) && quiet=1
  xml=$(mktemp) || return 0
  if ! virsh dumpxml --inactive --security-info "$dom" >"$xml" 2>/dev/null </dev/null; then
    rm -f -- "$xml"; ((quiet)) || conflict "libvirt has no domain $dom on this host: name the VM as virsh list --all shows it"; return 0
  fi
  need=$(vfs_py check "$xml" "$@" </dev/null) || { rm -f -- "$xml"; conflict "could not read the definition of $dom"; return 0; }
  if [[ -z $need ]]; then rm -f -- "$xml"; ((quiet)) || ok "$dom has its virtiofs devices and shared memory"; return 0; fi
  while IFS= read -r line; do
    case $line in
      mem) missing "$dom: shared memory backing (memfd, access shared)" ;;
      add\ *) missing "$dom: virtiofs device ${line#add }" ;;
      fix\ *) missing "$dom: virtiofs device ${line#fix } points at another folder"; simple=0 ;;
      drop\ *) missing "$dom: virtiofs device ${line#drop } is no longer in the design"; simple=0 ;;
    esac
  done <<<"$need"
  for w in "$@"; do [[ ${w#*=} == *,* ]] && simple=0; done
  command -v virt-xml >/dev/null || simple=0
  if ((!APPLY)); then rm -f -- "$xml"; info "an apply changes the persistent definition of $dom only: a running VM gets it at its next power cycle"; return 0; fi
  if ((simple)); then      # virt-xml first; whatever it leaves undone (an old virt-xml may not know a keyword) python3 does below
    if grep -qx mem <<<"$need"; then
      doing "virt-xml $dom --edit --memorybacking source.type=memfd,access.mode=shared"
      virt-xml "$dom" --edit --memorybacking source.type=memfd,access.mode=shared </dev/null >/dev/null 2>&1 || true
    fi
    for w in "$@"; do tag=${w%%=*}; src=${w#*=}
      grep -qx "add $tag" <<<"$need" || continue
      doing "virt-xml $dom --add-device --filesystem $tag"
      virt-xml "$dom" --add-device --filesystem "source=$src,target=$tag,driver.type=virtiofs,accessmode=passthrough" </dev/null >/dev/null 2>&1 || true
    done
    virsh dumpxml --inactive --security-info "$dom" >"$xml" 2>/dev/null </dev/null && need=$(vfs_py check "$xml" "$@" </dev/null) || need=still
  fi
  if [[ -n $need ]]; then
    doing "edit the definition of $dom with python3, then virsh define"
    virsh dumpxml --inactive --security-info "$dom" >"$xml" 2>/dev/null </dev/null || true
    if vfs_py edit "$xml" "$@" </dev/null && virsh define "$xml" >/dev/null 2>&1 </dev/null; then ok "$dom defined with its virtiofs devices"
    else conflict "could not define $dom with its virtiofs devices: the old definition is untouched"; fi
  else ok "$dom has its virtiofs devices and shared memory"; fi
  rm -f -- "$xml"
  state=$(virsh domstate "$dom" 2>/dev/null </dev/null || true)
  if [[ $state == "shut off" ]]; then info "$dom is shut off: it has the change when it starts"
  else info "$dom is $state: the change takes effect at its next full power cycle (shut it down, then start it; a reboot is not enough). StorageForge never restarts a VM"; fi
}
server_virtiofs() {
  local i j idx=() doms=() d args n tag
  mapfile -t idx < <(indices_of VIRTIOFS)
  if ! command -v virsh >/dev/null; then
    ((${#idx[@]})) && { section "virtiofs server"; conflict "virsh is not installed: this host is not a libvirt host, so it cannot share a folder with VMs"; }
    return 0
  fi
  ((${#idx[@]})) && { section "virtiofs server (libvirt $(virsh --version 2>/dev/null </dev/null || echo unknown))"; vfs_need_daemon; }
  declare -A want=()
  for i in ${idx[@]+"${idx[@]}"}; do
    tag=$(par tag "${E_PARAM[$i]}")
    [[ $tag =~ ^sf-[A-Za-z0-9][A-Za-z0-9_.-]{0,32}$ ]] || { conflict "${E_NAME[$i]}: not a usable virtiofs tag (the share name is letters, digits, . _ - and at most 33 characters)"; continue; }
    share_dir "${E_PATH[$i]}"
    for j in "${!C_PROTO[@]}"; do [[ ${C_PROTO[$j]} == VIRTIOFS && ${C_NAME[$j]} == "${E_NAME[$i]}" ]] || continue
      d=$(par domain "${C_PARAM[$j]}")
      [[ $d =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || { conflict "${C_HOST[$j]}:${C_TARGET[$j]} names no usable libvirt domain"; continue; }
      want[$d]+="$tag=${E_PATH[$i]}"$'\n'
    done
  done
  while IFS= read -r d; do [[ -n $d && -z ${want[$d]+x} ]] && doms+=("$d"); done < <(virsh list --all --name 2>/dev/null </dev/null | sort -u)
  for d in ${want[@]+"${!want[@]}"}; do
    args=(); while IFS= read -r n; do [[ -n $n ]] && args+=("$n"); done <<<"${want[$d]}"
    vfs_domain "$d" "${args[@]}"
  done
  # domains the design does not name keep none of StorageForge's devices (nothing is said unless one is taken out)
  for d in ${doms[@]+"${doms[@]}"}; do vfs_domain "$d"; done
}
client_virtiofs() {
  local i=$1 t=${C_TARGET[$1]} tag dom unit body changed=0 tags
  tag=$(par tag "${C_PARAM[$i]}"); dom=$(par domain "${C_PARAM[$i]}"); unit=$(share_unit "$t").service
  section "mount ${C_SOURCE[$i]} at $t (virtiofs)"
  [[ $tag =~ ^sf-[A-Za-z0-9][A-Za-z0-9_.-]{0,32}$ && $t =~ ^/[A-Za-z0-9_./-]*$ ]] || { conflict "the virtiofs tag or mount point is not usable: see the share check"; return 0; }
  body="# Written by StorageForge: the virtiofs share ${C_NAME[$i]} of $SERVER (tag $tag, domain $dom) at $t.
# It needs the VM to have been shut down and started since $SERVER added the device: a reboot does not add it.
[Unit]
Description=StorageForge virtiofs share ${C_NAME[$i]} of $SERVER at $t (tag $tag)
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/bin/mkdir -p \"$t\"
ExecStart=/usr/bin/mount -t virtiofs $tag \"$t\"
ExecStop=/usr/bin/umount \"$t\"

[Install]
WantedBy=multi-user.target"
  unit_file "$unit" "$body" && changed=1
  tags=$(find "$VFS_SYS" -mindepth 2 -maxdepth 2 -name tag -exec cat {} + 2>/dev/null || true)
  if ! grep -qxF -- "$tag" <<<"$tags"; then
    ((APPLY)) && { systemctl enable "$unit" >/dev/null 2>&1 || true; }
    info "this VM has no virtiofs device with the tag $tag yet. $SERVER adds it to the definition of $dom, but a VM only gets a new device at a full power cycle: shut it down and start it (a reboot is not enough), then deploy again or start $unit"
    ((APPLY)) || missing "not mounted"
    return 0
  fi
  if ((APPLY)); then
    if ((changed)) && systemctl is-active -q "$unit"; then systemctl restart "$unit" 2>/dev/null || true; fi
    timeout -k 2 10 mountpoint -q "$t" || systemctl enable --now "$unit" >/dev/null 2>&1 || conflict "$unit did not start: journalctl -u $unit"
    systemctl is-enabled -q "$unit" 2>/dev/null || systemctl enable "$unit" >/dev/null 2>&1 || true
  fi
  if timeout -k 2 10 mountpoint -q "$t"; then ok "mounted"; elif ((APPLY)); then conflict "$t is not mounted: journalctl -u $unit"; else missing "not mounted"; fi
}
cleanup_virtiofs() { return 0; }    # its client units go with driver_units_cleanup
"""


def tag_of(name: str) -> str:
    return f'sf-{name}' if NAME.fullmatch(name or '') else ''


class Virtiofs(Driver):
    def normalize_mount(self, s: dict) -> dict:
        out = netshares.clean(self.mount_fields, s)
        if out.get('domain') and not DOMAIN.fullmatch(out['domain']):
            raise ValueError('the libvirt domain is letters, digits, . _ - (at most 64), as virsh list --all shows it')
        return out

    def check(self, conn, hs, srv, e, say):
        from .fsmap import mount_kind
        from .moves import mount_of
        if not NAME.fullmatch(e['name'] or ''):
            say('crit', 'a virtiofs share needs a name of letters, digits, . _ - and at most 33 characters: sf-<name> is the tag the VM mounts')
        m = mount_of(srv, e['path'])
        if m and mount_kind(m) != 'local':
            say('crit', f'{e["path"]} is on a network or virtual mount: virtiofs shares a local folder of the KVM host')
        say('note', f'{srv["name"]} needs libvirt (the script checks for virsh), virtiofsd, and the VMs named in the mounts defined on it')
        say('note', 'the device goes into each VM\'s persistent definition only. A running VM gets it at its next full power cycle (shut it down, '
                    'then start it; a reboot is not enough), and StorageForge never restarts a VM')
        if not e['mounts']:
            say('warn', 'no VM mounts this share: add the VMs that should get it')

    def check_mount(self, conn, srv, e, mt, ch, say):
        st = mt.get('settings') or {}
        where = f'{ch["name"]}:{mt["path"]}'
        if not st.get('domain'):
            say('crit', f'{where}: name the libvirt domain of this VM on {srv["name"]}')
        others = {(m.get('settings') or {}).get('domain') for m in e['mounts'] if m['host'] == mt['host'] and (m.get('settings') or {}).get('domain')}
        if len(others) > 1:
            say('crit', f'{ch["name"]} is given more than one libvirt domain for this share ({", ".join(sorted(others))}): a VM is one domain')
        if not TARGET.fullmatch(mt['path'] or ''):
            say('crit', f'{where}: the mount point is letters, digits, . _ - and / only')
        say('note', f'{where} mounts tag {tag_of(e["name"]) or "sf-<name>"}; its VM sees it after the next full power cycle, not a reboot')

    def server_params(self, e, srv, hs):
        return {'tag': tag_of(e['name'])}

    def client_params(self, e, mt, srv, hs):
        st = mt.get('settings') or {}
        return {'domain': st.get('domain') or '', 'tag': tag_of(e['name'])}

    def client_source(self, e, address):
        return f'virtiofs:{tag_of(e["name"]) or e["name"]}'


netshares.register(Virtiofs(
    key='VIRTIOFS', label='virtiofs (KVM host to its VMs)',
    help='A KVM host shares a folder with its own VMs through a virtiofs device in their libvirt definition. No network: the VM needs a full power cycle to see it.',
    clients_label='VMs (informational)', clients_help='The VMs are the client mounts; each names its libvirt domain.',
    mount_fields=[Field('domain', 'text', 'Libvirt domain of this VM', 'The name virsh list --all shows on the KVM host.', required=True, placeholder='web01')],
    needs_server='virtiofsd', bash=BASH.replace('@@PY@@', PY.strip('\n'))))
