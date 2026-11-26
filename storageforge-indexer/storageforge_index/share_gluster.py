"""GlusterFS volumes: the server and its peers each hold a brick, clients mount the volume with the GlusterFS FUSE client.

Peers run first (shares.py runs peer_gluster on each of them before the server): glusterd installed and running, a brick folder, the
ports open. The server then does the same for itself, probes each peer into the trusted pool, waits for them, and creates the volume.

A brick is the folder `brick` inside the share path, never the share path itself: Gluster refuses a brick that is a mount point root,
and the data disk of a share usually is one. StorageForge never deletes a volume and never adds or removes bricks of one that exists:
a design that no longer matches a volume is reported with what to do by hand, because that can lose data.

Client: a unit (storageforge-share-SERVER.<target>.service) that mounts SERVER:/NAME and names the peers as backup volfile servers, so
the mount still comes up when the server is the one that is down.
"""
from __future__ import annotations

import re

from . import netshares
from .moves import find_host, mount_of
from .netshares import Driver, Field
from .scriptkit import host_name, package_check

VOLUME = re.compile(r'[A-Za-z0-9_-]{1,40}')
ADDRESS = re.compile(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}')
ALLOW = re.compile(r'[A-Za-z0-9_.:*/-]{1,100}')      # an address, subnet, host name or wildcard such as 10.0.0.*
REPLICAS = ('none', '2', '3')

BASH = r"""
G() { timeout -k 5 120 gluster --mode=script "$@"; }
gluster_conf() { # I -> G_VOL G_REP G_PEERS (addresses) G_ALLOW (what auth.allow gets) for share I; 1 when the design cannot be used
  local i=$1 toks=() c
  G_VOL=${E_NAME[$i]}; G_REP=$(par replica "${E_PARAM[$i]}"); G_REP=${G_REP:-none}
  read -ra G_PEERS <<<"$(par peer_addrs "${E_PARAM[$i]}")"
  [[ $G_VOL =~ ^[A-Za-z0-9_-]{1,40}$ ]] || { conflict "${E_NAME[$i]} is not a volume name (letters, digits, _ and -, at most 40)"; return 1; }
  read -ra toks <<<"${E_CLIENTS[$i]}"
  G_ALLOW=
  for c in ${toks[@]+"${toks[@]}"}; do
    [[ $c =~ ^[A-Za-z0-9_.:*/-]{1,100}$ ]] || { conflict "$c is not an address or subnet that auth.allow takes"; return 1; }
    G_ALLOW+=${G_ALLOW:+,}$c
  done
  # The self-heal daemons of the bricks reach the volume from the servers own addresses: auth.allow has to let them in too.
  [[ -z $G_ALLOW ]] || G_ALLOW+=",$SERVER_ADDR${G_PEERS[*]:+,${G_PEERS[*]// /,}},127.0.0.1"
  return 0
}
gluster_ports() { # I -> the ports Gluster needs open: management, and the brick ports clients and the other bricks connect to
  local i=$1 toks=() c who="$SERVER_ADDR $(par peer_addrs "${E_PARAM[$i]}")" any=0 range=49152-49251
  read -ra toks <<<"${E_CLIENTS[$i]}"
  ((${#toks[@]})) || any=1
  for c in ${toks[@]+"${toks[@]}"}; do [[ $c =~ ^[0-9.:]+(/[0-9]+)?$ ]] && who+=" $c" || any=1; done
  ((any)) && who=
  command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1 || range=49152:49251    # ufw writes a range with a colon
  open_port "GlusterFS management" 24007/tcp "$who"
  open_port "GlusterFS management" 24008/tcp "$who"
  open_port "GlusterFS bricks" "$range/tcp" "$who"
}
gluster_prepare() { # I -> glusterd installed and running, the brick folder made (the same on a peer and on the server)
  local i=$1 brick=${E_PATH[$i]}/brick
  need_cmd glusterd "GlusterFS server" glusterfs-server glusterfs-server glusterfs glusterfs || return 1
  service_on glusterd
  if [[ -d $brick ]]; then ok "brick folder $brick"
  elif ((APPLY)); then doing "mkdir -p $brick"; mkdir -p -- "$brick"
  else missing "brick folder $brick"; fi
  gluster_ports "$i"
}
gluster_peer_up() { timeout -k 2 30 gluster pool list 2>/dev/null | awk -v a="$1" '$2 == a && $3 == "Connected" { f = 1 } END { exit !f }'; }
gluster_running() { command -v gluster >/dev/null && systemctl is-active -q glusterd; }
peer_gluster() { # I -> this host holds a brick of a volume the server creates
  local i=$1
  section "GlusterFS brick for ${E_NAME[$i]} (a peer of $SERVER)"
  gluster_conf "$i" || return 0
  gluster_prepare "$i" || return 0
}
server_gluster() {
  local i idx=() names=()
  mapfile -t idx < <(indices_of GLUSTER)
  for i in ${idx[@]+"${idx[@]}"}; do names+=("${E_NAME[$i]}"); done
  gluster_orphans ${names[@]+"${names[@]}"}
  for i in ${idx[@]+"${idx[@]}"}; do gluster_volume "$i" || true; done
  return 0
}
gluster_orphans() { # NAME... -> volumes StorageForge made that the design no longer has are left alone, and said so
  gluster_running || return 0
  local keep=" $* " v found=0
  while IFS= read -r v; do
    [[ $keep != *" $v "* ]] || continue
    timeout -k 2 30 gluster volume info "$v" 2>/dev/null | grep -q "user.storageforge" || continue
    ((found)) || section "GlusterFS volumes the design no longer has"
    found=1
    info "volume $v was made by StorageForge and is still there. Nothing is deleted for you. By hand: gluster volume stop $v, then gluster volume delete $v (the files stay in the brick folders)"
  done < <(timeout -k 2 30 gluster volume list 2>/dev/null | grep -E "^[A-Za-z0-9_-]+$" || true)
  return 0
}
gluster_volume() { # I -> the peers probed, the volume made, its access list set, started
  local i=$1 a want=() have=() cmd out n=0 brick vinfo type cur wtype
  gluster_conf "$i" || return 1
  brick=${E_PATH[$i]}/brick
  section "GlusterFS volume $G_VOL (${G_REP/none/no replication}, ${#G_PEERS[@]} peer(s))"
  gluster_prepare "$i" || return 0
  if [[ $G_REP != none && $G_REP != $((${#G_PEERS[@]} + 1)) ]]; then
    conflict "replica $G_REP needs $G_REP bricks and the design has $((${#G_PEERS[@]} + 1)) (this server and ${#G_PEERS[@]} peer(s)): change the peers or the replica"; return 1
  fi
  want=("$SERVER_ADDR:$brick"); for a in ${G_PEERS[@]+"${G_PEERS[@]}"}; do want+=("$a:$brick"); done
  if ! gluster_running; then
    ((APPLY)) && { conflict "glusterd is not running here: journalctl -u glusterd"; return 1; }
    missing "peers probed and volume $G_VOL created (glusterd is not running yet)"; return 0
  fi
  for a in ${G_PEERS[@]+"${G_PEERS[@]}"}; do
    if gluster_peer_up "$a"; then ok "peer $a is connected"; continue; fi
    if ((!APPLY)); then missing "peer $a is not in the pool (would: gluster peer probe $a)"; continue; fi
    doing "gluster peer probe $a"; G peer probe "$a" >/dev/null 2>&1 || true
    for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do gluster_peer_up "$a" && break; sleep 2; done
    gluster_peer_up "$a" && ok "peer $a is connected" || { conflict "peer $a did not connect: is glusterd running there, and 24007/tcp open to $SERVER_ADDR?"; return 1; }
  done
  if vinfo=$(G volume info "$G_VOL" 2>&1) && grep -q "^Volume Name: $G_VOL\$" <<<"$vinfo"; then
    type=$(awk -F": " '$1 == "Type" { print $2 }' <<<"$vinfo")
    mapfile -t have < <(awk -F": " '/^Brick[0-9]+:/ { sub(/ .*/, "", $2); print $2 }' <<<"$vinfo" | sort)
    wtype=Distribute; [[ $G_REP == none ]] || wtype=Replicate
    mapfile -t want < <(printf "%s\n" "${want[@]}" | sort)
    if [[ $type != "$wtype" || "${have[*]}" != "${want[*]}" ]]; then
      conflict "volume $G_VOL exists as $type with bricks ${have[*]} and the design wants $wtype with ${want[*]}. StorageForge never adds, removes or converts bricks, which can lose data. Change the design back, or do it by hand (gluster volume add-brick, remove-brick, or make a new volume and copy the files)"
      return 1
    fi
    ok "volume $G_VOL exists with the bricks of the design"
  else
    cmd=(gluster volume create "$G_VOL"); [[ $G_REP == none ]] || cmd+=(replica "$G_REP")
    cmd+=("${want[@]}")
    if ((!APPLY)); then missing "volume $G_VOL (would: ${cmd[*]})"; return 0; fi
    doing "${cmd[*]}"
    if ! out=$(G "${cmd[@]:1}" 2>&1); then
      if [[ $out == *"root partition"* ]] && ! grep -qiE "already part of a volume|not a directory|not connected|failed to resolve" <<<"$out"; then
        info "a brick is on the system disk, which Gluster only allows with force: creating the volume that way. A data disk is safer"
        out=$(G "${cmd[@]:1}" force 2>&1) || { conflict "could not create volume $G_VOL: $(tr "\n" " " <<<"$out" | cut -c1-300)"; return 1; }
      else conflict "could not create volume $G_VOL: $(tr "\n" " " <<<"$out" | cut -c1-300)"; return 1; fi
    fi
    G volume set "$G_VOL" user.storageforge 1 >/dev/null 2>&1 || true
    vinfo=$(G volume info "$G_VOL" 2>&1 || true)
  fi
  grep -q "user.storageforge" <<<"$vinfo" || { ((APPLY)) && G volume set "$G_VOL" user.storageforge 1 >/dev/null 2>&1 || true; }
  cur=$(G volume get "$G_VOL" auth.allow 2>/dev/null | awk '$1 == "auth.allow" { print $2 }' || true)
  if [[ -n $G_ALLOW ]]; then
    if [[ $cur == "$G_ALLOW" ]]; then ok "auth.allow is $G_ALLOW"
    elif ((APPLY)); then doing "gluster volume set $G_VOL auth.allow $G_ALLOW"; G volume set "$G_VOL" auth.allow "$G_ALLOW" >/dev/null 2>&1 || conflict "could not set auth.allow"
    else missing "auth.allow $G_ALLOW (now ${cur:-*})"; fi
  elif [[ -n $cur && $cur != "*" ]]; then
    if ((APPLY)); then doing "gluster volume reset $G_VOL auth.allow"; G volume reset "$G_VOL" auth.allow >/dev/null 2>&1 || conflict "could not reset auth.allow"
    else missing "auth.allow back to every host (now $cur)"; fi
  fi
  if awk -F": " '$1 == "Status" { exit $2 != "Started" }' <<<"$vinfo"; then ok "volume $G_VOL is started"
  elif ((APPLY)); then doing "gluster volume start $G_VOL"; G volume start "$G_VOL" >/dev/null 2>&1 || conflict "could not start volume $G_VOL: gluster volume status $G_VOL"
  else missing "volume $G_VOL is not started"; fi
}
client_gluster() {
  local i=$1 t=${C_TARGET[$1]} vol=${C_NAME[$1]} unit backups opts body changed=0
  unit=$(share_unit "$t").service
  section "mount ${C_SOURCE[$i]} at $t (GlusterFS)"
  [[ $vol =~ ^[A-Za-z0-9_-]{1,40}$ ]] || { conflict "$vol is not a volume name"; return 0; }
  need_cmd mount.glusterfs "GlusterFS client" glusterfs-client glusterfs-fuse glusterfs glusterfs || return 0
  backups=$(par peer_addrs "${C_PARAM[$i]}"); backups=${backups// /:}
  opts="_netdev${backups:+,backup-volfile-servers=$backups}"
  [[ -z ${C_OPTS[$i]} ]] || opts+=,${C_OPTS[$i]}
  # A oneshot unit with a short start timeout: a server that is gone costs a boot at most that long, and the mount is retried by the next start.
  body="# Written by StorageForge: the GlusterFS volume $vol of $SERVER at $t.
[Unit]
Description=StorageForge GlusterFS volume $vol of $SERVER at $t
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=45
ExecStartPre=/usr/bin/mkdir -p \"$t\"
ExecStart=/usr/bin/mount -t glusterfs -o $opts $SERVER_ADDR:/$vol \"$t\"
ExecStop=/usr/bin/umount \"$t\"

[Install]
WantedBy=multi-user.target"
  unit_file "$unit" "$body" && changed=1
  if ((APPLY)); then
    if ((changed)) && systemctl is-active -q "$unit"; then systemctl restart "$unit" 2>/dev/null || true; fi
    systemctl is-active -q "$unit" || systemctl enable --now "$unit" >/dev/null 2>&1 || conflict "$unit did not start: journalctl -u $unit"
  fi
  if timeout -k 2 10 mountpoint -q "$t"; then ok "mounted"; elif ((APPLY)); then conflict "$t is not mounted: journalctl -u $unit"; else missing "not mounted"; fi
}
cleanup_gluster() { return 0; }    # its client units go with driver_units_cleanup; volumes are never removed for you
"""


class Gluster(Driver):
    def normalize(self, s: dict) -> dict:
        s = dict(s or {})
        if s.get('replica') not in (None, ''):
            s['replica'] = str(s['replica'])
        out = netshares.clean(self.fields, s)
        if out.get('peers'):
            seen = []
            for p in out['peers'].split():
                p = host_name(p, 'a peer')
                if p.lower() not in [x.lower() for x in seen]:
                    seen.append(p)
            if len(seen) > 16:
                raise ValueError('a volume has at most 16 peers here')
            out['peers'] = ' '.join(seen)
        return out

    @staticmethod
    def peers(e: dict) -> list:
        return [p for p in ((e.get('settings') or {}).get('peers') or '').split() if p]

    def peer_hosts(self, e):
        return self.peers(e)

    def check(self, conn, hs, srv, e, say):
        st = e.get('settings') or {}
        rep = st.get('replica') or 'none'
        if not VOLUME.fullmatch(e['name'] or ''):
            say('crit', 'a GlusterFS share needs a name of letters, digits, _ and - (at most 40): it is the volume name')
        seen, found = {srv['name'].lower()}, []
        for p in self.peers(e):
            ph = find_host(hs, p)
            if not ph:
                say('crit', f'peer {p} has not been scanned: scan it first, it is a brick of this volume')
                continue
            if ph['name'].lower() in seen:
                say('crit', f'{ph["name"]} is {"this server" if ph["name"] == srv["name"] else "named twice"}: a peer is another host')
                continue
            seen.add(ph['name'].lower())
            found.append(ph)
            if not ADDRESS.fullmatch(str(ph['ssh_host'] or '')):
                say('crit', f'{ph["name"]} is reached at {ph["ssh_host"]!r}: GlusterFS here needs an IPv4 address or host name for a peer')
            say(*package_check(conn, ph, 'GlusterFS server'))
        for h in [srv, *found]:
            m = mount_of(h, e['path'])
            if m and m['target'] == '/':
                say('warn', f'{e["path"]} is on the system disk of {h["name"]}: Gluster refuses a brick there unless forced, and StorageForge '
                            f'only forces it when that is the one complaint. A data disk is safer')
        bricks = 1 + len(found) + sum(1 for p in self.peers(e) if not find_host(hs, p))
        if rep != 'none' and int(rep) != bricks:
            say('crit', f'replica {rep} needs {rep} bricks and this has {bricks} ({srv["name"]} and {bricks - 1} peer(s)): change the peers or the replica')
        elif rep == '2':
            say('warn', 'two copies can disagree about a file when the hosts lose sight of each other (split-brain), and Gluster cannot tell which '
                        'is right. Replica 3 is safe; so is replica 2 with an arbiter, which StorageForge does not set up')
        elif rep == 'none' and bricks > 1:
            say('warn', f'no replication across {bricks} bricks: files are spread over the hosts, and losing one loses the files on it')
        elif rep == 'none':
            say('note', 'one brick and no peers: a plain volume on this server. Name peers and a replica count for redundancy')
        for c in (e.get('clients') or '').split():
            if not ALLOW.fullmatch(c):
                say('crit', f'{c!r} is not an address, subnet, host name or wildcard (10.0.0.*) that GlusterFS can allow')
        if not (e.get('clients') or '').strip():
            say('warn', 'no clients named: any host that can reach the volume may mount it')
        say('note', f'each brick is the folder brick inside {e["path"]} on its host. All peers run part of the deploy first (glusterd, the brick folder, '
                    f'the ports); then {srv["name"]} probes them and creates the volume. A volume that exists with other bricks is never changed or deleted')

    def server_params(self, e, srv, hs):
        st = e.get('settings') or {}
        addrs = [(ph['ssh_host'] if ph else p) for ph, p in ((find_host(hs, p), p) for p in self.peers(e))]
        return {'replica': st.get('replica') or 'none', 'peer_addrs': ' '.join(a for a in addrs if ADDRESS.fullmatch(str(a)))}

    def client_params(self, e, mt, srv, hs):
        return {'peer_addrs': self.server_params(e, srv, hs)['peer_addrs']}

    def client_source(self, e, address):
        return f'{address}:/{e["name"]}'


netshares.register(Gluster(
    key='GLUSTER', label='GlusterFS',
    help='A replicated or spread volume over bricks on this server and its peers, mounted by clients with the GlusterFS client; '
         'StorageForge makes the volume but never deletes or reshapes one.',
    clients_label='Clients that may mount it', clients_help='Addresses, subnets or wildcards (10.0.0.0/24, 10.0.0.*), space separated. The bricks are let in too.',
    fields=[Field('peers', 'hosts', 'Peers', 'Other scanned hosts that hold a brick at this same path, space separated.', placeholder='nas2 nas3'),
            Field('replica', 'choice', 'Replicas', 'none spreads files over the bricks. 2 or 3 keeps that many copies and needs exactly that many bricks '
                  '(this server and its peers); 2 can split-brain, 3 cannot.', options=REPLICAS, default='none')],
    needs_server='GlusterFS server', needs_client='GlusterFS client', bash=BASH))
