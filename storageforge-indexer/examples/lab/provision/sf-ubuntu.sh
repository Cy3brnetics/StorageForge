# ZFS: a raidz1 pool and a second pool to send to, plus a Docker container using a dataset.
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=300 update -qq
apt-get -o DPkg::Lock::Timeout=300 install -y -qq zfsutils-linux docker.io

echo 'options zfs zfs_arc_max=268435456' >/etc/modprobe.d/sflab-zfs.conf
modprobe zfs
echo 268435456 >/sys/module/zfs/parameters/zfs_arc_max

zpool create -f -o ashift=12 -O compression=lz4 -O atime=off -m /tank tank raidz1 "$(disk 1)" "$(disk 2)" "$(disk 3)"
for ds in media photos backups; do zfs create "tank/$ds"; done
zpool create -f -o ashift=12 -O compression=lz4 -m /backup backup "$(disk 4)"
zfs create backup/replica

systemctl enable --now docker
docker run -d --name sflab-web --restart unless-stopped -v /tank/media:/data:ro docker.io/library/alpine:3.20 sleep infinity
