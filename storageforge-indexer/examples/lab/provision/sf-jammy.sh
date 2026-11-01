# Ubuntu 22.04: a ZFS mirror, a smaller alternative to sf-ubuntu's raidz1, on the older ZFS release.
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=300 update -qq
apt-get -o DPkg::Lock::Timeout=300 install -y -qq zfsutils-linux
echo 'options zfs zfs_arc_max=268435456' >/etc/modprobe.d/sflab-zfs.conf
modprobe zfs
echo 268435456 >/sys/module/zfs/parameters/zfs_arc_max
zpool create -f -o ashift=12 -O compression=lz4 -O atime=off -m /vault vault mirror "$(disk 1)" "$(disk 2)"
for ds in media backups; do zfs create "vault/$ds"; done
