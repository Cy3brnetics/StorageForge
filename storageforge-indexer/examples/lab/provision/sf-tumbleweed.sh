# openSUSE Tumbleweed: btrfs raid1c3 data over three disks, a no-copy-on-write subvolume, and files sharing extents by reflink.
if ! modprobe -n btrfs 2>/dev/null; then
  zypper -n install --no-recommends kernel-default -kernel-default-base
  exit 100
fi
zypper -n install --no-recommends btrfsprogs
mkfs.btrfs -f -q -L sfc3 -d raid1c3 -m raid1c3 "$(disk 1)" "$(disk 2)" "$(disk 3)"
udevadm settle
mnt "UUID=$(uuid "$(disk 1)")" /srv/c3 btrfs noatime,nofail
btrfs -q subvolume create /srv/c3/media
btrfs -q subvolume create /srv/c3/nocow
chattr +C /srv/c3/nocow
btrfs -q subvolume create /srv/c3/snaps
head -c 64M /dev/urandom >/srv/c3/reflink-a.bin
cp --reflink=always /srv/c3/reflink-a.bin /srv/c3/reflink-b.bin
