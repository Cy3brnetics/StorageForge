# openSUSE Leap 15.6: the older btrfs-progs and kernel, single data with dup metadata and many nested subvolumes.
zypper -n install --no-recommends btrfsprogs xfsprogs
mkfs.btrfs -f -q -L sfdup -d single -m dup "$(disk 1)"
mkfs.xfs -q -f "$(disk 2)"
udevadm settle
mnt "UUID=$(uuid "$(disk 1)")" /srv/deep btrfs noatime,nofail
mnt "UUID=$(uuid "$(disk 2)")" /srv/plain xfs
btrfs -q subvolume create /srv/deep/a
btrfs -q subvolume create /srv/deep/a/b
btrfs -q subvolume create /srv/deep/a/b/c
echo "in a child subvolume" >/srv/deep/a/b/child-file.txt
mkdir -p /srv/deep/snaps /srv/deep/recv
