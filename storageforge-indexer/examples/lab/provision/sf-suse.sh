# mdadm raid1 with ext4, and on a third disk the nested btrfs subvolumes openSUSE uses on its root.
# The image's root is XFS, so the nesting lives here. @/var stays unmounted: a child subvolume only its parent can reach.
if ! modprobe -n md_mod 2>/dev/null; then
  # the image's kernel-default-base has no md modules, and the two packages can't be installed together
  zypper -n install --no-recommends kernel-default -kernel-default-base
  exit 100
fi
zypper -n install --no-recommends mdadm btrfsprogs e2fsprogs

mdadm --create /dev/md0 --run --level=1 --raid-devices=2 --metadata=1.2 "$(disk 1)" "$(disk 2)"
mkfs.ext4 -q -F /dev/md0
mdadm --detail --scan >/etc/mdadm.conf
udevadm settle
mnt "UUID=$(uuid /dev/md0)" /mnt/raid ext4

mkfs.btrfs -f -q -L sfnested "$(disk 3)"
udevadm settle
id=$(uuid "$(disk 3)")
mkdir -p /mnt/sflab-top
mount "$(disk 3)" /mnt/sflab-top
btrfs -q subvolume create /mnt/sflab-top/@
for sv in home var .snapshots; do btrfs -q subvolume create "/mnt/sflab-top/@/$sv"; done
umount /mnt/sflab-top
rmdir /mnt/sflab-top
mnt "UUID=$id" /srv/btrfs btrfs subvol=@,noatime,nofail
mnt "UUID=$id" /srv/btrfs/home btrfs subvol=@/home,noatime,nofail
mnt "UUID=$id" /srv/btrfs/.snapshots btrfs subvol=@/.snapshots,noatime,nofail
