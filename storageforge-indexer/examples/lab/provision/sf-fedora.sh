# btrfs raid1 over two disks, one mounted subvolume per job.
mkfs.btrfs -f -q -L sfdata -d raid1 -m raid1 "$(disk 1)" "$(disk 2)"
udevadm settle
id=$(uuid "$(disk 1)")
mkdir -p /mnt/sflab-top
mount "$(disk 1)" /mnt/sflab-top
for sv in @media @backups @snaps; do btrfs -q subvolume create "/mnt/sflab-top/$sv"; done
umount /mnt/sflab-top
rmdir /mnt/sflab-top
for sv in media backups snaps; do mnt "UUID=$id" "/data/$sv" btrfs "subvol=@$sv,compress=zstd,noatime,nofail"; done
