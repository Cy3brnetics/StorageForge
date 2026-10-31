# AlmaLinux 9: mdadm raid5 with XFS, under SELinux.
dnf install -y -q mdadm xfsprogs
mdadm --create /dev/md0 --run --level=5 --raid-devices=3 --metadata=1.2 "$(disk 1)" "$(disk 2)" "$(disk 3)"
mkfs.xfs -q -f /dev/md0
mdadm --detail --scan >/etc/mdadm.conf
udevadm settle
mnt "UUID=$(uuid /dev/md0)" /srv/raid5 xfs
