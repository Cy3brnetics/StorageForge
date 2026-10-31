# AlmaLinux 10: LVM on LUKS, with ext4 and XFS on separate logical volumes, under SELinux.
dnf install -y -q lvm2 cryptsetup e2fsprogs xfsprogs
(umask 077; head -c 64 /dev/urandom >/etc/sflab-luks.key)
cryptsetup luksFormat --batch-mode --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --key-file /etc/sflab-luks.key "$(disk 1)"
cryptsetup open --key-file /etc/sflab-luks.key "$(disk 1)" sealed
echo "sealed UUID=$(uuid "$(disk 1)") /etc/sflab-luks.key luks,nofail" >>/etc/crypttab
pvcreate -q /dev/mapper/sealed
vgcreate -q vgsealed /dev/mapper/sealed
lvcreate -q -y -L 1G -n docs vgsealed
lvcreate -q -y -L 1G -n media vgsealed
mkfs.ext4 -q /dev/vgsealed/docs
mkfs.xfs -q /dev/vgsealed/media
mnt /dev/vgsealed/docs /srv/docs ext4
mnt /dev/vgsealed/media /srv/media xfs
