# Rocky Linux 10: LVM thin provisioning with XFS, under SELinux.
dnf install -y -q lvm2 xfsprogs
pvcreate -q "$(disk 1)"
vgcreate -q vgthin "$(disk 1)"
lvcreate -q -y -L 3G --thinpool pool vgthin
lvcreate -q -y -V 2G --thin -n data vgthin/pool
mkfs.xfs -q /dev/vgthin/data
mnt /dev/vgthin/data /srv/thin xfs
lvcreate -q -y -s -n data-snap vgthin/data
