# LVM: XFS on a logical volume with a snapshot beside it, plus a Podman container using it.
dnf install -y -q lvm2 podman
pvcreate -q "$(disk 1)"
vgcreate -q vgdata "$(disk 1)"
lvcreate -q -y -L 2G -n data vgdata
mkfs.xfs -q /dev/vgdata/data
mnt /dev/vgdata/data /srv/data xfs
lvcreate -q -y -s -L 512M -n data-snap /dev/vgdata/data

systemctl enable podman-restart.service
podman run -d --name sflab-web --restart=always -v /srv/data:/data:ro docker.io/library/alpine:3.20 sleep infinity
