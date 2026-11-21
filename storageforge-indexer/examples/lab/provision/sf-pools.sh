# Ubuntu 24.04 with six blank disks and two NICs on the isolated segments that nothing sets up: tier 26 makes pools, LUKS and a bond
# from plans. The disks and the NICs are left as they are; only the tools the steps run are installed. ZFS is in the Ubuntu kernel.
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=300 update -qq
apt-get -o DPkg::Lock::Timeout=300 install -y -qq --no-install-recommends zfsutils-linux mdadm cryptsetup
echo 'options zfs zfs_arc_max=268435456' >/etc/modprobe.d/sflab-zfs.conf
modprobe zfs
echo 268435456 >/sys/module/zfs/parameters/zfs_arc_max
