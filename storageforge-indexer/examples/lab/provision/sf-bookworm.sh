# Debian 12: btrfs raid10 over four disks, with quotas on, so qgroup sizes and a profile needing four devices get read.
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=300 update -qq
apt-get -o DPkg::Lock::Timeout=300 install -y -qq --no-install-recommends btrfs-progs
mkfs.btrfs -f -q -L sfraid10 -d raid10 -m raid10 "$(disk 1)" "$(disk 2)" "$(disk 3)" "$(disk 4)"
udevadm settle
mnt "UUID=$(uuid "$(disk 1)")" /srv/pool btrfs compress=zstd,noatime,nofail
btrfs quota enable /srv/pool
for sv in media backups snaps; do btrfs -q subvolume create "/srv/pool/$sv"; done
