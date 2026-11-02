# Proxmox VE: a ZFS mirror registered as guest storage, as most installs have, beside the installer's LVM thin pool.
zpool create -f -o ashift=12 -O compression=lz4 -m /tank tank mirror "$(disk 1)" "$(disk 2)"
for ds in media backups; do zfs create "tank/$ds"; done
pvesm add zfspool tank-guests --pool tank --content images,rootdir
