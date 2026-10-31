# Filesystems without Unix permissions, and the GNU tools a scan needs: BusyBox's find is not enough.
apk update -q
apk add -q findutils util-linux coreutils tar dosfstools exfatprogs
mkfs.vfat -n SFFAT "$(disk 1)" >/dev/null
mkfs.exfat -L SFEXFAT "$(disk 2)" >/dev/null
mnt "UUID=$(uuid "$(disk 1)")" /mnt/fat vfat
mnt "UUID=$(uuid "$(disk 2)")" /mnt/exfat exfat
