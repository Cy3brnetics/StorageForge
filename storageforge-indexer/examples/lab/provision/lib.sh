# Prepended to each VM's layout script, which runs once as root. Exit 100 asks lab.sh to reboot and run it again.
set -eu

disk() {   # the data disk with this number, by the serial lab.sh gave it
  for d in /sys/block/vd*; do
    if [ "$(cat "$d/serial" 2>/dev/null)" = "sflab-data$1" ]; then echo "/dev/${d##*/}"; return; fi
  done
  echo "no data disk $1" >&2; exit 1
}

uuid() { blkid -s UUID -o value "$1"; }

mnt() {    # source mountpoint fstype options: add to fstab and mount, so a reboot brings it back
  mkdir -p "$2"
  printf '%s %s %s %s 0 0\n' "$1" "$2" "$3" "${4:-defaults,nofail}" >>/etc/fstab
  mount "$2"
}
