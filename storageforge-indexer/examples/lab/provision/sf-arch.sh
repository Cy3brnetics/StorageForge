# LUKS with f2fs, and mergerfs over two ext4 disks. Arch has no partial upgrades, and upgrading replaces the running
# kernel's modules, so this upgrades first and reboots. mergerfs isn't in the repositories: a pinned upstream build.
MERGERFS=2.42.0
MERGERFS_SHA256=0cf8692e1687c8a1140c714966c6f5f4b498a1537f1a0bef5665082ecb35fc12

pacman -Syu --noconfirm --needed --noprogressbar f2fs-tools fuse3 >/dev/null
[ -d "/usr/lib/modules/$(uname -r)" ] || exit 100

tmp=$(mktemp -d)
curl -fsSL -o "$tmp/m.tgz" "https://github.com/trapexit/mergerfs/releases/download/$MERGERFS/mergerfs-$MERGERFS-static-linux_amd64.tar.gz"
echo "$MERGERFS_SHA256  $tmp/m.tgz" | sha256sum -c --quiet
tar -xzf "$tmp/m.tgz" -C "$tmp"
mkdir -p /usr/local/lib/mergerfs                # not the whole tar: its sbin/ and share/man would replace Arch's symlinks
cp -a "$tmp/usr/local/bin/." /usr/local/bin/
cp -a "$tmp/usr/local/lib/mergerfs/." /usr/local/lib/mergerfs/
install -m 755 "$tmp/sbin/mount.mergerfs" /usr/bin/mount.mergerfs
ln -sf /usr/local/bin/mergerfs /usr/bin/mergerfs
rm -rf "$tmp"

(umask 077; head -c 64 /dev/urandom >/etc/sflab-luks.key)
cryptsetup luksFormat --batch-mode --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --key-file /etc/sflab-luks.key "$(disk 1)"
cryptsetup open --key-file /etc/sflab-luks.key "$(disk 1)" secure
echo "secure UUID=$(uuid "$(disk 1)") /etc/sflab-luks.key luks,nofail" >>/etc/crypttab
mkfs.f2fs -q -f /dev/mapper/secure
mnt /dev/mapper/secure /mnt/secure f2fs

mkfs.ext4 -q -F "$(disk 2)"
mkfs.ext4 -q -F "$(disk 3)"
udevadm settle
mnt "UUID=$(uuid "$(disk 2)")" /mnt/disk1 ext4
mnt "UUID=$(uuid "$(disk 3)")" /mnt/disk2 ext4
mnt /mnt/disk1:/mnt/disk2 /mnt/pool mergerfs cache.files=off,category.create=mfs,minfreespace=64M,x-systemd.requires=/mnt/disk1,x-systemd.requires=/mnt/disk2,nofail
