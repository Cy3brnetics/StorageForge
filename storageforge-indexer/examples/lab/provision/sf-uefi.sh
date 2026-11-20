# Debian 13 started by UEFI, with a blank disk left as it is: tier 23 installs a second system on it.
# What os-install needs on the host. The disk gets no partition table here: a blank disk is what the tier offers the step.
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=300 update -qq
apt-get -o DPkg::Lock::Timeout=300 install -y -qq --no-install-recommends qemu-utils gdisk efibootmgr curl fdisk
[ -d /sys/firmware/efi ] || { echo 'this VM was not started by UEFI: the libvirt host has no OVMF, or lab.sh did not ask for it' >&2; exit 1; }
