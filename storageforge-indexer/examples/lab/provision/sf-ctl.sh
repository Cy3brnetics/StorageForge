# Docker for StorageForge and ntfy. The images come from the libvirt host: building them takes more than this VM has.
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=300 update -qq
apt-get -o DPkg::Lock::Timeout=300 install -y -qq --no-install-recommends docker.io docker-cli docker-compose
systemctl enable --now docker
