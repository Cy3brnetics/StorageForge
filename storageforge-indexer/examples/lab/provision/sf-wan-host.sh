# The outside: reaches only the router's WAN address.
apk update -q
apk add -q findutils util-linux coreutils tar iproute2     # a scan needs GNU find, and ip and ss that can say what they read
apk add -q curl nmap >/dev/null
cat >>/etc/network/interfaces <<'NET'

auto eth1
iface eth1 inet static
    address 198.51.100.50/24
NET
ifup eth1
