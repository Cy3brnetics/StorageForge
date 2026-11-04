# Behind the router's LAN: anything beyond its own networks goes through the router under test. It also holds a service nothing forwards to.
apk update -q
apk add -q findutils util-linux coreutils tar iproute2     # a scan needs GNU find, and ip and ss that can say what they read
apk add -q busybox-extras curl >/dev/null
cat >>/etc/network/interfaces <<'NET'

auto eth1
iface eth1 inet static
    address 10.77.10.50/24
    post-up ip route replace 10.77.20.0/24 via 10.77.10.1
    post-up ip route replace 198.51.100.0/24 via 10.77.10.1
NET
ifup eth1
mkdir -p /srv/www; echo lan-client >/srv/www/index.html
printf '#!/bin/sh\nbusybox-extras httpd -p 8080 -h /srv/www\n' >/etc/local.d/sflab.start; chmod +x /etc/local.d/sflab.start; rc-update add local default >/dev/null 2>&1; /etc/local.d/sflab.start
