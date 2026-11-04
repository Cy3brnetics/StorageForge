# In the DMZ: answers on 80 and 443 (plain HTTP on both, what matters is the path). Replies to other segments go back through the router.
apk update -q
apk add -q findutils util-linux coreutils tar iproute2     # a scan needs GNU find, and ip and ss that can say what they read
apk add -q busybox-extras >/dev/null
cat >>/etc/network/interfaces <<'NET'

auto eth1
iface eth1 inet static
    address 10.77.20.80/24
    post-up ip route replace 10.77.10.0/24 via 10.77.20.1
    post-up ip route replace 198.51.100.0/24 via 10.77.20.1
NET
ifup eth1
mkdir -p /srv/www; echo dmz-server >/srv/www/index.html
printf '#!/bin/sh\nbusybox-extras httpd -p 80 -h /srv/www\nbusybox-extras httpd -p 443 -h /srv/www\n' >/etc/local.d/sflab.start; chmod +x /etc/local.d/sflab.start; rc-update add local default >/dev/null 2>&1; /etc/local.d/sflab.start
