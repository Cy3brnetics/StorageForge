#!/usr/bin/env python3
"""Sets up a router VM with nobody at its console, over the serial port, because neither image takes cloud-init. Afterwards it has the
lab's key on a `lab` account with full rights and on a `scan` account that can only read, an address on each network, and a firewall
worth reading: rules that decide what crosses between LAN and DMZ, and a port forward from the WAN. Does nothing if it is already set up.

    router.py chr|openwrt <name> <mgmt ip> <console port> <state dir>
"""
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

BOOT_SECS = 240
ROUTER_WAN, ROUTER_LAN, ROUTER_DMZ = '198.51.100.1', '10.77.10.1', '10.77.20.1'
LAN_CLIENT, DMZ_SERVER = '10.77.10.50', '10.77.20.80'


def lab_answers(ip, state, probe):
    return subprocess.run(['ssh', '-i', f'{state}/id_ed25519', '-o', f'UserKnownHostsFile={state}/known_hosts', '-o', 'StrictHostKeyChecking=accept-new', '-o', 'IdentitiesOnly=yes',
                           '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=3', '-o', 'LogLevel=ERROR', f'lab@{ip}', probe], stdin=subprocess.DEVNULL, capture_output=True, timeout=30).returncode == 0


class Console:
    def __init__(self, port):
        self.port, self.sock, self.text = port, None, ''

    def connect(self, until):
        while time.time() < until:
            try:
                self.sock = socket.create_connection(('127.0.0.1', self.port), timeout=5)
                self.sock.settimeout(0.3)
                return
            except OSError:
                time.sleep(1)
        raise SystemExit(f'no serial console on port {self.port}')

    def pump(self):
        try:
            chunk = self.sock.recv(65536)
        except TimeoutError:
            return
        self.text += re.sub(r'\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[=>78]|\r', '', chunk.decode('utf-8', 'replace'))

    def send(self, data):
        self.sock.sendall(data.encode())

    def wait(self, pattern, secs, poke=None):
        """Until what arrived since the last match ends in the pattern."""
        until, last = time.time() + secs, 0
        while time.time() < until:
            self.pump()
            m = re.search(pattern, self.text)
            if m:
                self.text = self.text[m.end():]
                return m
            if poke is not None and time.time() - last > 5:
                self.send(poke)
                last = time.time()
        raise SystemExit(f'waited {secs}s for {pattern!r}; the console last said: {self.text[-400:]!r}')


def chr_setup(c, ip, pubkey, password, name):
    prompt = r'\] (?:/[^\n]*)?> $'
    c.wait(r'Login: $', BOOT_SECS, poke='\r')
    c.send('admin+cet512w\r')
    c.wait(r'Password: $', 20)
    c.send('\r')
    # the first login asks about the licence and for a new password, in that order
    m = c.wait(r'\[Y/n\]:? *$|new password> *$|' + prompt, 30)
    if 'Y/n' in m[0]:
        c.send('n\r')
        m = c.wait(r'new password> *$|' + prompt, 30)
    if 'new password' in m[0]:
        c.send(password + '\r')
        c.wait(r'repeat new password> *$', 20)
        c.send(password + '\r')
        c.wait(prompt, 30)
    prefix = '.'.join(ip.split('.')[:3])
    for cmd in (
        f'/system/identity/set name={name}',
        '/ip/dhcp-client/remove [find]',
        f'/ip/address/add address={ip}/24 interface=ether1 comment=mgmt',
        f'/ip/route/add dst-address=0.0.0.0/0 gateway={prefix}.1 comment=mgmt',
        f'/ip/address/add address={ROUTER_WAN}/24 interface=ether2 comment=wan',
        f'/ip/address/add address={ROUTER_LAN}/24 interface=ether3 comment=lan1',
        f'/ip/address/add address={ROUTER_DMZ}/24 interface=ether4 comment=dmz',
        '/ip/dns/set servers=1.1.1.1,8.8.8.8',
        # layer 2 worth reading
        '/interface/bridge/add name=br-test vlan-filtering=no comment=lab',
        '/interface/vlan/add name=vlan20 vlan-id=20 interface=br-test',
        '/ip/address/add address=10.77.30.1/24 interface=vlan20 comment=vlan-lab',
        # services
        '/ip/pool/add name=lan-pool ranges=10.77.10.100-10.77.10.150',
        '/ip/dhcp-server/add name=dhcp-lan interface=ether3 address-pool=lan-pool disabled=no',
        '/ip/dhcp-server/network/add address=10.77.10.0/24 gateway=10.77.10.1',
        f'/ip/dhcp-server/lease/add address={LAN_CLIENT} mac-address=52:54:00:77:01:23 comment=lan-client server=dhcp-lan',
        f'/ip/firewall/address-list/add list=lab-admins address={prefix}.0/24 comment=mgmt',
        # the firewall the lab reasons about
        '/ip/firewall/filter/add chain=input connection-state=established,related action=accept comment=return-traffic',
        '/ip/firewall/filter/add chain=input in-interface=ether1 action=accept comment=management',
        '/ip/firewall/filter/add chain=input protocol=icmp action=accept comment=icmp',
        '/ip/firewall/filter/add chain=input action=drop comment=input-default',
        '/ip/firewall/filter/add chain=forward connection-state=established,related action=accept comment=return-traffic',
        f'/ip/firewall/filter/add chain=forward in-interface=ether3 out-interface=ether4 protocol=tcp dst-port=80 dst-address={DMZ_SERVER} action=accept comment=lan-to-dmz-web',
        f'/ip/firewall/filter/add chain=forward in-interface=ether2 out-interface=ether4 protocol=tcp dst-port=443 dst-address={DMZ_SERVER} action=accept comment=wan-to-dmz-https',
        '/ip/firewall/filter/add chain=forward action=drop comment=forward-default',
        f'/ip/firewall/nat/add chain=dstnat in-interface=ether2 protocol=tcp dst-port=443 action=dst-nat to-addresses={DMZ_SERVER} to-ports=443 comment=dmz-https',
        '/ip/firewall/nat/add chain=srcnat out-interface=ether2 action=masquerade comment=wan-out',
        # accounts: lab does everything, scan only reads
        '/user/group/add name=sf-read policy=ssh,read,test,!local,!telnet,!ftp,!reboot,!write,!policy,!winbox,!password,!web,!sniff,!sensitive,!api,!romon,!rest-api',
        f'/user/add name=lab group=full password={password}',
        f'/user/add name=scan group=sf-read password={password}',
        f'/file/add name=sflab.pub contents="{pubkey}"',
    ):
        c.send(cmd + '\r')
        c.wait(prompt, 30)
    time.sleep(1)
    for user in ('lab', 'scan'):
        c.send(f'/user/ssh-keys/import public-key-file=sflab.pub user={user}\r')
        c.wait(prompt, 30)
        c.send(f'/file/add name=sflab.pub contents="{pubkey}"\r')       # import takes the file away
        c.wait(prompt, 30)
    c.send('/file/remove sflab.pub\r')
    c.wait(prompt, 30)
    # a boot needs nothing after this: the console's own session ends
    c.send('/quit\r')


def openwrt_setup(c, ip, pubkey, password, name):
    prompt = r'root@[^\n]*# $'
    c.wait(r'Please press Enter|' + prompt, BOOT_SECS, poke='\r')
    c.send('\r')
    c.wait(prompt, 30, poke='\r')
    prefix = '.'.join(ip.split('.')[:3])
    script = f"""
set -e
uci -q delete network.lan || true
uci -q delete network.wan || true
uci -q delete network.wan6 || true
uci -q delete network.@device[0] || true
uci set system.@system[0].hostname='{name}'
uci set network.mgmt=interface; uci set network.mgmt.device=eth0; uci set network.mgmt.proto=static; uci set network.mgmt.ipaddr='{ip}'; uci set network.mgmt.netmask=255.255.255.0; uci set network.mgmt.gateway='{prefix}.1'; uci set network.mgmt.dns=1.1.1.1
uci set network.wan=interface; uci set network.wan.device=eth1; uci set network.wan.proto=static; uci set network.wan.ipaddr='198.51.100.2'; uci set network.wan.netmask=255.255.255.0
uci set network.lan1=interface; uci set network.lan1.device=eth2; uci set network.lan1.proto=static; uci set network.lan1.ipaddr='10.77.10.2'; uci set network.lan1.netmask=255.255.255.0
uci set network.dmz=interface; uci set network.dmz.device=eth3; uci set network.dmz.proto=static; uci set network.dmz.ipaddr='10.77.20.2'; uci set network.dmz.netmask=255.255.255.0
while uci -q delete firewall.@zone[0]; do :; done
while uci -q delete firewall.@forwarding[0]; do :; done
while uci -q delete firewall.@rule[0]; do :; done
while uci -q delete firewall.@redirect[0]; do :; done
z() {{ s=$(uci add firewall zone); uci set firewall.$s.name=$1; uci set firewall.$s.network=$2; uci set firewall.$s.input=$3; uci set firewall.$s.output=ACCEPT; uci set firewall.$s.forward=$4; [ -z "$5" ] || uci set firewall.$s.masq=1; }}
z mgmt mgmt ACCEPT REJECT; z wan wan REJECT REJECT 1; z lan1 lan1 ACCEPT REJECT; z dmz dmz REJECT REJECT
r=$(uci add firewall rule); uci set firewall.$r.name=lan-to-dmz-web; uci set firewall.$r.src=lan1; uci set firewall.$r.dest=dmz; uci set firewall.$r.proto=tcp; uci set firewall.$r.dest_port=80; uci set firewall.$r.dest_ip={DMZ_SERVER}; uci set firewall.$r.target=ACCEPT
r=$(uci add firewall redirect); uci set firewall.$r.name=dmz-https; uci set firewall.$r.src=wan; uci set firewall.$r.dest=dmz; uci set firewall.$r.proto=tcp; uci set firewall.$r.src_dport=443; uci set firewall.$r.dest_ip={DMZ_SERVER}; uci set firewall.$r.dest_port=443; uci set firewall.$r.target=DNAT
uci commit
uci set dropbear.@dropbear[0].PasswordAuth=off; uci set dropbear.@dropbear[0].RootPasswordAuth=off; uci commit dropbear
echo '{pubkey}' > /etc/dropbear/authorized_keys; chmod 600 /etc/dropbear/authorized_keys
printf '%s\\n%s\\n' '{password}' '{password}' | passwd root >/dev/null
sed -i '/^lab:/d; /^scan:/d' /etc/passwd /etc/shadow
echo 'lab:x:0:0:lab:/root:/bin/ash' >> /etc/passwd; echo 'lab:*:0:0:99999:7:::' >> /etc/shadow
echo 'scan:x:1000:1000:scan:/tmp/scan:/bin/ash' >> /etc/passwd; echo 'scan:*:0:0:99999:7:::' >> /etc/shadow
mkdir -p /tmp/scan
reload_config
/etc/init.d/network restart
/etc/init.d/firewall restart
/etc/init.d/dropbear restart
echo sf-setup-ok
"""
    c.send("cat > /tmp/sf-setup.sh <<'SFEOF'\r")
    for line in script.strip().splitlines():
        c.send(line + '\r')
        time.sleep(0.05)
    c.send('SFEOF\r')
    c.wait(prompt, 20)
    c.send('sh /tmp/sf-setup.sh\r')
    c.wait(r'sf-setup-ok\n', 90)


def main():
    kind, name, ip, port, state = sys.argv[1:6]
    probe = ':put ok' if kind == 'chr' else 'true'
    if Path(state, f'{name}-password').exists():      # set up on an earlier boot: only wait for this one
        until = time.time() + BOOT_SECS
        while time.time() < until:
            if lab_answers(ip, state, probe):
                return
            time.sleep(2)
        raise SystemExit(f'{name}: the lab account does not answer on {ip}')
    pubkey = Path(state, 'id_ed25519.pub').read_text().strip()
    password = Path(state, 'admin-password').read_text().strip().translate({ord(c): None for c in '/+='})[:20]
    c = Console(int(port))
    until = time.time() + BOOT_SECS
    c.connect(until)
    (chr_setup if kind == 'chr' else openwrt_setup)(c, ip, pubkey, password, name)
    Path(state, f'{name}-password').write_text(password)
    Path(state, f'{name}-password').chmod(0o600)
    until = time.time() + 120
    while time.time() < until:
        if lab_answers(ip, state, probe):
            return
        time.sleep(2)
    raise SystemExit(f'{name}: the lab account does not answer on {ip}')


if __name__ == '__main__':
    main()
