#!/usr/bin/env python3
"""Sets up a router VM with nobody at its console, over the serial port, because none of the images takes cloud-init. Afterwards it has the
lab's key on a `lab` account with full rights and on a `scan` account that can only read, an address on each network, and a firewall
worth reading: rules that decide what crosses between LAN and DMZ, and a port forward from the WAN. Does nothing if it is already set up.

    router.py chr|openwrt|opnsense <name> <mgmt ip> <console port> <state dir>
"""
import base64
import copy
import re
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from xml.etree import ElementTree as E

BOOT_SECS = 240
OPNSENSE_BOOT_SECS = 600      # the first boot grows its filesystem and makes its keys
ROUTER_WAN, ROUTER_LAN, ROUTER_DMZ = '198.51.100.1', '10.77.10.1', '10.77.20.1'
ROUTER = {'wan': '198.51.100.3', 'lan1': '10.77.10.3', 'dmz': '10.77.20.3'}      # OPNsense's own, beside RouterOS at .1 and OpenWrt at .2
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


def opnsense_ssh(ip, state, script, timeout=120):
    """sh on the device as root, before its config is the lab's. Its host keys change when the config is loaded, so none is kept from here."""
    p = subprocess.run(['ssh', '-i', f'{state}/id_ed25519', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no', '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
                        '-o', 'ConnectTimeout=5', '-o', 'LogLevel=ERROR', f'root@{ip}', 'sh -s'], input=script, capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise SystemExit(f'opnsense: {script[:60]!r} failed: {(p.stderr or p.stdout)[-300:]}')
    return p.stdout


def opnsense_config(xml, ip, name, pubkey, pw_hash):
    """The device's own first-boot config.xml, changed into the lab's: every element it does not touch stays as this release wrote it."""
    head, _, body = xml.partition('<opnsense')
    root = E.fromstring('<opnsense' + body)
    prefix = '.'.join(ip.split('.')[:3])

    def put(parent, tag, text=None):
        node = parent.find(tag)
        if node is None:
            node = E.SubElement(parent, tag)
        node.text = text
        return node
    for tag in ('trigger_initial_wizard',):
        for node in root.findall(tag):
            root.remove(node)
    system = root.find('system')
    put(system, 'hostname', name)
    put(system, 'domain', 'lab')
    ssh = put(system, 'ssh')
    for tag, text in (('group', 'admins'), ('enabled', 'enabled'), ('permitrootlogin', '1')):
        put(ssh, tag, text)
    admin = next(u for u in system.findall('user') if u.findtext('name') == 'root')
    put(admin, 'password', pw_hash)
    put(admin, 'authorizedkeys', base64.b64encode((pubkey + '\n').encode()).decode())
    put(admin, 'shell', '/bin/sh')
    uids = {'lab': '2000', 'scan': '2001'}
    for user, uid in uids.items():      # shell accounts in admins, as the GUI makes them: what a login that is not root can read is tier 12's to measure
        node = copy.deepcopy(admin)
        node.set('uuid', str(uuid.uuid4()))
        for tag, text in (('uid', uid), ('name', user), ('descr', f'lab {user}'), ('scope', 'user')):
            put(node, tag, text)
        system.insert(list(system).index(admin) + 1, node)
    admins = next(g for g in system.findall('group') if g.findtext('name') == 'admins')
    put(admins, 'member', ','.join(['0', *uids.values()]))
    put(system, 'nextuid', '2002')

    ifaces = root.find('interfaces')
    for tag in ('wan', 'lan'):
        ifaces.remove(ifaces.find(tag))

    def iface(key, dev, descr, addr):
        node = E.Element(key)
        for tag, text in (('enable', '1'), ('if', dev), ('descr', descr), ('ipaddr', addr), ('subnet', '24')):
            put(node, tag, text)
        ifaces.insert(0, node)
    iface('opt2', 'vtnet3', 'DMZ', ROUTER['dmz'])
    iface('opt1', 'vtnet2', 'LAN1', ROUTER['lan1'])
    iface('lan', 'vtnet0', 'MGMT', ip)           # the anti-lockout rule is on lan, so SSH stays in whatever the rules below say
    iface('wan', 'vtnet1', 'WAN', ROUTER['wan'])

    dns = root.find('dnsmasq')                    # its DHCP would answer on the lab's own network
    put(dns, 'enable', '0')
    for node in dns.findall('dhcp_ranges'):
        dns.remove(node)

    # rules as the 26.x GUI writes them, copied from the default rule this release made
    rules = root.find('OPNsense/Firewall/Filter/rules')
    template = rules.find('rule')
    seq = 100
    for descr, interface, proto, src, dst, port, action in (
            ('management-ssh', 'lan', 'TCP', 'lab_admins', '(self)', '22', 'pass'),
            ('lan-to-dmz-web', 'opt1', 'TCP', 'any', DMZ_SERVER, '80', 'pass'),
            ('wan-to-dmz-https', 'wan', 'TCP', 'any', DMZ_SERVER, '443', 'pass')):
        node = copy.deepcopy(template)
        node.set('uuid', str(uuid.uuid4()))
        seq += 10
        for tag, text in (('sequence', str(seq)), ('action', action), ('interface', interface), ('ipprotocol', 'inet'), ('protocol', proto),
                          ('source_net', src), ('destination_net', dst), ('destination_port', port), ('description', descr)):
            put(node, tag, text)
        rules.append(node)
    alias = E.SubElement(root.find('OPNsense/Firewall/Alias/aliases'), 'alias', {'uuid': str(uuid.uuid4())})
    for tag, text in (('enabled', '1'), ('name', 'lab_admins'), ('type', 'network'), ('content', f'{prefix}.0/24'), ('description', 'mgmt')):
        put(alias, tag, text)
    # one rule as pfSense and OPNsense before 26 write them, which 26.7 still loads
    legacy = E.SubElement(root.find('filter'), 'rule', {'uuid': str(uuid.uuid4())})
    for tag, text in (('type', 'block'), ('interface', 'opt2'), ('ipprotocol', 'inet'), ('descr', 'dmz-to-mgmt')):
        put(legacy, tag, text)
    E.SubElement(E.SubElement(legacy, 'source'), 'any')
    put(E.SubElement(legacy, 'destination'), 'network', 'lan')
    fwd = E.SubElement(root.find('nat'), 'rule', {'uuid': str(uuid.uuid4())})
    for tag, text in (('interface', 'wan'), ('ipprotocol', 'inet'), ('protocol', 'tcp'), ('target', DMZ_SERVER), ('local-port', '443'), ('descr', 'dmz-https')):
        put(fwd, tag, text)
    E.SubElement(E.SubElement(fwd, 'source'), 'any')
    dest = E.SubElement(fwd, 'destination')
    put(dest, 'network', 'wanip')
    put(dest, 'port', '443')
    return '<?xml version="1.0"?>\n' + E.tostring(root, encoding='unicode') + '\n'


def opnsense_setup(c, ip, pubkey, password, name, state):
    """OPNsense's nano image boots installed, with a menu on the serial console, its LAN on the first interface and a DHCP server on it. That
    interface is the lab's own network, so lab.sh starts the VM with its link down, and it stays down until the saved config no longer has that
    server: a link coming up makes OPNsense apply its saved config again, whatever was set by hand. From the console's shell, four small edits to
    config.xml (the lab's address, DHCP off, SSH on, the lab's key for root) and a reboot. Then the link comes up and the rest goes over SSH: the
    device's own config.xml, changed into the lab's and put back, and a second reboot into it."""
    prompt = r'root@[^\n]*:[^\n]* # $'
    key = base64.b64encode((pubkey + '\n').encode()).decode()
    try:        # nothing is sent while it boots: any key there starts the manual interface assignment
        c.wait(r'login: $', OPNSENSE_BOOT_SECS)
    except SystemExit:
        c.wait(r'login: $', 30, poke='\r')
    c.send('root\r')
    c.wait(r'Password: *$', 30)
    c.send('opnsense\r')
    c.wait(r'Enter an option: $', 60)
    c.send('8\r')
    c.wait(prompt, 30)
    # one short command at a time: the console drops what a long line sends faster than it reads
    for edit in ('s|<ipaddr>192.168.1.1</ipaddr>|<ipaddr>%s</ipaddr>|' % ip, '/<dnsmasq /,/<.dnsmasq>/ s|<enable>1</enable>|<enable>0</enable>|',
                 's|<group>admins</group>|&<enabled>enabled</enabled><permitrootlogin>1</permitrootlogin>|', 's|<authorizedkeys/>|<authorizedkeys>%s</authorizedkeys>|' % key):
        c.send(f"sed -i '' '{edit}' /conf/config.xml\r")
        c.wait(prompt, 30)
    c.send("grep -c '<ipaddr>%s<\\|permitrootlogin\\|<authorizedkeys>' /conf/config.xml | sed 's/^/edits=/'\r" % ip)
    c.wait(r'edits=3\n', 20)
    c.wait(prompt, 20)
    c.send('rm -f /tmp/config.cache; reboot\r')
    c.wait(r'login: $', OPNSENSE_BOOT_SECS)
    mac = '52:54:00:77:00:%02x' % int(ip.rsplit('.', 1)[1])
    for how in ([], ['--config']):      # now, and for every later boot
        subprocess.run(['virsh', '-q', 'domif-setlink', name, mac, 'up', *how], check=True, capture_output=True)
    until = time.time() + 90
    while True:
        try:
            first = opnsense_ssh(ip, state, 'cat /conf/config.xml')
            break
        except SystemExit:
            if time.time() > until:
                raise
            time.sleep(3)
    pw_hash = opnsense_ssh(ip, state, "php -r 'echo password_hash(trim(fgets(STDIN)), PASSWORD_BCRYPT);' <<'SFEOF'\n" + password + '\nSFEOF\n').strip()
    if not pw_hash.startswith('$2'):
        raise SystemExit(f'opnsense: no password hash: {pw_hash[:80]!r}')
    opnsense_ssh(ip, state, "cat > /conf/config.xml.lab <<'SFEOF'\n" + opnsense_config(first, ip, name, pubkey, pw_hash) + 'SFEOF\n'
                 'cp /conf/config.xml /conf/config.xml.first && mv /conf/config.xml.lab /conf/config.xml && rm -f /tmp/config.cache && (sleep 2; reboot) >/dev/null 2>&1 &\n')
    time.sleep(25)          # it is on its way down: the lab account answers only from the next boot


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
    if kind == 'opnsense':
        opnsense_setup(c, ip, pubkey, password, name, state)
    else:
        (chr_setup if kind == 'chr' else openwrt_setup)(c, ip, pubkey, password, name)
    Path(state, f'{name}-password').write_text(password)
    Path(state, f'{name}-password').chmod(0o600)
    until = time.time() + (OPNSENSE_BOOT_SECS if kind == 'opnsense' else 120)
    while time.time() < until:
        if lab_answers(ip, state, probe):
            return
        time.sleep(2)
    raise SystemExit(f'{name}: the lab account does not answer on {ip}')


if __name__ == '__main__':
    main()
