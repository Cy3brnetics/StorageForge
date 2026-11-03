# Standardized Full-Stack Networking: MikroTik-Style Declarative DSL & Multi-Backend Transpiler (RosTranspiler)

A comprehensive architectural blueprint for standardizing operator configuration of the **entire networking stack**—including Layer 2 switching, VLANs, bridges, bonding, IP addressing, static and policy routing, DNS, DHCP servers and clients, VPN overlay tunnels, and firewalls—on a **MikroTik RouterOS-style declarative DSL**. 

At deploy time, the StorageForge **`RosTranspiler`** compiles this universal specification into native configurations across **Linux (`systemd-networkd`, `NetworkManager`, `nftables`, `dnsmasq`), OpenWrt (`uci`, `fw4`), pfSense/OPNsense (`config.xml`, `pf`), Cisco IOS/IOS-XE, and native MikroTik RouterOS**.

---

## 1. Vision & Architecture

Heterogeneous fleets require operators to switch between dozens of disjoint network configuration models:
- Linux servers configure networking via Netplan, `systemd-networkd`, NetworkManager, `ifupdown`, or direct `iproute2` commands.
- Routers and firewalls configure networking via web GUIs, FreeBSD `/etc/rc.conf` + XML files (pfSense), UCI files (OpenWrt), or proprietary CLIs (Cisco IOS).

Requiring operators to write bespoke configuration files for each backend introduces extreme operational friction, configuration drift, and catastrophic lockout risk.

### Why Standardize on MikroTik RouterOS Syntax?
1. **Full-Stack Completeness**: MikroTik's configuration taxonomy covers every layer of the OSI model with consistent naming conventions:
   - `/interface bridge ...`, `/interface vlan ...`, `/interface bonding ...` (Layer 2)
   - `/ip address ...`, `/ipv6 address ...`, `/ip pool ...` (Layer 3)
   - `/ip route ...`, `/routing table ...`, `/routing rule ...` (Routing & Policy)
   - `/ip dns ...`, `/ip dhcp-server ...`, `/ip dhcp-client ...` (Services)
   - `/interface wireguard ...` (VPN & Tunnels)
   - `/ip firewall filter ...`, `/ip firewall nat ...` (Security)
2. **Explicit Key-Value Semantics**: Every command consists of an operation (`add`, `set`, `remove`) followed by explicit `key=value` pairs, creating an unambiguous Abstract Syntax Tree (AST).
3. **Universal Intermediate Representation (IR)**:
   - **Forward Transpilation**: User inputs universal MikroTik DSL ➔ `RosTranspiler` emits native target configurations (`systemd-networkd`, `nmcli`, `uci`, `config.xml`, Cisco CLI).
   - **Reverse Normalization**: Live scan state from any host ➔ rendered in uniform MikroTik DSL in the StorageForge Web UI and CLI.
4. **Unified Safe Rollback**: Every network operation across all backends is gated by StorageForge's automated rollback timer (`storageforge confirm`).

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │            STORAGEFORGE UNIVERSAL NETWORKING SPECIFICATION             │
 │                   (MikroTik RouterOS Declarative DSL)                  │
 └──────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                    RosTranspiler Compilation Engine                    │
 │               (Lexer, AST Validator, Graph Safety Checker)             │
 └──────────────────────────────────┬─────────────────────────────────────┘
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         │ Deploy-Time Translation  │ Deploy-Time Translation  │
         ▼                          ▼                          ▼
 ┌────────────────┐         ┌────────────────┐         ┌────────────────┐
 │  Linux Targets │         │ Router Targets │         │ Switch Targets │
 │systemd-networkd│         │OpenWrt (UCI/fw4│         │ Cisco IOS / XE │
 │ NetworkManager │         │ pfSense (XML)  │         │ (CLI / Trunks) │
 │nftables/dnsmasq│         │ MikroTik (REST)│         │                │
 └────────────────┘         └────────────────┘         └────────────────┘
```

---

## 2. Universal Full-Stack DSL Taxonomy

The DSL provides standardized command schemas across the complete networking stack:

### 2.1 Layer 2: Bridges, Ports, VLANs & Bonding
```routeros
# Bridges & Hardware VLAN Filtering
/interface bridge add name=br-lan vlan-filtering=yes comment="Main LAN Bridge"

# Adding physical ports to bridges
/interface bridge port add bridge=br-lan interface=eth1 pvid=10 comment="Access Port VLAN 10"
/interface bridge port add bridge=br-lan interface=eth2 pvid=20 comment="Access Port VLAN 20"
/interface bridge port add bridge=br-lan interface=eth3 comment="Trunk Uplink"

# Bridge VLAN definitions (Tagged/Untagged trunking)
/interface bridge vlan add bridge=br-lan vlan-ids=10,20 tagged=br-lan,eth3 untagged=eth1,eth2

# Dedicated 802.1Q VLAN interfaces
/interface vlan add name=vlan10 vlan-id=10 interface=br-lan comment="Management VLAN"
/interface vlan add name=vlan20 vlan-id=20 interface=br-lan comment="Storage SAN VLAN"

# Link Aggregation (LACP / 802.3ad Bond)
/interface bonding add name=bond0 slaves=eth1,eth2 mode=802.3ad lacp-rate=fast comment="Dual 10G LACP"
```

### 2.2 Layer 3: IP Addressing & Subnets
```routeros
# Static IPv4 and IPv6 assignment
/ip address add address=192.168.10.1/24 interface=vlan10 comment="LAN Gateway"
/ip address add address=10.77.0.10/24 interface=eth0 comment="Management Static IP"
/ipv6 address add address=2001:db8:10::1/64 interface=vlan10 comment="LAN IPv6"

# IP Address Pools
/ip pool add name=lan-pool ranges=192.168.10.100-192.168.10.200 comment="Client DHCP Pool"

# Static ARP & Neighbor bindings
/ip arp add address=192.168.10.50 mac-address=52:54:00:12:34:56 interface=vlan10 comment="Storage SAN"
```

### 2.3 Routing: Default, Static, & Policy-Based (PBR)
```routeros
# Default and Static Gateway Routes
/ip route add dst-address=0.0.0.0/0 gateway=198.51.100.1 distance=1 comment="Default Internet Route"
/ip route add dst-address=10.20.0.0/16 gateway=10.0.0.254 distance=5 comment="Transit to Site B"

# Policy-Based Routing (Routing Tables & Rules)
/routing table add name=dmz-table fib comment="Isolated DMZ Routing Table"
/routing rule add src-address=10.77.20.0/24 table=dmz-table comment="Force DMZ via Table"
/ip route add dst-address=0.0.0.0/0 gateway=198.51.100.2 routing-table=dmz-table comment="DMZ Uplink"
```

### 2.4 Network Core Services: DNS & DHCP
```routeros
# DNS Resolvers & Cache Forwarding
/ip dns set servers=1.1.1.1,8.8.8.8 allow-remote-requests=yes
/ip dns static add name=storage.internal address=10.77.0.10 comment="Internal Storage Controller"

# DHCP Server Setup
/ip dhcp-server add name=dhcp-lan interface=vlan10 address-pool=lan-pool lease-time=12h
/ip dhcp-server network add address=192.168.10.0/24 gateway=192.168.10.1 dns-server=192.168.10.1 domain=lab.local

# Static DHCP Lease Reservations
/ip dhcp-server lease add address=192.168.10.50 mac-address=52:54:00:12:34:56 comment="Static SAN IP"

# DHCP Client
/ip dhcp-client add interface=wan add-default-route=yes use-peer-dns=yes
```

### 2.5 VPN & Encrypted Overlay Tunnels
```routeros
# WireGuard Interface & Tunnel Setup
/interface wireguard add name=wg0 listen-port=51820 private-key="<key>" comment="Site-to-Site WireGuard"
/interface wireguard peers add interface=wg0 public-key="<pubkey>" allowed-address=10.99.0.0/24 endpoint-address=198.51.100.2 endpoint-port=51820 persistent-keepalive=25
```

### 2.6 Firewall & Security (Filters, NAT, Address Lists)
```routeros
# Filter Rules
/ip firewall filter add chain=input protocol=tcp dst-port=22 src-address=10.0.0.0/8 action=accept comment="SSH Mgmt"
/ip firewall filter add chain=forward action=drop in-interface=wan out-interface=lan connection-state=new

# NAT & Port Forwarding
/ip firewall nat add chain=dstnat protocol=tcp dst-port=443 in-interface=wan action=dst-nat to-addresses=10.77.20.80 to-ports=443 comment="DMZ HTTPS"
/ip firewall nat add chain=srcnat action=masquerade out-interface=wan

# Address Lists (IP Sets)
/ip firewall address-list add list=storage-admins address=10.0.0.50-10.0.0.60
```

---

## 3. The RosTranspiler Multi-Backend Translation Matrix

At deploy time, StorageForge compiles the universal AST into the appropriate backend configuration:

```text
┌─────────────────────────┬──────────────────────┬──────────────────────┬──────────────────────┬──────────────────────┐
│ Universal MikroTik DSL  │ Linux (systemd-net)  │ OpenWrt (UCI)        │ pfSense (config.xml) │ Cisco IOS / IOS-XE   │
├─────────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┤
│ /interface bridge add   │ [NetDev] Kind=bridge │ config interface     │ <bridges><bridge>    │ default bridge-domain│
│ name=br-lan             │ in 10-sf-br-lan.netdev│   option type 'bridge│   <bridgeif>bridge0  │ or VLAN interface    │
├─────────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┤
│ /interface vlan add     │ [NetDev] Kind=vlan   │ config interface     │ <vlans><vlan>        │ interface Vlan10     │
│ name=vlan10 vlan-id=10  │ in 20-sf-vlan10.netdev│   option proto 'none'│   <tag>10</tag>      │   encapsulation dot1q│
├─────────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┤
│ /ip address add         │ [Network]            │ config interface     │ <interfaces><lan>    │ interface Gi0/1      │
│ address=10.0.0.1/24     │ Address=10.0.0.1/24  │   option ipaddr ...  │   <ipaddr>10.0.0.1   │   ip address ...     │
├─────────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┤
│ /ip route add           │ [Route]              │ config route         │ <staticroutes><route>│ ip route 10.20.0.0   │
│ dst=10.20.0.0/16 via=...│ Destination=10.20... │   option target ...  │   <network>10.20.0.0 │   255.255.0.0 ...    │
├─────────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┤
│ /ip dns set servers=... │ [Network] DNS=1.1.1.1│ config dnsmasq       │ <system><dnsserver>  │ ip name-server ...   │
│                         │ or resolvectl dns    │   list server ...    │   <dnsserver>1.1.1.1 │                      │
├─────────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┤
│ /ip dhcp-server add ... │ dnsmasq.conf / kea   │ config dhcp          │ <dhcpd><lan>         │ ip dhcp pool ...     │
│                         │ dhcp-range=...       │   option start 100   │   <range><from>...   │   network ...        │
├─────────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┤
│ /interface wireguard ...│ [NetDev] Kind=wiregu.│ config interface     │ <wireguard><tunnel>  │ interface Tunnel1    │
│                         │ or /etc/wireguard/   │   option proto 'wireg│   <privatekey>...    │   tunnel mode ...    │
├─────────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┤
│ /ip firewall filter add │ nftables rule /      │ config rule          │ <filter><rule>       │ ip access-list ext...│
│ chain=input ...         │ storageforge-fwrules │   option target ...  │   <type>pass</type>  │   permit ...         │
└─────────────────────────┴──────────────────────┴──────────────────────┴──────────────────────┴──────────────────────┘
```

---

## 4. Deep Translation Mechanics by Subsystem

### 4.1 Layer 2 & Addressing on Linux
When compiling `/interface bridge add name=br-storage` and `/ip address add address=192.168.10.1/24 interface=br-storage`:

#### A. If Host Uses `systemd-networkd`:
StorageForge drops persistent, atomically generated files into `/etc/systemd/network/`:
- **`10-sf-br-storage.netdev`**:
  ```ini
  [NetDev]
  Name=br-storage
  Kind=bridge
  ```
- **`10-sf-br-storage.network`**:
  ```ini
  [Match]
  Name=br-storage

  [Network]
  Address=192.168.10.1/24
  DHCP=no
  LinkLocalAddressing=no
  ```
Triggered safely via: `networkctl reload`.

#### B. If Host Uses `NetworkManager`:
StorageForge uses declarative keyfile generation or `nmcli`:
```bash
nmcli connection add type bridge ifname br-storage con-name sf-br-storage \
    ipv4.method manual ipv4.addresses 192.168.10.1/24 ipv6.method disabled
nmcli connection up sf-br-storage
```

---

### 4.2 Routing & Gateways Translation
When compiling `/ip route add dst-address=10.20.0.0/16 gateway=10.0.0.254`:
- **Linux (`systemd-networkd`)**:
  Appends to matching interface `.network` file:
  ```ini
  [Route]
  Destination=10.20.0.0/16
  Gateway=10.0.0.254
  Metric=100
  ```
- **OpenWrt (`uci`)**:
  Appends to `/etc/config/network`:
  ```uci
  config route
      option interface 'lan'
      option target '10.20.0.0'
      option netmask '255.255.0.0'
      option gateway '10.0.0.254'
  ```
- **pfSense (`config.xml`)**:
  Inserts `<route>` inside `<staticroutes>`:
  ```xml
  <route>
      <interface>lan</interface>
      <network>10.20.0.0/16</network>
      <gateway>GW_LAN_TRANSIT</gateway>
      <descr><![CDATA[Transit to Site B]]></descr>
  </route>
  ```
- **Cisco IOS**:
  ```cisco
  ip route 10.20.0.0 255.255.0.0 10.0.0.254
  ```

---

### 4.3 DNS & DHCP Core Services Translation
When compiling `/ip dhcp-server add name=dhcp-lan interface=vlan10 address-pool=lan-pool` and static lease `/ip dhcp-server lease add address=192.168.10.50 mac-address=52:54:00:12:34:56`:
- **Linux Host (Deploying `dnsmasq`)**:
  ```text
  interface=vlan10
  dhcp-range=192.168.10.100,192.168.10.200,12h
  dhcp-option=option:router,192.168.10.1
  dhcp-option=option:dns-server,192.168.10.1
  dhcp-host=52:54:00:12:34:56,192.168.10.50,infinite
  ```
- **OpenWrt (`uci`)**:
  ```uci
  config dhcp 'lan'
      option interface 'vlan10'
      option start '100'
      option limit '101'
      option leasetime '12h'

  config host
      option name 'Static-SAN'
      option mac '52:54:00:12:34:56'
      option ip '192.168.10.50'
  ```
- **pfSense (`config.xml`)**:
  ```xml
  <dhcpd>
      <lan>
          <enable></enable>
          <range><from>192.168.10.100</from><to>192.168.10.200</to></range>
          <defaultleasetime>43200</defaultleasetime>
          <staticmap>
              <mac>52:54:00:12:34:56</mac>
              <ipaddr>192.168.10.50</ipaddr>
              <descr><![CDATA[Static-SAN]]></descr>
          </staticmap>
      </lan>
  </dhcpd>
  ```

---

### 4.4 WireGuard Overlay VPN Translation
When compiling `/interface wireguard add name=wg0 listen-port=51820 private-key="..."` and peer `/interface wireguard peers add interface=wg0 public-key="..." allowed-address=10.99.0.2/32`:
- **Linux Host (`/etc/wireguard/wg0.conf`)**:
  ```ini
  [Interface]
  PrivateKey = <key>
  ListenPort = 51820

  [Peer]
  PublicKey = <pubkey>
  AllowedIPs = 10.99.0.2/32
  Endpoint = 198.51.100.2:51820
  PersistentKeepalive = 25
  ```
- **OpenWrt (`uci`)**:
  ```uci
  config interface 'wg0'
      option proto 'wireguard'
      option private_key '<key>'
      option listen_port '51820'

  config wireguard_wg0
      option public_key '<pubkey>'
      list allowed_ips '10.99.0.2/32'
      option endpoint_host '198.51.100.2'
      option endpoint_port '51820'
      option persistent_keepalive '25'
  ```
- **pfSense (`config.xml`)**:
  Inserts `<tunnel>` and `<peer>` nodes into `<wireguard>` in `config.xml`, followed by `pfSsh.php playback wireguard_reload`.

---

## 5. Lockout Prevention & Automated Rollback Architecture

Modifying bridges, default routes, IP addresses, or VLANs carries high risk of severing the SSH connection over which StorageForge communicates with the host.

### 5.1 Connectivity-Path Guard (`net_guard`)
Before staging any network change, StorageForge verifies whether the target interface carries the controller's current SSH session:
```bash
net_is_ssh_path() {
  [[ -n ${SSH_CONNECTION:-} ]] || return 1
  [[ $(ip -o route get "${SSH_CONNECTION%% *}" 2>/dev/null) == *" dev $1 "* ]]
}
```
If an operation modifies the active ingress interface without an explicit rollback timer, **the plan is blocked before generation**.

### 5.2 Rollback Mechanisms Across Backends

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                      ROLLBACK ARMED (e.g. 5 MINUTES)                   │
 ├────────────────────────────────────────────────────────────────────────┤
 │ 1. Stage change with fallback restoration script & timer               │
 │ 2. Apply change on target host                                         │
 │ 3. Controller attempts immediate reconnection & health verification    │
 │    ├─► Success: Controller executes "storageforge confirm" (timer ends)│
 │    └─► Loss of Contact: Timer fires on host, restoring prior state     │
 └────────────────────────────────────────────────────────────────────────┘
```

1. **Linux Hosts (`systemd-networkd` / `NetworkManager`)**:
   - `fw_arm` journals pre-change state in `/etc/storageforge/network/journal`.
   - Starts an independent systemd timer unit (`sf-net-rollback.timer`).
   - If `sf-ctl` does not issue a signed confirmation within the window, the rollback unit fires, restoring original files and reloading network services.
2. **MikroTik RouterOS**:
   - Uses native **Safe Mode** (`<CTRL-X>` or session API safe mode). Any disconnection immediately auto-reverts the uncommitted delta.
3. **Cisco Systems**:
   - Executes `configure replace flash:pre-change.cfg revert <minutes>`.
   - Reverts automatically unless confirmed with `configure confirm`.
4. **OpenWrt**:
   - Staged UCI commit with a scheduled background `procd` rollback watchdog.
5. **pfSense**:
   - Versioned XML revision stored in `/conf/backup/backup-*.xml`.
   - Fallback script triggers `cp /conf/backup/backup-prev.xml /conf/config.xml && /etc/rc.reload_all`.

---

## 6. Bidirectional Inspection & UI Integration

StorageForge's Topology and Network views do not merely use this DSL for deployments; they use it as the **universal language for fleet inspection**:

1. **Fleet-Wide Uniformity**:
   - Clicking on a Debian hypervisor bridge, an OpenWrt router, or a Cisco switch displays its live configuration rendered in standardized MikroTik DSL syntax.
   - Operators can copy, edit, and restage the configuration across hosts seamlessly.
2. **What-If Impact Analysis (`whatif.py`)**:
   - Editing a route or VLAN in MikroTik syntax automatically computes the reachability delta across all workloads and storage shares before apply.
3. **IaC Export**:
   - Any staged full-stack network plan can be exported not only as raw MikroTik commands, but as declarative Ansible playbooks, Terraform resources, or Bash deploy scripts.
