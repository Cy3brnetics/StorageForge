# Expanded Networking Roadmap: Router & Switch Support, Multi-Transport (SSH/Telnet), and Isolated KVM Lab

A comprehensive engineering roadmap for expanding StorageForge from host-based networking into **full network infrastructure**: routers, managed switches, and firewalls running **MikroTik RouterOS, Cisco IOS/IOS-XE, OpenWrt, and pfSense/OPNsense**.

It establishes the multi-transport layer (SSH with PTY/legacy cipher support, Telnet, and REST APIs), maps out the complete feature capabilities of each router operating system, normalizes network and firewall facts into the existing StorageForge engines (`netfacts.py`, `firewall.py`, `reach.py`, `exposure.py`), and details the **isolated KVM lab architecture** (multi-segmented virtual topologies and Tier 12 tests) to validate everything without touching production traffic.

Status: **planned** on branch `dev-expanded-networking`. Builds on [infrastructure-platform-roadmap.md](infrastructure-platform-roadmap.md) and [docs/kvm-lab.md](docs/kvm-lab.md).

---

## 1. Goals and Non-Goals

### 1.1 Goals
1. **Multi-Platform Support**: Connect to and manage enterprise and homelab network gear:
   - **MikroTik RouterOS** (RouterOS v6 and v7)
   - **Cisco Systems** (IOS, IOS-XE, NX-OS)
   - **OpenWrt** (Linux-based router firmware with `uci`, `fw4`/`nftables`, and `fw3`/`iptables`)
   - **pfSense / OPNsense** (FreeBSD-based firewall appliances with `pf`, `pfctl`, and `config.xml`)
2. **Multi-Transport Connectivity**:
   - Modern SSH (key-based, agent-forwarded, non-interactive execution).
   - Network CLI SSH (interactive pseudo-terminal / PTY allocation, paging suppression, prompt detection).
   - Legacy SSH negotiation (compatibility ciphers and key exchanges for older Cisco/legacy hardware: `diffie-hellman-group1-sha1`, `ssh-rsa`, `aes128-cbc`).
   - Telnet transport with safe credential handling, banner negotiation, and strict timeout boundaries.
   - Native REST API adapters where available (MikroTik v7 REST, OPNsense REST, Cisco RESTCONF).
3. **Passive Facts Extraction**:
   - Extract interfaces, bridges, VLANs, MAC address tables, ARP caches, routing tables, DNS, and DHCP lease allocations.
   - Extract firewall filter rules, NAT/port-forwarding rules, mangle tables, and address-lists/aliases.
   - Extract L2/L3 neighbor discovery protocols (LLDP, CDP, MNDP) to establish physical topology links passively.
4. **Normalized Modeling**:
   - Feed router facts directly into `netfacts.py` and `inframeasure.py`.
   - Normalize BSD `pf`, RouterOS filter/NAT, OpenWrt `fw4`, and Cisco ACLs into the unified `firewall.py` schema (`chains`, `rules`, `nat`, `policies`).
   - Multi-hop path resolution in `reach.py`: determine if host A can reach host B across intermediate routers and firewalls.
   - Exposure badging in `exposure.py`: evaluate WAN-to-LAN DNAT / port-forwarding exposures.
5. **Safe Changes & Automated Rollback**:
   - Stage, diff, and dry-run configuration changes through the Plan → Report → Apply loop.
   - Enforce commit-confirmed / safety rollback timers across all platforms (RouterOS Safe Mode, Cisco `configure replace ... revert`, OpenWrt UCI rollback watchdog, pfSense revision backups).
6. **Standardized User Input & Multi-Backend Transpiler**:
   - Standardize all operator firewall rules, NAT policies, and network config inputs on an intuitive, declarative **MikroTik-style DSL** across all fleet targets.
   - Deploy-time compiler (**RosTranspiler**) translates the universal rules into native targets: Linux `nftables`, `firewalld`, `ufw`, `iptables`/`DOCKER-USER`, OpenWrt `fw4`/UCI, pfSense `pf`/XML, Cisco ACLs, and native RouterOS.
   - Bidirectional normalization: live rules parsed from any backend render back into uniform MikroTik DSL for consistent inspection across the fleet.
7. **Isolated KVM Testing Lab**:
   - Multi-homed, segmented virtual network topology (WAN, LAN1, LAN2, DMZ, Management) on isolated libvirt bridges.
   - Automated VM provisioning for router appliances (MikroTik CHR, OpenWrt x86, pfSense CE, Cisco virtual routers).
   - Test suite integration: **Tier 12 (Network Appliances & Routers)**.

### 1.2 Non-Goals
- No active network scanning, ping sweeps, or port probes. Topology discovery remains strictly passive and derived from authenticated router/switch state.
- Not a replacement for NetBox, LibreNMS, or Zabbix. StorageForge observes network state to provide unified storage, workload, and security context.
- No unverified direct configuration pushes. Every change must be dry-runnable, reported first, and protected by automatic rollback.

---

## 2. Transport Architecture

StorageForge's current `Transport` in `remote.py` is tailored for Linux/FreeBSD hosts with a POSIX shell, running `sh -c '<script>'` over an OpenSSH control socket. Network appliances differ significantly: they run custom CLI shells, require PTY allocation, paginate output with `--More--`, or use dedicated APIs.

```text
                     ┌──────────────────────────────────────────────┐
                     │           StorageForge Collector             │
                     └──────────────────────┬───────────────────────┘
                                            │
               ┌────────────────────────────┼───────────────────────────┐
               ▼                            ▼                           ▼
    ┌──────────────────────┐     ┌──────────────────────┐    ┌──────────────────────┐
    │  POSIX SSH Transport │     │ Network CLI Transport│    │  REST / HTTP Engine  │
    │  (Linux / BSD hosts) │     │    (SSH PTY / Telnet)│    │ (ROS v7, pfSense API)│
    └──────────┬───────────┘     └──────────┬───────────┘    └──────────┬───────────┘
               │                            │                           │
         sh -c '<script>'             CLI commands               JSON / RESTCONF
               │                            │                           │
               ▼                            ▼                           ▼
       Target Servers              Routers & Switches           Modern Appliances
```

### 2.1 Network CLI SSH Transport
- **PTY Allocation**: Allocate a pseudo-terminal (`ssh -tt` or programmatic PTY) to interact with command shells that reject non-interactive `sh -c`.
- **Terminal Pagination Handling**:
  - Cisco: execute `terminal length 0` and `terminal width 512` upon connection.
  - MikroTik: execute `:put [/terminal/screen-length/set value=0]` or run single commands directly via non-interactive SSH arguments: `ssh admin@host "/ip/address/print as-value"`.
  - OpenWrt: run standard POSIX ash/sh commands directly.
  - pfSense: bypass the 16-option console menu by invoking commands directly via SSH (`ssh admin@host "sh -c '...'"`), or run PHP snippets via `pfSsh.php`.
- **Prompt Detection & Command Buffering**: Robust regex-based prompt matching (`[>#\$]\s*$`) with configurable timeouts to reliably delineate command boundaries.
- **Legacy Cipher Negotiation**: Managed switches and older routers require legacy cryptographic suites:
  ```bash
  ssh -o KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1 \
      -o HostKeyAlgorithms=+ssh-rsa,ssh-dss \
      -o Ciphers=+aes128-cbc,3des-cbc,aes256-cbc \
      -p 22 user@switch
  ```

### 2.2 Telnet Transport Engine
Many legacy access switches (e.g. Cisco Catalyst 2950/2960, older HP ProCurve) and emergency serial console servers only offer Telnet.
- **Pure-Python Telnet Client**: Socket-based implementation handling Telnet Option Negotiation (RFC 854: `DO`, `DONT`, `WILL`, `WONT`, `IAC`), avoiding external binary dependencies.
- **Authentication Handshake**: State machine detecting `login:`, `username:`, and `password:` prompts with strict authentication timeouts (10 seconds).
- **Security & Secret Hygiene**:
  - Telnet credentials stored in the encrypted StorageForge key vault.
  - Plaintext passwords and session tokens are strictly redacted from deploy logs, command history, and UI outputs.
  - Warnings flagged in the Security panel when an active node is managed over unencrypted Telnet.

### 2.3 Native REST API Adapters
- **MikroTik RouterOS v7**: Native HTTPS REST API (`https://router/rest/ip/address`, `/rest/ip/firewall/filter`, `/rest/ip/route`) returning structured JSON natively.
- **OPNsense Core API**: Official JSON REST endpoints (`/api/diagnostics/interface/...`, `/api/firewall/...`).
- **Cisco IOS-XE RESTCONF**: RFC 8040 interface using YANG data models returning JSON.

---

## 3. Router System Deep Dive & Feature Capabilities

### 3.1 MikroTik RouterOS (v6 & v7)

MikroTik is particularly straightforward to adapt because RouterOS provides structured, machine-readable data across multiple interfaces:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        MikroTik RouterOS Facts                         │
├───────────────────┬────────────────────────────────────────────────────┤
│ CLI (SSH/Telnet)  │ /ip/address/print as-value                         │
│                   │ /ip/route/print as-value                           │
│                   │ /ip/firewall/filter/print as-value                 │
│                   │ /interface/print as-value                          │
│                   │ /ip/neighbor/print as-value                        │
│                   │ /export terse                                      │
├───────────────────┼────────────────────────────────────────────────────┤
│ REST API (v7)     │ GET /rest/ip/address                               │
│                   │ GET /rest/ip/firewall/filter                       │
│                   │ GET /rest/ip/route                                 │
│                   │ GET /rest/interface                                │
├───────────────────┼────────────────────────────────────────────────────┤
│ RouterOS API      │ Native binary protocol on port 8728/8729 (TLS)     │
└───────────────────┴────────────────────────────────────────────────────┘
```

#### Supported Features & Extraction
- **Interfaces & Layer 2**:
  - Ethernet, SFP/QSFP ports, bonding (LACP / 802.3ad), hardware-offloaded bridge (`/interface/bridge`), VLANs (`/interface/vlan` and `/interface/bridge/vlan`), MAC addresses, MTU, line speeds, and duplex.
- **Addressing & IP Services**:
  - IPv4 and IPv6 addresses with subnet masks, IP address pools, DHCP servers, and active DHCP leases (`/ip/dhcp-server/lease/print as-value` providing IP, MAC, hostname, and status).
  - Active ARP table (`/ip/arp/print as-value`).
- **Topology Discovery**:
  - MikroTik Neighbor Discovery Protocol (MNDP), CDP, and LLDP neighbors (`/ip/neighbor/print as-value`) revealing connected switches, routers, and access points.
- **Routing**:
  - Routing tables (`/ip/route/print as-value`), gateway next-hops, distance/metric, scope, static routes, OSPF, BGP, and routing marks (policy-based routing).
- **Firewall & NAT**:
  - Filter rules (`/ip/firewall/filter`): input, forward, output chains; actions (accept, drop, reject, fasttrack-connection); port, protocol, source, and destination matches.
  - NAT rules (`/ip/firewall/nat`): source NAT (masquerade), destination NAT (port forwarding to internal LAN/DMZ IPs), `to-addresses`, `to-ports`.
  - Address Lists (`/ip/firewall/address-list`): static and dynamic IP sets (frequently used for security fences and geo-blocking).
  - Connection Tracking: active connection counts and TCP states.
- **Safe Change Mechanism**:
  - **RouterOS Safe Mode**: Toggle safe mode (`<CTRL-X>` or API session flag). If the connection breaks or StorageForge cannot confirm the apply within the timeout, RouterOS automatically reverts all changes made during that session.
  - Scripted backup & rollback: `/system/backup/save name=pre-change` with automated `/system/backup/load` fallback.

---

### 3.2 Cisco Systems (IOS, IOS-XE, NX-OS)

Cisco devices run specialized operating systems with command-line interfaces requiring pagination control and privilege escalation.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                          Cisco IOS / IOS-XE Facts                      │
├───────────────────┬────────────────────────────────────────────────────┤
│ Base Session      │ terminal length 0                                  │
│                   │ terminal width 512                                 │
│                   │ enable [password]                                  │
├───────────────────┼────────────────────────────────────────────────────┤
│ Layer 2 & Physical│ show interfaces status                             │
│                   │ show ip interface brief                            │
│                   │ show vlan brief                                    │
│                   │ show etherchannel summary                          │
│                   │ show mac address-table                             │
├───────────────────┼────────────────────────────────────────────────────┤
│ Neighbors (L2)    │ show cdp neighbors detail                          │
│                   │ show lldp neighbors detail                         │
│                   │ show ip arp                                        │
├───────────────────┼────────────────────────────────────────────────────┤
│ Layer 3 & Routing │ show ip route [json]                               │
│                   │ show ipv6 route                                    │
│                   │ show ip route vrf *                                │
├───────────────────┼────────────────────────────────────────────────────┤
│ Firewall & ACLs   │ show ip access-lists                               │
│                   │ show object-group                                  │
│                   │ show ip nat translations                           │
│                   │ show zone-pair security                            │
├───────────────────┼────────────────────────────────────────────────────┤
│ Configuration     │ show running-config                                │
└───────────────────┴────────────────────────────────────────────────────┘
```

#### Supported Features & Extraction
- **Interfaces & Layer 2**:
  - Physical ports (FastEthernet, GigabitEthernet, TenGigabitEthernet), Port-Channels (EtherChannel LACP), Switchport mode (access, trunk), native VLAN, allowed VLANs, administrative and operational status, MAC address table.
- **Topology & Neighbor Discovery**:
  - Cisco Discovery Protocol (CDP) and Link Layer Discovery Protocol (LLDP) detailing remote device hostname, platform, remote interface port, management IP, and capabilities (Router, Switch, Host).
  - Dynamic and static ARP table mappings (`show ip arp`).
- **Routing & VRF**:
  - Global routing table (`show ip route`), directly connected subnets, static routes, dynamic routing (OSPF, EIGRP, BGP), administrative distance, metric.
  - Virtual Routing and Forwarding (VRF) instances for multi-tenant network segmentation.
- **Security & Access Control**:
  - Standard and Extended Access Control Lists (ACLs): numbered and named ACLs with sequence numbers, permit/deny actions, protocol, source/destination IP/wildcard mask, and port operators (`eq`, `range`, `gt`, `lt`).
  - Object Groups (network and service object groups).
  - NAT translations (static 1:1 NAT and dynamic overload/PAT).
  - Cisco Zone-Based Policy Firewall (ZFW): zones, zone-pairs, class-maps, and inspect policies.
- **Safe Change Mechanism**:
  - **Commit-Confirmed Rollback**:
    ```text
    archive
      path flash:archive-config
    configure replace flash:pre-change.cfg revert 10
    ```
    If the operator or StorageForge does not issue `configure confirm` within 10 minutes, the device automatically reverts to the saved configuration.
  - Fallback: `reload in 10` prior to applying configuration, followed by `reload cancel` on verified connectivity.

---

### 3.3 OpenWrt

OpenWrt is a modular Linux distribution designed for routers and wireless gateways. Because it is standard Linux with the Unified Configuration Interface (UCI), facts extraction is comprehensive, lightweight, and robust.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                              OpenWrt Facts                             │
├───────────────────┬────────────────────────────────────────────────────┤
│ Unified Config    │ uci show network                                   │
│ (UCI Engine)      │ uci show firewall                                  │
│                   │ uci show dhcp                                      │
│                   │ uci show wireless                                  │
├───────────────────┼────────────────────────────────────────────────────┤
│ Micro-Bus (ubus)  │ ubus call network.interface dump                   │
│                   │ ubus call network.device status                    │
│                   │ ubus call system info                              │
├───────────────────┼────────────────────────────────────────────────────┤
│ Linux Kernel & L3 │ ip -j addr show                                    │
│                   │ ip -j route show                                   │
│                   │ ip -j neigh show                                   │
│                   │ bridge -j vlan show                                │
├───────────────────┼────────────────────────────────────────────────────┤
│ Firewall Backends │ OpenWrt 22+ (fw4): nft -j list ruleset             │
│                   │ OpenWrt 19/21 (fw3): iptables-save                 │
├───────────────────┼────────────────────────────────────────────────────┤
│ DHCP & Clients    │ cat /tmp/dhcp.leases                               │
├───────────────────┼────────────────────────────────────────────────────┤
│ Wireless          │ iwinfo                                             │
└───────────────────┴────────────────────────────────────────────────────┘
```

#### Supported Features & Extraction
- **Network & Layer 2**:
  - Network interfaces (LAN, WAN, Guest, DMZ), bridge devices (`br-lan`), Distributed Switch Architecture (DSA) switch VLAN tagging, MTU, MAC addresses.
  - `ubus call network.interface dump` returns structured JSON with interface statistics, assigned IPs, gateways, and uptime.
- **Firewall & Traffic Rules**:
  - OpenWrt 22.03+ uses **`fw4`** based on `nftables`: native JSON rulesets (`nft -j list ruleset`) map directly into StorageForge's `firewall.py` engine.
  - Older OpenWrt releases use **`fw3`** based on `iptables`: parsed via `iptables-save`.
  - UCI firewall models: zones (WAN, LAN), zone forwarding matrix (`src`, `dest`, `action`), port redirects (DNAT), traffic rules, and SNAT masquerading.
- **DHCP, DNS & Connected Devices**:
  - Active DHCP leases (`/tmp/dhcp.leases`): lease expiration time, MAC address, assigned IP, hostname, and client ID.
  - DNS forwarder (`dnsmasq` or `unbound`) upstream servers and domain search lists.
- **Wireless Interfaces**:
  - Radio interfaces (2.4 GHz, 5 GHz, 6 GHz), SSIDs, encryption modes (WPA2/WPA3), active wireless clients, signal strength (RSSI), and bitrate.
- **Safe Change Mechanism**:
  - UCI batch staging: changes are written to staging (`uci set ...`) and committed (`uci commit`).
  - Staged rollback script with systemd/procd watchdog timer: if network access is severed after `service firewall restart` or `service network restart`, an automated timer restores `/etc/config/` backups.

---

### 3.4 pfSense / OPNsense

Both pfSense and OPNsense are built on FreeBSD and utilize the **Packet Filter (`pf`)** kernel firewall. Their defining architectural advantage is a single, authoritative configuration file.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        pfSense / OPNsense Facts                        │
├───────────────────┬────────────────────────────────────────────────────┤
│ Single Source     │ /cf/conf/config.xml (or /conf/config.xml)          │
│ of Truth          │ (Contains full interfaces, firewall rules, NAT,   │
│                   │  gateways, aliases, users, DHCP, and VPNs)         │
├───────────────────┼────────────────────────────────────────────────────┤
│ Kernel & CLI      │ pfctl -sr (filter rules)                           │
│                   │ pfctl -sn (NAT rules)                              │
│                   │ pfctl -s Tables (active alias tables)              │
│                   │ pfctl -ss (active state table)                     │
│                   │ ifconfig -a                                        │
│                   │ netstat -rn                                        │
│                   │ sockstat -4 -6 -l                                  │
├───────────────────┼────────────────────────────────────────────────────┤
│ PHP Shell / CLI   │ pfSsh.php playback <command>                       │
├───────────────────┼────────────────────────────────────────────────────┤
│ REST APIs         │ OPNsense: /api/diagnostics/interface/...           │
│                   │ pfSense: FauxAPI / Community REST API              │
└───────────────────┴────────────────────────────────────────────────────┘
```

#### Supported Features & Extraction
- **The XML Configuration Model (`config.xml`)**:
  - StorageForge can read `/cf/conf/config.xml` in a single pass. It parses with 100% fidelity without parsing complex CLI text:
    - `<interfaces>`: physical assignments (WAN, LAN, OPT1), static IPs, DHCP client status, MTU, spoofed MAC.
    - `<vlans>`: VLAN tag, physical parent interface, description.
    - `<gateways>`: default gateways, gateway monitoring, Multi-WAN failover/tier groups.
    - `<filter>`: firewall rules, interface assignment, protocol, source/destination aliases, action (pass, block, reject), logging, and schedule.
    - `<nat>`: inbound port forwards (DNAT), outbound NAT rules (manual, hybrid, automatic), 1:1 NAT mappings.
    - `<aliases>`: IP lists, network lists, port lists, URL tables.
    - `<openvpn>` & `<wireguard>`: tunnels, listening ports, remote networks, client configurations.
    - `<dhcpd>`: pools, static IP reservations, lease ranges.
- **Live Kernel State via `pfctl`**:
  - `pfctl -sr`: currently loaded packet filter rules.
  - `pfctl -sn`: active NAT rules.
  - `pfctl -s Tables`: in-memory IP tables used by aliases.
  - `pfctl -ss`: current connection state count.
- **Safe Change Mechanism**:
  - pfSense automatically saves versioned configuration revisions in `/conf/backup/backup-*.xml` before any modification.
  - Configuration rollback: copy previous revision to `config.xml` and trigger reload via `pfSsh.php playback filter_reload` or `/etc/rc.filter_configure`.
  - Self-healing watchdog: test connectivity from `sf-ctl` post-apply; if unreachable, a staged background script reinstates the previous XML and reloads the rules.

---

## 4. Multi-Platform Feature Matrix

| Feature Domain | MikroTik RouterOS | Cisco Systems | OpenWrt | pfSense / OPNsense |
| :--- | :--- | :--- | :--- | :--- |
| **Primary Transports** | SSH, Telnet, REST (v7), ROS API | SSH (PTY), Telnet, RESTCONF | SSH, Telnet, ubus over HTTP | SSH, REST (OPNsense), FauxAPI |
| **Data Format** | Key-Value / JSON / Export | Text CLI / YANG JSON | JSON (`ubus`, `ip -j`) / UCI | XML (`config.xml`) / Text CLI |
| **L2 & VLANs** | Bridge VLAN filtering, Bonds | Switchport trunks/access, LACP | DSA bridges, 802.1q VLANs | FreeBSD lagg, VLAN tags |
| **Routing Protocols** | Static, OSPF, BGP, Policy Marks | Static, OSPF, EIGRP, BGP, VRF | Static, OSPF (BIRD/FRR), BGP | Static, Gateway Groups, FRR |
| **Firewall Engine** | RouterOS Filter & Mangle | Cisco ACLs / ZFW | `fw4` (nftables) / `fw3` (iptables)| FreeBSD Packet Filter (`pf`) |
| **NAT Support** | srcnat/masquerade, dstnat | Dynamic NAT/PAT, Static 1:1 | Zone redirects, Masquerade | Port forwards, Outbound NAT, 1:1 |
| **Neighbor Discovery** | MNDP, CDP, LLDP | CDP, LLDP, ARP | ARP, DHCP leases, `ip neigh` | ARP, DHCP leases, NDP |
| **Rollback Safety** | RouterOS Safe Mode (`<CTRL-X>`) | `configure replace ... revert` | Staged UCI watchdog timer | Config XML revision rollback |

---

## 5. StorageForge Core Normalization Engine

All facts gathered from routers and switches are normalized into StorageForge's existing data models so that all upper layers (Topology Graph, Path Query, Exposure Badging, and Planner) remain completely vendor-agnostic.

```text
                  ROUTER DISCOVERY & NORMALIZATION PIPELINE
 ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
 │   MikroTik   │   │ Cisco IOS/XE │   │   OpenWrt    │   │pfSense/OPNs  │
 │(as-value/REST│   │(show commands│   │ (uci / ubus) │   │ (config.xml) │
 └──────┬───────┘   └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
        │                  │                  │                  │
        ▼                  ▼                  ▼                  ▼
 ┌───────────────────────────────────────────────────────────────────────┐
 │                      Device Facts Normalizer                          │
 └──────────────────────────────────┬────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
 ┌──────────────┐            ┌──────────────┐            ┌──────────────┐
 │  netfacts.py │            │  firewall.py │            │ infragraph.py│
 │ (Interfaces, │            │ (Normalized  │            │(Topology Map,│
 │Routes, Neigh)│            │ Rules & NAT) │            │Edges, Hops)  │
 └──────┬───────┘            └──────┬───────┘            └──────┬───────┘
        │                           │                           │
        └───────────────────────────┼───────────────────────────┘
                                    │
                                    ▼
                ┌───────────────────────────────────────┐
                │   reach.py (Multi-Hop Path Query)     │
                │   exposure.py (WAN Exposure Badging)  │
                └───────────────────────────────────────┘
```

### 5.1 Normalized Interface Model (`netfacts.py`)
Routers map physical and virtual interfaces to:
```python
{
    'name': 'ether1' or 'GigabitEthernet0/1' or 'eth0' or 'igb0',
    'kind': 'ethernet' | 'bridge' | 'vlan' | 'bond' | 'tunnel',
    'state': 'up' | 'down',
    'mtu': 1500,
    'mac': '00:0c:29:ab:cd:ef',
    'master': 'bridge' | 'Port-Channel1' | None,
    'bridge_vlans': [10, 20, 30],
    'addresses': [
        {'ip': '192.168.1.1', 'prefix': 24, 'scope': 'global'}
    ]
}
```

### 5.2 Normalized Firewall & NAT Model (`firewall.py`)
Rules from pfSense `pf`, RouterOS filter, Cisco ACLs, and OpenWrt `fw4` normalize into:
```python
{
    'backend': 'pf' | 'routeros' | 'cisco_acl' | 'nftables' | 'iptables',
    'policies': {'input': 'drop', 'forward': 'drop', 'output': 'accept'},
    'chains': [
        {'name': 'wan_in', 'hook': 'forward', 'policy': 'drop', 'prio': 0}
    ],
    'rules': [
        {
            'order': 10,
            'chain': 'wan_in',
            'action': 'accept' | 'drop' | 'reject',
            'proto': 'tcp',
            'dports': [443],
            'saddr': '0.0.0.0/0',
            'daddr': '192.168.1.50',
            'comment': 'Allow HTTPS to DMZ Web'
        }
    ],
    'nat': [
        {
            'action': 'dnat',
            'proto': 'tcp',
            'ext_port': 443,
            'to_addr': '192.168.1.50',
            'to_port': 443,
            'iif': 'wan'
        }
    ]
}
```

### 5.3 Multi-Hop Path Query (`reach.py`)
Today, `reach.py` calculates whether Host A can reach Host B assuming a flat direct connection or a single default gateway. With router normalization:
1. **Source Hop**: Out of Host A via its routing table.
2. **Intermediate Router Hops**:
   - Router receives packet on ingress interface.
   - Evaluates router firewall filter / forward rules.
   - Evaluates NAT/DNAT mapping.
   - Matches routing table / VRF for next hop towards destination subnet.
3. **Destination Hop**: Into Host B via ingress firewall and listening socket.
4. **Verdict**: `allowed`, `blocked`, or `unknown` (identifying the exact router rule that dropped or permitted the traffic).

---

## 6. Standardized User Input (MikroTik DSL) & Full-Stack Multi-Backend Transpiler

To eliminate cognitive friction across diverse environments, StorageForge **standardizes all operator input across the entire networking stack—L2 switching, VLANs, bridges, bonding, IP addressing, static and policy routing, DNS, DHCP, WireGuard overlay tunnels, and firewalls—on an intuitive MikroTik RouterOS declarative DSL**. 

At deploy time, the StorageForge **`RosTranspiler`** compiles this standardized definition into the target host's native configuration syntax, while preserving commit-confirmed rollback guards. Full technical specification in [docs/standardized-network-stack-mikrotik.md](docs/standardized-network-stack-mikrotik.md).

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │           UNIVERSAL FULL-STACK NETWORKING SPECIFICATION (DSL)          │
 │   /interface bridge ... | /ip address ... | /ip route ... | /ip dns ...│
 │   /ip dhcp-server ... | /interface wireguard ... | /ip firewall ...    │
 └──────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    ▼
                 ┌──────────────────────────────────────┐
                 │ StorageForge RosTranspiler Engine    │
                 │ (AST Parser, Validator, & Generator) │
                 └──────────────────┬───────────────────┘
                                    │
    ┌──────────────┬────────────────┼──────────────┬────────────────┐
    ▼              ▼                ▼              ▼                ▼
┌──────────┐ ┌──────────┐     ┌──────────┐   ┌───────────┐    ┌───────────┐
│ Linux    │ │ Linux    │     │  OpenWrt │   │  pfSense  │    │ Cisco IOS │
│systemd-nt│ │NetworkMgr│     │ (UCI/fw4)│   │ (BSD XML) │    │  (CLI)    │
└──────────┘ └──────────┘     └──────────┘   └───────────┘    └───────────┘
```

### 6.1 Full-Stack DSL Taxonomy
Operators can provide input via CLI strings or structured JSON in plan steps:
- **Layer 2 (Bridges, Ports, VLANs, Bonds)**:
  ```routeros
  /interface bridge add name=br-lan vlan-filtering=yes
  /interface bridge port add bridge=br-lan interface=eth1 pvid=10
  /interface bridge vlan add bridge=br-lan vlan-ids=10,20 tagged=br-lan,eth3 untagged=eth1
  /interface vlan add name=vlan10 vlan-id=10 interface=br-lan
  /interface bonding add name=bond0 slaves=eth1,eth2 mode=802.3ad
  ```
- **Layer 3 (IP Addressing, Subnets, Pools)**:
  ```routeros
  /ip address add address=192.168.10.1/24 interface=vlan10 comment="Gateway"
  /ip pool add name=dhcp-pool ranges=192.168.10.100-192.168.10.200
  ```
- **Routing & Policy Routing**:
  ```routeros
  /ip route add dst-address=0.0.0.0/0 gateway=198.51.100.1 distance=1
  /routing table add name=dmz-table fib
  /routing rule add src-address=10.77.20.0/24 table=dmz-table
  ```
- **Core Network Services (DNS & DHCP)**:
  ```routeros
  /ip dns set servers=1.1.1.1,8.8.8.8 allow-remote-requests=yes
  /ip dhcp-server add name=dhcp-lan interface=vlan10 address-pool=dhcp-pool
  /ip dhcp-server lease add address=192.168.10.50 mac-address=52:54:00:12:34:56
  ```
- **VPN & Tunnels (WireGuard)**:
  ```routeros
  /interface wireguard add name=wg0 listen-port=51820 private-key="<key>"
  /interface wireguard peers add interface=wg0 public-key="<pubkey>" allowed-address=10.99.0.0/24
  ```
- **Firewall & NAT**:
  ```routeros
  /ip firewall filter add chain=input protocol=tcp dst-port=22 src-address=10.0.0.0/8 action=accept
  /ip firewall nat add chain=dstnat protocol=tcp dst-port=443 in-interface=wan action=dst-nat to-addresses=10.77.20.80 to-ports=443
  ```

### 6.2 Deploy-Time Target Compilation Across the Stack
- **Linux Hosts (`systemd-networkd` / `NetworkManager`)**:
  - Bridges, VLANs, and Bonds generate atomic `.netdev` and `.network` configuration units (or `nmcli` connection profiles).
  - Routes and DNS populate `.network` `[Route]` and `[Network] DNS=` sections.
  - DHCP services generate lightweight `dnsmasq` or `kea` configuration blocks.
  - WireGuard maps to `wg-quick` or systemd `[WireGuard]`.
  - Firewall and NAT compile via `storageforge-fwrules` into `nftables`, `firewalld`, or `ufw`.
- **OpenWrt (`uci`)**:
  - Bridges, interfaces, and routes compile to `/etc/config/network`.
  - DNS and DHCP compile to `/etc/config/dhcp`.
  - WireGuard compiles to `proto 'wireguard'` interface sections.
  - Firewall and NAT compile to `/etc/config/firewall` (`fw4` rules and redirects).
- **pfSense / OPNsense**:
  - Compiles into respective nodes within `/conf/config.xml`: `<interfaces>`, `<vlans>`, `<bridges>`, `<laggs>`, `<gateways>`, `<staticroutes>`, `<dns>`, `<dhcpd>`, `<wireguard>`, `<filter>`, and `<nat>`.
- **Cisco IOS/IOS-XE**:
  - Compiles to native interface definitions (`switchport mode trunk`, `ip address ...`), `ip route`, `ip name-server`, `ip dhcp pool`, and extended access-lists.
- **MikroTik RouterOS**:
  - Executed directly over SSH CLI or v7 REST API.

### 6.3 Universal Bidirectional Normalization
When inspecting live state on ANY managed server, router, or switch, StorageForge reverse-normalizes the target's native configuration into standard MikroTik DSL syntax, giving operators one consistent syntax across the entire fleet in both the Web UI and CLI.

---

## 7. Isolated KVM Test Lab Architecture

To thoroughly test router adaptations, multi-transport connectivity, and multi-hop reachability without affecting external networks, the KVM test lab (`examples/lab/lab.sh`) is extended with an **isolated, multi-subnet virtual topology**.

### 7.1 Isolated Network Topology

The lab topology deploys 4 isolated libvirt bridges with no default masquerade to the host:

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                     LIBVIRT ISOLATED NETWORK LAB                       │
 ├────────────────────────────────────────────────────────────────────────┤
 │                                                                        │
 │                      [ Management Bridge: 10.77.0.0/24 ]               │
 │                                   │                                    │
 │                       ┌───────────┴───────────┐                        │
 │                       │  sf-ctl (Debian 13)   │                        │
 │                       │ StorageForge Instance │                        │
 │                       └───────────┬───────────┘                        │
 │                                   │                                    │
 │              ┌────────────────────┼────────────────────┐               │
 │              │                    │                    │               │
 │              ▼                    ▼                    ▼               │
 │      ┌───────────────┐    ┌───────────────┐    ┌───────────────┐       │
 │      │  sf-mikrotik  │    │  sf-openwrt   │    │  sf-pfsense   │       │
 │      │ RouterOS CHR  │    │  OpenWrt x86  │    │  pfSense CE   │       │
 │      └───────┬───────┘    └───────┬───────┘    └───────┬───────┘       │
 │              │                    │                    │               │
 │              ▼                    ▼                    ▼               │
 │   ┌───────────────────────┬───────────────────────┬─────────────────┐  │
 │   │ sflab-wan             │ sflab-lan1            │ sflab-dmz       │  │
 │   │ (198.51.100.0/24)     │ (10.77.10.0/24)       │ (10.77.20.0/24) │  │
 │   └───────────────────────┴───────────────────────┴─────────────────┘  │
 │              │                    │                    │               │
 │              ▼                    ▼                    ▼               │
 │      ┌───────────────┐    ┌───────────────┐    ┌───────────────┐       │
 │      │ sf-wan-host   │    │ sf-lan-client │    │ sf-dmz-server │       │
 │      │ (Mock Internet│    │  (Alpine 3.24)│    │ (Ubuntu/Nginx)│       │
 └──────┴───────────────┴────────────────────┴────────────────────┴───────┘
```

#### Network Segments
- **`sflab-mgmt` (`10.77.0.0/24`)**: Out-of-band management network where `sf-ctl` resides and communicates with the management IP of each router and server VM.
- **`sflab-wan` (`198.51.100.0/24`)**: Simulates the external WAN network. Routers expose their external interfaces here.
- **`sflab-lan1` (`10.77.10.0/24`)**: Internal corporate/client network. Protected behind the router NAT/firewall.
- **`sflab-dmz` (`10.77.20.0/24`)**: Demilitarized zone for exposed services (e.g. mock web/NFS servers).

### 7.2 Router Appliance VM Specifications

| VM Name | Operating System | Base Image / Source | vCPU | RAM | Disk | Interfaces Attached |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| `sf-mikrotik` | RouterOS 7.x CHR | Official MikroTik Cloud Hosted Router QCOW2 | 1 | 128 MB | 1 GB | mgmt, wan, lan1, dmz |
| `sf-openwrt` | OpenWrt 23.05 x86 | Official generic-ext4-combined.img.gz | 1 | 128 MB | 1 GB | mgmt, wan, lan1, dmz |
| `sf-pfsense` | pfSense CE 2.7.x | Official ISO / Pre-seeded UFS QCOW2 disk | 1 | 1024 MB | 8 GB | mgmt, wan, lan1, dmz |
| `sf-cisco` | Cisco IOSv / VyOS | IOSv QCOW2 / VyOS 1.4 rolling cloud-init | 1 | 1024 MB | 4 GB | mgmt, wan, lan1, dmz |

### 7.3 Automated VM Provisioning & Pre-Seeding

1. **MikroTik CHR (`sf-mikrotik`)**:
   - Download official `chr-7.x.vmdk` or `.img.zip`, convert to QCOW2.
   - Attach a secondary 10 MB FAT disk image holding `autorun.scr` containing initial credentials (`admin` with pre-shared SSH key) and IP assignment on `ether1` (management).
2. **OpenWrt (`sf-openwrt`)**:
   - Decompress `openwrt-x86-64-generic-ext4-combined.img.gz`.
   - Use `virt-customize` or `guestfish` to mount the rootfs and pre-populate `/etc/config/network`, `/etc/config/dropbear`, and `/etc/dropbear/authorized_keys`.
   - Boots in under 5 seconds with zero interactive steps.
3. **pfSense (`sf-pfsense`)**:
   - Unattended pre-seeded disk image with `/cf/conf/config.xml` pre-installed:
     - Pre-assigned interfaces: `vtnet0` (mgmt: 10.77.0.25), `vtnet1` (wan: 198.51.100.1), `vtnet2` (lan1: 10.77.10.1), `vtnet3` (dmz: 10.77.20.1).
     - SSH enabled with pre-shared public key in `<authorizedkeys>`.
     - Standard test firewall rules and port forward from WAN 443 to DMZ 443.

---

## 8. Test Tier 12: Network Appliances & Routers

Extending the test suite (`tests/lab/tiers_network.py`) to validate all capabilities systematically:

### Tier 12 Checks
- **12.0: Multi-Transport Handshake**:
  - Connect to `sf-mikrotik` over modern SSH.
  - Connect to `sf-openwrt` over modern SSH and Telnet.
  - Connect to `sf-pfsense` over SSH (verifying console menu bypass).
  - Connect to `sf-cisco` over Telnet and legacy cipher SSH.
  - Verify credential redacting in logs.
- **12.1: Passive Facts Extraction (`netfacts`)**:
  - Verify interface extraction (physical names, MACs, MTUs, IP assignments).
  - Verify VLAN tagging and bridge membership extraction.
  - Verify routing tables and default gateways.
  - Verify ARP and neighbor tables without generating outbound probe packets.
- **12.2: Firewall & NAT Normalization**:
  - Parse pfSense `config.xml` and verify parsed rules match `pfctl -sr`.
  - Parse MikroTik `/ip/firewall/filter` and `/ip/firewall/nat`.
  - Parse OpenWrt `fw4` (`nftables` JSON) and verify rule ordering.
  - Confirm that all 4 models produce identical normalized rule structures in `firewall.py`.
- **12.3: Cross-Segment Reachability Query (`reach.py`)**:
  - Query reachability: `sf-lan-client` (10.77.10.50) → `sf-dmz-server` (10.77.20.80) on port 80.
  - Verify `reach.py` models router traversal, identifies the allowing forward rule, and outputs `verdict: 'allowed'`.
  - Execute real `curl` between the two VMs to confirm the analytical prediction matches physical reality.
  - Change router rule to `drop` traffic between LAN1 and DMZ.
  - Re-run `reach.py` query; confirm verdict flips to `blocked`, citing the exact router rule.
- **12.4: WAN Exposure Badging (`exposure.py`)**:
  - Verify that a service on `sf-dmz-server:443` with a port-forward rule on the router is marked as `exposure: 'any'` (publicly exposed).
  - Verify that an internal service on `sf-lan-client` with no port forward is marked as `exposure: 'lan'`.
- **12.5: Standardized Input & Transpilation Verification**:
  - Submit rules via MikroTik DSL for all targets.
  - Verify `RosTranspiler` compiles valid native rulesets for `nftables`, `firewalld`, `ufw`, `iptables`, `OpenWrt`, `pfSense`, and `Cisco`.
  - Verify reverse normalization correctly renders active rules back into standard MikroTik DSL.
- **12.6: Safe Configuration & Rollback Testing**:
  - Stage a dangerous plan step: insert a firewall rule blocking SSH port 22 on the management interface.
  - Apply the plan step with a 3-minute rollback timer.
  - Verify that the connection is severed, triggering the safety mechanism.
  - Observe automatic rollback (RouterOS safe mode / Cisco revert / watchdog timer).
  - Confirm `sf-ctl` re-establishes SSH contact automatically once the rollback completes.

---

## 9. Implementation Phases & Milestones

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                      IMPLEMENTATION ROADMAP PHASES                     │
 ├────────────────────────────────────────────────────────────────────────┤
 │ Phase 1: Transports (SSH PTY, Telnet Engine, Legacy Ciphers)           │
 │ Phase 2: MikroTik RouterOS Adapter (CLI as-value & REST v7)            │
 │ Phase 3: OpenWrt Adapter (UCI & fw4/nftables Parser)                   │
 │ Phase 4: pfSense / OPNsense Adapter (config.xml & pfctl Engine)        │
 │ Phase 5: Cisco IOS/IOS-XE Adapter (CLI parser & commit-confirmed)      │
 │ Phase 6: RosTranspiler (MikroTik DSL Compiler & Target Emitters)       │
 │ Phase 7: Normalization, Multi-Hop reach.py & exposure.py Updates       │
 │ Phase 8: Isolated KVM Lab Environment & Tier 12 Test Suite             │
 └────────────────────────────────────────────────────────────────────────┘
```

- **Phase 1: Transports**: Develop `NetworkTransport` and `TelnetTransport` classes in `remote.py` with PTY allocation, prompt detection, and legacy cipher profiles.
- **Phase 2: MikroTik Adapter**: Implement `routeros.py` collector, extracting interfaces, routes, neighbors, and firewall filter/NAT.
- **Phase 3: OpenWrt Adapter**: Implement `openwrt.py` collector using `ubus` and `uci`, normalizing `fw4` nftables JSON.
- **Phase 4: pfSense Adapter**: Implement `pfsense.py` XML reader, extracting full configuration directly from `config.xml`.
- **Phase 5: Cisco Adapter**: Implement `cisco.py` CLI parser for `show` commands, supporting Cisco ACLs and `configure replace ... revert`.
- **Phase 6: RosTranspiler**: Build `rostranspiler.py` to parse MikroTik DSL and compile to native `nftables`, `firewalld`, `ufw`, `iptables`, OpenWrt UCI, pfSense XML, and Cisco ACLs.
- **Phase 7: Multi-Hop Reasoning**: Update `reach.py` to trace hops through intermediate routers and firewalls; update `exposure.py` for router DNAT mappings.
- **Phase 8: KVM Lab & Tier 12 Tests**: Add router configurations to `images.conf`, `nodes.conf`, and `roles.conf`, configure multi-bridge topologies in `lab.sh`, and build Tier 12 test coverage.
