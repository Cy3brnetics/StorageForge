# Standardized Firewall & Network Config: MikroTik-Style DSL & Multi-Backend Transpiler

A technical architecture and specification for standardizing operator input for **firewall rules, NAT policies, and network configuration** across all StorageForge managed hosts using a **MikroTik-style declarative DSL**. At deploy time, StorageForge compiles and translates this universal definition into the native syntax required by each target system's backend.

---

## 1. Executive Summary & Design Vision

Modern homelabs and enterprise infrastructures contain heterogeneous firewalls and networking engines: Linux servers running `nftables`, `firewalld`, `ufw`, or raw `iptables`; routers running `OpenWrt` (`fw4`/`uci`), `pfSense`/`OPNsense` (`pf`), or `Cisco IOS` (ACLs/ZFW); and `MikroTik RouterOS` appliances.

Requiring operators to write bespoke rules for each backend is error-prone and undermines StorageForge's cross-fleet visibility. 

### Why MikroTik RouterOS Syntax as the Universal Standard?
MikroTik RouterOS provides one of the most mature, intuitive, and granular network configuration syntaxes in the industry:
1. **Explicit Chains & Actions**: Distinct separation of packet paths (`input`, `forward`, `output`, `dstnat`, `srcnat`) and explicit actions (`accept`, `drop`, `reject`, `dst-nat`, `masquerade`, `jump`).
2. **Key-Value Declarative Format**: Key-value pairs (`protocol=tcp dst-port=22 src-address=10.0.0.0/8`) that parse cleanly into machine-readable ASTs while remaining natural for human operators.
3. **First-Class Address Lists**: Intuitive IP set grouping (`address-list`) that translates cleanly to nftables sets, ipsets, pfSense aliases, and Cisco object-groups.
4. **Bidirectional Uniformity**: Because MikroTik syntax is expressive enough to represent the capabilities of `nftables` and `pf`, it works as a **universal intermediate representation (IR)**:
   - **Forward Translation**: User input (MikroTik DSL) ➔ Target Native Ruleset (`nftables`, `ufw`, `firewalld`, `OpenWrt`, `pfSense`, `Cisco`).
   - **Reverse Normalization**: Live backend rules ➔ Rendered in MikroTik DSL in the UI and CLI for uniform fleet-wide inspection.

---

## 2. Universal Rule Syntax & Grammar

### 2.1 Filter Rules (`/ip firewall filter`)
```text
/ip firewall filter add chain=<input|forward|output> action=<accept|drop|reject|jump> \
    [protocol=<tcp|udp|icmp|gre|esp|any>] \
    [src-address=<cidr|range|ip>] [dst-address=<cidr|range|ip>] \
    [src-port=<port|range>] [dst-port=<port|range>] \
    [in-interface=<iface>] [out-interface=<iface>] \
    [src-address-list=<name>] [dst-address-list=<name>] \
    [connection-state=<new|established|related|invalid>] \
    [comment="<label>"] [rollback=<minutes>]
```

### 2.2 NAT Rules (`/ip firewall nat`)
```text
/ip firewall nat add chain=<dstnat|srcnat> action=<dst-nat|src-nat|masquerade> \
    [protocol=<tcp|udp>] \
    [in-interface=<iface>] [out-interface=<iface>] \
    [src-address=<cidr>] [dst-address=<cidr>] \
    [dst-port=<port>] \
    [to-addresses=<ip>] [to-ports=<port>] \
    [comment="<label>"] [rollback=<minutes>]
```

### 2.3 Address Lists & Sets (`/ip firewall address-list`)
```text
/ip firewall address-list add list=<name> address=<cidr|range|ip> [comment="<label>"]
```

### 2.4 Structured JSON Representation (API / Plan Steps)
In addition to CLI text input, plan steps in `changes.py` and the Web UI use the structured JSON schema:
```json
{
  "type": "fw_rule_v2",
  "scope": "filter",
  "chain": "input",
  "action": "accept",
  "protocol": "tcp",
  "dst_port": "22",
  "src_address": "10.0.0.0/8",
  "in_interface": "mgmt0",
  "comment": "SSH from Management Subnet",
  "rollback": 10
}
```

---

## 3. Translation Matrix Across Target Backends

At deploy time, the StorageForge **RosTranspiler** inspects the target host's detected firewall engine and compiles the rule into the target's native format.

### Example Rule Scenario:
*Allow TCP port 22 from management subnet `10.0.0.0/8` on interface `mgmt0`, dropping all others by default.*

**Standardized User Input (MikroTik DSL):**
```text
/ip firewall filter add chain=input protocol=tcp dst-port=22 src-address=10.0.0.0/8 in-interface=mgmt0 action=accept comment="sf-ssh-mgmt"
```

### Backend Translation Outputs:

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                    USER INPUT (MIKROTIK STANDARD)                      │
 │ /ip firewall filter add chain=input protocol=tcp dst-port=22 ...       │
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
│ nftables │ │firewalld │     │   ufw    │   │  OpenWrt  │    │  pfSense  │
│ (Linux)  │ │ (RHEL)   │     │ (Ubuntu) │   │ (fw4/UCI) │    │  (BSD pf) │
└──────────┘ └──────────┘     └──────────┘   └───────────┘    └───────────┘
```

#### 1. Linux with `nftables`
StorageForge manages rules inside its isolated, high-priority table `inet storageforge_rules`:
```nft
table inet storageforge_rules {
    chain input {
        type filter hook input priority -150; policy accept;
        iifname "mgmt0" ip saddr 10.0.0.0/8 tcp dport 22 accept comment "sf-rule-sf-ssh-mgmt"
    }
}
```

#### 2. Linux with `firewalld`
Generates a persistent rich rule in the appropriate zone:
```bash
firewall-cmd --permanent --zone=trusted --add-rich-rule='rule family="ipv4" source address="10.0.0.0/8" port port="22" protocol="tcp" accept'
firewall-cmd --reload
```

#### 3. Linux with `ufw`
Generates numbered, commented UFW rules ahead of the default policies:
```bash
ufw route allow in on mgmt0 proto tcp from 10.0.0.0/8 to any port 22 comment "sf-rule-sf-ssh-mgmt"
```

#### 4. Linux with `iptables` / `DOCKER-USER`
If published container ports or Docker are active, rules routing traffic to containers are inserted into `DOCKER-USER` rather than `INPUT`:
```bash
iptables -I INPUT 1 -i mgmt0 -p tcp -s 10.0.0.0/8 --dport 22 -m comment --comment "sf-rule-sf-ssh-mgmt" -j ACCEPT
```

#### 5. OpenWrt (UCI & `fw4`)
Appends a declarative rule to `/etc/config/firewall` and reloads via `fw4 reload`:
```uci
config rule
    option name 'sf-ssh-mgmt'
    option src 'mgmt0'
    option proto 'tcp'
    option dest_port '22'
    option src_ip '10.0.0.0/8'
    option target 'ACCEPT'
```

#### 6. pfSense / OPNsense (`config.xml` & `pfctl`)
Injects a `<rule>` node into `<filter>` inside `/conf/config.xml` and triggers a background filter reload:
```xml
<rule>
    <id>sf-ssh-mgmt</id>
    <type>pass</type>
    <interface>opt0</interface>
    <ipprotocol>inet</ipprotocol>
    <protocol>tcp</protocol>
    <source>
        <network>10.0.0.0/8</network>
    </source>
    <destination>
        <any></any>
        <port>22</port>
    </destination>
    <descr><![CDATA[sf-ssh-mgmt]]></descr>
</rule>
```

#### 7. Cisco IOS / IOS-XE
Compiles into standard or extended named access lists:
```cisco
ip access-list extended STORAGEFORGE_MGMT_IN
 permit tcp 10.0.0.0 0.255.255.255 any eq 22
```

#### 8. Native MikroTik RouterOS
Applied directly via SSH CLI or RouterOS v7 REST API without syntax translation:
```routeros
/ip firewall filter add chain=input protocol=tcp dst-port=22 src-address=10.0.0.0/8 in-interface=mgmt0 action=accept comment="sf-ssh-mgmt"
```

---

## 4. NAT & Port-Forwarding Translation

Destination NAT (port-forwarding to internal servers/containers) follows the same universal MikroTik input:

### User Input:
```text
/ip firewall nat add chain=dstnat protocol=tcp dst-port=443 in-interface=wan action=dst-nat to-addresses=10.77.20.80 to-ports=443 comment="DMZ Web Forward"
```

### Backend Compilations:
- **MikroTik RouterOS**: Direct execution.
- **Linux `nftables`**:
  ```nft
  table inet storageforge_nat {
      chain prerouting {
          type nat hook prerouting priority dstnat; policy accept;
          iifname "wan" tcp dport 443 dnat to 10.77.20.80:443 comment "sf-nat-dmz-web"
      }
  }
  ```
- **Linux `iptables`**:
  ```bash
  iptables -t nat -A PREROUTING -i wan -p tcp --dport 443 -j DNAT --to-destination 10.77.20.80:443 -m comment --comment "sf-nat-dmz-web"
  ```
- **OpenWrt UCI**:
  ```uci
  config redirect
      option name 'DMZ Web Forward'
      option src 'wan'
      option proto 'tcp'
      option src_dport '443'
      option dest_ip '10.77.20.80'
      option dest_port '443'
      option target 'DNAT'
  ```
- **pfSense XML**:
  ```xml
  <rule>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <destination><port>443</port></destination>
      <target>10.77.20.80</target>
      <local-port>443</local-port>
      <descr><![CDATA[DMZ Web Forward]]></descr>
  </rule>
  ```

---

## 5. The Staging & Deployment Pipeline (Plan ➔ Report ➔ Apply)

The deployment pipeline strictly adheres to StorageForge's verification invariants:

```text
 ┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
 │ 1. USER      │ ──► │ 2. REPORT    │ ──► │ 3. APPLY     │ ──► │ 4. CONFIRM   │
 │ Input rule in│     │ Preview both │     │ Signed run   │     │ Rescan tests │
 │ MikroTik DSL │     │ DSL & Native │     │ with rollback│     │ match & drift│
 └──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
```

1. **Staging / Input**:
   - The user writes the rule in the UI or CLI in MikroTik syntax.
   - Preflight validator checks for parameter collisions, unresolvable interfaces, and syntax errors immediately.
2. **Report Stage (Dry-Run Preview)**:
   - The Report presents:
     - **Original Universal Rule**: `/ip firewall filter add ...`
     - **Translated Host Native Commands**: The exact `nft`, `firewall-cmd`, `ufw`, `uci`, or XML snippet that will be generated for that specific host.
     - **What-If Analysis (`whatif.py`)**: A diff indicating which paths are opened or blocked, and whether any public exposure changes.
3. **Apply Stage (Signed & Rollback Guarded)**:
   - Deploys the translated command using StorageForge's signed runner (`storageforge-run`).
   - Arms the rollback timer (`fw_arm` or platform-native commit-confirmed).
4. **Confirm Stage**:
   - Rescans the host, passes the updated reading into `reach.py`, and confirms the change took effect without breaking controller connectivity.

---

## 6. Implementation Components

1. **`storageforge_index/rostranspiler.py`**:
   - Grammar lexer & AST parser for `/ip firewall ...` commands.
   - Target backend emitters (`EmitNftables`, `EmitFirewalld`, `EmitUfw`, `EmitIptables`, `EmitOpenWrt`, `EmitPfSense`, `EmitCisco`).
2. **`storageforge_index/steps_infra.py`**:
   - Extends plan steps to accept `fw_rule_v2` with `dsl_rule` parameter.
   - Invokes `rostranspiler` during script generation to produce native commands.
3. **`storageforge_index/firewall.py`**:
   - Extends the normalization engine to reverse-translate live parsed rules into clean MikroTik DSL strings for fleet-wide display in the UI.
4. **Web UI & CLI**:
   - Firewall editor provides syntax highlighting, auto-completion for MikroTik syntax, and instant target translation previews.
