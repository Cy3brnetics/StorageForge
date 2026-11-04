# Network devices

StorageForge reads routers, switches and firewalls and can change them, with a timer on the device that undoes the change if StorageForge loses it. A device shows up on the [map](infrastructure-map.md), in path queries and in exposure, like any host.

## What has been tested on what

| Platform | How it's read | Tested on |
| :--- | :--- | :--- |
| MikroTik RouterOS 7 | SSH, one command at a time | **KVM lab**, a real CHR 7.25 |
| MikroTik RouterOS 6, or 7 before 7.13 | The same, in the older `print terse` | Unit tests only, against its format |
| OpenWrt | SSH and a POSIX shell: `ubus`, `uci`, `nft` | **KVM lab**, a real 25.12 |
| pfSense, OPNsense | SSH and a POSIX shell: `config.xml`, `pfctl` | Unit tests only. There's no free image the lab can install unattended |
| Cisco IOS, IOS-XE | SSH terminal or Telnet, `show` commands | Unit tests only. There's no free image. **It has never met a real device: check what it reports before you rely on it** |

A real device of an untested kind may well behave differently. Start with one you can reach by another route.

## The management planner

`/manage` lists every host and device, and is where a change is written. See [the roadmap](../management-planner-roadmap.md) for why it's separate from the [storage planner](planner.md). It's linked from **Manage** in the top bar.

## Adding a device

1. **Give it an account.** Reading needs far less than changing, so make two where the device can:

   ```routeros
   /user/group/add name=sf-read policy=ssh,read,test,!local,!telnet,!ftp,!reboot,!write,!policy,!winbox,!password,!web,!sniff,!sensitive,!api,!romon,!rest-api
   /user/add name=scan group=sf-read
   ```

2. **Bind keys** in **Keys**, as for a host: one to its address with the `scan` action, and one with `deploy` for an account that can change it. OpenWrt's firewall and `ubus` need root, so both are root there.
3. **Add it** under **Devices**, with its name, address and system.
4. **Read now.** After that it's read every hour, or every 5 minutes with traffic monitoring on.

**Which interface is the WAN** decides what counts as exposed to the internet. StorageForge takes what you say when adding the device, then what the device says (a zone that masquerades, on OpenWrt), then wherever its default route goes.

### With a password

Telnet has no keys, and some old gear has none either. Store the password as a credential: `POST /api/devices/credentials`. It's sealed in the vault like a key, and nothing returns it.

RouterOS refuses a password for an account that has an SSH key, so use an account with none, or a key and no credential.

Before a password goes over SSH, someone has to compare the device's host key: `POST /api/devices/<name>/hostkey`. Telnet has no way to prove who answered, and **Fleet** warns about any device managed over it, because everything including the password crosses the network in the clear.

## The network language

One syntax for every target: RouterOS's. Under **Compose**, it shows what you wrote as the machine's own syntax as you type. It covers bridges, VLANs, bonds, addresses, routes, DNS, DHCP, WireGuard, filter rules, NAT and address lists.

```routeros
/ip firewall filter add chain=forward in-interface=ether3 out-interface=ether4 protocol=tcp dst-port=80 action=accept comment="LAN to web"
/ip firewall nat add chain=dstnat in-interface=ether2 protocol=tcp dst-port=443 action=dst-nat to-addresses=10.77.20.80 to-ports=443
```

| Target | Takes |
| :--- | :--- |
| RouterOS | Everything, as written |
| nftables | Firewall, with address lists as sets, in its own table |
| iptables | Firewall, for `iptables-restore --noflush`. Address lists need an ipset first, so they're listed as left out |
| firewalld | What comes in, through rich rules, forward ports and masquerade |
| ufw | Rules with a verdict, addresses and a port. No NAT |
| OpenWrt | Firewall by zone, network and DHCP, through `uci` |
| pfSense | Filter, port forwards, aliases, VLANs, routes and DNS, as `config.xml` sections |
| Cisco | ACLs on interfaces, static NAT, routes, addresses, VLANs and DHCP pools |
| networkd, NetworkManager | Bridges, VLANs, bonds, addresses and more. Firewall goes through a firewall target |

Anything a target can't express is **listed, not dropped**, and a device won't apply it. **Load what it runs** does the reverse: whatever a machine runs, in this syntax. That's for reading, and a rule that couldn't be fully followed says so in a comment.

RouterOS appends. A rule added below a chain's final `drop` never matches, on the router or in a what-if, which shows you that rather than what you meant.

Values are checked against a pattern for their kind before anything else sees them, because they become shell lines, XML and device commands.

## Paths and exposure

The [path query](infrastructure-map.md) now walks router by router: each router's own routes say where next, and each one's forward rules decide. It names the rule that stops it, and goes through a port forward to where it lands. A router that hasn't been read is a blind spot, and can only make the answer less certain.

**Exposure** counts forwards. A listener on a LAN host that a router forwards to from its WAN shows as reachable from any address, naming the router and the forward. A forward the router's own rules drop exposes nothing.

## Changing a device

Under **Compose**, on a device: **Report**, then **Apply**.

1. The report saves exactly what will happen, and works out whether it blocks the SSH StorageForge comes in on.
2. The apply needs your password again. **The way back goes on the device first:**

   | Platform | The way back |
   | :--- | :--- |
   | RouterOS | A backup, and a scheduler that loads it when the time is up, which reboots the router |
   | OpenWrt | A copy of `/etc/config`, and a background shell that restores it and reloads |
   | pfSense, OPNsense | A copy of `config.xml`, and a background shell that restores it and reloads the filter |
   | Cisco | `configure terminal revert timer` |

3. StorageForge connects again from scratch. If the device answers, the change is kept and the timer is removed. If not, it waits and watches the device come back.

Tick **I will confirm it myself** to look around first. The timer is 60 seconds to an hour, and defaults to 3 minutes. A RouterOS rollback reboots the router, so allow for that.

**A Linux host** doesn't go this way. Its plain firewall rules become `fw-rule` steps in **Changes**, with their checks, signed deploy and rollback.

## The network scanner

Off until someone turns it on. With it off, nothing in StorageForge sends a packet to find out what exists, and lab tier 12 checks that with a capture.

Open **Scan**, next to **Map**. Name your networks, turn it on, and **Scan now**, or set it to run every so many hours.

- It's an nmap connect scan (`-sT`) of the top ports. It needs no extra privileges, and the container keeps none.
- Only private networks, no wider than a /20. It won't scan the internet.
- Each machine it finds links back: a host to its **Config** and **Network** pages and the map, a device to its page. Anything StorageForge doesn't manage is marked, with a way to add it.
- It marks what's new since the scan before, and lists what's gone.

Scanning can trip intrusion detection and wake up fragile equipment. Do it on networks you run.

## Traffic monitoring

Off until turned on, under **Traffic**. It sends nothing: each number is a device's own counter, from an ordinary reading.

It stores rates per interface for 14 days, and points out an interface moving far above its own normal (it needs about an hour of history first), and errors or drops where there were none. A counter that goes backwards means a reboot, and that interval is skipped. Linux hosts aren't included yet: this covers devices only.
