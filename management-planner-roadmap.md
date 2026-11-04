# Management Planner: One Place to Plan the Fleet and Its Network

The plan for `/manage`, which the [Expanded Networking Roadmap](expanded-networking-roadmap.md) needed once routers joined hosts.

Status: **built**, and through the KVM lab (tier 12). What's left is under [Later](#later).

## Why a second planner

`/planner` designs one host's storage, and it stays that: disks, pools, mounts, and a plan for getting there. It has no idea what a router is, and bending it to fit would make both worse.

What the expanded features need is different in kind. A network change crosses machines, it can cut off the thing making it, and the same intent has to work on six firewall syntaxes. So `/manage` is a page of its own that starts from the fleet rather than from one host, and links to `/planner` and the Map instead of redoing them.

## What it has

| View | What it's for |
| :--- | :--- |
| **Fleet** | Every host and device: what it runs, whether its firewall has been read, how many forwards it has, what's exposed. Changes waiting on a timer, Telnet warnings and traffic anomalies come first |
| **Devices** | Add a device. Read it. See its interfaces, routes, firewall and what it knows about, and its configuration in the one language |
| **Compose** | Write once in the network language, pick a machine, see what it becomes on that machine, try a path against it, then report and apply |
| **Changes** | What was reported, applied, confirmed and rolled back, and by whom |
| **Traffic** | Rates per interface, and what stands out. Off until turned on |
| **Scanner** | The way to the Scan tab, which sits beside the Map because that's where someone is looking at the network |

## How a change goes

Plan → Report → Apply, as everywhere else, with the same refusal: nothing moves that hasn't been reported.

1. **Write.** Each value is checked as it's typed, against a pattern for its kind. A target can't be told to run something by way of a comment or an interface name.
2. **See.** What it becomes on this machine's own syntax, and any line that machine can't express. Those lines block an apply: what was written and what happens must not differ silently.
3. **Try a path.** The path query, before and after, from the index. Nothing is sent.
4. **Report.** Saved as a change. It works out whether this would block the SSH that StorageForge comes in on.
5. **Apply.** Needs the password again, and `devices.apply`. The way back goes on the device before the change does.
6. **Settle.** StorageForge connects again from scratch. If the device answers, the change stays and the timer is removed. If not, it waits to see the device put itself back. Someone who wants to look first can hold the confirm for themselves.

The device holds the timer rather than StorageForge, because a change that severs StorageForge is exactly when StorageForge can't be relied on to undo it. It works the same if StorageForge crashes.

A Linux host doesn't take this route. Its rules become `fw-rule` steps in Changes, where signed deploys, checks and rollbacks already exist. Compose says which of the lines came across and which didn't.

## Decisions worth keeping

- **A device is a row in `hosts`.** The map, reach, exposure and the fleet then work without knowing. It's refused where a host's abilities are assumed: deploy access says plainly that it's a device.
- **Reading and changing are separate accounts.** The `scan` binding reads, the `deploy` binding changes. On RouterOS the read account can't write, and the router itself enforces it: tier 12 checks by trying.
- **Who may do what.** `devices.view` and `netscan.view` for viewers, `devices.manage` to add and read, `devices.apply` to change. `devices.apply` and `netscan.run` are marked high risk.
- **No REST adapters.** SSH reads everything on all four platforms. A second way in is a second thing to secure, for no new fact.

## Later

- Moving a rule to a position. RouterOS appends, and a rule below a chain's final drop does nothing. The what-if shows that honestly, but the language has no `place-before` yet.
- Drawing scan results on the Map as placeholders. The Scan tab links to the Map, but they're separate drawings.
- Scheduled reports of what the scanner found new, through the existing alert channels.
- A real pfSense and Cisco, if an image can be had. See [what has been tested on what](docs/network-devices.md#what-has-been-tested-on-what).
