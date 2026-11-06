---
id: SF-64
status: open
severity: low
effort: S
area: Network language
verified: proven
tags: [finding, audit-2026-11-05]
found: 2026-11-05
---
# SF-64 The address checks of the network language accept IPv6 zone text and non-ASCII digits

**Low** · S · Network language · Proven · part of [[Audit 2026-11-05]]

## What exists
The header of `rostranspiler.py` says every value is checked against a pattern for its kind "because these become shell lines, XML and device commands". The checks for addresses (`_ip_ok`, `_cidr`, `_iface_addr`, `_ips`, `_cidrs`, `_range`) call `ipaddress.ip_address` or `ip_network` and accept what those accept. Since Python 3.9 they accept an IPv6 zone after a `%`, and the zone may be any text except `%` and `/`: spaces, `;`, `$`, backticks, `'`, `\`, `[`, `]`. Separately, `_int`, `_ports`, `_proto` and `_vlans` test with `str.isdigit()`, which is true for digits of other scripts (`²`, Arabic-Indic `١٢`).

Six of the ten emitters write these values with no quoting: the nftables, iptables, ufw, RouterOS and Cisco texts and the networkd files (firewalld, OpenWrt, NetworkManager and pfSense quote or escape them). Only RouterOS and Cisco text is sent to a device, one line at a time, by `devices.apply`; the others are shown to be copied.

## Evidence
`rostranspiler.py:33-58`, `:60-62`, `:119-135`, `:201` (the token pattern keeps a quoted value whole, so spaces survive in a zone). Ran `/tmp/sfaudit/a/p1.py` and a follow-up, with `/tmp/sfvenv/bin/python` 3.14; the project targets 3.10 and up and 3.13 in the image, both with zone support:
- `src-address=fe80::1%$(id)` parses and compiles to `ufw allow from fe80::1%$(id) to any` and `-A INPUT -s fe80::1%$(id) -j ACCEPT`
- `src-address="fe80::1%a;touch${IFS}x;id'"` parses and appears unquoted in the ufw line and the nftables rule
- `/ip dns set servers=fe80::1%a;:error` compiles to `/ip dns set servers=fe80::1%a;:error`, with the `;` unquoted, for RouterOS
- a value with a space stays in quotes for RouterOS (the parser folds a tab to a space first), and OpenWrt, firewalld and pfSense output was quoted or escaped
- `distance=²` gives `ip route 10.0.0.0 255.0.0.0 10.0.0.1 ²` for Cisco, and `vlan-id=٣` gives `vlan ٣`
- `/` is refused in a zone, which keeps a full path out of a RouterOS command; whether `;` plus a `[...]` or `:` command can do harm on a router was not tried, there was no router

## Why it matters
Nobody gains code execution on a host or router from this alone: the shell-capable outputs are texts a person reads and copies, and the two sent to devices go through `devices.apply`, a permission the catalog already calls root on the network. What it breaks is the stated guarantee: what a person reviews in a report is not guaranteed to be one command per statement, and a text a viewer builds with `/api/dsl/compile` and passes to a colleague can carry `$(...)` or `;` that looks like an address. The `from_model` path does not parse its own output, so it is not affected. Low.

## Suggested approach
Make one `_addr` helper: the value must match `[0-9A-Fa-f:.]+` (plus `/` and a number where a prefix is allowed, and `-` for a range), and then pass `ipaddress`. Use `re.fullmatch('[0-9]+')` instead of `isdigit()`. Add the lines `src-address=fe80::1%$(id)` and `distance=²` to the language's rejection tests, and add these emitters to the check that every generator keeps values as data.

## Done when
- [ ] A `%` in any address field, and a non-ASCII digit in any number field, are refused by `parse`
- [ ] A test holds both, and a property test checks that no emitted line has `;`, `$`, a backtick or a quote that was not in the validated alphabet
- [ ] The commit is written here
