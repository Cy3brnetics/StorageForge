---
id: SF-62
status: done
severity: medium
effort: S
area: Network devices
verified: proven
tags: [finding, audit-2026-11-05]
found: 2026-11-05
---
# SF-62 An OpenWrt reading keeps WireGuard keys in the clear and a viewer can read them

**Medium** · S · Network devices · Proven · part of [[Audit 2026-11-05]]

## What exists
Reading an OpenWrt router runs `uci show network` and stores the whole output as the device's `config`, in the `device` measurement in the database. `GET /api/devices/<name>` returns that `config` to any account with `security.view`, which the built-in `viewer` role holds. On OpenWrt, `uci show network` prints a WireGuard interface's `private_key` and each peer's `preshared_key` in plain text. The Cisco reader runs its config through `cisco.strip_secrets` first, and the RouterOS and pfSense readers store `config: None`; OpenWrt is the one that stores the text as it came.

## Evidence
`openwrt.py:17` (the script line `uci show network`) and `openwrt.py:193` (`'config': s.get('uci_network')`), against `cisco.py:21-23` and `cisco.py:325` (`strip_secrets(t['running'])`). The route: `routes_network.py:157-168`, which drops `config` only when the caller lacks `security.view`.

Ran `/tmp/sfaudit/a/probe_api.py` (`test_a_openwrt_config_secret_to_viewer`), throwaway database, synthetic values: fed `openwrt.parse` a reading whose `@@uci_network` section holds `network.wg0.private_key='SYNTHETICPRIVATEKEY...'` and a peer `preshared_key='SYNTHETICPSK...'`, stored it with `netdevice.store`, signed in as a `viewer` and called `GET /api/devices/wrt`. Both values were in the response body, and one `security_measurements` row for the device held them. `/api/fleet` did not carry them.

## Why it matters
A viewer, the lowest role that sees devices, can read a router's WireGuard private key and pre-shared keys, and so impersonate the router to its peers or decrypt captured traffic. The same text sits unencrypted in the database (whether the backup tables carry that measurement was not checked), which breaks the promise that secrets never touch disk in plaintext. It is Medium by the scale (secrets exposed to a lesser account); it only applies to OpenWrt routers that run WireGuard in UCI.

## Suggested approach
Do what Cisco does: pass `uci_network` through a scrubber before it is stored, replacing the value of any option whose name matches `private_key`, `preshared_key`, `key`, `password` or `psk` with `<removed>`. Add the same call for any other `uci show` section added later. Existing rows keep the old text, so add a small migration (or a one-off in the next read) that rewrites stored `config` values. A test feeds a reading with both options and checks that neither the stored row nor the route holds them.

## Done when
- [x] No stored or returned `config` holds a `private_key`, `preshared_key` or password value for any platform
- [x] Rows stored before the fix are scrubbed
- [x] A test in `test_routers.py` holds it, signed in as a viewer
- [x] The commit is written here

## Fixed
2026-11-06, in `3e70456`. OpenWrt `uci show network` is stored without private or pre-shared keys or any option named key, psk, password, passphrase, secret or token. Rows stored before are cleaned when read. Unit-tested, with the test seen to fail on the old code. Not lab-tested.
