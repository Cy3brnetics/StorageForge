---
id: GM-18
status: open
severity: medium
effort: S
area: "[[Docker, Nginx and Infrastructure]]"
tags: [finding, security, firewall, docker, gemini-audit]
found: 2026-10-29
---
# GM-18 Egress firewall fails open on bridge switch or invalid port and misses host INPUT chain

## Location
- `docker/egress-firewall.sh:2, 16-18, 24-36`

## Mechanics & Root Cause
1. **Docker Host Services (`INPUT` Chain) Are Completely Unprotected**:
   - `egress-firewall.sh` hooks `SF-EGRESS` into `DOCKER-USER` (`line 34`), which is only traversed by `FORWARD` packets routed through the host to other machines.
   - Connections from the `storageforge` or `proxy` containers to **any IP address belonging to the Docker host itself** (`sf0` gateway, host LAN IP, Tailscale IP) traverse the netfilter **`INPUT` chain**, bypassing `DOCKER-USER` and `SF-EGRESS` completely.
2. **Fail-Open Crash When Used Across Multiple Bridges (`sf0` and `sfdemo0`) or Invalid Ports**:
   ```sh
   while "$ipt" -D DOCKER-USER -i "$BRIDGE" ! -o "$BRIDGE" -j "$CHAIN" 2>/dev/null; do :; done
   "$ipt" -F "$CHAIN" 2>/dev/null || true
   "$ipt" -X "$CHAIN" 2>/dev/null || true
   [ "$MODE" = remove ] && { echo "$ipt: removed"; return 0; }
   "$ipt" -N "$CHAIN"
   ```
   - `CHAIN=SF-EGRESS` is hardcoded regardless of `BRIDGE`. If `egress-firewall.sh` is active on `sf0` and an operator runs `STORAGEFORGE_BRIDGE=sfdemo0 ./docker/egress-firewall.sh`, line 24 only removes the `sfdemo0` rule from `DOCKER-USER`, leaving the `sf0 -> SF-EGRESS` jump rule in place. Line 25 **flushes `SF-EGRESS`**, line 26 fails to delete `SF-EGRESS` (ignored via `|| true`), and line 28 (`iptables -N SF-EGRESS`) **aborts the script under `set -e`**, leaving `SF-EGRESS` completely empty (no `REJECT` rule) and silently disabling egress filtering for `sf0`!
   - Similarly, lines 16–18 only check that `$PORTS` consists of digits (`*[!0-9]*`), not `1 <= p <= 65535`. If `p=70000` is passed, lines 24–26 tear down the existing firewall before line 32 fails, leaving the firewall removed.

## Impact
Running `egress-firewall.sh` for a second bridge or with an out-of-range port tears down the existing egress firewall and fails open; services listening on the Docker host itself remain reachable on all ports from inside the container.

## Remediation
1. Scope the chain name per bridge: `CHAIN="SF-EGRESS-$BRIDGE"`.
2. Validate `[ "$p" -ge 1 ] && [ "$p" -le 65535 ]` before modifying any iptables rules.
3. Build or replace rules atomically (insert the jump rule or final `REJECT` before flushing old rules) and optionally restrict `-i "$BRIDGE"` on the `INPUT` chain.

## Done when
- [ ] `egress-firewall.sh` uses a per-bridge chain name, validates port ranges `1..65535`, and never fails open.
