---
tags: [audit, coverage, audit-2026-11-05]
date: 2026-11-05
---
# Coverage B: ransomware defense, signed scans, the receiving run of sends

Part of [[Audit 2026-11-05]]. One reader, working from `dev-expanded-networking` at `fb6b024`. Nothing in the application or the tests was changed. Probes ran on localhost under `/tmp/sfaudit/b/` with synthetic data and throwaway SQLite databases.

## Read fully
- `scansign.py`, `receiving.py`, `access.py`
- `security.py` (1 to 1664)
- `remote.py`: `Transport` (`argv`, `run`, `stream`, `check_stream`, `StderrTail`, `read_capped`, `child_env`)
- `scriptkit.py`: `RECEIVE_KIT` and `SEND_KIT` (the receiving and sending verbs)
- `permissions.py` from the rule table down; the new `/api/scans/signing` routes in `server.py`; every POST/PUT/DELETE of `routes_security.py` (decorators and the report route)

## Read in part
- `secscripts.py`: lines 35 to 772 (roots, fence, peer, measure, hold, release, quarantine, airgap, brake, sentinel, install). Not read: 773 to 1060 (relabel, tools, entropy, diff scan, clean room, compliance script).
- `secplus.py`: 51 to 200 (waivers, profiles, readings), 296 to 1125 (policies, freeze, evidence, identity, Falco, YARA, playbooks). Not read: 1 to 50 and 200 to 296 (plan staging), 1125 to 1519 (ban tiers, thresholds, noise, dashboards, timeline, tick).
- `jobscript.py`: the `--serve` dispatch only, to see how a send id reaches `recv_serve`.
- `scanner.py`, `gitrepos.py`, `runtimes/docker.py`: only where they call `check_stream`, to see what is used before the check.
- `docs/security.md`: the sends section.

## Not read
The tests (`test_scansign.py`, `test_security.py`, `test_sends.py`), apart from fixtures used to build probes; `routes_secplus.py`; the rest of `remote.py`; `deploy.py` internals (run lock, nonce); `hostkeys.py`.

## Probed
- `p1.py`: the real `WRAP` run under `/bin/sh` with a real ed25519 key; signed, replayed nonce, changed bytes, `SFSIG0` and missing mark with a pinned key, truncated signatures, TOFU, `require`, a forged `SFSIG0` line in the command's stderr.
- `p2.py`: the wrapper with no `sha256sum` or `shasum` and no key: it finished, printed `SFSIG0`, left no temporary folder.
- `p3.py`: a `brake_ran` report through `ingest_events` into holds, quarantine and the compliance `worm` check.
- `p4.py`: the real decoy-write loop against a symlink swap in a 0777 folder (150 of 150 swaps won).
- `p5.py`: row growth through the report path; the tick's prune.
- `p6.py`: first-use pinning on a host whose signer is its SSH host key.

## Found
[[SF-70 A host's own report can write holds and quarantines into the controller's records|SF-70]] Medium, [[SF-71 The decoy installer writes its files through a temporary name anyone in the folder can swap|SF-71]] Medium, [[SF-72 A send takes the stream's own properties and ownership, which the docs say it cannot|SF-72]] Medium (read), [[SF-73 A host with a report token can fill the controller's database|SF-73]] Medium, [[SF-74 Signed scans accept an unsigned or newly signed answer from a host that signed before|SF-74]] Low, [[SF-75 A malformed signature raises a raw error and the signing switch reads any text as on|SF-75]] Low.

## Ruled out
- **Nonce:** 16 random bytes from `secrets`, new per command, checked by equality against the signed message; a replay under another nonce is refused (probe case 3). Changed bytes refused (case 4). A forged `SFSIG0` in the payload's stderr does not matter: the wrapper's mark is last (case 8).
- **Wrapper:** the fifo and files live in a `mktemp -d` folder (mode 0700) owned by the scan account; no other account can race it. The script and the nonce reach `sh` as data (`shlex.quote`); key paths are quoted. A failure of `mktemp`, the hash tool or the key falls back to an `SFSIG0` line, never to a false `SFSIG1`. A killed ssh can leave `/tmp/sfsig.*` behind (no trap): hygiene only.
- **Streams:** rows are staged and applied only after `check_stream` (`end` message), so a bad stream leaves the index as it was; the git and Docker surveys check before parsing.
- **Routes:** `GET /api/scans/signing` is `scans.view` and returns fingerprints only; `PUT` and `DELETE` are `keys.manage` with a fresh password; an address with a slash matches no rule and falls to default-deny. No secret is stored or returned. The scan signing key's public half is pinned over the confirmed host key.
- **Security routes:** every state-changing route listed has `login_required` and `password_confirmed`; the report route authenticates by token hash with `compare_digest`, and the token decides the host.
- **Receiving run:** the whole forced-command line is matched against a strict pattern before it is split, the conf is read line by line and never sourced, ids and names are validated, the nonce is recorded `noclobber`, retention and paths come from the conf, and keys expire. No injection found. What remains is the stream itself ([[SF-72 A send takes the stream's own properties and ownership, which the docs say it cannot|SF-72]]).
- **Regexes:** the ones in `security.py`, `secplus.py` and `receiving.py` are linear (bounded classes, no nested quantifiers); no timing probe was needed.

## Not reached
The compliance, relabel, entropy and clean-room scripts in `secscripts.py`; the second half of `secplus.py` (ban tiers, dashboards, timeline); `routes_secplus.py`; the tests. Nothing about sends or the sentinel was run on a real host, and ZFS and btrfs behaviour in SF-72 is from the documented tools, not from a lab run.
