# Test report, 2026-11-16 and 17

What was tested, how it was run, what broke and what changed, from the first timing of the suite to a server answering 128 clients at once on two million files. It includes the afternoon the testing took the workstation down with it.

Branch `tests/light-medium-heavy`, from the 0.6.0 roadmap commit `7d3c96c`. Seventeen commits, `4fd6cff` to `2bac1bf`. Nothing pushed.

## Contents

1. [Where it started](#1-where-it-started)
2. [Three blocks, and running them in parallel](#2-three-blocks-and-running-them-in-parallel)
3. [Random tests, and the bugs they found](#3-random-tests-and-the-bugs-they-found)
4. [Code no test reached](#4-code-no-test-reached)
5. [The 3-disk raidz](#5-the-3-disk-raidz)
6. [The browser test that failed one time in ten, and the crash](#6-the-browser-test-that-failed-one-time-in-ten-and-the-crash)
7. [Stress: a real server until it breaks](#7-stress-a-real-server-until-it-breaks)
8. [Stress on PostgreSQL](#8-stress-on-postgresql)
9. [How to run all of it again](#9-how-to-run-all-of-it-again)
10. [Still open](#10-still-open)

## 1. Where it started

The whole unit suite ran in one process with `python -m unittest discover -s tests`. On the owner's workstation (24 cores, 31 GiB, CachyOS), in a fresh virtual environment:

| Tests | Time | Failed | Skipped |
| ---: | ---: | ---: | ---: |
| 1,859 | 941 s | 0 | 9 |

The 9 skips were all for something this machine lacks: `shellcheck` (3), `puppet` and `terraform` on `PATH`, `CAP_NET_ADMIN` for `nft -c`, root for `chroot`, `dash`, and a machine where scan access had been set up.

Timing every test showed where the 16 minutes went:

| Per test | Tests | Their total |
| :--- | ---: | ---: |
| under 0.1 s | 1,067 | 23 s |
| under 0.5 s | 1,582 | 155 s |
| under 3 s | 1,770 | 355 s |
| all | 1,859 | 926 s |

So 89 tests took 60 % of the time. The slowest classes were key rotation (6 tests, 99 s), the browser smoke tests (95 tests, 94 s), the decoys (13 tests, 79 s) and the real sentinel (10 tests, 72 s).

## 2. Three blocks, and running them in parallel

Commit `4fd6cff`. `tests/blocks.py` names each class that is medium or heavy, and anything it doesn't name is light. The blocks were drawn from the timings and from what each class needs:

| Block | What its tests need | Tests | One core | `-j 12` |
| :--- | :--- | ---: | ---: | ---: |
| light | Python and a temporary database | 1,223 | 83 s | 13 s |
| medium | bash, telnet and console sessions, the scheduler's runner, longer API walks | 227 | 102 s | |
| heavy | Chromium, sshd, Docker, real waits, scans end to end | 409 | 741 s | |
| all | | 1,859 | 941 s | 125 s |

`tests/run.py` runs one or more blocks. With `-j N` it hands out whole classes to N worker processes, so each class keeps its `setUpClass` and its order. Run on one core, it lists any light test slower than 1.5 s and any medium test slower than 6 s. `test_blocks.py` fails if a class named in `blocks.py` no longer exists, so a renamed class can't fall into light without anyone noticing.

CI (`.forgejo` and `.github`) now runs light, medium, heavy and the deep random tests as four steps on each database. Each step runs even if an earlier one failed, so a red step says which block broke. zizmor found nothing in the changed workflows.

## 3. Random tests, and the bugs they found

Six `test_props_*.py` modules use Hypothesis (the new `test` extra). Each states what must hold for any input of a kind. They run 60 fixed examples in light, so a red light run means something changed, and 2,000 from a fresh seed with `run.py deep`. Every bug they found is also pinned as a controlled test.

| Module | What must hold | What it found | Commit |
| :--- | :--- | :--- | :--- |
| `test_props_netlang` | The network language reads back what it accepts; every target emits every statement or says why not; no accepted value holds a shell character; a comment reaches `ufw` as one argument | **Comments lost their spacing**: two spaces became one, a no-break space became a space. **A route, routing rule or DHCP network took a negated or ranged address**, then OpenWrt and Cisco threw and the other targets wrote it as it was (`Destination=!::/0`). **A redirect read from a firewall was written back as a `dst-nat` with no address**, which the language refuses | `8b39384` |
| `test_props_search` | Every road of a search (extension, exact name, prefix, trigram index, PostgreSQL regex) finds what `fnmatch` finds, written through the scanner's own path | **`[!x]` found the opposite on SQLite**, whose GLOB negates with `^`. **`[^x]` was a negation on PostgreSQL** where a shell reads "`^` or `x`". **`[b-a]` was a database error on PostgreSQL** where it should find nothing | `a415dfd` |
| `test_props_parsers` | Every parser of host and device output reads any text or refuses it with a `ValueError`; real fixtures damaged line by line | **One odd network section lost a host's whole network reading.** **A findmnt printing `null` failed the scan** before the mountinfo fallback. **An unreadable size in `df` stopped every row after it.** **A damaged RouterOS or OpenWrt reading lost the device's reading.** pfSense and nmap XML that didn't parse escaped as `ParseError` | `fc1735d` |
| `test_props_capacity` | Every byte of raw space is counted once; no pool survives losing all its disks; more disks never give less; more permissions never allow less | **A one-disk mirror said it survived one failure**, a two-disk raid6 two; an md array short of members showed a negative reserve | `98822af` |
| `test_props_scripts` | A hostile value built from every piece of shell syntax is data in every send, task and plan script, or is refused | Nothing: 400 values checked as text, 60 run for real. Its first, naive quote check gave false alarms; it was replaced with a scanner that follows bash's quoting | `4fd6cff` |
| `test_props_folders` | The fast system-folder test agrees with the rules one by one, and follows the lists when a test changes them | Nothing: written with the fast version (section 7). Its first version was compiled once at import, and `test_feature_routes`, which changes `NOISE_DIRS` while it runs, caught that in a full run | `b8fd1e6` |

## 4. Code no test reached

A branch-coverage run of the whole suite gave **85 %** (29,795 statements, 3,710 missed). The lowest modules were `keyinstall` 51 %, `steps_md` 61 %, `console` 64 %, `access` 64 %, `netdevice` 67 %, `deploy` 68 % and `preflight` 69 %. New tests went where the risk was:

| Area | What the tests do | What they found | Commit |
| :--- | :--- | :--- | :--- |
| Installing a key with a password | A stand-in `ssh-copy-id` asks the real askpass helper, as ssh does. The password reaches ssh only through askpass, never argv or a file; the scratch folder is gone after success, refusal or a hang | Nothing wrong | `dce9e98` |
| The md-array step | Its plan checks, and its Ansible export run against a stand-in `mdadm` and `blkid` that answer as the real ones do | **The export failed on every real host, twice over.** It put `--` before the devices, which mdadm 4.3 and 4.6 count as a device (checked in Alpine 3 and Alpine edge containers). And under `set -e` it ended silently on a blank disk, where `blkid -p` exits 2. The test fails on the old code | `ab6a4b2` |
| The check before a deploy | Each fact and its finding, the probe read line by line, scan facts, SSH login methods against a stand-in `ssh`, blockers by kind of deploy, both report paths | **A probe printing `clock=x` crashed the host check**, and every deploy's check of its blockers with it. `'١٢٣'` was read as 123 | `9b08780` |

## 5. The 3-disk raidz

The planner and the zfs-pool step refused a raidz below parity plus two disks, though `zpool create` takes parity plus one, and `capacity.py` already counted those pools. Both now allow a raidz2 of three disks, a raidz1 of two and a raidz3 of four. The planner notes that the narrowest raidz holds one drive of data, as a mirror of the same width does. Three new vectors hold the planner's JavaScript and `capacity.py` to the same figures. Commit `abd77a1`.

## 6. The browser test that failed one time in ten, and the crash

### The flake

Re-running everything on both databases with `run.py all -j 12`:

| Database | Ran | Failed | Skipped |
| :--- | ---: | ---: | ---: |
| PostgreSQL | 1,925 | 0 | 88 (the known SQLite-only ones) |
| SQLite | 1,925 | 1 | 9 |

The SQLite failure was in `test_browser_logs.BrowserLogs`: it waited 30 s for the first host-log line and timed out. Run alone it passed. It failed again in 3 of about 10 runs while the machine was busy with the PostgreSQL suite. A test that fails under load and passes alone is a finding, by the rule `run.py` itself states, so it went back to the owner as "not understood" rather than getting a longer timeout.

Then it was chased. Comparing the branch with the original commit `7d3c96c` on a quiet machine, both passed 6 of 6. Under 24 CPU-burning loops, both passed 5 of 5. A probe that saved the page whenever the wait timed out caught one failure. The page had been sent to `#/topo/hostlogs`, reloaded, and had come back up on `#/topo/details`, without asking the server for a single log line. Its start-up had decided the link couldn't be followed.

### The crash

To catch it again with more detail, the load went up, all of it on the owner's workstation at once:

- a loop running the heavy browser smoke tests with 8 to 10 workers, each driving Chromium;
- a loop running the security tests with 6 workers;
- 16 more shell loops spinning a core each, on top;
- and the instrumented probe, run again and again.

The load average reached about 30. Then the session ended mid-command, and when it came back the machine had rebooted. The kernel had gone from 7.3.1 to 7.3.4, and `/tmp`, with the test environment in it, was gone.

The previous boot's journal showed no out-of-memory kill and no kernel panic. What it showed, up to 19:10:49, was the NVIDIA driver's userspace at 620.70 refusing to talk to a kernel module still at 615.78: a system update had been installed underneath the work and was waiting for a reboot. So the log can't say whether the load froze the desktop or the half-updated graphics driver did. But piling a dozen browsers and sixteen busy loops onto someone's daily machine was the choice that mattered, and the owner put it well: *"congrats you tested how well it crashes a machine lol"*.

What changed after:

- **A standing rule** (in the assistant's memory for this project): no busy loops or load generators on this machine; the suite at most `-j 6`, one suite at a time.
- **`tests/ci.sh` runs at most 6 classes at once** unless `SF_TEST_JOBS` says otherwise. One per core on a workstation runs a dozen browsers at once.
- **The cause found without the load.** `test_browser_smoke` and `test_browser_vms` both wait for `html[data-route-ready]`, the marker the router sets once the page follows its address, with a comment saying why. `test_browser_logs` didn't: it moved and reloaded the page while its first start-up was still running. It waits now, and if a link is ever not followed it fails at once with the address it ended on, not after 30 s. That is the likely cause, not a proven one, because the failure was never reproduced on demand (`c3338f3`).

The owner then asked for the stress testing again "until it don't crash my pc", and then said what was actually wanted: *"full load and then the storage forge adapts to it some how. The goal is to break it and fix it over and over again with the stress tests."* That is section 7. The load there goes to StorageForge, and the machine is protected by a watchdog that kills the server, not the desktop, if memory runs short. It never came near: at least 16.8 GiB stayed free throughout.

## 7. Stress: a real server until it breaks

### How it runs

`tests/stress/seed.py` writes a fleet through the scanner's own path (`stage_insert` and `apply_diff`): 20 hosts of 100,000 files, a deep folder tree, sizes, ages and checksums that make duplicates and cold data, and 2,000 host-log lines each. On SQLite that takes 47 s and makes a 0.74 GiB database.

`tests/stress/hammer.py` starts `storageforge-index serve` in a temporary folder of its own (its own database, data folder and home, so a real install is never touched). It times the cold start, then runs stages of 30 to 40 s with 8, 32, 64, 128, 256 and 512 clients asking with no pause, across 21 routes. A client waits out a `503` with `Retry-After`, as the page does. The routes fall in three kinds, each with its own limit:

| Kind | Routes | Limit (p99) |
| :--- | :--- | :--- |
| light | hosts, map, graph, canvas, capacity, host logs and their counts, file changes, browse, the quick folder listing | 2 s |
| queued | search (three ways), duplicate files (one host and all), host-log export | 30 s |
| folder analyses | the file map (one host and all), twin folders, cold folders | 90 s |

A stage also breaks at 5 % errors, at 6 GiB for the server, or when the machine has under 4 GiB available, in which case the server is killed. Other options: `--only light|heavy` runs one kind of route, `--profile` starts the server under py-spy (attaching to another process needs root here), and `--writer N` lands a scan of a new host every N seconds during the stages.

### The rounds

Two million files, SQLite unless it says otherwise. "Broke at" is the first stage that broke a limit.

| Round | Broke at | What broke | What changed |
| :--- | :--- | :--- | :--- |
| 1 | 8 clients | The file map rebuilt for every request: the server reached 5.7 GiB and requests ran past 30 s | One build per analysis; anyone else asking waits for that one |
| 2 | 8 | Memory fixed (1.9 GiB), but the request that started a build held its thread for all of it | Built off the request; it waits 20 s, then `503` |
| 3 | 8 | The file map's twin folders waited for the slot the file map's own build held: a deadlock | An analysis inside a build is made on its slot |
| 4 | 8 | Every host's twin folders redid the fleet-wide comparison, 3.5 s each | Made once per folder index, held by identity, filtered per host |
| 5 | 8 | The cold start (12.4 s) counted against stage 1 | Cold start timed on its own, as `serve()` warms it once |
| 6 | 32 | `_noise()`, the system-folder test, was 3 s of a host's 7 s file map | One regular expression. Its first version was compiled at import and missed a test that changes the list; it is now built from the lists as they are |
| 7 | 8 | Waits of 2 s held server threads | One build at a time, waits of 2 s, the page retries 20 times |
| 8 | 32 | One limit for everything mixed queued routes with light ones | Light, queued and analyses judged apart; a 503 still in flight when a stage ends counts as cut off, not as an error |
| 8b | 32 | Light routes alone: 9.3 s at p99, 4.6 GiB, 17 answers a second | Per-request SQLite cache 16 MiB instead of 256; searches and exports four at a time |
| 8c | 32 | Requests waiting for an expensive slot held threads too | The wait is 0.25 s, then come back in 1 s |
| 9 | 128 | Waitress took 100 connections and kept idle ones 120 s: the 101st waited unanswered | 500 connections, idle ones closed after 30 s |
| 10 | 64 | The folder analyses were Python in the web's process, sharing its interpreter with every request | `folderwork.py`: a worker process of their own, replaced if it dies. The folder index (2 GiB) is the worker's memory |
| 11 | 256 | A request waited 2 s for an analysis, holding a thread | 0.25 s under `serve()`, then come back in 2 s; at most 32 builds waiting |
| 12, `--writer 10` | 64 | Each finished scan emptied the analysis cache, and nothing was kept mid-scan: analyses never settled, 5 % gave up | The last result is answered at once, marked `stale`, while one build of the new one runs; during a scan it stands and nothing is built |

Two side findings along the way:

- **The mistake in round 10.** The worker module was first written as `analysis.py`, which already existed (297 lines of report checks). It was caught at once and restored from git before any commit, and the module became `folderwork.py`.
- **A guard `__main__.py` lacked.** A spawned worker imports the main module again. The console script is guarded; `__main__.py` was not, so under `python -m storageforge_index serve` the worker would have run the CLI a second time. It is guarded now.
- **GM-25 came back, briefly.** The first version of round 12's fix served a result made mid-scan as current once the scan ended. `test_platform`'s test for GM-25 caught it in the full run. A result made mid-scan is now only ever answered as stale.

### Where SQLite stands

| Clients | Light p99 | Queued p99 | Analyses p99 | Answers a second | Errors | Web memory |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 8 | 0.02 s | 1.4 s | 9.0 s | 9 | 0 | 1.1 GiB |
| 32 | 0.30 s | 4.2 s | 20.3 s | 17 | 0 | 1.8 GiB |
| 64 | 0.65 s | 4.6 s | 30.3 s | 22 | 0 | 1.9 GiB |
| 128 | 1.62 s | 14.0 s | 30.0 s | 33 | 0 | 2.3 GiB |
| 256 | 3.79 s | 23.9 s | 33.3 s | 39 | 0 | 2.4 GiB |

256 clients is the ceiling of one Python process, about 40 answers a second. Going further needs more than one web process, which the in-memory caches and sessions don't allow yet. With a scan landing every 10 s, every stage up to 128 clients passes with no errors, and each scan lands in about 1.1 s.

## 8. Stress on PostgreSQL

PostgreSQL 16 (alpine) in Docker with default settings, the same 20 × 100,000 files through the same scanner path.

**Round 1** passed up to 128 clients, but one search at 32 answered **500**: `could not resize shared memory segment ... No space left on device`, in a parallel worker. Docker gives a container 64 MiB of `/dev/shm`, and parallel queries ran out of it. Now an error of PostgreSQL's class 53 (out of memory, shared memory, disk or connections), or SQLite's busy lock, answers `503` and the page waits it out, and `docs/database.md` says to give the container `--shm-size=256m`.

**Round 2**, with scans landing every 10 s: at 64 clients, 4 of 1,094 requests gave up. They were analyses made for the first time, and on PostgreSQL those take longer than the page's 20 retries. The page now waits up to 40, about 90 s. **Round 3**: no errors up to 128 clients.

| | SQLite | PostgreSQL |
| :--- | :--- | :--- |
| writing the fleet | 47 s (0.9 s a host) | 349 s (10.7 s a host) |
| a scan of 20,000 files landing under load | 1.1 s | 4 to 8 s |
| database size | 0.74 GiB | 1.44 GiB |
| 128 clients: light / queued p99 | 1.6 s / 14 s | 1.75 s / 7.7 s |
| answers a second at 256 | 39 | 51 |
| web process memory | about 2.5 GiB | 0.2 to 0.3 GiB |
| scans every 10 s, up to 128 clients | no errors | no errors |

Why PostgreSQL writes so much slower, from `EXPLAIN (ANALYZE, BUFFERS)` inside `apply_diff`: of 10.7 s a host, **3.9 s is foreign-key checks**, one row at a time:

- `file_records → mounts`: 1.3 s;
- `file_records → directories`: 1.5 s;
- `directories → mounts`: 1.1 s.

The checks can't fail, because each new row was joined to its parent in the same transaction. Most of the rest is maintaining `file_records`' twelve indexes. The trigram indexes account for only 1.4 s, and raising `gin_pending_list_limit`, `work_mem` and `maintenance_work_mem` changed nothing. Dropping or reshaping the foreign keys is a migration, left to the owner.

## 9. How to run all of it again

From `storageforge-indexer`:

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[postgres,test]" playwright coverage
.venv/bin/python -m playwright install chromium

# the unit suite
.venv/bin/python tests/run.py                       # light, about 13 s on 6+ cores
.venv/bin/python tests/run.py all -j 6              # everything, about 3 minutes here
.venv/bin/python tests/run.py deep -j 6             # the random tests with 2,000 examples each
.venv/bin/python tests/run.py --list heavy          # what is in a block

# on PostgreSQL too
docker run -d --rm --name sf-test-pg --shm-size=256m -e POSTGRES_USER=sf -e POSTGRES_PASSWORD=sftest -p 127.0.0.1:55432:5432 postgres:16-alpine
STORAGEFORGE_TEST_PG=postgresql://sf:sftest@127.0.0.1:55432/postgres .venv/bin/python tests/run.py all -j 6

# coverage
COVERAGE_FILE=/tmp/.coverage .venv/bin/python -m coverage run --source=storageforge_index --branch -m unittest discover -s tests
COVERAGE_FILE=/tmp/.coverage .venv/bin/python -m coverage report --sort=miss

# the planner's capacity engine against capacity.py
node tests/vectors/check.mjs

# stress (loads the machine on purpose: not alongside anything else)
.venv/bin/python tests/stress/seed.py /tmp/sf/big.db 20 100000
.venv/bin/python tests/stress/hammer.py /tmp/sf/big.db --stages 8,32,64,128,256,512 --seconds 30 --out /tmp/sf/run.json
.venv/bin/python tests/stress/hammer.py /tmp/sf/big.db --stages 64,128 --seconds 40 --writer 10
docker run -d --rm --name sf-stress-pg --shm-size=256m -e POSTGRES_USER=sf -e POSTGRES_PASSWORD=sftest -p 127.0.0.1:55433:5432 postgres:16-alpine
docker exec sf-stress-pg psql -U sf -c "CREATE DATABASE sfstress"
.venv/bin/python tests/stress/seed.py postgresql://sf:sftest@127.0.0.1:55433/sfstress 20 100000
.venv/bin/python tests/stress/hammer.py postgresql://sf:sftest@127.0.0.1:55433/sfstress --stages 8,32,64,128,256 --seconds 30
```

The last full run: **1,955 tests, 0 failed, 9 skipped, in 179 s** at `-j 6` on SQLite. The new tests ran on PostgreSQL as well.

## 10. Still open

- **The foreign keys** that make PostgreSQL scans about 7 times slower than SQLite's: a migration, the owner's call.
- **More than one web process**, to go past about 40 answers a second: the in-memory caches, sessions and rate limits would have to move out first.
- **The browser flake's cause** is likely, not proven.
- **Coverage still low in** `deploy`, `console`, `alerts` and `netdevice`.
- **`shellcheck` is not on this machine**, so 3 tests skip here; CI has it.
- **No KVM lab run** for any of this. The roadmap's section 1 lab items (OPNsense, the appliances, the skipped checks) are not started.
