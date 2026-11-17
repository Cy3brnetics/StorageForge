# The unit suite

Run from `storageforge-indexer`, after `pip install -e ".[postgres,test]"`. Without `test` (Hypothesis) the random tests skip and everything else runs.

```bash
python tests/run.py                  # light: the minute after any change
python tests/run.py light medium     # both
python tests/run.py all -j 8         # light, medium and heavy, eight classes at a time: what CI runs
python tests/run.py deep -j 8        # the random tests again, with many examples and a fresh seed
python tests/run.py --list heavy     # what is in a block
python -m unittest discover -s tests # everything in one process, as before
```

Every block also runs on PostgreSQL when `STORAGEFORGE_TEST_PG` names a server it may create databases on (see [Operations](../../docs/operations.md#tests)). CI runs light, medium, heavy and deep as four steps on each database (`tests/ci.sh <block>`), and each step runs even when one before it failed.

## Three blocks

[`blocks.py`](blocks.py) says which class is in which. A class it does not name is light. [`test_blocks.py`](test_blocks.py) fails when a name there is no longer a class, so a renamed class can't drop into light unseen.

| Block | What its tests need | On 2026-11-16, one core | With `-j 12` |
| :--- | :--- | ---: | ---: |
| **light** | Python and a temporary database: parsers, compilers, scripts as text, the API through Flask's test client | 1,223 tests, 83 s | 13 s |
| **medium** | local tools: bash running generated scripts, telnet and console sessions, the scheduler's runner, nft and iptables in check mode, longer API walks | 227 tests, 102 s | |
| **heavy** | real servers and real time: Chromium, sshd, Docker, the sentinel and its decoys, key rotation, scans end to end | 409 tests, 741 s | |
| all three | | 1,859 tests, 941 s | 125 s |

`run.py` lists, at the end of a run on one core, any light test over 1.5 s and any medium test over 6 s: move its class in `blocks.py`, or make it faster. Under `-j` the machine is shared and times say little, so it lists none. The longest class, `test_rotation.Rotation` at about 100 s, sets the floor for `all -j`.

`-j N` runs N worker processes, each taking the next class off a queue, so a class keeps its `setUpClass` and its order. Every test makes its own temporary folder, database and ports. A test that fails under `-j` and passes alone is a finding: say so rather than widening its margin.

## Controlled and random

Most tests are **controlled**: one input, one answer, named for what it shows (`test_a_redirect_read_from_a_firewall_reads_back_as_a_redirect`).

The **random** tests are the `test_props_*.py` modules, using [Hypothesis](https://hypothesis.readthedocs.io). Each says what must hold for every input of a kind, and Hypothesis looks for an input where it doesn't, then shrinks it to the smallest it can find.

| Module | What must hold |
| :--- | :--- |
| `test_props_netlang.py` | The network language reads back what it accepts, every target emits every statement or says why not, no accepted value holds a character a shell reads, a comment reaches `ufw` as one argument, and the shell targets run only their own commands |
| `test_props_search.py` | A pattern finds the same names by every road (extension, exact, prefix, trigram index, PostgreSQL regex) as a plain `fnmatch` does, through the scanner's own write path |
| `test_props_parsers.py` | Every parser of host and device output reads any text, keeping what it can, or refuses it with a `ValueError` that says why. Real fixtures are damaged too. A new `parse*` function fails the suite until it has a contract |
| `test_props_capacity.py` | Every byte of a pool's raw space is counted once, no pool survives losing all its disks, more disks never give less, and any route needs a known permission, with more permissions never allowing less |
| `test_props_scripts.py` | A hostile value built from every piece of shell syntax is data in every send, task and plan script, or is refused. Checked as text by a scanner that follows Bash's quoting, with `bash -n`, and by running the send scripts |

They run in two ways ([`props.py`](props.py)):

- **In light**, a small number of examples, the same ones every run, so a red light run is a change and not luck.
- **In `deep`**, 2,000 examples each (`--examples N` to change it) from a fresh seed. A failure is kept in `.hypothesis/` and tried first next time.

When one fails, Hypothesis prints the smallest input it found. **Add that input as a controlled test** (or an `@example` on the random test), so it stays pinned when the seed moves on. Each bug the random tests found on 2026-11-16 is pinned this way: see `test_routers.Language`, `test_indexer.Patterns`, `test_props_parsers.FoundByTheseTests`, `test_md_services` and `tests/vectors/capacity.json`.

## Stress runs

[`stress/`](stress/) puts a real server under load until it breaks, so it can be made to cope and pushed again. It is not part of the suite: it
loads the machine on purpose.

```bash
python tests/stress/seed.py /tmp/sf/big.db 20 100000        # 20 hosts of 100,000 files, written as a scan writes them (about 50 s)
python tests/stress/hammer.py /tmp/sf/big.db --stages 8,32,64,128,256,512 --seconds 30 --out /tmp/sf/run.json
python tests/stress/hammer.py /tmp/sf/big.db --stages 64 --only light            # one kind of route, to tell which slows the other
python tests/stress/hammer.py /tmp/sf/big.db --stages 32 --profile /tmp/sf/spy.txt   # where the server's time went (py-spy)
```

`hammer.py` starts `storageforge-index serve` in a temporary folder of its own (database, data folder, home: a real install is never touched),
times the cold start (the folder index and the file map, built once), then runs each stage with that many clients asking with no pause, across
the routes that read the most. A client waits out a `503` with `Retry-After` as the page does. A stage breaks when:

| Limit | |
| :--- | :--- |
| light routes, p99 | 2 s: a list of hosts, the map, a host's logs must stay quick whatever else runs |
| queued routes, p99 | 30 s: searches, duplicate files and exports, admitted four at a time |
| folder analyses, p99 | 90 s: the file map, twin and cold folders, built one at a time |
| errors | 5 %, counting anything but an answer under 500 |
| memory | 6 GiB for the server, and 4 GiB left on the machine: past that the server is killed, and that is the finding |

What it found on 2026-11-16, at two million files, and what changed (each pinned in `test_under_load.py` or `test_props_folders.py`):

| Round | Broke at | Why | Now |
| :--- | :--- | :--- | :--- |
| 1 | 8 clients | Each request for the file map built it again: 5.7 GiB, past 30 s | One build per analysis; the others wait for it |
| 2-3 | 8 | The request that started a build held its thread for all of it | Built off the request; a request waits 2 s, then is asked back |
| 3 | 8 | The file map's twin folders waited for the slot the file map held | An analysis inside a build is made on its slot |
| 4 | 8 | Every host's twin folders repeated the fleet-wide comparison | Made once per folder index, filtered per host |
| 6 | 32 | `_noise()`, the system-folder test, was 3 s of a host's file map | One regular expression, held to the old rules by a random test |
| 8 | 32 | Fourteen connections, each with a 256 MiB SQLite cache: 4.6 GiB | 16 MiB for a request's connection |
| 8 | 32 | Searches and exports filled every thread; a list of hosts took 2 s | Four at a time, the rest asked back in a second |
| 9 | 128 | Waitress took 100 connections and kept idle ones 120 s | 500, and idle ones closed after 30 s |
| 10 | 64 | The analyses were Python in the web's process, sharing its interpreter with every request | A worker process of their own (`folderwork.py`), replaced if it dies; the folder index is its memory |
| 11 | 64 | A request waited 2 s for an analysis, holding a thread | 0.25 s under `serve()`, then asked back in 2 s; at most 32 builds waiting |

Where it stands: with every kind of route at once, 128 clients asking with no pause pass every limit (light routes 1.6 s at p99, queued ones
14 s, analyses 30 s, no errors, the web process under 2.5 GiB). 256 break the light routes at about 4 s: that is one Python process answering
about 40 requests a second, and the next step past it would be more than one web process, which the in-memory caches and sessions don't
allow yet.

## Where else tests live

- [`vectors/`](vectors/): capacity figures that `capacity.py` and the planner's JavaScript must both reach (`node tests/vectors/check.mjs`).
- [`feature_map.py`](feature_map.py): every feature, its unit tests and its lab check. `test_feature_map.py` holds it to the code and the docs.
- [`lab/`](lab/): the KVM lab's tiers, run by `examples/lab/lab.sh`, not by `run.py`. See [docs/kvm-lab.md](../../docs/kvm-lab.md).
