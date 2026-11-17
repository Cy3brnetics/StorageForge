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

## Where else tests live

- [`vectors/`](vectors/): capacity figures that `capacity.py` and the planner's JavaScript must both reach (`node tests/vectors/check.mjs`).
- [`feature_map.py`](feature_map.py): every feature, its unit tests and its lab check. `test_feature_map.py` holds it to the code and the docs.
- [`lab/`](lab/): the KVM lab's tiers, run by `examples/lab/lab.sh`, not by `run.py`. See [docs/kvm-lab.md](../../docs/kvm-lab.md).
