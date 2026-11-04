# Test audit, 2026-11-03

What the test suites covered, what was added so that every feature has a test and a place in the KVM lab, and what that found. Run on the `dev-expanded-networking` branch, at commit `119b7cf` with these changes uncommitted, on the build `sf-ctl,sf-ubuntu,sf-fedora,sf-rocky,sf-suse,sf-alpine,sf-bookworm`.

## What was there

| Measure | Before | After |
| :--- | :--- | :--- |
| Unit and browser tests | 946 | 1043 |
| Branch coverage | 79% | 84% |
| `cli.py` | 35% | 80% |
| `routes_clamav.py` | 65% | 100% |
| `hostkeys.py` | 59% | 93% |
| `workloads.py` | 57% | 89% |
| `server.py` | 78% | 84% |
| `secplus.py` | 72% | 84% |
| Lab tiers | 0 to 11 | 0 to 11, and 13 |

The features that had never been verified in the lab were those the [feature guide](features/README.md) marks **Shown** or **Not run**, and a few it doesn't list. No lab tier mentioned the file map, the planner, Git, canvas or Markdown export, the activity log, accounts, roles, sites, reset, retiring a host, keys added by hand, snapshot job import, or ClamAV's actions. Of about 277 web routes, 20 were called by no test.

[`kvm-lab.md`](kvm-lab.md) also listed a tier 12 in `tests/lab/tiers_network.py`, and there is no such file. The router work is on the roadmap and not built. The table now says so.

## What was added

- **`tests/lab/tiers_features.py`, tier 13:** 35 kinds of check, giving 41 results across hosts, comparing what StorageForge reports with what the VM shows. `lab.sh test --all` runs it and the report includes it. `SFLAB_ONLY=git,clamav` runs just those checks.
- **`tests/feature_map.py` and `tests/test_feature_map.py`:** every feature with its unit tests and lab checks. The suite fails if a feature, web route or command has none, if a named test or check doesn't exist, or if the docs name a tier that isn't there.
- **`tests/test_feature_routes.py`:** the routes no test had called, on data from a real scan.
- **`tests/test_cli_commands.py`:** every command on a scanned database, exit codes included.

## What it found

Three bugs in the product, all fixed:

| Bug | Found by | What happened |
| :--- | :--- | :--- |
| Snapper configs that never snapshot under SELinux | Tier 13, on Fedora 44 | **Create snapper config** said it had worked, and every later snapshot was denied. The timeline service still exited 0, so nothing showed that no backups were being taken. The script now adds the SELinux file-context rule before making the config, and only reports success once a first snapshot exists. |
| Removing a plan's jobs left it stuck | Tier 13 | **Remove from hosts** kept a `deployed` row. The plan could then never be deleted, and the host could never be retired, each with an error saying to do the removal that had already been done. |
| A rollback preview hid its reason | Unit test | The check for the script's `ERROR` line came after the check for `DONE`, so it could never run. A missing snapshot read as "the preview did not finish", and now says what is missing. |

The first snapper fix passed its unit tests and failed in the lab. A label set with `chcon` worked for one snapshot and was gone from the next daemon's view, and only a timeline run from a new daemon showed that. The fix was verified on Fedora only, so openSUSE and the Enterprise Linux configs have not run this path.

Left as they are, for you to decide:

- **ClamAV refuses every "2 GB" machine.** Its script wants 2048 MiB of `MemTotal`, and a 2 GB VM reports about 1771. The message says signatures take about 1 GiB, so the limit may be stricter than it needs to be. Tier 13 checks the refusal, then hides the real figure from that guard to test the rest on a 1.7 GiB VM.
- **`--run` on ClamAV before it is installed** fails with "Unit sf-clamav.service not found", and doesn't say to install it first.
- **`remote add` with no tunnel** prints a Python traceback. The message at the end of it is correct.
- **Scan intervals under 10 minutes** can't be kept, because the scheduler looks every 10 minutes. The API accepts them without saying so.
- **`usage` in the reinstall script** reads its own file, so `--help` fails when the script is piped to `bash -s`. It works when saved first, which is how the docs use it.

## What the lab still can't verify

Each has a `why` in `feature_map.py`, and [`kvm-lab.md`](kvm-lab.md#what-the-lab-cant-test) lists them:

| Feature | Why | What covers it instead |
| :--- | :--- | :--- |
| PostgreSQL | The lab runs on SQLite | The unit suite on PostgreSQL: 1043 tests, 78 skipped, 0 failed |
| System updates | What a mirror holds changes daily | Scripts against stand-ins |
| Tailscale, proxies, identity providers | Needs an outside account | Parsers |
| PagerDuty | Needs the real service | Routes. ntfy is delivered to for real |
| FIDO2 | Needs a physical token | Chromium's virtual authenticator |

Coverage of other kinds is thinner than the table suggests in three places:

- **Configs:** this ran on 7 of the 14. The other 7, and the appliances, last ran earlier tiers on 2026-10-31 and 2026-11-01, and have not run tier 13.
- **Skips in this build:** ZFS send and the sync engine's ZFS stream need two ZFS hosts, and tier 8 needs appliances in the build.
- **Browser check:** `ui-pages` only runs where `playwright` is installed, and `lab.sh` uses the system Python, so it skips there unless that Python has it. It opens every page and tab but takes no actions.

`feature_map.py` shows that a check exists, not how deep it goes. Some low-coverage modules remain, chiefly `keyinstall.py` at 51% and `deploy.py` at 66%, whose paths need a real SSH password login. Tier 2 runs `deploy.py` on real hosts, and that doesn't count toward the unit percentages.

## Results

| Run | Passed | Failed | Skipped |
| :--- | :--- | :--- | :--- |
| Unit and browser tests on SQLite | 1039 | 0 | 4 |
| Unit tests on PostgreSQL 16 | 965 | 0 | 78 |
| Lab tiers 0 to 11 and 13 | 482 | 0 | 3 |

The three lab skips are ZFS send and the sync engine's ZFS stream, which need two ZFS hosts, and tier 8, which needs appliances.

The lab total joins two runs. `lab.sh test --all` ran every tier and had one failure, `lxc-guests`: `unattended-upgrades` held the dpkg lock on a fresh VM, and the check didn't wait. That check was fixed, and tier 13 ran again on its own, with Playwright, so `ui-pages` ran too. Only the test changed between the two runs, not the product. Tiers 0 to 11 were not repeated.

The coverage figures come from a run before the last snapper change, which rewrote one function and its tests. The PostgreSQL run came after it, as did a final SQLite run, and neither measured coverage.

The golden snapshot was retaken with StorageForge built from this working tree, so a reset returns to the fixed code.
