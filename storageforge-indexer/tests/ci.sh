#!/bin/bash
# The suite as CI runs it, from storageforge-indexer. CI containers run as root, where dozens of tests skip themselves
# (root ignores the test paths and reads every folder), so it drops to a normal user first.
#
#   bash tests/ci.sh                 everything, in one process, as python -m unittest discover -s tests does
#   bash tests/ci.sh light           one block of tests/blocks.py (light, medium, heavy, all, or deep), a class per core
set -euo pipefail
if ((EUID == 0)); then
  id sfci >/dev/null 2>&1 || useradd -m sfci
  chown -R sfci .
  exec runuser -u sfci -- env HOME=/home/sfci bash "$0" "$@"
fi
if (($#)); then
  exec python tests/run.py "$@" -j "${SF_TEST_JOBS:-$(nproc)}"
fi
exec python -m unittest discover -s tests
