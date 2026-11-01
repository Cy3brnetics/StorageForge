#!/bin/bash
# The suite as CI runs it, from storageforge-indexer. CI containers run as root, where dozens of tests skip themselves
# (root ignores the test paths and reads every folder), so it drops to a normal user first.
set -euo pipefail
if ((EUID == 0)); then
  id sfci >/dev/null 2>&1 || useradd -m sfci
  chown -R sfci .
  exec runuser -u sfci -- env HOME=/home/sfci bash "$0"
fi
exec python -m unittest discover -s tests
