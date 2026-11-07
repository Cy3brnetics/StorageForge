# Security policy

StorageForge logs in to machines as root and changes disks, filesystems, firewalls and network devices, so a hole in it is a hole in every
machine it manages. Reports are welcome.

## Reporting a vulnerability

Please report it privately, not in a public issue: use **Report a vulnerability** on the repository's
[Security tab](https://github.com/Cy3brnetics/StorageForge/security/advisories/new). Say what you found, how to reproduce it, and what an
attacker would need (an account and which role, an enrolled host, a network position). A proof on throwaway machines is better than one on
real ones; please don't test against machines that are not yours.

There is no bug bounty and no promised response time: this is a small project. Reports are read, and a fix is credited in the
[changelog](CHANGELOG.md) unless you'd rather it wasn't.

## Supported versions

Only the newest release gets fixes. Releases are tagged `vX.Y.Z`.

## What has been looked at

The security audits are in `notebook/` (the newest is `notebook/Audit 2026-11-05`), each with what it read, what it did not reach, and
every finding with its fix. They are partial, and say so. [docs/security.md](docs/security.md) describes the design, including
[what to do if a key may have leaked](docs/security.md#if-a-key-may-have-leaked).

StorageForge comes with no warranty: see the top of the [README](README.md) and the [licence](LICENSE).
