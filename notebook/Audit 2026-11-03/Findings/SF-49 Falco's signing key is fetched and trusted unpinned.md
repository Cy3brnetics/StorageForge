---
id: SF-49
status: in-progress
severity: low
effort: S
area: Falco install
verified: read
tags: [finding, audit-2026-11-03]
found: 2026-11-03
---
# SF-49 Falco's signing key is fetched and trusted unpinned

**Low** · S · Falco install · Read · part of [[Audit 2026-11-03]]

## What exists
The Falco install runs as a signed script, but it downloads the package signing key at run time and trusts whatever it gets, then installs Falco as root. StorageForge's signature says nothing about what that download returns.

## Evidence
`secplus.py:660` runs `curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor`. `secplus.py:665` and `:669` run `rpm --import` on the same URL, `:666` and `:670` fetch the repo file, and `:671` uses `zypper --gpg-auto-import-keys`. No fingerprint is compared.

Read only. No package was installed. Only HTTPS to falco.org protects this.

## Why it matters
Whoever controls that download, or that site, controls what root installs on every host where someone deploys Falco. It takes control of a third party's site, which is why this is Low.

## Suggested approach
Keep the expected key fingerprint in the script and refuse to continue when the downloaded key doesn't match. Take the value from Falco's own documentation and check it before committing. Untested.

## Done when
- [x] A key with another fingerprint stops the install with a `conflict` line, on apt, rpm and zypper
- [x] A test covers the refusal with a stand-in key

**Fix:** in the working tree on 2026-11-03, not committed, so this is `in-progress` until a commit can be recorded here. Pinned `478B2FBBC75F4237B731DA4365106822B35B1B1F`, checked against the key Falco serves and the trusted entry in Falco's documentation table, which gives its expiry as 2028-12-10 (the older `2005399…7A8D` is marked revoked). The repository file is written by the script with no `gpgkey` line, and `--gpg-auto-import-keys` is gone. Tested with stand-ins. **KVM lab tier 11 must confirm real installs on apt, dnf and zypper**, zypper especially.
