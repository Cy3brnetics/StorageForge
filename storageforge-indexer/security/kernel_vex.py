#!/usr/bin/env python3
"""Evidence-based OpenVEX for the key enclave's micro-VM kernel (docs/security.md, "Key enclave").

Grype's binary cataloger reports the kernel the image ships as package `linux-kernel` and matches every kernel CVE by version. The
enclave's kernel is `make tinyconfig` plus enclave/image/kernel.config, so most of those CVEs are in code that is not compiled in. The
kernel CNA records the files each fix touches (programFiles); the build records every file that went into any object (kernel-sources.txt, from
kbuild's dependency records). A CVE whose files are all absent from those lists for every shipped architecture gets `not_affected` / `vulnerable_code_not_present`. Anything
else gets no statement and stays visible. This tool never writes `fixed` or `affected`.

Standard library only.
"""
import argparse
import datetime
import json
import os
import re
import sys
import urllib.error
import urllib.request

KERNEL_PACKAGE = "linux-kernel"
BASE = "https://git.kernel.org/pub/scm/linux/security/vulns.git/plain/cve/published"
KERNEL_CNA_ORG = "f4215fc3-5b6b-47ff-a258-f7189bd81038"
COMPILED_EXT = (".c", ".h", ".s", ".rs", ".lds")
ID_PREFIX = "https://storageforge.dev/vex/linux-kernel-"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def read_sources(path):
    with open(path, encoding="utf-8") as fh:
        return {line.strip() for line in fh if line.strip() and not line.startswith("#")}


def record_path(root, cve):
    return os.path.join(root, "cve", "published", cve.split("-")[1], cve + ".json")


def fetch_record(cve, vulns=None, cache=None, timeout=30):
    """The CNA record as a dict, or None where the kernel CNA has none."""
    if vulns:
        path = record_path(vulns, cve)
        if not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    cached = os.path.join(cache, cve + ".json") if cache else None
    if cached and os.path.isfile(cached):
        with open(cached, encoding="utf-8") as fh:
            return json.load(fh)
    try:
        with urllib.request.urlopen("%s/%s/%s.json" % (BASE, cve.split("-")[1], cve), timeout=timeout) as resp:  # noqa: S310
            body = resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    data = json.loads(body)
    if cached:
        os.makedirs(cache, exist_ok=True)
        with open(cached, "wb") as fh:
            fh.write(body)
    return data


def program_files(record):
    cna = (record.get("containers") or {}).get("cna") or {}
    files = []
    for entry in cna.get("affected") or []:
        for name in entry.get("programFiles") or []:
            if name not in files:
                files.append(name)
    return files


def from_kernel_cna(record):
    meta = record.get("cveMetadata") or {}
    cna = (record.get("containers") or {}).get("cna") or {}
    org = (cna.get("providerMetadata") or {}).get("orgId")
    if org:
        return org == KERNEL_CNA_ORG
    return meta.get("assignerShortName") == "Linux"


def decide(cve, record, sources_by_arch):
    """(statement-worthy, files, reason). Reason says why there is no statement when the first is False.
    Kconfig, Makefiles and the like are ignored only where a compiled-type file is listed beside them and all of those are absent."""
    if record is None:
        return False, [], "no record in the kernel CNA's vulns.git"
    if not from_kernel_cna(record):
        return False, [], "record is not from the kernel CNA"
    files = program_files(record)
    if not files:
        return False, [], "record lists no programFiles"
    typed = [f for f in files if f.lower().endswith(COMPILED_EXT)]
    if not typed:
        return False, files, "touches no compiled-type file (%s)" % ", ".join(files)
    present = ["%s (%s)" % (f, arch) for f in typed for arch, srcs in sorted(sources_by_arch.items()) if f in srcs]
    if present:
        return False, files, "compiled in: " + ", ".join(present)
    return True, typed, ""


def cve_ids(match):
    vuln = match.get("vulnerability") or {}
    ids = []
    for ident in [vuln.get("id")] + [r.get("id") for r in match.get("relatedVulnerabilities") or []]:
        if ident and CVE_RE.match(ident) and ident not in ids:
            ids.append(ident)
    return vuln.get("id"), ids


def kernel_matches(grype):
    out = {}
    for match in grype.get("matches") or []:
        art = match.get("artifact") or {}
        if art.get("name") != KERNEL_PACKAGE:
            continue
        vid, cves = cve_ids(match)
        if not vid:
            continue
        entry = out.setdefault(vid, {"cves": cves, "purls": [], "versions": set()})
        if art.get("purl") and art["purl"] not in entry["purls"]:
            entry["purls"].append(art["purl"])
        entry["versions"].add(art.get("version") or "")
    return out


def build(grype, sources_by_arch, kernel, vulns=None, cache=None, timestamp=None, fetch=fetch_record):
    """The OpenVEX document and the rows (id, reason) of what got no statement."""
    stamp = timestamp or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    kernel_purl = "pkg:generic/linux-kernel@" + kernel
    statements, kept = [], []
    for vid, info in sorted(kernel_matches(grype).items()):
        odd = sorted(v for v in info["versions"] if v != kernel)
        if odd:
            kept.append((vid, "Grype saw kernel version %s, not %s" % (", ".join(odd), kernel)))
            continue
        if not info["cves"]:
            kept.append((vid, "not a CVE id and no related CVE id"))
            continue
        record = None
        for cve in info["cves"]:
            record = fetch(cve, vulns, cache)
            if record is not None:
                break
        ok, files, reason = decide(info["cves"][0], record, sources_by_arch)
        if not ok:
            kept.append((vid, reason))
            continue
        archs = ", ".join(sorted(sources_by_arch))
        products = [{"@id": kernel_purl, "identifiers": {"purl": kernel_purl}}]
        for purl in info["purls"]:
            if purl != kernel_purl:
                products.append({"@id": purl, "identifiers": {"purl": purl}})
        statement = {
            "vulnerability": {"name": vid},
            "products": products,
            "status": "not_affected",
            "justification": "vulnerable_code_not_present",
            "impact_statement": "The fix for this CVE changes %s. None of those files is compiled into this kernel or included by anything that is (make tinyconfig plus "
            "enclave/image/kernel.config, checked against every file the build read, for %s)." % (", ".join(files), archs),
        }
        aliases = [c for c in info["cves"] if c != vid]
        if aliases:
            statement["vulnerability"]["aliases"] = aliases
        statements.append(statement)
    doc = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": ID_PREFIX + kernel,
        "author": "StorageForge",
        "role": "Maintainer",
        "timestamp": stamp,
        "version": 1,
        "tooling": "storageforge-indexer/security/kernel_vex.py",
        "statements": statements,
    }
    return doc, kept


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--grype", required=True, help="grype -o json report")
    ap.add_argument("--sources", action="append", required=True, help="kernel-sources.txt, once per shipped architecture")
    ap.add_argument("--kernel", required=True, help="kernel version, e.g. 6.18.65")
    ap.add_argument("--out", required=True)
    ap.add_argument("--vulns", help="local checkout of the kernel CNA's vulns.git")
    ap.add_argument("--cache", help="directory for per-CVE records fetched over HTTPS")
    ap.add_argument("--timestamp", help="fixed timestamp, for a reproducible document")
    args = ap.parse_args(argv)
    with open(args.grype, encoding="utf-8") as fh:
        grype = json.load(fh)
    sources = {p: read_sources(p) for p in args.sources}
    doc, kept = build(grype, sources, args.kernel, args.vulns, args.cache, args.timestamp)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    print("%d not_affected statements written to %s" % (len(doc["statements"]), args.out))
    if kept:
        width = max(len(v) for v, _ in kept)
        print("\n%d left visible:" % len(kept))
        for vid, reason in kept:
            print("  %-*s  %s" % (width, vid, reason))
    return 0


if __name__ == "__main__":
    sys.exit(main())
