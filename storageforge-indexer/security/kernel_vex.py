#!/usr/bin/env python3
"""Evidence-based OpenVEX for the key enclave's micro-VM kernel (docs/security.md, "Key enclave").

Grype's binary cataloger reports the kernel the image ships as package `linux-kernel` and matches every kernel CVE by version. The
enclave's kernel is `make tinyconfig` plus enclave/image/kernel.config, so most of those CVEs are in code that is not compiled in. The
kernel CNA records the files each fix touches (programFiles); the build records every file that went into any object (kernel-sources.txt, from
kbuild's dependency records). A CVE whose files are all absent from those lists for every shipped architecture gets `not_affected` / `vulnerable_code_not_present`. Anything
else gets no statement and stays visible. It also writes `fixed` where the CNA's own version data shows a fix on this kernel's branch at or before this version,
and `not_affected` where the bug was introduced after this version. It never writes `affected`.

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


def files_verdict(files, sources_by_arch):
    """(True, typed files, "") where the files a fix touches are all absent from every architecture's sources; otherwise the reason.
    Kconfig, Makefiles and the like are ignored only where a compiled-type file is listed beside them and all of those are absent."""
    typed = [f for f in files if f.lower().endswith(COMPILED_EXT)]
    if not typed:
        return False, files, "touches no compiled-type file (%s)" % ", ".join(files)
    present = ["%s (%s)" % (f, arch) for f in typed for arch, srcs in sorted(sources_by_arch.items()) if f in srcs]
    if present:
        return False, files, "compiled in: " + ", ".join(present)
    return True, typed, ""


def decide(cve, record, sources_by_arch):
    """(statement-worthy, files, reason) from a kernel CNA record's programFiles."""
    if record is None:
        return False, [], "no record in the kernel CNA's vulns.git"
    if not from_kernel_cna(record):
        return False, [], "record is not from the kernel CNA"
    files = program_files(record)
    if not files:
        return False, [], "record lists no programFiles"
    return files_verdict(files, sources_by_arch)


def vtuple(version):
    """6.18.9 -> (6, 18, 9); None for anything that is not dotted numbers."""
    parts = version.split(".")
    if not parts or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def cmp_version(a, b):
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def branch_verdict(record, kernel):
    """What the CNA's own version data says about this kernel: ("fixed", note), ("not_affected", note) or None. Only semver entries
    count; an affected range that covers the kernel, or no entry that decides, gives None."""
    ours = vtuple(kernel)
    if ours is None or len(ours) < 3:
        return None
    line = "%d.%d" % ours[:2]
    cna = (record.get("containers") or {}).get("cna") or {}
    entries = []
    for aff in cna.get("affected") or []:
        for v in aff.get("versions") or []:
            if v.get("versionType") in (None, "semver"):
                entries.append(v)
    fixes, introduced = [], []
    for v in entries:
        start = vtuple(v.get("version") or "")
        status = v.get("status")
        less = v.get("lessThan")
        less_eq = v.get("lessThanOrEqual")
        if start is None:
            continue
        if status == "affected":
            if less or less_eq:
                if less_eq == "*" or (less_eq and less_eq.endswith(".*")):
                    prefix = vtuple(less_eq[:-2]) if less_eq != "*" else ()
                    if prefix is not None and ours[:len(prefix)] == prefix and cmp_version(start, ours) <= 0:
                        return None
                    continue
                end = vtuple(less or less_eq)
                if end is None:
                    continue
                covers = cmp_version(start, ours) <= 0 and (cmp_version(ours, end) <= 0 if less_eq else cmp_version(ours, end) < 0)
                if covers:
                    return None
                if start[:2] == ours[:2] and cmp_version(end, ours) <= 0:
                    fixes.append((end, "fixed in %s by the CNA's affected range" % ".".join(map(str, end))))
            else:
                introduced.append(start)
        elif status == "unaffected":
            if less_eq and less_eq.endswith(".*") and less_eq[:-2] == line and cmp_version(start, ours) <= 0:
                fixes.append((start, "fixed in %s" % v["version"]))
            elif less and start == (0,) and vtuple(less) is not None and cmp_version(ours, vtuple(less)) < 0:
                return ("not_affected", "introduced in %s, after %s" % (less, kernel))
    # an affected-with-no-end entry is where the bug came in; a 6.18 fix proves nothing was lost if it is before ours
    if fixes:
        end, note = min(fixes)
        return ("fixed", "The kernel CNA's record lists this fix on the %s branch: %s, before %s." % (line, note, kernel))
    if introduced and all(cmp_version(ours, i) < 0 for i in introduced):
        first = ".".join(map(str, min(introduced)))
        return ("not_affected", "introduced in %s, after %s" % (first, kernel))
    return None


def load_manual(path):
    if not path or not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


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


def build(grype, sources_by_arch, kernel, vulns=None, cache=None, timestamp=None, fetch=fetch_record, manual=None):
    """The OpenVEX document and the rows (id, reason) of what got no statement."""
    manual = manual or {}
    stamp = timestamp or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    kernel_purl = "pkg:generic/linux-kernel@" + kernel
    archs = ", ".join(sorted(sources_by_arch))
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
        fields, reason = None, ""
        if record is not None and from_kernel_cna(record):
            ok, files, reason = decide(info["cves"][0], record, sources_by_arch)
            if ok:
                fields = {
                    "status": "not_affected",
                    "justification": "vulnerable_code_not_present",
                    "impact_statement": "The fix for this CVE changes %s. None of those files is compiled into this kernel or included by "
                    "anything that is (make tinyconfig plus enclave/image/kernel.config, checked against every file the build read, for "
                    "%s)." % (", ".join(files), archs),
                }
            else:
                verdict = branch_verdict(record, kernel)
                if verdict and verdict[0] == "fixed":
                    fields = {"status": "fixed", "status_notes": verdict[1]}
                elif verdict:
                    fields = {
                        "status": "not_affected",
                        "justification": "vulnerable_code_not_present",
                        "impact_statement": "The kernel CNA's record for this CVE says it was %s." % verdict[1],
                    }
        elif record is None:
            entry = next((manual[c] for c in info["cves"] if c in manual), None)
            if entry:
                ok, files, reason = files_verdict(entry["files"], sources_by_arch)
                if ok:
                    fields = {
                        "status": "not_affected",
                        "justification": "vulnerable_code_not_present",
                        "impact_statement": "The fix for this CVE changes %s (%s). None of those files is compiled into this kernel or "
                        "included by anything that is (make tinyconfig plus enclave/image/kernel.config, checked against every file the "
                        "build read, for %s)." % (", ".join(files), entry["source"], archs),
                    }
            else:
                reason = "no record in the kernel CNA's vulns.git"
        else:
            reason = "record is not from the kernel CNA"
        if fields is None:
            kept.append((vid, reason or "no decision"))
            continue
        products = [{"@id": kernel_purl, "identifiers": {"purl": kernel_purl}}]
        for purl in info["purls"]:
            if purl != kernel_purl:
                products.append({"@id": purl, "identifiers": {"purl": purl}})
        statement = {"vulnerability": {"name": vid}, "products": products}
        statement.update(fields)
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
    ap.add_argument("--manual", help="kernel_vex_manual.json: files and a source URL for CVEs the kernel CNA has no record of")
    ap.add_argument("--timestamp", help="fixed timestamp, for a reproducible document")
    args = ap.parse_args(argv)
    with open(args.grype, encoding="utf-8") as fh:
        grype = json.load(fh)
    sources = {p: read_sources(p) for p in args.sources}
    doc, kept = build(grype, sources, args.kernel, args.vulns, args.cache, args.timestamp, manual=load_manual(args.manual))
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    print("%d statements written to %s" % (len(doc["statements"]), args.out))
    if kept:
        width = max(len(v) for v, _ in kept)
        print("\n%d left visible:" % len(kept))
        for vid, reason in kept:
            print("  %-*s  %s" % (width, vid, reason))
    return 0


if __name__ == "__main__":
    sys.exit(main())
