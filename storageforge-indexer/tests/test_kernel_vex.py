import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "security"))
import kernel_vex  # noqa: E402

KERNEL = "6.18.65"
KERNEL_ORG = kernel_vex.KERNEL_CNA_ORG


def record(files, org=KERNEL_ORG):
    affected = [{"product": "Linux", "defaultStatus": "unaffected"}]
    if files is not None:
        affected[0]["programFiles"] = files
    return {"cveMetadata": {"assignerShortName": "Linux"}, "containers": {"cna": {"providerMetadata": {"orgId": org}, "affected": affected}}}


def match(vid, related=(), version=KERNEL, name="linux-kernel"):
    return {
        "vulnerability": {"id": vid},
        "relatedVulnerabilities": [{"id": r} for r in related],
        "artifact": {"name": name, "version": version, "purl": "pkg:generic/linux-kernel@" + version + "?x=1"},
    }


RECORDS = {
    "CVE-2025-0001": record(["net/sched/sch_api.c"]),
    "CVE-2025-0002": record(["kernel/fork.c", "net/core/dev.c"]),
    "CVE-2025-0003": record(["include/linux/skbuff.h"]),
    "CVE-2025-0005": record(["drivers/virtio/virtio_ring.c"]),
    "CVE-2025-0006": record(["net/core/dev.c", "include/net/x.h"]),
    "CVE-2025-0007": record([]),
    "CVE-2025-0008": record(["net/x.c"], org="other"),
    "CVE-2025-0009": record(["kernel/sched/fair.c"]),
}
GRYPE = {"matches": [
    match("CVE-2025-0001"), match("CVE-2025-0002"), match("CVE-2025-0003"), match("CVE-2025-0004"), match("CVE-2025-0005"),
    match("CVE-2025-0006"), match("CVE-2025-0007"), match("CVE-2025-0008"), match("CVE-2025-0009"),
    match("GHSA-aaaa-bbbb-cccc", related=["CVE-2025-0001"]),
    match("CVE-2025-0001", name="openssl"),
]}
X86 = {"kernel/fork", "arch/x86/kernel/setup", "drivers/virtio/virtio_ring", "kernel/sched/build_policy"}
ARM = {"kernel/fork", "net/core/dev", "arch/arm64/kernel/setup"}


def fetch(cve, vulns=None, cache=None):
    return RECORDS.get(cve)


class KernelVex(unittest.TestCase):
    def run_build(self, objs=None, grype=GRYPE):
        return kernel_vex.build(grype, objs or {"x86_64": X86, "arm64": ARM}, KERNEL, timestamp="2026-11-26T00:00:00Z", fetch=fetch)

    def test_decisions(self):
        doc, kept = self.run_build()
        got = {s["vulnerability"]["name"] for s in doc["statements"]}
        self.assertEqual(got, {"CVE-2025-0001", "GHSA-aaaa-bbbb-cccc"})
        why = dict(kept)
        self.assertIn("compiled in: kernel/fork.c (x86_64)", why["CVE-2025-0002"])
        self.assertIn("non-source", why["CVE-2025-0003"])
        self.assertIn("no record", why["CVE-2025-0004"])
        self.assertIn("virtio_ring.c (x86_64)", why["CVE-2025-0005"])
        self.assertIn("non-source", why["CVE-2025-0006"])
        self.assertIn("no programFiles", why["CVE-2025-0007"])
        self.assertIn("not from the kernel CNA", why["CVE-2025-0008"])
        self.assertIn("kernel/sched/fair.c (x86_64)", why["CVE-2025-0009"])

    def test_present_in_one_architecture_only(self):
        rec = record(["net/core/dev.c"])
        self.assertTrue(kernel_vex.decide("c", rec, {"x86_64": {"kernel/fork"}})[0])
        self.assertFalse(kernel_vex.decide("c", rec, {"x86_64": {"kernel/fork"}, "arm64": ARM})[0])

    def test_statement_content(self):
        doc, _ = self.run_build()
        st = [s for s in doc["statements"] if s["vulnerability"]["name"] == "CVE-2025-0001"][0]
        self.assertEqual(st["status"], "not_affected")
        self.assertEqual(st["justification"], "vulnerable_code_not_present")
        self.assertIn("net/sched/sch_api.c", st["impact_statement"])
        self.assertIn("not compiled", st["impact_statement"])
        ids = [p["@id"] for p in st["products"]]
        self.assertEqual(ids[0], "pkg:generic/linux-kernel@" + KERNEL)
        self.assertIn("pkg:generic/linux-kernel@6.18.65?x=1", ids)
        alias = [s for s in doc["statements"] if s["vulnerability"]["name"].startswith("GHSA")][0]
        self.assertEqual(alias["vulnerability"]["aliases"], ["CVE-2025-0001"])

    def test_only_not_affected_and_other_packages_ignored(self):
        doc, kept = self.run_build()
        self.assertTrue(all(s["status"] == "not_affected" for s in doc["statements"]))
        self.assertEqual(len(doc["statements"]), 2)
        self.assertEqual(len(kept), 8)

    def test_wrong_kernel_version_stays_visible(self):
        doc, kept = self.run_build(grype={"matches": [match("CVE-2025-0001", version="6.1.0")]})
        self.assertEqual(doc["statements"], [])
        self.assertIn("6.1.0", kept[0][1])

    def test_openvex_shape(self):
        doc, _ = self.run_build()
        for key in ("@context", "@id", "author", "timestamp", "statements"):
            self.assertIn(key, doc)
        self.assertEqual(doc["@context"], "https://openvex.dev/ns/v0.2.0")
        self.assertTrue(doc["@id"].endswith("linux-kernel-" + KERNEL))
        self.assertRegex(doc["timestamp"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        for s in doc["statements"]:
            self.assertTrue(s["products"] and s["vulnerability"]["name"])
        json.dumps(doc)

    def test_cli_with_local_checkout(self):
        with tempfile.TemporaryDirectory() as d:
            vulns = os.path.join(d, "vulns")
            os.makedirs(os.path.join(vulns, "cve", "published", "2025"))
            with open(os.path.join(vulns, "cve", "published", "2025", "CVE-2025-0001.json"), "w") as fh:
                json.dump(RECORDS["CVE-2025-0001"], fh)
            paths = {}
            for name, content in (("a.txt", "\n".join(sorted(X86))), ("b.txt", "\n".join(sorted(ARM)))):
                paths[name] = os.path.join(d, name)
                with open(paths[name], "w") as fh:
                    fh.write(content + "\n")
            gp = os.path.join(d, "g.json")
            with open(gp, "w") as fh:
                json.dump({"matches": [match("CVE-2025-0001"), match("CVE-2025-0002")]}, fh)
            out = os.path.join(d, "vex.json")
            rc = kernel_vex.main(["--grype", gp, "--objects", paths["a.txt"], "--objects", paths["b.txt"], "--kernel", KERNEL,
                                  "--out", out, "--vulns", vulns])
            self.assertEqual(rc, 0)
            with open(out) as fh:
                doc = json.load(fh)
            self.assertEqual([s["vulnerability"]["name"] for s in doc["statements"]], ["CVE-2025-0001"])


if __name__ == "__main__":
    unittest.main()
