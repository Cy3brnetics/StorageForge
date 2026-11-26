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
    "CVE-2025-0015": record(["include/linux/sched.h"]),
    "CVE-2025-0005": record(["drivers/virtio/virtio_ring.c"]),
    "CVE-2025-0006": record(["net/core/dev.c", "include/net/x.h"]),
    "CVE-2025-0007": record([]),
    "CVE-2025-0010": record(["kernel/sched/fair.c"]),
    "CVE-2025-0011": record(["include/net/x.h", "net/core/neigh.c"]),
    "CVE-2025-0012": record(["net/Makefile", "net/Kconfig"]),
    "CVE-2025-0013": record(["net/Makefile", "net/ipv4/tcp.c"]),
    "CVE-2025-0014": record(["Documentation/foo.rst", "include/net/x.h"]),
    "CVE-2025-0008": record(["net/x.c"], org="other"),
    "CVE-2025-0009": record(["kernel/sched/fair.c"]),
}
GRYPE = {"matches": [
    match("CVE-2025-0001"), match("CVE-2025-0002"), match("CVE-2025-0003"), match("CVE-2025-0015"), match("CVE-2025-0004"), match("CVE-2025-0005"),
    match("CVE-2025-0006"), match("CVE-2025-0007"), match("CVE-2025-0008"), match("CVE-2025-0009"), match("CVE-2025-0010"),
    match("CVE-2025-0011"), match("CVE-2025-0012"), match("CVE-2025-0013"), match("CVE-2025-0014"),
    match("GHSA-aaaa-bbbb-cccc", related=["CVE-2025-0001"]),
    match("CVE-2025-0001", name="openssl"),
]}
X86 = {"kernel/fork.c", "include/linux/sched.h", "arch/x86/kernel/setup.c", "drivers/virtio/virtio_ring.c", "kernel/sched/core.c",
       "kernel/sched/fair.c", "include/net/y.h"}
ARM = {"kernel/fork.c", "net/core/dev.c", "arch/arm64/kernel/setup.c", "include/net/x.h"}


def fetch(cve, vulns=None, cache=None):
    return RECORDS.get(cve)


class KernelVex(unittest.TestCase):
    def run_build(self, objs=None, grype=GRYPE):
        return kernel_vex.build(grype, objs or {"x86_64": X86, "arm64": ARM}, KERNEL, timestamp="2026-11-26T00:00:00Z", fetch=fetch)

    def test_decisions(self):
        doc, kept = self.run_build()
        got = {s["vulnerability"]["name"] for s in doc["statements"]}
        # 0003 is a header no compiled object included; 0011 and 0014 name a header that arm64 compiled, so they stay visible
        self.assertEqual(got, {"CVE-2025-0001", "GHSA-aaaa-bbbb-cccc", "CVE-2025-0003", "CVE-2025-0013"})
        why = dict(kept)
        self.assertIn("kernel/fork.c", why["CVE-2025-0002"])
        self.assertIn("include/linux/sched.h", why["CVE-2025-0015"])
        self.assertIn("no record", why["CVE-2025-0004"])
        self.assertIn("virtio_ring.c", why["CVE-2025-0005"])
        self.assertIn("include/net/x.h", why["CVE-2025-0006"])
        self.assertIn("no programFiles", why["CVE-2025-0007"])
        self.assertIn("not from the kernel CNA", why["CVE-2025-0008"])
        self.assertIn("kernel/sched/fair.c", why["CVE-2025-0009"])
        self.assertIn("kernel/sched/fair.c", why["CVE-2025-0010"])
        self.assertIn("no compiled-type file", why["CVE-2025-0012"])
        self.assertIn("include/net/x.h", why["CVE-2025-0014"])
        self.assertIn("include/net/x.h", why["CVE-2025-0011"])

    def test_included_c_file_counts(self):
        # fair.c has no object of its own; it is in the sources list because core.c's build included it
        ok, _, why = kernel_vex.decide("c", RECORDS["CVE-2025-0009"], {"x86_64": X86})
        self.assertFalse(ok)
        self.assertIn("fair.c", why)

    def test_absent_header_with_absent_c(self):
        ok, files, _ = kernel_vex.decide("c", record(["net/x.c", "include/net/z.h"]), {"a": X86})
        self.assertTrue(ok)
        self.assertEqual(files, ["net/x.c", "include/net/z.h"])
        self.assertFalse(kernel_vex.decide("c", record(["net/x.c", "include/linux/sched.h"]), {"a": X86})[0])

    def test_makefile_only_and_ignored_noncompiled(self):
        self.assertFalse(kernel_vex.decide("c", record(["net/Makefile"]), {"a": X86})[0])
        ok, files, _ = kernel_vex.decide("c", record(["net/Makefile", "net/ipv4/tcp.c"]), {"a": X86})
        self.assertTrue(ok)
        self.assertEqual(files, ["net/ipv4/tcp.c"])

    def test_present_in_one_architecture_only(self):
        rec = record(["net/core/dev.c"])
        self.assertTrue(kernel_vex.decide("c", rec, {"x86_64": X86})[0])
        self.assertFalse(kernel_vex.decide("c", rec, {"x86_64": X86, "arm64": ARM})[0])

    def test_statement_content(self):
        doc, _ = self.run_build()
        st = [s for s in doc["statements"] if s["vulnerability"]["name"] == "CVE-2025-0001"][0]
        self.assertEqual(st["status"], "not_affected")
        self.assertEqual(st["justification"], "vulnerable_code_not_present")
        self.assertIn("net/sched/sch_api.c", st["impact_statement"])
        self.assertIn("None of those files is compiled", st["impact_statement"])
        ids = [p["@id"] for p in st["products"]]
        self.assertEqual(ids[0], "pkg:generic/linux-kernel@" + KERNEL)
        self.assertIn("pkg:generic/linux-kernel@6.18.65?x=1", ids)
        alias = [s for s in doc["statements"] if s["vulnerability"]["name"].startswith("GHSA")][0]
        self.assertEqual(alias["vulnerability"]["aliases"], ["CVE-2025-0001"])

    def test_only_not_affected_and_other_packages_ignored(self):
        doc, kept = self.run_build()
        self.assertTrue(all(s["status"] == "not_affected" for s in doc["statements"]))
        self.assertEqual(len(doc["statements"]), 4)
        self.assertEqual(len(kept), 12)

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
            rc = kernel_vex.main(["--grype", gp, "--sources", paths["a.txt"], "--sources", paths["b.txt"], "--kernel", KERNEL,
                                  "--out", out, "--vulns", vulns])
            self.assertEqual(rc, 0)
            with open(out) as fh:
                doc = json.load(fh)
            self.assertEqual([s["vulnerability"]["name"] for s in doc["statements"]], ["CVE-2025-0001"])


if __name__ == "__main__":
    unittest.main()
