#!/usr/bin/env python3
# Copyright (c) DED BUILD DEVOPS. All rights reserved.
"""Tests for oscap_diff.py. Standard library only.

Run:  python3 -m unittest -v test_oscap_diff
"""
import contextlib
import io
import json
import os
import re
import shutil
import tempfile
import unittest
import zipfile

import oscap_diff as od

NS = 'xmlns="http://checklists.nist.gov/xccdf/1.2"'
PROFILE = "xccdf_org.ssgproject.content_profile_pci-dss"


def xccdf(host, rules, oscap="1.3.10", arf=False, title_prefix="Rule "):
    """Build an XCCDF results document. rules: {rule_id: (severity, result)}."""
    defs = "".join(f'<Rule id="{rid}" severity="{sev}"><title>{title_prefix}{rid}</title>'
                   f'<description>About {rid}</description>'
                   f'<ident system="https://ncp.nist.gov/cce">CCE-{rid}</ident></Rule>'
                   for rid, (sev, _) in rules.items())
    results = "".join(f'<rule-result idref="{rid}" severity="{sev}"><result>{res}</result></rule-result>'
                      for rid, (sev, res) in rules.items())
    test_system = f' test-system="cpe:/a:redhat:openscap:{oscap}"' if oscap else ""
    body = (f'<Benchmark {NS} id="b"><title>Guide</title>{defs}'
            f'<TestResult id="tr"{test_system}><profile idref="{PROFILE}"/><target>{host}</target>'
            f'{results}<score maximum="100">70</score></TestResult></Benchmark>')
    if arf:
        body = ('<arf:asset-report-collection '
                'xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1">'
                f'{body}</arf:asset-report-collection>')
    return '<?xml version="1.0"?>' + body


VMAAS = {
    "web01": {"r_fixed": ("high", "fail"), "r_regr": ("medium", "pass"), "r_still": ("low", "fail"),
              "r_chg": ("low", "notapplicable"), "r_same": ("medium", "pass"),
              "r_sev": ("medium", "pass"), "r_gone": ("low", "fail")},
    "db01": {"r_same": ("medium", "pass")},
    "old01": {"r_same": ("medium", "pass")},  # no TOOLKIT counterpart
}
TOOLKIT = {
    "web01": {"r_fixed": ("high", "pass"), "r_regr": ("medium", "fail"), "r_still": ("low", "fail"),
              "r_chg": ("low", "pass"), "r_same": ("medium", "pass"),
              "r_sev": ("high", "pass"), "r_newfail": ("high", "fail"), "r_newok": ("low", "pass")},
    "db01": {"r_same": ("medium", "pass")},
}
REQUIRED = ["--vmaas-version", "4.2.0", "--toolkit-version", "1.8.3", "--app-name", "payments"]


class OscapDiffTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="oscap_diff_test_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def path(self, name):
        return os.path.join(self.tmp, name)

    def make_zip(self, name, hosts, nested=False, extras=True):
        with zipfile.ZipFile(self.path(name), "w") as z:
            for host, rules in hosts.items():
                if nested and host == "db01":
                    inner = io.BytesIO()
                    with zipfile.ZipFile(inner, "w") as zi:
                        zi.writestr("results.xml", xccdf(host, rules))
                    z.writestr(f"{host}.zip", inner.getvalue())
                else:
                    z.writestr(f"{host}/results.xml", xccdf(host, rules))
            if extras:
                z.writestr("web01/report.html", "<html>not a scan</html>")
                z.writestr("web01/oval-results.xml", '<?xml version="1.0"?><oval_results/>')
                z.writestr("broken.xml", "<not closed")
        return self.path(name)

    def run_main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = od.main(list(args))
            except SystemExit as e:
                code = e.code
        return code, out.getvalue(), err.getvalue()

    def run_default(self, *extra, vmaas=VMAAS, toolkit=TOOLKIT):
        v = self.make_zip("vmaas.zip", vmaas)
        t = self.make_zip("toolkit.zip", toolkit, nested=True)
        code, out, err = self.run_main("--vmaas-scan", v, "--toolkit-scan", t, *REQUIRED,
                                       "-o", self.path("out"), "--zip", self.path("out.zip"), *extra)
        diff = None
        if os.path.exists(self.path("out/diff.json")):
            with open(self.path("out/diff.json"), encoding="utf-8") as f:
                diff = json.load(f)
        return code, out, err, diff

    # ------------------------------------------------------------------ units
    def test_classify(self):
        c = od.classify
        self.assertEqual(c("pass", "fail"), "regressed")
        self.assertEqual(c("notapplicable", "error"), "regressed")
        self.assertEqual(c("fail", "pass"), "fixed")
        self.assertEqual(c("fail", "unknown"), "still_failing")
        self.assertEqual(c("notapplicable", "pass"), "changed")
        self.assertEqual(c("pass", "pass"), "unchanged")
        self.assertEqual(c(None, "fail"), "added_failing")
        self.assertEqual(c(None, "notapplicable"), "added_passing")
        self.assertEqual(c("fail", None), "removed")

    def test_oscap_version(self):
        self.assertEqual(od.oscap_version("cpe:/a:redhat:openscap:1.3.10"), "1.3.10")
        self.assertEqual(od.oscap_version("cpe:/a:redhat:openscap:1.4.0-beta"), "1.4.0-beta")
        self.assertEqual(od.oscap_version("cpe:/a:open-scap:oscap"), "")
        self.assertEqual(od.oscap_version(""), "")

    def test_oscap_version_from_oval_generator(self):
        doc = xccdf("h", {"r": ("low", "pass")}, oscap=None, arf=True).replace(
            "</arf:asset-report-collection>",
            '<oval_results xmlns="http://oval.mitre.org/XMLSchema/oval-results-5"><generator>'
            '<product_name>cpe:/a:open-scap:oscap</product_name>'
            '<product_version>1.3.8</product_version></generator></oval_results>'
            "</arf:asset-report-collection>")
        scans = od.parse_xml("arf.xml", doc.encode())
        self.assertEqual(scans[0]["meta"]["oscap_version"], "1.3.8")

    # ------------------------------------------------------------ end to end
    def test_end_to_end_categories_and_summary(self):
        code, out, err, diff = self.run_default()
        self.assertEqual(code, 0, err)
        self.assertEqual(diff["summary"]["pairs"], 2)
        self.assertEqual(diff["summary"]["unmatched"], 1)
        self.assertEqual(diff["unmatched"][0]["key"][0], "old01")
        web = next(c for c in diff["comparisons"] if c["key"][0] == "web01")
        cats = {r["id"]: r["category"] for r in web["rows"]}
        self.assertEqual(cats, {"r_fixed": "fixed", "r_regr": "regressed", "r_still": "still_failing",
                                "r_chg": "changed", "r_same": "unchanged", "r_sev": "unchanged",
                                "r_gone": "removed", "r_newfail": "added_failing",
                                "r_newok": "added_passing"})
        sev = next(r for r in web["rows"] if r["id"] == "r_sev")
        self.assertTrue(sev["severity_changed"])
        self.assertEqual((sev["severity_vmaas"], sev["severity_toolkit"]), ("medium", "high"))
        self.assertEqual(web["counts"]["severity_changed"], 1)
        self.assertTrue(web["has_changes"])
        db = next(c for c in diff["comparisons"] if c["key"][0] == "db01")
        self.assertFalse(db["has_changes"])
        s = diff["summary"]
        self.assertEqual((s["verdict"], s["regressed"], s["added_failing"], s["pairs_failing"]),
                         ("FAIL", 1, 1, 1))
        # pairs with problems are listed first
        self.assertEqual(diff["comparisons"][0]["key"][0], "web01")
        # rule text is stored once, not per row
        self.assertEqual(diff["rules"]["r_regr"]["title"], "Rule r_regr")
        self.assertNotIn("title", web["rows"][0])
        self.assertIn("Verdict: FAIL", out)

    def test_versions_and_labels(self):
        code, out, err, diff = self.run_default()
        self.assertEqual(diff["baseline_label"], "VMAAS")
        self.assertEqual(diff["current_label"], "payments TOOLKIT")
        self.assertEqual((diff["vmaas_version"], diff["toolkit_version"], diff["app_name"]),
                         ("4.2.0", "1.8.3", "payments"))
        self.assertEqual(diff["oscap_versions"], {"vmaas": ["1.3.10"], "toolkit": ["1.3.10"]})

    def test_fail_on_regression_exit_codes(self):
        code, *_ = self.run_default("--fail-on-regression")
        self.assertEqual(code, 2)
        # only a new failing rule -> still exit 2
        v = {"h": {"a": ("low", "pass")}}
        t = {"h": {"a": ("low", "pass"), "b": ("high", "fail")}}
        code, *_ = self.run_default("--fail-on-regression", vmaas=v, toolkit=t)
        self.assertEqual(code, 2)
        # severity change and new passing rule only -> exit 0
        t = {"h": {"a": ("high", "pass"), "b": ("high", "pass")}}
        code, out, err, diff = self.run_default("--fail-on-regression", vmaas=v, toolkit=t)
        self.assertEqual(code, 0, err)
        self.assertEqual(diff["summary"]["verdict"], "PASS")

    def test_output_zip_contents(self):
        self.run_default()
        with zipfile.ZipFile(self.path("out.zip")) as z:
            self.assertEqual(sorted(z.namelist()), ["diff.json", "report.html"])

    def test_report_html(self):
        v = {"h": {"a": ("low", "pass")}}
        t = {"h": {"a": ("low", "fail")}}
        # hostile title must not break out of the data <script>
        with zipfile.ZipFile(self.path("vmaas.zip"), "w") as z:
            z.writestr("h.xml", xccdf("h", v["h"], title_prefix="&lt;/script&gt;&lt;b&gt;x \u00e9\U0001f512 "))
        with zipfile.ZipFile(self.path("toolkit.zip"), "w") as z:
            z.writestr("h.xml", xccdf("h", t["h"], title_prefix="&lt;/script&gt;&lt;b&gt;x \u00e9\U0001f512 "))
        code, out, err = self.run_main("--vmaas-scan", self.path("vmaas.zip"),
                                       "--toolkit-scan", self.path("toolkit.zip"), *REQUIRED,
                                       "-o", self.path("out"), "--zip", self.path("out.zip"))
        self.assertEqual(code, 0, err)
        with open(self.path("out/report.html"), "rb") as f:
            html = f.read()
        self.assertFalse(re.search(rb"[^\x00-\x7f]", html), "report.html must be pure ASCII")
        self.assertEqual(len(re.findall(rb"</script", html, re.I)), 2,
                         "only the two real script blocks may contain '</script'")
        self.assertIn(b"data:image/png;base64,", html)
        self.assertIn(b"DED BUILD DEVOPS", html)

    def test_compact_payload_roundtrip(self):
        code, out, err, diff = self.run_default()
        packed = od.compact_payload(diff)
        ids, vocab = packed["rule_ids"], packed["vocab"]
        val = lambda i: None if i < 0 else vocab[i]  # noqa: E731
        for orig, comp in zip(diff["comparisons"], packed["comparisons"]):
            for row, arr in zip(orig["rows"], comp["r"]):
                self.assertEqual(
                    (ids[arr[0]], vocab[arr[1]], val(arr[2]), val(arr[3]), val(arr[4]), val(arr[5])),
                    (row["id"], row["category"], row["severity_vmaas"], row["severity_toolkit"],
                     row["baseline"], row["current"]))

    def test_script_source_is_ascii(self):
        with open(od.__file__, "rb") as f:
            self.assertFalse(re.search(rb"[^\x00-\x7f]", f.read()))

    # ---------------------------------------------------------- bad options
    def test_required_options(self):
        v = self.make_zip("v.zip", VMAAS)
        code, out, err = self.run_main("--vmaas-scan", v, "--toolkit-scan", v)
        self.assertEqual(code, 1)
        self.assertIn("--vmaas-version", err)
        code, out, err = self.run_main(*REQUIRED)
        self.assertEqual(code, 1)
        self.assertIn("--vmaas-scan", err)

    def test_empty_value_rejected(self):
        v = self.make_zip("v.zip", VMAAS)
        code, out, err = self.run_main("--vmaas-scan", v, "--toolkit-scan", v, "--vmaas-version", " ",
                                       "--toolkit-version", "1", "--app-name", "x")
        self.assertEqual(code, 1)
        self.assertIn("must not be empty", err)

    def test_zip_only(self):
        v = self.make_zip("v.zip", VMAAS)
        with open(self.path("scan.xml"), "w") as f:
            f.write(xccdf("h", {"a": ("low", "pass")}))
        shutil.copy(self.path("scan.xml"), self.path("fake.zip"))
        for bad, msg in ((self.path("scan.xml"), "must be a .zip"),
                         (self.path("missing.zip"), "not found"),
                         (self.path("fake.zip"), "not a valid zip")):
            code, out, err = self.run_main("--vmaas-scan", bad, "--toolkit-scan", v, *REQUIRED)
            self.assertEqual(code, 1, bad)
            self.assertIn(msg, err)

    def test_help_exits_zero(self):
        code, out, err = self.run_main("--help")
        self.assertEqual(code, 0)
        self.assertIn("--vmaas-scan", out)

    def test_ci_context(self):
        jenkins = {"JENKINS_URL": "https://ci/", "BUILD_NUMBER": "42", "JOB_NAME": "oscap-diff",
                   "GIT_BRANCH": "origin/main", "GIT_COMMIT": "3d3d77c0123456789"}
        self.assertEqual(od.ci_context(jenkins), "oscap-diff #42 (origin/main @ 3d3d77c0)")
        self.assertEqual(od.ci_context({"JENKINS_URL": "x", "BUILD_NUMBER": "7"}), "Jenkins #7")
        gitlab = {"CI_PIPELINE_ID": "99", "CI_COMMIT_REF_NAME": "main", "CI_COMMIT_SHORT_SHA": "abc"}
        self.assertEqual(od.ci_context(gitlab), "pipeline #99 (main @ abc)")
        self.assertEqual(od.ci_context({}), "")

    def test_no_pairs(self):
        v = self.make_zip("v.zip", {"a": {"r": ("low", "pass")}}, extras=False)
        t = self.make_zip("t.zip", {"b": {"r": ("low", "pass")}}, extras=False)
        code, out, err = self.run_main("--vmaas-scan", v, "--toolkit-scan", t, *REQUIRED,
                                       "-o", self.path("out"), "--zip", self.path("out.zip"))
        self.assertIn("no VMAAS scan could be paired", str(code))


if __name__ == "__main__":
    unittest.main()
