#!/usr/bin/env python3
# Copyright (c) DED BUILD DEVOPS. All rights reserved.
"""
oscap_diff.py - Compare VMAAS and TOOLKIT OpenSCAP scans and build an HTML diff report.

--vmaas-scan and --toolkit-scan each take a .zip file holding any number of
files (zips inside it are searched too). Every XML file found is parsed; files
without an XCCDF TestResult (OVAL results, HTML reports, logs, ...) are skipped.
Each TestResult is one "scan". VMAAS and TOOLKIT scans are paired on target
host + profile and every pair gets its own diff in a single report.

--app-name is put in front of the TOOLKIT label, e.g. "payments TOOLKIT".
The OpenSCAP version is read from the scan results.

Outputs:
  <outdir>/report.html   self-contained interactive UI (no external assets)
  <outdir>/diff.json     machine-readable diff of every pair
  <zip>                  zip archive of the two files above

Only the Python standard library is used. Zips are read in memory and never
extracted to disk.

Usage:
  python3 oscap_diff.py --vmaas-scan vmaas.zip --toolkit-scan toolkit.zip \
      --vmaas-version 4.2.0 --toolkit-version 1.8.3 --app-name payments \
      --zip oscap-diff.zip --fail-on-regression
"""
import argparse
import datetime
import io
import json
import os
import re
import sys
import zipfile
import xml.etree.ElementTree as ET

FAILING = {"fail", "error", "unknown"}
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3, "unknown": 4}
MAX_MEMBER_BYTES = 1024 * 1024 * 1024  # skip zip members bigger than 1 GiB
MAX_ZIP_DEPTH = 3
CATEGORIES = [
    ("regressed", "Regressed", "Was not failing, now failing"),
    ("added_failing", "New \u2013 failing", "Only present in the {cur} scan, and failing there"),
    ("fixed", "Fixed", "Was failing, now not failing"),
    ("still_failing", "Still failing", "Failing in both scans"),
    ("changed", "Changed", "Other result change (e.g. notapplicable -> pass)"),
    ("added_passing", "New \u2013 not failing",
     "Only present in the {cur} scan, not failing there (pass, notapplicable, ...)"),
    ("removed", "Removed rule", "Only present in the {base} scan"),
    ("unchanged", "Unchanged", "Same non-failing result in both scans"),
]


def log(msg):
    print(msg, file=sys.stderr)


# --------------------------------------------------------------------------- #
# Collecting XML files from zips / directories / plain files
# --------------------------------------------------------------------------- #
def _iter_zip(data_or_path, prefix, depth):
    try:
        zf = zipfile.ZipFile(data_or_path)
    except zipfile.BadZipFile:
        log(f"warning: {prefix or data_or_path} is not a valid zip, skipped")
        return
    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = f"{prefix}{info.filename}"
            lower = info.filename.lower()
            if info.file_size > MAX_MEMBER_BYTES:
                log(f"warning: {name} is larger than {MAX_MEMBER_BYTES} bytes, skipped")
                continue
            if lower.endswith(".zip"):
                if depth < MAX_ZIP_DEPTH:
                    yield from _iter_zip(io.BytesIO(zf.read(info)), name + "!/", depth + 1)
                continue
            if lower.endswith(".xml"):
                yield name, zf.read(info)


def collect_xml(path):
    """Yield (display_name, bytes) for every candidate XML file under `path`."""
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for fn in sorted(files):
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, path)
                if fn.lower().endswith(".zip"):
                    yield from _iter_zip(full, rel + "!/", 1)
                elif fn.lower().endswith(".xml"):
                    with open(full, "rb") as f:
                        yield rel, f.read()
    elif zipfile.is_zipfile(path):
        yield from _iter_zip(path, "", 1)
    else:
        with open(path, "rb") as f:
            yield os.path.basename(path), f.read()


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def _local(tag):
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _text(el, limit=None):
    if el is None:
        return ""
    txt = " ".join("".join(el.itertext()).split())
    if limit and len(txt) > limit:
        txt = txt[:limit].rstrip() + "\u2026"
    return txt


def oscap_version(test_system):
    """'cpe:/a:redhat:openscap:1.3.10' -> '1.3.10' ('' if not an OpenSCAP CPE)."""
    m = re.search(r"open-?scap:([0-9][\w.\-]*)", test_system or "", re.I)
    return m.group(1) if m else ""


def parse_xml(name, data):
    """Return a list of scans (one per XCCDF TestResult) found in one XML document."""
    try:
        root = ET.parse(io.BytesIO(data)).getroot()
    except ET.ParseError as e:
        log(f"warning: {name} is not well-formed XML ({e}), skipped")
        return []

    rule_meta, test_results, bench_title, oval_oscap = {}, [], "", ""
    for el in root.iter():
        n = _local(el.tag)
        if n == "Rule" and el.get("id"):
            title, desc, idents = "", "", []
            for child in el:
                ln = _local(child.tag)
                if ln == "title" and not title:
                    title = _text(child)
                elif ln == "description" and not desc:
                    desc = _text(child, limit=800)
                elif ln == "ident":
                    idents.append(_text(child))
            rule_meta[el.get("id")] = {"title": title, "description": desc,
                                       "severity": el.get("severity", ""), "idents": idents}
        elif n == "TestResult":
            test_results.append(el)
        elif n == "generator" and not oval_oscap:
            # OVAL results in ARF files: <generator><product_name>...open-scap...</product_name>
            # <product_version>1.3.10</product_version>
            prod = {_local(c.tag): _text(c) for c in el}
            if "scap" in prod.get("product_name", "").lower().replace("-", ""):
                oval_oscap = prod.get("product_version", "")
        elif n == "Benchmark" and not bench_title:
            for child in el:
                if _local(child.tag) == "title":
                    bench_title = _text(child)
                    break

    scans = []
    for tr in test_results:
        meta = {"source": name, "test_result_id": tr.get("id", ""),
                "start_time": tr.get("start-time", ""), "end_time": tr.get("end-time", ""),
                "profile": "", "target": "", "score": None, "score_max": None,
                "benchmark_title": bench_title,
                "oscap_version": oscap_version(tr.get("test-system", "")) or oval_oscap}
        rules = {}
        for child in tr:
            ln = _local(child.tag)
            if ln == "profile":
                meta["profile"] = child.get("idref", "")
            elif ln == "target" and not meta["target"]:
                meta["target"] = _text(child)
            elif ln == "score" and meta["score"] is None:
                try:
                    meta["score"] = round(float(_text(child)), 2)
                    meta["score_max"] = float(child.get("maximum", "100"))
                except ValueError:
                    pass
            elif ln == "rule-result":
                rid = child.get("idref")
                result, idents = "unknown", []
                for sub in child:
                    sln = _local(sub.tag)
                    if sln == "result":
                        result = _text(sub).lower()
                    elif sln == "ident":
                        idents.append(_text(sub))
                m = rule_meta.get(rid, {})
                rules[rid] = {
                    "result": result,
                    "severity": (child.get("severity") or m.get("severity") or "unknown").lower(),
                    "title": m.get("title") or rid,
                    "description": m.get("description", ""),
                    "idents": sorted(set(idents or m.get("idents", []))),
                }
        if rules:
            scans.append({"meta": meta, "rules": rules})
    return scans


def load_side(path):
    if not os.path.exists(path):
        sys.exit(f"error: {path} does not exist")
    scans, n_xml = [], 0
    for name, data in collect_xml(path):
        n_xml += 1
        scans.extend(parse_xml(name, data))
    log(f"{path}: {n_xml} XML file(s) inspected, {len(scans)} scan result(s) found")
    return scans


# --------------------------------------------------------------------------- #
# Pairing
# --------------------------------------------------------------------------- #
def short_profile(p):
    return re.sub(r"^xccdf_[^_]+(_[^_]+)*?_profile_", "", p) or p


def _stem(name):
    base = os.path.basename(name.split("!/")[-1])
    base = re.sub(r"\.xml$", "", base, flags=re.I)
    # drop common result-file suffixes so "web01-arf.xml" ~ "web01-results.xml"
    return re.sub(r"[-_.]?(arf|results?|xccdf)$", "", base, flags=re.I)


def scan_key(scan):
    """Pair scans on target host + profile (file name if the scan has no target)."""
    m = scan["meta"]
    return (m["target"] or _stem(m["source"]), m["profile"])


def index_side(scans, side):
    """key -> scan. If several scans share a key (e.g. results.xml and arf.xml of the
    same run), keep the one with the most rule results."""
    out = {}
    for s in scans:
        k = scan_key(s)
        prev = out.get(k)
        if prev is None or len(s["rules"]) > len(prev["rules"]):
            if prev is not None:
                log(f"note: {side}: {prev['meta']['source']} and {s['meta']['source']} "
                    f"share key {k}; using the one with more rules")
            out[k] = s
    return out


# --------------------------------------------------------------------------- #
# Diffing
# --------------------------------------------------------------------------- #
def classify(base, cur):
    if base is None:
        return "added_failing" if cur in FAILING else "added_passing"
    if cur is None:
        return "removed"
    b_fail, c_fail = base in FAILING, cur in FAILING
    if not b_fail and c_fail:
        return "regressed"
    if b_fail and not c_fail:
        return "fixed"
    if b_fail and c_fail:
        return "still_failing"
    return "unchanged" if base == cur else "changed"


def diff_scans(baseline, current, rule_text):
    """Diff two scans. Rule title/description/identifiers go into `rule_text`
    (shared by all pairs) instead of being repeated in every row."""
    rows = []
    b_rules, c_rules = baseline["rules"], current["rules"]
    for rid in sorted(set(b_rules) | set(c_rules)):
        b, c = b_rules.get(rid), c_rules.get(rid)
        info = c or b
        if rid not in rule_text:
            rule_text[rid] = {"title": info["title"], "description": info["description"],
                              "idents": info["idents"]}
        b_sev, c_sev = (b["severity"] if b else None), (c["severity"] if c else None)
        rows.append({
            "id": rid, "severity": info["severity"],
            "severity_vmaas": b_sev, "severity_toolkit": c_sev,
            "severity_changed": bool(b and c and b_sev != c_sev),
            "baseline": b["result"] if b else None,
            "current": c["result"] if c else None,
            "category": classify(b["result"] if b else None, c["result"] if c else None),
        })
    rank = {k: i for i, (k, _, _) in enumerate(CATEGORIES)}
    rows.sort(key=lambda r: (rank[r["category"]], SEV_ORDER.get(r["severity"], 9), r["id"]))
    counts = {k: 0 for k, _, _ in CATEGORIES}
    for r in rows:
        counts[r["category"]] += 1
    counts["severity_changed"] = sum(r["severity_changed"] for r in rows)
    return rows, counts


CHANGE_KEYS = ("regressed", "added_failing", "fixed", "changed", "added_passing", "removed",
               "severity_changed")


def summarize(comps, unmatched):
    """Totals across all pairs. FAIL when any rule regressed or a new rule fails."""
    keys = ("regressed", "added_failing", "fixed", "still_failing", "severity_changed")
    tot = {k: sum(c["counts"][k] for c in comps) for k in keys}
    for c in comps:
        c["has_changes"] = any(c["counts"][k] for k in CHANGE_KEYS)
    failing = sum(1 for c in comps if c["counts"]["regressed"] or c["counts"]["added_failing"])
    return dict(tot, verdict="FAIL" if failing else "PASS", pairs=len(comps), pairs_failing=failing,
                pairs_changed=sum(c["has_changes"] for c in comps), unmatched=len(unmatched))


def totals(scan):
    t = {}
    for r in scan["rules"].values():
        t[r["result"]] = t.get(r["result"], 0) + 1
    return t


def build_comparisons(b_idx, c_idx):
    comps, rule_text = [], {}
    for k in sorted(set(b_idx) & set(c_idx)):
        b, c = b_idx[k], c_idx[k]
        rows, counts = diff_scans(b, c, rule_text)
        target = c["meta"]["target"] or b["meta"]["target"]
        profile = c["meta"]["profile"] or b["meta"]["profile"]
        label = " \u00b7 ".join(x for x in (target, short_profile(profile)) if x) or _stem(c["meta"]["source"])
        comps.append({"key": list(k), "label": label,
                      "baseline": {"meta": b["meta"], "totals": totals(b)},
                      "current": {"meta": c["meta"], "totals": totals(c)},
                      "counts": counts, "rows": rows})
    comps.sort(key=lambda c: (-(c["counts"]["regressed"] + c["counts"]["added_failing"]),
                              -c["counts"]["regressed"], c["label"]))
    unmatched = (
        [{"side": "baseline", "source": b_idx[k]["meta"]["source"], "key": list(k)}
         for k in sorted(set(b_idx) - set(c_idx))] +
        [{"side": "current", "source": c_idx[k]["meta"]["source"], "key": list(k)}
         for k in sorted(set(c_idx) - set(b_idx))])
    return comps, unmatched, rule_text


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenSCAP Scan Diff</title>
<style>
:root{
  --bg:#f6f7f9;--panel:#fff;--text:#1d2330;--muted:#5f6b7a;--border:#dde2e8;
  --red:#c62828;--red-bg:#fdecec;--green:#2e7d32;--green-bg:#e8f5e9;
  --amber:#b26a00;--amber-bg:#fff4e0;--blue:#1f5fbf;--blue-bg:#e8f0fc;
  --grey-bg:#eef0f3;--purple:#6a3fb5;--purple-bg:#f1ebfb;--sel:#e3ecfa;
}
@media (prefers-color-scheme: dark){:root{
  --bg:#12151b;--panel:#1b2029;--text:#e4e8ee;--muted:#98a3b3;--border:#2c3340;
  --red:#ff7b7b;--red-bg:#3a1f22;--green:#7fd18a;--green-bg:#1c3324;
  --amber:#ffc266;--amber-bg:#3a2e1a;--blue:#7fb0ff;--blue-bg:#1c2a42;
  --grey-bg:#262c37;--purple:#c4a8ff;--purple-bg:#2b2340;--sel:#22314a;}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
  font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{padding:20px 24px 8px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.logo{height:52px;width:auto;border-radius:8px;display:block}
h1{margin:0 0 4px;font-size:20px}
h2.sec{font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin:22px 0 8px}
.sub{color:var(--muted);font-size:13px}
main{padding:8px 24px 40px;max-width:1400px}
.verdict{border-radius:8px;padding:12px 16px;margin:14px 0 10px;border:1px solid var(--border)}
.verdict.fail{background:var(--red-bg);color:var(--red);border-color:var(--red)}
.verdict.pass{background:var(--green-bg);color:var(--green);border-color:var(--green)}
.verdict .vh{font-size:16px;font-weight:700}
.verdict .vd{font-size:13px;margin-top:3px;color:var(--text);opacity:.85}
.sechead{display:flex;align-items:flex-end;justify-content:space-between;gap:12px;flex-wrap:wrap}
.toggle{font-size:13px;color:var(--muted);margin:22px 0 8px;cursor:pointer;user-select:none}
.toggle input{vertical-align:-2px;margin-right:6px}
.versions{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:10px 14px;margin:10px 0;display:grid;grid-template-columns:max-content 1fr;gap:4px 24px}
.versions>div{display:contents}
.versions .vk{color:var(--muted)}
.versions b{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.warn{background:var(--amber-bg);color:var(--amber);border-radius:8px;padding:10px 14px;margin:10px 0;font-size:13px}
.warn ul{margin:4px 0 0;padding-left:18px}
.scans{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px;margin:12px 0}
.scan{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:12px 14px}
.scan h3{margin:0 0 6px;font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.scan .score{font-size:26px;font-weight:600}
.scan dl{display:grid;grid-template-columns:auto 1fr;gap:2px 10px;margin:6px 0 0;font-size:12px}
.scan dt{color:var(--muted)} .scan dd{margin:0;word-break:break-all}
.delta-up{color:var(--green)} .delta-down{color:var(--red)}
.cards{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}
.card{cursor:pointer;border:1px solid var(--border);background:var(--panel);border-radius:8px;
  padding:8px 12px;min-width:120px;user-select:none}
.card .l{font-size:12px;color:var(--muted);margin-top:2px}
.card.off{opacity:.4}
.sevcard{border-style:dashed}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0 12px}
input[type=search],select{background:var(--panel);color:var(--text);border:1px solid var(--border);
  border-radius:6px;padding:6px 10px;font:inherit}
input[type=search]{flex:1;min-width:220px}
button{background:var(--panel);color:var(--text);border:1px solid var(--border);border-radius:6px;
  padding:6px 10px;font:inherit;cursor:pointer}
.table-wrap{overflow-x:auto;background:var(--panel);border:1px solid var(--border);border-radius:8px}
table{border-collapse:collapse;width:100%}
th,td{padding:8px 10px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}
th{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.03em;
  position:sticky;top:0;background:var(--panel)}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
#overview table{table-layout:fixed;min-width:1100px}
#overview th:first-child{width:28%}
#overview th.num,#overview td.num{text-align:center}
#overview th{vertical-align:bottom}
#overview td:first-child{overflow-wrap:anywhere}
tr.row,tr.pair{cursor:pointer} tr.row:hover td,tr.pair:hover td{background:var(--grey-bg)}
tr.pair.sel td{background:var(--sel)}
tr.detail td{background:var(--grey-bg);font-size:13px}
.rid{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--muted);word-break:break-all}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.c-regressed{background:var(--red-bg);color:var(--red)}
.c-fixed{background:var(--green-bg);color:var(--green)}
.c-still_failing{background:var(--amber-bg);color:var(--amber)}
.c-changed{background:var(--blue-bg);color:var(--blue)}
.c-added_failing{background:var(--red-bg);color:var(--red);outline:1px dashed var(--red);outline-offset:-1px}
.c-added_passing,.c-removed{background:var(--purple-bg);color:var(--purple)}
.c-unchanged{background:var(--grey-bg);color:var(--muted)}
.r-fail,.r-error{color:var(--red);font-weight:600}
.r-pass,.r-fixed{color:var(--green);font-weight:600}
.r-unknown{color:var(--amber);font-weight:600}
.r-none{color:var(--muted);font-style:italic}
.sev-high{background:var(--red-bg);color:var(--red)}
.sev-medium{background:var(--amber-bg);color:var(--amber)}
.sev-low{background:var(--blue-bg);color:var(--blue)}
.sev-info,.sev-unknown{background:var(--grey-bg);color:var(--muted)}
.arrow{color:var(--muted);padding:0 4px}
.sevchg{white-space:nowrap}
.empty{padding:30px;text-align:center;color:var(--muted)}
footer{color:var(--muted);font-size:12px;margin-top:24px;padding-top:12px;border-top:1px solid var(--border);display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
.copy{font-weight:600;letter-spacing:.02em}
@media (max-width:640px){header,main{padding-left:12px;padding-right:12px}}
</style>
</head>
<body>
<header>
  __LOGO__
  <div>
    <h1>OpenSCAP Scan Diff</h1>
    <div class="sub" id="subtitle"></div>
  </div>
</header>
<main>
  <div id="verdict" class="verdict"></div>
  <div id="versions" class="versions"></div>
  <div id="warnings"></div>
  <section id="overview">
    <div class="sechead"><h2 class="sec">Scan pairs</h2>
      <label class="toggle"><input type="checkbox" id="onlyChg"> Only scan pairs with changes</label></div>
    <div class="table-wrap"><table>
      <thead><tr><th>Target &#183; profile</th><th class="num lbl-b"></th><th class="num lbl-c"></th>
        <th class="num">&#916; score</th><th class="num">Regressed</th><th class="num">New failing</th><th class="num">Fixed</th>
        <th class="num">Still failing</th><th class="num">Severity changed</th><th class="num">Rules</th></tr></thead>
      <tbody id="pairs"></tbody>
    </table></div>
  </section>
  <h2 class="sec" id="pairTitle"></h2>
  <section class="scans" id="scans"></section>
  <section class="cards" id="cards"></section>
  <div class="toolbar">
    <input type="search" id="q" placeholder="Search rule id, title, CCE&#8230;">
    <select id="sev">
      <option value="">All severities</option>
      <option value="high">High</option><option value="medium">Medium</option>
      <option value="low">Low</option><option value="info">Info</option>
      <option value="unknown">Unknown</option>
      <option value="__changed">Severity changed</option>
    </select>
    <button id="allBtn">Show all</button>
    <button id="chgBtn">Changes only</button>
    <button id="csvBtn">Export CSV</button>
  </div>
  <div class="sub" id="shown" style="margin-bottom:6px"></div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Status</th><th>Severity</th><th>Rule</th>
        <th class="lbl-b"></th><th></th><th class="lbl-c"></th></tr></thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>
  <footer><span id="footer"></span><div class="copy">__COPYRIGHT__</div></footer>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
(function(){
  const D = JSON.parse(document.getElementById('data').textContent);
  // Expand the compact encoding written by compact_payload() in oscap_diff.py.
  (function expand() {
    const V = D.vocab, ids = D.rule_ids, val = i => i < 0 ? null : V[i];
    D.rules = {};
    ids.forEach((id, i) => { const x = D.rule_list[i]; D.rules[id] = {title: x[0], description: x[1], idents: x[2]}; });
    D.comparisons.forEach(c => {
      c.rows = c.r.map(a => {
        const sv = val(a[2]), st = val(a[3]);
        return {id: ids[a[0]], category: V[a[1]], severity_vmaas: sv, severity_toolkit: st,
                severity: st ?? sv, severity_changed: sv != null && st != null && sv !== st,
                baseline: val(a[4]), current: val(a[5])};
      });
      delete c.r;
    });
    delete D.rule_list; delete D.vocab; delete D.rule_ids;
  })();
  const CATS = D.categories;
  const RT = id => D.rules[id] || {title: id, description: '', idents: []};
  const $ = id => document.getElementById(id);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const label = Object.fromEntries(CATS.map(c => [c.key, c.label]));
  const SEVCHG = 'severity_changed';
  const active = new Set(CATS.map(c => c.key).filter(k => k !== 'unchanged'));
  active.add(SEVCHG);
  const open = new Set();
  let cur = 0;

  document.querySelectorAll('.lbl-b').forEach(e => e.textContent = D.baseline_label);
  document.querySelectorAll('.lbl-c').forEach(e => e.textContent = D.current_label);
  const sideLabel = s => s === 'baseline' ? D.baseline_label : D.current_label;
  $('subtitle').textContent = `${D.baseline_label} \u2192 ${D.current_label}` +
    ` \u00b7 ${D.comparisons.length} scan pair(s)` + (D.pipeline ? ` \u00b7 ${D.pipeline}` : '');

  const ov = D.oscap_versions, ovV = ov.vmaas.join(', '), ovT = ov.toolkit.join(', ');
  const oscapLine = !ovV && !ovT ? '<i>unknown</i>'
    : ovV === ovT && ov.vmaas.length === 1 ? `<b>${esc(ovV)}</b>`
    : `<b>${esc(D.baseline_label)}: ${esc(ovV || 'unknown')} \u00b7 ${esc(D.current_label)}: ${esc(ovT || 'unknown')}</b>`;
  const S = D.summary, plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
  $('verdict').className = 'verdict ' + S.verdict.toLowerCase();
  $('verdict').innerHTML = (S.verdict === 'FAIL'
      ? `<div class="vh">FAIL \u00b7 ${[S.regressed && plural(S.regressed, 'regressed rule'), S.added_failing && plural(S.added_failing, 'new failing rule')].filter(Boolean).join(' and ')} on ${S.pairs_failing} of ${plural(S.pairs, 'scan pair')}</div>`
      : `<div class="vh">PASS \u00b7 No regressed or new failing rules on ${plural(S.pairs, 'scan pair')}</div>`) +
    `<div class="vd">Fixed ${S.fixed} \u00b7 Still failing ${S.still_failing} \u00b7 Severity changed ${S.severity_changed}` +
    ` \u00b7 ${S.pairs_changed} of ${plural(S.pairs, 'scan pair')} with changes` +
    (S.unmatched ? ` \u00b7 ${plural(S.unmatched, 'unmatched scan')}` : '') + `</div>`;

  $('versions').innerHTML =
    `<div><span class="vk">OpenSCAP version</span>${oscapLine}</div>` +
    `<div><span class="vk">Application</span><b>${esc(D.app_name)}</b></div>` +
    `<div><span class="vk">${esc(D.baseline_label)} version</span><b>${esc(D.vmaas_version)}</b></div>` +
    `<div><span class="vk">${esc(D.current_label)} version</span><b>${esc(D.toolkit_version)}</b></div>`;

  if (D.unmatched.length) {
    $('warnings').innerHTML = `<div class="warn"><b>${D.unmatched.length} scan(s) had no counterpart in the other stage</b>
      and are not compared:<ul>${D.unmatched.map(u => `<li>${esc(sideLabel(u.side))}: ${esc(u.source)} <span class="rid">(${esc(u.key.join(' \u00b7 '))})</span></li>`).join('')}</ul></div>`;
  }

  const fmtDelta = (a, b) => {
    if (a == null || b == null) return '';
    const d = +(b - a).toFixed(2);
    return d === 0 ? '0' : `<span class="${d > 0 ? 'delta-up' : 'delta-down'}">${d > 0 ? '+' : ''}${d}</span>`;
  };

  function drawPairs() {
    if (D.comparisons.length < 2) { $('overview').style.display = 'none'; return; }
    const only = $('onlyChg').checked;
    const list = D.comparisons.map((c, i) => [c, i]).filter(([c]) => !only || c.has_changes);
    if (!list.length) { $('pairs').innerHTML = '<tr><td colspan="10" class="empty">No scan pair has changes.</td></tr>'; return; }
    $('pairs').innerHTML = list.map(([c, i]) => `<tr class="pair ${i === cur ? 'sel' : ''}" data-i="${i}">
      <td>${esc(c.label)}</td>
      <td class="num">${c.baseline.meta.score ?? '\u2014'}</td><td class="num">${c.current.meta.score ?? '\u2014'}</td>
      <td class="num">${fmtDelta(c.baseline.meta.score, c.current.meta.score)}</td>
      <td class="num">${c.counts.regressed ? `<span class="pill c-regressed">${c.counts.regressed}</span>` : 0}</td>
      <td class="num">${c.counts.added_failing ? `<span class="pill c-added_failing">${c.counts.added_failing}</span>` : 0}</td>
      <td class="num">${c.counts.fixed ? `<span class="pill c-fixed">${c.counts.fixed}</span>` : 0}</td>
      <td class="num">${c.counts.still_failing}</td>
      <td class="num">${c.counts.severity_changed ? `<span class="pill c-changed">${c.counts.severity_changed}</span>` : 0}</td>
      <td class="num">${c.rows.length}</td></tr>`).join('');
  }
  $('onlyChg').addEventListener('change', drawPairs);
  $('pairs').addEventListener('click', e => {
    const tr = e.target.closest('tr.pair'); if (!tr) return;
    cur = +tr.dataset.i; open.clear(); renderPair();
  });

  function scanPanel(title, s, other) {
    const m = s.meta;
    const dv = other ? fmtDelta(other.meta.score, m.score) : '';
    const delta = dv && dv !== '0' ? ' <span style="font-size:14px">' + dv + '</span>' : '';
    const t = Object.entries(s.totals).sort().map(([k,v]) => `${esc(k)}: ${v}`).join(' \u00b7 ');
    return `<div class="scan"><h3>${esc(title)}</h3>
      <div class="score">${m.score != null ? esc(m.score) + '<span class="sub"> / ' + esc(m.score_max) + '</span>' : '<span class="sub">no score</span>'}${other ? delta : ''}</div>
      <dl><dt>Source</dt><dd>${esc(m.source)}</dd>
      <dt>OpenSCAP</dt><dd>${esc(m.oscap_version) || '\u2014'}</dd>
      <dt>Profile</dt><dd>${esc(m.profile) || '\u2014'}</dd>
      <dt>Target</dt><dd>${esc(m.target) || '\u2014'}</dd>
      <dt>Scanned</dt><dd>${esc(m.end_time || m.start_time) || '\u2014'}</dd>
      <dt>Results</dt><dd>${t}</dd></dl></div>`;
  }

  function drawCards() {
    const C = D.comparisons[cur];
    $('cards').innerHTML = CATS.map(c => `<div class="card ${active.has(c.key) ? '' : 'off'}" data-k="${c.key}" title="${esc(c.hint)}">
      <span class="pill c-${c.key}" style="font-size:18px">${C.counts[c.key]}</span><div class="l">${esc(c.label)}</div></div>`).join('') +
      `<div class="card sevcard ${active.has(SEVCHG) ? '' : 'off'}" data-k="${SEVCHG}" title="Rules whose severity differs between ${esc(D.baseline_label)} and ${esc(D.current_label)}. When on, they are shown whatever their status.">
      <span class="pill c-changed" style="font-size:18px">${C.counts.severity_changed}</span><div class="l">Severity changed</div></div>`;
  }
  $('cards').addEventListener('click', e => {
    const card = e.target.closest('.card'); if (!card) return;
    const k = card.dataset.k; active.has(k) ? active.delete(k) : active.add(k);
    drawCards(); drawRows();
  });

  const sevPill = v => `<span class="pill sev-${esc(v)}">${esc(v)}</span>`;
  const sevCell = r => r.severity_changed
    ? `<span class="sevchg" title="Severity changed between ${esc(D.baseline_label)} and ${esc(D.current_label)}">${sevPill(r.severity_vmaas)}<span class="arrow">\u2192</span>${sevPill(r.severity_toolkit)}</span>`
    : sevPill(r.severity);
  const resCell = r => r == null ? '<span class="r-none">absent</span>' : `<span class="r-${esc(r)}">${esc(r)}</span>`;

  function filtered() {
    const q = $('q').value.trim().toLowerCase(), sev = $('sev').value;
    return D.comparisons[cur].rows.filter(r => (active.has(r.category) || (active.has(SEVCHG) && r.severity_changed))
      && (!sev || (sev === '__changed' ? r.severity_changed : r.severity === sev))
      && (!q || (r.id + ' ' + RT(r.id).title + ' ' + RT(r.id).idents.join(' ')).toLowerCase().includes(q)));
  }

  function drawRows() {
    const rows = filtered(), total = D.comparisons[cur].rows.length;
    $('shown').textContent = `Showing ${rows.length} of ${total} rules`;
    if (!rows.length) { $('tbody').innerHTML = '<tr><td colspan="6" class="empty">No rules match the current filters.</td></tr>'; return; }
    $('tbody').innerHTML = rows.map(r => {
      const t = RT(r.id);
      let h = `<tr class="row" data-id="${esc(r.id)}">
        <td><span class="pill c-${r.category}">${esc(label[r.category])}</span></td>
        <td>${sevCell(r)}</td>
        <td><div>${esc(t.title)}</div><div class="rid">${esc(r.id)}</div></td>
        <td>${resCell(r.baseline)}</td><td class="arrow">\u2192</td><td>${resCell(r.current)}</td></tr>`;
      if (open.has(r.id)) h += `<tr class="detail"><td colspan="6">
          ${t.idents.length ? '<div><b>Identifiers:</b> ' + t.idents.map(esc).join(', ') + '</div>' : ''}
          <div style="margin-top:4px">${esc(t.description) || '<i>No description in scan results.</i>'}</div></td></tr>`;
      return h;
    }).join('');
  }
  $('tbody').addEventListener('click', e => {
    const tr = e.target.closest('tr.row'); if (!tr) return;
    const id = tr.dataset.id; open.has(id) ? open.delete(id) : open.add(id); drawRows();
  });

  function renderPair() {
    const C = D.comparisons[cur];
    $('pairTitle').textContent = C.label;
    $('scans').innerHTML = scanPanel(D.baseline_label, C.baseline) + scanPanel(D.current_label, C.current, C.baseline);
    drawPairs(); drawCards(); drawRows();
  }

  $('q').addEventListener('input', drawRows);
  $('sev').addEventListener('change', drawRows);
  $('allBtn').onclick = () => { CATS.forEach(c => active.add(c.key)); active.add(SEVCHG); drawCards(); drawRows(); };
  $('chgBtn').onclick = () => { active.clear(); ['regressed','added_failing','fixed','changed','added_passing','removed',SEVCHG].forEach(k => active.add(k)); drawCards(); drawRows(); };
  $('csvBtn').onclick = () => {
    const C = D.comparisons[cur], q = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';
    const lines = [['pair','status','severity',D.baseline_label + ' severity',D.current_label + ' severity','rule_id','title',D.baseline_label,D.current_label,'identifiers'].map(q).join(',')]
      .concat(filtered().map(r => [C.label, label[r.category], r.severity, r.severity_vmaas ?? 'absent', r.severity_toolkit ?? 'absent', r.id, RT(r.id).title, r.baseline ?? 'absent', r.current ?? 'absent', RT(r.id).idents.join(' ')].map(q).join(',')));
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([lines.join('\n')], {type: 'text/csv'}));
    a.download = 'oscap-diff-' + C.label.replace(/[^\w.-]+/g, '_') + '.csv'; a.click();
  };
  $('footer').textContent = `Generated ${D.generated} by oscap_diff.py`;
  renderPair();
})();
</script>
</body>
</html>
"""


def _to_ascii(page):
    """Make the page pure ASCII so it renders correctly whatever encoding the
    browser assumes (file://, GitLab artifact viewer, proxies...). Non-ASCII
    characters become \\uXXXX escapes inside <script> blocks and &#N; entities
    everywhere else."""
    parts = re.split(r"(<script\b.*?</script>)", page, flags=re.S)
    out = []
    for i, part in enumerate(parts):
        if i % 2:  # script block
            out.append("".join(c if ord(c) < 128 else json.dumps(c)[1:-1] for c in part))
        else:
            out.append(part.encode("ascii", "xmlcharrefreplace").decode("ascii"))
    return "".join(out)


# Built-in header logo (STET), PNG, base64-encoded. Lines are kept short so the
# file survives copy/paste. To replace it: base64 -w76 new-logo.png
LOGO_MIME = "image/png"
LOGO_B64 = (
    "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"
    "rkJggg=="
)

VMAAS_LABEL = "VMAAS"
TOOLKIT_LABEL = "TOOLKIT"

COPYRIGHT_OWNER = "DED BUILD DEVOPS"


def logo_tag():
    if not LOGO_B64:
        return ""
    return f'<img class="logo" alt="STET" src="data:{LOGO_MIME};base64,{LOGO_B64}">'


def compact_payload(payload):
    """Encode rows as small integer arrays for the HTML page (decoded by its script).
    A row becomes [rule, category, VMAAS severity, TOOLKIT severity, VMAAS result,
    TOOLKIT result], each an index into `rule_ids` / `vocab` (-1 = absent)."""
    rule_ids = list(payload["rules"])
    rule_pos = {rid: i for i, rid in enumerate(rule_ids)}
    vocab, vpos = [], {}

    def v(x):
        if x is None:
            return -1
        if x not in vpos:
            vpos[x] = len(vocab)
            vocab.append(x)
        return vpos[x]

    comps = []
    for c in payload["comparisons"]:
        c2 = {k: val for k, val in c.items() if k != "rows"}
        c2["r"] = [[rule_pos[r["id"]], v(r["category"]), v(r["severity_vmaas"]), v(r["severity_toolkit"]),
                    v(r["baseline"]), v(r["current"])] for r in c["rows"]]
        comps.append(c2)
    out = {k: val for k, val in payload.items() if k not in ("rules", "comparisons")}
    out.update({"rule_ids": rule_ids, "vocab": vocab, "comparisons": comps,
                "rule_list": [[payload["rules"][rid]["title"], payload["rules"][rid]["description"],
                               payload["rules"][rid]["idents"]] for rid in rule_ids]})
    return out


def render_html(payload, logo=""):
    data = json.dumps(compact_payload(payload), ensure_ascii=True, separators=(",", ":"))
    # Keep "</script>" and similar inside the data from ending the script block.
    data = data.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    year = datetime.datetime.now(datetime.timezone.utc).year
    copyright_html = f"&copy; {year} {COPYRIGHT_OWNER}. All rights reserved."
    return _to_ascii(HTML_TEMPLATE.replace("__LOGO__", logo)
                     .replace("__COPYRIGHT__", copyright_html)
                     .replace("__DATA__", data))


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
class _Parser(argparse.ArgumentParser):
    """Exit with 1 (not argparse's default 2) on bad options, so that exit code 2
    only ever means 'regressed or new failing rules found'."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


def ci_context(env):
    """Describe the CI run (Jenkins or GitLab) for the report subtitle; '' outside CI."""
    if env.get("JENKINS_URL") and env.get("BUILD_NUMBER"):
        branch = env.get("BRANCH_NAME") or env.get("GIT_BRANCH", "")
        commit = env.get("GIT_COMMIT", "")[:8]
        text = f"{env.get('JOB_NAME', 'Jenkins')} #{env['BUILD_NUMBER']}"
        extra = " @ ".join(x for x in (branch, commit) if x)
        return f"{text} ({extra})" if extra else text
    if env.get("CI_PIPELINE_ID"):
        return (f"pipeline #{env['CI_PIPELINE_ID']}"
                f" ({env.get('CI_COMMIT_REF_NAME', '')} @ {env.get('CI_COMMIT_SHORT_SHA', '')})")
    return ""


def main(argv=None):
    p = _Parser(
        description="Diff VMAAS and TOOLKIT OpenSCAP scan zips into an HTML report.")
    req = p.add_argument_group("required")
    req.add_argument("--vmaas-scan", required=True, metavar="ZIP",
                     help="Zip file with the VMAAS scan results (zips inside it are searched too)")
    req.add_argument("--toolkit-scan", required=True, metavar="ZIP",
                     help="Zip file with the TOOLKIT scan results (zips inside it are searched too)")
    req.add_argument("--vmaas-version", required=True, help="VMAAS version shown in the report")
    req.add_argument("--toolkit-version", required=True, help="TOOLKIT version shown in the report")
    req.add_argument("--app-name", required=True,
                     help="Application name, put in front of the TOOLKIT label (e.g. 'payments TOOLKIT')")
    p.add_argument("-o", "--outdir", default="oscap-diff", help="Output directory (default: oscap-diff)")
    p.add_argument("--zip", default="oscap-diff.zip", help="Zip archive path (default: oscap-diff.zip)")
    p.add_argument("--fail-on-regression", action="store_true",
                   help="Exit with code 2 if any rule regressed, or a new rule fails, in any pair")
    args = p.parse_args(argv)
    for opt in ("vmaas_version", "toolkit_version", "app_name"):
        val = (getattr(args, opt) or "").strip()
        if not val:  # e.g. an unset CI variable expands to ""
            p.error(f"--{opt.replace('_', '-')} must not be empty")
        setattr(args, opt, val)
    for opt in ("vmaas_scan", "toolkit_scan"):
        path, flag = getattr(args, opt), "--" + opt.replace("_", "-")
        if not path.lower().endswith(".zip"):
            p.error(f"{flag} must be a .zip file, got {path}")
        if not os.path.isfile(path):
            p.error(f"{flag}: file {path} not found")
        if not zipfile.is_zipfile(path):
            p.error(f"{flag}: {path} is not a valid zip file")
    vmaas_label = VMAAS_LABEL
    toolkit_label = f"{args.app_name} {TOOLKIT_LABEL}"

    v_scans = load_side(args.vmaas_scan)
    t_scans = load_side(args.toolkit_scan)
    if not v_scans or not t_scans:
        sys.exit("error: no XCCDF scan results found in "
                 + (args.vmaas_scan if not v_scans else args.toolkit_scan)
                 + ". The XML files must come from `oscap xccdf eval --results` or `--results-arf`.")

    comps, unmatched, rule_text = build_comparisons(index_side(v_scans, vmaas_label),
                                         index_side(t_scans, toolkit_label))
    for u in unmatched:
        side = vmaas_label if u["side"] == "baseline" else toolkit_label
        log(f"warning: {side} scan {u['source']} {tuple(u['key'])} has no counterpart")
    if not comps:
        sys.exit("error: no VMAAS scan could be paired with a TOOLKIT scan "
                 "(scans are paired on target host + profile).")

    pipeline = ci_context(os.environ)

    payload = {
        "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "pipeline": pipeline,
        "vmaas_version": args.vmaas_version,
        "toolkit_version": args.toolkit_version,
        "app_name": args.app_name,
        "oscap_versions": {
            "vmaas": sorted({s["meta"]["oscap_version"] for s in v_scans} - {""}),
            "toolkit": sorted({s["meta"]["oscap_version"] for s in t_scans} - {""}),
        },
        "baseline_label": vmaas_label,
        "current_label": toolkit_label,
        "categories": [{"key": k, "label": l,
                        "hint": h.format(base=vmaas_label, cur=toolkit_label)}
                       for k, l, h in CATEGORIES],
        "summary": summarize(comps, unmatched),
        "rules": rule_text,
        "comparisons": comps,
        "unmatched": unmatched,
    }

    os.makedirs(args.outdir, exist_ok=True)
    html_path = os.path.join(args.outdir, "report.html")
    json_path = os.path.join(args.outdir, "diff.json")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(render_html(payload, logo_tag()))
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=1, ensure_ascii=False)

    os.makedirs(os.path.dirname(os.path.abspath(args.zip)), exist_ok=True)
    with zipfile.ZipFile(args.zip, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.write(html_path, "report.html")
        z.write(json_path, "diff.json")

    ovs = payload["oscap_versions"]
    print(f"OpenSCAP version: {vmaas_label} {', '.join(ovs['vmaas']) or 'unknown'}, "
          f"{toolkit_label} {', '.join(ovs['toolkit']) or 'unknown'}")
    print(f"{vmaas_label} version: {args.vmaas_version}")
    print(f"{toolkit_label} version: {args.toolkit_version}")
    print(f"{len(comps)} scan pair(s) compared, {len(unmatched)} unmatched")
    for c in comps:
        cnt = c["counts"]
        print(f"  {c['label'].replace(chr(0xb7), '|')}: score {c['baseline']['meta']['score']} -> {c['current']['meta']['score']}, "
              f"regressed {cnt['regressed']}, new failing {cnt['added_failing']}, fixed {cnt['fixed']}, "
              f"still failing {cnt['still_failing']}, severity changed {cnt['severity_changed']}")
    sm = payload["summary"]
    if sm["verdict"] == "FAIL":
        print(f"Verdict: FAIL - {sm['regressed']} regressed, {sm['added_failing']} new failing "
              f"on {sm['pairs_failing']} of {sm['pairs']} scan pair(s)")
    else:
        print(f"Verdict: PASS - no regressed or new failing rules on {sm['pairs']} scan pair(s)")
    print(f"Report: {html_path}\nArchive: {args.zip}")

    if args.fail_on_regression and sm["verdict"] == "FAIL":
        log(f"FAIL: {sm['regressed']} rule(s) regressed, {sm['added_failing']} new rule(s) failing")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
