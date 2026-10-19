#!/usr/bin/env python3
"""
oscap_diff.py - Compare two OpenSCAP scan stages and build an HTML diff report.

Each input (baseline / current) can be:
  * a .zip archive holding any number of files (nested zips are searched too)
  * a directory
  * a single XCCDF results or ARF .xml file

Every XML file found is parsed; files without an XCCDF TestResult (OVAL results,
HTML reports, logs, ...) are skipped. Each TestResult is one "scan". Baseline and
current scans are paired (by default on target host + profile) and every pair
gets its own diff in a single report.

Outputs:
  <outdir>/report.html   self-contained interactive UI (no external assets)
  <outdir>/diff.json     machine-readable diff of every pair
  <zip>                  zip archive of the above (+ the input archives if asked)

Only the Python standard library is used. Zips are read in memory and never
extracted to disk.

Usage:
  python3 oscap_diff.py scans-stage1.zip scans-stage2.zip \
      --baseline-label "pre-hardening" --current-label "post-hardening" \
      --zip oscap-diff.zip --include-inputs --fail-on-regression
"""
import argparse
import datetime
import fnmatch
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
    ("fixed", "Fixed", "Was failing, now not failing"),
    ("still_failing", "Still failing", "Failing in both scans"),
    ("changed", "Changed", "Other result change (e.g. notapplicable -> pass)"),
    ("added", "New rule", "Only present in the current scan"),
    ("removed", "Removed rule", "Only present in the baseline scan"),
    ("unchanged", "Unchanged", "Same non-failing result in both scans"),
]


def log(msg):
    print(msg, file=sys.stderr)


# --------------------------------------------------------------------------- #
# Collecting XML files from zips / directories / plain files
# --------------------------------------------------------------------------- #
def _iter_zip(data_or_path, prefix, pattern, depth):
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
                    yield from _iter_zip(io.BytesIO(zf.read(info)), name + "!/",
                                         pattern, depth + 1)
                continue
            if lower.endswith(".xml") and fnmatch.fnmatch(os.path.basename(lower), pattern):
                yield name, zf.read(info)


def collect_xml(path, pattern="*.xml"):
    """Yield (display_name, bytes) for every candidate XML file under `path`."""
    pattern = pattern.lower()
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for fn in sorted(files):
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, path)
                if fn.lower().endswith(".zip"):
                    yield from _iter_zip(full, rel + "!/", pattern, 1)
                elif fn.lower().endswith(".xml") and fnmatch.fnmatch(fn.lower(), pattern):
                    with open(full, "rb") as f:
                        yield rel, f.read()
    elif zipfile.is_zipfile(path):
        yield from _iter_zip(path, "", pattern, 1)
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


def parse_xml(name, data):
    """Return a list of scans (one per XCCDF TestResult) found in one XML document."""
    try:
        root = ET.parse(io.BytesIO(data)).getroot()
    except ET.ParseError as e:
        log(f"warning: {name} is not well-formed XML ({e}), skipped")
        return []

    rule_meta, test_results, bench_title = {}, [], ""
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
                "benchmark_title": bench_title}
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


def load_side(path, pattern):
    if not os.path.exists(path):
        sys.exit(f"error: {path} does not exist")
    scans, n_xml = [], 0
    for name, data in collect_xml(path, pattern):
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


def scan_key(scan, match_by):
    m = scan["meta"]
    if match_by == "profile":
        return (m["profile"],)
    if match_by == "filename":
        return (_stem(m["source"]),)
    return (m["target"] or _stem(m["source"]), m["profile"])  # "target" (default)


def index_side(scans, match_by, side):
    """key -> scan. If several scans share a key (e.g. results.xml and arf.xml of the
    same run), keep the one with the most rule results."""
    out = {}
    for s in scans:
        k = scan_key(s, match_by)
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
        return "added"
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


def diff_scans(baseline, current):
    rows = []
    b_rules, c_rules = baseline["rules"], current["rules"]
    for rid in sorted(set(b_rules) | set(c_rules)):
        b, c = b_rules.get(rid), c_rules.get(rid)
        info = c or b
        rows.append({
            "id": rid, "title": info["title"], "severity": info["severity"],
            "description": info["description"], "idents": info["idents"],
            "baseline": b["result"] if b else None,
            "current": c["result"] if c else None,
            "category": classify(b["result"] if b else None, c["result"] if c else None),
        })
    rank = {k: i for i, (k, _, _) in enumerate(CATEGORIES)}
    rows.sort(key=lambda r: (rank[r["category"]], SEV_ORDER.get(r["severity"], 9), r["id"]))
    counts = {k: 0 for k, _, _ in CATEGORIES}
    for r in rows:
        counts[r["category"]] += 1
    return rows, counts


def totals(scan):
    t = {}
    for r in scan["rules"].values():
        t[r["result"]] = t.get(r["result"], 0) + 1
    return t


def build_comparisons(b_idx, c_idx):
    comps = []
    for k in sorted(set(b_idx) & set(c_idx)):
        b, c = b_idx[k], c_idx[k]
        rows, counts = diff_scans(b, c)
        target = c["meta"]["target"] or b["meta"]["target"]
        profile = c["meta"]["profile"] or b["meta"]["profile"]
        label = " \u00b7 ".join(x for x in (target, short_profile(profile)) if x) or _stem(c["meta"]["source"])
        comps.append({"key": list(k), "label": label,
                      "baseline": {"meta": b["meta"], "totals": totals(b)},
                      "current": {"meta": c["meta"], "totals": totals(c)},
                      "counts": counts, "rows": rows})
    comps.sort(key=lambda c: (-c["counts"]["regressed"], c["label"]))
    unmatched = (
        [{"side": "baseline", "source": b_idx[k]["meta"]["source"], "key": list(k)}
         for k in sorted(set(b_idx) - set(c_idx))] +
        [{"side": "current", "source": c_idx[k]["meta"]["source"], "key": list(k)}
         for k in sorted(set(c_idx) - set(b_idx))])
    return comps, unmatched


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
header{padding:20px 24px 8px}
h1{margin:0 0 4px;font-size:20px}
h2.sec{font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin:22px 0 8px}
.sub{color:var(--muted);font-size:13px}
main{padding:8px 24px 40px;max-width:1400px}
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
tr.row,tr.pair{cursor:pointer} tr.row:hover td,tr.pair:hover td{background:var(--grey-bg)}
tr.pair.sel td{background:var(--sel)}
tr.detail td{background:var(--grey-bg);font-size:13px}
.rid{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--muted);word-break:break-all}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.c-regressed{background:var(--red-bg);color:var(--red)}
.c-fixed{background:var(--green-bg);color:var(--green)}
.c-still_failing{background:var(--amber-bg);color:var(--amber)}
.c-changed{background:var(--blue-bg);color:var(--blue)}
.c-added,.c-removed{background:var(--purple-bg);color:var(--purple)}
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
.empty{padding:30px;text-align:center;color:var(--muted)}
footer{color:var(--muted);font-size:12px;margin-top:16px}
@media (max-width:640px){header,main{padding-left:12px;padding-right:12px}}
</style>
</head>
<body>
<header>
  <h1>OpenSCAP Scan Diff</h1>
  <div class="sub" id="subtitle"></div>
</header>
<main>
  <div id="warnings"></div>
  <section id="overview">
    <h2 class="sec">Scan pairs</h2>
    <div class="table-wrap"><table>
      <thead><tr><th>Target &#183; profile</th><th class="num">Baseline</th><th class="num">Current</th>
        <th class="num">&#916; score</th><th class="num">Regressed</th><th class="num">Fixed</th>
        <th class="num">Still failing</th><th class="num">Rules</th></tr></thead>
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
      <option value="low">Low</option><option value="unknown">Unknown</option>
    </select>
    <button id="allBtn">Show all</button>
    <button id="chgBtn">Changes only</button>
    <button id="csvBtn">Export CSV</button>
  </div>
  <div class="sub" id="shown" style="margin-bottom:6px"></div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Status</th><th>Severity</th><th>Rule</th>
        <th>Baseline</th><th></th><th>Current</th></tr></thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>
  <footer id="footer"></footer>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
(function(){
  const D = JSON.parse(document.getElementById('data').textContent);
  const CATS = D.categories;
  const $ = id => document.getElementById(id);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const label = Object.fromEntries(CATS.map(c => [c.key, c.label]));
  const active = new Set(CATS.map(c => c.key).filter(k => k !== 'unchanged'));
  const open = new Set();
  let cur = 0;

  $('subtitle').textContent = `${D.baseline_label} \u2192 ${D.current_label}` +
    ` \u00b7 ${D.comparisons.length} scan pair(s)` + (D.pipeline ? ` \u00b7 ${D.pipeline}` : '');

  if (D.unmatched.length) {
    $('warnings').innerHTML = `<div class="warn"><b>${D.unmatched.length} scan(s) had no counterpart in the other stage</b>
      and are not compared:<ul>${D.unmatched.map(u => `<li>${esc(u.side)}: ${esc(u.source)} <span class="rid">(${esc(u.key.join(' \u00b7 '))})</span></li>`).join('')}</ul></div>`;
  }

  const fmtDelta = (a, b) => {
    if (a == null || b == null) return '';
    const d = +(b - a).toFixed(2);
    return d === 0 ? '0' : `<span class="${d > 0 ? 'delta-up' : 'delta-down'}">${d > 0 ? '+' : ''}${d}</span>`;
  };

  function drawPairs() {
    if (D.comparisons.length < 2) { $('overview').style.display = 'none'; return; }
    $('pairs').innerHTML = D.comparisons.map((c, i) => `<tr class="pair ${i === cur ? 'sel' : ''}" data-i="${i}">
      <td>${esc(c.label)}</td>
      <td class="num">${c.baseline.meta.score ?? '\u2014'}</td><td class="num">${c.current.meta.score ?? '\u2014'}</td>
      <td class="num">${fmtDelta(c.baseline.meta.score, c.current.meta.score)}</td>
      <td class="num">${c.counts.regressed ? `<span class="pill c-regressed">${c.counts.regressed}</span>` : 0}</td>
      <td class="num">${c.counts.fixed ? `<span class="pill c-fixed">${c.counts.fixed}</span>` : 0}</td>
      <td class="num">${c.counts.still_failing}</td><td class="num">${c.rows.length}</td></tr>`).join('');
  }
  $('pairs').addEventListener('click', e => {
    const tr = e.target.closest('tr.pair'); if (!tr) return;
    cur = +tr.dataset.i; open.clear(); renderPair();
  });

  function scanPanel(title, s, other) {
    const m = s.meta;
    const delta = other ? ' <span style="font-size:14px">' + fmtDelta(other.meta.score, m.score) + '</span>' : '';
    const t = Object.entries(s.totals).sort().map(([k,v]) => `${esc(k)}: ${v}`).join(' \u00b7 ');
    return `<div class="scan"><h3>${esc(title)}</h3>
      <div class="score">${m.score != null ? esc(m.score) + '<span class="sub"> / ' + esc(m.score_max) + '</span>' : '<span class="sub">no score</span>'}${other ? delta : ''}</div>
      <dl><dt>Source</dt><dd>${esc(m.source)}</dd>
      <dt>Profile</dt><dd>${esc(m.profile) || '\u2014'}</dd>
      <dt>Target</dt><dd>${esc(m.target) || '\u2014'}</dd>
      <dt>Scanned</dt><dd>${esc(m.end_time || m.start_time) || '\u2014'}</dd>
      <dt>Results</dt><dd>${t}</dd></dl></div>`;
  }

  function drawCards() {
    const C = D.comparisons[cur];
    $('cards').innerHTML = CATS.map(c => `<div class="card ${active.has(c.key) ? '' : 'off'}" data-k="${c.key}" title="${esc(c.hint)}">
      <span class="pill c-${c.key}" style="font-size:18px">${C.counts[c.key]}</span><div class="l">${esc(c.label)}</div></div>`).join('');
  }
  $('cards').addEventListener('click', e => {
    const card = e.target.closest('.card'); if (!card) return;
    const k = card.dataset.k; active.has(k) ? active.delete(k) : active.add(k);
    drawCards(); drawRows();
  });

  const resCell = r => r == null ? '<span class="r-none">absent</span>' : `<span class="r-${esc(r)}">${esc(r)}</span>`;

  function filtered() {
    const q = $('q').value.trim().toLowerCase(), sev = $('sev').value;
    return D.comparisons[cur].rows.filter(r => active.has(r.category)
      && (!sev || r.severity === sev)
      && (!q || (r.id + ' ' + r.title + ' ' + r.idents.join(' ')).toLowerCase().includes(q)));
  }

  function drawRows() {
    const rows = filtered(), total = D.comparisons[cur].rows.length;
    $('shown').textContent = `Showing ${rows.length} of ${total} rules`;
    if (!rows.length) { $('tbody').innerHTML = '<tr><td colspan="6" class="empty">No rules match the current filters.</td></tr>'; return; }
    $('tbody').innerHTML = rows.map(r => {
      let h = `<tr class="row" data-id="${esc(r.id)}">
        <td><span class="pill c-${r.category}">${esc(label[r.category])}</span></td>
        <td><span class="pill sev-${esc(r.severity)}">${esc(r.severity)}</span></td>
        <td><div>${esc(r.title)}</div><div class="rid">${esc(r.id)}</div></td>
        <td>${resCell(r.baseline)}</td><td class="arrow">\u2192</td><td>${resCell(r.current)}</td></tr>`;
      if (open.has(r.id)) h += `<tr class="detail"><td colspan="6">
          ${r.idents.length ? '<div><b>Identifiers:</b> ' + r.idents.map(esc).join(', ') + '</div>' : ''}
          <div style="margin-top:4px">${esc(r.description) || '<i>No description in scan results.</i>'}</div></td></tr>`;
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
  $('allBtn').onclick = () => { CATS.forEach(c => active.add(c.key)); drawCards(); drawRows(); };
  $('chgBtn').onclick = () => { active.clear(); ['regressed','fixed','changed','added','removed'].forEach(k => active.add(k)); drawCards(); drawRows(); };
  $('csvBtn').onclick = () => {
    const C = D.comparisons[cur], q = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';
    const lines = [['pair','status','severity','rule_id','title','baseline','current','identifiers'].join(',')]
      .concat(filtered().map(r => [C.label, label[r.category], r.severity, r.id, r.title, r.baseline ?? 'absent', r.current ?? 'absent', r.idents.join(' ')].map(q).join(',')));
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


def render_html(payload):
    data = json.dumps(payload, ensure_ascii=True)
    # Keep "</script>" and similar inside the data from ending the script block.
    data = data.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return _to_ascii(HTML_TEMPLATE.replace("__DATA__", data))


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main(argv=None):
    p = argparse.ArgumentParser(
        description="Diff two stages of OpenSCAP scans (zip, directory or XML) into an HTML report.")
    p.add_argument("baseline", help="Baseline scans: .zip, directory, or results/ARF .xml")
    p.add_argument("current", help="Current scans: .zip, directory, or results/ARF .xml")
    p.add_argument("--baseline-label", default="Baseline")
    p.add_argument("--current-label", default="Current")
    p.add_argument("--pattern", default="*.xml",
                   help="Only inspect XML files whose name matches this glob (default: *.xml), "
                        "e.g. '*-arf.xml'")
    p.add_argument("--match-by", choices=["target", "profile", "filename"], default="target",
                   help="How to pair baseline and current scans: target host + profile (default), "
                        "profile only, or file name")
    p.add_argument("-o", "--outdir", default="oscap-diff", help="Output directory (default: oscap-diff)")
    p.add_argument("--zip", default="oscap-diff.zip", help="Zip archive path (default: oscap-diff.zip)")
    p.add_argument("--include-inputs", action="store_true", help="Also put both inputs in the zip")
    p.add_argument("--fail-on-regression", action="store_true",
                   help="Exit with code 2 if any rule regressed in any pair")
    args = p.parse_args(argv)

    b_scans = load_side(args.baseline, args.pattern)
    c_scans = load_side(args.current, args.pattern)
    if not b_scans or not c_scans:
        sys.exit("error: no XCCDF scan results found in "
                 + (args.baseline if not b_scans else args.current)
                 + ". The XML files must come from `oscap xccdf eval --results` or `--results-arf`.")

    comps, unmatched = build_comparisons(index_side(b_scans, args.match_by, "baseline"),
                                         index_side(c_scans, args.match_by, "current"))
    for u in unmatched:
        log(f"warning: {u['side']} scan {u['source']} {tuple(u['key'])} has no counterpart")
    if not comps:
        sys.exit("error: no baseline scan could be paired with a current scan. "
                 "Try --match-by profile or --match-by filename.")

    pipeline = ""
    if os.environ.get("CI_PIPELINE_ID"):
        pipeline = (f"pipeline #{os.environ['CI_PIPELINE_ID']}"
                    f" ({os.environ.get('CI_COMMIT_REF_NAME', '')}"
                    f" @ {os.environ.get('CI_COMMIT_SHORT_SHA', '')})")

    payload = {
        "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "pipeline": pipeline,
        "baseline_label": args.baseline_label,
        "current_label": args.current_label,
        "categories": [{"key": k, "label": l, "hint": h} for k, l, h in CATEGORIES],
        "comparisons": comps,
        "unmatched": unmatched,
    }

    os.makedirs(args.outdir, exist_ok=True)
    html_path = os.path.join(args.outdir, "report.html")
    json_path = os.path.join(args.outdir, "diff.json")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(render_html(payload))
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    os.makedirs(os.path.dirname(os.path.abspath(args.zip)), exist_ok=True)
    with zipfile.ZipFile(args.zip, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.write(html_path, "report.html")
        z.write(json_path, "diff.json")
        if args.include_inputs:
            for side, src in (("baseline", args.baseline), ("current", args.current)):
                if os.path.isdir(src):
                    for root, _, files in os.walk(src):
                        for fn in files:
                            full = os.path.join(root, fn)
                            z.write(full, os.path.join("inputs", side, os.path.relpath(full, src)))
                else:
                    z.write(src, os.path.join("inputs", side, os.path.basename(src)))

    total_regressed = 0
    print(f"{len(comps)} scan pair(s) compared, {len(unmatched)} unmatched")
    for c in comps:
        cnt = c["counts"]
        total_regressed += cnt["regressed"]
        print(f"  {c['label'].replace(chr(0xb7), '|')}: score {c['baseline']['meta']['score']} -> {c['current']['meta']['score']}, "
              f"regressed {cnt['regressed']}, fixed {cnt['fixed']}, still failing {cnt['still_failing']}")
    print(f"Report: {html_path}\nArchive: {args.zip}")

    if args.fail_on_regression and total_regressed:
        log(f"FAIL: {total_regressed} rule(s) regressed")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
