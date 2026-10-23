# oscap_diff

Compares **VMAAS** and **TOOLKIT** OpenSCAP scan results and produces a
self-contained HTML report of what changed. Python 3.8+, no dependencies.

Copyright (c) DED BUILD DEVOPS. All rights reserved.

## Usage

```bash
python3 oscap_diff.py --vmaas-scan vmaas.zip --toolkit-scan toolkit.zip \
  --vmaas-version 4.2.0 --toolkit-version 1.8.3 --app-name payments
```

| Option | Required | Description |
|---|---|---|
| `--vmaas-scan` | yes | Zip with the VMAAS scan results |
| `--toolkit-scan` | yes | Zip with the TOOLKIT scan results |
| `--vmaas-version` | yes | VMAAS version |
| `--toolkit-version` | yes | TOOLKIT version |
| `--app-name` | yes | Application name (shown as `payments TOOLKIT`) |
| `-o`, `--outdir` | no | Output folder (default `oscap-diff`) |
| `--zip` | no | Output zip (default `oscap-diff.zip`) |
| `--fail-on-regression` | no | Exit 2 if a rule regressed or a new rule fails |

**Inputs.** Every XCCDF/ARF result in the zips is read, including zips inside
zips; other files are skipped. Scans are paired by host and profile.

**Outputs.** `report.html` (the report) and `diff.json` (same data for tools),
in the output folder and the zip.

## Report

A PASS/FAIL verdict, the OpenSCAP, VMAAS and TOOLKIT versions, a table of all
scan pairs, and per-pair rule details with search, filters and CSV export.

| Category | Meaning |
|---|---|
| Regressed | Not failing in VMAAS, failing in TOOLKIT |
| New - failing | Only in TOOLKIT, failing |
| Fixed | Failing in VMAAS, not in TOOLKIT |
| Still failing | Failing in both |
| Changed | Other result change |
| New - not failing | Only in TOOLKIT, not failing |
| Removed rule | Only in VMAAS |
| Unchanged | Same non-failing result |

Failing = `fail`, `error` or `unknown`. Severity changes between the scans are
shown as `medium -> high`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Error (bad option, missing zip, no scans found or paired) |
| `2` | Regressed or new failing rules (only with `--fail-on-regression`) |

## Tests

```bash
python3 -m unittest -v test_oscap_diff
```
