# oscap_diff

Compares two sets of OpenSCAP scan results, **VMAAS** and **TOOLKIT**, and
produces a self-contained HTML report of what changed, plus a JSON file with
the same data. It runs in Jenkins (`Jenkinsfile`) or GitLab CI (`.gitlab-ci.yml`).

Copyright (c) DED BUILD DEVOPS. All rights reserved.

## Requirements

- Python 3.8 or newer
- Nothing else: only the Python standard library is used

## Quick start

```bash
python3 oscap_diff.py \
  --vmaas-scan vmaas.zip \
  --toolkit-scan toolkit.zip \
  --vmaas-version 4.2.0 \
  --toolkit-version 1.8.3 \
  --app-name payments
```

Then open `oscap-diff/report.html` in a browser. The same report and
`diff.json` are also packed into `oscap-diff.zip`.

## Options

| Option | Required | Description |
|---|---|---|
| `--vmaas-scan ZIP` | yes | Zip file with the VMAAS scan results |
| `--toolkit-scan ZIP` | yes | Zip file with the TOOLKIT scan results |
| `--vmaas-version` | yes | VMAAS version, shown at the top of the report |
| `--toolkit-version` | yes | TOOLKIT version, shown at the top of the report |
| `--app-name` | yes | Application name, shown at the top of the report and put in front of the TOOLKIT label (`payments TOOLKIT`) |
| `-o`, `--outdir` | no | Output folder (default `oscap-diff`) |
| `--zip` | no | Output zip path (default `oscap-diff.zip`) |
| `--fail-on-regression` | no | Exit with code 2 if any rule regressed or a new rule fails |
| `-h`, `--help` | no | Show the options |

Required values cannot be empty. In CI, an unset parameter or variable expands
to an empty string, so the build fails with a clear message instead of
producing a report with blank fields.

## Input zips

- `--vmaas-scan` and `--toolkit-scan` must be `.zip` files.
- A zip may hold any number of files, in any folder layout. Zips inside the zip
  are searched too, up to two levels deep (a zip in a zip in your zip).
- Every `.xml` file is read. Results from `oscap xccdf eval --results` and
  `--results-arf` are both supported.
- Anything that is not an XCCDF scan result is skipped: HTML reports, OVAL
  result files, logs, and malformed XML (with a warning).
- Zips are read in memory; nothing is extracted to disk.

### How scans are paired

Each scan result (XCCDF `TestResult`) is one scan. A VMAAS scan is compared with
the TOOLKIT scan that has the **same target host and profile**. If a result has
no target, its file name is used instead.

- If the same host and profile appear twice on one side (for example both
  `results.xml` and `arf.xml` from one run), the one with more rules is used.
- A scan with no counterpart on the other side is listed as a warning at the
  top of the report and in the job log, and is not compared.

## The report

From top to bottom:

1. **Verdict.** `FAIL` (red) if any rule regressed or a new rule fails on any
   scan pair, otherwise `PASS` (green), with totals across all pairs.
2. **Versions.** OpenSCAP version (read from the scan files), application name,
   VMAAS version and TOOLKIT version. If VMAAS and TOOLKIT were scanned with
   different OpenSCAP versions, both are shown.
3. **Warnings.** Scans that had no counterpart.
4. **Scan pairs.** One row per host and profile: scores, score change, and the
   number of regressed, new failing, fixed, still failing and severity-changed
   rules. Pairs with regressions or new failures are listed first. The
   **Only scan pairs with changes** checkbox hides pairs where nothing changed.
   Click a row to see that pair's details below.
5. **Pair details.** VMAAS and TOOLKIT panels (score, source file, OpenSCAP
   version, profile, host, scan time, result totals), then the rule table.

### Rule categories

| Category | Meaning |
|---|---|
| Regressed | Was not failing in VMAAS, failing in TOOLKIT |
| New - failing | Only in TOOLKIT, and failing there |
| Fixed | Was failing in VMAAS, not failing in TOOLKIT |
| Still failing | Failing in both |
| Changed | Another result change, e.g. `notapplicable` to `pass` |
| New - not failing | Only in TOOLKIT, not failing there (`pass`, `notapplicable`, ...) |
| Removed rule | Only in VMAAS |
| Unchanged | Same non-failing result in both |

"Failing" means a result of `fail`, `error` or `unknown`.

Each category card above the rule table toggles that category on or off. By
default everything except **Unchanged** is shown. **Show all** turns every
category on; **Changes only** shows only rules whose result changed.

### Severity changes

If a rule has a different severity in the two scans (for example after a
security content update), the rule table shows both, e.g. `medium -> high`. The
**Severity changed** card keeps these rules visible whatever their category.

### Search, filters and export

- Search by rule ID, title or CCE identifier.
- Filter by severity (High, Medium, Low, Info, Unknown) or by
  **Severity changed**.
- Click a rule to see its identifiers and description.
- **Export CSV** downloads the rules currently shown.

The report works offline, in light and dark mode, and contains only ASCII
characters, so it displays correctly whatever encoding the browser assumes.

## Output files

The output folder and the output zip both contain:

- `report.html`: the report described above, in a single file.
- `diff.json`: the same results for other tools. Main fields:
  - `summary`: verdict and totals across all pairs
  - `vmaas_version`, `toolkit_version`, `app_name`, `oscap_versions`
  - `rules`: title, description and identifiers of every rule, stored once
  - `comparisons`: one entry per scan pair with both scans' details, `counts`
    per category, `has_changes`, and `rows` (one per rule: ID, category, VMAAS
    and TOOLKIT result and severity, `severity_changed`)
  - `unmatched`: scans with no counterpart

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Error: a required option is missing or invalid, a scan zip is not found, no scan results were found, or no scans could be paired |
| `2` | Only with `--fail-on-regression`: a rule regressed or a new rule fails. The report is still written |

Exit code `2` never means anything else, so CI can treat it as "unstable"
rather than "failed".

## Jenkins

The `Jenkinsfile` at the root of the repository defines the pipeline. Create a
Pipeline job (or Multibranch Pipeline) pointing at this GitHub repository.

**Stages**

1. **Test** runs the unit tests. A broken script never produces a report.
2. **Get scans** checks that the two scan zips exist. Put the step that fetches
   them here, for example with the Copy Artifact plugin (an example is in the
   file).
3. **Report** runs `oscap_diff.py`.

**Parameters**

| Parameter | Default | Description |
|---|---|---|
| `VMAAS_SCAN` | `scans/vmaas.zip` | Path of the VMAAS scan zip in the workspace |
| `TOOLKIT_SCAN` | `scans/toolkit.zip` | Path of the TOOLKIT scan zip in the workspace |
| `VMAAS_VERSION` | (empty) | VMAAS version, required |
| `TOOLKIT_VERSION` | (empty) | TOOLKIT version, required |
| `APP_NAME` | (empty) | Application name, required |
| `FAIL_ON_REGRESSION` | on | Mark the build UNSTABLE on regressed or new failing rules |

Jenkins only learns the parameters after the first run, so the very first
build runs with the defaults (empty versions) and fails on purpose. Use
**Build with Parameters** from then on, or pass the values from an upstream
job.

**Build result**

| Result | When |
|---|---|
| SUCCESS | No regressed or new failing rules |
| UNSTABLE | Rules regressed or new rules fail (with `FAIL_ON_REGRESSION`) |
| FAILURE | Tests failed, a scan zip or required parameter is missing, or any other error |

**Where to find the report**

- Build page > **Build Artifacts**: `oscap-diff-<build>.zip`, `report.html`
  and `diff.json`, kept for every build.
- Build page > **OpenSCAP diff**, if the HTML Publisher plugin is installed.
- The report subtitle shows the job name, build number, branch and commit.

**If the report looks broken in Jenkins.** By default, Jenkins serves archived
files with a strict Content-Security-Policy that blocks JavaScript, so the
report appears without its tables and filters. Ask your Jenkins administrator
to set a **Resource Root URL** (Manage Jenkins > Security), which serves these
files from a separate address without that restriction. Until then, download
the zip and open `report.html` locally. Turning the policy off for the whole
Jenkins instance is not recommended.

**Agent requirements.** `python3` (3.8 or newer) on the agent, nothing else.
With the Docker Pipeline plugin you can use `agent { docker { image
'python:3.12-slim' } }` instead of `agent any`.

## GitLab CI

`.gitlab-ci.yml` contains an equivalent example pipeline: a `test` stage, then
the `oscap_diff` job with `VMAAS_VERSION`, `TOOLKIT_VERSION` and `APP_NAME` as
CI/CD variables. `allow_failure: exit_codes: [2]` turns regressions and new
failures into a warning (orange); remove it to block the pipeline. In GitLab the
report subtitle shows the pipeline number, branch and commit.

## Tests

```bash
python3 -m unittest -v test_oscap_diff
```

The tests build small scan zips on the fly and check the categories, severity
changes, summary, exit codes, option validation, output files and report
safety. The Jenkins **Test** stage (and the GitLab `test` job) runs them
first in every build.

## Troubleshooting

- **Diamond `?` characters in the report.** The script file was damaged while
  being copied, often by pasting it into an email. Get it from the repository
  instead and check it with `sha256sum oscap_diff.py`.
- **"no XCCDF scan results found".** The zip contains no `oscap xccdf eval`
  results. Check that the scan jobs save `--results` or `--results-arf` files.
- **"no VMAAS scan could be paired".** The two zips have no host and profile in
  common. Check that both stages scanned the same hosts with the same profile.
- **"OpenSCAP version: unknown".** The scan files do not record the version.
  This does not affect the comparison.
