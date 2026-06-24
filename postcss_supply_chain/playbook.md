# PostCSS Typosquat → Windows RAT — Investigation Playbook

Playbook for investigating whether a GitHub org was affected by the `abdrizak`
PostCSS-lookalike npm campaign (disclosed June 2026 by JFrog Security Research).

> **CI/CD platform note:** This playbook targets GitHub Actions. For other CI/CD
> platforms, adapt the log-collection commands — the investigation logic is the same.

> **Note for AI agents:** Most checks are read-only org/API queries you can run
> directly. The host-forensics and credential-rotation steps run on developer
> machines — hand those to the operator or use [workstation-playbook.md](workstation-playbook.md).

---

## Incident Details

In June 2026, JFrog Security Research found three malicious npm packages published
by the npm user `abdrizak`. They impersonate PostCSS tooling — chiefly
`postcss-minify-selector-parser`, a lookalike of the legitimate
`postcss-selector-parser` (150M+ weekly downloads). These are **not hijacked
legitimate packages**: every published version is attacker-authored malware. When
the package entry point is imported, an encoded blob decodes (via a chain that
includes AES-256-GCM) into a JavaScript dropper that writes and runs a PowerShell
script, which downloads and launches a Windows RAT.

### Trigger model — read this first

- **Fires on `require`/import, NOT on a `postinstall` hook.** The malicious blob
  lives in `src/config/defaults.js`, loaded when `index.js` (the entry point) is
  required. `npm install --ignore-scripts` does **not** protect against it.
- **Windows-only payload.** The PowerShell/VBS/`chost.exe` chain only runs on
  Windows. A Linux/macOS host that installed the package downloaded the malware
  to disk but the RAT chain does not execute there. Treat non-Windows hosts as
  "package present, payload did not run" — still remove the package and rotate any
  secrets that the package could have read at import time.
- **Implication for detection:** presence in a manifest/lock file means the package
  *could* have been installed; the package being **imported and run on a Windows
  host or Windows CI runner** is what confirms execution. Center detection on
  manifest/lock-file presence + Windows CI runs + Windows host forensics.

### Malicious packages

| Package | Affected versions | Poses as |
|---|---|---|
| `postcss-minify-selector-parser` | **all** (every version is malicious) | layered AES/codec helper; depends on real `postcss-selector-parser` |
| `postcss-minify-selector` | **all** | PostCSS selector minifier; depends on `postcss-minify-selector-parser` |
| `aes-decode-runner-pro` | **all** | layered AES/codec helper; depends on real `postcss-selector-parser` |

At authoring time the published versions were: `postcss-minify-selector-parser`
1.0.11–1.0.18 / 2.0.1 / 2.0.2; `postcss-minify-selector` 0.1.2–0.1.11 / 2.0.1 /
2.0.2; `aes-decode-runner-pro` 1.0.1–1.0.11. Because the whole package is malicious,
treat **any** version as compromised — including any new versions `abdrizak`
publishes after authoring.

### Exposure window

| Event | Time (UTC) |
|---|---|
| `aes-decode-runner-pro` first published | 2026-05-25 |
| `postcss-minify-selector` first published | 2026-06-04 |
| Latest malicious versions published | 2026-06-12 |
| JFrog disclosure (packages still live on npm) | 2026-06-22 |
| npm removed all three (replaced with `0.0.1-security`) | 2026-06-24 |

**Recommended scan window:** `2026-05-25T00:00:00Z` to `2026-06-24T02:00:00Z` — from
the first malicious publish to npm's takedown. The packages are no longer installable,
so the window is closed; this is now a historical-exposure hunt for orgs/hosts that
installed during the window.

### Indicators of compromise

| IOC | Value |
|---|---|
| C2 | `95.216.92.207:8080` (HTTP, RC4/ARC4-wrapped packets, MD5 checksums) |
| Payload host | `nvidiadriver[.]net` (fake NVIDIA driver site) |
| Payload file | `winpatch-xd7d.win` |
| Dropped artifacts | `%TEMP%\winPatch`, `%TEMP%.store`, `%TEMP%.host`, `settings.ps1`, `update.vbs`, `dll.zip`, `chost.exe`, `loader.py` |
| Registry persistence | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value `csshost` |
| Attacker | npm user `abdrizak` |
| RAT module hashes (SHA-256) | `audiodriver` `164e322d6fbc62e254d73583acd7f39444c884d3f5e6a5d27db143fc25bc88b3`; `api` `50ffce607867d8fa8eaf6ef5cd25a3c0e7e4415e881b9e55c04a67bcddb74fdf`; `auto` `17832aa629524ef6e8d8d6e9b6b902a8d324b559e3c36dbd0e221ab1690be871`; `command` `c8075bbff748096e1c6a1ea0aa67bb6762fdd7551427a12425b35b94c1f1ecf2`; `config` `f6669bd504ce6b0e303be7ee47f2ebbc062989c88c41f0a3f436044a24869798`; `util` `282b9bc318ad1234cbd1b86424b784299b8be31545802a7c6b751166b814b990` |

### What IS affected

- Any repo whose `package.json` or lock file references one of the three packages
  (any version) — they are 100% malicious.
- **Transitive installs** within this set: `postcss-minify-selector` pulls
  `postcss-minify-selector-parser`. (The two `*-parser`/`runner` packages also
  depend on the *legitimate* `postcss-selector-parser` as cover — depending on the
  real package is **not** itself a signal.)
- Windows developer machines / Windows CI runners that imported any of the three
  packages — these are where the RAT actually executes.

### What is NOT affected

- A dependency on the **legitimate** `postcss-selector-parser` (150M+ weekly
  downloads). This is the real package the malware impersonates and depends on — a
  reference to it is not a compromise.
- Other PostCSS packages (`postcss`, `cssnano`, `postcss-minify-selectors` — note
  the legitimate cssnano plugin is `postcss-minify-selectors`, **plural**, which is
  a different, benign package).
- Non-Windows hosts ran no RAT payload (package present but chain did not execute) —
  remove the package and rotate import-time-readable secrets, but no host RAT cleanup.

### Lock file protection

Lock files (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) help here only by
recording exactly which packages resolved. Unlike the axios incident, there is **no
"safe version" to pin to** — every version is malicious. A lock file that contains
any of the three package names is evidence the malicious package was resolved.
The fix is removal, not a version bump.

- A committed lock file naming one of the three packages → that package was installed.
- `npm ci` / `yarn install --frozen-lockfile` only stop *new* drift; they do not
  help if the malicious package is already in the lock file.

---

## Setup

```bash
export ORG="<your-github-org>"
export SINCE="2026-05-25T00:00:00Z"
export UNTIL="2026-06-24T02:00:00Z"             # npm takedown — window is closed
export LOG_DIR="/tmp/supply-chain-scan-postcss"
mkdir -p "$LOG_DIR"

# The three malicious package names (alternation for grep)
PKGS="postcss-minify-selector-parser|postcss-minify-selector|aes-decode-runner-pro"
```

**Log caching:** If `$LOG_DIR` already has logs from a previous run, reuse them —
skip the download step.

**Write to files, not context:** Results can be large. Write structured evidence
(CSV) to `$LOG_DIR` as you go. Don't accumulate findings in conversation context.

**Rate limits:** Before scanning a large org, check your GitHub API budget:
```bash
gh api /rate_limit --jq '.resources.core | "\(.remaining)/\(.limit) remaining (resets \(.reset | todate))"'
```
Code search: ~30 req/min. REST API: 5,000 req/hr. Use `xargs -P 10` for parallelism,
cache everything to `$LOG_DIR`.

---

## Phase 1: Repo Analysis

**Goal:** Find every repo that references any of the three malicious packages in a
manifest, lock file, Dockerfile, or workflow. Because the packages are 100%
malicious, **any** reference is a finding — there is no "in range / out of range"
nuance as with a version-specific CVE.

### 1. Find all references across the org

```bash
for pkg in postcss-minify-selector-parser postcss-minify-selector aes-decode-runner-pro; do
  # Gate on total_count first to save rate-limit budget
  total=$(gh api "search/code?q=${pkg}+org:${ORG}&per_page=1" --jq '.total_count' 2>/dev/null)
  echo "$pkg: $total matches"
  if [ "${total:-0}" -gt 0 ]; then
    gh api "search/code?q=${pkg}+org:${ORG}&per_page=100" \
      --jq ".items[] | \"$pkg\t\(.repository.full_name)\t\(.path)\"" 2>/dev/null
  fi
  sleep 2
done | sort -u > "$LOG_DIR/refs.tsv"
cat "$LOG_DIR/refs.tsv"
```

**Disambiguation:** `postcss-minify-selector-parser` is a substring of itself and a
near-match of the benign plural `postcss-minify-selectors`. Confirm each hit names
one of the three exact packages, not the legitimate `postcss-selector-parser` or
`postcss-minify-selectors`.

For orgs over ~50 repos, code search caps out — shallow-clone the org and grep
locally instead:
```bash
grep -rEn "\"(postcss-minify-selector-parser|postcss-minify-selector|aes-decode-runner-pro)\"" \
  --include=package.json --include=package-lock.json --include=yarn.lock --include=pnpm-lock.yaml .
```

### 2. For each reference, record where it lives

For every repo/path hit, classify the file:

- **`package.json`** — direct dependency declared. Note the version spec.
- **`package-lock.json` / `yarn.lock` / `pnpm-lock.yaml`** — package actually
  resolved. Note the resolved version and `resolved` URL (should point at npm).
- **Dockerfile** — `RUN npm install` with the package in `package.json` bakes it
  into the image.
- **`.github/workflows/*.yml`** — direct `npm install <pkg>` in a `run:` step.

```bash
# Manifest / lock content for a specific hit
gh api "repos/${ORG}/<repo>/contents/<path>" --jq '.content' | base64 -d \
  | grep -inE "postcss-minify-selector-parser|postcss-minify-selector|aes-decode-runner-pro"
```

### 3. Write the repo evidence table

Write `$LOG_DIR/evidence-repos.csv`:

```
repo,path,source_type,package,version_seen,os_target,can_have_executed
```

| Column | What to write |
|---|---|
| `repo` | Repo name (no org prefix) |
| `path` | File path where the reference was found |
| `source_type` | `manifest` / `lockfile` / `dockerfile` / `ci-workflow` |
| `package` | Which of the three packages |
| `version_seen` | Exact version from the lock file, or the manifest spec |
| `os_target` | `windows` / `linux` / `macos` / `mixed` — what platform the repo's CI/build runs on (the RAT only runs on Windows) |
| `can_have_executed` | `yes` if the package is present AND a Windows host/runner could have imported it; `no (non-windows only)` if the build is Linux/macOS only; `unknown` if unclear |

**Rules:** any of the three package names present = the package was pulled. No blank
cells. The `os_target` column matters here — it scopes where the RAT could have run.

---

## Phase 2: CI Run Analysis

**Why:** Phase 1 finds repos that *name* the packages. CI logs confirm whether the
package was actually installed and — critically — whether it ran on a **Windows**
runner where the RAT chain executes.

### 1. Find runs during the exposure window

```bash
gh api "/orgs/${ORG}/repos" --paginate --jq '.[].name' | while read repo; do
  gh api "repos/${ORG}/${repo}/actions/runs?created=${SINCE}..${UNTIL}&per_page=100" \
    --jq ".workflow_runs[] | \"${repo}|\(.id)|\(.name)\"" 2>/dev/null
done > "$LOG_DIR/all_runs.txt"
```

### 2. Download logs in parallel

Skip if `$LOG_DIR` already has logs from a previous run.

```bash
cat "$LOG_DIR/all_runs.txt" | while IFS='|' read repo run_id name; do
  echo "$repo $run_id"
done | xargs -P 10 -L 1 bash -c \
  'gh run view "$1" --repo "${ORG}/$0" --log > "${LOG_DIR}/run-$1.log" 2>/dev/null && echo "OK: $0 $1" || echo "FAIL: $0 $1"'
```

### 3. Scan for the packages and IOCs

GitHub Actions log lines are tab-prefixed (`<workflow>\t<step>\t<timestamp> content`) —
don't anchor patterns with `^`.

```bash
# Package install lines
grep -rliE "postcss-minify-selector-parser|postcss-minify-selector|aes-decode-runner-pro" "$LOG_DIR"/run-*.log

# IOCs (network + payload + persistence)
grep -rliE "nvidiadriver\.net|95\.216\.92\.207|winpatch-xd7d|winPatch|settings\.ps1|update\.vbs|csshost" "$LOG_DIR"/run-*.log

# Windows runners specifically (where the RAT executes)
grep -rliE "windows|win32|win-amd64|Runner.Worker.*Windows" "$LOG_DIR"/run-*.log
```

> **Positive control:** prove the grep works before trusting a clean result. Run it
> against a string you *know* is in the logs (e.g. `grep -rliE "npm (ci|install)"
> "$LOG_DIR"/run-*.log` — every Node repo's CI logs that). A zero-hit grep and a
> *broken* grep look identical; a working positive control distinguishes them.

### 4. Classify hits

**Real install indicators:**
- `added postcss-minify-selector...@<version>` (verbose npm output)
- `npm http fetch GET https://registry.npmjs.org/postcss-minify-selector...`
- `npm ci` / `yarn install` lines are silent per-package — confirm the package via
  the committed lock file, not per-package log output.

**False positives (ignore):**
- The legitimate `postcss-selector-parser` and the benign `postcss-minify-selectors`
  (plural).
- Branch names / env vars containing `postcss`.

**Windows vs non-Windows:** a confirmed install on a `windows-latest` runner =
the RAT chain ran. The same install on `ubuntu-latest` / `macos-latest` = package
on disk, RAT did not execute.

### 5. Write the CI runs evidence table

Write `$LOG_DIR/evidence-ci-runs.csv`:

```
repo,run_id,workflow,platform,package_installed,version,iocs_found,rat_executed,verdict
```

| Column | What to write |
|---|---|
| `platform` | `windows-latest`, `ubuntu-latest`, `macos-latest`, self-hosted, etc. |
| `package_installed` | Which of the three, or `none` |
| `iocs_found` | `yes (which IOC)` or `no` |
| `rat_executed` | `yes` only if a malicious package installed **and** the runner was Windows; `no (non-windows)` if installed on Linux/macOS; `no` if not installed |
| `verdict` | `compromised` / `package-present-no-execution` / `clean` |

---

## Phase 3: Network Investigation (Firewall / Proxy / DNS Logs)

Check network telemetry for contact with the C2 / payload infrastructure during or
after the exposure window.

| IOC | Where to search |
|---|---|
| DNS resolution of `nvidiadriver.net` | DNS logs, DNS proxy, Route 53 Resolver, Cloudflare Gateway |
| Connection to `95.216.92.207` | Firewall logs, VPC flow logs, proxy logs |
| Connection to port `8080` on that IP | Firewall / proxy logs |
| HTTP GET of `winpatch-xd7d.win` | Proxy logs with URL visibility |

**Example queries**

Splunk:
```
index=firewall dest_ip="95.216.92.207" OR dest_port=8080
| stats count by src_ip, dest_ip, dest_port, action
```
```
index=dns query="nvidiadriver.net" | stats count by src_ip, query, answer
```

AWS CloudWatch Logs Insights (VPC Flow Logs):
```
filter dstAddr = "95.216.92.207" | stats count(*) as hits by srcAddr, dstPort, action
```

**Time window:** from `2026-05-25T00:00:00Z` to now — the RAT persists and beacons
after initial infection, so search past the install date.

**Interpretation:** any successful connection to `95.216.92.207:8080`, or a DNS
lookup of `nvidiadriver.net`, means a host fetched/ran the payload. Treat that source
host as compromised and rotate every credential on it.

---

## Phase 4: Workstation Investigation

Windows developer machines that imported any of the three packages are where the RAT
actually runs — and where persistence (registry Run key + `%TEMP%` artifacts) survives
package removal. Use the dedicated [workstation-playbook.md](workstation-playbook.md)
on each suspect machine. It covers:

1. RAT artifact detection (`%TEMP%\winPatch`, `chost.exe`, the six `.pyd` hashes)
2. Registry persistence (`HKCU\...\Run` value `csshost`) and scheduled tasks
3. npm cache + local lock-file / `node_modules` scanning for the three packages
4. Network indicators (active connections to `95.216.92.207`, DNS for `nvidiadriver.net`)
5. Chrome credential-theft exposure (the RAT targets saved logins)
6. AI-agent conversation-log forensics (with self-pollution exclusion)

### Exfiltration / new-repo check

```bash
gh api --paginate "/orgs/$ORG/repos?per_page=100&sort=created&direction=desc" \
  --jq '.[] | select(.created_at > "2026-05-25T00:00:00Z") | "\(.name) | \(.created_at) | \(.visibility)"'
```

---

## Phase 5: Present Results

Return three deliverables:

1. **`evidence-repos.csv`** — which repos reference the malicious packages and on what
   platform they build.
2. **`evidence-ci-runs.csv`** — what installed during the window and whether it ran on
   a Windows runner (RAT executed).
3. **Executive summary** — verdict (`compromised` / `package-present-no-execution` /
   `clean`), repos scanned, CI runs analyzed, whether C2/payload IOCs appeared in
   network logs, and whether any Windows workstation showed RAT artifacts.

**Action routing:**
- `verdict = compromised` (Windows install or network IOC or host artifact) → full
  incident response: Phase 6.
- `verdict = package-present-no-execution` (non-Windows only) → remove the package,
  rotate import-time-readable secrets, no host re-image.
- `verdict = clean` → no action.

---

## Phase 6: Hardening & Remediation (User Approval Required)

**Do NOT proceed without explicit user approval.** Present findings first, then ask.

### If compromised (Windows install, network IOC, or host artifact found):

1. **Remove persistence FIRST** on each infected Windows host — delete the `csshost`
   value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and the
   `%TEMP%\winPatch`, `%TEMP%.store`, `%TEMP%.host` artifacts. Package removal alone
   leaves the RAT running.
2. **Rotate all secrets** stored on or accessible from infected machines — Chrome
   saved logins (the RAT's primary target, incl. app-bound-encryption bypass), SSH
   keys, cloud creds, npm/registry tokens, API keys, signing keys.
3. **Remove the packages** from every manifest and lock file; reinstall from a clean
   cache (`npm cache clean --force`).
4. **Rebuild Docker images** built during the window with `--no-cache`.
5. **Block IOCs at the network edge**: `nvidiadriver.net` and `95.216.92.207`.
6. **Re-image** infected Windows workstations — in-place cleaning may miss persistence.

### Hardening (all orgs):

| Attack surface | Fix |
|---|---|
| Lookalike package slipped past review | Add the three names to a deny list; review new deps against typosquat distance to popular packages |
| `npm install` resolves unknown latest | Use `npm ci` / `yarn install --frozen-lockfile` and commit lock files |
| Trust in `--ignore-scripts` | Note it does **not** help here — the payload runs on `require`, not `postinstall` |
| Docker image pinned by tag | Pin to digest (`@sha256:...`) |
