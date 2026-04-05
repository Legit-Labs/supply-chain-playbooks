# Axios Supply Chain Compromise — Investigation Playbook

Playbook for investigating whether a GitHub org was affected by the axios npm
supply chain compromise (March 31, 2026).

> **CI/CD platform note:** This playbook targets GitHub Actions. For other CI/CD
> platforms, adapt the log collection commands — the investigation logic is the same.

---

## Incident Details

On March 31, 2026, two compromised versions of the `axios` npm package were published
using hijacked maintainer credentials (`jasonsaayman`, email changed to `ifstap@proton.me`).
Both versions inject a phantom dependency `plain-crypto-js@4.2.1` whose `postinstall`
script deploys a cross-platform RAT.

### Compromised versions

| Package | Version | Shasum |
|---|---|---|
| axios | 1.14.1 | `2553649f2322049666871cea80a5d0d6adc700ca` |
| axios | 0.30.4 | `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71` |
| plain-crypto-js | 4.2.1 | `07d889e2dadce6f3910dcbc253317d28ca61c766` |

### Exposure window

| Event | Time (UTC) |
|---|---|
| `plain-crypto-js@4.2.0` published (clean decoy) | March 30, 05:57 |
| `plain-crypto-js@4.2.1` published (malicious) | March 30, 23:59 |
| `axios@1.14.1` published | March 31, 00:21 |
| `axios@0.30.4` published | March 31, 01:00 |
| Both axios versions unpublished | March 31, ~03:15 |
| `plain-crypto-js` security hold | March 31, 03:25 |

**Recommended scan window (padded):** `2026-03-31T00:00:00Z` to `2026-03-31T05:00:00Z`

### Indicators of compromise

| IOC | Value |
|---|---|
| C2 domain | `sfrclak.com` |
| C2 IP | `142.11.206.73` |
| C2 port | `8000` |
| C2 endpoint | `/6202033` |
| Phantom dependency | `plain-crypto-js` (never imported in axios source) |
| Attacker emails | `ifstap@proton.me`, `nrwise@proton.me` |
| RAT path (macOS) | `/Library/Caches/com.apple.act.mond` |
| RAT path (Windows) | `%PROGRAMDATA%\wt.exe`, `%TEMP%\6202033.vbs`, `%TEMP%\6202033.ps1` |
| RAT path (Linux) | `/tmp/ld.py` |
| Anti-forensics | Malware deletes `setup.js`, replaces `package.json` with clean stub |

### What IS affected

- Any `npm install` that resolved `axios@1.14.1` or `axios@0.30.4` during the window
- **Transitive installs** — `npm install <some-package>` where that package
  depends on `axios@^1.x` or `axios@^0.x`. This is especially dangerous because
  axios may not appear anywhere in the CI log output at default verbosity.
  Many popular npm packages depend on axios transitively.
- Docker image builds that run `npm install` during the window
- Developer machines that installed or upgraded axios during the window

### What is NOT affected

- Installs from a committed lock file with `npm ci` (lock file pins exact version)
- Any axios version other than 1.14.1 and 0.30.4
- Pre-built Docker images that were not rebuilt during the window
- `npm install <package>` where the package does NOT depend on axios (directly
  or transitively)

### Lock file protection

Lock files (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) **DO protect**
against this attack — they are the primary defense:
- `npm ci` installs exactly what the lock file specifies
- If the lock file pins `axios@1.13.2`, there is no path to `1.14.1`
- The malicious `plain-crypto-js` is never downloaded, so its `postinstall` never runs

Lock files do NOT help if:
- No lock file is committed
- CI uses `npm install` (can update the lock file and resolve to latest)
- The lock file was generated during the exposure window
- CI runs `npm install <package>` for a package **not in the lock file** — the
  lock file only covers packages it already contains. Dynamically installed
  packages resolve from the registry regardless of the lock file.

---

## Setup

```bash
export ORG="<your-github-org>"
export SINCE="2026-03-31T00:00:00Z"
export UNTIL="2026-03-31T05:00:00Z"
export LOG_DIR="/tmp/supply-chain-scan-axios"
mkdir -p "$LOG_DIR"
```

**Log caching:** If `$LOG_DIR` already has logs from a previous run, reuse them —
skip the download step.

**Write to files, not context:** Results can be large. Write structured data to
CSV files in `$LOG_DIR` as you go. Don't accumulate findings in conversation context.

**Rate limits:** Before scanning a large org, check your GitHub API budget:
```bash
gh api /rate_limit --jq '.resources.core | "\(.remaining)/\(.limit) remaining (resets \(.reset | todate))"'
```
Code search: ~30 req/min. REST API: 5,000 req/hr. Log downloads count against REST.
Use `xargs -P 10` for parallelism, cache everything to `$LOG_DIR`.

---

## Phase 1: Repo Analysis

**Goal:** For every repo that references axios, build a static picture of its
dependency configuration — what version is declared, what's locked, what the CI
install command does, and whether the configuration is vulnerable in principle.

### 1. Find all references to axios

```bash
gh api "search/code?q=axios+org:${ORG}&per_page=100" \
  --jq '.items[] | "\(.repository.full_name)\t\(.path)"' | sort -u > "$LOG_DIR/refs.tsv"
```

Paginate (`&page=2`, etc.) if more than 100 results. Code search is throttled at
~30 req/min — add `sleep 2` between pages.

### 2. For each reference, extract version data

For every repo/path that has axios in a dependency file, collect:

- **Manifest spec** — the version specifier from `package.json`
  (e.g. `^1.13.6`, `^1.2.6`, `~1.14.0`). Copy it exactly as written.
- **Lock file version** — the exact resolved version from `package-lock.json`
  or `yarn.lock`.
- **Install command** — which install command does CI use? Read from
  `.github/workflows/*.yml`. If install happens inside a shared/reusable action,
  note that (e.g. `yarn (via common-workflows/build-fe action)`).

```bash
# Manifest spec
gh api "repos/${ORG}/<repo>/contents/<package.json>" --jq '.content' | base64 -d | grep -in "axios"

# Lock file version (package-lock.json)
gh api "repos/${ORG}/<repo>/contents/<package-lock.json>" --jq '.content' | base64 -d | \
  python3 -c "import sys,json; d=json.load(sys.stdin); pkgs=d.get('packages',{}); [print(f'{k}: {v[\"version\"]}') for k,v in pkgs.items() if 'axios' in k.split('/')[-1]]"

# Lock file version (yarn.lock)
gh api "repos/${ORG}/<repo>/contents/<yarn.lock>" --jq '.content' | base64 -d | grep -A2 "^axios@"

# Install command (from workflow files)
gh api "repos/${ORG}/<repo>/contents/.github/workflows/<workflow>.yml" --jq '.content' | base64 -d | grep -iE "npm ci|npm install|yarn"
```

### 3. Also check Dockerfiles, scripts, and other install vectors

The code search will surface references beyond manifests. Check ALL of these:

- **Dockerfiles:** `RUN npm install axios` or `RUN npm install` with axios in
  package.json — adds axios to the image. Affected if built during the window.
- **Shell scripts / Makefiles:** `install.sh`, `setup.sh` that run npm install
- **CI workflow `run:` steps:** direct install commands in workflow files
- **Helm charts:** `values.yaml` `image:` field — check if the image is internally
  built (may have npm install) or pre-built

### 4. Third-party base images

Third-party Docker images pulled during CI builds may themselves contain axios if
they were rebuilt during the exposure window. Flag these if:
- A repo uses third-party base images with mutable tags (not digest-pinned)
- Those images are known to include axios in their dependency tree

Note in findings as requiring follow-up with the image vendor.

### 5. Write the repo evidence table

Write `$LOG_DIR/evidence-repos.csv`:

```
repo,path,source_type,manifest_spec,spec_in_range,has_lockfile,lockfile_version,lock_protects,install_command,install_upgrades,can_be_compromised
```

**Column guide:**

| Column | What to write |
|---|---|
| `repo` | Repo name (no org prefix) |
| `path` | Full file path where the reference was found (e.g. `extension/package.json`, `.github/workflows/build.yaml`, `Dockerfile`) |
| `source_type` | Type of file: `manifest`, `lockfile`, `ci-workflow`, `dockerfile`, `script`, `helm` |
| `manifest_spec` | For manifests: exact specifier as written (`^1.13.6`). For CI workflows/scripts: the exact install command. For transitive deps: `transitive` |
| `spec_in_range` | `yes (allows 1.14.1)` or `yes (allows 0.30.4)` or `no (reason)`. `^1.x` allows 1.14.1. `^0.21.x` allows 0.30.4. Always explain |
| `has_lockfile` | `yes (package-lock.json)` / `yes (yarn.lock)` / `no`. Always include type |
| `lockfile_version` | Exact pinned version (e.g. `1.13.2`). `none` if no lock file |
| `lock_protects` | `yes` if lockfile_version is not 1.14.1 or 0.30.4. `no` if it is |
| `install_command` | From workflow files: `npm ci`, `npm install (no args)`, `yarn (via build-fe action)`, etc. Every repo with CI has one — don't write `n/a` |
| `install_upgrades` | `no` for `npm ci` (lock-safe). `possible` for `npm install`. `n/a` only if axios is not part of this install |
| `can_be_compromised` | `no` if lock protects AND install doesn't upgrade. `yes` otherwise |

**Rules:**
- This table is agnostic to the exposure window — it describes the repo's posture
- No blank cells — every field has a value
- Parenthetical explanations after the value: `yes (allows 1.14.1)`

### Install command cheat sheet

| Command | Lock file respected? |
|---|---|
| `npm ci` | **Yes** — installs exactly what lock file says |
| `npm install` (no args) | **Partially** — can upgrade if versions drift |
| `npm install <pkg>` | **No** — resolves to latest matching |
| `npm update` | **No** — upgrades all to latest matching range |
| `yarn install` | **Yes** — respects yarn.lock by default |
| `yarn install --frozen-lockfile` | **Yes** — fails if lock file is out of date |

**Key insight:** If a repo has a committed lock file pinning axios to a safe version
AND CI uses `npm ci` or `yarn install`, that repo cannot be compromised.

---

## Phase 2: CI Run Analysis

**Why this phase is critical:** The code search in Phase 1 only finds repos that
mention axios by name. But a repo can install axios without naming it — through
transitive dependencies or shared CI actions. The only way to know what was actually
installed during the exposure window is to check the CI logs.

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

### 3. Scan for compromised versions and IOCs

```bash
# Broad search — bare package name
grep -rlin "axios" "$LOG_DIR"/run-*.log

# Compromised versions specifically
grep -rlE "axios.*(1\.14\.1|0\.30\.4)" "$LOG_DIR"/run-*.log

# Phantom dependency
grep -rli "plain-crypto-js" "$LOG_DIR"/run-*.log

# C2 domain and IP
grep -rli "sfrclak" "$LOG_DIR"/run-*.log
grep -rli "142\.11\.206\.73" "$LOG_DIR"/run-*.log

# RAT artifacts
grep -rliE "com\.apple\.act\.mond|wt\.exe|6202033|ld\.py" "$LOG_DIR"/run-*.log
```

### 4. Classify hits as real installs vs false positives

**Real npm install indicators** (axios WAS installed):
- `added axios@<version>` (only visible with `--loglevel verbose`)
- `added N packages` (default output — does NOT list individual packages)
- `npm http fetch GET https://registry.npmjs.org/axios`
- `npm http fetch GET https://registry.npmjs.org/axios/-/axios-<version>.tgz`
- `postinstall` script execution output from `plain-crypto-js`

**False positives (ignore):**
- Branch names: `origin/dependabot/npm_and_yarn/*/axios-1.13.5`
- Environment variables: `AXIOS_BASE_URL`, `AXIOS_TIMEOUT`
- Scan output, Helm lint, ArgoCD sync, Terraform resource names

### 5. For each run with install commands, determine what version was installed

- Find the install command in the log (`npm ci`, `npm install`, etc.)
- For `npm ci`: the version comes from the lock file
- For `npm install`: look for `added axios@<version>` in the log output
- Check if package counts are consistent across runs (indicates lock file was respected)

### 6. Write the CI runs evidence table

Write `$LOG_DIR/evidence-ci-runs.csv`:

```
repo,run_id,workflow,platform,install_command,log_line,version_installed,lock_respected,iocs_found,ci_compromised
```

**Column guide:**

| Column | What to write |
|---|---|
| `repo` | Repo name. If the run checks out a different repo, note both (e.g. `e2e-scheduler (my-app)`) |
| `run_id` | Numeric GitHub Actions run ID |
| `workflow` | Workflow name as shown in GitHub. Include environment if applicable |
| `platform` | `darwin-arm64`, `win32-x64`, `linux`, etc. Check the log |
| `install_command` | Exact command from the log: `npm ci`, `npm install (no args)`, `npm install -g aws-cdk@2.144.0` |
| `log_line` | Actual line number(s) in the log file where the command appears |
| `version_installed` | Exact axios version installed (e.g. `1.13.2`). `not installed (step installs <what>)` if axios is not part of this step |
| `lock_respected` | `yes` if version matches lock file. `no` if different. `n/a (reason)` if lock doesn't apply to this command |
| `iocs_found` | `yes (which IOC)` or `no` |
| `ci_compromised` | **Verdict:** `clean` or `compromised`. Use `clean (component not installed)` if step doesn't install axios |

**Rules:**
- One row per install command execution, not per run
- Only include runs that executed install commands
- No blank cells
- `version_installed` is the axios version specifically — not package counts or unrelated packages

---

## Phase 3: Network Investigation (Firewall / Proxy / DNS Logs)

The malware contacts `sfrclak.com` on port `8000` at endpoint `/6202033`.
Check network logs for any connection to the C2 infrastructure during or after
the exposure window.

### What to look for

| IOC | Where to search |
|---|---|
| DNS resolution of `sfrclak.com` | DNS logs, DNS proxy, Pi-hole, Cloudflare Gateway, etc. |
| Connection to `142.11.206.73` | Firewall logs, VPC flow logs, proxy logs |
| Connection to port `8000` on that IP | Firewall logs, proxy logs |
| HTTP POST to `/6202033` | Proxy logs, WAF logs (if TLS-inspected) |
| POST body containing `packages.npm.org/product0` (macOS), `product1` (Windows), `product2` (Linux) | Proxy logs with body inspection |
| User-Agent: `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)` | Proxy logs — deliberately mimics IE 8 on Windows XP, highly anomalous on modern systems |

### Where to check

**Cloud environments:**
- AWS: VPC Flow Logs, CloudTrail (if DNS query logging is enabled), Route 53 Resolver query logs
- GCP: VPC Flow Logs, Cloud DNS query logs
- Azure: NSG Flow Logs, Azure DNS Analytics

**On-premise / corporate network:**
- Firewall (Palo Alto, Fortinet, etc.) — search for destination IP `142.11.206.73` or destination port `8000`
- Web proxy (Zscaler, Squid, etc.) — search for domain `sfrclak.com`
- DNS server logs — search for `sfrclak.com` resolution
- SIEM (Splunk, Elastic, etc.) — correlate across sources

**CI runners:**
- Self-hosted runners: check the host's network logs
- GitHub-hosted runners: no direct network log access, but proxy/firewall at the network edge may have captured egress

### Time window

Search from `2026-03-31T00:00:00Z` to at least `2026-04-01T00:00:00Z` — the RAT
may have persisted and continued beaconing after the initial infection.

### Example queries

**Splunk:**
```
index=firewall dest_ip="142.11.206.73" OR dest_port=8000
| stats count by src_ip, dest_ip, dest_port, action
```

```
index=dns query="sfrclak.com"
| stats count by src_ip, query, answer
```

**Elastic/Kibana:**
```
destination.ip: "142.11.206.73" OR dns.question.name: "sfrclak.com"
```

**AWS CloudWatch Logs Insights (VPC Flow Logs):**
```
filter dstAddr = "142.11.206.73"
| stats count(*) as hits by srcAddr, dstPort, action
```

### Interpret results

- **DNS resolution of `sfrclak.com` found:** A machine attempted contact. Check which
  machine, whether the connection succeeded, and whether data was transferred.
- **Connection to `142.11.206.73:8000` found:** The RAT dropper ran and reached the C2.
  Treat the source machine as compromised — rotate all credentials on it.
- **No results:** The C2 was not contacted from your network. This is consistent with
  a clean finding from Phases 1 and 2, but does not rule out compromise if the machine
  had direct internet access bypassing your proxy/firewall.

---

## Phase 4: Workstation Investigation

Developer machines that ran `npm install` or `npm update` during the exposure window
may have installed the compromised version. Unlike CI (where we have logs), workstation
investigation relies on checking for artifacts on each machine.

**Important:** The malware uses postinstall self-deletion — after execution, it deletes
`setup.js` and replaces `package.json` with a clean stub. Inspecting `node_modules`
will NOT reveal the dropper. Focus on the RAT artifacts, npm cache, and tool logs.

> **Dedicated workstation playbook:** For a comprehensive, step-by-step workstation
> investigation (including AI agent conversation scanning, npm cache shasum checks,
> OS persistence mechanisms, and network indicators), see
> [workstation-playbook.md](workstation-playbook.md).

### 1. Check for RAT artifacts

**macOS:**
```bash
# RAT binary disguised as Apple cache daemon
ls -la /Library/Caches/com.apple.act.mond 2>/dev/null && echo "FOUND — COMPROMISED" || echo "clean"

# Check if it's running
ps aux | grep -i "com.apple.act.mond" | grep -v grep

# Check for persistence in LaunchAgents/LaunchDaemons
grep -rl "com.apple.act.mond\|sfrclak\|142.11.206.73" \
  ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/ 2>/dev/null
```

**Windows:**
```powershell
# RAT binary disguised as Windows Terminal
Test-Path "$env:PROGRAMDATA\wt.exe"

# VBScript and PowerShell dropper (may have self-deleted)
Test-Path "$env:TEMP\6202033.vbs"
Test-Path "$env:TEMP\6202033.ps1"

# Check running processes
Get-Process | Where-Object { $_.Path -like "*wt.exe" -and $_.Path -like "*ProgramData*" }

# Check persistence in scheduled tasks and registry
Get-ScheduledTask | Where-Object { $_.Actions.Execute -like "*wt.exe*" -or $_.Actions.Execute -like "*6202033*" }
```

**Linux:**
```bash
# Python RAT script
ls -la /tmp/ld.py 2>/dev/null && echo "FOUND — COMPROMISED" || echo "clean"

# Check if it's running (nohup'd to PID 1)
ps aux | grep "ld.py" | grep -v grep

# Check persistence in cron/systemd
crontab -l 2>/dev/null | grep -E "ld\.py|sfrclak|142\.11\.206\.73"
```

### 2. Check npm cache for compromised packages

The npm cache may still contain the compromised tarball even if node_modules was cleaned.
Check both the package listing and the content-addressable store by shasum:

```bash
# High-level listing
npm cache ls 2>/dev/null | grep -E "axios.*(1\.14\.1|0\.30\.4)" || echo "not in cache"
npm cache ls 2>/dev/null | grep "plain-crypto-js" || echo "not in cache"

# Deep check: search content-addressable store by known compromised shasums
NPM_CACHE=$(npm config get cache 2>/dev/null)
if [ -d "$NPM_CACHE/_cacache" ]; then
  grep -rl "2553649f2322049666871cea80a5d0d6adc700ca" "$NPM_CACHE/_cacache" 2>/dev/null \
    && echo "FOUND — axios 1.14.1 shasum in cache"
  grep -rl "d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71" "$NPM_CACHE/_cacache" 2>/dev/null \
    && echo "FOUND — axios 0.30.4 shasum in cache"
  grep -rl "07d889e2dadce6f3910dcbc253317d28ca61c766" "$NPM_CACHE/_cacache" 2>/dev/null \
    && echo "FOUND — plain-crypto-js shasum in cache"
fi
```

### 3. Check network indicators

```bash
# Active connections to C2 IP
netstat -an 2>/dev/null | grep "142.11.206.73" \
  && echo "FOUND — active C2 connection" || echo "C2 IP not in active connections"

# C2 domain in hosts file
grep "sfrclak.com" /etc/hosts 2>/dev/null

# macOS DNS query log
log show --predicate 'process == "mDNSResponder" && composedMessage contains "sfrclak.com"' \
  --last 7d 2>/dev/null | head -20
```

### 4. Check shell history

```bash
grep -E "axios@(1\.14\.1|0\.30\.4)|plain-crypto-js" \
  ~/.zsh_history ~/.bash_history 2>/dev/null \
  || echo "No compromised package references in shell history"
```

### 5. Check lock files and node_modules in local projects

```bash
PROJECT_ROOT="${HOME}/projects"  # adjust as needed

# Lock files
find "$PROJECT_ROOT" -maxdepth 5 \
  \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) \
  -not -path "*/node_modules/*" 2>/dev/null | while read lockfile; do
  if grep -qE "axios.*(1\.14\.1|0\.30\.4)|plain-crypto-js" "$lockfile" 2>/dev/null; then
    echo "COMPROMISED: $lockfile"
  fi
done

# Phantom dependency in node_modules
find "$PROJECT_ROOT" -maxdepth 5 -path "*/node_modules/plain-crypto-js" -type d 2>/dev/null
```

### 6. Check npm debug logs

```bash
NPM_LOGS="${HOME}/.npm/_logs"
if [ -d "$NPM_LOGS" ]; then
  grep -rl "axios.*\(1\.14\.1\|0\.30\.4\)\|plain-crypto-js\|sfrclak\|142\.11\.206\.73" \
    "$NPM_LOGS"/ 2>/dev/null \
    && echo "FOUND — IOC match in npm debug logs" || echo "No IOC matches in npm logs"
fi
```

### 7. Check AI agent conversation logs

AI coding agents store conversation histories with full tool outputs. If an agent
ran `npm install` during the exposure window, the resolved versions are captured.

```bash
# Claude Code sessions
find ~/.claude/projects -name "*.jsonl" -print0 2>/dev/null \
  | xargs -0 grep -l "axios.*\(1\.14\.1\|0\.30\.4\)\|plain-crypto-js\|sfrclak\|142\.11\.206\.73" 2>/dev/null
```

**Important:** Matches may be from sessions that *discussed* the playbook, not
sessions that ran compromised installs. For matched files, verify whether the
session contains actual npm bash commands. See
[workstation-playbook.md](workstation-playbook.md) Check 8 for the classification
script.

### 8. Docker images built locally

```bash
docker images --format '{{.Repository}}:{{.Tag}} {{.CreatedAt}}' 2>/dev/null | grep "2026-03-31"
```

Rebuild suspicious images with `docker build --no-cache`.

### 9. Exfiltration repos

Check if any repos were created in the org during the exposure window (fallback exfil):
```bash
gh api --paginate "/orgs/$ORG/repos?per_page=100&sort=created&direction=desc" \
  --jq '.[] | select(.created_at > "2026-03-31T00:00:00Z" and .created_at < "2026-03-31T05:00:00Z") | "\(.name) | \(.created_at) | \(.visibility)"'
```

---

## Phase 5: Present Results

Produce three deliverables and return them to the user:

### 1. Repo Analysis table (`evidence-repos.csv`)

The CSV file showing the dependency posture of every repo that references axios.
This is independent of the exposure window — it describes whether the config is
vulnerable in principle.

### 2. CI Runs table (`evidence-ci-runs.csv`)

The CSV file showing what actually happened during the exposure window — which
install commands ran, what version was installed, whether IOCs were found, and
the `clean`/`compromised` verdict per run.

### 3. Executive Summary

Short prose summary for incident response leads. Include:

- **Verdict**: `clean` or `compromised`
- **Scope**: repos scanned, CI runs analyzed, logs downloaded
- **Repo analysis**: how many repos have axios, lock file coverage, how many
  manifest ranges include 1.14.1 or 0.30.4
- **CI analysis**: how many runs used `npm ci` (lock-safe) vs `npm install`
  (can upgrade), what axios versions were actually installed, any IOCs found
- **Network**: whether C2 domain/IP was found in firewall/proxy/DNS logs
- **Workstations**: whether RAT artifacts or compromised packages were found
  on developer machines
- **Bottom line**: one sentence

### 4. Determine which repos need action

**Repos that need NO action** — all of these are true:
- `can_be_compromised` = no (lock protects + install respects lock)
- All CI runs show `ci_compromised` = clean

These repos are protected by their lock files. No remediation needed.

**Repos that need ATTENTION** — any of these are true:
- `can_be_compromised` = yes (no lock file, or install can upgrade)
- `ci_compromised` = compromised (axios 1.14.1 or 0.30.4 was installed)
- Uses third-party base images that may have been rebuilt during the window

**Repos that are vulnerable but weren't hit** — `can_be_compromised` = yes but no
CI runs during the window: not compromised this time, but the configuration is
vulnerable to future attacks. Flag for hardening.

Return `$LOG_DIR/evidence-repos.csv`, `$LOG_DIR/evidence-ci-runs.csv`, and the
executive summary to the user.

---

## Phase 6: Hardening & Remediation (User Approval Required)

**Do NOT proceed without explicit user approval.** Present findings first, then ask.

### If compromised (any `ci_compromised` = compromised, network IOCs found, or RAT artifacts found):

1. **Rotate all secrets** accessible to affected workflows and compromised machines —
   npm tokens, AWS keys, SSH keys, Docker registry creds, API keys, signing keys
2. **Remove RAT artifacts** from compromised machines (see Phase 4 for paths per OS)
3. **Clean npm cache** on compromised machines: `npm cache clean --force`
4. **Rebuild Docker images** built during the window with `--no-cache`
5. **Block C2 at network level**: add `sfrclak.com` and `142.11.206.73` to
   firewall/proxy deny lists
6. **Audit GitHub logs** for unauthorized commits, PRs, or releases during the window
7. **Re-image compromised workstations** if RAT was found — in-place cleaning
   may miss persistence mechanisms

### Hardening (for repos where `can_be_compromised` = yes):

| Attack surface | Fix |
|---|---|
| No lock file | Commit `package-lock.json` or `yarn.lock` |
| CI uses `npm install` not `npm ci` | Switch to `npm ci` |
| Unpinned `^` ranges in package.json | Consider exact pins for critical deps |
| Docker image pinned by tag | Pin to digest (`@sha256:...`) |
| Postinstall scripts in CI | Use `npm ci --ignore-scripts` as defense-in-depth |
