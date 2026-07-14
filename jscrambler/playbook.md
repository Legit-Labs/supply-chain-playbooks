# Jscrambler npm Compromise (July 2026) — Investigation Playbook

Playbook for investigating whether a GitHub org was affected by the **July 2026 `jscrambler` npm supply-chain compromise**. An attacker with compromised npm publishing credentials published four malicious `jscrambler` versions carrying a cross-platform infostealer that executes during the npm **`preinstall`** hook. Packages were live for ~3 hours on 2026-07-11 and downloaded ~1,479 times before removal.

> **CI/CD platform note:** This playbook targets GitHub Actions. For other platforms (GitLab CI, Jenkins, CircleCI, Bitbucket, Azure DevOps), adapt the log-collection commands — the logic is identical: find repos that install `jscrambler`, pull run logs from the exposure window, and grep for the malicious versions + `preinstall` execution + the C2 indicator.

> **Trigger model — install/build time.** The payload runs in the `preinstall` lifecycle hook, so it fires during `npm install` on CI runners, build hosts, and developer machines — **before any application code runs**. Detection therefore centers on **CI install logs + dependency manifests/lockfiles**, not application source or runtime egress. (`jscrambler` is also commonly invoked as a build-time CLI, so it is frequently a real, installed dependency — not just a source import.)

---

## Incident Details

`jscrambler` is a widely used JavaScript-protection/obfuscation tool (~17,000 weekly npm downloads), so it is trusted and often sits inside build toolchains. On **2026-07-11**, an attacker used **compromised npm publishing credentials** (since revoked by the maintainer) to publish four backdoored releases. Each shipped an information-stealer:

- Executes in the **`preinstall`** hook, dropping and running a native **Rust infostealer** built for Windows (via WSL), macOS, and Linux. A related analysis also reported an obfuscated **Node.js stealer with a WebSocket reverse shell**.
- Sweeps the host for secrets and exfiltrates them over **TLS via multipart HTTP POST** to the drop server.
- Per-string obfuscation via the **ChaCha20-Poly1305** algorithm.

### CVE / advisory

- **CVE:** none assigned as of drafting.
- **Detection source:** Socket Research Team (detected `8.14.0` within ~6 minutes of publication) — https://socket.dev/blog/jscrambler-supply-chain-attack
- **Press:** https://www.bleepingcomputer.com/news/security/hackers-backdoor-jscrambler-npm-package-with-infostealer-malware/ · https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html

### Affected package

| Package | Malicious versions | Safe version |
|---|---|---|
| `jscrambler` (npm) | `8.14.0`, `8.16.0`, `8.17.0`, `8.20.0` | `8.22.0` |

The four malicious versions have been removed from the registry; `8.22.0` is the clean release. Downloads that resolved a malicious version during the window are already on disk / in caches and lockfiles regardless of the later removal.

### Exposure window

| Event | Time (UTC) |
|---|---|
| First malicious version published (`8.14.0`) | 2026-07-11 ~15:12 |
| Socket public detection | 2026-07-11 ~15:18 |
| Remaining malicious versions (`8.16.0`/`8.17.0`/`8.20.0`) published | 2026-07-11 ~17:26–17:53 |
| Clean `8.22.0` published | 2026-07-11 ~18:13 |

**Recommended scan window (padded):** `2026-07-11T15:00:00Z` to `2026-07-11T19:00:00Z`. If your CI timestamps are coarse or timezone-uncertain, treat the **entire day 2026-07-11 (UTC)** as the window.

### Indicators of compromise

| IOC | Value | Where it shows up |
|---|---|---|
| Malicious versions | `jscrambler@8.14.0`, `@8.16.0`, `@8.17.0`, `@8.20.0` | manifests, lockfiles, CI install logs |
| Install-time execution | `preinstall` script of `jscrambler` spawning a native binary / node child during `npm install` | CI logs, host telemetry |
| C2 / drop server | `216.126.225.243` | network logs |
| C2 ports | `8085`, `8086`, `8087` (TLS; multipart HTTP POST exfil) | network / proxy / firewall logs |
| Exfil behavior | outbound POST of archived secrets to the C2 over TLS | proxy/NetFlow/VPC Flow Logs |

> No file hashes for the dropped binaries were published by the authoritative sources at drafting time. If Socket or the maintainer later publishes SHA-256s, append them here and to the workstation playbook's Setup block.

### What IS affected

- Any `npm install` / `yarn` / `pnpm` that resolved `jscrambler` to `8.14.0`/`8.16.0`/`8.17.0`/`8.20.0` during the window — **direct or transitive**.
- CI workflows and Docker builds that ran an install during the window (the `preinstall` hook executes even before app code).
- Developer machines that installed or updated `jscrambler` during the window.
- Any secret reachable from a host that ran the payload: Git/SSH keys, env vars, CI/CD tokens, cloud credentials (AWS/Azure/GCP/K8s), npm/registry tokens, AI-tool configs (Claude/Cursor/Windsurf/VS Code/Zed), crypto wallets/seed phrases, and messaging-app (Slack/Discord/Telegram) tokens.

### What is NOT affected

- Installs from a committed lock file with `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --frozen-lockfile`, **provided the lock file pins a non-malicious `jscrambler` version** (e.g. an `8.13.0`/`8.15.0`/`8.18.0` predating the window, or `8.22.0`).
- Pre-built Docker images **not rebuilt during the window**.
- Source-only references (`import`/`require('jscrambler')` or a `jscrambler.json` config) where no install ran during the window.
- Repos that name `jscrambler` only in docs, or in a lockfile pinned to a safe version with a frozen install command.

### Lock file protection

Lock files (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`) **do protect** if used correctly:

- `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --frozen-lockfile` install exactly what the lock file pins.
- A lock file generated **before 2026-07-11 15:12 UTC** that pins a pre-window `jscrambler` version never resolves a malicious one.

Lock files do **NOT** protect if: no lock file is committed; CI runs `npm install` / `pnpm install` (no frozen flag) and could update the lock; the lock file was regenerated during the window; or a Dependabot/Renovate PR merged during the window bumped `jscrambler` into a malicious version.

---

## Setup

```bash
export ORG="<your-github-org>"
export SINCE="2026-07-11T15:00:00Z"
export UNTIL="2026-07-11T19:00:00Z"
export LOG_DIR="/tmp/supply-chain-scan-jscrambler"
mkdir -p "$LOG_DIR"

# Malicious-version regex (reused throughout)
export MAL_RE='jscrambler.*(8\.14\.0|8\.16\.0|8\.17\.0|8\.20\.0)'
# C2 indicator
export C2_IP='216\.126\.225\.243'
```

**Write to files, not context:** results can be large — write evidence CSVs to `$LOG_DIR` as you go. **Log caching:** reuse logs already in `$LOG_DIR` from a prior run.

**Rate limits:** check budget before a large org:
```bash
gh api /rate_limit --jq '.resources.core | "\(.remaining)/\(.limit) core"'
gh api /rate_limit --jq '.resources.code_search | "\(.remaining)/\(.limit) code-search"'
```

---

## Phase 1: Repo Analysis

**Goal:** find every repo that references `jscrambler` and classify whether its configuration could resolve a malicious version. Window-agnostic.

### 1. Find all references

```bash
gh api "search/code?q=jscrambler+org:${ORG}&per_page=100" \
  --jq '.items[] | "\(.repository.full_name)\t\(.path)"' 2>/dev/null | sort -u > "$LOG_DIR/refs.tsv"
wc -l "$LOG_DIR/refs.tsv"
```

Paginate (`&page=2`, …) if over 100 results. For orgs over ~50 repos, shallow-clone and grep locally instead (faster, no code-search cap):

```bash
mkdir -p "$LOG_DIR/clones" && cd "$LOG_DIR/clones"
gh repo list "$ORG" --no-archived --limit 1000 --json nameWithOwner --jq '.[].nameWithOwner' | \
  xargs -P 10 -I {} bash -c 'git clone --depth 1 --filter=blob:none "git@github.com:{}.git" 2>/dev/null || echo "FAIL: {}"'
grep -rEl --include='package.json' --include='package-lock.json' --include='pnpm-lock.yaml' --include='yarn.lock' \
  '"?jscrambler"?' . > "$LOG_DIR/refs-from-local-clone.txt"
```

### 2. Classify each reference

| File pattern | Category | Risk |
|---|---|---|
| `package.json` | npm manifest | **HIGH** — check the `jscrambler` spec range vs malicious versions |
| `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` | Lock file | **CRITICAL** — check pinned version against `8.14.0/8.16.0/8.17.0/8.20.0` |
| `Dockerfile` | Docker build | **HIGH** if it runs `npm/pnpm/yarn install` |
| `.github/workflows/*.yml` | CI workflow | **CHECK** — does it install JS deps including `jscrambler`? |
| `*.js`, `*.ts`, `jscrambler.json` | Source / tool config | **NOT AFFECTED** — reference, not install |
| `*.md`, `README*` | Docs | **NOT AFFECTED** |

### 3. Extract version data per repo

```bash
# package.json — jscrambler spec
gh api "repos/${ORG}/<repo>/contents/package.json" --jq '.content' | base64 -d | \
  python3 -c "import sys,json; d=json.load(sys.stdin);
[print(f'{s}: jscrambler = {v[\"jscrambler\"]}') for s in ('dependencies','devDependencies','optionalDependencies') if 'jscrambler' in v.get(s,{}) for v in [d]]"

# package-lock.json — resolved jscrambler version
gh api "repos/${ORG}/<repo>/contents/package-lock.json" --jq '.content' | base64 -d | \
  python3 -c "import sys,json; d=json.load(sys.stdin);
[print(k,'->',x.get('version')) for k,x in d.get('packages',{}).items() if k.split('node_modules/')[-1]=='jscrambler']"

# Install command in workflows
gh api "repos/${ORG}/<repo>/contents/.github/workflows" --jq '.[].path' 2>/dev/null | while read wf; do
  gh api "repos/${ORG}/<repo>/contents/${wf}" --jq '.content' | base64 -d | grep -iE "npm ci|npm install|pnpm install|yarn install|yarn$|bun install"
done
```

### 4. Write the repo evidence table

`$LOG_DIR/evidence-repos.csv`:
```
repo,path,source_type,manifest_spec,spec_in_range,has_lockfile,lockfile_version,lock_protects,install_command,install_upgrades,can_be_compromised
```
Rules: window-agnostic posture; no blank cells; annotate values (`yes (allows 8.14.0)`). `spec_in_range` = does the manifest range admit any of `8.14.0/8.16.0/8.17.0/8.20.0`? `lock_protects` = `yes` unless `lockfile_version` is one of the four malicious values. `can_be_compromised` = `no` only when the lock pins a safe version AND the install command respects the lock.

### Install command cheat sheet

| Command | Lock respected? |
|---|---|
| `npm ci` | **Yes** |
| `npm install` (no args) | **Partially** — can update lock |
| `pnpm install --frozen-lockfile` / `yarn install --immutable` | **Yes** |
| `pnpm install` / `yarn install` (no flag) | **No (CI)** — may update |
| `bun install` | **Partially** (respects `bun.lockb` if present) |

---

## Phase 2: CI Run Analysis

Phase 1 only finds repos that name `jscrambler`. A repo can install it transitively. The only way to know what actually installed during the window is the CI logs.

### 1. Find runs in the window

```bash
gh api "/orgs/${ORG}/repos" --paginate --jq '.[].name' | while read repo; do
  gh api "repos/${ORG}/${repo}/actions/runs?created=${SINCE}..${UNTIL}&per_page=100" \
    --jq ".workflow_runs[] | \"${repo}|\(.id)|\(.created_at)|\(.name)|\(.conclusion)\"" 2>/dev/null
done > "$LOG_DIR/all_runs.txt"
echo "runs to scan: $(wc -l < "$LOG_DIR/all_runs.txt")"
```

### 2. Download run logs in parallel

```bash
cat "$LOG_DIR/all_runs.txt" | while IFS='|' read repo run_id rest; do echo "$repo $run_id"; done | \
  xargs -P 10 -L 1 bash -c 'gh run view "$1" --repo "${ORG}/$0" --log > "${LOG_DIR}/run-$1.log" 2>/dev/null && echo "OK $0 $1" || echo "FAIL $0 $1"'
```

### 3. Scan logs — malicious installs, preinstall execution, C2

```bash
# Malicious version actually installed (install-only lines, NOT source imports)
echo "=== jscrambler malicious version installs ==="
grep -rlE "(added|Downloading|Successfully installed|http fetch GET .*).*${MAL_RE}|${MAL_RE}\.tgz" "$LOG_DIR"/run-*.log 2>/dev/null

# preinstall hook firing for jscrambler
echo "=== jscrambler preinstall execution ==="
grep -rliE "jscrambler.*preinstall|preinstall.*jscrambler" "$LOG_DIR"/run-*.log 2>/dev/null

# C2 indicator in build output
echo "=== C2 indicator ==="
grep -rliE "${C2_IP}|:(8085|8086|8087)\b" "$LOG_DIR"/run-*.log 2>/dev/null
```

**Positive control** (prove the grep works before trusting a clean result): confirm the pattern matches a known install line in the same corpus, e.g. `grep -rlE "added .*jscrambler@" "$LOG_DIR"/run-*.log` should hit on any run that installed jscrambler at all. A zero-hit grep and a broken grep look identical.

### 4. Classify hits — real install vs false positive

**Real install:** `added jscrambler@8.14.0`, `+ jscrambler 8.16.0` (pnpm), `Downloading jscrambler-8.17.0.tgz`, `npm http fetch GET https://registry.npmjs.org/jscrambler`, or `preinstall` output from the `jscrambler` package.
**False positive (ignore):** `import ... from 'jscrambler'`, a `jscrambler.json` config dump, branch names (`feat/upgrade-jscrambler`), SAST/dependency-review listings, docs.

> **Silent-install caveat:** `npm ci` / `yarn install --immutable` print no per-package lines when the lockfile is satisfied — a zero-hit grep does **not** prove no install happened. Confirm the resolved version from the committed lockfile (Phase 1), not from per-package log output.

### 5. Write the CI evidence table

`$LOG_DIR/evidence-ci-runs.csv`:
```
repo,run_id,created_at,workflow,install_command,log_line,version_installed,lock_respected,iocs_found,ci_compromised
```
One row per install-command execution. `ci_compromised` verdict: `clean` / `compromised` / `clean (component not installed)`.

---

## Phase 3: Network Investigation

Check network logs from any host that ran CI or dev work on/after 2026-07-11.

| IOC | Where to search |
|---|---|
| Outbound to `216.126.225.243` (ports `8085`/`8086`/`8087`, TLS) | VPC/NSG Flow Logs, firewall, web proxy, NetFlow, SIEM |
| Large/unexpected multipart HTTPS POST from a CI runner or dev host during a build | proxy logs, egress telemetry |

**Splunk:** `index=firewall dest_ip="216.126.225.243" (dest_port=8085 OR dest_port=8086 OR dest_port=8087) | stats count by src_ip`
**AWS CloudWatch Insights (VPC Flow):** `filter dstAddr="216.126.225.243" | stats count(*) by srcAddr, dstPort`

**Interpret:** any successful connection to the C2 → treat the source host as compromised and rotate every credential reachable from it (Hardening below). No hits from your visibility is consistent with clean Phases 1–2 but does not clear a BYO/off-network laptop.

---

## Phase 4: Workstation Investigation

The infostealer's primary target is the developer machine (SSH/cloud creds, wallets, AI-tool configs). For any workstation that ran `npm install`/`update` on a `jscrambler`-consuming project during the window, run **[workstation-playbook.md](workstation-playbook.md)**.

---

## Hardening (apply after investigation)

1. **Pin to the safe version:** set `jscrambler` to exactly `8.22.0` in every manifest; for Docker, rebuild with `--no-cache`. Never allow a floating range that could re-resolve a removed-but-cached malicious version.
2. **Migrate to lock-file-respecting installs:** replace `npm install` with `npm ci` (and `--frozen-lockfile`/`--immutable` for pnpm/yarn) in CI.
3. **Rotate every credential reachable from a host that installed during the window** — not "rotate exposed credentials" in the abstract: Git/SSH keys, npm/registry tokens, GitHub PATs, `secrets.*` referenced by any workflow that ran in the window, OIDC-issued cloud creds (AWS/Azure/GCP/K8s), signing keys, and any crypto-wallet seed phrases stored on the host. Assume exfiltration if the C2 connection (Phase 3) succeeded.
4. **Audit CI/CD:** review run logs from the window for `preinstall` activity and outbound calls to `216.126.225.243`; pin GitHub Actions to SHAs and Docker base images to digests.

---

## Pitfalls & Fixes

1. **Match installs, not imports.** `grep -r "jscrambler"` matches `require('jscrambler')` in build config. Use install-only patterns (`added .*jscrambler@`, `Downloading jscrambler-…tgz`, `preinstall`) with the version regex.
2. **Silent lock-strict installs.** `npm ci` / `yarn install --immutable` emit no per-package lines — a clean grep is not proof; verify the lockfile-pinned version instead.
3. **AI-agent self-pollution.** When scanning AI-agent logs (workstation playbook, and here if you grep dev machines), the investigating agent's own session will "hit" on `jscrambler`/`216.126.225.243` because it just read them. Exclude the current session's data dir (for Claude Code: `~/.claude/projects/<current-workdir-slug>/*.jsonl`, `~/.claude/paste-cache/`, `~/.claude/file-history/`). Hits that remain after that filter are real.
4. **Coarse CI timestamps.** If run timestamps are timezone-uncertain, widen the window to the full UTC day 2026-07-11 rather than miss an install near the edges.
