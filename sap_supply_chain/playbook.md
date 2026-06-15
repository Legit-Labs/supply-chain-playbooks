# April 2026 SAP CAP Mini Shai-Hulud npm Wave (TeamPCP) — Investigation Playbook

Playbook for investigating whether a GitHub org was affected by the **April 29, 2026 "Mini Shai-Hulud" compromise of four SAP npm packages**, attributed to **TeamPCP**. The packages were backdoored with a **two-stage, Bun-based credential stealer** that fires automatically on `npm install`, harvests GitHub/npm/cloud/Kubernetes/CI credentials (including secrets pulled from GitHub Actions runner memory), and exfiltrates them AES-256-GCM-encrypted to attacker-controlled **public GitHub repositories**. The four packages total ~1.2M monthly installs, predominantly in **enterprise SAP CI/CD pipelines**.

> **CI/CD platform note:** This playbook targets GitHub Actions. For other CI/CD platforms (GitLab CI, Jenkins, CircleCI, Bitbucket, Azure DevOps), adapt the log-collection commands — the investigation logic is the same: identify references to any compromised package, collect run logs from the exposure window, search for compromised versions and IOCs, and verify lock-file protection.

> **Trigger model: install-time (`preinstall` hook).** The payload runs from a `package.json` `preinstall` lifecycle script, so detection centers on **CI install logs + manifests/lockfiles**, and **`--ignore-scripts` DOES block it** at install time (contrast the "Miasma" worm's `binding.gyp`/node-gyp vector, which `--ignore-scripts` does not stop).

> **Threat-actor lineage.** TeamPCP also ran the later **AntV wave (May 19, 2026)** (`antv_supply_chain/playbook.md`) and the **TanStack wave (May 11, 2026)** (`tanstack_supply_chain/playbook.md`), plus **Trivy (March 2026)** (`trivy/`). This SAP wave is an **earlier, distinct wave** — same TTPs, but its own package set, payload filenames, dead-drop signature, and known-clean downgrade targets. Don't substitute another wave's IOCs blindly.

---

## Incident Details

The attacker modified each compromised package's `package.json` to add a **`preinstall` hook** that fires automatically during `npm install`:

1. The hook (dropper **`setup.mjs`**) downloads the **Bun** JavaScript runtime and uses it to execute the second-stage payload **`execution.js`** — an ~11.7 MB obfuscated credential stealer.
2. The stealer targets **both developer machines and CI/CD runners**, collecting: **GitHub and npm tokens, AWS / Azure / GCP credentials, Kubernetes service-account tokens, and GitHub Actions secrets** (including secrets extracted directly from **runner process memory**).
3. Stolen data is **AES-256-GCM encrypted** and exfiltrated to **attacker-controlled public GitHub repositories** (described **"A Mini Shai-Hulud has Appeared"**).
4. **Persistence:** for any GitHub token with **`workflow` scope**, the malware commits a malicious **`.vscode/tasks.json`** to victim repositories that re-executes the dropper on folder-open — establishing persistent access. Commits are authored as **`claude <claude@users.noreply.github.com>`**.
5. **Region guardrail (attribution signal):** the payload **terminates without exfiltrating** if a **Russian locale (`ru`)** is detected — an encoding/guardrail overlap that ties it to TeamPCP.

**Root cause:** a **compromised SAP developer account** combined with an **overly broad npm OIDC trusted-publishing configuration** that allowed token exchange from **any branch**, not just protected ones. (This is the key SAP-specific hardening lesson — see Phase 6.)

### CVE / advisory

- **CVE:** none assigned. Recheck NVD / GitHub Advisories under "Mini Shai-Hulud" / the affected `@cap-js/*` packages.
- Public reporting exists from multiple vendors/press; cross-check the package list against **GitHub Advisories** and the maintainer (SAP / `cap-js`) channels for the canonical per-version inventory.

### Affected packages

Four packages (~1.2M monthly installs combined). All platforms (Windows, Linux, macOS) affected.

| Package | Compromised version | Last known-clean |
|---|---|---|
| `@cap-js/sqlite` | **2.2.2** | 2.2.1 |
| `@cap-js/postgres` | **2.2.2** | 2.2.1 |
| `@cap-js/db-service` | **2.10.1** | 2.10.0 |
| `mbt` | **1.2.48** | 1.2.47 |

> **Detection regex (package@version):**
> ```
> @cap-js/(sqlite|postgres)["@:[:space:]].*2\.2\.2|@cap-js/db-service["@:[:space:]].*2\.10\.1|(^|[^a-z-])mbt["@:[:space:]].*1\.2\.48
> ```
> Match the **name + the exact compromised version**; the clean versions one patch below are safe.

### Exposure window

| Event | Time (UTC) |
|---|---|
| Compromised versions published / disclosed | April 29, 2026 |

**Recommended scan window (padded):** `2026-04-29T00:00:00Z` to `2026-04-30T12:00:00Z` — the advisory does not publish exact start/end timestamps; treat the full day of disclosure as the window and pad forward to catch installs that resolved a compromised version before npm/maintainer remediation propagated. **Anything that installed an affected version on or after Apr 29, 2026 is in scope.**

### Indicators of compromise

| IOC | Value | Where it shows up |
|---|---|---|
| Dropper file | `setup.mjs` | `node_modules/<pkg>/`, repo working trees, CI logs |
| Stage-2 payload | `execution.js` (~11.7 MB, obfuscated) | `node_modules/<pkg>/`, CI logs, disk |
| Install-time trigger | a `preinstall` hook in the compromised package's `package.json` | `node_modules/<pkg>/package.json`, CI install logs |
| Runtime download | Bun runtime fetched **during `npm install`** | network logs, CI logs |
| Exfil destination | AES-256-GCM blobs pushed to **attacker public GitHub repos** | GitHub audit log, network logs |
| Dead-drop repo description | **"A Mini Shai-Hulud has Appeared"** | GitHub repo descriptions |
| Forged commit author | `claude <claude@users.noreply.github.com>` (in repos that aren't yours) | git log |
| Editor/agent backdoor | malicious `.vscode/tasks.json`; unexpected `.claude/` or `.vscode/setup.mjs` | repo working trees, workstations |
| Guardrail behavior | payload exits without exfil under Russian locale (`ru`) | host telemetry (rarely observed) |

### What IS affected

- Any `npm install` / `pnpm install` / `yarn install` that resolved a **compromised version** of the four packages on/after Apr 29 — **direct or transitive** — with install scripts **enabled**.
- CI workflows that ran package installs during the window **without** `--ignore-scripts`.
- Docker image builds that ran installs during the window.
- Developer machines that installed/updated an affected package during the window — check `.vscode/`/`.claude/` backdoors even after the package is removed.
- Your **own** npm-published packages, if a maintainer's GitHub/npm token was stolen — the worm republishes via the victim's identity (forward propagation; see Phase 2b).

### What is NOT affected

- The **last known-clean versions** (`@cap-js/sqlite@2.2.1`, `@cap-js/postgres@2.2.1`, `@cap-js/db-service@2.10.0`, `mbt@1.2.47`) and anything older.
- Installs from a committed lock file with `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --frozen-lockfile` **as long as the lock pins a clean version**.
- Installs run with **`--ignore-scripts`** (this wave fires via a `preinstall` hook) — though if a compromised version was still resolved into the tree, rebuild clean.
- Pre-built Docker images **not rebuilt during the window**; source-only references / docs / infra config that merely name a package.

### Lock file protection

Lock files (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`) **do protect** if used correctly:

- `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --frozen-lockfile` (`--immutable` on berry) install exactly what the lock says.
- A lock generated **before Apr 29** pinning a clean version never resolves the compromised tarball.

Lock files do **NOT** protect if: no lock is committed; CI runs a non-frozen install; the lock was regenerated during the window; a Dependabot/Renovate PR bumped an affected package mid-window; or a floating range (`^2.2`, `~2.10`, `latest`) lets a fresh install resolve the compromised version.

**`--ignore-scripts` IS an effective install-time mitigation here** (the payload runs from a `preinstall` hook) — use it as defense-in-depth, but it does not undo a compromised version already pinned in the tree.

---

## Setup

```bash
export ORG="<your-github-org>"
export SINCE="2026-04-29T00:00:00Z"
export UNTIL="2026-04-30T12:00:00Z"
export LOG_DIR="/tmp/supply-chain-scan-sap-capjs"
mkdir -p "$LOG_DIR"
```

**Log caching:** reuse logs in `$LOG_DIR` if present. **Write evidence to files, not context** — write CSV to `$LOG_DIR` as you go. **Rate limits:**

```bash
gh api /rate_limit --jq '.resources.core | "\(.remaining)/\(.limit) (resets \(.reset|todate))"'
gh api /rate_limit --jq '.resources.code_search | "code-search: \(.remaining)/\(.limit)"'
```

Code search ~30 req/min; REST 5,000/hr; log downloads count against REST. For orgs over ~50 repos, shallow-clone and grep locally (Phase 1).

---

## Phase 1: Repo Analysis

**Goal:** For every repo referencing one of the four packages, capture declared/locked versions, the install command, and whether the config is vulnerable in principle. Window-agnostic.

### 1. Find references to the four packages

```bash
PKG_RE='@cap-js/sqlite|@cap-js/postgres|@cap-js/db-service|(^|[^a-z-])mbt([^a-z-]|$)'

for pkg in "@cap-js/sqlite" "@cap-js/postgres" "@cap-js/db-service" "mbt"; do
  q=$(printf '%s' "$pkg" | python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.stdin.read()))")
  echo "=== $pkg ==="
  gh api "search/code?q=${q}+org:${ORG}&per_page=100" \
    --jq '.items[] | "'"$pkg"'\t\(.repository.full_name)\t\(.path)"' 2>/dev/null
  sleep 2
done | sort -u > "$LOG_DIR/refs.tsv"
wc -l "$LOG_DIR/refs.tsv"
```

> **`mbt` is a short, collision-prone name** — it will false-positive on variable names, acronyms, and unrelated tokens. Filter `mbt` hits to actual npm manifest/lock references (`"mbt"` as a JSON dependency key, or `mbt@` in a lockfile), not bare source mentions.

> **Large-org alternative (>50 repos):** shallow-clone and grep locally.
> ```bash
> mkdir -p "$LOG_DIR/clones" && cd "$LOG_DIR/clones"
> gh repo list "$ORG" --no-archived --limit 1000 --json nameWithOwner --jq '.[].nameWithOwner' | \
>   xargs -P 10 -I {} bash -c 'd=$(echo "{}" | tr "/" "_"); git clone --depth 1 --filter=blob:none "https://github.com/{}.git" "$d" 2>/dev/null || echo "FAIL {}"'
> grep -rEn --include='package.json' --include='package-lock.json' --include='pnpm-lock.yaml' --include='yarn.lock' \
>   '@cap-js/(sqlite|postgres|db-service)|(^|[/"@[:space:]])mbt[@"/:]' . > "$LOG_DIR/refs-from-local-clone.txt"
> ```

### 2. Classify each reference

| File pattern | Category | Risk |
|---|---|---|
| `package.json` | npm manifest | **HIGH** — check spec range vs the compromised version |
| `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` | Lock file | **CRITICAL** — check pinned version against the compromised list |
| `Dockerfile` | Docker build | **HIGH** if it runs an install during the window |
| `.github/workflows/*.yml` | CI workflow | **CHECK** — does it install JS deps incl. an affected package? Also audit OIDC/`id-token` usage (root-cause class) |
| `*.ts/.js/.json` (source/config) | Source | **NOT AFFECTED** — reference, not install |
| `*.md`, infra config | Docs / infra | **NOT AFFECTED** |

### 3. Extract version data per repo

```bash
# package.json — affected spec
gh api "repos/${ORG}/<repo>/contents/package.json" --jq '.content' | base64 -d | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
want={'@cap-js/sqlite','@cap-js/postgres','@cap-js/db-service','mbt'}
for s in ('dependencies','devDependencies','optionalDependencies','peerDependencies'):
  for k,v in d.get(s,{}).items():
    if k in want: print(f'{s}: {k} = {v}')
"

# package-lock.json — resolved versions
gh api "repos/${ORG}/<repo>/contents/package-lock.json" --jq '.content' | base64 -d | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
want={'@cap-js/sqlite','@cap-js/postgres','@cap-js/db-service','mbt'}
for k,v in d.get('packages',{}).items():
  name=k.split('node_modules/')[-1]
  if name in want: print(f'{name}: {v.get(\"version\")}')
"
```

### 4. Write the repo evidence table

Write `$LOG_DIR/evidence-repos.csv`:

```
repo,path,source_type,manifest_spec,spec_in_range,has_lockfile,lockfile_version,lock_protects,install_command,ignore_scripts,can_be_compromised
```

| Column | What to write |
|---|---|
| `manifest_spec` | Exact specifier as written; `transitive` if indirect |
| `spec_in_range` | `yes (allows 2.2.2)` / `no (pins 2.2.1)` |
| `lock_protects` | `yes` if `lockfile_version` is a clean version; `no` if it's the compromised one |
| `install_command` | `npm ci`, `pnpm install --frozen-lockfile`, `yarn install`, etc. |
| `ignore_scripts` | `yes` if the install uses `--ignore-scripts` (blocks the preinstall hook); `no` otherwise |
| `can_be_compromised` | `no` if lock protects AND install respects lock (or `--ignore-scripts`); `yes` otherwise |

---

## Phase 2: CI Run Analysis

**Why:** Phase 1 only finds repos that name a package. Transitive installs won't show. CI logs reveal what actually got installed.

### 1. Find runs in the window

```bash
gh api "/orgs/${ORG}/repos" --paginate --jq '.[].name' | while read repo; do
  gh api "repos/${ORG}/${repo}/actions/runs?created=${SINCE}..${UNTIL}&per_page=100" \
    --jq ".workflow_runs[] | \"${repo}|\(.id)|\(.created_at)|\(.name)|\(.conclusion)\"" 2>/dev/null
done > "$LOG_DIR/all_runs.txt"
echo "Runs: $(wc -l < "$LOG_DIR/all_runs.txt")"
```

### 2. Download logs in parallel

```bash
cat "$LOG_DIR/all_runs.txt" | while IFS='|' read repo run_id rest; do echo "$repo $run_id"; done | \
  xargs -P 10 -L 1 bash -c \
  'gh run view "$1" --repo "${ORG}/$0" --log > "${LOG_DIR}/run-$1.log" 2>/dev/null && echo "OK: $0 $1" || echo "FAIL: $0 $1"'
```

### 3. Scan logs for affected packages and SAP-wave IOCs

```bash
# Affected package@version
echo "=== compromised versions ==="
grep -rlnE "@cap-js/(sqlite|postgres).*2\.2\.2|@cap-js/db-service.*2\.10\.1|\bmbt@?1\.2\.48" "$LOG_DIR"/run-*.log 2>/dev/null

# Install-time trigger + payload filenames
echo "=== preinstall / Bun / payload files ==="
grep -rlinE "preinstall|setup\.mjs|execution\.js|github\.com/oven-sh/bun|bun-(linux|darwin|windows)|installing bun" "$LOG_DIR"/run-*.log 2>/dev/null

# Dead-drop + forged author + persistence
echo "=== dead-drop / forged author / vscode persistence ==="
grep -rlinE "A Mini Shai-Hulud has Appeared|claude@users\.noreply\.github\.com|\.vscode/tasks\.json|\.vscode/setup\.mjs" "$LOG_DIR"/run-*.log 2>/dev/null
```

> **Why scan IOCs, not just versions?** A frozen install of a clean tree shows package names with no compromise; a transitive pull of a compromised version may be quiet on names but show the `preinstall` → Bun-download → `execution.js` chain. The execution chain is the higher-fidelity signal.

### 4. Classify hits

**Real install / execution:** `added @cap-js/<pkg>@2.2.2` (npm), `+ @cap-js/<pkg> 2.2.2` (pnpm), resolution lines (yarn); `preinstall` script output; a Bun download; `setup.mjs` / `execution.js` execution.
**False positives:** source imports, SAST/dependency-review output, branch names, docs; bare `mbt` mentions that aren't an npm dependency; your own legitimate `bun` usage (correlate with the affected versions before flagging).

### 5. Write `$LOG_DIR/evidence-ci-runs.csv`

```
repo,run_id,created_at,workflow,platform,install_command,ignore_scripts,version_installed,lock_respected,iocs_found,ci_compromised
```
One row per install execution; verdict `clean` / `compromised` / `clean (component not installed)`. No blank cells.

---

## Phase 2b: The Customer's Own Published Packages (Forward-Propagation Risk)

If any maintainer in the org had a GitHub/npm token stolen during the window, the worm republishes their packages with the `preinstall` payload. Check whether the customer shipped it forward.

```bash
# Enumerate own packages by scope + maintainer, list versions published in the window
curl -s "https://registry.npmjs.org/-/v1/search?text=scope:${SCOPE}&size=250" | \
  python3 -c "import sys,json; [print(p['package']['name']) for p in json.load(sys.stdin)['objects']]" > "$LOG_DIR/own-packages.txt"
while read pkg; do
  curl -s "https://registry.npmjs.org/${pkg}" | python3 -c "
import sys,json
d=json.load(sys.stdin); t=d.get('time',{})
since='${SINCE}'; until='${UNTIL}'
for v,ts in t.items():
    if v in ('created','modified'): continue
    if since<=ts<=until: print(f'${pkg}@{v}\t{ts}')
" 2>/dev/null
done < "$LOG_DIR/own-packages.txt" > "$LOG_DIR/own-published-in-window.tsv"

# Per candidate: pull tarball, check for the preinstall payload
mkdir -p "$LOG_DIR/tarballs/${pkg//\//_}-${version}" && cd "$LOG_DIR/tarballs/${pkg//\//_}-${version}"
npm pack "${pkg}@${version}" 2>/dev/null && tar xzf *.tgz
python3 -c "import json; print('preinstall:', json.load(open('package/package.json')).get('scripts',{}).get('preinstall'))"
ls package/setup.mjs package/execution.js 2>/dev/null && echo "*** payload files present ***"
cd -
```

A `preinstall` hook plus `setup.mjs`/`execution.js` → **directly republished**: `npm deprecate '<pkg>@<version>' 'Compromised (Mini Shai-Hulud) — do not install.'`, publish a clean superseding version from a clean host, notify downstream, and rotate the publisher's GitHub + npm tokens (Phase 6).

---

## Phase 3: Network Investigation

| Signal | Where to search |
|---|---|
| Bun runtime download from `github.com/oven-sh/bun/...` from a build host / dev machine that has no reason to install Bun | DNS logs, proxy, NetFlow, VPC Flow Logs |
| GitHub API repo-creation / pushes from a CI runner (exfil to attacker public repos) | GitHub audit log, proxy logs |
| New **public** repos (org or user) described **"A Mini Shai-Hulud has Appeared"** | GitHub audit log / org repo list |
| Anomalous AWS STS / Azure / GCP / Vault / Kubernetes auth from a host that ran an affected install | CloudTrail / cloud audit logs |

**Where:** AWS VPC Flow Logs + Route 53 Resolver logs + CloudTrail; GCP/Azure equivalents; on-prem firewall/proxy/DNS; SIEM. **Time window:** Apr 29 forward **at least 7 days** — stolen tokens are abused after the install.

---

## Phase 4: Workstation Investigation

Dev machines that ran installs during the window may have executed the payload. The backdoors (`.vscode/tasks.json`, `.claude/`) survive package removal — check them even if `node_modules` looks clean.

### 4a. Payload files + preinstall hooks in `node_modules`

```bash
for root in ~/projects ~/code ~/repos ~/work "$HOME"; do
  [ -d "$root" ] || continue
  find "$root" -path '*/node_modules/*' \( -name 'setup.mjs' -o -name 'execution.js' \) 2>/dev/null
  # affected packages that ship a preinstall hook
  for p in @cap-js/sqlite @cap-js/postgres @cap-js/db-service mbt; do
    find "$root" -path "*/node_modules/$p/package.json" 2>/dev/null | \
      xargs grep -l '"preinstall"' 2>/dev/null
  done
done
```

### 4b. Lock files referencing the affected packages

Flag any lockfile that **names** an affected package, then confirm the exact pinned version by parsing it. A single-line `name.*version` regex is brittle across lockfile formats — npm keys `mbt` as `node_modules/mbt` (not `"mbt"`), and yarn.lock puts the name and resolved version on **separate lines** — so match by name first, then verify.

```bash
find ~ \( -name 'package-lock.json' -o -name 'pnpm-lock.yaml' -o -name 'yarn.lock' \) \
  -not -path '*/node_modules/*' 2>/dev/null | \
  xargs grep -lE '@cap-js/(sqlite|postgres|db-service)|(^|[/"@[:space:]])mbt[@"/:]' 2>/dev/null \
  > "$LOG_DIR/workstation-lockfiles-with-affected.txt"
```

For each hit, confirm whether the **pinned version** is the compromised one (`@cap-js/sqlite@2.2.2`, `@cap-js/postgres@2.2.2`, `@cap-js/db-service@2.10.1`, `mbt@1.2.48`) vs the clean version one patch below — parse the lockfile as in Phase 1 step 3, don't trust a one-line grep.

### 4c. Editor / agent backdoors (survive package removal)

```bash
find ~ -maxdepth 6 \( -path '*/.vscode/tasks.json' -o -path '*/.vscode/setup.mjs' -o -path '*/.claude/*' \) 2>/dev/null | while read f; do
  echo "=== $f (modified $(stat -f '%Sm' "$f" 2>/dev/null || stat -c '%y' "$f" 2>/dev/null)) ==="
  grep -lE "setup\.mjs|execution\.js|bun|child_process|curl|base64" "$f" 2>/dev/null && echo "  *** SUSPICIOUS ***"
done
```
Pay particular attention to files modified on/after **2026-04-29**.

### 4d. npm / pnpm / yarn cache + debug logs

```bash
for p in @cap-js/sqlite @cap-js/postgres @cap-js/db-service mbt; do npm cache ls "$p" 2>/dev/null; done
grep -liE "setup\.mjs|execution\.js|preinstall|oven-sh/bun" ~/.npm/_logs/*.log 2>/dev/null
```

### 4e. AI agent conversation logs (exclude the investigating agent's own session)

> If you're running this playbook through an AI coding agent, its transcript will contain these IOC strings because you've been *reading* them — that's investigation, not compromise. Exclude the current session.

```bash
CURRENT_SESSION_PROJECT=$(echo "$PWD" | sed 's|/|-|g')
grep -rliE "A Mini Shai-Hulud has Appeared|setup\.mjs|execution\.js|@cap-js/(sqlite|postgres|db-service)" \
  "$HOME/.claude/projects" \
  "$HOME/Library/Application Support/Cursor" \
  "$HOME/Library/Application Support/Windsurf" \
  "$HOME/.config/github-copilot" 2>/dev/null | \
  grep -v "${CURRENT_SESSION_PROJECT}" | grep -v "paste-cache" | grep -v "file-history"
```

### 4f. Dead-drop repos in your own GitHub org

```bash
gh api --paginate "/orgs/${ORG}/repos?per_page=100&sort=created&direction=desc" \
  --jq ".[] | select(.created_at >= \"${SINCE}\") | select(.visibility==\"public\") | \"\(.name) | \(.created_at)\""
gh api --paginate "/orgs/${ORG}/repos?per_page=100" \
  --jq '.[] | select((.description // "") | test("Mini Shai-Hulud has Appeared")) | "\(.name) | \(.description)"'
gh api "search/commits?q=org:${ORG}+author-email:claude@users.noreply.github.com" \
  --jq '.items[]? | "\(.repository.full_name) | \(.html_url) | \(.commit.message)"' 2>/dev/null
```

---

## Phase 5: Present Results

1. **Repo Analysis table** (`evidence-repos.csv`) — posture per repo, window-agnostic.
2. **CI Runs table** (`evidence-ci-runs.csv`) — installs in the window, IOCs, verdict.
3. **Customer-Published Packages table** (`evidence-own-published.csv`) — forward-propagation; verdict per version.
4. **Executive Summary** — verdict (`clean`/`compromised`); scope; repo posture (which of the 4 packages, lock coverage, `--ignore-scripts` usage); CI findings; network (Bun download, GitHub-repo exfil); workstation (`.vscode`/`.claude` backdoors, `setup.mjs`/`execution.js`, caches); org-side dead-drop repos / forged `claude` commits; forward propagation; one-sentence bottom line.

> **Positive control before declaring "clean."** A zero-hit grep and a broken grep look identical. Before concluding clean, prove the detection pattern works against the same corpus — confirm it matches a known-present benign token (`react` / an existing scoped dep) — so "no hits" is defensible.

**Action needed** if any: `can_be_compromised=yes`, any `ci_compromised=compromised`, workstation backdoors/persistence, dead-drop repos, or forged `claude` commits. **Vulnerable but not hit** (`can_be_compromised=yes`, no runs in window) → Phase 6 hardening.

---

## Phase 6: Hardening & Remediation (User Approval Required)

**Do NOT proceed without explicit user approval.** Present findings first.

### Remediation — only if compromised

Rotate before scrubbing — the stealer grabs GitHub/npm/cloud/Kubernetes/CI credentials.

1. **Quarantine** affected workstations; drain/stop affected CI runners (terminate if ephemeral).
2. **Snapshot** payload files (`setup.mjs`, `execution.js`), `.vscode/tasks.json`, `.claude/`, shell history, `~/.npmrc` for forensics.
3. **Rotate all credentials installed on/after Apr 29 on any affected host:** **GitHub tokens** (PATs, `gh` token, deploy keys, App installation tokens — prioritize any with `workflow` scope), **npm tokens**, **AWS / Azure / GCP** credentials, **Kubernetes** service-account tokens, and **every CI/CD secret** the runner could read. Enforce **2FA**.
4. **Remove the editor/agent backdoors**: delete malicious `.vscode/tasks.json`, `.vscode/setup.mjs`, and unexpected `.claude/` entries (removing the npm package alone is insufficient).
5. **Purge caches + node_modules**: `npm cache clean --force`; `pnpm store prune`; `yarn cache clean`; `rm -rf node_modules`; remove any `setup.mjs`/`execution.js`.
6. **Rebuild Docker images** with `--no-cache`.
7. **Audit GitHub** for dead-drop repos (description "A Mini Shai-Hulud has Appeared"), forged `claude@users.noreply.github.com` commits, and unexpected pushes during the window; delete attacker repos and revoke the tokens that created them.

### Hardening — wherever `can_be_compromised` = yes

| Surface | Fix |
|---|---|
| Loose ranges on the four packages | **Downgrade to the last known-clean versions** — `@cap-js/sqlite@2.2.1`, `@cap-js/postgres@2.2.1`, `@cap-js/db-service@2.10.0`, `mbt@1.2.47` — pin exact, regenerate lock on a clean host |
| No lock file / non-frozen install | Commit a lock file; use `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --immutable` |
| Install scripts enabled in CI | Add `--ignore-scripts` (this wave's `preinstall` hook is blocked by it); run a separate, vetted build step for packages that genuinely need lifecycle scripts |
| **Over-broad npm OIDC trusted publishing** (the root cause) | Scope OIDC trusted-publisher configs to a **specific workflow file on a protected branch**, not the whole repository / any branch. Audit every package's trusted-publisher config |
| Unrestricted CI egress | Allow-list build egress; block runtime Bun downloads from `github.com` and unexpected GitHub repo-creation from runners |
| Long-lived publish tokens | Short-lived OIDC + 2FA + provenance |
| No dependency review | Enable `actions/dependency-review-action`; alert on new `preinstall` hooks in added packages |

---

## Pitfalls & Fixes

Seed this section from a dry-run against a real/test org and grow it from each live run (see the TanStack playbook's "Pitfalls & Fixes" for the pattern). Known so far:

- **`mbt` is a high-collision name.** A bare `mbt` search hits variables, acronyms, and unrelated tokens. Gate on actual npm references: `"mbt"` as a dependency key in `package.json`, or `mbt@` / a resolved `mbt` entry in a lockfile — not source-code mentions.
- **`--ignore-scripts` reasoning differs from the Miasma worm.** Here the trigger is a `preinstall` lifecycle hook, so `--ignore-scripts` blocks it. Do **not** carry over the Miasma assumption that `--ignore-scripts` is ineffective (that was the `binding.gyp`/node-gyp vector).
- **`mbt` name-matching is format-sensitive across lockfiles.** A naive `"mbt"` only matches the `package.json` dependency key; it misses `node_modules/mbt` (npm-lock), `/mbt@…` (pnpm), and `mbt@…:` at line-start (yarn). The validated pattern is **`(^|[/"@[:space:]])mbt[@"/:]`** — it matches all four manifest/lockfile forms while still ignoring prose (`const mbt =`, "combat"). Then **confirm the exact version by parsing** the lockfile (Phase 1 step 3), not with a single-line `name.*version` grep (yarn puts name and version on separate lines). Caught by this playbook's synthetic-fixture functional test (npm + pnpm + yarn, true-positive and true-negative).

---

## References

- StepSecurity / Socket / BleepingComputer / The Hacker News coverage of the SAP `@cap-js` Mini Shai-Hulud wave (use the most comprehensive non-competitor write-up as the canonical reference; cross-check the package list against GitHub Advisories).
- Related TeamPCP / Mini Shai-Hulud waves — `antv_supply_chain/playbook.md` (May 19), `tanstack_supply_chain/playbook.md` (May 11), `trivy/` (March).
- npm OIDC trusted publishing (root-cause hardening) — https://docs.npmjs.com/trusted-publishers
- OSSF malicious-packages database — https://github.com/ossf/malicious-packages
