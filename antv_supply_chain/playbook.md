# May 2026 AntV Mini Shai-Hulud npm Wave (TeamPCP) — Investigation Playbook

Playbook for investigating whether a GitHub org was affected by the **May 19, 2026 "Mini Shai-Hulud" npm wave** that compromised the **`@antv` ecosystem** (and several other packages) via **compromised maintainer accounts**, attributed to the financially-motivated threat actor **TeamPCP**. The campaign published **600+ malicious versions across hundreds of packages** — including a burst of **317 packages in ~22 minutes** — carrying a credential stealer that harvests 20+ secret types, backdoors developer tooling (`.vscode/`, `.claude/`), self-propagates through stolen npm tokens, and forges SLSA/Sigstore provenance.

> **CI/CD platform note:** This playbook targets GitHub Actions. For other CI/CD platforms (GitLab CI, Jenkins, CircleCI, Bitbucket, Azure DevOps), adapt the log-collection commands — the investigation logic is the same: identify references to any compromised package, collect run logs from the exposure window, search for compromised versions and IOCs, and verify lock-file protection.

> **Threat-actor lineage.** TeamPCP also ran the **TanStack / Mini Shai-Hulud wave (May 11, 2026)** (`tanstack_supply_chain/playbook.md`), the **Trivy compromise (March 2026)** (`trivy/`), and the **Bitwarden CLI npm compromise (April 2026)**. This **AntV wave is a distinct, later wave** — same TTPs, but a **different package set and a new C2** (`t.m-kosche[.]com` — the advisory explicitly notes the C2 infrastructure changed from prior waves). If a customer was investigated for the TanStack wave, the procedure here is identical; **the package list and IOC strings are different and must not be substituted blindly.**

---

## Incident Details

The attacker took over legitimate `@antv` (and adjacent) maintainer accounts and pushed trojanized versions. The payload is a worm:

1. **Compromised maintainer accounts** push malicious updates — 600+ malicious versions across hundreds of unique packages.
2. **Credential-stealing payload** harvests **20+ credential types**: AWS, Google Cloud, Azure, GitHub, npm, SSH, Kubernetes, Vault, Stripe, and database connection strings. It also attempts **Docker container escape via the host socket**.
3. **Persistent developer-environment backdoors** — the payload writes malicious entries into **`.vscode/tasks.json`** and **`.claude/settings.json`**, backdooring VS Code and Claude Code. *Removing the malicious package alone does not remediate this.*
4. **Data exfiltration** — stolen data is serialized, compressed, encrypted, and exfiltrated to C2 **`t.m-kosche[.]com:443`**.
5. **Fallback exfiltration** — if C2 fails, the malware uses a stolen GitHub token to create a **public repo under the victim's account** and commits the stolen data as a JSON file. These repos carry the description **`niagA oG eW ereH :duluH-iahS`** (reverses to "Shai-Hulud: Here We Go Again"). **2,500+** such repos have been observed.
6. **npm self-propagation** — with stolen npm tokens the worm: validates the token via the registry API → enumerates the owner's packages → downloads tarballs → injects the payload and a **`preinstall` hook (e.g. `bun run index.js`)** → bumps the version → republishes under the compromised maintainer's identity.
7. **Sigstore / SLSA provenance forgery** — in CI, the payload mints new OIDC tokens and signs artifacts with legitimate Sigstore certificates, making malicious releases indistinguishable from authorized ones. **Provenance attestation is not a safety signal for this wave** — it proves *where* a package was built, not *whether* it was authorized.

> **Install-time vector note (differs from the "Miasma" worm):** This wave executes via a **`preinstall` lifecycle hook** (`bun run index.js`). That means **`--ignore-scripts` DOES block it at install time** — unlike the Miasma "Phantom Gyp" worm, which runs via `node-gyp rebuild` and is not stopped by `--ignore-scripts`. Don't carry the Miasma assumption over to this wave.

### CVE / advisory

- **CVE:** none assigned at time of writing. Recheck NVD / GitHub Advisories under "Mini Shai-Hulud" / "AntV" / affected package names.
- **Primary writeup:** The Hacker News — https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html

### Affected packages

**114 `@antv/*` packages (228+ malicious versions) plus 12 other packages.** The campaign-wide count is 600+ malicious versions. Use the threat-feed item's `indications` list (or GitHub Advisories) as the **per-version source of truth**; the table below groups for detection.

| Group | Packages |
|---|---|
| `@antv/*` core viz | `@antv/g`, `@antv/g2`, `@antv/g6`, `@antv/x6`, `@antv/l7`, `@antv/s2`, `@antv/f2`, `@antv/g2plot`, `@antv/graphin`, `@antv/data-set` (high blast-radius — millions of weekly downloads combined) |
| `@antv/*` (full set) | 114 names total incl. `@antv/adjust`, `@antv/algorithm`, `@antv/attr`, `@antv/coord`, `@antv/component`, `@antv/color-util`, `@antv/dom-util`, `@antv/event-emitter`, `@antv/f-engine`, `@antv/data-wizard`, `@antv/dw-*`, `@antv/dipper-*`, `@antv/f-*` … — treat **any** `@antv/*` install in the window as suspect, confirm version against the canonical list |
| `@lint-md/*` | `@lint-md/cli` (2.1.0, 2.2.0), `@lint-md/core` (2.1.0, 2.2.0), `@lint-md/parser` (0.1.14, 0.2.14) |
| `@openclaw-cn/*` | `@openclaw-cn/cli` (1.4.1), `@openclaw-cn/feishu` (0.2.11), `@openclaw-cn/libsignal` (2.1.1), `@openclaw-cn/toutiao-ops` (1.2.4) |
| Unscoped | `echarts-for-react` (3.1.7, 3.2.7), `timeago.js` (4.1.2, 4.2.2), `size-sensor` (1.1.4, 1.2.4), `canvas-nest.js` (2.1.4, 2.2.4), `@starmind/collector-cli` (0.3.10) |

> **Detection regex (package names):**
> ```
> @antv/|@lint-md/|@openclaw-cn/|@starmind/collector-cli|\b(echarts-for-react|timeago\.js|size-sensor|canvas-nest\.js)\b
> ```

> **High-blast-radius packages** to prioritize: `@antv/g2`, `@antv/g6`, `@antv/x6`, `@antv/l7`, `echarts-for-react`, `timeago.js` (all broadly used in dashboards/visualization frontends and pulled transitively).

### Exposure window

| Event | Time (UTC) |
|---|---|
| AntV wave disclosed | May 19, 2026 |
| Observed burst | 317 packages in ~22 minutes (automated, token-driven) |

**Recommended scan window (padded):** `2026-05-19T00:00:00Z` to `2026-05-20T00:00:00Z` — the advisory does not publish exact start/end timestamps; pad to the full day of disclosure and forward to catch installs that resolved a malicious version before deprecation propagated. Widen if the customer's CI ran infrequently.

### Indicators of compromise

| IOC | Value | Where it shows up |
|---|---|---|
| C2 domain | `t.m-kosche[.]com:443` (encrypted, compressed exfil) | network / proxy / DNS logs |
| Install-time trigger | `preinstall` hook running `bun run index.js` | `node_modules/<pkg>/package.json`, CI install logs |
| Credential targets | AWS, GCP, Azure, GitHub, npm, SSH, Kubernetes, Vault, Stripe, DB connection strings | exfil payloads / cred-access telemetry |
| Container escape | Payload accesses the **Docker host socket** (`/var/run/docker.sock`) **at runtime on a runner** | EDR / host telemetry — **not** a static config grep (see note below) |
| Editor/agent backdoor | Unexpected entries in `.vscode/tasks.json`, `.claude/settings.json` | repo working trees, workstations |
| Fallback exfil | Stolen GitHub token creates a **public repo** with stolen data as JSON | victim's own GitHub account |
| Dead-drop repo description | `niagA oG eW ereH :duluH-iahS` ("Shai-Hulud: Here We Go Again") — 2,500+ observed | GitHub repo descriptions |
| Provenance forgery | Malicious releases carrying **valid Sigstore/SLSA attestations** | npm provenance — **not** a safety signal |
| Self-propagation | Version bumps + republish of the victim's own packages with a `preinstall` hook | npm registry, own packages |

> **False-positive — `/var/run/docker.sock`.** Legitimate CI configs mount the Docker socket all the time — Drone (`.drone.yml`), Docker-in-Docker, `docker-compose` service mounts, GitHub Actions `services`. A **static grep of repo files** for `/var/run/docker.sock` will hit these and they are **not** compromise. The container-escape signal counts only as the **payload accessing the socket at runtime on a runner** (EDR / host telemetry, or an install/run step that has no business touching Docker). Do not flag a repo just because a CI manifest mounts the socket.

### What IS affected

- Any `npm install` / `pnpm install` / `yarn install` that resolved an affected `@antv/*` (or other listed) version during the window — **direct or transitive** — where install scripts were **not** disabled.
- CI workflows that ran package installs during the window without `--ignore-scripts`.
- Docker image builds that ran installs during the window — and any runner where the payload could reach `/var/run/docker.sock` (container-escape risk).
- Developer machines that installed/updated affected packages during the window — check `.vscode/`/`.claude/` backdoors and persistence even after package removal.
- Your **own** npm-published packages, if a maintainer's token was stolen — the worm republishes them with a `preinstall` payload (self-propagation; see Phase 2b).

### What is NOT affected

- Installs from a committed lock file with `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --frozen-lockfile` **as long as the lock pins a non-malicious version** predating the window.
- Installs run with **`--ignore-scripts`** (this wave fires via a `preinstall` hook, which `--ignore-scripts` blocks) — **but** if a malicious *version* was still resolved into the dependency tree, treat it as present and rebuild clean.
- Pre-built Docker images **not rebuilt during the window**.
- Source-only references (a TypeScript `import` without an install in the window); docs/Helm/Terraform that merely name a package.

### Lock file protection

Lock files (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`) **do protect** if used correctly:

- `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --frozen-lockfile` (`--immutable` on berry) install exactly what the lock says.
- A lock generated **before May 19** pinning clean versions never resolves the malicious tarball.

Lock files do **NOT** protect if: no lock is committed; CI runs a non-frozen install; the lock was regenerated during the window; a Dependabot/Renovate PR bumped an affected package mid-window; or a floating range (`^`, `~`, `latest`) lets a fresh install resolve an affected version.

**Unlike the Miasma worm, `--ignore-scripts` IS an effective install-time mitigation here** (the payload runs from a `preinstall` hook). Use it as defense-in-depth — but it does not undo a malicious version already pinned in the tree.

---

## Setup

```bash
export ORG="<your-github-org>"
export SINCE="2026-05-19T00:00:00Z"
export UNTIL="2026-05-20T00:00:00Z"
export LOG_DIR="/tmp/supply-chain-scan-antv"
mkdir -p "$LOG_DIR"
```

**Log caching:** reuse logs in `$LOG_DIR` if present. **Write evidence to files, not context** — write CSV to `$LOG_DIR` as you go. **Rate limits:**

```bash
gh api /rate_limit --jq '.resources.core | "\(.remaining)/\(.limit) (resets \(.reset|todate))"'
gh api /rate_limit --jq '.resources.code_search | "code-search: \(.remaining)/\(.limit)"'
```

Code search ~30 req/min; REST 5,000/hr; log downloads count against REST. Use `xargs -P 10`. For orgs over ~50 repos, shallow-clone and grep locally (Phase 1).

---

## Phase 1: Repo Analysis

**Goal:** For every repo referencing an affected package, capture declared/locked versions, the install command, and whether the config is vulnerable in principle. Window-agnostic.

### 1. Find references to any affected package

```bash
PKG_RE='@antv/|@lint-md/|@openclaw-cn/|@starmind/collector-cli|echarts-for-react|timeago\.js|size-sensor|canvas-nest\.js'

for pkg in "@antv" "@lint-md" "@openclaw-cn" "@starmind/collector-cli" \
           echarts-for-react timeago.js size-sensor canvas-nest.js; do
  q=$(printf '%s' "$pkg" | python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.stdin.read()))")
  echo "=== $pkg ==="
  gh api "search/code?q=${q}+org:${ORG}&per_page=100" \
    --jq '.items[] | "'"$pkg"'\t\(.repository.full_name)\t\(.path)"' 2>/dev/null
  sleep 2
done | sort -u > "$LOG_DIR/refs.tsv"
wc -l "$LOG_DIR/refs.tsv"
```

> **Faster alternative for large orgs (>50 repos):** shallow-clone and grep locally.
> ```bash
> mkdir -p "$LOG_DIR/clones" && cd "$LOG_DIR/clones"
> gh repo list "$ORG" --no-archived --limit 1000 --json nameWithOwner --jq '.[].nameWithOwner' | \
>   xargs -P 10 -I {} bash -c 'git clone --depth 1 --filter=blob:none "git@github.com:{}.git" 2>/dev/null || echo "FAIL: {}"'
> grep -rE --include='package.json' --include='package-lock.json' --include='pnpm-lock.yaml' --include='yarn.lock' \
>   "$PKG_RE" . > "$LOG_DIR/refs-from-local-clone.txt"
> ```

### 2. Classify each reference

| File pattern | Category | Risk |
|---|---|---|
| `package.json` | npm manifest | **HIGH** — check spec range vs malicious versions |
| `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` | Lock file | **CRITICAL** — check pinned version against malicious list |
| `Dockerfile` | Docker build | **HIGH** if it runs an install during the window |
| `.github/workflows/*.yml` | CI workflow | **CHECK** — does it install JS deps incl. an affected package? |
| `*.ts/.tsx/.js/.jsx` | Source | **NOT AFFECTED** — import, not install |
| `*.md`, `values.yaml`, `*.tf` | Docs / infra | **NOT AFFECTED** |

### 3. Extract version data per repo

```bash
# package.json — affected spec
gh api "repos/${ORG}/<repo>/contents/package.json" --jq '.content' | base64 -d | \
  python3 -c "
import sys,json,re
d=json.load(sys.stdin)
rx=re.compile(r'(@antv/|@lint-md/|@openclaw-cn/|@starmind/collector-cli|echarts-for-react|timeago\.js|size-sensor|canvas-nest\.js)')
for s in ('dependencies','devDependencies','optionalDependencies','peerDependencies'):
  for k,v in d.get(s,{}).items():
    if rx.search(k): print(f'{s}: {k} = {v}')
"

# package-lock.json — resolved versions
gh api "repos/${ORG}/<repo>/contents/package-lock.json" --jq '.content' | base64 -d | \
  python3 -c "
import sys,json,re
d=json.load(sys.stdin)
rx=re.compile(r'(@antv/|@lint-md/|@openclaw-cn/|@starmind/collector-cli|echarts-for-react|timeago\.js|size-sensor|canvas-nest\.js)')
for k,v in d.get('packages',{}).items():
  name=k.split('node_modules/')[-1]
  if rx.search(name): print(f'{name}: {v.get(\"version\")}')
"

# Install commands
gh api "repos/${ORG}/<repo>/contents/.github/workflows" --jq '.[].path' 2>/dev/null | while read wf; do
  gh api "repos/${ORG}/<repo>/contents/${wf}" --jq '.content' | base64 -d | \
    grep -iE "npm ci|npm install|pnpm install|yarn install|yarn$|bun install|--ignore-scripts"
done
```

### 4. Write the repo evidence table

Write `$LOG_DIR/evidence-repos.csv`:

```
repo,path,source_type,manifest_spec,spec_in_range,has_lockfile,lockfile_version,lock_protects,install_command,ignore_scripts,can_be_compromised
```

| Column | What to write |
|---|---|
| `manifest_spec` | Exact specifier as written; `transitive` if indirect |
| `spec_in_range` | `yes (allows <malicious-version>)` / `no (reason)` |
| `lock_protects` | `yes` if `lockfile_version` is not a malicious value; `no` if it is |
| `install_command` | `npm ci`, `pnpm install --frozen-lockfile`, `yarn install`, etc. |
| `ignore_scripts` | `yes` if the install uses `--ignore-scripts` (blocks the preinstall hook); `no` otherwise |
| `can_be_compromised` | `no` if lock protects AND install respects lock; `yes` otherwise. Note: `--ignore-scripts` reduces but doesn't eliminate risk if a malicious version is still resolved |

---

## Phase 2: CI Run Analysis

**Why:** Phase 1 only finds repos that name an affected package. Transitive installs won't show. CI logs reveal what actually got installed.

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

### 3. Scan logs for affected packages and AntV-wave IOCs

```bash
# Affected package references
echo "=== Affected-package references ==="
grep -rlinE "@antv/|@lint-md/|@openclaw-cn/|@starmind/collector-cli|echarts-for-react|timeago\.js|size-sensor|canvas-nest\.js" "$LOG_DIR"/run-*.log 2>/dev/null

# Install-time trigger: preinstall hook running bun
echo "=== preinstall / bun run index.js ==="
grep -rlinE "preinstall|bun run index\.js|bun install" "$LOG_DIR"/run-*.log 2>/dev/null

# C2 + dead-drop + container escape + provenance forgery
echo "=== AntV-wave IOCs ==="
grep -rlinE "t\.m-kosche\.com|m-kosche" "$LOG_DIR"/run-*.log 2>/dev/null
grep -rlinE "niagA oG eW ereH|Shai-Hulud" "$LOG_DIR"/run-*.log 2>/dev/null
grep -rlinE "/var/run/docker\.sock|docker.*socket" "$LOG_DIR"/run-*.log 2>/dev/null
```

> **Why scan IOCs, not just package names?** A frozen install of a clean tree shows package names with no compromise; a transitive pull of a malicious version may be quiet on names but show the `preinstall`/`bun` execution or a connection to `t.m-kosche.com`. The execution + C2 signals are higher-fidelity.

### 4. Classify hits

**Real install / execution:** `added @antv/<pkg>@<version>` (npm), `+ @antv/<pkg> <version>` (pnpm), resolution lines (yarn); `preinstall` script output / `bun run index.js`; any connection to `t.m-kosche.com`; Docker-socket access.
**False positives:** source imports, SAST/dependency-review output, branch names (`dependabot/npm_and_yarn/@antv/...`), docs, your own legitimate `bun` usage (correlate with the affected-package list + C2 before flagging).

### 5. Write `$LOG_DIR/evidence-ci-runs.csv`

```
repo,run_id,created_at,workflow,platform,install_command,ignore_scripts,version_installed,lock_respected,iocs_found,ci_compromised
```
One row per install execution; verdict `clean` / `compromised` / `clean (component not installed)`. No blank cells.

---

## Phase 2b: The Customer's Own Published Packages (Forward-Propagation Risk)

This is a worm: if any maintainer in the org had an npm token stolen during the window, it enumerated their packages and **republished them with a `preinstall` payload**. Check whether the customer shipped the payload forward.

```bash
# Enumerate own packages by scope + maintainer
curl -s "https://registry.npmjs.org/-/v1/search?text=scope:${SCOPE}&size=250" | \
  python3 -c "import sys,json; [print(p['package']['name']) for p in json.load(sys.stdin)['objects']]" > "$LOG_DIR/own-packages.txt"

# Versions published in the window
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
python3 -c "import json; d=json.load(open('package/package.json')); print('preinstall:', d.get('scripts',{}).get('preinstall'))"
grep -rliE "bun run index\.js|t\.m-kosche\.com|/var/run/docker\.sock" package/ 2>/dev/null
cd -
```

A `preinstall` running `bun`/`index.js`, or any reference to `t.m-kosche.com` → **directly republished by the worm**: `npm deprecate '<pkg>@<version>' 'Compromised (Mini Shai-Hulud) — do not install.'`, publish a clean superseding version from a clean host, notify downstream, and rotate the publisher's npm + GitHub tokens (Phase 6).

---

## Phase 3: Network Investigation

| Signal | Where to search |
|---|---|
| DNS resolution / outbound to `t.m-kosche[.]com` (port 443) | DNS logs, proxy, NetFlow, VPC Flow Logs |
| GitHub API repo-creation from a CI runner / dev host (fallback exfil) | GitHub audit log, proxy logs |
| New **public** repos under org/user accounts with description `niagA oG eW ereH :duluH-iahS` | GitHub audit log / org repo list |
| Outbound to npm registry token-validation + tarball downloads from an unexpected host (self-propagation) | proxy logs |
| Docker host-socket access from a build step | EDR / host telemetry |

**Where:** AWS VPC Flow Logs + Route 53 Resolver logs + CloudTrail; GCP/Azure equivalents; on-prem firewall/proxy/DNS; SIEM. **Time window:** May 19 forward **at least 7 days** — stolen tokens are abused after the install.

**Splunk example:**
```
index=dns query="t.m-kosche.com" OR query="*m-kosche.com"
| stats count by src_ip, query, answer
```

---

## Phase 4: Workstation Investigation

Dev machines that ran installs during the window may have executed the payload. The backdoors (`.vscode/`, `.claude/`) survive package removal — check them even if `node_modules` looks clean.

### 4a. Payload in `node_modules` + preinstall hooks

```bash
PKG_RE='@antv|@lint-md|@openclaw-cn|collector-cli|echarts-for-react|timeago|size-sensor|canvas-nest'
for root in ~/projects ~/code ~/repos ~/work "$HOME"; do
  [ -d "$root" ] || continue
  find "$root" -path '*/node_modules/*/package.json' 2>/dev/null | \
    xargs grep -lE '"preinstall".*("bun"|index\.js)' 2>/dev/null | grep -iE "$PKG_RE"
done
```

### 4b. Lock files referencing malicious versions

```bash
find ~ \( -name 'package-lock.json' -o -name 'pnpm-lock.yaml' -o -name 'yarn.lock' \) \
  -not -path '*/node_modules/*' 2>/dev/null | \
  xargs grep -lE "@antv/|@lint-md/|@openclaw-cn/|echarts-for-react|timeago\.js|size-sensor|canvas-nest\.js" 2>/dev/null \
  > "$LOG_DIR/workstation-lockfiles-with-affected-pkgs.txt"
```
Cross-check pinned versions against the canonical malicious list.

### 4c. Editor / agent backdoors (survive package removal)

```bash
find ~ -maxdepth 6 \( -path '*/.vscode/tasks.json' -o -path '*/.claude/settings.json' \) 2>/dev/null | while read f; do
  echo "=== $f (modified $(stat -f '%Sm' "$f" 2>/dev/null || stat -c '%y' "$f" 2>/dev/null)) ==="
  grep -lE "bun run index\.js|t\.m-kosche\.com|curl|wget|base64 -d|child_process" "$f" 2>/dev/null && echo "  *** SUSPICIOUS ***"
done
```
Pay particular attention to files modified on/after **2026-05-19**.

### 4d. OS-level Docker-socket / persistence checks

```bash
ls -la /var/run/docker.sock 2>/dev/null
lsof /var/run/docker.sock 2>/dev/null | grep -iE "node|bun" 
netstat -an 2>/dev/null | grep -E "ESTABLISHED" | grep -v 127.0.0.1
grep -iE "m-kosche" /etc/hosts 2>/dev/null
```

### 4e. npm / pnpm / yarn cache + debug logs

```bash
npm cache ls 2>/dev/null | grep -iE "@antv|@lint-md|@openclaw-cn|echarts-for-react|timeago|size-sensor|canvas-nest"
grep -liE "@antv/|preinstall|bun run index\.js|m-kosche" ~/.npm/_logs/*.log 2>/dev/null
```

### 4f. AI agent conversation logs (exclude the investigating agent's own session)

> If you're running this playbook through an AI coding agent, its transcript will contain these IOC strings because you've been *reading* them — that's investigation, not compromise. Exclude the current session.

```bash
CURRENT_SESSION_PROJECT=$(echo "$PWD" | sed 's|/|-|g')
grep -rliE "t\.m-kosche\.com|niagA oG eW ereH|bun run index\.js|@antv/" \
  "$HOME/.claude/projects" \
  "$HOME/Library/Application Support/Cursor" \
  "$HOME/Library/Application Support/Windsurf" \
  "$HOME/.config/github-copilot" 2>/dev/null | \
  grep -v "${CURRENT_SESSION_PROJECT}" | grep -v "paste-cache" | grep -v "file-history"
```

### 4g. Dead-drop repos in your own GitHub org

```bash
# Public repos created in the window
gh api --paginate "/orgs/${ORG}/repos?per_page=100&sort=created&direction=desc" \
  --jq ".[] | select(.created_at > \"${SINCE}\") | select(.visibility==\"public\") | \"\(.name) | \(.created_at)\""
# Repos whose description matches the dead-drop signature
gh api --paginate "/orgs/${ORG}/repos?per_page=100" \
  --jq '.[] | select((.description // "") | test("niagA oG eW ereH|Shai-Hulud")) | "\(.name) | \(.description)"'
```

---

## Phase 5: Present Results

1. **Repo Analysis table** (`evidence-repos.csv`) — posture per repo, window-agnostic.
2. **CI Runs table** (`evidence-ci-runs.csv`) — installs in the window, IOCs, verdict.
3. **Customer-Published Packages table** (`evidence-own-published.csv`) — forward-propagation; verdict per version.
4. **Executive Summary** — verdict (`clean`/`compromised`); scope; repo posture (which `@antv/*` etc. families, lock coverage, `--ignore-scripts` usage); CI findings; network (`t.m-kosche.com`, fallback repo-creation); workstation (`.vscode`/`.claude` backdoors, Docker-socket, caches); org-side dead-drop repos; forward propagation; one-sentence bottom line.

**Action needed** if any: `can_be_compromised=yes`, any `ci_compromised=compromised`, workstation backdoors/persistence, or dead-drop repos. **Vulnerable but not hit** (`can_be_compromised=yes`, no runs in window) → Phase 6 hardening.

---

## Phase 6: Hardening & Remediation (User Approval Required)

**Do NOT proceed without explicit user approval.** Present findings first.

### Remediation — only if compromised

Rotate before scrubbing — the stealer grabs **20+ credential types**, so rotate broadly.

1. **Quarantine** affected workstations; drain/stop affected CI runners (terminate if ephemeral).
2. **Snapshot** payload files, `.vscode/tasks.json`, `.claude/settings.json`, shell history, `~/.npmrc` for forensics.
3. **Rotate all of**: GitHub tokens (PATs, `gh` token, deploy keys, App installation tokens), npm tokens, **AWS / GCP / Azure** credentials, SSH keys, **Kubernetes** secrets, **Vault** tokens, **Stripe** API keys, and any **database connection strings** reachable from affected hosts. Enforce **2FA** everywhere.
4. **Remove the editor/agent backdoors**: clean malicious entries from `.vscode/tasks.json` and `.claude/settings.json` (removing the npm package alone is insufficient).
5. **Purge caches + node_modules**: `npm cache clean --force`; `pnpm store prune`; `yarn cache clean`; `rm -rf node_modules`.
6. **Rebuild Docker images** with `--no-cache`; given the **Docker-socket escape**, treat any host whose build runner exposed `/var/run/docker.sock` as potentially host-compromised.
7. **Block C2** `t.m-kosche[.]com` at the network edge.
8. **Audit GitHub** for dead-drop repos (description `niagA oG eW ereH :duluH-iahS`) under your org/users and delete them; revoke the tokens that created them.
9. **Do not trust provenance** for this wave — malicious releases carry forged Sigstore/SLSA attestations. Re-verify against maintainer-confirmed safe versions, not attestation alone.

### Hardening — wherever `can_be_compromised` = yes

| Surface | Fix |
|---|---|
| No lock file | Commit `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` |
| Non-frozen install | Switch to `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --immutable` |
| Install scripts enabled in CI | Add `--ignore-scripts` (this wave's `preinstall` hook is blocked by it) and run a separate, vetted build step for packages that truly need lifecycle scripts |
| Loose `^`/`~`/`latest` ranges on `@antv/*` etc. | Pin exact pre-incident versions; regenerate lock on a clean host |
| CI runner can reach the Docker socket | Don't mount `/var/run/docker.sock` into build jobs; use rootless/remote builders |
| Unrestricted CI egress | Allow-list build egress; block `t.m-kosche.com` and unexpected GitHub repo-creation from runners |
| Long-lived publish tokens | Short-lived OIDC + 2FA + provenance — but treat provenance as non-authoritative for trust decisions |
| No dependency review | Enable `actions/dependency-review-action`; alert on new `preinstall` hooks in added packages |

### Upgrade path

No single "safe replacement" is published per package. **Downgrade to a pre-incident version** of each affected `@antv/*` (and other) package (predating May 19) until maintainers confirm a clean post-incident release; then regenerate the lock on a clean host and commit it.

---

## References

- The Hacker News — "Mini Shai-Hulud Pushes Malicious AntV npm Packages via Compromised Maintainer Account" — https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html
- Related TeamPCP / Mini Shai-Hulud wave (May 11, 2026, TanStack) — `tanstack_supply_chain/playbook.md`
- Related TeamPCP compromise (March 2026, Trivy) — `trivy/`
- OSSF malicious-packages database — https://github.com/ossf/malicious-packages
