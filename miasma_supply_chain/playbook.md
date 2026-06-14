# June 2026 "Miasma" npm Worm (Phantom Gyp) — Investigation Playbook

Playbook for investigating whether a GitHub org was affected by the **June 2026 "Miasma" npm worm**, a self-replicating supply-chain attack that compromised **57 npm packages across 286+ malicious versions**. Miasma's defining trait is the **"Phantom Gyp"** execution technique: a malicious `binding.gyp` triggers code execution during `npm install` **without any `package.json` lifecycle script** — so `--ignore-scripts` does **not** stop it. The payload escalates privileges, scrapes GitHub tokens and other secrets out of the GitHub Actions `Runner.Worker` process memory (`/proc/<pid>/mem`), and exfiltrates credentials to attacker-controlled GitHub repositories.

> **CI/CD platform note:** This playbook targets GitHub Actions. For other CI/CD platforms (GitLab CI, Jenkins, CircleCI, Bitbucket, Azure DevOps), adapt the log-collection commands — the investigation logic is the same: identify references to **any compromised package**, collect run logs from the exposure window, search for compromised versions and IOCs, and verify lock-file protection.

> **Threat-actor lineage.** Miasma is a Shai-Hulud-family worm. One of its own dead-drop repository descriptions is the reversed string `niagA oG eW ereH :duluH-iahS` — "**Shai-Hulud: Here We Go Again**". If a customer was investigated for the **TanStack / Mini Shai-Hulud wave (May 2026)** (`tanstack_supply_chain/playbook.md`), the same detection workflow applies here with updated package names and IOCs — but note the install-time vector is different (see "Phantom Gyp" below), so the `--ignore-scripts` mitigation that helped against earlier waves does **not** help against Miasma.

---

## Incident Details

Miasma propagates the way classic worms do — it compromises a package, runs at install time on whoever pulls it (developer or CI), steals that victim's GitHub/npm credentials, then republishes the victim's own packages with the same payload — but it lands its code through a vector most tooling ignores:

1. A compromised package ships a malicious **`binding.gyp`** (the build-configuration file `node-gyp` consumes for native addons).
2. During `npm install`, npm invokes **`node-gyp rebuild`** for any package that has a `binding.gyp`. node-gyp evaluates the file's actions — so the attacker gets code execution **without a `preinstall`/`postinstall` script in `package.json`**. This is the **"Phantom Gyp"** technique.
3. The gyp action runs **`node index.js`**, which downloads the **Bun** runtime from `github.com`, then executes the second-stage payload from a randomized temp path (e.g. `/tmp/p1764ajw42rg.js`).
4. The payload runs **`gh auth token`** to steal the GitHub token, attempts **`sudo python3`** for privilege escalation, and uses **`python3`** to read **`/proc/<pid>/mem`** of the GitHub Actions `Runner.Worker` process to extract secrets/OIDC tokens held only in memory.
5. Stolen credentials are exfiltrated to **attacker-controlled GitHub repositories** (used as credential dead-drops) via `api.github.com`, and the worm enumerates the victim's own published packages and republishes them with the payload — self-propagation.

> **Critical — `--ignore-scripts` is not a defense here.** Because execution rides `node-gyp rebuild` (a build step, not a lifecycle script), disabling install scripts does not block Miasma. The only install-time defenses are a **frozen lock file pinned to a clean version** and **not building native addons from untrusted packages** (see Lock file protection + Hardening).

### CVE / advisory

- **CVE:** none assigned at time of writing. Recheck NVD / GitHub Advisories under "Miasma" / "Phantom Gyp" / affected package names.
- **Primary writeup:** StepSecurity — https://www.stepsecurity.io/blog/binding-gyp-npm-supply-chain-attack-spreads-like-worm

### Affected packages

**57 npm package names across 286+ malicious versions.** Use the threat-feed item's `indications` list (or GitHub Advisories) as the **per-version source of truth** — the table below groups by family for detection. The malicious versions are scattered point-releases, so treat **any** install of these package names during the window as suspect and confirm the exact version against the canonical list.

| Family | Package names (representative) | Notes |
|---|---|---|
| `autotel*` | `autotel`, `autotel-cli`, `autotel-mcp` (27 versions), `autotel-subscribers` (28), `autotel-terminal` (22), `autotel-mongoose`, `autotel-devtools`, `autotel-eventcatalog`, `autotel-mcp-instrumentation`, `autotel-aws`, `autotel-cloudflare`, `autotel-edge`, `autotel-hono`, `autotel-sentry`, `autotel-pact`, `autotel-plugins`, `autotel-adapters`, `autotel-audit`, `autotel-backends`, `autotel-drizzle`, `autotel-playwright`, `autotel-tanstack`, `autotel-vitest`, `autotel-web` | Largest cluster; many consecutive malicious versions |
| `awaitly*` | `awaitly`, `awaitly-libsql` (23), `awaitly-mongo` (24), `awaitly-postgres` (24), `awaitly-visualizer` (22), `awaitly-analyze` (9), `eslint-plugin-awaitly` | High version counts per package |
| `executable-stories*` | `executable-stories-vitest`, `-jest`, `-cypress`, `-playwright`, `-mcp`, `-react`, `-demo`, `-init`, `-formatters`; `eslint-plugin-executable-stories-{jest,playwright,vitest}` | Test-tooling cluster |
| `node-env-resolver*` | `node-env-resolver`, `-aws`, `-dotenvx`, `-nextjs`, `-vite` | Config-resolution cluster |
| AI/agent SDKs | `ai-sdk-ollama`, `@vapi-ai/server-sdk` (0.11.1, 0.11.2, 1.2.1, 1.2.2), `@evolvconsulting/evolv-coder-lite`, `@jagreehal/workflow` | — |
| Misc | `mountly`, `mountly-tailwind`, `effect-analyzer`, `http-uploader-dev`, `wrangler-deploy` | — |
| **Earlier variants** | `@redhat-cloud-services/*` (32 packages, June 1 2026); `@vapi-ai/server-sdk` (4 versions, June 3 2026) | Same worm, earlier waves — include if scanning a wider window |

> **Detection regex (package names):**
> ```
> @vapi-ai/server-sdk|@evolvconsulting/evolv-coder-lite|@jagreehal/workflow|ai-sdk-ollama|@redhat-cloud-services/|\b(autotel|awaitly|eslint-plugin-awaitly|executable-stories[-a-z]*|eslint-plugin-executable-stories[-a-z]*|node-env-resolver[-a-z]*|mountly|mountly-tailwind|effect-analyzer|http-uploader-dev|wrangler-deploy)\b
> ```

### Exposure window

| Event | Time (UTC) |
|---|---|
| Main campaign start | June 3, 2026, ~23:30 |
| Main campaign duration | under ~2 hours |
| Earlier variant — `@redhat-cloud-services` (32 pkgs) | June 1, 2026 |
| Earlier variant — `@vapi-ai/server-sdk` (4 versions) | June 3, 2026 |

**Recommended scan window (padded):** `2026-06-01T00:00:00Z` to `2026-06-04T06:00:00Z` — wide enough to catch the June 1 `@redhat-cloud-services` variant and the main June 3 burst, plus a forward pad for installs that resolved a malicious version before npm pulled it. If you only consume the main-wave package families, narrow to `2026-06-03T23:00:00Z` … `2026-06-04T03:00:00Z`.

### Indicators of compromise

| IOC | Value | Where it shows up |
|---|---|---|
| Install-time build vector | A `binding.gyp` in a package that has no legitimate native addon | `node_modules/<pkg>/binding.gyp` |
| Process chain | `node-gyp rebuild` → `node index.js` → Bun download → `gh auth token` → `sudo python3` → `python3` reading `/proc/<pid>/mem` | CI logs, host telemetry/EDR |
| Dropped payload | Second-stage written to randomized temp path, e.g. `/tmp/p1764ajw42rg.js` (pattern: `/tmp/p<random>.js`) | runner / workstation filesystem |
| Runtime download | Bun runtime fetched from `github.com` **during `npm install`** | network logs, CI logs |
| Exfil channel | Outbound to `api.github.com` to push stolen creds into attacker repos **during/after install** | network logs |
| Attacker GitHub account | `liuende501` (hosted ~236 repos used as credential dead-drops) | GitHub references, exfil destinations |
| Dead-drop repo naming | Dynamically created repos, e.g. `nemean-hydra-34343`; descriptions `"Miasma - The Spreading Blight"` or reversed `"niagA oG eW ereH :duluH-iahS"` | attacker org / your org if self-propagated |
| Token theft command | Unexpected `gh auth token` invocations in build output | CI logs, shell history |
| Memory scrape | Any process reading `/proc/<pid>/mem` of `Runner.Worker` | CI logs, EDR |

> **Why `github.com` / `api.github.com` are tricky IOCs.** Both are normal destinations for CI. The signal is **timing and context**: an outbound fetch of the Bun runtime from `github.com`, or pushes to `api.github.com`, **interleaved with an `npm install` / `node-gyp rebuild` step**, from a runner that has no reason to download Bun or write to GitHub during a build. Legitimate `npm install` traffic should go to `registry.npmjs.org` and `nodejs.org`, not pull a runtime from `github.com`.

### What IS affected

- Any `npm install` / `pnpm install` / `yarn install` that resolved an affected package-version during the window — **direct or transitive** — on a machine that builds native addons (i.e. has `node-gyp` / a C toolchain available, which most CI runners do).
- CI workflows that ran package installs during the window. **`--ignore-scripts` does not protect** — the gyp build step still runs.
- Docker image builds that ran `npm/pnpm/yarn install` during the window.
- Developer machines that installed or updated any affected package during the window — especially hosts where `gh` is authenticated (the payload steals the `gh` token).
- Your **own** npm-published packages, if a maintainer's machine or release runner was hit — the worm republishes the victim's packages with the payload (self-propagation; see Phase 2b).

### What is NOT affected

- Installs from a committed lock file with `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --frozen-lockfile` **as long as the lock file pins a non-malicious version** that predates the window.
- Pre-built Docker images **not rebuilt during the window**.
- Source-code-only references (a TypeScript `import` without an install having run during the window).
- Repos that name an affected package in docs / Helm / Terraform without installing it.
- Environments with **no native-build toolchain** where the install is fully lock-pinned and frozen (the gyp step can't fetch/compile) — but do not rely on this alone; verify the lock + frozen install instead.

### Lock file protection

Lock files (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`) **do protect** against Miasma **if used correctly** — but the usual "just add `--ignore-scripts`" advice does **not** apply here.

- `npm ci`, `pnpm install --frozen-lockfile`, `yarn install --frozen-lockfile` (`--immutable` on berry) install exactly what the lock file says.
- If the lock file was generated **before the window** and pins clean versions, the malicious tarball is never resolved and no `binding.gyp` from an affected package ever runs.

Lock files do **NOT** protect if:
- No lock file is committed.
- CI runs `npm install` / `pnpm install` / `yarn install` without a frozen flag (these can update the lock).
- The lock file was regenerated **during** the window.
- A Dependabot/Renovate PR merged during the window bumped an affected package to a malicious version inside the lock file.
- A floating range (`^`, `~`, `latest`) lets a fresh `npm install <other-pkg>` resolve an affected transitive dep.

**`--ignore-scripts` does NOT protect** against Miasma, because the code executes via `node-gyp rebuild`, not a lifecycle script.

---

## Setup

```bash
export ORG="<your-github-org>"
export SINCE="2026-06-01T00:00:00Z"
export UNTIL="2026-06-04T06:00:00Z"
export LOG_DIR="/tmp/supply-chain-scan-miasma"
mkdir -p "$LOG_DIR"
```

**Log caching:** If `$LOG_DIR` already has logs from a previous run, reuse them — skip the download step.

**Write to files, not context:** Results can be large. Write structured evidence (CSV) to `$LOG_DIR` as you go; don't accumulate findings in conversation context.

**Rate limits.** Before scanning a large org, check your GitHub API budget:

```bash
gh api /rate_limit --jq '.resources.core | "\(.remaining)/\(.limit) remaining (resets \(.reset | todate))"'
gh api /rate_limit --jq '.resources.code_search | "code-search: \(.remaining)/\(.limit) remaining"'
```

Code search is ~30 req/min; REST is 5,000 req/hr; log downloads count against REST. Use `xargs -P 10` for parallelism and cache everything to `$LOG_DIR`. For orgs over ~50 repos, shallow-clone and grep locally (see Phase 1).

---

## Phase 1: Repo Analysis

**Goal:** For every repo that references an affected package, build a static picture of dependency configuration — declared versions, what's locked, what install command CI uses, and whether the configuration is vulnerable in principle. Window-agnostic.

### 1. Find references to any affected package

```bash
# Set up the package-name patterns (family-level)
PKG_RE='@vapi-ai/server-sdk|@evolvconsulting/evolv-coder-lite|@jagreehal/workflow|ai-sdk-ollama|@redhat-cloud-services/|autotel|awaitly|executable-stories|node-env-resolver|mountly|effect-analyzer|http-uploader-dev|wrangler-deploy'

# Search per distinctive token (code search can't OR a long list in one query)
for pkg in autotel awaitly executable-stories node-env-resolver ai-sdk-ollama \
           mountly effect-analyzer http-uploader-dev wrangler-deploy \
           "@vapi-ai/server-sdk" "@evolvconsulting/evolv-coder-lite" "@jagreehal/workflow" \
           "@redhat-cloud-services"; do
  q=$(printf '%s' "$pkg" | python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.stdin.read()))")
  echo "=== $pkg ==="
  gh api "search/code?q=${q}+org:${ORG}&per_page=100" \
    --jq '.items[] | "'"$pkg"'\t\(.repository.full_name)\t\(.path)"' 2>/dev/null
  sleep 2  # code-search rate limit ~30 req/min
done | sort -u > "$LOG_DIR/refs.tsv"

wc -l "$LOG_DIR/refs.tsv"
```

> **Faster alternative for large orgs (recommended >50 repos):** shallow-clone the org and grep locally.
> ```bash
> mkdir -p "$LOG_DIR/clones" && cd "$LOG_DIR/clones"
> gh repo list "$ORG" --no-archived --limit 1000 --json nameWithOwner --jq '.[].nameWithOwner' | \
>   xargs -P 10 -I {} bash -c 'git clone --depth 1 --filter=blob:none "git@github.com:{}.git" 2>/dev/null || echo "FAIL: {}"'
> grep -rE --include='package.json' --include='package-lock.json' --include='pnpm-lock.yaml' --include='yarn.lock' \
>   "$PKG_RE" . > "$LOG_DIR/refs-from-local-clone.txt"
> wc -l "$LOG_DIR/refs-from-local-clone.txt"
> ```

### 2. Classify each reference

| File pattern | Category | Risk |
|---|---|---|
| `package.json` | npm manifest | **HIGH** — check spec range vs malicious versions |
| `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` | Lock file | **CRITICAL** — check pinned version against malicious list |
| `Dockerfile` | Docker build | **HIGH** if it runs `npm/pnpm/yarn install` and builds native deps |
| `.github/workflows/*.yml` | CI workflow | **CHECK** — does it install JS deps that include an affected package? |
| `*.ts`, `*.tsx`, `*.js`, `*.jsx` | Source code | **NOT AFFECTED** — import reference, not install |
| `*.md`, `README*`, `values.yaml`, `*.tf` | Docs / infra | **NOT AFFECTED** |

### 3. Extract version data per repo

```bash
# package.json — extract affected-pkg spec
gh api "repos/${ORG}/<repo>/contents/package.json" --jq '.content' | base64 -d | \
  python3 -c "
import sys,json,re
d=json.load(sys.stdin)
rx=re.compile(r'(@vapi-ai/server-sdk|@evolvconsulting/evolv-coder-lite|@jagreehal/workflow|ai-sdk-ollama|@redhat-cloud-services/|autotel|awaitly|executable-stories|node-env-resolver|mountly|effect-analyzer|http-uploader-dev|wrangler-deploy)')
for section in ('dependencies','devDependencies','optionalDependencies','peerDependencies'):
  for k,v in d.get(section,{}).items():
    if rx.search(k): print(f'{section}: {k} = {v}')
"

# package-lock.json — resolved versions
gh api "repos/${ORG}/<repo>/contents/package-lock.json" --jq '.content' | base64 -d | \
  python3 -c "
import sys,json,re
d=json.load(sys.stdin)
rx=re.compile(r'(autotel|awaitly|executable-stories|node-env-resolver|ai-sdk-ollama|@vapi-ai/server-sdk|@redhat-cloud-services/|mountly|effect-analyzer|http-uploader-dev|wrangler-deploy)')
for k,v in d.get('packages',{}).items():
  name=k.split('node_modules/')[-1]
  if rx.search(name): print(f'{name}: {v.get(\"version\")}')
"

# Install command in workflows / Dockerfile
gh api "repos/${ORG}/<repo>/contents/.github/workflows" --jq '.[].path' 2>/dev/null | while read wf; do
  gh api "repos/${ORG}/<repo>/contents/${wf}" --jq '.content' | base64 -d | \
    grep -iE "npm ci|npm install|pnpm install|yarn install|yarn$|bun install"
done
gh api "repos/${ORG}/<repo>/contents/Dockerfile" --jq '.content' 2>/dev/null | base64 -d | \
  grep -iE "RUN.*(npm|pnpm|yarn|bun).*install"
```

### 4. Write the repo evidence table

Write `$LOG_DIR/evidence-repos.csv`:

```
repo,path,source_type,manifest_spec,spec_in_range,has_lockfile,lockfile_version,lock_protects,install_command,install_upgrades,can_be_compromised
```

| Column | What to write |
|---|---|
| `repo` | Repo name (no org prefix) |
| `path` | Full file path of the reference |
| `source_type` | `manifest` / `lockfile` / `ci-workflow` / `dockerfile` / `script` |
| `manifest_spec` | Exact specifier as written (`^2.26.0`); `transitive` if pulled indirectly |
| `spec_in_range` | `yes (allows <malicious-version>)` or `no (reason)` |
| `has_lockfile` | `yes (package-lock.json)` / `yes (pnpm-lock.yaml)` / `yes (yarn.lock)` / `no` |
| `lockfile_version` | Exact pinned version for the affected package(s); `none` if no lock |
| `lock_protects` | `yes` if `lockfile_version` is not a malicious value; `no` if it is |
| `install_command` | `npm ci`, `pnpm install --frozen-lockfile`, `yarn install` (no flags), etc. |
| `install_upgrades` | `no` for frozen/`ci`; `possible` for non-frozen; `n/a` if affected pkg not installed here |
| `can_be_compromised` | `no` if lock protects AND install respects lock; `yes` otherwise |

### Install command cheat sheet

| Command | Lock file respected? |
|---|---|
| `npm ci` | **Yes** |
| `npm install` (no args) | **Partially** — can update lock |
| `npm install <pkg>` | **No** — resolves to latest matching |
| `pnpm install --frozen-lockfile` | **Yes** |
| `pnpm install` (no flag) | **No (in CI)** |
| `yarn install --frozen-lockfile` / `--immutable` | **Yes** |
| `yarn install` (no flag) | **Partial** |
| `bun install` | **Partially** — respects `bun.lockb` if present |

> **Note:** `--ignore-scripts` does **not** appear in this table as a protection, because it is ineffective against the Phantom Gyp vector.

---

## Phase 2: CI Run Analysis

**Why this phase is critical:** Phase 1 only finds repos that name an affected package. A repo can install it transitively without ever naming it. The only way to know what actually got installed during the window is the CI logs.

### 1. Find runs during the exposure window

```bash
gh api "/orgs/${ORG}/repos" --paginate --jq '.[].name' | while read repo; do
  gh api "repos/${ORG}/${repo}/actions/runs?created=${SINCE}..${UNTIL}&per_page=100" \
    --jq ".workflow_runs[] | \"${repo}|\(.id)|\(.created_at)|\(.name)|\(.conclusion)\"" 2>/dev/null
done > "$LOG_DIR/all_runs.txt"
echo "Total runs to scan: $(wc -l < "$LOG_DIR/all_runs.txt")"
```

### 2. Download all run logs in parallel

```bash
cat "$LOG_DIR/all_runs.txt" | while IFS='|' read repo run_id rest; do echo "$repo $run_id"; done | \
  xargs -P 10 -L 1 bash -c \
  'gh run view "$1" --repo "${ORG}/$0" --log > "${LOG_DIR}/run-$1.log" 2>/dev/null && echo "OK: $0 $1" || echo "FAIL: $0 $1"'
```

### 3. Scan logs for affected packages and Phantom-Gyp IOCs

```bash
# Affected package references (family-level)
echo "=== Affected-package references ==="
grep -rlinE "@vapi-ai/server-sdk|@evolvconsulting/evolv-coder-lite|@jagreehal/workflow|ai-sdk-ollama|@redhat-cloud-services/|\b(autotel|awaitly|executable-stories|node-env-resolver|mountly|effect-analyzer|http-uploader-dev|wrangler-deploy)\b" "$LOG_DIR"/run-*.log 2>/dev/null

# The smoking gun: node-gyp build step on a package that shouldn't need one, then node index.js
echo "=== Phantom Gyp: node-gyp rebuild -> node index.js ==="
grep -rlinE "node-gyp rebuild|gyp info|node index\.js" "$LOG_DIR"/run-*.log 2>/dev/null

# Bun runtime fetched from github.com during install
echo "=== Bun runtime download during install ==="
grep -rlinE "github\.com/oven-sh/bun|bun-(linux|darwin|windows).*\.zip|installing bun|bun\.sh/install" "$LOG_DIR"/run-*.log 2>/dev/null

# Token theft + privilege escalation + memory scrape
echo "=== Token theft / privesc / memory scrape ==="
grep -rlinE "gh auth token|sudo python3|/proc/[0-9]+/mem|Runner\.Worker" "$LOG_DIR"/run-*.log 2>/dev/null

# Dropped payload temp path pattern
echo "=== Dropped payload temp path (/tmp/p<random>.js) ==="
grep -rlinE "/tmp/p[a-z0-9]{6,}\.js" "$LOG_DIR"/run-*.log 2>/dev/null

# Attacker dead-drop signals
echo "=== Attacker dead-drop signals ==="
grep -rlinE "liuende501|nemean-hydra|Miasma - The Spreading Blight|niagA oG eW ereH" "$LOG_DIR"/run-*.log 2>/dev/null
```

> **Why scan for the gyp/Bun/`/proc/mem` chain, not just package names?** A frozen install of a clean transitive tree shows package names with no compromise. Conversely, a transitive pull of a malicious version may show **no** affected package name in a quiet install log but **will** show the anomalous `node-gyp rebuild → node index.js → Bun download` chain. The process chain is the higher-fidelity signal.

### 4. Classify hits as real installs vs false positives

**Real install / execution indicators:**
- `added <pkg>@<version>` (npm), `+ <pkg> <version>` (pnpm), resolution lines (yarn) for an affected name.
- `node-gyp rebuild` / `gyp info spawn` for a package with no legitimate native addon, followed by `node index.js`.
- Any Bun download, `gh auth token`, `sudo python3`, or `/proc/<pid>/mem` read during an install step.

**False positives (ignore):**
- Source-code imports, TypeScript errors, SAST/dependency-review output naming the package.
- Branch names (`dependabot/npm_and_yarn/autotel-...`), docs, comments.
- `node-gyp rebuild` for a package that **legitimately** ships a native addon (e.g. `node-sass`, `bcrypt`, `better-sqlite3`) — correlate with the affected-package list and the Bun/`/proc/mem` chain before flagging.

### 5. Write the CI runs evidence table

Write `$LOG_DIR/evidence-ci-runs.csv`:

```
repo,run_id,created_at,workflow,platform,install_command,log_line,version_installed,lock_respected,iocs_found,ci_compromised
```

| Column | What to write |
|---|---|
| `version_installed` | Exact affected-pkg version installed; `not installed` if none in this step |
| `iocs_found` | `yes (which IOC: node-gyp+node index.js / Bun download / gh auth token / /proc/mem)` or `no` |
| `ci_compromised` | **Verdict:** `clean` / `compromised` / `clean (component not installed)` |

One row per install-command execution. No blank cells. Only include runs that executed package installs.

---

## Phase 2b: The Customer's Own Published Packages (Forward-Propagation Risk)

Miasma is a worm: if any maintainer in the customer's org had GitHub/npm credentials stolen during the window, it enumerates their published packages and **republishes them with the Phantom-Gyp payload** (a malicious `binding.gyp` + `index.js`). The customer then ships the payload forward to *their* downstream consumers.

### 2b.1. Enumerate the customer's published npm packages

```bash
curl -s "https://registry.npmjs.org/-/v1/search?text=scope:${SCOPE}&size=250" | \
  python3 -c "import sys,json; [print(p['package']['name']) for p in json.load(sys.stdin)['objects']]" > "$LOG_DIR/own-packages.txt"
for user in $(cat "$LOG_DIR/maintainers.txt" 2>/dev/null); do
  curl -s "https://registry.npmjs.org/-/v1/search?text=maintainer:${user}&size=250" | \
    python3 -c "import sys,json; [print(p['package']['name']) for p in json.load(sys.stdin)['objects']]"
done >> "$LOG_DIR/own-packages.txt"
sort -u "$LOG_DIR/own-packages.txt" -o "$LOG_DIR/own-packages.txt"
```

### 2b.2. List versions published during the window

```bash
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
cat "$LOG_DIR/own-published-in-window.tsv"
```

### 2b.3. Per-candidate forensics

For each `pkg@version` published in the window:

```bash
mkdir -p "$LOG_DIR/tarballs/${pkg//\//_}-${version}" && cd "$LOG_DIR/tarballs/${pkg//\//_}-${version}"
npm pack "${pkg}@${version}" 2>/dev/null && tar xzf *.tgz
# Phantom-Gyp payload signatures
ls package/binding.gyp 2>/dev/null && echo "*** has binding.gyp ***"
grep -rliE "gh auth token|/proc/[0-9]+/mem|bun|liuende501|child_process" package/ 2>/dev/null
# Did the publisher account match the customer's known identities?
curl -s "https://registry.npmjs.org/${pkg}/${version}" | python3 -c "import sys,json; d=json.load(sys.stdin); print('npmUser:', d.get('_npmUser'))"
cd -
```

- A `binding.gyp` in a package that has no native addon, or an `index.js` referencing `gh auth token` / `/proc/*/mem` / Bun → **directly republished by the worm**. Deprecate immediately and notify downstream consumers.
- A clean tarball whose lock file pins a malicious affected version → **built with a bad dep**; publish a clean superseding version with a fresh lock file.

### 2b.4. If republished or built-with-bad-dep

1. `npm deprecate '<pkg>@<version>' 'Compromised (Miasma worm) — do not install. See advisory.'`
2. Publish a clean superseding version from a known-clean host with a fresh, fully-pinned lock file.
3. Notify downstream consumers (issue / changelog / email).
4. **Rotate the publisher's npm token** (and GitHub token — see Phase 6) and re-issue with 2FA + provenance.
5. File a takedown with npm security if deprecation isn't enough.

---

## Phase 3: Network Investigation (Firewall / Proxy / DNS Logs)

Miasma's network IOCs overlap with legitimate traffic (`github.com`, `api.github.com`), so focus on **anomalous, install-correlated** activity rather than the bare domains.

### What to look for

| Signal | Where to search |
|---|---|
| Bun runtime download from `github.com/oven-sh/bun/...` from a CI runner / build host that has no reason to install Bun | Proxy logs, NetFlow, VPC Flow Logs |
| `api.github.com` writes (repo creation / content push) from a build runner during/after an install step | GitHub audit log, proxy logs |
| New repos created by, or pushes to, the attacker account `liuende501` referencing your org's data | GitHub audit log |
| Read access to `/proc/<pid>/mem` on a runner | EDR / host telemetry |
| Outbound to `nodejs.org` / `registry.npmjs.org` is normal; a runtime fetch from `github.com` mid-install is **not** | Proxy logs |

### Where to check

- **Cloud:** AWS VPC Flow Logs + Route 53 Resolver query logs + CloudTrail; GCP VPC Flow Logs + Cloud DNS logs; Azure NSG Flow Logs + DNS Analytics.
- **On-prem:** firewall (Palo Alto, Fortinet), web proxy (Zscaler, Squid, Netskope), DNS server logs, SIEM (Splunk, Elastic, Chronicle).
- **CI runners:** self-hosted → host egress + EDR; GitHub-hosted → rely on network-edge logs + the GitHub audit log.

### Example queries

**Splunk** (anomalous GitHub download from build subnet):
```
index=proxy (url="*github.com/oven-sh/bun*" OR uri_path="*/bun*") src_ip IN (<ci-runner-cidr>)
| stats count by src_ip, url, _time
```

**AWS VPC Flow Logs (CloudWatch Insights):**
```
filter @message like /github\.com|api\.github\.com/ and srcAddr like /<ci-runner-prefix>/
| stats count(*) as hits by srcAddr, dstAddr
```

### Time window

Search from `2026-06-01T00:00:00Z` to **at least 7 days forward** — credential abuse via stolen tokens can lag the install.

---

## Phase 4: Workstation Investigation

Developer machines that ran `npm/pnpm/yarn install` during the window may have executed the payload. Unlike CI, you can't rely on logs — check artifacts directly. The payload steals the `gh` token and may self-clean the dropper, so absence of `/tmp/p*.js` does not prove a clean host.

### 4a. Phantom-Gyp payloads in `node_modules`

```bash
PKG_RE='autotel|awaitly|executable-stories|node-env-resolver|ai-sdk-ollama|server-sdk|evolv-coder-lite|workflow|mountly|effect-analyzer|http-uploader-dev|wrangler-deploy|redhat-cloud-services'
for root in ~/projects ~/code ~/repos ~/work "$HOME"; do
  [ -d "$root" ] || continue
  # affected packages that ship a binding.gyp (suspicious for pure-JS packages)
  find "$root" -path '*/node_modules/*/binding.gyp' 2>/dev/null | grep -iE "$PKG_RE"
  # the dropper's index.js referencing the token-theft chain
  find "$root" -path '*/node_modules/*/index.js' 2>/dev/null | \
    xargs grep -liE "gh auth token|/proc/[0-9]+/mem|oven-sh/bun" 2>/dev/null
done
```

### 4b. Lock files referencing malicious versions

```bash
find ~ \( -name 'package-lock.json' -o -name 'pnpm-lock.yaml' -o -name 'yarn.lock' \) \
  -not -path '*/node_modules/*' 2>/dev/null | \
  xargs grep -lE "$PKG_RE" 2>/dev/null > "$LOG_DIR/workstation-lockfiles-with-affected-pkgs.txt"
cat "$LOG_DIR/workstation-lockfiles-with-affected-pkgs.txt"
```
Cross-check each hit's pinned version against the canonical malicious-version list.

### 4c. Dropped payloads & process artifacts

```bash
ls -la /tmp/p*.js 2>/dev/null                 # /tmp/p<random>.js dropper
grep -iE "gh auth token|node-gyp rebuild|/proc/.*/mem|oven-sh/bun|liuende501" \
  ~/.bash_history ~/.zsh_history ~/.local/share/fish/fish_history 2>/dev/null
ps aux 2>/dev/null | grep -iE "bun |index\.js|node-gyp" | grep -v grep
```

### 4d. Stolen-credential blast radius (host)

```bash
gh auth status 2>/dev/null            # is gh authenticated on this host? (token was a target)
ls -la ~/.config/gh/hosts.yml ~/.npmrc 2>/dev/null
# Active connections / hosts tampering
lsof -i -P 2>/dev/null | grep -iE "github|bun"
grep -iE "github|bun|liuende501" /etc/hosts 2>/dev/null
```

### 4e. npm / pnpm / yarn cache content

```bash
npm cache ls 2>/dev/null | grep -iE "$PKG_RE"
ls ~/.npm/_logs 2>/dev/null | tail -50
grep -liE "node-gyp|oven-sh/bun|gh auth token" ~/.npm/_logs/*.log 2>/dev/null
pnpm store path 2>/dev/null
```

### 4f. AI agent conversation logs (Claude Code, Cursor, Windsurf, Copilot)

> **Exclude the investigating agent's own session.** If you're running this playbook through an AI coding agent, its transcript will contain these IOC strings because you've been *reading* them — that's evidence of investigation, not compromise. Exclude the current session dir.

```bash
CURRENT_SESSION_PROJECT=$(echo "$PWD" | sed 's|/|-|g')
grep -rliE "Miasma|liuende501|nemean-hydra|gh auth token|node-gyp rebuild|/tmp/p[a-z0-9]{6,}\.js|oven-sh/bun" \
  "$HOME/.claude/projects" \
  "$HOME/Library/Application Support/Cursor" \
  "$HOME/Library/Application Support/Windsurf" \
  "$HOME/.config/github-copilot" 2>/dev/null | \
  grep -v "${CURRENT_SESSION_PROJECT}" | grep -v "paste-cache" | grep -v "file-history"
```

### 4g. Worm self-propagation footprint in your own GitHub org

```bash
# New / exfil-style repos created in the window (worm dead-drops)
gh api --paginate "/orgs/${ORG}/repos?per_page=100&sort=created&direction=desc" \
  --jq ".[] | select(.created_at > \"${SINCE}\" and .created_at < \"${UNTIL}\") | \"\(.name) | \(.created_at) | \(.visibility)\""
# Repos whose description matches the worm's signature strings
gh api --paginate "/orgs/${ORG}/repos?per_page=100" \
  --jq '.[] | select((.description // "") | test("Miasma|Spreading Blight|niagA oG eW ereH")) | "\(.name) | \(.description)"'
# Attacker account referenced anywhere
gh api "search/commits?q=org:${ORG}+author:liuende501" --jq '.items[]? | "\(.repository.full_name) | \(.html_url)"' 2>/dev/null
```

---

## Phase 5: Present Results

Produce these deliverables and return them to the user.

1. **Repo Analysis table** (`evidence-repos.csv`) — dependency posture per repo, window-agnostic.
2. **CI Runs table** (`evidence-ci-runs.csv`) — what actually happened during the window: install commands, versions, IOCs, verdict per run.
3. **Customer-Published Packages table** (`evidence-own-published.csv`) — forward-propagation picture; verdict per version (`clean` / `directly republished` / `built with poisoned dep` / `inconclusive`).
4. **Executive Summary** — verdict (`clean` / `compromised`); scope (repos/runs/logs); repo posture; CI findings; network findings (Bun-from-github, api.github.com writes, `/proc/mem`); workstation findings (Phantom-Gyp payloads, dropped `/tmp/p*.js`, `gh` token exposure); org-side worm signals; forward propagation; one-sentence bottom line.

**Action needed** if any: `can_be_compromised=yes`, any `ci_compromised=compromised`, workstation payload/`gh`-token exposure, or worm-style repo/commit activity. **Vulnerable but not hit** (`can_be_compromised=yes`, no runs in window) → flag for Phase 6 hardening.

---

## Phase 6: Hardening & Remediation (User Approval Required)

**Do NOT proceed without explicit user approval.** Present findings first, then ask which steps to execute.

### Remediation — only if compromised

Rotate before scrubbing. **GitHub tokens are Miasma's primary loot — rotate them first.**

1. **Quarantine.** Disconnect affected dev workstations; drain/stop affected CI runners (terminate if ephemeral).
2. **Snapshot before cleanup** for forensics: `ps`, any `/tmp/p*.js`, `~/.config/gh/hosts.yml`, `~/.npmrc`, `~/.gitconfig`, shell history.
3. **Rotate credentials** (in order):
   1. **GitHub tokens** — `gh` CLI token (`gh auth token` was the theft target), PATs, `.git-credentials`, deploy keys, GitHub App installation tokens. (`GITHUB_TOKEN` in Actions auto-rotates, but anything the runner read from memory is burned.)
   2. **npm publish tokens** — `~/.npmrc`, automation/granular tokens; `npm token list` and revoke anything tied to the suspect host.
   3. **Cloud instance creds** the runner held (AWS IMDS/role session, GCP metadata, Azure managed-identity).
   4. **Secrets Manager / Vault tokens** and **Kubernetes service-account tokens** the runner could read.
   5. **SSH keys** (`~/.ssh/*`) and **browser-stored sessions** (github.com, npmjs.com).
4. **Remove dropped payloads & node_modules**: `rm -f /tmp/p*.js`; `rm -rf node_modules`; `npm cache clean --force`; `pnpm store prune`; `yarn cache clean`.
5. **Rebuild affected Docker images** with `--no-cache` — the payload may be baked into a layer.
6. **Audit GitHub** for repos created by `liuende501`, dead-drop repos in your org (descriptions matching `Miasma` / `Spreading Blight` / the reversed Shai-Hulud string), and unexpected pushes during the window. Delete attacker repos and revoke any forks.
7. **Re-image compromised workstations** if you can't be certain you removed every foothold.

### Hardening — wherever `can_be_compromised` = yes

| Attack surface | Fix |
|---|---|
| No lock file committed | Commit `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` |
| CI uses non-frozen install | Switch to `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --immutable` |
| Loose `^`/`~`/`latest` ranges on affected deps | Pin exact, pre-incident versions; regenerate lock on a clean host |
| **Native-addon builds from untrusted packages** | This is the Phantom-Gyp surface. Where you don't need native builds, install with a toolchain-free image, or use an allow-list of packages permitted to run `node-gyp`. **`--ignore-scripts` alone does NOT close this** |
| CI runners have `sudo` / broad host access | Run builds least-privilege; deny `sudo`; restrict `/proc` access so a build step can't read another process's memory |
| Unrestricted CI egress | Allow-list build egress to `registry.npmjs.org` + `nodejs.org`; block runtime downloads from `github.com` and writes to `api.github.com` from build steps |
| Long-lived publish tokens | Replace with short-lived OIDC; require 2FA + provenance on publish |
| No dependency review on PRs | Enable `actions/dependency-review-action`; alert on new packages that ship a `binding.gyp` |

### Upgrade path

No single "safe replacement" is published per package. **Downgrade to a pre-incident version** of each affected package (predating the June 1–3 window) until the maintainers cut a verified clean release, then regenerate the lock file on a clean host and commit it.

---

## References

- StepSecurity — "binding.gyp npm supply chain attack spreads like a worm" (primary writeup + IOCs) — https://www.stepsecurity.io/blog/binding-gyp-npm-supply-chain-attack-spreads-like-worm
- node-gyp / `binding.gyp` background — https://github.com/nodejs/node-gyp
- Related Shai-Hulud-family wave (May 2026, TanStack / Mini Shai-Hulud) — `tanstack_supply_chain/playbook.md`
- OSSF malicious-packages database — https://github.com/ossf/malicious-packages
