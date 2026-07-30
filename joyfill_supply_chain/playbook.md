# joyfill npm Compromise (DEV#POPPER / PolinRider) — Investigation Playbook

Playbook for investigating whether a GitHub org was affected by the **28 July 2026 `@joyfill` npm compromise**. Six malicious prerelease versions across `@joyfill/layouts` and `@joyfill/components` (~20,000 weekly downloads each) shipped an import-time loader that pulls a **DEV#POPPER-family remote access trojan** through blockchain-resolved C2, followed by a Python credential stealer. Attributed to the **PolinRider** cluster (assessed related to North Korea-linked Contagious Interview activity).

> **CI/CD platform note:** commands target GitHub Actions and GitHub-hosted repos. For GitLab CI, Jenkins, CircleCI, Bitbucket or Azure DevOps, adapt the log-collection calls — the logic is unchanged: find references to the affected packages, determine which builds *ran* code from them during or after the window, and check egress.

> ## ⚠️ Trigger model: import-time, not install-time — read this before you scan
>
> There is **no `postinstall` hook**. The implant lives in the packages' built bundles and executes when Node.js **loads the entrypoint**. Consequences for this investigation:
>
> - `npm install --ignore-scripts` provides **zero** protection.
> - A CI run that only *installed* dependencies and then stopped may never have detonated. A run that installed **and then executed anything** — `npm test`, `npm run build`, `next build`, a Storybook build, a smoke test, a container start — did.
> - Install logs alone are **not** sufficient evidence. You need install evidence **plus** execution evidence.
> - A cached `node_modules` (`actions/cache`, `actions/setup-node` cache) can carry a malicious version into runs *after* the window with **no install line in the log at all**.
> - Container images are affected if they were built **or started** with a `2773` prerelease inside them.

---

## Incident Details

### Compromised packages and versions

All six versions were published on **28 July 2026**. Four have since been removed from npm — **both `@joyfill/layouts` prereleases are still installable** (status verified 30 July 2026), so an unpinned prerelease range on that package is still exploitable today.

> **Removal is not remediation.** A pulled version still resolves from a committed lock file, a warm package-manager cache, or an image layer built while it was live. Treat all six versions as in scope for detection regardless of registry status — only the *fresh-resolve* risk goes away when npm pulls a version.

| Package | Version | Published (UTC) | Registry status |
|---|---|---|---|
| `@joyfill/layouts` | `0.1.2-2773.beta.0` | 10:54:57 | removed |
| `@joyfill/layouts` | `0.1.2-2773.beta.1` | 13:57:01 | **still live** |
| `@joyfill/layouts` | `0.1.2-2773.beta.2` | 15:16:43 | **still live** |
| `@joyfill/components` | `4.0.0-rc24-2773-beta.4` | 11:03:59 | removed |
| `@joyfill/components` | `4.0.0-rc24-2773-beta.5` | 14:01:19 | removed 30 Jul |
| `@joyfill/components` | `4.0.0-rc24-2773-beta.6` | 15:21:29 | removed 30 Jul |

> **Version-string trap.** `layouts` spells the prerelease `2773.beta.N` (dot) and `components` spells it `2773-beta.N` (hyphen). A pattern anchored on `2773.beta` silently misses every `components` hit. Always use `2773[.-]beta`.

**Clean reference releases:** `@joyfill/layouts@0.1.1`, `@joyfill/components@4.0.0-rc24` (the stable `latest` tags). Only `2773` prereleases are compromised.

**Payload location inside the tarballs** — built bundles only, source files are clean:

| Package | Files carrying the implant |
|---|---|
| `@joyfill/components` | appended to `dist/index.js`, `dist/index.esm.js`, `dist/joyfill.min.js` |
| `@joyfill/layouts` | prepended to `dist/index.cjs.js`, `dist/index.es.js` |

### CVE / advisory

- **CVE:** none assigned (malicious-package compromise, not a code vulnerability).
- **GitHub advisory:** none filed for either package as of 29 July 2026 — do **not** rely on `gh api /advisories` or Dependabot to flag this.
- **Original research:** https://socket.dev/blog/joyfill-npm-beta-releases-compromised
- **Independent analysis:** https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise

### Exposure window

| Event | Time (UTC) |
|---|---|
| First malicious version published (`layouts@…beta.0`) | 28 Jul, 10:54 |
| Last malicious version published (`components@…beta.6`) | 28 Jul, 15:21 |
| Public disclosure (Socket / StepSecurity) | 28 Jul, evening |
| Partial npm removal (2 of 6 versions) | 28 Jul – 29 Jul |
| Both `@joyfill/components` prereleases removed (4 of 6 total) | 30 Jul |
| Two `@joyfill/layouts` prereleases still live | ongoing as of 30 Jul |

**Recommended scan window (padded):** `2026-07-28T10:00:00Z` to **now**. Unlike a fully-unpublished compromise, the window does **not** close — the still-live versions can be resolved by any build today. Pad the start back to 10:00 UTC to catch clock skew and cache warming.

### Indicators of compromise

| IOC | Value | Where it shows up |
|---|---|---|
| Malicious version marker | `2773[.-]beta` on a `@joyfill/*` package | manifests, lock files, CI logs, image layers |
| C2 (primary) | `166.88.134.62` (ports 443, 80) | network logs, CI egress |
| C2 (boot payload) | `23.27.13.43/$/boot` | network logs |
| C2 (secondary) | `198.105.127.210`, `23.27.202.27` (443, 27017) | network logs |
| C2 paths | `/$/boot`, `/u/e`, `/u/f`, `/0x/js`, `/verify-human/`, `/snv` | proxy logs |
| Campaign header | `Sec-V: A9-0135-3` | proxy logs, packet capture |
| Blockchain resolvers | `api.trongrid.io`, `fullnode.mainnet.aptoslabs.com`, `bsc-dataseed.binance.org`, `bsc-rpc.publicnode.com` | network logs — **at build/app-start time** |
| Tron pointers | `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP`, `TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG`, `TA48dct6rFW8BXsiLAtjFaVFoSuryMjD3v` | payload strings, blockchain lookups |
| Aptos pointers | `0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e`, `0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3` | payload strings |
| BSC transactions | `0x18a8420f727f2405f9d1805ad887b31029b584b2ff5a7ec0f57c72635183e99d`, `0x7ffb4efddd96e20aec90724be2ac9a71c138a9af697b9fb8224bbf80ea4f22be`, `0xb6c725890be6890fd2c735eedc47e24b85a350301f6c19a3864e43c35e470968` | payload strings |
| XOR keys | `2[gWfGj;<:-93Z^C` (branch A), `m6:tTh^D)cBz?NM]` (branch B), `ThZG+0jfXE6VAGOJ` (stage 2) | payload strings |
| Campaign markers | `global["!"] = "9-0135-3"`, `_V = "A9-0135-3"` | payload strings |
| Injection markers | `/*C250617A*/`, `/*C250618A*/`, `/*C250619A*/`, `/*C250620A*/`, `/*C260511A*/`, `/*C260512A*/`, `/*RS260605*/` | **developer tooling**, global npm CLI |
| Injected files | `<npm root -g>/npm/lib/cli.js`, `**/@vscode/deviceid/dist/index.js`, `modules/discord_desktop_core/discord_desktop_core/index.js`, `GitHub Desktop/resources/app/main.js` | workstation |
| Credential staging | `/tmp/.npm` (Unix), `%USERPROFILE%\.npm` (Windows) | workstation, runner |
| Socket.IO command set | `ss_info`, `ss_ip`, `ss_cb`, `ss_upf`, `ss_upd`, `ss_dir`, `ss_fcd`, `ss_stop`, `ss_eval`, `ss_exit` | payload strings, EDR |
| Runtime dep pull | unexplained `npm install socket.io-client` / `axios` during app or test execution | CI logs, EDR |
| Public IP lookup | `ip-api.com` | network logs |
| SHA-256 (stage 1) | `cb46f12d70824ea24ed1f8bcf45bf3f86680e02a9089aafc03b27f691be57be3` | file hashing |
| SHA-256 (final RAT) | `26351aed0397158d3a3b8cc8fd3047d4c015d264c9895f10f20f1521b974ed18` | file hashing |
| SHA-256 (Python stealer) | `36ff00b45e67baa7e3674b0c80f48e88737264c61e5c6b3b091200972de8157c` | file hashing |

### What IS affected

- Any install that resolved a `2773` prerelease of `@joyfill/layouts` or `@joyfill/components` — **and then loaded it** (test, build, dev server, SSR render, container start).
- Repos tracking a prerelease range (`^0.1.2-2773.beta.1`, `next`/beta dist-tag, `*`) on `@joyfill/layouts` — **including right now**, because both of its malicious prereleases remain live. For `@joyfill/components` a fresh resolve no longer reaches a malicious version, but a pinned lock file, warm cache, or existing image still can.
- CI runs that restored a **cached `node_modules` or package-manager store** containing a malicious version, even with no install line in that run's log.
- Container images built **or started** with a malicious version present in `node_modules` or in a bundled `dist`.
- Developer workstations that ran the app, tests, or Storybook after installing a `2773` prerelease — see Phase 5.
- Any host where the **global npm CLI or an editor/Electron bundle carries an injection marker** — that persistence survives `rm -rf node_modules` and re-executes on the next `npm` command.

### What is NOT affected

- Installs pinned to `@joyfill/layouts@0.1.1` or `@joyfill/components@4.0.0-rc24` (stable tags) — these builds were never compromised.
- `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --immutable` against a lock file generated **before 28 July 2026 10:54 UTC** that pins a stable version, **and** with no cached `node_modules` restored from a later run.
- Source-code references only — a TypeScript `import { … } from '@joyfill/components'` in a repo whose dependencies were never installed and executed during or after the window.
- Docs, Helm values, Terraform, or design files that merely name the package.
- A build that installed a malicious version but **provably never executed any code from it** (install-only job that then failed or stopped) — the loader needs module load. Treat this as "likely clean but verify egress", not as proven clean.

### Lock file protection

Lock files **do** protect here, with two caveats that matter more than usual:

- `npm ci`, `pnpm install --frozen-lockfile`, `yarn install --immutable` install exactly what the lock file pins. If it pins a stable release, no malicious tarball is fetched.
- **Caveat 1 — cache bypass.** A restored `node_modules` cache can reintroduce a malicious version regardless of what the lock file says. Check cache steps, not just install steps.
- **Caveat 2 — prerelease ranges.** A manifest range that allows prereleases (`^0.1.2-2773.beta.1`, or a `next` tag) re-resolves to a live malicious version on any non-frozen install *today*. The window has not closed for these repos.

Lock files do **not** protect if: no lock file is committed; CI runs `npm install` / `pnpm install` / `yarn install` without a frozen flag; the lock file was regenerated on or after 28 July; or a Renovate/Dependabot PR bumped `@joyfill/*` into the lock file.

---

## Pitfalls & Fixes

Harvested from a dry-run of these commands. Read before starting.

1. **`2773.beta` misses half the incident.** `components` uses `2773-beta.N`, `layouts` uses `2773.beta.N`. **Fix:** always `2773[.-]beta`. Verified: a repo with a `components@4.0.0-rc24-2773-beta.5` lock entry returns zero hits for `2773\.beta`.
2. **Positive control before trusting a clean result.** A broken grep and a genuinely clean org look identical. **Fix:** run the same pattern shape against a token you know exists in the corpus (e.g. `react` in `package.json`) and confirm it hits before concluding "no `@joyfill` exposure".
3. **`npm ci` / `yarn install --immutable` print no per-package lines.** Zero `@joyfill` hits in a run log does **not** mean it wasn't installed. **Fix:** read the install command plus the committed lock file, not the per-package output.
4. **Install-only greps miss the actual detonation.** Because the trigger is import-time, the highest-value log evidence is the *execution* step (`npm test`, `npm run build`, `next build`, `vite build`, container start) in a job that had a malicious version on disk. **Fix:** always pair the install grep with an execution grep (Phase 2.4).
5. **Don't hardcode the global npm root.** On Homebrew macOS it is `/opt/homebrew/lib/node_modules`, not `/usr/local/lib/node_modules` or `/usr/lib/node_modules`. **Fix:** always `$(npm root -g)`.
6. **`npm cache ls` is not available on every npm.** It works on npm 11.x but not on several older majors. **Fix:** grep `$(npm config get cache)/_cacache` directly as the fallback.
7. **Injection-marker greps need escaping and scoping.** `/*C260511A*/` must be written `/\*C260511A\*/` under `grep -E`, and an unscoped `grep -r` over `node_modules` on a large machine is slow and noisy against minified bundles. **Fix:** scope to the specific tool paths in Phase 5 / the workstation playbook.
8. **Blockchain RPC endpoints are shared infrastructure.** `api.trongrid.io` and `bsc-dataseed.binance.org` are legitimate for a Web3 project. They are IOCs **only** as runtime egress from a build, test, or app-start process that has no business talking to a chain — never as a static repo-file match. Note this explicitly in findings for any customer with Web3 code.
9. **AI-agent self-pollution.** If you run this playbook through an AI coding agent, the agent's own session logs will contain every IOC string in this file. **Fix:** exclude the current session before treating an agent-log hit as evidence — see the workstation playbook, Check 9.

---

## Setup

```bash
export ORG="<your-github-org>"
export SINCE="2026-07-28T10:00:00Z"
export UNTIL="$(date -u +%Y-%m-%dT%H:%M:%SZ)"   # window is still open — scan to now
export LOG_DIR="/tmp/supply-chain-scan-joyfill"
mkdir -p "$LOG_DIR"

# Version marker — covers both spellings (layouts: 2773.beta.N, components: 2773-beta.N)
export JOYFILL_VER_RE='@joyfill/(layouts|components)[^ ]*2773[.-]beta'
export JOYFILL_ANY_RE='@joyfill/(layouts|components)'

# Network IOCs
export C2_RE='166\.88\.134\.62|23\.27\.13\.43|198\.105\.127\.210|23\.27\.202\.27'
export C2_PATH_RE='/\$/boot|/u/e|/u/f|/0x/js|/verify-human/|/snv'
export CHAIN_RE='api\.trongrid\.io|fullnode\.mainnet\.aptoslabs\.com|bsc-dataseed\.binance\.org|bsc-rpc\.publicnode\.com'
export MARKER_RE='/\*(C25061[7-9]A|C250620A|C26051[12]A|RS260605)\*/'
```

**Write to files, not context.** Results can be large — write CSV evidence into `$LOG_DIR` as you go.

**Rate limits.** Check budget before scanning a large org:

```bash
gh api /rate_limit --jq '.resources.core | "\(.remaining)/\(.limit) core"'
gh api /rate_limit --jq '.resources.code_search | "\(.remaining)/\(.limit) code-search"'
```

---

## Phase 1: Org-Wide Asset Discovery

**Goal:** find every repo that declares or locks `@joyfill/*`, and record whether its configuration can resolve a `2773` prerelease. Window-agnostic.

### 1.1 Code search across the org

```bash
q=$(printf '%s' '@joyfill/' | python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.stdin.read().strip()))")
gh api "search/code?q=${q}+org:${ORG}&per_page=100" \
  --jq '.items[] | "\(.repository.full_name)\t\(.path)"' | sort -u > "$LOG_DIR/refs.tsv"
wc -l < "$LOG_DIR/refs.tsv"
```

> **Positive control.** Before trusting an empty `refs.tsv`, confirm the query mechanism works: `gh api "search/code?q=react+org:${ORG}&per_page=1" --jq .total_count` should return a non-zero number for any JS-using org. Zero on both means the query, not the org, is clean.

> **Large orgs (>50 repos):** shallow-clone and grep locally — usually far faster than paginated code search.
>
> ```bash
> mkdir -p "$LOG_DIR/clones" && cd "$LOG_DIR/clones"
> gh repo list "$ORG" --no-archived --limit 1000 --json nameWithOwner --jq '.[].nameWithOwner' | \
>   xargs -P 10 -I {} bash -c 'git clone --depth 1 --filter=blob:none "git@github.com:{}.git" 2>/dev/null || echo "FAIL: {}"'
>
> grep -rEn --include='package.json' --include='package-lock.json' --include='pnpm-lock.yaml' \
>   --include='yarn.lock' --include='Dockerfile' "$JOYFILL_ANY_RE" . > "$LOG_DIR/refs-local.txt"
> grep -rEn --include='*.json' --include='*.yaml' --include='*.lock' "$JOYFILL_VER_RE" . > "$LOG_DIR/hits-malicious-versions.txt"
> wc -l "$LOG_DIR/refs-local.txt" "$LOG_DIR/hits-malicious-versions.txt"
> ```

### 1.2 Classify each hit

| File pattern | Category | Risk |
|---|---|---|
| `package.json` | npm manifest | **HIGH** — does the range allow a `2773` prerelease? |
| `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` | lock file | **CRITICAL** — check the pinned version directly |
| `Dockerfile` | container build | **HIGH** if it installs **and** runs JS (build step, `CMD` that loads the bundle) |
| `.github/workflows/*.yml` | CI workflow | **CHECK** — install command, cache steps, and whether any step executes app code |
| `*.ts`, `*.tsx`, `*.js` | source import | **NOT AFFECTED** on its own — but marks a repo whose runtime loads the package |
| `*.md`, `values.yaml`, `*.tf` | docs / infra | **NOT AFFECTED** |

### 1.3 Extract the version data per repo

```bash
# Manifest specifier
gh api "repos/${ORG}/<repo>/contents/package.json" --jq '.content' | base64 -d | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
for sec in ('dependencies','devDependencies','optionalDependencies','peerDependencies'):
    for k, v in d.get(sec, {}).items():
        if k.startswith('@joyfill/'): print(f'{sec}: {k} = {v}')
"

# Resolved lock-file version (npm)
gh api "repos/${ORG}/<repo>/contents/package-lock.json" --jq '.content' | base64 -d | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
for k, v in d.get('packages', {}).items():
    name = k.split('node_modules/')[-1]
    if name.startswith('@joyfill/'): print(f\"{name}: {v.get('version')}\")
"

# pnpm / yarn
gh api "repos/${ORG}/<repo>/contents/pnpm-lock.yaml" --jq '.content' | base64 -d | grep -E "'?@joyfill/"
gh api "repos/${ORG}/<repo>/contents/yarn.lock"      --jq '.content' | base64 -d | grep -A2 -E '"?@joyfill/'
```

**Decision rule per repo:** a repo is exposed-in-principle if the resolved version matches `2773[.-]beta`, **or** if the manifest range admits prereleases on `@joyfill/layouts` and CI runs a non-frozen install (because both of its malicious prereleases are still live).

### 1.4 Workflow and Dockerfile review

```bash
# Install command, cache restore, and execution steps in one pass
gh api "repos/${ORG}/<repo>/contents/.github/workflows" --jq '.[].path' | while read -r wf; do
  echo "--- $wf"
  gh api "repos/${ORG}/<repo>/contents/${wf}" --jq '.content' | base64 -d | \
    grep -inE "npm ci|npm install|pnpm install|yarn install|bun install|actions/cache|cache: *'?(npm|pnpm|yarn)|npm (run |test)|yarn (build|test)|next build|vite build|storybook"
done

# Dockerfile: install AND run
gh api "repos/${ORG}/<repo>/contents/Dockerfile" --jq '.content' | base64 -d | \
  grep -inE "RUN.*(npm|pnpm|yarn|bun).*(install|ci)|RUN.*(build|test)|^(CMD|ENTRYPOINT)"
```

Record three facts per repo: **install command**, **whether a cache is restored**, and **whether any step executes app code**. The third is what turns exposure into detonation.

---

## Phase 2: CI Run Analysis

**Why this phase differs from a normal supply-chain investigation:** you are looking for two things, not one — the malicious version reaching disk, *and* code from it being loaded.

### 2.1 Find runs in the window

```bash
gh api "/orgs/${ORG}/repos" --paginate --jq '.[].name' | while read -r repo; do
  gh api "repos/${ORG}/${repo}/actions/runs?created=${SINCE}..${UNTIL}&per_page=100" \
    --jq ".workflow_runs[] | \"${repo}|\(.id)|\(.created_at)|\(.name)|\(.conclusion)\"" 2>/dev/null
done > "$LOG_DIR/all_runs.txt"
echo "Runs to scan: $(wc -l < "$LOG_DIR/all_runs.txt")"
```

Narrow to repos from Phase 1 if the org is large — but remember `@joyfill/*` can arrive **transitively**, so a full sweep is the thorough option.

### 2.2 Download logs in parallel

```bash
cut -d'|' -f1,2 "$LOG_DIR/all_runs.txt" | tr '|' ' ' | \
  xargs -P 10 -L 1 bash -c \
  'gh run view "$1" --repo "${ORG}/$0" --log > "${LOG_DIR}/run-$1.log" 2>/dev/null && echo "OK $0 $1" || echo "FAIL $0 $1"'
```

Skip if `$LOG_DIR` already holds logs from a previous run.

### 2.3 Scan for the package and the malicious versions

```bash
echo "=== Any @joyfill reference ==="
grep -rlEi "$JOYFILL_ANY_RE" "$LOG_DIR"/run-*.log 2>/dev/null

echo "=== Malicious version resolved (high confidence) ==="
grep -rlE "$JOYFILL_VER_RE" "$LOG_DIR"/run-*.log 2>/dev/null

echo "=== Real-install evidence lines ==="
grep -rhE "added @joyfill/|\+ @joyfill/|Downloading @joyfill|registry\.npmjs\.org/@joyfill" "$LOG_DIR"/run-*.log 2>/dev/null | sort -u | head -40

echo "=== Cache restore (can reintroduce a malicious version with no install line) ==="
grep -rlE "Cache restored from key|Received [0-9]+ of [0-9]+ .*node_modules|actions/cache" "$LOG_DIR"/run-*.log 2>/dev/null
```

### 2.4 Scan for execution — the detonation signal

```bash
echo "=== Runtime dependency pull by the implant ==="
grep -rlE "(added|installing) (socket\.io-client|axios)" "$LOG_DIR"/run-*.log 2>/dev/null

echo "=== C2 / blockchain egress inside build logs ==="
grep -rliE "$C2_RE|$CHAIN_RE|Sec-V" "$LOG_DIR"/run-*.log 2>/dev/null

echo "=== Campaign / payload strings leaked into logs ==="
grep -rliE 'A9-0135-3|ss_(info|eval|upf|fcd)|ThZG\+0jfXE6VAGOJ' "$LOG_DIR"/run-*.log 2>/dev/null

echo "=== Execution steps in runs that also referenced @joyfill ==="
for f in $(grep -rlEi "$JOYFILL_ANY_RE" "$LOG_DIR"/run-*.log 2>/dev/null); do
  echo "--- $f"
  grep -inE "npm test|npm run |yarn (build|test|start)|pnpm (build|test)|next build|vite build|jest|vitest|playwright|storybook|node (dist|build|server)" "$f" | head -5
done
```

> **Log lines are tab-prefixed** (`<workflow>\t<step>\t<timestamp> <content>`) — do not anchor patterns with `^`.

### 2.5 Classify each hit

**Detonation likely** — malicious version present **and** an execution step ran in the same job. **Detonation confirmed** — any C2/blockchain egress, implant dependency pull, or campaign string in the log.

**False positives to discard:** source imports quoted in type-check or lint output; branch names such as `feat/joyfill-upgrade`; Renovate/Dependabot PR titles; SAST or dependency-review tool output listing the package; docs and comments.

### 2.6 Evidence table

Write `$LOG_DIR/evidence-ci-runs.csv`:

```
repo,run_id,created_at,workflow,install_command,cache_restored,joyfill_version,executed_app_code,iocs_found,verdict
```

| Column | What to write |
|---|---|
| `install_command` | exact command from the log (`npm ci`, `npm install`, `yarn install --immutable`, …) |
| `cache_restored` | `yes (key)` / `no` — a restored `node_modules` bypasses lock-file protection |
| `joyfill_version` | resolved version, or `not installed`, or `unknown (silent install)` |
| `executed_app_code` | `yes (npm test)` / `yes (next build)` / `no (install only)` |
| `iocs_found` | `no`, or the specific IOC (`166.88.134.62`, `socket.io-client pull`, `Sec-V`) |
| `verdict` | `clean` / `exposed (installed, no execution)` / `detonation likely` / `compromised` |

No blank cells.

---

## Phase 3: Container Image Forensics

The payload lives in `dist/` bundles, so it is baked into any image layer built with a malicious version — and it fires when the container **starts** and loads the bundle.

```bash
# Which images were built during/after the window? (check your registry's tag timestamps)
# Then, per candidate image, inspect without running it:
IMG="<registry>/<image>:<tag>"

# 1. Malicious version in a lock file or manifest inside the image
docker run --rm --entrypoint sh "$IMG" -c \
  "grep -rEl '2773[.-]beta' /app/package.json /app/package-lock.json /app/yarn.lock /app/pnpm-lock.yaml 2>/dev/null || echo clean"

# 2. Malicious package present in node_modules
docker run --rm --entrypoint sh "$IMG" -c \
  "ls -d /app/node_modules/@joyfill/* 2>/dev/null && cat /app/node_modules/@joyfill/*/package.json | grep -E '\"version\"' || echo clean"

# 3. Payload strings in the shipped bundles (works even after a bundler inlined them)
docker run --rm --entrypoint sh "$IMG" -c \
  "grep -rlE 'A9-0135-3|166\.88\.134\.62|trongrid|ss_eval' /app/dist /app/build /app/node_modules/@joyfill 2>/dev/null || echo clean"
```

If a bundler inlined `@joyfill` code into an app bundle, the package directory may be absent while the payload strings are present — check (3) even when (2) is clean. Rebuild any hit with `--no-cache` from a pinned stable version and redeploy; then treat every secret available to that container as exposed.

---

## Phase 4: Network Investigation

The strongest evidence of detonation is egress. Search from `2026-07-28T10:00:00Z` forward — and keep the alert live, since malicious versions remain installable.

| IOC | Where to search |
|---|---|
| `166.88.134.62`, `23.27.13.43`, `198.105.127.210`, `23.27.202.27` | firewall, proxy, VPC/NSG flow logs, NetFlow |
| Paths `/$/boot`, `/u/e`, `/u/f`, `/0x/js` | proxy logs with URI capture |
| Header `Sec-V: A9-0135-3` | TLS-inspecting proxy, packet capture |
| `api.trongrid.io`, `fullnode.mainnet.aptoslabs.com`, `bsc-dataseed.binance.org`, `bsc-rpc.publicnode.com` | DNS logs — **correlate with build/app-start times** |
| `ip-api.com` | DNS/proxy logs |

**Splunk**

```
index=proxy (dest_ip IN ("166.88.134.62","23.27.13.43","198.105.127.210","23.27.202.27")
  OR uri_path IN ("/$/boot","/u/e","/u/f","/0x/js"))
| stats count by src_ip, dest_ip, uri_path, http_user_agent
```

**Elastic**

```
destination.ip : ("166.88.134.62" or "23.27.13.43" or "198.105.127.210" or "23.27.202.27")
  or dns.question.name : ("api.trongrid.io" or "fullnode.mainnet.aptoslabs.com" or "bsc-dataseed.binance.org" or "bsc-rpc.publicnode.com")
```

**AWS VPC Flow Logs (CloudWatch Insights)**

```
filter dstAddr in ["166.88.134.62","23.27.13.43","198.105.127.210","23.27.202.27"]
| stats count(*) as hits by srcAddr, dstAddr, dstPort
```

**Interpretation.** A C2 IP hit is compromise — identify the host and rotate everything it could reach. A blockchain-RPC hit from a build or app-start process, with no Web3 code in that service, is strong detonation evidence; the same hit from a Web3 service is inconclusive on its own (see Pitfall 8). No hits, with clean Phases 1–3, is consistent with a clean finding but does not cover hosts outside your inspection path (laptops on home networks).

---

## Phase 5: Workstation Investigation

Developer machines are the campaign's real target: the RAT injects into editor and Electron bundles and into the **global npm CLI**, so it survives dependency cleanup and re-fires on the next `npm` invocation. Run these checks on every machine that installed or ran a `2773` prerelease. Each is read-only.

**If you do only one check, do 5.1.**

### 5.1 Global npm CLI injection (highest value)

The npm CLI is the amplification point — once injected, every subsequent `npm` command re-executes the implant.

```bash
NPM_G="$(npm root -g)"            # do NOT hardcode — Homebrew macOS uses /opt/homebrew/lib/node_modules
grep -lE '/\*(C25061[7-9]A|C250620A|C26051[12]A|RS260605)\*/' "$NPM_G/npm/lib/cli.js" 2>/dev/null \
  && echo "COMPROMISED — global npm CLI is injected" || echo "global npm CLI: clean"
```

### 5.2 Editor / Electron bundle injection

```bash
# VS Code, Cursor, Antigravity (@vscode/deviceid), Discord Desktop, GitHub Desktop
find / -path '*/@vscode/deviceid/dist/index.js' \
     -o -path '*/discord_desktop_core/index.js' \
     -o -path '*/GitHub Desktop/resources/app/main.js' 2>/dev/null | \
  while read -r f; do
    grep -lE '/\*(C25061[7-9]A|C250620A|C26051[12]A|RS260605)\*/' "$f" 2>/dev/null \
      && echo "INJECTED: $f"
  done
echo "(editor/Electron bundle scan complete)"
```

Narrow the `find` root to `/Applications` (macOS), `$LOCALAPPDATA` (Windows) or `~/.vscode* ~/.cursor*` if a full-disk walk is too slow.

### 5.3 Credential staging directory

Presence of archives here means collection **succeeded** — rotate before cleanup.

```bash
ls -la /tmp/.npm 2>/dev/null && echo "FOUND — staged exfil data (Unix)" || echo "/tmp/.npm: clean"
# Windows (PowerShell): Get-ChildItem "$env:USERPROFILE\.npm" -ErrorAction SilentlyContinue
```

### 5.4 Malicious versions on disk

```bash
# node_modules
find ~ -type d -path '*/node_modules/@joyfill/*' -maxdepth 8 2>/dev/null | while read -r d; do
  v=$(python3 -c "import json,sys;print(json.load(open('$d/package.json'))['version'])" 2>/dev/null)
  case "$v" in *2773*) echo "MALICIOUS: $d @ $v";; *) echo "ok: $d @ $v";; esac
done

# Lock files and manifests — both prerelease spellings
find ~ \( -name package.json -o -name package-lock.json -o -name yarn.lock -o -name pnpm-lock.yaml \) \
  -not -path '*/node_modules/*' -maxdepth 6 2>/dev/null | \
  xargs grep -lE '@joyfill/(layouts|components)[^ ]*2773[.-]beta' 2>/dev/null \
  || echo "No malicious @joyfill versions in local manifests/lock files"
```

### 5.5 Payload strings in installed bundles

Catches the case where the package directory was cleaned but a built artifact still carries the implant.

```bash
grep -rlE 'A9-0135-3|166\.88\.134\.62|ThZG\+0jfXE6VAGOJ|ss_eval' \
  ~/projects ~/code ~/repos 2>/dev/null --include='*.js' --include='*.mjs' --include='*.cjs' | head -20 \
  || echo "No payload strings in local build output"
```

### 5.6 npm cache

```bash
npm cache ls 2>/dev/null | grep -E '@joyfill/(layouts|components).*2773[.-]beta' \
  || echo "npm cache ls: no malicious versions (or unsupported on this npm)"

# Fallback — npm cache ls does not exist on all npm majors
CACHE="$(npm config get cache)"
[ -d "$CACHE/_cacache" ] && grep -rlE '2773[.-]beta' "$CACHE/_cacache" 2>/dev/null | head -5
```

### 5.7 Network indicators on the host

```bash
netstat -an 2>/dev/null | grep -E '166\.88\.134\.62|23\.27\.13\.43|198\.105\.127\.210|23\.27\.202\.27' \
  && echo "FOUND — active C2 connection" || echo "no active C2 connections"

# macOS DNS query log
log show --predicate 'process == "mDNSResponder"' --last 7d 2>/dev/null | \
  grep -E 'trongrid|aptoslabs|bsc-dataseed|bsc-rpc\.publicnode' | head -10

# Linux
journalctl -u systemd-resolved --since "2026-07-28" 2>/dev/null | grep -E 'trongrid|aptoslabs|bsc-dataseed'
```

### 5.8 Shell history, npm debug logs, and AI-agent conversation logs

```bash
grep -hE '@joyfill/(layouts|components)[^ ]*2773[.-]beta' \
  ~/.zsh_history ~/.bash_history ~/.local/share/fish/fish_history 2>/dev/null \
  || echo "no malicious @joyfill installs in shell history"

grep -rlE '2773[.-]beta' ~/.npm/_logs/ 2>/dev/null || echo "no IOC matches in npm debug logs"
```

AI-agent session logs retain full command output long after npm rotates its own logs, so they are often the best record of what a build actually resolved:

```bash
# EXCLUDE the investigating agent's own session — it has read every IOC string in this file
CURRENT_SESSION_PROJECT=$(echo "$PWD" | sed 's|/|-|g')
find ~/.claude/projects -name '*.jsonl' -print0 2>/dev/null | \
  xargs -0 grep -lE '2773[.-]beta|A9-0135-3|166\.88\.134\.62' 2>/dev/null | \
  grep -v "$CURRENT_SESSION_PROJECT" | grep -v 'paste-cache' | grep -v 'file-history' \
  || echo "no IOC matches in prior agent sessions"
```

A hit that survives that filter is worth reading: classify it as **INVESTIGATE** if the same session also executed an install or a test/build command, or **REFERENCE ONLY** if the session merely discussed the incident.

### Workstation results

| Check | Status |
|---|---|
| 5.1 Global npm CLI injection | found / clean |
| 5.2 Editor / Electron bundle injection | found / clean |
| 5.3 Credential staging dir | found / clean |
| 5.4 Malicious version in `node_modules` / lock files | found / clean |
| 5.5 Payload strings in build output | found / clean |
| 5.6 npm cache | found / clean |
| 5.7 Active C2 or blockchain DNS | found / clean |
| 5.8 Shell history / npm logs / agent logs | found / reference only / clean |

Any `found` in 5.1, 5.2, 5.3, 5.5 or 5.7 means **treat the machine as compromised** — preserve evidence, then go to Phase 7 (persistence removal comes before anything else). A `found` in 5.4, 5.6 or 5.8 alone means the malicious version reached the machine; whether it detonated depends on whether the package was ever loaded, so verify egress (5.7) and treat it as compromised if you cannot rule that out.

---

## Phase 6: Present Results

1. **Repo posture** (`evidence-repos.csv`) — which repos declare or lock `@joyfill/*`, whether their range admits a prerelease, install command, cache use.
2. **CI runs** (`evidence-ci-runs.csv`) — per run: version on disk, whether app code executed, IOCs, verdict.
3. **Images** — per image: built/started in window, malicious version present, payload strings present, action taken.
4. **Executive summary** — a short verdict per repo (`clean` / `exposed` / `detonation likely` / `compromised`), the count of workstations checked and their results, and the credential-rotation scope implied by the worst verdict.

---

## Phase 7: Remediation & Hardening (User Approval Required)

Order matters — persistence first, or you will re-infect the host with the next `npm` command.

### Remediation — only if compromised

1. **Remove persistence FIRST.** Reinstall the global npm CLI (`brew reinstall node` / `nvm install --reinstall-packages-from`, or replace `<npm root -g>/npm`) and reinstall any editor/Electron app whose bundle carries an injection marker — VS Code, Cursor, Antigravity, Discord, GitHub Desktop. Do not hand-edit an injected minified bundle.
2. **Preserve evidence before cleanup** — copy the injected files, the `.npm` staging directory contents, and relevant logs.
3. **Purge the malicious versions** — `rm -rf node_modules`, `npm cache clean --force`, then `npm ci` from a lock file pinning a stable version.
4. **Rebuild and redeploy** every image built or started with a malicious version, using `docker build --no-cache`.
5. **Rotate every credential reachable from the affected process or runner** — npm tokens, GitHub PATs and `gh` CLI tokens, SSH keys, cloud credentials (including OIDC-issued), registry credentials, signing keys, and every `secrets.*` value exposed to an affected workflow. Check `/tmp/.npm` and `%USERPROFILE%\.npm` for staged archives first; their presence means collection succeeded.
6. **Block the C2** — deny the four C2 IPs at the egress boundary and alert on the C2 paths and the `Sec-V` header.

### Hardening — wherever a repo can still resolve a malicious version

1. **Pin `@joyfill/*` to an exact stable version** — `0.1.1` for `layouts`, `4.0.0-rc24` for `components`. Stop tracking `2773` prereleases and any beta dist-tag. Both `@joyfill/layouts` malicious prereleases are still live, so this is not merely hygiene.
2. **Never take prereleases for UI dependencies in CI** — prefer exact pins; if a range is required, exclude prereleases.
3. **Switch every CI install to lock-file-respecting** — `npm ci`, `pnpm install --frozen-lockfile`, `yarn install --immutable`.
4. **Audit `node_modules` caching.** Caching a whole `node_modules` tree defeats lock-file protection; cache the package-manager store instead and let the frozen install rebuild the tree.
5. **Egress-allowlist CI runners.** A build step contacting a blockchain RPC or an unknown IP should fail, not silently succeed.
6. **Enable file-integrity monitoring on developer machines** for the global npm CLI and Electron app bundles — the persistence sites this campaign uses.

---

## References

- Socket — original research, attribution, hashes: https://socket.dev/blog/joyfill-npm-beta-releases-compromised
- StepSecurity — payload locations, campaign markers, detection strategies: https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise
- The Hacker News — coverage: https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html
- npm registry metadata (publish times, current availability): `https://registry.npmjs.org/@joyfill/layouts`, `https://registry.npmjs.org/@joyfill/components`
