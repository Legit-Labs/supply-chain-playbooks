# August 2026 Shai-Hulud npm Wave (keyv / cacheable) — Investigation Playbook

Playbook for investigating whether a GitHub org was affected by the **August 4, 2026 Shai-Hulud npm wave** that began with a **compromised maintainer account behind `keyv` and the `cacheable` family** and spread worm-like to **400+ packages across 1,300+ versions** with a combined **2+ billion monthly installs**. The payload is a credential stealer, an npm worm, **and** a GitHub repository infector in one binary — and this wave adds three capabilities prior Shai-Hulud waves did not have: **Ethereum-contract-resolved C2**, **GitHub Actions secret harvesting via an injected workflow**, and **OIDC trusted-publisher abuse**.

> **CI/CD platform note:** This playbook targets GitHub Actions. For other CI/CD platforms (GitLab CI, Jenkins, CircleCI, Bitbucket, Azure DevOps), adapt the log-collection commands — the investigation logic is the same: identify references to any compromised package, collect run logs from the exposure window, search for compromised versions and IOCs, and verify lock-file protection. **Phase 2c (Actions secret harvesting) is GitHub-Actions-specific** and has no equivalent on other platforms.

> **Wave lineage — do NOT substitute IOCs from earlier playbooks.** This is the same *campaign family* as the **AntV wave (May 19, 2026)** (`antv_supply_chain/`), the **TanStack wave (May 11, 2026)** (`tanstack_supply_chain/`), and the **SAP CAP wave (April 29, 2026)** (`sap_supply_chain/`) — but the **payload file names, C2 mechanism, injected-file set, and branch/workflow artifacts are all different**. Running one of those playbooks against this wave makes the agent grep for the wrong strings. The procedure is shared; **the indicators are not.**

| | Earlier "Mini Shai-Hulud" waves | **This wave (August 2026)** |
|---|---|---|
| Payload file | `index.js` / `execution.js` | **`math_init.js`** / `Math_Symbol.js` |
| Loader | `bun run index.js` | **`node setup.mjs`** |
| C2 | Hardcoded domain (`t.m-kosche[.]com`) | **Ethereum contract → rotating domains**; fallback `npm-cache[.]com` |
| Dead-drop description | `niagA oG eW ereH :duluH-iahS` (reversed) | **`Shai-Hulud: Here We Go Again`** (plain) |
| Actions secret theft | — | **Injected `codeql_analysis.yml` workflow** |
| Trusted publishing | Provenance forgery | **OIDC token exchange for a publish token** |

---

## Incident Details

An attacker took over the GitHub/npm identity behind `keyv` and the broader `cacheable` family (malicious commits appeared in `jaredwray/keyv`, `jaredwray/cacheable`, and `jaredwray/ecto`) and published trojanized patch releases. The payload is a self-replicating worm:

1. **`preinstall` hook fires** — `scripts.preinstall: node setup.mjs`. The obfuscated `setup.mjs` downloads **Bun 1.3.13** from `github.com/oven-sh/bun/releases/download/bun-v1.3.13/` if not already present, executes the **~710–728 KB obfuscated payload** (`math_init.js` / `Math_Symbol.js`), then deletes the temporary Bun executable. Obfuscation is a position-dependent substitution cipher derived from PBKDF2-HMAC-SHA256.

2. **Credential harvesting across hundreds of configured paths** (Windows, macOS, Linux) — package-manager tokens (npm, Yarn, PyPI, Verdaccio), cloud (AWS profiles + **IMDSv2** + Secrets Manager, Azure, GCP, Alibaba, Tencent, Hetzner), **Kubernetes** service-account tokens and kubeconfigs, **HashiCorp Vault** KV mounts, SSH keys, browser credential stores, `.env` files, shell histories, **AI-service keys** (OpenAI, Anthropic, Claude, Cursor, Codex, Gemini), crypto wallet material, `/etc/shadow`, `/proc/self/environ`, plus Stripe and Slack tokens via ~200 glob patterns.

3. **CI runner memory scraping** — on Linux GitHub Actions runners the payload uses **`sudo python3` to read the `Runner.Worker` process memory** and extract secret-store objects. *Masked secrets in logs are no protection against this.*

4. **Exfiltration with rotating C2** — results are gzipped, **AES-256-GCM** encrypted with a random key, wrapped in an RSA public key. The C2 address list is resolved dynamically by calling **Ethereum mainnet contract `0xE1f2395ee43e45A1556EC6438a88c31B83493103`** (selector `0x53ed5143`) via `eth-mainnet.nodereal[.]io`; results POST to `/router` over HTTPS. Fallback endpoint: **`npm-cache[.]com:443/router`**.

5. **Remote code execution** — C2 responses may contain a `code` field passed to **`eval()`**, giving the operator full RCE inside the compromised process. Treat any confirmed C2 contact as full host compromise, not just credential theft.

6. **GitHub dead-drop fallback** — a stolen token creates a **public repository** named from Dune vocabulary (`sardaukar`, `fremen`, `atreides`, `sandworm`, `melange`) with description **`Shai-Hulud: Here We Go Again`**, committing encrypted results under `results/`. ~1,300 such repos observed. **If the account has no organizations**, the worm instead publishes the victim's own PAT — double-base64 encoded — in a **commit message** prefixed `IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients:` so other infected hosts can reuse it.

7. **npm self-propagation** — the worm validates each stolen npm token, checking for **`bypass_2fa === true`** and write permission. For every writable package it downloads the current `latest` tarball, injects `package/math_init.js`, writes `package/setup.mjs`, **replaces the package's entire `scripts` object** with `scripts.preinstall: node setup.mjs`, increments the patch version, and publishes via authenticated `PUT` to the registry (User-Agent `npm/11.13.1 node/v24.10.0 …`).

8. **Repository infection** — with a stolen GitHub token, the worm commits **five files to up to 50 branches** per repo (skipping `dependabot/*` and `copilot/*`): `.vscode/tasks.json` (an `Environment Setup` task running `node .claude/setup.mjs`), `.vscode/setup.mjs`, `.claude/math_init.js`, `.claude/settings.json` (a `SessionStart` hook running `node .vscode/setup.mjs`), and `.claude/setup.mjs`. Commit message: **`chore: update config`** with a forged `Co-authored-by: claude <claude@users.noreply.github.com>` trailer. **Opening an infected repo in VS Code, or starting a Claude Code session in it, is enough to detonate the payload** — no `npm install` required.

9. **GitHub Actions secret harvesting** — for tokens carrying the `workflow` scope, the worm enumerates up to 100 repos with push permission (updated since September 2025), checks for Actions secrets, creates branch **`dependabot/github_actions/format/setup-formatter`**, adds **`.github/workflows/codeql_analysis.yml`** (workflow display name `Run Copilot` / `Add CodeQL Analysis`, impersonating `github-advanced-security[bot]`) that assigns **`${{ toJSON(secrets) }}`** to an env var and writes it to `format-results.txt`, uploads it as an artifact, then **downloads the artifact and deletes the workflow and branch**. Actions are pinned to real SHAs (`actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd`, `actions/upload-artifact@bbbca2ddaa5d8feaa63e36b76fdaad77386f024f`) to look legitimate. **The cleanup means the branch and workflow may be gone — the audit log and artifact history are the surviving evidence.**

10. **Targeted trusted-publishing attack (OpenSearch)** — special-cased: when `GITHUB_WORKFLOW_REF` contains `release-drafter.yml` **and** `GITHUB_REPOSITORY` contains `/opensearch-js`, the payload requests an Actions **OIDC token** (audience `npm:registry.npmjs.org`), adds a malicious `optionalDependencies` entry pointing at a fixed attacker commit, and exchanges the OIDC token for a real publish token — producing a **valid Sigstore/Rekor provenance bundle** from the legitimate workflow context. **Provenance is not a trust signal for this wave.**

> **Evasion behavior to expect during investigation:** the payload relaunches itself with `_NODE_RUNTIME_INIT=1` when *not* in CI, holds a PID lock at **`/tmp/tmp.dpkg_14527.lock`**, installs empty `SIGINT`/`SIGTERM` handlers, and swallows all top-level exceptions with **exit code 0**. A green CI run is not evidence of a clean run.

> **Dormant capabilities — do not report as active persistence without evidence.** The payload embeds a Bash Bun loader, a Python Bun loader, and a **`gh-token-monitor`** installer (macOS LaunchAgent / Linux systemd, polling GitHub token validity every 60s for up to 24h) with **no observed call sites**. Check for them (Phase 4), but treat a hit as a finding requiring confirmation, not an assumed install.

### CVE / advisory

- **CVE:** none assigned at time of writing. **GHSA:** none published for `keyv` / `cacheable` as of August 5, 2026 — recheck GitHub Advisories and NVD.
- **Primary writeup:** JFrog Security Research — https://research.jfrog.com/post/shai-hulud-is-back-august/
- **Package-level tracking:** Socket.dev — https://socket.dev/blog/popular-npm-packages-in-the-keyv-and-cacheable-namespaces-compromised-in-active-supply-chain

### Affected packages

**Primary entry points (all versions below have since been UNPUBLISHED from npm).** Each malicious version is exactly **one patch above** the package's legitimate `latest` — the worm's version-bump signature. The "Safe version" column was verified directly against the npm registry on **August 5, 2026**.

| Package | Malicious version | Safe version (current `latest`) | Monthly downloads |
|---|---|---|---|
| `keyv` | `6.0.0` | `5.6.0` | ~604M |
| `flat-cache` | `6.1.24` | `6.1.23` | ~580M |
| `file-entry-cache` | `11.1.6`, `11.1.7` † | `11.1.5` | ~571M |
| `cacheable-request` | `13.0.20` | `13.0.19` | ~137M |
| `@cacheable/utils` | `2.5.1` | `2.5.0` | ~34M |
| `cacheable` | `2.5.1` | `2.5.0` | ~30M |
| `@cacheable/memory` | `2.2.1` | `2.2.0` | ~28M |
| `cache-manager` | `7.2.10` | `7.2.9` | ~16M |
| `@cacheable/node-cache` | `3.1.2` | `3.1.1` | ~6M |
| `@cacheable/net` | `2.1.1` | `2.1.0` | ~3.7K |
| `ecto` | `5.0.1` | `5.0.0` | ~4.5K |
| `@thiennq/docs-viewer` | `1.6.2` | — (outside primary namespaces) | — |

† **Version disagreement between sources.** One vendor reports `file-entry-cache@11.1.6`, another `11.1.7`. Neither exists on the registry today (current `latest` is `11.1.5`), so **treat both as malicious** — a lock file pinning either is a finding.

> ⚠️ **`flat-cache` and `file-entry-cache` sit underneath ESLint.** Any repo with ESLint in its dev-dependency tree is in scope transitively, even if it never names these packages.

**Community spread — the much larger surface.** The worm republished **every package writable by every stolen npm token**: 400+ packages across 1,300–1,700+ versions. Heavily hit scopes include **`@servicetitan/*`** (100+ packages), **`@or-sdk/*`** (80+), **`@ornikar/*`** (40+), **`@onereach/*`**, and **`@nebula.js/*`**. **Do not treat the table above as the full inventory** — for the community-spread wave, the reliable detection is the **payload fingerprint** (a `preinstall` running `node setup.mjs`, or a `math_init.js` inside a package), not a package-name list. Phase 1 step 5 and Phase 2 step 3 both scan for it.

> **Detection regex (primary package names):**
> ```
> \b(keyv|cacheable|cacheable-request|cache-manager|flat-cache|file-entry-cache|ecto)\b|@cacheable/|@keyv/
> ```

### Exposure window

| Event | Time (UTC) |
|---|---|
| `keyv@6.0.0` published with malicious `preinstall` hook | **2026-08-04 09:35** |
| Campaign observed spreading beyond keyv/cacheable namespaces | 2026-08-04 09:38 |
| `cacheable` family burst published | 2026-08-04 10:09:44 – 10:14:41 |
| Public disclosure | 2026-08-04 (~13:37 CEST) |
| New infections observed | 50–100 packages every few minutes, **ongoing at time of writing** |

**Recommended scan window (padded):** `2026-08-03T00:00:00Z` to **now**. The initial compromise is precisely timestamped, but **this campaign is still active** — the worm keeps republishing as new tokens are stolen, so do not close the window at the disclosure date. Pad backward one day to catch pre-positioning commits.

```bash
export SINCE="2026-08-03T00:00:00Z"
export UNTIL="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

### Indicators of compromise

| IOC | Value | Where it shows up |
|---|---|---|
| Loader file | `setup.mjs` (`preinstall: node setup.mjs`) | package tarballs, `node_modules`, CI install logs, `.vscode/`, `.claude/` |
| Payload file | `math_init.js`, `Math_Symbol.js` | package tarballs, `.claude/` |
| Loader hash (npm tarball) | `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668` | file hash |
| Loader hash (community spread / repo-injected) | `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb` | file hash |
| Payload hash | `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc` | file hash |
| Injected `.vscode/tasks.json` hash | `927387d0cfac1118df4b383decc2ea6ba49c9d2f98b47098bcbcba1efc026e1f` | repo working trees, all branches |
| Injected `.claude/settings.json` hash | `14eb4ce01dd4307759887ff819359b70d7d9ff709ecde039a5abc1aac325b128` | repo working trees, all branches |
| Injected Actions workflow hash | `3f3f42d072bd36860ab7db7fb5e10ac0d22c741c13c89505ccd6ec0ea572eea7` | `.github/workflows/codeql_analysis.yml` |
| Runner memory scraper hash | `29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7` | runner host |
| C2 fallback domain | `npm-cache[.]com` (path `/router`) | DNS / proxy / NetFlow |
| C2 resolver | `eth-mainnet.nodereal[.]io` | DNS / proxy — **see false-positive note** |
| Ethereum C2 contract | `0xE1f2395ee43e45A1556EC6438a88c31B83493103` (selector `0x53ed5143`) | payload strings, blockchain RPC traffic |
| Dead-drop repo description | `Shai-Hulud: Here We Go Again` | GitHub repo descriptions (~1,300 observed) |
| Dead-drop repo names | `sardaukar`, `fremen`, `atreides`, `sandworm`, `melange` | GitHub repo names |
| PAT-in-commit marker | `IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients:` | GitHub commit messages |
| Campaign search markers | `thebeautifulmarchoftime`, `thebeautifulsnadsoftime` | GitHub code/commit search |
| Injected branch | `dependabot/github_actions/format/setup-formatter` | repo branch list, audit log |
| Injected workflow | `.github/workflows/codeql_analysis.yml`, display name `Run Copilot` / `Add CodeQL Analysis` | Actions runs, audit log |
| Secret-exfil artifact | `format-results.txt` / `format-results` artifact | Actions artifact list |
| Secret serialization | `${{ toJSON(secrets) }}` in any workflow | workflow files, run logs |
| Infection commit message | `chore: update config` + `Co-authored-by: claude <claude@users.noreply.github.com>` | git history, **all branches** |
| PID lock | `/tmp/tmp.dpkg_14527.lock` | runner / workstation filesystem |
| Env marker | `_NODE_RUNTIME_INIT=1` | process environment, shell history |
| Bun download | `github.com/oven-sh/bun/releases/download/bun-v1.3.13/` | CI logs, proxy |
| Dormant persistence | `gh-token-monitor` (LaunchAgent / systemd) | workstation — **confirm before reporting** |

> **False positive — `eth-mainnet.nodereal[.]io` and the Ethereum contract.** If the customer builds anything blockchain-related, calls to public Ethereum RPC endpoints are entirely normal. This is an IOC **only** when correlated with the contract address `0xE1f2395ee43e45A1556EC6438a88c31B83493103` or selector `0x53ed5143`, or when it originates from a **CI runner or developer host that has no business touching Ethereum**. Do not flag a Web3 team's build agents on the domain alone.

> **False positive — `dependabot/*` branches and CodeQL workflows.** Real Dependabot branches and real `codeql-analysis.yml` workflows are everywhere. The signals here are **specific**: the exact branch `dependabot/github_actions/format/setup-formatter`, and a `codeql_analysis.yml` (underscore, not the conventional hyphen) that **serializes `${{ toJSON(secrets) }}`**. Match on the secret-serialization line, not on "there is a CodeQL workflow."

> **False positive — `.claude/settings.json` and `.vscode/tasks.json` existing at all.** These are ordinary developer files. The signal is a **`SessionStart` hook or task that shells out to `node …/setup.mjs`**, or the file hashes above — not the file's presence.

### What IS affected

- Any `npm` / `pnpm` / `yarn` / `bun` install that resolved a malicious version during the window — **direct or transitive** — where install scripts were **not** disabled. `flat-cache` / `file-entry-cache` reach most repos transitively **through ESLint**.
- CI workflows that ran installs during the window without `--ignore-scripts`, on **any** runner — and Linux GitHub Actions runners specifically, where the payload scrapes `Runner.Worker` memory for secrets that never appear in logs.
- Docker image builds that ran installs during the window.
- **Repos infected via stolen GitHub tokens — even with no npm install at all.** The five injected files detonate when a developer opens the repo in VS Code or starts a Claude Code session. Check **all branches**, not just the default.
- Any org whose GitHub token had `workflow` scope — Actions secrets may have been exfiltrated and the evidence self-deleted.
- **Your own published npm packages**, if any maintainer's token was stolen (Phase 2b).

### What is NOT affected

- Installs from a committed lock file with `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --immutable`, **provided the lock pins a version predating the window** — verify the pinned version against the malicious list rather than assuming.
- **npm 12 and later**: `preinstall` hooks do not execute by default, so the install-time vector does **not** fire. This is a genuine mitigation for the npm-install path — **but it does not protect against the repo-infection path** (VS Code / Claude Code detonation), which needs no npm at all.
- Installs run with `--ignore-scripts` — blocks the `preinstall` hook. But if a malicious *version* was still resolved into the tree, treat it as present and rebuild clean.
- Pre-built container images not rebuilt during the window.
- Source-only references — a TypeScript `import` with no install in the window; docs, Helm charts, or Terraform that merely name a package.

### Lock file protection

Lock files (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`) **do protect** when used correctly:

- `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --immutable` install exactly what the lock says.
- A lock generated **before August 3, 2026** pinning clean versions never resolves a malicious tarball.

Lock files do **NOT** protect if: no lock is committed; CI runs a non-frozen install; the lock was regenerated during the window; a Dependabot/Renovate PR bumped an affected package mid-window; or a floating range (`^`, `~`, `latest`) lets a fresh install resolve a malicious version. Because the malicious versions were **patch bumps**, a `^` or `~` range on any listed package resolved them automatically.

> **Removal from npm is NOT remediation.** Every malicious version has been unpublished. That means a fresh install can no longer fetch one — but a version already recorded in a committed lock file, sitting in `~/.npm/_cacache`, or baked into an existing container image is still there. Unpublishing does not undo an install that already ran.

---

## Setup

```bash
export ORG="<your-github-org>"
export SINCE="2026-08-03T00:00:00Z"
export UNTIL="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export LOG_DIR="/tmp/supply-chain-scan-keyv-cacheable"
mkdir -p "$LOG_DIR"
```

**Log caching:** reuse logs in `$LOG_DIR` if present. **Write evidence to files, not context** — write CSV to `$LOG_DIR` as you go.

**Rate limits:**

```bash
gh api /rate_limit --jq '.resources.core | "\(.remaining)/\(.limit) (resets \(.reset|todate))"'
gh api /rate_limit --jq '.resources.code_search | "code-search: \(.remaining)/\(.limit)"'
```

Code search ~30 req/min; REST 5,000/hr; log downloads count against REST. Use `xargs -P 10`. For orgs over ~50 repos, shallow-clone and grep locally (Phase 1).

> **Positive control — run this before trusting any clean result.** A zero-hit grep and a broken grep look identical. Confirm your search path works by matching something you know is present:
> ```bash
> gh api "search/code?q=eslint+org:${ORG}&per_page=1" --jq '.total_count'
> ```
> A non-zero count proves code search reaches this org. If it returns `0` for `eslint`, your query or auth is broken — fix that before concluding the org is clean.

---

## Phase 1: Repo Analysis

**Goal:** For every repo referencing an affected package, capture declared/locked versions, the install command, and whether the config is vulnerable in principle. Window-agnostic.

### 1. Find references to any affected package

```bash
for pkg in keyv "@keyv" cacheable "@cacheable" cacheable-request cache-manager \
           flat-cache file-entry-cache ecto; do
  q=$(printf '%s' "$pkg" | python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.stdin.read().strip()))")
  total=$(gh api "search/code?q=${q}+org:${ORG}&per_page=1" --jq '.total_count' 2>/dev/null)
  echo "=== $pkg (total: ${total:-0}) ==="
  [ "${total:-0}" -gt 0 ] && gh api "search/code?q=${q}+org:${ORG}&per_page=100" \
    --jq '.items[] | "'"$pkg"'\t\(.repository.full_name)\t\(.path)"' 2>/dev/null
  sleep 2
done | sort -u > "$LOG_DIR/refs.tsv"
wc -l "$LOG_DIR/refs.tsv"
```

> **Gate on `total_count` first** (1 API unit) before pulling `items` — halves rate-limit consumption on orgs where most names return zero.

> **Faster alternative for large orgs (>50 repos):** shallow-clone and grep locally.
> ```bash
> mkdir -p "$LOG_DIR/clones" && cd "$LOG_DIR/clones"
> gh repo list "$ORG" --no-archived --limit 1000 --json nameWithOwner --jq '.[].nameWithOwner' | \
>   xargs -P 10 -I {} bash -c 'git clone --depth 1 --filter=blob:none "git@github.com:{}.git" 2>/dev/null || echo "FAIL: {}"'
> grep -rE --include='package.json' --include='package-lock.json' --include='pnpm-lock.yaml' --include='yarn.lock' \
>   '"(keyv|cacheable|cacheable-request|cache-manager|flat-cache|file-entry-cache|ecto)"|@cacheable/|@keyv/' . \
>   > "$LOG_DIR/refs-from-local-clone.txt"
> ```

### 2. Classify each reference

| File pattern | Category | Risk |
|---|---|---|
| `package.json` | npm manifest | **HIGH** — check spec range vs malicious versions |
| `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` | Lock file | **CRITICAL** — check pinned version against malicious list |
| `Dockerfile` | Docker build | **HIGH** if it runs an install during the window |
| `.github/workflows/*.yml` | CI workflow | **CHECK** — does it install JS deps? |
| `.vscode/tasks.json`, `.claude/settings.json` | Agent/editor config | **CRITICAL** — direct infection vector (Phase 1 step 5) |
| `*.ts/.tsx/.js/.jsx` | Source | **NOT AFFECTED** — import, not install |
| `*.md`, `values.yaml`, `*.tf` | Docs / infra | **NOT AFFECTED** |

### 3. Extract version data per repo

```bash
python3 <<'PY'
import base64, json, re, subprocess, os
ORG = os.environ["ORG"]; REPO = "<repo>"
BAD = {
  "keyv": {"6.0.0"}, "cacheable": {"2.5.1"}, "flat-cache": {"6.1.24"},
  "file-entry-cache": {"11.1.6", "11.1.7"}, "cacheable-request": {"13.0.20"},
  "cache-manager": {"7.2.10"}, "ecto": {"5.0.1"},
  "@cacheable/memory": {"2.2.1"}, "@cacheable/node-cache": {"3.1.2"},
  "@cacheable/utils": {"2.5.1"}, "@cacheable/net": {"2.1.1"},
  "@thiennq/docs-viewer": {"1.6.2"},
}
rx = re.compile(r'^(keyv|cacheable|cacheable-request|cache-manager|flat-cache|file-entry-cache|ecto)$|^@(cacheable|keyv)/')

def fetch(path):
    try:
        out = subprocess.run(["gh","api",f"repos/{ORG}/{REPO}/contents/{path}","--jq",".content"],
                             capture_output=True, text=True, check=True).stdout
        return base64.b64decode(out)
    except Exception:
        return None

pj = fetch("package.json")
if pj:
    d = json.loads(pj)
    for s in ("dependencies","devDependencies","optionalDependencies","peerDependencies"):
        for k, v in (d.get(s) or {}).items():
            if rx.search(k): print(f"MANIFEST {s}: {k} = {v}")
    print("SCRIPTS:", json.dumps(d.get("scripts", {})))

pl = fetch("package-lock.json")
if pl:
    d = json.loads(pl)
    for k, v in (d.get("packages") or {}).items():
        name = k.split("node_modules/")[-1]
        ver = v.get("version")
        if rx.search(name):
            flag = "  *** MALICIOUS ***" if ver in BAD.get(name, set()) else ""
            print(f"LOCK {name}: {ver}{flag}")
PY

# Install commands in workflows
gh api "repos/${ORG}/<repo>/contents/.github/workflows" --jq '.[].path' 2>/dev/null | while read wf; do
  gh api "repos/${ORG}/<repo>/contents/${wf}" --jq '.content' | base64 -d | \
    grep -iE "npm ci|npm install|pnpm install|yarn install|bun install|--ignore-scripts"
done
```

### 4. Check ESLint reach (transitive exposure)

`flat-cache` and `file-entry-cache` arrive via ESLint in repos that never name them. Any repo with a non-frozen install and ESLint in devDependencies is in scope:

```bash
gh api "search/code?q=eslint+filename:package.json+org:${ORG}&per_page=100" \
  --jq '.items[] | .repository.full_name' 2>/dev/null | sort -u > "$LOG_DIR/eslint-repos.txt"
wc -l "$LOG_DIR/eslint-repos.txt"
```

Cross-reference against repos with no committed lock file or a non-frozen install command — those are the transitive-exposure candidates.

### 5. Scan ALL branches for the injected infection files

This is the vector that needs no npm install. **The default branch is not enough** — the worm writes to up to 50 branches.

```bash
gh repo list "$ORG" --no-archived --limit 1000 --json nameWithOwner --jq '.[].nameWithOwner' | \
while read repo; do
  gh api "repos/${repo}/branches?per_page=100" --jq '.[].name' 2>/dev/null | \
  while read br; do
    for f in ".claude/math_init.js" ".claude/setup.mjs" ".vscode/setup.mjs"; do
      if gh api "repos/${repo}/contents/${f}?ref=${br}" --jq '.sha' >/dev/null 2>&1; then
        echo "*** INFECTED: ${repo} @ ${br} :: ${f}"
      fi
    done
  done
done | tee "$LOG_DIR/infected-branches.txt"
```

The presence of **`math_init.js` or `setup.mjs` under `.claude/` or `.vscode/` is unambiguous** — these are not legitimate files. Also hunt the infection commit signature across all branches:

```bash
gh repo list "$ORG" --no-archived --limit 1000 --json nameWithOwner --jq '.[].nameWithOwner' | \
while read repo; do
  gh api "repos/${repo}/commits?since=${SINCE}&per_page=100" \
    --jq ".[] | select(.commit.message | test(\"chore: update config\")) | \"${repo} | \(.sha[0:8]) | \(.commit.author.date) | \(.commit.message | split(\"\n\")[0])\"" 2>/dev/null
done | tee "$LOG_DIR/suspect-commits.txt"
```

Then verify each hit carries the forged trailer:

```bash
gh api "repos/<repo>/commits/<sha>" --jq '.commit.message' | grep -i "claude@users.noreply.github.com"
```

---

## Phase 2: CI Run Analysis

**Why:** Phase 1 only finds repos that *name* an affected package. Transitive installs (ESLint!) won't show. CI logs reveal what actually got installed.

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

### 3. Scan logs for affected packages and this wave's IOCs

```bash
cd "$LOG_DIR"
run_grep() {
  local label="$1"; local pat="$2"
  hits=$(grep -lE "$pat" run-*.log 2>/dev/null)
  if [ -z "$hits" ]; then printf "  %-52s  CLEAN\n" "$label"
  else printf "  %-52s  *** %s hits ***\n" "$label" "$(echo "$hits" | wc -l | tr -d ' ')"; fi
}

run_grep "affected package names"   'keyv|cacheable|flat-cache|file-entry-cache|cache-manager|\becto\b'
run_grep "malicious versions"       'keyv@6\.0\.0|cacheable@2\.5\.1|flat-cache@6\.1\.24|file-entry-cache@11\.1\.[67]|cacheable-request@13\.0\.20|cache-manager@7\.2\.10|ecto@5\.0\.1'
run_grep "loader / payload files"   'setup\.mjs|math_init\.js|Math_Symbol\.js'
run_grep "preinstall execution"     'preinstall.*node setup\.mjs|node setup\.mjs'
run_grep "Bun download (v1.3.13)"   'oven-sh/bun/releases/download/bun-v1\.3\.13'
run_grep "C2 fallback"              'npm-cache\.com'
run_grep "Ethereum C2"              '0xE1f2395ee43e45A1556EC6438a88c31B83493103|0x53ed5143|eth-mainnet\.nodereal\.io'
run_grep "dead-drop marker"         'Shai-Hulud: Here We Go Again|thebeautifulmarchoftime|thebeautifulsnadsoftime'
run_grep "PAT-in-commit marker"     'IfYouBlockThisAPIKeyItWillCrash'
run_grep "secret serialization"     'toJSON\(secrets\)|format-results'
run_grep "runner memory scrape"     'sudo python3|Runner\.Worker'
run_grep "PID lock / env marker"    'tmp\.dpkg_14527\.lock|_NODE_RUNTIME_INIT'
```

> **Why scan IOCs, not just package names?** A frozen install of a clean tree prints package names with no compromise; a transitive pull of a malicious version may be quiet on names but show `node setup.mjs` executing or the Bun v1.3.13 download. **The execution and C2 signals are the high-fidelity ones.**

> **`npm ci` and `yarn install --immutable` print ZERO per-package output.** A broad grep for `keyv` returning nothing on a frozen-install run is expected and is *not* evidence that no install happened. Verify the resolved version from the committed lock file instead.

> **GitHub Actions log lines are tab-prefixed** (`<workflow>\t<step>\t<timestamp> <content>`). Don't anchor patterns with `^`.

### 4. Classify hits

**Real install / execution:** `added keyv@6.0.0` (npm), `+ flat-cache 6.1.24` (pnpm), yarn resolution lines; `preinstall` output invoking `node setup.mjs`; the Bun v1.3.13 download; any contact with `npm-cache.com` or the Ethereum contract.

**False positives:** source imports; SAST / dependency-review output; Dependabot branch names; docs; a Web3 project's legitimate `eth-mainnet.nodereal.io` traffic; a repo that legitimately downloads Bun (correlate with version `1.3.13` **and** `setup.mjs` before flagging).

### 5. Write `$LOG_DIR/evidence-ci-runs.csv`

```
repo,run_id,created_at,workflow,platform,install_command,ignore_scripts,npm_major,version_installed,lock_respected,iocs_found,ci_compromised
```

One row per install execution; verdict `clean` / `compromised` / `clean (component not installed)`. Record `npm_major` — npm ≥ 12 does not run `preinstall` by default and changes the verdict. No blank cells.

---

## Phase 2b: The Customer's Own Published Packages (Forward-Propagation)

If any maintainer in the org had an npm token stolen, the worm enumerated their packages and republished them with the payload. Check whether the customer shipped it forward.

> ⚠️ **`text=scope:<name>` returns zero results — do not use it.** The `scope:` qualifier is not supported by the registry search endpoint: verified 2026-08-05, `text=scope:keyv` returns `0 total / 0 objects` while the package set plainly exists. Because the next step filters client-side, a broken query yields an empty `own-packages.txt` and the phase reports "nothing published" instead of failing. Enumerate by **maintainer** (authoritative for "what this account can publish", which is exactly what the worm targets) and by **`@scope` free text**, then always run the positive control below.

```bash
export SCOPE="<your-npm-scope>"           # without the leading @
export MAINTAINERS="<npm-user-1> <npm-user-2>"   # every publisher account in the org

# 1. By maintainer — the authoritative list for forward-propagation risk
for user in $MAINTAINERS; do
  curl -s "https://registry.npmjs.org/-/v1/search?text=maintainer:${user}&size=250" | \
    python3 -c "
import sys, json
d = json.load(sys.stdin)
print('\n'.join(o['package']['name'] for o in d.get('objects', [])))"
done > "$LOG_DIR/own-packages.txt"

# 2. By scope as free text (NOT scope:), paginated, filtered client-side —
#    a query for '@acme' also returns unrelated fuzzy matches, so the prefix filter is required
for from in 0 250 500; do
  curl -s "https://registry.npmjs.org/-/v1/search?text=@${SCOPE}&size=250&from=${from}" | \
    python3 -c "
import sys, json, os
d = json.load(sys.stdin)
pfx = '@' + os.environ['SCOPE'] + '/'
print('\n'.join(o['package']['name'] for o in d.get('objects', [])
                if o['package']['name'].startswith(pfx)))"
done >> "$LOG_DIR/own-packages.txt"

sort -u "$LOG_DIR/own-packages.txt" -o "$LOG_DIR/own-packages.txt"
echo "enumerated $(wc -l < "$LOG_DIR/own-packages.txt") packages"

# 3. POSITIVE CONTROL — prove the endpoint works before trusting an empty result.
#    'maintainer:jaredwray' returned 54 total on 2026-08-05. A zero here means the
#    query mechanism is broken, NOT that the org publishes nothing.
curl -s "https://registry.npmjs.org/-/v1/search?text=maintainer:jaredwray&size=5" | \
  python3 -c "
import sys, json
n = json.load(sys.stdin).get('total', 0)
print(f'positive control: {n} results —', 'endpoint OK' if n else 'BROKEN, fix before trusting an empty own-packages.txt')"

while read pkg; do
  curl -s "https://registry.npmjs.org/${pkg}" | python3 -c "
import sys, json, os
d = json.load(sys.stdin); t = d.get('time', {})
since, until = os.environ['SINCE'], os.environ['UNTIL']
for v, ts in t.items():
    if v in ('created','modified'): continue
    if since <= ts <= until: print(f\"${pkg}@{v}\t{ts}\")" 2>/dev/null
done < "$LOG_DIR/own-packages.txt" > "$LOG_DIR/own-published-in-window.tsv"
```

For each candidate, pull the tarball and check for the payload fingerprint:

```bash
mkdir -p "$LOG_DIR/tarballs/check" && cd "$LOG_DIR/tarballs/check"
npm pack "${pkg}@${version}" 2>/dev/null && tar xzf *.tgz
python3 -c "import json; d=json.load(open('package/package.json')); print('scripts:', d.get('scripts'))"
ls -la package/setup.mjs package/math_init.js 2>/dev/null
shasum -a 256 package/setup.mjs package/math_init.js 2>/dev/null
```

**A `scripts` object reduced to a single `preinstall: node setup.mjs`** (the worm *replaces* the whole object — a package that previously had `build`/`test` scripts and now has only `preinstall` is conclusive), or the presence of `math_init.js`, means the worm republished it.

**Response:** `npm deprecate '<pkg>@<version>' 'Compromised (Shai-Hulud, Aug 2026) — do not install.'`, publish a clean superseding version from a known-clean host, notify downstream consumers, and rotate the publisher's npm + GitHub tokens (Phase 6).

---

## Phase 2c: GitHub Actions Secret Harvesting (GitHub-specific)

The worm deletes the workflow and branch after stealing secrets, so **the code may be gone while the audit log and artifact history survive**. This phase is the only way to detect that path.

```bash
# 1. The injected branch (may already be deleted — check anyway)
gh repo list "$ORG" --no-archived --limit 1000 --json nameWithOwner --jq '.[].nameWithOwner' | \
while read repo; do
  gh api "repos/${repo}/branches?per_page=100" --jq '.[].name' 2>/dev/null | \
    grep -x "dependabot/github_actions/format/setup-formatter" >/dev/null && echo "*** BRANCH: $repo"
done

# 2. Workflow runs with the impersonated display names
gh repo list "$ORG" --no-archived --limit 1000 --json nameWithOwner --jq '.[].nameWithOwner' | \
while read repo; do
  gh api "repos/${repo}/actions/runs?created=${SINCE}..${UNTIL}&per_page=100" \
    --jq ".workflow_runs[] | select(.name | test(\"Run Copilot|Add CodeQL Analysis\")) | \"${repo} | \(.id) | \(.name) | \(.created_at) | \(.head_branch)\"" 2>/dev/null
done | tee "$LOG_DIR/suspect-workflow-runs.txt"

# 3. Artifacts named format-results (the exfil container)
gh repo list "$ORG" --no-archived --limit 1000 --json nameWithOwner --jq '.[].nameWithOwner' | \
while read repo; do
  gh api "repos/${repo}/actions/artifacts?per_page=100" \
    --jq ".artifacts[] | select(.name | test(\"format-results\")) | \"${repo} | \(.name) | \(.created_at) | expired=\(.expired)\"" 2>/dev/null
done | tee "$LOG_DIR/suspect-artifacts.txt"

# 4. Any workflow that serializes the whole secrets context — on ANY branch
gh api "search/code?q=%22toJSON(secrets)%22+org:${ORG}&per_page=100" \
  --jq '.items[] | "\(.repository.full_name) :: \(.path)"' 2>/dev/null
```

Then check the **org audit log** (Settings → Archives, or `gh api /orgs/${ORG}/audit-log`) for `workflows.created_workflow_run`, branch-creation, and branch-deletion events clustered within minutes of each other in the window. Rapid create-then-delete of a `codeql_analysis.yml` is the signature.

> **If any hit lands here, treat every Actions secret in that repository as compromised** — including secrets that never appeared in a log, because `toJSON(secrets)` serializes them all at once.

---

## Phase 3: Network Investigation

| Signal | Where to search |
|---|---|
| DNS / outbound to `npm-cache[.]com` (443, path `/router`) | DNS logs, proxy, NetFlow, VPC Flow Logs |
| Outbound to `eth-mainnet.nodereal[.]io` **from a host with no blockchain workload** | DNS / proxy — see false-positive note |
| Bun v1.3.13 download from a CI runner that doesn't use Bun | proxy / egress logs |
| GitHub API **public repo creation** from a runner or dev host | GitHub audit log, proxy |
| npm registry `PUT` (publish) from an unexpected host | proxy logs, npm audit trail |
| AWS IMDS access (`169.254.169.254`, `169.254.170.2`) from a build step | VPC Flow Logs, host telemetry |

**Where:** AWS VPC Flow Logs + Route 53 Resolver logs + CloudTrail; GCP/Azure equivalents; on-prem firewall/proxy/DNS; SIEM.
**Time window:** August 3 forward, **and ongoing** — stolen tokens are abused well after the install, and the campaign is still active.

**Splunk example:**
```
index=dns query="npm-cache.com" OR query="*.npm-cache.com"
| stats count by src_ip, query, answer
```

---

## Phase 4: Workstation & Runner Investigation

Machines that ran installs during the window — **or that merely opened an infected repo in VS Code or Claude Code** — may have executed the payload. See `workstation-playbook.md` for the full per-machine procedure. The org-side essentials:

### 4a. Payload files and hijacked `preinstall` hooks in `node_modules`

```bash
for root in ~/projects ~/code ~/repos ~/work "$HOME"; do
  [ -d "$root" ] || continue
  find "$root" -path '*/node_modules/*' \( -name 'math_init.js' -o -name 'Math_Symbol.js' -o -name 'setup.mjs' \) 2>/dev/null
  find "$root" -path '*/node_modules/*/package.json' 2>/dev/null | \
    xargs grep -lE '"preinstall"[[:space:]]*:[[:space:]]*"node setup\.mjs"' 2>/dev/null
done
```

### 4b. Lock files pinning a malicious version

```bash
find ~ \( -name 'package-lock.json' -o -name 'pnpm-lock.yaml' -o -name 'yarn.lock' \) \
  -not -path '*/node_modules/*' 2>/dev/null | \
  xargs grep -lE 'keyv.*6\.0\.0|cacheable.*2\.5\.1|flat-cache.*6\.1\.24|file-entry-cache.*11\.1\.[67]|cacheable-request.*13\.0\.20|cache-manager.*7\.2\.10' 2>/dev/null \
  > "$LOG_DIR/workstation-lockfiles-malicious.txt"
```

### 4c. Editor / agent backdoors (survive package removal)

```bash
find ~ -maxdepth 6 \( -path '*/.vscode/tasks.json' -o -path '*/.claude/settings.json' \
     -o -path '*/.claude/setup.mjs' -o -path '*/.vscode/setup.mjs' -o -path '*/.claude/math_init.js' \) 2>/dev/null | \
while read f; do
  echo "=== $f (modified $(stat -f '%Sm' "$f" 2>/dev/null || stat -c '%y' "$f" 2>/dev/null))"
  grep -lE 'setup\.mjs|math_init|SessionStart|Environment Setup' "$f" 2>/dev/null && echo "  *** SUSPICIOUS ***"
done
```

Pay particular attention to files modified on or after **2026-08-04**, and to any `.claude/settings.json` containing a `SessionStart` hook that shells out to `node`.

### 4d. Runner / host artifacts

```bash
ls -la /tmp/tmp.dpkg_14527.lock 2>/dev/null && echo "*** PID LOCK PRESENT ***"
env | grep -i "_NODE_RUNTIME_INIT" && echo "*** ENV MARKER PRESENT ***"
grep -riE "_NODE_RUNTIME_INIT|setup\.mjs|math_init" ~/.bash_history ~/.zsh_history 2>/dev/null
# Dormant persistence — confirm before reporting as active
ls -la ~/Library/LaunchAgents/ 2>/dev/null | grep -i "gh-token-monitor"
systemctl --user list-units 2>/dev/null | grep -i "gh-token-monitor"
```

### 4e. Package-manager cache and npm debug logs

```bash
grep -rl "math_init\|setup.mjs" ~/.npm/_cacache/content-v2 2>/dev/null | head
npm cache ls 2>/dev/null | grep -iE "keyv|cacheable|flat-cache|file-entry-cache|cache-manager"
grep -liE "keyv@6\.0\.0|flat-cache@6\.1\.24|setup\.mjs|math_init" ~/.npm/_logs/*.log 2>/dev/null
```

### 4f. AI-agent conversation logs (exclude the investigating agent's own session)

> If you are running this playbook through an AI coding agent, its transcript **will** contain these IOC strings — because you have been reading them. That is evidence of investigation, not compromise. Exclude the current session.

```bash
CURRENT_SESSION_PROJECT=$(echo "$PWD" | sed 's|/|-|g')
grep -rliE "math_init|Math_Symbol|npm-cache\.com|0xE1f2395ee43e45A1556EC6438a88c31B83493103|Shai-Hulud: Here We Go Again|thebeautifulmarchoftime" \
  "$HOME/.claude/projects" \
  "$HOME/Library/Application Support/Cursor" \
  "$HOME/Library/Application Support/Windsurf" \
  "$HOME/.config/github-copilot" 2>/dev/null | \
  grep -v "${CURRENT_SESSION_PROJECT}" | grep -v "paste-cache" | grep -v "file-history"
```

Hits surviving that filter — especially `.jsonl` files from prior, unrelated sessions — are real signal.

### 4g. Dead-drop repos under your own org and users

```bash
# Public repos created in the window
gh api --paginate "/orgs/${ORG}/repos?per_page=100&sort=created&direction=desc" \
  --jq ".[] | select(.created_at > \"${SINCE}\") | select(.visibility==\"public\") | \"\(.name) | \(.created_at)\""

# Repos matching the dead-drop description or Dune naming
gh api --paginate "/orgs/${ORG}/repos?per_page=100" \
  --jq '.[] | select((.description // "") | test("Shai-Hulud")) or (.name | test("^(sardaukar|fremen|atreides|sandworm|melange)$")) | "\(.name) | \(.description)"'
```

Also search GitHub globally for the PAT-leak marker in case an org member's token was published from a personal account:

```bash
gh api "search/commits?q=IfYouBlockThisAPIKeyItWillCrash+author-name:<member>" \
  --jq '.items[] | "\(.repository.full_name) | \(.sha[0:8])"' 2>/dev/null
```

---

## Phase 5: Present Results

1. **Repo Analysis table** (`evidence-repos.csv`) — posture per repo, window-agnostic.
2. **CI Runs table** (`evidence-ci-runs.csv`) — installs in the window, IOCs, verdict.
3. **Infected-branch table** (`infected-branches.txt`, `suspect-commits.txt`) — repo-infection path.
4. **Actions secret-harvesting table** (`suspect-workflow-runs.txt`, `suspect-artifacts.txt`) — Phase 2c.
5. **Own-published packages table** — forward propagation, verdict per version.
6. **Executive Summary** — verdict (`clean` / `compromised`); scope; repo posture (lock coverage, `--ignore-scripts`, npm major version, ESLint transitive reach); CI findings; Actions-secret exposure; network findings; workstation/agent backdoors; dead-drop repos; forward propagation; one-sentence bottom line.

**Action needed** if any of: `can_be_compromised=yes`, any `ci_compromised=compromised`, any infected branch, any Phase 2c hit, workstation backdoors, or dead-drop repos.
**Vulnerable but not hit** (`can_be_compromised=yes`, no runs in window) → Phase 6 hardening.

---

## Phase 6: Hardening & Remediation (User Approval Required)

**Do NOT proceed without explicit user approval.** Present findings first.

### Remediation — only if compromised

**Order matters: preserve evidence, then rotate, then scrub.** Rotating before scrubbing prevents the operator from reusing a credential you were about to delete evidence of.

1. **Preserve first** — snapshot CI artifacts, GitHub audit logs (they age out), runner images, `.vscode/tasks.json`, `.claude/settings.json`, `~/.npmrc`, and shell history *before* cleanup. Actions artifacts expire; pull `format-results` immediately if present.
2. **Quarantine** affected workstations; drain and **terminate** affected CI runners — ephemeral runners should be destroyed, not reused, given the `eval()`-based RCE.
3. **Revoke npm tokens first**, prioritizing any with **`bypass_2fa`** enabled — these are what drive republication. Then GitHub PATs, OAuth tokens, App installation tokens, and deploy keys.
4. **Rotate every secret reachable from an affected host or workflow**: `secrets.*` values in any repo flagged in Phase 2c (all of them — `toJSON(secrets)` takes the whole context), OIDC-issued cloud credentials, AWS/Azure/GCP/Alibaba/Tencent/Hetzner keys, Kubernetes service-account tokens and kubeconfigs, HashiCorp Vault tokens, SSH keys, database connection strings, Stripe and Slack tokens, **AI-service API keys** (OpenAI, Anthropic, Gemini, Cursor), and any crypto wallet material.
5. **Remove the repo infection on every branch** — delete `.claude/math_init.js`, `.claude/setup.mjs`, `.vscode/setup.mjs`, and the malicious entries in `.claude/settings.json` / `.vscode/tasks.json`. *Removing the npm package does not touch these.* Force-push cleanup or revert commits across all affected branches, then verify with the Phase 1 step 5 scan.
6. **Delete the injected workflow and branch** if still present, and audit what ran from them.
7. **Purge caches and trees**: `npm cache clean --force`; `pnpm store prune`; `yarn cache clean`; `rm -rf node_modules`.
8. **Rebuild container images with `--no-cache`** — a malicious version baked into a layer survives everything above.
9. **Block C2** — `npm-cache[.]com` at the network edge; alert on the Ethereum contract address in egress if you have the visibility.
10. **Audit and delete dead-drop repos** under org and personal accounts; revoke the tokens that created them.
11. **Do not trust npm provenance for this wave** — the OIDC trusted-publisher path produces genuine Sigstore/Rekor attestations on malicious artifacts. Verify against maintainer-confirmed safe versions, not attestation.

### Hardening — wherever `can_be_compromised` = yes

| Surface | Fix |
|---|---|
| No lock file | Commit `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` |
| Non-frozen install | Switch to `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --immutable` |
| Install scripts enabled in CI | Add `--ignore-scripts`; run a separate vetted build step for packages that genuinely need lifecycle scripts |
| npm ≤ 11 in CI | Upgrade to **npm 12+**, where `preinstall` does not run by default — defense in depth, not a substitute for the above |
| Floating `^`/`~` ranges on affected packages | Pin exact pre-incident versions; regenerate the lock on a clean host |
| Long-lived npm tokens, `bypass_2fa` enabled | Disable `bypass_2fa`; move to short-lived OIDC trusted publishing **scoped narrowly** — and note this wave abused over-broad trusted publishing, so scope it per-package |
| GitHub tokens with `workflow` scope | Remove `workflow` scope wherever not strictly required — it is the prerequisite for the Phase 2c secret theft |
| Unrestricted CI egress | Allow-list build egress; block `npm-cache.com`; alert on public-repo creation and npm `PUT` from runners |
| No branch protection | Require PR review on all branches; the worm writes directly to up to 50 branches |
| Agent/editor configs unreviewed | Treat `.claude/settings.json` and `.vscode/tasks.json` as security-relevant — add CODEOWNERS review and alert on changes |
| No dependency review | Enable `actions/dependency-review-action`; alert on any newly added `preinstall` hook |

### Upgrade path

Every malicious version has been unpublished, so a fresh resolve cannot reach one — but **existing lock files, caches, and images still can**. Pin each package to the verified safe version in the Affected packages table, regenerate the lock on a clean host, and commit it. There is no "patched" release to move forward to; the safe version is the one immediately preceding the malicious bump.

---

## Pitfalls & Fixes

Read before kicking off.

1. **Do not reuse the AntV or TanStack IOC strings.** Same campaign family, entirely different indicators. `t.m-kosche.com` and `bun run index.js` will return zero hits here and produce a false "clean."
2. **`npm ci` / `yarn install --immutable` print no per-package output.** Zero package-name hits on a frozen-install run is expected, not exculpatory. Read the lock file.
3. **The default branch is not enough.** The repo-infection path writes to up to 50 branches. A clean `main` says nothing about the other 49.
4. **Phase 2c evidence self-deletes.** The worm removes the workflow and branch after exfiltration. Check the **audit log and artifact list**, not just current repo contents — and pull artifacts before they expire.
5. **`eth-mainnet.nodereal.io` is a legitimate public RPC endpoint.** Only an IOC when correlated with the contract address/selector, or on a host with no blockchain workload.
6. **`.claude/settings.json` and `.vscode/tasks.json` are normal files.** Match on the `node …/setup.mjs` invocation or the file hashes, not on file existence.
7. **npm 12+ changes the verdict for the install path only.** `preinstall` not firing does not protect a developer who opened an infected repo in VS Code.
8. **Bash associative arrays (`declare -A`) fail under zsh** with `bad substitution`. Use the `run_grep` helper function pattern in Phase 2 step 3.
9. **Inline `python3 -c "…"` is escape hell** with nested quotes and f-strings. Use `python3 <<'PY'` heredocs (as in Phase 1 step 3).
10. **`npm search text=scope:foo` is fuzzy**, returning thousands of unrelated packages. Filter client-side on the literal `@scope/` prefix (Phase 2b does this).
11. **`curl -sf` swallows 404s into empty stdout**, then `json.load` crashes. Check the status code separately or wrap in try/except.
12. **Gate code-search on `total_count` first** — 1 API unit versus a full page fetch. Matters on orgs with many repos.
13. **AI-agent self-pollution.** Phase 4f always hits when run through an AI coding agent, because the agent has been reading these IOCs all session. Exclude the current session dir, `paste-cache`, and `file-history` before treating a hit as real.
14. **A green CI run proves nothing.** The payload swallows exceptions and exits 0.

---

## References

- JFrog Security Research — "Major Shai Hulud campaign strikes npm again, affecting keyv and 400+ packages" — https://research.jfrog.com/post/shai-hulud-is-back-august/
- Socket.dev — "Popular npm packages in the keyv and cacheable namespaces compromised" — https://socket.dev/blog/popular-npm-packages-in-the-keyv-and-cacheable-namespaces-compromised-in-active-supply-chain
- StepSecurity — Shai-Hulud "Here We Go Again" campaign tracking — https://www.stepsecurity.io/blog/shai-hulud-here-we-go-again-mass-npm-supply-chain-attack-hits-the-antv-ecosystem
- Earlier waves in this campaign family — `antv_supply_chain/playbook.md` (May 19, 2026), `tanstack_supply_chain/playbook.md` (May 11, 2026), `sap_supply_chain/playbook.md` (April 29, 2026)
- OSSF malicious-packages database — https://github.com/ossf/malicious-packages
