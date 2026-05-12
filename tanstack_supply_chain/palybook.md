# May 2026 npm Supply Chain Compromise Wave (TeamPCP) — Investigation Playbook

Playbook for investigating whether a GitHub org was affected by the **May 2026 npm worm wave** attributed to the threat group **TeamPCP**. The wave started with `@tanstack/*` on May 11 19:20 UTC and self-propagated to **at least 19 additional npm scopes** within 48 hours — **373 malicious package-versions across 169 distinct package names** by May 12.

> **CI/CD platform note:** This playbook targets GitHub Actions. For other CI/CD platforms (GitLab CI, Jenkins, CircleCI, Bitbucket, Azure DevOps), adapt the log-collection commands — the investigation logic is the same: identify references to **any compromised scope**, collect run logs from the exposure window, search for compromised versions and IOCs, and verify lock-file protection.

> **Threat-actor history.** TeamPCP is the same group responsible for the **Trivy ecosystem compromise (March 2026)** and the **Bitwarden CLI npm compromise (April 2026)**. If a customer was investigated for either of those, the same detection workflow applies here with updated package names and IOCs.

---

## Incident Details

The initial vector compromised `TanStack/router`: on **May 11, 2026, between 19:20 and 19:26 UTC**, an attacker published **84 malicious versions across 42 `@tanstack/*` npm packages**. From there the worm self-propagated to other maintainers' packages. The compromise did not start by stealing npm credentials — instead:

1. The attacker opened a PR from a fork against `TanStack/router`, triggering a `pull_request_target` workflow that executed the fork's code with elevated trust.
2. The malicious workflow **poisoned the GitHub Actions cache** with a tainted `pnpm` store across the fork↔base trust boundary.
3. When legitimate maintainer PRs were later merged to `main`, the release workflow restored the poisoned cache. An attacker-controlled binary then **dumped the GitHub Actions runner's process memory (`/proc/<pid>/mem`) to extract a valid OIDC token**.
4. That OIDC token was used to publish 84 malicious tarballs through the project's own release pipeline — producing the **first documented case of a malicious npm package carrying valid SLSA Build Level 3 provenance**.

> **Critical:** SLSA provenance attestation is **not a safety signal here**. The malicious tarballs are validly attested.

> **Tarballs deprecated, not unpublished.** npm's "no unpublish if dependents exist" policy blocked unpublishing for almost all packages. npm security has had to pull tarballs server-side. Until that completes, malicious versions remain **installable from npm caches, lock files, and mirrors**.

### CVE / advisory

- **CVE:** CVE-2026-45321 (CVSS 9.6 — Critical)
- **GitHub advisory:** GHSA-g7cv-rxg3-hmpx (canonical version list)
- **Tracking issue:** https://github.com/TanStack/router/issues/7383
- **Vendor postmortem:** https://tanstack.com/blog/npm-supply-chain-compromise-postmortem

### Affected packages

**Total wave: ~373 malicious package-versions across ~169 distinct package names spanning 19+ npm scopes.** This is not a `@tanstack/*`-only investigation — your detection must cover every scope below.

Use this scope list as the **detection-time source of truth**. Refer to the [Mend writeup](https://www.mend.io/blog/mini-shai-hulud-is-back-172-npm-and-pypi-packages-compromised-in-latest-wave/), the [package-list aggregator](https://thecybersecguru.com/news/mini-shai-hulud-npm-worm-affected-packages-list/), and GitHub advisory **GHSA-g7cv-rxg3-hmpx** for the canonical per-version inventory.

```bash
export AFFECTED_SCOPES='@tanstack @mistralai @uipath @squawk @tallyui @draftauth @draftlab @ml-toolkit-ts @supersurkhet @cap-js @dirigible-ai @mesadev @beproduct @opensearch-project @taskflow-corp @tolka'
export AFFECTED_UNSCOPED='agentwork-cli cmux-agent-mcp cross-stitch git-branch-selector git-git-git intercom-client ml-toolkit-ts mbt nextmove-mcp safe-action ts-dna wot-api'
```

#### Direct-compromise inventory (representative malicious versions per scope)

| Scope | Notable compromised packages → malicious versions |
|---|---|
| `@tanstack` (42 pkgs) | `react-router`, `router-core`, `vue-router`, `solid-router` → **1.169.5, 1.169.8**; `history`, `eslint-plugin-router`, `start-fn-stubs` → **1.161.9, 1.161.12**; `react-router-devtools`, `router-devtools`, `solid-router-devtools`, `vue-router-devtools` → **1.166.16, 1.166.19**; `react-start` → **1.167.68, 1.167.71**; full list spans 1.154.x – 1.169.x |
| `@mistralai` | `mistralai` → **2.2.2, 2.2.3, 2.2.4**; `mistralai-azure`, `mistralai-gcp` → **1.7.1, 1.7.2, 1.7.3** |
| `@uipath` (60+ pkgs) | `cli`, `auth`, `common`, `robot`, `agent-sdk`, `apollo-core`, `apollo-react`, dozens of `*-tool` packages → mostly **1.0.1, 1.0.2** or **0.x** single-version bumps |
| `@squawk` (22 pkgs, aviation-data) | `airports`, `airspace`, `airways`, `flightplan`, `geo`, `weather`, `mcp`, `notams`, `procedures`, `types`, `units` → 5 consecutive malicious versions each (e.g. **0.4.2 – 0.4.6**) |
| `@tallyui` (10 pkgs) | `core`, `components`, `database`, `pos`, `theme`, multiple `connector-*` → **1.0.1, 1.0.2, 1.0.3** (or 0.x equivalent) |
| `@draftauth` | `core` → **0.13.1, 0.13.2**; `client` → **0.2.1, 0.2.2** |
| `@draftlab` | `auth` → **0.24.1, 0.24.2**; `auth-router` → **0.5.1, 0.5.2**; `db` → **0.16.1, 0.16.2** |
| `@opensearch-project` | `opensearch` → **3.5.3, 3.6.2, 3.7.0, 3.8.0** (1.3M weekly downloads — high blast-radius) |
| `@cap-js` | `db-service` → **2.10.1**; `postgres`, `sqlite` → **2.2.2** |
| `@dirigible-ai` | `sdk` → **0.6.2, 0.6.3** |
| `@mesadev` | `rest`, `sdk` → **0.28.3**; `saguaro` → **0.4.22** |
| `@ml-toolkit-ts` | `preprocessing` → **1.0.2, 1.0.3**; `xgboost` → **1.0.3, 1.0.4** |
| `@supersurkhet` | `cli`, `sdk` → **0.0.2 – 0.0.7** |
| `@beproduct` | `nestjs-auth` → **0.1.2 – 0.1.19** (18 consecutive malicious versions) |
| `@taskflow-corp` | `cli` → **0.1.24 – 0.1.29** |
| `@tolka` | `cli` → **1.0.2 – 1.0.6** |
| Unscoped | `intercom-client@7.0.4`, `cross-stitch@1.1.3–1.1.7`, `ts-dna@3.0.1–3.0.5`, `wot-api@0.8.1–0.8.4`, `git-branch-selector@1.3.3–1.3.7`, `git-git-git@1.0.8–1.0.12`, `nextmove-mcp@0.1.3–0.1.7`, `cmux-agent-mcp@0.1.3–0.1.8`, `agentwork-cli@0.1.4–0.1.5`, `ml-toolkit-ts@1.0.4–1.0.5`, `mbt@1.2.48`, `safe-action@0.8.3–0.8.4` |

**High-blast-radius packages** to prioritize when scanning a customer's posture:
- `@tanstack/react-router` (~12.7M weekly downloads)
- `@opensearch-project/opensearch` (~1.3M weekly downloads)
- `@mistralai/mistralai` (in OSSF malicious packages DB as MAL-2026-3432)
- `@uipath/*` (broad enterprise automation surface)
- `intercom-client` (any customer using Intercom)

**Confirmed-clean `@tanstack` families:** `@tanstack/query*`, `@tanstack/table*`, `@tanstack/form*`, `@tanstack/virtual*`, `@tanstack/store`, `@tanstack/start` (meta-package only).

> **Crypto / Web3 callout.** The payload targets credentials in environments that handle private keys, seed phrases, `wallet.dat`, and signing keys. If the customer has Web3 / DeFi / blockchain code touching any of the scopes above, raise the priority on workstation forensics (Phase 4) and wallet-credential rotation.

### Exposure window

| Event | Time (UTC) |
|---|---|
| First malicious `@tanstack/*` version published | May 11, 19:20 |
| Last malicious `@tanstack/*` version published | May 11, 19:26 |
| Public detection (StepSecurity / ashishkurmi) | May 11, ~19:40 |
| Deprecation begins | May 11, ~20:00 |
| npm-security tarball pull (server-side) | May 11, in progress |

**Recommended scan window (padded):** `2026-05-11T19:00:00Z` to `2026-05-12T03:00:00Z` — pad forward to catch installs that resolved a malicious version before deprecation propagated.

### Indicators of compromise

| IOC | Value | Where it shows up |
|---|---|---|
| Manifest fingerprint | `"@tanstack/setup": "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"` in `optionalDependencies` | `node_modules/@tanstack/*/package.json` |
| Payload file | `router_init.js` (~2.3 MB) | `node_modules/@tanstack/<pkg>/` |
| Payload file SHA-256 | `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c` | (hash of `router_init.js`) |
| Payload file | `tanstack_runner.js` | `node_modules/@tanstack/<pkg>/` |
| Payload file SHA-256 | `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96` | (hash of `tanstack_runner.js`) |
| Agent-config tampering | `.claude/settings.json`, `.claude/setup.mjs`, `.vscode/tasks.json` modified | repo working trees |
| Persistence (macOS) | `~/Library/LaunchAgents/com.user.gh-token-monitor.plist` | workstation |
| Persistence (Linux) | `~/.config/systemd/user/gh-token-monitor.service` | workstation |
| Daemon behavior | Polls GitHub every 60s; on 4xx (revoked token) attempts `rm -rf ~/`; self-exits after 24h | workstation |
| Process pattern | `bun run tanstack_runner.js`, `sudo python3` reading `/proc/*/mem` | CI logs, workstation |
| C2 domain (typosquat) | `git-tanstack.com` | network logs |
| C2 domain | `api.masscan.cloud` | network logs |
| Decentralized exfil | `filev2.getsession.org`, `seed1.getsession.org`, `seed2.getsession.org`, `seed3.getsession.org` | network logs |
| Stage-2 payload host | `litter.catbox.moe/h8nc9u.js`, `litter.catbox.moe/7rrc6l.mjs` | CI logs, network |
| Poisoned pnpm cache key | `Linux-pnpm-store-6f9233a50def742c09fde54f56553d6b449a535adf87d4083690539f49ae4da11` | GH Actions cache audit |
| Attacker GitHub accounts | `voicproducoes` (id 269549300), `zblgg` (id 127806521) | PRs, commits |
| Attacker fork repo | `github.com/zblgg/configuration` (may be renamed) | PR sources |
| Forged commit author | `claude <claude@users.noreply.github.com>` (in repos that aren't yours) | git log |
| Worm propagation branch pattern | `dependabot/github_actions/format/<random-word>` (fake Dependabot) | branch list |
| Worm propagation commit msg | `"chore: update dependencies"` paired with workflow changes you didn't approve | commit log |
| Reference compromised runs | `github.com/TanStack/router/actions/runs/25613093674`, `.../25691781302` | (TanStack's own runs — for pattern matching) |

### What IS affected

- Any `npm install` / `pnpm install` / `yarn install` that resolved an affected `@tanstack/*` version during the window — direct or **transitive**.
- CI workflows that ran package installs during the window. The malicious tarball's `optionalDependencies` chain pulls `@tanstack/setup` (the payload).
- Docker image builds that ran `npm/pnpm/yarn install` during the window.
- Developer machines that installed or updated `@tanstack/*` during the window — especially any host that ran `bun` afterward (the payload uses `bun run`).
- Any environment where the **`gh-token-monitor` daemon** is present — persistence survives package cleanup.
- Your **own** npm-published packages, if a maintainer's machine was hit — the worm queries the registry for packages the victim publishes and attempts to republish them with the payload (lateral/self-propagation).

### What is NOT affected

- Installs from a committed lock file with `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --frozen-lockfile` **as long as the lock file pins a non-malicious version**.
- Installs of `@tanstack/query*`, `@tanstack/table*`, `@tanstack/form*`, `@tanstack/virtual*`, `@tanstack/store`, or the `@tanstack/start` meta-package alone (these families were not compromised).
- Pre-built Docker images that were **not rebuilt during the window**.
- Source-code-only references (TypeScript imports without `npm install` having run during the window).
- Helm charts, Terraform, or other infra references that name `@tanstack/*` without actually installing it.

### Lock file protection

Lock files (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`) **do protect against this attack** if used correctly:

- `npm ci`, `pnpm install --frozen-lockfile`, `yarn install --frozen-lockfile` install exactly what the lock file says.
- If the lock file was generated **before May 11 19:20 UTC** and pins a pre-compromise version, the malicious tarball is never resolved.

Lock files do **NOT** protect if:
- No lock file is committed.
- CI runs `npm install` / `pnpm install` (no frozen flag) — these can update the lock file.
- The lock file was regenerated **during** the window.
- A `dependabot`/`renovate` PR merged during the window bumped `@tanstack/*` to a malicious version inside the lock file.
- A floating range (`^1.169.x`, `latest`) lets `npm install <other-pkg>` resolve `@tanstack/*` fresh.

---

## Pitfalls & Fixes (from running this playbook live against a 279-repo org)

These tripped us up during a real run. Read them before kicking off so you don't burn rate-limit budget or chase ghost hits.

1. **Don't run scope-iterating loops via backgrounded `eval`.** Bash parameter expansion like `${scope//@/%40}` silently fails when the loop body is eval'd in a backgrounded shell context — the inner var lookups resolve to empty and you end up issuing one giant malformed query with all scopes concatenated. **Fix:** keep code-search loops in the foreground, or write them to a `.sh` file and execute the file (not eval). Phase 2's log-download loop is fine to background because it doesn't rely on per-iteration param expansion.

2. **`pkill -f` against malformed gh-api query strings often misses.** If a hung process's command line contains URL-encoded special chars or spaces, the pattern match fails silently. **Fix:** find the PID via `ps aux | grep ...` and `kill -9 <PID>` directly.

3. **Bash associative arrays (`declare -A patterns=(...)`) don't work under zsh.** You'll get `bad substitution` at the lookup line. **Fix:** use a helper function with positional args, or parallel arrays. Sample helper:
   ```bash
   run_grep() {
     local label="$1"; local pat="$2"
     hits=$(grep -lE "$pat" run-*.log 2>/dev/null)
     if [ -z "$hits" ]; then printf "  %-55s  CLEAN\n" "$label"
     else printf "  %-55s  *** %s hits ***\n" "$label" "$(echo "$hits" | wc -l | tr -d ' ')"; fi
   }
   run_grep "label here" "regex here"
   ```

4. **Inline Python via `python3 -c "..."` is escape hell.** Especially with nested f-strings and dict access. **Fix:** use heredocs:
   ```bash
   python3 <<'PY'
   import sys, json
   ...
   PY
   ```

5. **`yarn install --immutable` (and `npm ci`) produces ZERO per-package output in CI logs.** A broad grep for `@tanstack/` will return 0 hits even on a run that installed dozens of `@tanstack` packages — because immutable mode is silent when the lockfile is satisfied. **Don't conclude "no install happened" from "no package names in logs."** The real signal is the **install command line itself** + the lockfile state in the repo. Verify the resolved version from the committed lockfile, not from per-package log output.

6. **`npm search text=scope:foo` is fuzzy, not strict.** A query for `scope:acme-labs` can return 13,000+ unrelated hits. **Fix:** fetch the result and filter client-side by literal `@<scope>/` name prefix:
   ```python
   real = [p for p in d["objects"] if p["package"]["name"].startswith(f"@{scope}/")]
   ```

7. **Gate code-search queries on `total_count` first.** Run `?per_page=1 --jq .total_count` (1 API unit, returns just the integer), then only pull `?per_page=100 .items[]` if `total > 0`. Halves your rate-limit consumption on orgs where most scopes return zero.

8. **GitHub Actions log lines are tab-prefixed: `<workflow>\t<step>\t<timestamp> <content>`.** Don't anchor grep patterns with `^` — your IOC will be mid-line. Use unanchored or `\b` patterns.

9. **`gh search code` returns max 100 items per page and doesn't paginate cleanly past 1000 results** for org-scoped queries. For repos with thousands of file matches, **shallow-clone the org and grep locally** (recommended threshold: orgs over ~50 repos). See the alternative recipe in Phase 1.

10. **Naive `org/repo` join can produce doubled prefixes.** `gh api`'s `.repository.full_name` already returns `org/repo`. If your script prepends `${ORG}/` you end up with `acme-org/acme-org/some-service`. Pick one side and stick to it.

11. **`curl -sf` swallows 404s into empty stdout.** Downstream `json.load(sys.stdin)` then crashes on empty input. **Fix:** check HTTP status separately with `curl -s -o /dev/null -w '%{http_code}'`, or wrap json.load in try/except.

12. **`yarn install --immutable` (and similar lock-strict commands) plus a non-router `@tanstack/*` dep tree means you can finish the investigation in ~5 minutes** — the bad versions can't resolve and no malicious tarball touches disk. Don't over-investigate when both layers of defense are in place; bank the time for hardening or workstation sweeps.

13. **AI-agent self-pollution: exclude the investigating agent's own session log from the IOC search.** Phase 4i (AI agent conversation logs) will *always* hit if the investigator is running the playbook through an AI coding agent (Claude Code, Cursor, Windsurf, Copilot CLI) — because the agent has been reading, writing, and discussing IOC strings throughout the session. The agent's own transcript/paste-cache/file-history are not evidence of compromise; they're evidence of investigation. **Fix:** when running Phase 4i, exclude the current session's data dir. For Claude Code specifically, exclude `~/.claude/projects/<current-workdir-slug>/*.jsonl`, `~/.claude/paste-cache/`, and `~/.claude/file-history/<current-session-uuid>/`. A safer grep:
   ```bash
   # Find AI-agent logs but exclude the current Claude Code session
   CURRENT_SESSION_PROJECT=$(echo "$PWD" | sed 's|/|-|g')
   grep -rliE "tanstack_runner|router_init|gh-token-monitor|git-tanstack\.com|getsession\.org|masscan\.cloud|catbox\.moe" \
     "$HOME/.claude/projects" \
     "$HOME/Library/Application Support/Cursor" \
     "$HOME/Library/Application Support/Windsurf" \
     "$HOME/.config/github-copilot" 2>/dev/null | \
     grep -v "${CURRENT_SESSION_PROJECT}" | grep -v "paste-cache" | grep -v "file-history"
   ```
If hits remain after that filter, **then** they're suspicious — review each: a `.jsonl` from a prior unrelated session that contains IOC strings is a real signal.

---

## Setup

```bash
export ORG="<your-github-org>"
export SINCE="2026-05-11T19:00:00Z"
export UNTIL="2026-05-12T03:00:00Z"
export LOG_DIR="/tmp/supply-chain-scan-tanstack"
mkdir -p "$LOG_DIR"
```

**Log caching:** If `$LOG_DIR` already has logs from a previous run, reuse them — skip the download step.

**Write to files, not context:** Results can be large. Write structured evidence (CSV) to `$LOG_DIR` as you go. Don't accumulate findings in conversation context.

**Rate limits.** Before scanning a large org, check your GitHub API budget:

```bash
gh api /rate_limit --jq '.resources.core | "\(.remaining)/\(.limit) remaining (resets \(.reset | todate))"'
gh api /rate_limit --jq '.resources.code_search | "code-search: \(.remaining)/\(.limit) remaining"'
```

Code search: ~30 req/min. REST API: 5,000 req/hr. Log downloads count against REST. Use `xargs -P 10` for parallelism, cache everything to `$LOG_DIR`.

---

## Phase 1: Repo Analysis

**Goal:** For every repo that references `@tanstack/*`, build a static picture of dependency configuration — what versions are declared, what's locked, what install command CI uses, and whether the configuration is vulnerable in principle. This phase is window-agnostic.

### 1. Find all references to any compromised scope

Run one search per scope — code search doesn't allow scope-list disjunction in a single query.

```bash
# Scoped packages
for scope in @tanstack @mistralai @uipath @squawk @tallyui @draftauth @draftlab \
             @ml-toolkit-ts @supersurkhet @cap-js @dirigible-ai @mesadev \
             @beproduct @opensearch-project @taskflow-corp @tolka; do
  q=$(printf '%s' "$scope/" | python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.stdin.read()))")
  echo "=== $scope ==="
  gh api "search/code?q=${q}+org:${ORG}&per_page=100" \
    --jq '.items[] | "'$scope'\t\(.repository.full_name)\t\(.path)"' 2>/dev/null
  sleep 2  # code-search rate limit ~30 req/min
done | sort -u > "$LOG_DIR/refs.tsv"

# Unscoped packages — search by name (these collide with infra refs more often, dedupe later)
for pkg in agentwork-cli cmux-agent-mcp cross-stitch git-branch-selector git-git-git \
           intercom-client mbt nextmove-mcp safe-action ts-dna wot-api; do
  gh api "search/code?q=${pkg}+org:${ORG}&per_page=100" \
    --jq '.items[] | "unscoped:'$pkg'\t\(.repository.full_name)\t\(.path)"' 2>/dev/null
  sleep 2
done >> "$LOG_DIR/refs.tsv"

wc -l "$LOG_DIR/refs.tsv"
```

Paginate (`&page=2`, etc.) per scope if more than 100 results. Code search is throttled at ~30 req/min.

> **Customer-specific narrowing.** Most customers only consume a handful of these scopes. If the customer is e.g. an enterprise that doesn't touch crypto/Web3 or aviation data, you can deprioritize scanning for `@squawk`, `@beproduct`, `@tallyui`. Use the first pass (Phase 1.1) to scope down the rest of the investigation.

> **Faster alternative for large orgs (recommended >50 repos):** `gh search code` is rate-limited to 10 req/min and caps at 100 results per query. For orgs with hundreds of repos, **shallow-clone everything and grep locally** — usually 5-10x faster end-to-end:
>
> ```bash
> mkdir -p "$LOG_DIR/clones" && cd "$LOG_DIR/clones"
> # Clone every non-archived repo in the org, shallow
> gh repo list "$ORG" --no-archived --limit 1000 --json nameWithOwner --jq '.[].nameWithOwner' | \
>   xargs -P 10 -I {} bash -c 'git clone --depth 1 --filter=blob:none "git@github.com:{}.git" 2>/dev/null || echo "FAIL: {}"'
>
> # One grep across the entire org tree — covers every scope + version pattern at once
> SCOPES_RE='@(tanstack|mistralai|uipath|opensearch-project|squawk|tallyui|draftauth|draftlab|cap-js|dirigible-ai|mesadev|ml-toolkit-ts|supersurkhet|beproduct|taskflow-corp|tolka)/'
> grep -rE --include='package.json' --include='package-lock.json' --include='pnpm-lock.yaml' --include='yarn.lock' "$SCOPES_RE" . > "$LOG_DIR/refs-from-local-clone.txt"
> wc -l "$LOG_DIR/refs-from-local-clone.txt"
> ```
>
> Trade-off: disk space (a few GB for the average org) for speed and the ability to grep arbitrary patterns without re-querying. The `--filter=blob:none` flag avoids downloading blob contents until grep needs them, keeping the clone lean.
> Rule of thumb: under ~50 repos, stick with `gh search code`. Above that, clone locally.

### 2. Classify each reference

For each file found:

| File pattern | Category | Risk |
|---|---|---|
| `package.json` | npm manifest | **HIGH** — check spec range vs malicious versions |
| `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` | Lock file | **CRITICAL** — check pinned version against malicious list |
| `Dockerfile` | Docker build | **HIGH** if it runs `npm/pnpm/yarn install` |
| `.github/workflows/*.yml` | CI workflow | **CHECK** — does it install JS deps that include `@tanstack/*`? |
| `*.ts`, `*.tsx`, `*.js`, `*.jsx` | Source code | **NOT AFFECTED** — import reference, not install |
| `*.md`, `README*` | Docs | **NOT AFFECTED** |
| `values.yaml`, `Chart.yaml`, `*.tf` | Infra config | **NOT AFFECTED** |

### 3. Extract version data per repo

For every repo with a `@tanstack/*` dep:

- **Manifest spec** — version specifier as written in `package.json` (e.g. `^1.169.0`, `~1.169.5`, `latest`). Copy exactly.
- **Lock file version** — exact pinned version from the lock file.
- **Install command** — read from `.github/workflows/*.yml` and `Dockerfile`. Note shared/reusable actions (e.g. `build-fe (via common-workflows)`).

```bash
# package.json — extract @tanstack/* spec
gh api "repos/${ORG}/<repo>/contents/package.json" --jq '.content' | base64 -d | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
for section in ('dependencies','devDependencies','optionalDependencies','peerDependencies'):
  for k,v in d.get(section,{}).items():
    if k.startswith('@tanstack/'): print(f'{section}: {k} = {v}')
"

# package-lock.json — extract resolved @tanstack/* versions
gh api "repos/${ORG}/<repo>/contents/package-lock.json" --jq '.content' | base64 -d | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
for k,v in d.get('packages',{}).items():
  name = k.split('node_modules/')[-1]
  if name.startswith('@tanstack/'): print(f'{name}: {v.get(\"version\")}')
"

# pnpm-lock.yaml — find @tanstack/* entries
gh api "repos/${ORG}/<repo>/contents/pnpm-lock.yaml" --jq '.content' | base64 -d | grep -E "^\s+'?@tanstack/"

# yarn.lock — find @tanstack/* entries
gh api "repos/${ORG}/<repo>/contents/yarn.lock" --jq '.content' | base64 -d | grep -B1 -A2 "^\"?@tanstack/"

# Install command in workflows
gh api "repos/${ORG}/<repo>/contents/.github/workflows" --jq '.[].path' | while read wf; do
  gh api "repos/${ORG}/<repo>/contents/${wf}" --jq '.content' | base64 -d | \
    grep -iE "npm ci|npm install|pnpm install|yarn install|yarn$|bun install"
done

# Dockerfile install commands
gh api "repos/${ORG}/<repo>/contents/Dockerfile" --jq '.content' | base64 -d | \
  grep -iE "RUN.*(npm|pnpm|yarn|bun).*install"
```

### 4. Check Dockerfiles, scripts, and shared actions

- **Dockerfiles:** `RUN npm install` / `RUN pnpm install` rebuilt during the window → image may carry the payload baked into a layer.
- **Shell scripts / Makefiles:** `install.sh`, `setup.sh`, `bootstrap.sh` running JS package installs.
- **Workflow `run:` steps:** direct install commands.
- **Shared reusable actions:** `your-org/common-workflows/.github/actions/build-fe@<ref>` — chase down what it actually does.

### 5. Third-party base images

If repos use third-party base images with mutable tags (not digest-pinned) and those images include `@tanstack/*` (frontend builder images, etc.), and the image was rebuilt during the window — flag for follow-up with the image vendor.

### 6. Write the repo evidence table

Write `$LOG_DIR/evidence-repos.csv`:

```
repo,path,source_type,manifest_spec,spec_in_range,has_lockfile,lockfile_version,lock_protects,install_command,install_upgrades,can_be_compromised
```

**Column guide:**

| Column | What to write |
|---|---|
| `repo` | Repo name (no org prefix) |
| `path` | Full file path of the reference (e.g. `apps/web/package.json`) |
| `source_type` | `manifest` / `lockfile` / `ci-workflow` / `dockerfile` / `script` |
| `manifest_spec` | Exact specifier as written (`^1.169.0`). For CI/scripts: the install command. For transitive: `transitive` |
| `spec_in_range` | `yes (allows 1.169.5)`, `yes (allows 1.169.8)`, `yes (allows 1.161.9)`, `yes (allows 1.161.12)`, or `no (reason)`. `^1.169.x` and `^1.169.0` both allow the router-family malicious versions; `~1.169.4` does not |
| `has_lockfile` | `yes (package-lock.json)` / `yes (pnpm-lock.yaml)` / `yes (yarn.lock)` / `no`. Always include the type |
| `lockfile_version` | Exact pinned version for the relevant `@tanstack/*` package(s). `none` if no lock file |
| `lock_protects` | `yes` if `lockfile_version` is not one of the malicious values from the advisory. `no` if it is |
| `install_command` | From workflows: `npm ci`, `pnpm install --frozen-lockfile`, `yarn install (no flags)`, `bun install`, etc. |
| `install_upgrades` | `no` for `npm ci`/frozen-lockfile (lock-safe). `possible` for `npm install`/`pnpm install` without frozen. `n/a` only if `@tanstack/*` is not in this install |
| `can_be_compromised` | `no` if lock protects AND install respects lock. `yes` otherwise |

**Rules:**
- This table is window-agnostic — it describes the repo's posture.
- No blank cells.
- Parenthetical explanations after values: `yes (allows 1.169.5)`.

### Install command cheat sheet

| Command | Lock file respected? |
|---|---|
| `npm ci` | **Yes** — installs exactly what lock file says |
| `npm install` (no args) | **Partially** — can update lock if specs drift |
| `npm install <pkg>` | **No** — resolves to latest matching |
| `pnpm install --frozen-lockfile` | **Yes** — fails if lock is out of date |
| `pnpm install` (no flag) | **No (in CI)** — may update lock |
| `yarn install --frozen-lockfile` (classic) / `yarn install --immutable` (berry) | **Yes** |
| `yarn install` (no flag) | **Partial** — can update |
| `bun install` | **Partially** — respects `bun.lockb` if present |

**Key insight:** A repo with a committed lock file pinning router-family `@tanstack/*` to a safe version AND a frozen install command in CI cannot be compromised through CI.

---

## Phase 2: CI Run Analysis

**Why this phase is critical:** Phase 1 only finds repos that mention `@tanstack/*` by name. A repo can install it transitively (a UI library that depends on `@tanstack/react-router`) without ever naming it. The only way to know what actually got installed during the window is to check the CI logs.

### 1. Find runs during the exposure window

```bash
gh api "/orgs/${ORG}/repos" --paginate --jq '.[].name' | while read repo; do
  gh api "repos/${ORG}/${repo}/actions/runs?created=${SINCE}..${UNTIL}&per_page=100" \
    --jq ".workflow_runs[] | \"${repo}|\(.id)|\(.created_at)|\(.name)|\(.conclusion)\"" 2>/dev/null
done > "$LOG_DIR/all_runs.txt"

echo "Total runs to scan: $(wc -l < "$LOG_DIR/all_runs.txt")"
```

### 2. Download all run logs in parallel

Skip if `$LOG_DIR` already has logs from a previous run.

```bash
cat "$LOG_DIR/all_runs.txt" | while IFS='|' read repo run_id rest; do
  echo "$repo $run_id"
done | xargs -P 10 -L 1 bash -c \
  'gh run view "$1" --repo "${ORG}/$0" --log > "${LOG_DIR}/run-$1.log" 2>/dev/null && echo "OK: $0 $1" || echo "FAIL: $0 $1"'
```

### 3. Scan logs for compromised-scope references and IOCs

```bash
# Broad: any reference to any compromised scope
echo "=== Compromised-scope references ==="
grep -rlinE "(@tanstack/|@mistralai/|@uipath/|@squawk/|@tallyui/|@draftauth/|@draftlab/|@ml-toolkit-ts/|@supersurkhet/|@cap-js/|@dirigible-ai/|@mesadev/|@beproduct/|@opensearch-project/|@taskflow-corp/|@tolka/)" "$LOG_DIR"/run-*.log 2>/dev/null

# Broad: unscoped compromised package names (more false-positive-prone, classify carefully)
echo "=== Unscoped compromised-package references ==="
grep -rlinE "\b(agentwork-cli|cmux-agent-mcp|cross-stitch|git-branch-selector|git-git-git|intercom-client|nextmove-mcp|safe-action|ts-dna|wot-api)\b" "$LOG_DIR"/run-*.log 2>/dev/null

# Compromised version markers — @tanstack router family
echo "=== Compromised version: @tanstack router family ==="
grep -rlE "@tanstack/(router|history|react-router|vue-router|solid-router|router-core).*(1\.169\.5|1\.169\.8|1\.161\.9|1\.161\.12)" "$LOG_DIR"/run-*.log 2>/dev/null

# Compromised version markers — high-blast-radius scopes
echo "=== Compromised version: @mistralai ==="
grep -rlE "@mistralai/mistralai.*(2\.2\.[2-4])|@mistralai/mistralai-(azure|gcp).*(1\.7\.[1-3])" "$LOG_DIR"/run-*.log 2>/dev/null

echo "=== Compromised version: @opensearch-project ==="
grep -rlE "@opensearch-project/opensearch.*(3\.5\.3|3\.6\.2|3\.7\.0|3\.8\.0)" "$LOG_DIR"/run-*.log 2>/dev/null

echo "=== Compromised version: intercom-client (unscoped) ==="
grep -rlE "intercom-client.*7\.0\.4" "$LOG_DIR"/run-*.log 2>/dev/null

# Manifest fingerprint — the malicious tarball adds an optionalDependency pointing at a github: URL
echo "=== Malicious optionalDependency fingerprint ==="
grep -rliE '"@tanstack/setup"|"github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"' "$LOG_DIR"/run-*.log 2>/dev/null

# Payload file names (these names are reused across scopes — the worm rebuilds tarballs but keeps payload names)
echo "=== Payload file names ==="
grep -rliE "router_init\.js|tanstack_runner\.js|gh-token-monitor" "$LOG_DIR"/run-*.log 2>/dev/null

# C2 / exfil domains
echo "=== C2 / exfil domains ==="
grep -rliE "git-tanstack\.com|api\.masscan\.cloud|getsession\.org|litter\.catbox\.moe" "$LOG_DIR"/run-*.log 2>/dev/null

# Process patterns (memory dump, bun invocation of the runner)
echo "=== Process IOCs ==="
grep -rliE "/proc/[0-9]+/mem|bun run tanstack_runner" "$LOG_DIR"/run-*.log 2>/dev/null
```

> **Why scan all scopes, not just `@tanstack`?** The worm self-propagates by stealing the first victim's npm credentials, then enumerating every package that maintainer publishes and republishing it with the same payload. A customer who has never touched `@tanstack/*` but consumes `@mistralai/mistralai` or `@opensearch-project/opensearch` is still at full risk.

### 4. Classify hits as real installs vs false positives

**Real install indicators** (`@tanstack/*` WAS installed):
- `added @tanstack/<pkg>@<version>` (npm verbose)
- `+ @tanstack/<pkg> <version>` (pnpm)
- `@tanstack/<pkg>@<version>` in `yarn install` resolution output
- `npm http fetch GET https://registry.npmjs.org/@tanstack/<pkg>`
- `Downloading @tanstack/<pkg>-<version>.tgz`
- Lockfile-update lines: `Updated @tanstack/<pkg>` in CI diff output
- Postinstall script output from `@tanstack/setup`

**False positives (ignore):**
- Source-code imports in scan output: `import { useNavigate } from '@tanstack/react-router'`.
- TypeScript errors mentioning the package name.
- SAST/dependency-review tool output listing the package without indicating an install.
- Branch names: `feat/upgrade-tanstack`, `dependabot/npm_and_yarn/@tanstack/react-router-1.169.0`.
- Helm/values.yaml or Terraform that names the package without installing it.
- Comments / docs that quote the package name.

### 5. For each run with install commands, determine the version installed

- Find the install command in the log (`npm ci`, `pnpm install --frozen-lockfile`, `yarn install`, etc.).
- For frozen/`ci` commands: the resolved version is in the lock file — cross-check Phase 1's `lockfile_version` column.
- For non-frozen commands: look for `added @tanstack/...@<version>` lines in the log; if logs are too quiet, re-trigger with verbose logging on a clean branch (do not re-trigger on `main`).

### 6. Write the CI runs evidence table

Write `$LOG_DIR/evidence-ci-runs.csv`:

```
repo,run_id,created_at,workflow,platform,install_command,log_line,version_installed,lock_respected,iocs_found,ci_compromised
```

**Column guide:**

| Column | What to write |
|---|---|
| `repo` | Repo name |
| `run_id` | GitHub Actions run ID |
| `created_at` | UTC timestamp of the run |
| `workflow` | Workflow name |
| `platform` | `ubuntu-latest`, `macos-14`, `windows-latest`, etc. (from log) |
| `install_command` | Exact command from the log |
| `log_line` | Line number(s) in `run-<id>.log` where the install / hit appears |
| `version_installed` | Exact `@tanstack/<pkg>` version installed, e.g. `1.169.4`. `not installed (this step installs <what>)` if no router-family `@tanstack/*` install in this step |
| `lock_respected` | `yes` if version matches lock file. `no` if different. `n/a (reason)` if lock doesn't apply |
| `iocs_found` | `yes (which IOC)` (router_init.js, getsession.org, etc.) or `no` |
| `ci_compromised` | **Verdict:** `clean` / `compromised` / `clean (component not installed)` |

**Rules:**
- One row per install-command execution, not per run.
- Only include runs that executed package-install commands.
- No blank cells.

### 7. Audit `pull_request_target` workflows in TanStack-adjacent repos

The original attack vector was `pull_request_target` running a fork's code. Audit your own org for the same exposure:

```bash
gh api "search/code?q=%22pull_request_target%22+org:${ORG}+filename:.yml&per_page=100" \
  --jq '.items[] | "\(.repository.full_name)\t\(.path)"' | sort -u > "$LOG_DIR/prt-workflows.tsv"
```

For each hit, verify:
- Does it `actions/checkout` the PR's head ref? If yes, untrusted code is running with the repo's secrets — high-risk pattern even if not currently exploited.
- Does it use `pnpm`/`npm` cache restoration (`actions/cache`) that crosses branches? Poisoned-cache risk.

This is a hardening signal, not a "compromised" signal — record findings for Phase 6.

### Reducing false positives

Most hits will be infrastructure/source-code references. Focus exclusively on package-install output. If a hit doesn't look like an npm/pnpm/yarn resolver/installer line, it's not a risk.

---

## Phase 2b: The Customer's Own Published Packages (Forward-Propagation Risk)

**Why this phase exists.** The customer is not only a *consumer* of compromised packages — if they publish their own npm packages, **their own published artifacts can carry a compromised dep forward** to *their* downstream users. Two distinct things can have happened:

1. **Direct republish by the worm.** If any maintainer in the customer's org had their npm/GitHub credentials stolen on a workstation during the window, the worm enumerated that maintainer's packages and republished them with the payload. The new version is on npm under the customer's name — same payload mechanism (`@tanstack/setup` optionalDependency, `router_init.js` / `tanstack_runner.js`).

2. **Built-with-bad-dep during the window.** The customer's release pipeline ran during the window, resolved a compromised version of a transitive dep, and shipped a normal-looking release whose lockfile/`package-lock.json` now pins downstream consumers to the malicious version. The customer's tarball itself is clean, but anyone installing it freshly will re-resolve the bad dep — propagating exposure forward.

Both need affirmative checks.

### 2b.1. Enumerate the customer's published npm packages

Ask the customer for their npm scope(s) and individual publisher accounts. Then list everything that's been published:

```bash
# By scope (e.g. @acme-corp)
curl -s "https://registry.npmjs.org/-/v1/search?text=scope:${SCOPE}&size=250" | \
  python3 -c "import sys,json; [print(p['package']['name']) for p in json.load(sys.stdin)['objects']]" > "$LOG_DIR/own-packages.txt"

# By maintainer username (catches packages outside the org scope)
for user in $(cat "$LOG_DIR/maintainers.txt"); do
  curl -s "https://registry.npmjs.org/-/v1/search?text=maintainer:${user}&size=250" | \
    python3 -c "import sys,json; [print(p['package']['name']) for p in json.load(sys.stdin)['objects']]"
done >> "$LOG_DIR/own-packages.txt"

sort -u "$LOG_DIR/own-packages.txt" -o "$LOG_DIR/own-packages.txt"
echo "Customer publishes $(wc -l < "$LOG_DIR/own-packages.txt") packages"
```

### 2b.2. Check publication timestamps in the window

For every customer-owned package, list the versions published between `$SINCE` and `$UNTIL`:

```bash
while read pkg; do
  curl -s "https://registry.npmjs.org/${pkg}" | python3 -c "
import sys, json
from datetime import datetime
d = json.load(sys.stdin)
times = d.get('time', {})
since = '${SINCE}'
until = '${UNTIL}'
for v, t in times.items():
    if v in ('created','modified'): continue
    if since <= t <= until:
        print(f'${pkg}@{v}\t{t}')
" 2>/dev/null
done < "$LOG_DIR/own-packages.txt" > "$LOG_DIR/own-published-in-window.tsv"

cat "$LOG_DIR/own-published-in-window.tsv"
```

**Every row in this file is a candidate.** Each was published during the worm's active window — investigate each one in 2b.3.

### 2b.3. Per-candidate forensics

For each candidate `pkg@version`, answer four questions:

**(a) Was the publisher account active where you'd expect?**

Pull the tarball metadata:
```bash
curl -s "https://registry.npmjs.org/${pkg}/${version}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('npmUser:', d.get('_npmUser'))
print('maintainers:', d.get('maintainers'))
print('publish time:', d.get('time') or '(see parent)')
print('shasum:', d.get('dist',{}).get('shasum'))
print('integrity:', d.get('dist',{}).get('integrity'))
print('attestations:', bool(d.get('dist',{}).get('attestations')))
"
```

Cross-check the `npmUser` against the customer's known publishing identities. Discrepancy → likely worm republish.

**(b) Does the tarball contain payload files?**

```bash
mkdir -p "$LOG_DIR/tarballs/${pkg//\//_}-${version}"
cd "$LOG_DIR/tarballs/${pkg//\//_}-${version}"
npm pack "${pkg}@${version}" 2>/dev/null
tar tzf *.tgz | grep -iE "router_init\.js|tanstack_runner\.js|setup\.mjs"
tar xzf *.tgz
grep -lE '"@tanstack/setup"|getsession\.org|gh-token-monitor' package/package.json package/**/*.{js,json,mjs} 2>/dev/null
shasum -a 256 package/router_init.js 2>/dev/null   # compare to ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c
shasum -a 256 package/tanstack_runner.js 2>/dev/null  # compare to 2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96
cd -
```

If the payload files or the manifest fingerprint are present → **directly republished by the worm.** Deprecate the version immediately and notify downstream consumers.

**(c) Does the published package's lockfile pin a malicious dep?**

The tarball itself may be clean but ship a `package-lock.json` / `npm-shrinkwrap.json` / `pnpm-lock.yaml` that pins a compromised resolution. Anyone running `npm install` against this published package will re-fetch the bad version.

```bash
cd "$LOG_DIR/tarballs/${pkg//\//_}-${version}/package"
for lockfile in package-lock.json npm-shrinkwrap.json pnpm-lock.yaml yarn.lock; do
  [ -f "$lockfile" ] || continue
  echo "=== $lockfile ==="
  # @tanstack router family
  grep -E "@tanstack/(router|history|react-router|vue-router|solid-router|router-core).*(1\.169\.5|1\.169\.8|1\.161\.9|1\.161\.12)" "$lockfile" | head -5
  # @mistralai
  grep -E "@mistralai/mistralai.*2\.2\.[2-4]|@mistralai/mistralai-(azure|gcp).*1\.7\.[1-3]" "$lockfile" | head -5
  # @opensearch-project
  grep -E "@opensearch-project/opensearch.*(3\.5\.3|3\.6\.2|3\.7\.0|3\.8\.0)" "$lockfile" | head -5
  # intercom-client
  grep -E "\"intercom-client\".*7\.0\.4" "$lockfile" | head -5
done
cd -
```

If a published lockfile pins a malicious version → **built with a bad dep.** The customer's tarball needs a corrective re-publish (new version with a clean lockfile + an explicit deprecation of the bad one).

**(d) Does the release CI run show the malicious resolution?**

Cross-reference each `pkg@version` candidate with the Phase 2 run scan. The release workflow's log for that publication should show the install resolving a clean version. If it resolved a malicious one — the published tarball is poisoned even if the tarball check (b) didn't find the payload directly (e.g. the dep is a transitive dep that got bundled, not unpacked into the top level).

### 2b.4. Write the customer-published evidence table

Write `$LOG_DIR/evidence-own-published.csv`:

```
package,version,published_at,publisher_account,publisher_expected,tarball_payload,lockfile_poisoned,release_run_id,verdict
```

| Column | Values |
|---|---|
| `package` | `@acme/sdk` |
| `version` | `2.5.7` |
| `published_at` | ISO timestamp from the registry |
| `publisher_account` | npm user that published it |
| `publisher_expected` | `yes` / `no (expected: <user>)` |
| `tarball_payload` | `none` / `router_init.js + tanstack_runner.js` / `@tanstack/setup optional-dep` / etc. |
| `lockfile_poisoned` | `no` / `yes (@tanstack/react-router@1.169.5)` / etc. |
| `release_run_id` | GH Actions run that published it, if known |
| `verdict` | `clean` / `directly republished` / `built with poisoned dep` / `inconclusive` |

### 2b.5. If any "directly republished" or "built with poisoned dep" verdict

This is a **publisher-side incident**, not just a consumer-side one. Treat it like:

1. **Deprecate the affected version immediately**: `npm deprecate '<pkg>@<version>' 'Compromised — do not install. See <advisory>'`. Do this even before you can publish a clean version — deprecation is non-destructive and warns consumers immediately.
2. **Publish a clean superseding version**, generated on a known-clean host, with a fresh lockfile that excludes every malicious version across all 19+ scopes.
3. **Notify downstream consumers** — github issue / changelog / customer email — listing the bad version and the safe replacement. Include the deprecation message.
4. **Rotate the publisher's npm token**. If it's not obvious which token was used, rotate them all and re-issue with 2FA + provenance.
5. **File a takedown with npm security** if `npm deprecate` isn't enough — for "directly republished" cases, you can request npm unpublish via support.

---

## Phase 3: Network Investigation (Firewall / Proxy / DNS Logs)

The payload exfiltrates via **three redundant channels**. Check network logs from any host that ran CI or developer work during and after the window.

### What to look for

| IOC | Where to search |
|---|---|
| DNS resolution of `git-tanstack.com` | DNS logs, DNS proxy, Cloudflare Gateway |
| DNS resolution of `api.masscan.cloud` | DNS logs |
| DNS resolution of `*.getsession.org` (`filev2`, `seed1`, `seed2`, `seed3`) | DNS logs |
| Outbound HTTPS to any of the above | Proxy logs, NetFlow, VPC Flow Logs |
| Outbound HTTPS to `litter.catbox.moe/h8nc9u.js` or `/7rrc6l.mjs` | Proxy logs |
| Anomalous GitHub API traffic from CI runners | GitHub audit log, runner egress logs |
| Read access to `/proc/<pid>/mem` from a non-root-ish process on a runner | EDR, host telemetry |

### Where to check

**Cloud:**
- AWS: VPC Flow Logs, Route 53 Resolver query logs, CloudTrail (with DNS query logging).
- GCP: VPC Flow Logs, Cloud DNS query logs.
- Azure: NSG Flow Logs, Azure DNS Analytics.

**On-prem / corporate:**
- Firewall (Palo Alto, Fortinet) — search for any of the domains/IPs above.
- Web proxy (Zscaler, Squid, Netskope) — search for the domains.
- DNS server logs — search for resolution attempts.
- SIEM (Splunk, Elastic, Chronicle) — correlate across sources.

**CI runners:**
- Self-hosted: check the host's egress logs and EDR telemetry.
- GitHub-hosted: no direct host telemetry; rely on network-edge logs.

### Time window

Search from `2026-05-11T19:00:00Z` to **at least 7 days forward** — the `gh-token-monitor` daemon polls GitHub for 24h and may stay quiet but then resume; secondary beacons may surface later.

### Example queries

**Splunk:**
```
index=dns query IN ("git-tanstack.com","api.masscan.cloud","filev2.getsession.org","seed1.getsession.org","seed2.getsession.org","seed3.getsession.org")
| stats count by src_ip, query, answer
```

**Elastic/Kibana:**
```
dns.question.name : ("git-tanstack.com" or "api.masscan.cloud" or "*.getsession.org")
```

**AWS VPC Flow Logs (CloudWatch Insights):**
```
filter @message like /git-tanstack|masscan\.cloud|getsession\.org/
| stats count(*) as hits by srcAddr, dstAddr
```

### Interpret results

- **DNS resolution found for any IOC domain:** A machine attempted contact. Identify the source, confirm whether the connection succeeded (firewall/proxy logs), and treat the source as suspect.
- **Successful POST to `filev2.getsession.org`:** Exfil channel was used. Treat source as compromised — full credential rotation.
- **No results:** Network was not contacted from your visibility. Consistent with a clean finding from Phases 1–2, but does not rule out compromise if the host had egress paths outside your inspection (BYO laptop on home network, etc.).

---

## Phase 4: Workstation Investigation

Developer machines that ran `npm install` / `pnpm install` / `yarn install` during the window may have installed the compromised version. Unlike CI, you cannot rely on logs — check artifacts directly.

> **Important:** The payload installs persistence (`gh-token-monitor` daemon) and tampers with **agent config files** (`.claude/`, `.vscode/`). It may also self-clean the dropper after first run. Absence of `router_init.js` does not prove absence of compromise — check persistence and shell/agent logs as well.

Run these on each developer machine that worked on JS/TS code during May 11–12, 2026.

### 4a. Payload files in `node_modules`

```bash
# Search all known project locations
for root in ~/projects ~/code ~/repos ~/work "$HOME"; do
  [ -d "$root" ] || continue
  find "$root" -path '*/node_modules/@tanstack/*' \
    \( -name 'router_init.js' -o -name 'tanstack_runner.js' -o -name 'setup.mjs' \) 2>/dev/null
done

# Manifest fingerprint
find ~ -path '*/node_modules/@tanstack/*/package.json' 2>/dev/null | \
  xargs grep -l '"@tanstack/setup"' 2>/dev/null
```

Optional hash check on any hit:
```bash
shasum -a 256 <found-file>
# Compare against:
# ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c  (router_init.js)
# 2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96  (tanstack_runner.js)
```

### 4b. Lock files referencing malicious versions (all scopes)

```bash
# Build a single regex covering high-signal compromised versions across scopes
MALICIOUS_RE='@tanstack/(router|history|react-router|vue-router|solid-router|router-core).*(1\.169\.5|1\.169\.8|1\.161\.9|1\.161\.12)|@mistralai/mistralai.*2\.2\.[2-4]|@mistralai/mistralai-(azure|gcp).*1\.7\.[1-3]|@opensearch-project/opensearch.*(3\.5\.3|3\.6\.2|3\.7\.0|3\.8\.0)|"intercom-client".*"?7\.0\.4'

# package-lock.json
find ~ -name 'package-lock.json' -not -path '*/node_modules/*' 2>/dev/null | \
  xargs grep -lE "$MALICIOUS_RE" 2>/dev/null

# pnpm-lock.yaml
find ~ -name 'pnpm-lock.yaml' -not -path '*/node_modules/*' 2>/dev/null | \
  xargs grep -lE "$MALICIOUS_RE" 2>/dev/null

# yarn.lock
find ~ -name 'yarn.lock' -not -path '*/node_modules/*' 2>/dev/null | \
  xargs grep -lE "$MALICIOUS_RE" 2>/dev/null

# Coarser pass: any reference to any compromised scope in a lockfile (manual triage required)
ANY_SCOPE_RE='@(tanstack|mistralai|uipath|squawk|tallyui|draftauth|draftlab|ml-toolkit-ts|supersurkhet|cap-js|dirigible-ai|mesadev|beproduct|opensearch-project|taskflow-corp|tolka)/'
find ~ \( -name 'package-lock.json' -o -name 'pnpm-lock.yaml' -o -name 'yarn.lock' \) \
  -not -path '*/node_modules/*' 2>/dev/null | \
  xargs grep -lE "$ANY_SCOPE_RE" 2>/dev/null > "$LOG_DIR/workstation-lockfiles-with-affected-scopes.txt"
```

### 4c. OS persistence

**macOS:**
```bash
# The malicious LaunchAgent
ls -la ~/Library/LaunchAgents/com.user.gh-token-monitor.plist 2>/dev/null
launchctl list | grep -i gh-token-monitor

# Anything else that touches gh-token-monitor
grep -rli "gh-token-monitor" ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/ 2>/dev/null
```

**Linux:**
```bash
ls -la ~/.config/systemd/user/gh-token-monitor.service 2>/dev/null
systemctl --user status gh-token-monitor 2>/dev/null
grep -rli "gh-token-monitor" /etc/systemd/ ~/.config/systemd/ 2>/dev/null
```

### 4d. AI-agent / editor config tampering

The payload writes to agent / editor config files. Check for unexpected entries:

```bash
# Find tampered files
find ~ -maxdepth 6 \( -path '*/.claude/settings.json' -o -path '*/.claude/setup.mjs' -o -path '*/.vscode/tasks.json' \) 2>/dev/null | while read f; do
  echo "=== $f ==="
  echo "  modified: $(stat -f '%Sm' "$f" 2>/dev/null || stat -c '%y' "$f" 2>/dev/null)"
  grep -lE "tanstack_runner|router_init|getsession\.org|gh-token-monitor|catbox\.moe" "$f" 2>/dev/null && echo "  *** IOC MATCH ***"
done
```

Pay particular attention to files modified **on or after 2026-05-11**.

### 4e. npm / pnpm / yarn cache content

The malicious tarballs may still live in local caches:

```bash
# npm
ls ~/.npm/_cacache/content-v2/sha512 2>/dev/null | head
npm cache ls "@tanstack/router" 2>/dev/null
npm cache ls "@tanstack/history" 2>/dev/null

# pnpm
pnpm store path 2>/dev/null
ls "$(pnpm store path 2>/dev/null)/v3/files" 2>/dev/null | head

# yarn (classic)
ls ~/.yarn/cache 2>/dev/null | grep -i tanstack
# yarn berry
ls ./.yarn/cache 2>/dev/null | grep -i tanstack
```

### 4f. Network indicators on the host

```bash
# Active connections to known C2
netstat -an 2>/dev/null | grep -E "ESTABLISHED|CLOSE_WAIT" | grep -v 127.0.0.1
lsof -i -P 2>/dev/null | grep -iE "tanstack|masscan|getsession|catbox"

# /etc/hosts tampering
grep -iE "git-tanstack|masscan|getsession|catbox" /etc/hosts 2>/dev/null
```

### 4g. Shell history

```bash
grep -iE "tanstack|gh-token-monitor|bun run|/proc/.*mem" ~/.bash_history ~/.zsh_history ~/.local/share/fish/fish_history 2>/dev/null
```

### 4h. npm debug logs

```bash
ls ~/.npm/_logs 2>/dev/null | sort | tail -50
grep -liE "@tanstack/setup|router_init|tanstack_runner" ~/.npm/_logs/*.log 2>/dev/null
```

### 4i. AI agent conversation logs (Claude Code, Cursor, Windsurf, Copilot)

The payload tampers with `.claude/` files. If an AI agent ran during the window, its session log may contain evidence of unexpected file edits / shell commands the user didn't issue.

| Agent | Conversation log location |
|---|---|
| Claude Code | `~/.claude/projects/*/conversation_*.jsonl` |
| Cursor | `~/Library/Application Support/Cursor/User/History/` (macOS), `~/.config/Cursor/User/History/` (Linux) |
| Windsurf | similar Application Support / config path |
| Copilot CLI | `~/.config/github-copilot/` |

Grep for the IOCs across them:
```bash
grep -rliE "tanstack_runner|router_init|gh-token-monitor|getsession\.org|git-tanstack\.com" ~/.claude ~/Library/Application\ Support/Cursor ~/.config 2>/dev/null
```

### 4j. Worm self-propagation footprint in your own GitHub org

The worm queries the registry for packages the victim maintains and tries to republish them. Check your own org for the post-compromise signals:

```bash
# Suspicious PRs / commits authored as "claude" that you didn't make
gh api "search/issues?q=org:${ORG}+author:app/dependabot+is:pr+created:>=2026-05-11" --jq '.items[] | "\(.repository_url) | \(.user.login) | \(.title)"' 2>/dev/null
gh api "search/commits?q=org:${ORG}+author-email:claude@users.noreply.github.com" --jq '.items[] | "\(.repository.full_name) | \(.html_url) | \(.commit.message)"' 2>/dev/null

# Branches matching the worm's pattern
gh api "/orgs/${ORG}/repos" --paginate --jq '.[].name' | while read repo; do
  gh api "repos/${ORG}/${repo}/branches" --paginate --jq ".[] | select(.name | test(\"dependabot/github_actions/format/\")) | \"${repo} | \(.name)\""
done

# Attacker accounts mentioned anywhere
gh api "search/commits?q=org:${ORG}+author:voicproducoes" --jq '.items[] | "\(.repository.full_name) | \(.html_url)"' 2>/dev/null
gh api "search/commits?q=org:${ORG}+author:zblgg" --jq '.items[] | "\(.repository.full_name) | \(.html_url)"' 2>/dev/null
```

### 4k. New / exfil repos created during the window

```bash
gh api --paginate "/orgs/${ORG}/repos?per_page=100&sort=created&direction=desc" \
  --jq ".[] | select(.created_at > \"${SINCE}\" and .created_at < \"${UNTIL}\") | \"\(.name) | \(.created_at) | \(.visibility) | \(.owner.login)\""
```

Flag any new public repos, especially with names matching `tpcp*`, `*-docs`, or unusual short names from accounts you don't recognize.

---

## Phase 5: Present Results

Produce four deliverables and return them to the user.

### 1. Repo Analysis table (`evidence-repos.csv`)

CSV from Phase 1 — dependency posture per repo, independent of the window.

### 2. CI Runs table (`evidence-ci-runs.csv`)

CSV from Phase 2 — what actually happened during the window: install commands, versions installed, IOCs, verdict per run.

### 3. Customer-Published Packages table (`evidence-own-published.csv`)

CSV from Phase 2b — every package the customer published during the window, with a verdict per version: `clean` / `directly republished` / `built with poisoned dep` / `inconclusive`. This is the **forward-propagation** picture — what the customer may have shipped to *their* downstream consumers.

### 4. Executive Summary

Short prose summary for incident-response leads. Cover:

- **Verdict:** `clean` or `compromised`.
- **Scope:** repos scanned, CI runs analyzed, logs downloaded.
- **Repo analysis:** repos referencing `@tanstack/*` (router family vs clean families), lock-file coverage, manifest ranges that allow malicious versions.
- **CI analysis:** frozen-install vs unfrozen, versions installed, IOCs.
- **Network:** whether any IOC domain/IP was contacted.
- **Workstations:** how many developer machines were checked, whether persistence (`gh-token-monitor`) was found, agent-config tampering, npm-cache hits.
- **Org-side worm signals:** unexpected commits/branches/PRs.
- **Forward propagation:** whether any package the customer publishes was either directly republished by the worm or shipped during the window with a malicious dep pinned in its lockfile. List the package versions that need deprecation + corrective releases.
- **Bottom line:** one sentence.

### 4. Determine which repos need action

**No action needed** — all true:
- `can_be_compromised` = no.
- All CI runs `ci_compromised` = clean.
- No workstation IOCs tied to that repo.

**Action needed** — any true:
- `can_be_compromised` = yes.
- Any `ci_compromised` = compromised.
- Workstation persistence / payload found on a machine used to build the repo.
- Worm-style commit/branch activity matching the IOC patterns.

**Vulnerable but not hit** — `can_be_compromised` = yes but no CI runs during the window: not compromised this time, but config is vulnerable to the next supply-chain event. Flag for Phase 6 hardening.

Return `$LOG_DIR/evidence-repos.csv`, `$LOG_DIR/evidence-ci-runs.csv`, and the executive summary.

---

## Phase 6: Hardening & Remediation (User Approval Required)

**Do NOT proceed without explicit user approval.** Present findings first, then ask which steps to execute.

### Remediation — only if compromised

Order matters; rotate before scrubbing.

1. **Quarantine.** Disconnect affected dev workstations from corporate network; drain and stop affected CI runners (terminate if ephemeral).
2. **Snapshot before cleanup.** Capture `ps`, the payload files, persistence units, shell history, `~/.npmrc`, `~/.gitconfig`. Useful for forensics — also useful if anyone questions the verdict later.
3. **Rotate credentials** (in this order):
    1. **npm publish tokens** — `~/.npmrc`, automation tokens, granular tokens. Run `npm token list` and revoke anything tied to the suspect host. Re-publish any of your own packages with strict 2FA + provenance if the host had publish rights.
    2. **GitHub tokens** — env vars (`GITHUB_TOKEN` is auto-rotated; PATs are not), `gh` CLI token, `.git-credentials`, deploy keys, GitHub App installation tokens.
    3. **Cloud instance credentials** — AWS IMDS / IAM-role session creds, GCP metadata tokens, Azure managed-identity tokens.
    4. **Secrets Manager / Vault tokens** that the runner held.
    5. **Kubernetes service-account tokens** the runner could read.
    6. **SSH private keys** — `~/.ssh/*`. Rotate and remove the old public keys from GitHub/GitLab/servers.
    7. **Browser-stored sessions** — npm.com, github.com, cloud consoles. Force re-auth.
4. **Remove persistence** on affected workstations:
   ```bash
   # macOS
   launchctl bootout gui/$(id -u)/com.user.gh-token-monitor 2>/dev/null
   rm -f ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
   # Linux
   systemctl --user stop gh-token-monitor 2>/dev/null
   systemctl --user disable gh-token-monitor 2>/dev/null
   rm -f ~/.config/systemd/user/gh-token-monitor.service
   ```
5. **Purge package caches and `node_modules`** on every affected host:
   ```bash
   npm cache clean --force
   pnpm store prune
   yarn cache clean
   rm -rf node_modules
   ```
6. **Rebuild affected Docker images** with `--no-cache` — the payload may be baked into a layer.
7. **Block C2 at network edge:** add `git-tanstack.com`, `api.masscan.cloud`, `*.getsession.org`, `litter.catbox.moe` to firewall/proxy deny lists.
8. **Audit GitHub** for unauthorized commits, PRs, releases, branches, and new repos in the window — see Phase 4j and 4k.
9. **Re-image compromised workstations** if `gh-token-monitor` was active and you can't be certain you got every persistence vector — in-place cleaning may miss further footholds.

### Hardening — wherever `can_be_compromised` = yes

| Attack surface | Fix |
|---|---|
| No lock file committed | Commit `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` |
| CI uses non-frozen install | Switch to `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --frozen-lockfile` (or `--immutable` on berry) |
| Loose `^`/`~`/`latest` ranges on critical deps | Pin exact versions (`@tanstack/react-router: 1.169.4`); regenerate lock |
| Postinstall scripts run in CI | Add `--ignore-scripts` to install commands as defense-in-depth (will break packages that depend on postinstalls — test first) |
| `pull_request_target` workflows that check out PR head ref | Refactor so untrusted code never runs with repo secrets. If the workflow genuinely needs to act on the PR, use [`pull_request`](https://docs.github.com/en/actions/writing-workflows/choosing-when-workflows-run/events-that-trigger-workflows#pull_request) and accept it doesn't get secrets, or split into a privileged + unprivileged job |
| `actions/cache` keys not scoped per branch/actor | Add `${{ github.ref }}` / `${{ github.actor }}` to cache keys so a fork can't poison `main`'s cache |
| Docker base images pinned by mutable tag | Pin to digest (`@sha256:...`) |
| Floating `latest` ranges | Replace with pinned versions; let Dependabot/Renovate propose updates instead of resolving live |
| No verifying npm proxy | Stand up Verdaccio / JFrog / GitHub Packages and require CI to install from the proxy with an allow-after-N-hours window |
| Long-lived publish automation tokens | Replace with short-lived OIDC; require 2FA on publish |
| No SBOM / dependency review on PRs | Enable [`actions/dependency-review-action`](https://github.com/actions/dependency-review-action) |

### Upgrade path for `@tanstack/*` router family

The vendor postmortem does not publish a single "safe replacement" version per package. Two options:

- **Downgrade to a pre-compromise version** (e.g. `1.169.4` for the router family, `1.161.7` or earlier for `@tanstack/history`) until the vendor tags a clearly post-incident release. Track the [tracking issue](https://github.com/TanStack/router/issues/7383).
- **Upgrade to the post-incident release** once the vendor cuts one (and verify the release commit is signed by a known maintainer + the tarball matches the lock-file integrity hash you compute locally).

Whichever you choose, **regenerate the lock file** on a clean host and commit it.

---

## References

**Vendor postmortem and canonical lists**
- TanStack postmortem — https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
- Tracking issue (canonical version list) — https://github.com/TanStack/router/issues/7383
- GitHub Security Advisory — GHSA-g7cv-rxg3-hmpx
- CVE record — https://cvereports.com/reports/CVE-2026-45321

**Multi-scope inventories (use these for the full package list across all scopes)**
- Mend writeup — 172 npm + PyPI packages — https://www.mend.io/blog/mini-shai-hulud-is-back-172-npm-and-pypi-packages-compromised-in-latest-wave/
- Aggregated package list — https://thecybersecguru.com/news/mini-shai-hulud-npm-worm-affected-packages-list/
- Aikido analysis — https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
- Wiz analysis — https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised

**Detection & IOC writeups**
- StepSecurity (first detection + full IOCs) — https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem
- Snyk advisory — https://snyk.io/blog/tanstack-npm-packages-compromised/
- Semgrep analysis — https://semgrep.dev/blog/2026/tanstack-router-packages-hit-by-coordinated-supply-chain-attack/
- Socket analysis — https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack
- BleepingComputer — https://www.bleepingcomputer.com/news/security/shai-hulud-attack-ships-signed-malicious-tanstack-mistral-npm-packages/
- The Register (cache-poisoning vector) — https://www.theregister.com/cyber-crime/2026/05/12/cache-poisoning-caper-turns-tanstack-npm-packages-toxic/
- GitLab discovery writeup — https://about.gitlab.com/blog/gitlab-discovers-widespread-npm-supply-chain-attack/

**Threat-actor context (TeamPCP)**
- Trivy compromise (March 2026) — same threat actor — supply-chain-playbooks/trivy/
- Bitwarden CLI npm compromise (April 2026) — same threat actor
