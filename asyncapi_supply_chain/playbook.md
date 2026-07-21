# AsyncAPI npm Supply Chain Compromise (July 14, 2026) — Investigation Playbook

Playbook for investigating whether a GitHub org was affected by the **July 14, 2026 compromise of the `@asyncapi` npm organization**. An attacker abused a misconfigured `pull_request_target` workflow to steal a privileged CI token, then let the projects' own **OIDC trusted-publisher** release pipelines publish **five malicious package-versions across four `@asyncapi` packages** — each carrying an obfuscated loader for the **Miasma** multi-stage botnet. The packages together see **~2.25M weekly downloads**; `@asyncapi/specs` is a transitive dependency of much of the AsyncAPI tooling ecosystem, so most exposure is **indirect**.

> **CI/CD platform note:** This playbook targets GitHub Actions. For other CI/CD platforms (GitLab CI, Jenkins, CircleCI, Bitbucket, Azure DevOps), adapt the log-collection commands — the investigation logic is the same: identify references to any affected `@asyncapi` package, collect run logs from the exposure window, search for the malicious versions and the runtime IOCs, and verify lock-file protection.

> **⚠️ Critical — trigger model is IMPORT-time, not install-time.** The injected loader runs the moment a consuming build or application **imports/`require()`s** a poisoned package — not from a lifecycle/`postinstall` hook. **`npm install --ignore-scripts` does NOT neutralize this campaign.** This shifts detection: the payload fires wherever the package is *loaded* — during a codegen/build step that runs the AsyncAPI generator, during tests, or in a running service that imports `@asyncapi/specs` transitively. Look for **runtime egress in build logs** (IPFS gateways, the HTTP C2, Nostr/BitTorrent bootstrap) in addition to install-resolution lines, and treat **deployed artifacts / container images** built or started during the window as in-scope.

> **⚠️ Critical — valid provenance is NOT a safety signal.** The malicious tarballs were published by the legitimate `npm-oidc-no-reply@github.com` release identity and carry **valid npm provenance / SLSA attestations built from unauthorized source commits**. Do not treat "signed / has provenance" as clean here.

---

## Incident Details

The initial vector compromised `asyncapi/generator`: a workflow used `pull_request_target` (which runs in the base repo's context with full access to secrets) but then **checked out the pull request's head code and executed it**. On July 14 the attacker opened **37 pull requests**; one (**PR #2155**, targeting `manual-netlify-preview.yml`) carried obfuscated JavaScript that exfiltrated the npm publish token to `rentry.co`. The attacker then pushed commits under a placeholder git identity and let each repository's real release workflow publish the poisoned packages via npm's **GitHub OIDC trusted-publisher** integration — producing artifacts with valid provenance from unauthorized commits.

The injected loader decodes a second-stage downloader that pulls an encrypted loader (`sync.js`) from **IPFS**, which in turn runs the **Miasma** tasking framework (encrypted bootstrap, persistence, multi-channel C2, resilient peer discovery). Capability modules for credential harvest, encrypted exfiltration, supply-chain propagation (npm/PyPI/Cargo), metamorphic generation, AI-tool poisoning, and sandbox evasion are present; per Microsoft's analysis several were implemented but **disabled in this build**, while the loader, persistence, and C2-discovery paths were active. A **dead-man's-switch** wipes a directory if the stolen token is revoked.

> **"Miasma" branding caveat.** This loader shares branding with the June 3, 2026 "Phantom Gyp" npm worm ([miasma_supply_chain/](../miasma_supply_chain/playbook.md)), but the delivery (OIDC trusted-publisher via a pwn-request, not a `node-gyp`/Bun install chain), the trigger model (import-time, not install-time), the package set, and the C2 infrastructure are **all different**. Researchers note the branding may reflect code reuse, imitation, or deliberate mislabeling. Treat this as a distinct incident with the IOCs below.

### CVE / advisory

- **CVE:** none assigned as of this writing.
- **GitHub advisory:** none published as of this writing (recheck the GitHub Advisory Database for `@asyncapi/*`).
- **Root-cause fix:** the hardened `pull_request_target` workflow (asyncapi/generator PR #2078).

### Affected packages

All five malicious versions have been **unpublished** from the npm registry. Any environment that resolved them from a cache, lock file, or mirror during the window is still in scope.

```bash
# Malicious package-versions (the detection-time source of truth)
export AFFECTED='@asyncapi/generator@3.3.1 @asyncapi/generator-helpers@1.1.1 @asyncapi/generator-components@0.7.1 @asyncapi/specs@6.11.2 @asyncapi/specs@6.11.2-alpha.1'
```

| Package | Malicious version(s) | Injected file (inside the tarball) | Safe version (pre/post-compromise) |
|---|---|---|---|
| `@asyncapi/specs` | `6.11.2`, `6.11.2-alpha.1` | `index.js` | `6.11.1` (last clean) |
| `@asyncapi/generator` | `3.3.1` | `lib/templates/config/validator.js` | `3.3.0` (last clean) |
| `@asyncapi/generator-components` | `0.7.1` | `lib/utils/ErrorHandling.js` | `0.7.0` (last clean; `1.0.0` is a clean post-incident release) |
| `@asyncapi/generator-helpers` | `1.1.1` | `src/utils.js` | `1.1.0` (last clean) |

**High-blast-radius note:** `@asyncapi/specs` (~part of the 2.25M weekly downloads across the org) is a **transitive** dependency of most AsyncAPI generator/parser tooling. A customer who never names `@asyncapi/specs` directly can still resolve it through `@asyncapi/parser`, `@asyncapi/generator`, or a studio/CLI dependency.

### Exposure window

| Event | Time (UTC) |
|---|---|
| First malicious commit pushed (`asyncapi/generator` `next`, `3eab3ec9304aa26081358330491d3cfeb55cc245`) | Jul 14, 06:58:42 |
| First malicious package published (`@asyncapi/generator@3.3.1`, and generator-helpers/components) | Jul 14, ~07:10 |
| `@asyncapi/specs@6.11.2-alpha.1` published | Jul 14, 08:06:20 |
| `@asyncapi/specs@6.11.2` (stable) published | Jul 14, 08:30:09 |
| First downstream fetch observed (Yarn cache) | Jul 14, 08:49:22 |
| All malicious versions unpublished | Jul 14, ~11:12–11:18 |

**Recommended scan window (padded):** `2026-07-14T06:00:00Z` to `2026-07-14T12:30:00Z` — pad each side to catch a build that resolved a malicious version just before the unpublish propagated, and any late-firing runtime beacon.

### Indicators of compromise

| IOC | Value | Where it shows up |
|---|---|---|
| HTTP C2 | `85.137.53.71` — `:8080` (commands), `:8081` (upload), `:8091` (management/proxy) | build-log egress, network/proxy logs, host telemetry |
| Stage-2 loader (IPFS CID) — generator family | `QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9` | build logs, IPFS gateway requests |
| Stage-2 loader (IPFS CID) — specs | `Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf` | build logs, IPFS gateway requests |
| IPFS gateways abused | `ipfs.io`, `dweb.link`, `cloudflare-ipfs.com` | build-log egress, proxy/DNS logs |
| Token exfil endpoint | `rentry.co/elzotebo999` | CI logs of the poisoned generator run, proxy logs |
| Nostr relays (C2 channel) | `wss://relay.damus.io`, `wss://relay.nostr.com/` | network/proxy logs, host telemetry |
| BitTorrent DHT bootstrap (C2 discovery) | `router.bittorrent.com:6881`, `dht.transmissionbt.com:6881` | network logs, host telemetry |
| Ethereum contract (C2 discovery) | `0x12c37A86a0Ed0beBe5d1d6a43E42f07860eAc710` | host telemetry, on-chain lookups |
| Dropped loader file | `sync.js` (see per-OS paths in the [workstation playbook](workstation-playbook.md)) | workstation / self-hosted runner |
| Persistence — Windows | HKCU `...\Run` key `miasma-monitor` | workstation / runner |
| Persistence — Linux | `miasma-monitor.service` | workstation / runner |
| Persistence — service discovery | mDNS service `_miasma._tcp` | LAN telemetry |
| Runtime lock file | `~/.config/.miasma/run/node.lock` | workstation / runner |
| Injected-file SHA-256 — `@asyncapi/specs@6.11.2-alpha.1` `index.js` | `d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7` | tarball forensics |
| Injected-file SHA-256 — `@asyncapi/specs@6.11.2` `index.js` | `9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b` | tarball forensics |
| Injected-file SHA-256 — `@asyncapi/generator@3.3.1` `lib/templates/config/validator.js` | `bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4` | tarball forensics |
| Injected-file SHA-256 — `@asyncapi/generator-components@0.7.1` `lib/utils/ErrorHandling.js` | `082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab` | tarball forensics |
| Injected-file SHA-256 — `@asyncapi/generator-helpers@1.1.1` `src/utils.js` | `34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1` | tarball forensics |
| Malicious git identity | name `Your Name`, email `you@example.com`, GitHub login `invalid-email-address` | commit metadata on affected repos |
| Publishing identity (legit bot, unauthorized commits) | `npm-oidc-no-reply@github.com` | npm publish metadata / provenance |
| Reference malicious commits | `asyncapi/spec-json-schemas` `master`: `36269ce81837` (07:56:11), `689f5b96693a` (08:28:02) | (upstream — for pattern matching) |

> **False-positive caution on shared infrastructure.** `ipfs.io` / `dweb.link` / `cloudflare-ipfs.com` and public Nostr relays appear in legitimate Web3/decentralized-app code and CI. They are IOCs **only as runtime egress from a build step or host that had no prior reason to reach them** — never as a static match in a repo file. Pair any gateway hit with one of the specific CIDs, `85.137.53.71`, or `rentry.co/elzotebo999` before calling it compromise.

### What IS affected

- Any `npm/pnpm/yarn install` that **resolved** one of the malicious versions during the window — direct or **transitive** via `@asyncapi/specs`.
- CI jobs that **ran the AsyncAPI generator, parser, or tests** (i.e. *imported* an affected package) during the window — this is where the import-time payload fires, independent of whether the install step itself looked normal.
- Docker image builds that installed **and** exercised (imported) an affected version during the window — the loader may have run at build time and/or the poisoned code is baked into a layer.
- Running services / long-lived processes that imported `@asyncapi/specs` (transitively) from a dependency tree resolved during the window.
- Developer machines that installed/updated `@asyncapi/*` during the window — see the [workstation playbook](workstation-playbook.md).

### What is NOT affected

- Installs from a committed lock file with `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --immutable` **where the lock file pins `@asyncapi/specs ≤ 6.11.1`, `@asyncapi/generator ≤ 3.3.0`, `@asyncapi/generator-helpers ≤ 1.1.0`, `@asyncapi/generator-components ≤ 0.7.0`** (any pre-window resolution).
- Source-code-only references (a TypeScript `import` from `@asyncapi/*` in a file that was never installed *and* executed during the window).
- Docs, `values.yaml`, Terraform, or other config that names an `@asyncapi` package without installing/importing it.
- Pre-built images pulled (not rebuilt) during the window whose lock state predates it.

### Lock file protection

Lock files (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`) **do protect** if used correctly:

- `npm ci`, `pnpm install --frozen-lockfile`, `yarn install --immutable` install exactly what the lock file pins.
- A lock file generated **before Jul 14 ~07:10 UTC** pins pre-compromise versions, so the malicious tarball is never resolved.

Lock files do **NOT** protect if:
- No lock file is committed.
- CI runs `npm install` / `pnpm install` / `yarn install` without a frozen/immutable flag (can re-resolve floating ranges).
- The lock file was regenerated **during** the window.
- A Dependabot/Renovate PR merged during the window bumped an `@asyncapi/*` dep into a malicious version.

> **`--ignore-scripts` is NOT protection here.** Because the payload runs at import time, disabling lifecycle scripts does nothing. The only install-side defenses are a clean lock file + a frozen installer.

---

## Setup

```bash
export ORG="<your-github-org>"
export SINCE="2026-07-14T06:00:00Z"
export UNTIL="2026-07-14T12:30:00Z"
export LOG_DIR="/tmp/supply-chain-scan-asyncapi"
mkdir -p "$LOG_DIR"
```

**Log caching:** If `$LOG_DIR` already has logs from a previous run, reuse them — skip the download step.

**Write to files, not context:** Results can be large. Write structured evidence (CSV) to `$LOG_DIR` as you go; don't accumulate findings in conversation context.

**Rate limits.** Before scanning a large org, check your GitHub API budget:

```bash
gh api /rate_limit --jq '.resources.core | "\(.remaining)/\(.limit) core remaining (resets \(.reset|todate))"'
gh api /rate_limit --jq '.resources.code_search | "code-search: \(.remaining)/\(.limit) remaining"'
```

Code search: ~30 req/min. REST API: 5,000 req/hr. Log downloads count against REST. Use `xargs -P 10` for parallelism, cache everything to `$LOG_DIR`.

---

## Phase 1: Repo Analysis

**Goal:** For every repo that references an `@asyncapi` package, build a static picture — declared versions, lock state, install/build command — and decide whether it *could* have resolved a malicious version. Window-agnostic.

### 1. Find all references to `@asyncapi`

```bash
q=$(printf '%s' "@asyncapi/" | python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.stdin.read()))")
gh api "search/code?q=${q}+org:${ORG}&per_page=100" \
  --jq '.items[] | "\(.repository.full_name)\t\(.path)"' 2>/dev/null | sort -u > "$LOG_DIR/refs.tsv"
wc -l "$LOG_DIR/refs.tsv"
```

Paginate (`&page=2`, …) if more than 100 results.

> **Positive control — prove the search works before trusting a clean result.** Run the same query for a token you *know* the org uses (e.g. `react`, or a scoped dep you can see in a manifest). A zero-hit query and a *broken* query look identical; a non-zero control hit confirms the pipeline is live.
>
> ```bash
> qc=$(printf '%s' "react" | python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.stdin.read()))")
> gh api "search/code?q=${qc}+org:${ORG}&per_page=1" --jq '.total_count'   # expect > 0
> ```

> **Faster alternative for large orgs (>~50 repos):** shallow-clone every repo and grep locally.
>
> ```bash
> mkdir -p "$LOG_DIR/clones" && cd "$LOG_DIR/clones"
> gh repo list "$ORG" --no-archived --limit 1000 --json nameWithOwner --jq '.[].nameWithOwner' | \
>   xargs -P 10 -I {} bash -c 'git clone --depth 1 --filter=blob:none "git@github.com:{}.git" 2>/dev/null || echo "FAIL: {}"'
> grep -rE --include='package.json' --include='package-lock.json' --include='pnpm-lock.yaml' --include='yarn.lock' \
>   '@asyncapi/' . > "$LOG_DIR/refs-from-local-clone.txt"
> wc -l "$LOG_DIR/refs-from-local-clone.txt"
> ```

### 2. Classify each reference

| File pattern | Category | Risk |
|---|---|---|
| `package.json` | npm manifest | **HIGH** — check spec range vs malicious versions |
| `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` | Lock file | **CRITICAL** — check pinned version against the malicious list |
| `Dockerfile` | Docker build | **HIGH** if it installs **and** runs `@asyncapi` tooling |
| `.github/workflows/*.yml` | CI workflow | **CHECK** — does it install/run codegen with `@asyncapi/*`? |
| `*.ts/*.tsx/*.js/*.jsx` | Source code | **NOT AFFECTED by itself** — but note it if the file is executed in a windowed build (import-time trigger) |
| `*.md`, `values.yaml`, `*.tf` | Docs / infra | **NOT AFFECTED** |

### 3. Extract version data per repo

For every repo with an `@asyncapi` dep, capture the manifest spec, the locked version, and the install/build command:

```bash
# package.json — @asyncapi specs
gh api "repos/${ORG}/<repo>/contents/package.json" --jq '.content' | base64 -d | python3 -c "
import sys,json
d=json.load(sys.stdin)
for section in ('dependencies','devDependencies','optionalDependencies','peerDependencies'):
    for k,v in d.get(section,{}).items():
        if k.startswith('@asyncapi/'): print(f'{section}: {k} = {v}')
"

# package-lock.json — resolved @asyncapi versions
gh api "repos/${ORG}/<repo>/contents/package-lock.json" --jq '.content' | base64 -d | python3 -c "
import sys,json
d=json.load(sys.stdin)
for k,v in d.get('packages',{}).items():
    name=k.split('node_modules/')[-1]
    if name.startswith('@asyncapi/'): print(f'{name}: {v.get(\"version\")}')
"

# pnpm / yarn
gh api "repos/${ORG}/<repo>/contents/pnpm-lock.yaml" --jq '.content' | base64 -d | grep -E "^\s+'?@asyncapi/"
gh api "repos/${ORG}/<repo>/contents/yarn.lock"       --jq '.content' | base64 -d | grep -B1 -A2 "^\"?@asyncapi/"

# Install / build command
gh api "repos/${ORG}/<repo>/contents/.github/workflows" --jq '.[].path' | while read wf; do
  gh api "repos/${ORG}/<repo>/contents/${wf}" --jq '.content' | base64 -d | \
    grep -iE "npm ci|npm install|pnpm install|yarn install|yarn$|asyncapi generate|ag |@asyncapi/cli"
done
```

### 4. Write the repo evidence table

Write `$LOG_DIR/evidence-repos.csv`:

```
repo,path,source_type,manifest_spec,spec_in_range,has_lockfile,lockfile_version,lock_protects,install_command,imports_at_build,can_be_compromised
```

| Column | What to write |
|---|---|
| `source_type` | `manifest` / `lockfile` / `ci-workflow` / `dockerfile` / `source` |
| `manifest_spec` | Exact specifier (`^6.11.0`, `~3.3.0`, `latest`). For transitive: `transitive` |
| `spec_in_range` | `yes (allows 6.11.2)`, `yes (allows 3.3.1)`, or `no (reason)`. `^6.11.0`/`^6.11.1` both allow `6.11.2`; `~6.11.1` also allows `6.11.2`; an exact `6.11.1` does not |
| `has_lockfile` | `yes (package-lock.json)` / `yes (pnpm-lock.yaml)` / `yes (yarn.lock)` / `no` |
| `lockfile_version` | Exact pinned `@asyncapi/*` version(s); `none` if no lock file |
| `lock_protects` | `yes` if pinned version is not a malicious value; `no` if it is |
| `install_command` | `npm ci`, `pnpm install --frozen-lockfile`, `yarn install (no flags)`, etc. |
| `imports_at_build` | `yes` if a windowed job runs codegen/tests that `require()` the package (import-time trigger surface); `no`/`unknown` otherwise |
| `can_be_compromised` | `no` if lock protects AND install respects lock AND no windowed import; `yes` otherwise |

No blank cells; add parentheticals (`yes (allows 6.11.2)`).

---

## Phase 2: CI Run Analysis

**Why this phase is critical:** Phase 1 only finds repos that name `@asyncapi` by hand. `@asyncapi/specs` is pulled transitively by other AsyncAPI tooling, and — because the trigger is import-time — the decisive evidence is **what a job did when it loaded the package**, visible only in the run logs.

### 1. Find runs during the window

```bash
gh api "/orgs/${ORG}/repos" --paginate --jq '.[].name' | while read repo; do
  gh api "repos/${ORG}/${repo}/actions/runs?created=${SINCE}..${UNTIL}&per_page=100" \
    --jq ".workflow_runs[] | \"${repo}|\(.id)|\(.created_at)|\(.name)|\(.conclusion)\"" 2>/dev/null
done > "$LOG_DIR/all_runs.txt"
echo "Total runs to scan: $(wc -l < "$LOG_DIR/all_runs.txt")"
```

### 2. Download run logs in parallel

Skip if `$LOG_DIR` already has logs.

```bash
cat "$LOG_DIR/all_runs.txt" | while IFS='|' read repo run_id rest; do echo "$repo $run_id"; done | \
  xargs -P 10 -L 1 bash -c \
  'gh run view "$1" --repo "${ORG}/$0" --log > "${LOG_DIR}/run-$1.log" 2>/dev/null && echo "OK: $0 $1" || echo "FAIL: $0 $1"'
```

### 3. Scan logs — resolution AND runtime egress

GitHub Actions log lines are tab-prefixed (`<workflow>\t<step>\t<timestamp> <content>`) — do **not** anchor patterns with `^`.

```bash
# (a) Malicious versions resolved / installed
echo "=== @asyncapi malicious versions ==="
grep -rlnE "@asyncapi/generator[^-].*3\.3\.1|@asyncapi/generator-helpers.*1\.1\.1|@asyncapi/generator-components.*0\.7\.1|@asyncapi/specs.*6\.11\.2(-alpha\.1)?" "$LOG_DIR"/run-*.log 2>/dev/null

# (b) Any @asyncapi resolution at all (triage manually against the version list)
echo "=== any @asyncapi resolution ==="
grep -rlniE "added @asyncapi/|@asyncapi/[a-z-]+@|registry.npmjs.org/@asyncapi|Downloading @asyncapi" "$LOG_DIR"/run-*.log 2>/dev/null

# (c) RUNTIME IOCs — the import-time payload firing inside a build step
echo "=== stage-2 IPFS CIDs ==="
grep -rlF "QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9" "$LOG_DIR"/run-*.log 2>/dev/null
grep -rlF "Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf" "$LOG_DIR"/run-*.log 2>/dev/null

echo "=== HTTP C2 / token exfil ==="
grep -rlF "85.137.53.71" "$LOG_DIR"/run-*.log 2>/dev/null
grep -rliE "rentry\.co/elzotebo999|rentry\.co" "$LOG_DIR"/run-*.log 2>/dev/null

echo "=== decentralized C2 channels ==="
grep -rliE "ipfs\.io|dweb\.link|cloudflare-ipfs\.com|relay\.damus\.io|relay\.nostr\.com|router\.bittorrent\.com|dht\.transmissionbt\.com" "$LOG_DIR"/run-*.log 2>/dev/null

echo "=== dropped loader / persistence names ==="
grep -rliE "NodeJS/sync\.js|miasma-monitor|_miasma\._tcp|\.miasma/run/node\.lock" "$LOG_DIR"/run-*.log 2>/dev/null
```

> **Why runtime IOCs matter more here than install lines.** A `yarn install --immutable` (or `npm ci`) that satisfies the lock file produces **zero per-package output**, so a version grep can be clean on a run that still *imported* the package downstream. The high-confidence signal for this campaign is **egress to the IPFS CIDs / `85.137.53.71` / `rentry.co` during a build step** — that only happens if the malicious code executed.

### 4. Classify hits as real vs false positive

**Real signal:**
- `added @asyncapi/<pkg>@<malicious-version>` / `Downloading @asyncapi/...` resolving a malicious version.
- Any build step reaching an IPFS CID above, `85.137.53.71`, `rentry.co/elzotebo999`, or the Nostr/BitTorrent bootstrap hosts.

**False positives (ignore):**
- Source-code imports echoed in logs (`import ... from '@asyncapi/parser'`), TypeScript errors, SAST/dependency-review output listing the package.
- Branch names (`feat/upgrade-asyncapi`, `dependabot/npm_and_yarn/@asyncapi/...`).
- Docs/Helm/Terraform naming the package.
- IPFS/Nostr hostnames in a repo that is *legitimately* a Web3/decentralized app (verify against a CID or `85.137.53.71` before escalating).

### 5. Write the CI runs evidence table

Write `$LOG_DIR/evidence-ci-runs.csv`:

```
repo,run_id,created_at,workflow,platform,install_command,log_line,version_installed,imported_at_runtime,iocs_found,ci_compromised
```

| Column | What to write |
|---|---|
| `version_installed` | Exact `@asyncapi/*` version resolved, or `not installed` / `n/a (frozen, see lock)` |
| `imported_at_runtime` | `yes` if the run also *ran* the tooling (codegen/tests) that imports the package; `no`/`unknown` |
| `iocs_found` | `yes (which IOC)` (CID, `85.137.53.71`, `rentry.co`, …) or `no` |
| `ci_compromised` | `clean` / `compromised` / `clean (component not installed)` |

One row per install/build step; no blank cells.

### 6. Audit `pull_request_target` in your own org (same root cause)

The attack succeeded because a `pull_request_target` workflow checked out and ran PR-head code with secrets. Audit your org for the identical foot-gun:

```bash
gh api "search/code?q=%22pull_request_target%22+org:${ORG}+extension:yml&per_page=100" \
  --jq '.items[] | "\(.repository.full_name)\t\(.path)"' | sort -u > "$LOG_DIR/prt-workflows.tsv"
```

For each hit, verify whether it `actions/checkout`s the PR **head** ref (`github.event.pull_request.head.*`) and then runs build/preview steps with repo secrets in scope. That is the exploitable pattern — record findings for Phase 5 hardening even if not currently abused.

---

## Phase 3: Runtime & Deployed-Artifact Investigation

Because the payload fires at import time, an affected version can be running in a **deployed service or a built container image**, not just a CI log. Check anything built or (re)started during and after the window.

### 3a. Container images

```bash
# Images built on the exposure date (local Docker)
docker images --format '{{.Repository}}:{{.Tag}} {{.CreatedAt}}' 2>/dev/null | grep "2026-07-14"

# Inspect an image's resolved @asyncapi versions without running it
IMG=<image:tag>
container=$(docker create "$IMG")
docker export "$container" | tar -x --wildcards -O '*/package-lock.json' '*/package.json' 2>/dev/null | \
  grep -E "@asyncapi/(specs|generator|generator-helpers|generator-components)" | head
docker rm "$container" >/dev/null
```

Rebuild any suspect image with `docker build --no-cache` after remediation.

### 3b. Network egress from runtime hosts

Check firewall / proxy / DNS / VPC-flow logs from any host that ran CI or served traffic **from the window forward at least 7 days** (persistence + delayed beacons):

| IOC | Where to search |
|---|---|
| Outbound to `85.137.53.71` (:8080/:8081/:8091) | proxy, NetFlow, VPC Flow Logs, EDR |
| DNS/HTTPS to `ipfs.io`, `dweb.link`, `cloudflare-ipfs.com` **carrying a CID above** | DNS/proxy logs |
| HTTPS to `rentry.co/elzotebo999` | proxy logs |
| WSS to `relay.damus.io`, `relay.nostr.com` | proxy/firewall logs |
| UDP to `router.bittorrent.com:6881`, `dht.transmissionbt.com:6881` | firewall/NetFlow |
| mDNS advertising `_miasma._tcp` | LAN telemetry |

**Splunk example:**
```
index=proxy (dest_ip="85.137.53.71" OR url="*rentry.co/elzotebo999*" OR url="*QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9*" OR url="*Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf*")
| stats count by src_ip, dest_ip, url
```

A confirmed connection to `85.137.53.71`, a CID fetch, or a `rentry.co/elzotebo999` POST from your infrastructure = treat that host as compromised and rotate everything it could reach.

---

## Phase 4: Workstation Investigation

Developer machines (and self-hosted runners) that installed/updated `@asyncapi/*` and then ran the generator/tests during the window may have executed the loader and installed persistence (`sync.js` + `miasma-monitor`). This has a distinct, per-OS structure — run the dedicated **[workstation-playbook.md](workstation-playbook.md)** on each such machine.

---

## Phase 5: Present Results & Harden (User Approval Required)

### Deliverables

1. `evidence-repos.csv` — dependency posture per repo (window-agnostic).
2. `evidence-ci-runs.csv` — what happened during the window: install/build command, version, runtime IOCs, verdict.
3. `prt-workflows.tsv` — your own `pull_request_target` exposure (hardening input).
4. **Executive summary** — verdict (`clean` / `compromised`); repos scanned + runs analyzed; whether any malicious version resolved; whether any runtime IOC (CID / `85.137.53.71` / `rentry.co`) was contacted; workstation/runner persistence findings; own-org `pull_request_target` exposure; one-sentence bottom line.

### Remediation — only if compromised (rotate BEFORE scrubbing)

1. **Quarantine** affected workstations/self-hosted runners; drain and terminate ephemeral runners.
2. **Snapshot** persistence artifacts, `sync.js`, `node.lock`, shell history, `~/.npmrc`, `~/.gitconfig` before cleanup.
3. **Rotate every secret** accessible to any CI workflow that ran during the window and to any host that showed a runtime IOC: npm tokens (`~/.npmrc`, automation/granular tokens), GitHub PATs / App-installation tokens / OIDC-derived cloud creds, AWS/GCP/Azure keys, SSH keys, signing keys, and browser-saved sessions (npm, GitHub, cloud consoles). **The stolen token was an npm publish token** — prioritize npm publish credentials and re-issue with 2FA.
4. **Remove persistence** (see the [workstation playbook](workstation-playbook.md) for the exact `miasma-monitor` / `sync.js` removal commands per OS). **Remove persistence before the dead-man's-switch matters** — but the switch keys off token *revocation*, so do step 4 alongside/just after rotating the specific stolen token, and preserve a snapshot first.
5. **Purge caches & `node_modules`:** `npm cache clean --force` / `pnpm store prune` / `yarn cache clean`; `rm -rf node_modules`.
6. **Rebuild affected Docker images** with `--no-cache`.
7. **Block C2 at the edge:** `85.137.53.71`, `rentry.co/elzotebo999`, and the specific IPFS CIDs; alert (don't blanket-block) on `ipfs.io`/Nostr/BitTorrent bootstrap unless your environment never uses them.
8. **Re-image** any workstation/runner where `miasma-monitor` was active — in-place cleaning may miss a foothold.

### Hardening — wherever `can_be_compromised` = yes

| Attack surface | Fix |
|---|---|
| No lock file committed | Commit `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` |
| CI uses non-frozen install | Switch to `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --immutable` |
| Loose `^`/`~`/`latest` on `@asyncapi/*` | Pin exact safe versions (`@asyncapi/specs@6.11.1`, `@asyncapi/generator@3.3.0`, `@asyncapi/generator-helpers@1.1.0`, `@asyncapi/generator-components@1.0.0`); regenerate the lock on a clean host |
| Relying on provenance/SLSA as a trust gate | Do **not** — the malicious tarballs had valid provenance from unauthorized commits. Prefer a version allow-list + a hold-back window (install only versions ≥ N hours old) |
| `pull_request_target` checking out PR head with secrets | Refactor so untrusted code never runs with repo secrets — use `pull_request` (no secrets) for build/preview, or split into privileged + unprivileged jobs and pass only sanitized artifacts across |
| Docker base images pinned by mutable tag | Pin to digest (`@sha256:...`) |
| Long-lived npm publish tokens / trusted-publisher without guardrails | Require 2FA on publish; scope OIDC trusted-publisher to protected branches/tags only; review who can trigger release workflows |
| No verifying npm proxy | Stand up Verdaccio / JFrog / GitHub Packages with an allow-after-N-hours policy |

### Upgrade path

Pin to the last clean release per package and regenerate the lock file on a known-clean host:

- `@asyncapi/specs` → `6.11.1`
- `@asyncapi/generator` → `3.3.0`
- `@asyncapi/generator-helpers` → `1.1.0`
- `@asyncapi/generator-components` → `1.0.0` (clean post-incident) or `0.7.0` (last pre-compromise)

---

## Pitfalls & Fixes

Seed this section from your first live run and grow it each time.

1. **Don't conclude "no install happened" from "no package names in logs."** `npm ci` and `yarn install --immutable` are silent when the lock is satisfied. Verify the resolved version from the committed lock file, and rely on **runtime IOC egress** as the decisive signal for this import-time campaign.
2. **GitHub Actions log lines are tab-prefixed** — anchor patterns with `\b`, not `^`, or you'll miss mid-line IOCs.
3. **`ipfs.io` / Nostr / BitTorrent hosts are shared infrastructure.** A hit is only meaningful paired with a specific CID, `85.137.53.71`, or `rentry.co/elzotebo999`. A Web3 repo legitimately using an IPFS gateway is not compromise.
4. **`@asyncapi/specs` arrives transitively.** A repo can be exposed without ever naming it — scan CI logs of jobs that run AsyncAPI codegen/parse even when Phase 1 found no direct manifest entry.
5. **`curl -sf` swallows 404s into empty stdout**, crashing a downstream `json.load`. Check the HTTP status separately (`curl -s -o /dev/null -w '%{http_code}'`) or wrap parsing in try/except.
6. **AI-agent self-pollution.** If you run this playbook through an AI coding agent, its own session transcript will contain every IOC string above. When scanning AI-agent conversation logs (workstation playbook, Check 8), **exclude the current session's data dir** — see the workstation playbook's self-pollution note.

---

## References

- Microsoft Threat Intelligence — "Unpacking the AsyncAPI npm supply chain compromise and import-time payload delivery" (primary research, IOCs, timeline) — https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
- StepSecurity — "Coordinated AsyncAPI Supply Chain Attack: Miasma RAT via Compromised CI/CD Pipelines" (CI/CD detection + IOCs) — https://www.stepsecurity.io/blog/compromised-next-branch-pushes-malicious-asyncapi-generator-generator-helpers-and-generator-components-to-npm
- Socket.dev — "Compromised npm Packages in the AsyncAPI Namespace" — https://socket.dev/blog/asyncapi-supply-chain-attack
- The Hacker News — "Compromised AsyncAPI npm Packages Deliver Multi-Stage Botnet Malware" — https://thehackernews.com/2026/07/compromised-asyncapi-npm-packages.html
- Unit 42 (Palo Alto) — npm threat-landscape tracker (updated Jul 15) — https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/
