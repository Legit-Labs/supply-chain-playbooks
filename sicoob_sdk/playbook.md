# Malicious `Sicoob.Sdk` NuGet Package — Investigation Playbook

Playbook for investigating whether a GitHub org was affected by the malicious **`Sicoob.Sdk` NuGet package** (versions **2.0.0–2.0.4**), which masqueraded as an official C# SDK for **Sicoob** (a large Brazilian cooperative financial system) and covertly exfiltrated **banking client IDs and PFX certificates** to a hardcoded third-party **Sentry** endpoint. The same threat actor (`vpmdhaj`) concurrently published **~14 malicious npm packages** that steal cloud credentials (AWS, HashiCorp Vault, npm tokens, CI/CD secrets) via typosquatting + `preinstall` hooks — this playbook covers both.

> **Two distinct trigger models — read this first.**
> - **`Sicoob.Sdk` (NuGet) fires at _application runtime_, not install time.** The theft happens when code instantiates `SicoobClient(clientId, pfxPath, pfxPassword)`. So NuGet lock files and `--ignore-scripts`-style install controls **do not** prevent the exfiltration — if the package is referenced and the app ran with a real PFX, treat the certificate as compromised. Detection centres on *source usage* and *deployed artifacts*, not just install logs.
> - **The `vpmdhaj` npm packages fire at _install time_** via `preinstall` hooks (typosquatting). Here lock files and `--ignore-scripts` **do** help, and the detection mirrors a normal npm install-time investigation.

> **CI/CD platform note:** Commands target GitHub Actions + the .NET CLI. For GitLab CI / Azure DevOps / Jenkins, adapt log collection — the logic is identical: find references to the malicious packages, collect restore/build/run logs from the window, search for the package and its IOCs, and verify lock state.

---

## Incident Details

`Sicoob.Sdk` presented itself as the official Sicoob banking SDK and was given a veneer of legitimacy: a clean public GitHub repository, and amplification by Google's Search AI Mode surfacing it as a real library. The malicious behaviour lived only in the published NuGet package, not the repo.

When a developer instantiates the client:

```csharp
var client = new SicoobClient(clientId, pfxFilePath, pfxPassword);
```

the package:

1. **Exfiltrates the PFX certificate** — reads the PFX file from disk, **Base64-encodes** its bytes, and transmits the supplied **client ID**, **PFX password**, and the encoded PFX to a **hardcoded third-party Sentry endpoint**.
2. **Captures Boleto data** — sends raw Sicoob Boleto API responses (transaction details, payment status, amounts, due dates, payer/payee data) to a separate Sentry path.
3. **Enables impersonation** — with a stolen PFX + client ID + password, an attacker can impersonate the victim's Sicoob API integration, enabling banking fraud and unauthorized operations.

**Concurrent npm campaign (same actor `vpmdhaj`):** ~14 typosquatting npm packages with `preinstall` hooks that harvest AWS keys, HashiCorp Vault tokens, npm tokens, and CI/CD secrets. These run at install time on any developer/CI that pulls them.

### CVE / advisory

- **CVE:** none assigned. `Sicoob.Sdk` was **blocked/removed by NuGet** following responsible disclosure.
- **Primary writeup:** The Hacker News — https://thehackernews.com/2026/05/malicious-sicoob-nuget-steals-banking.html

### Affected packages

**NuGet — `Sicoob.Sdk`:** versions **`2.0.0`, `2.0.1`, `2.0.2`, `2.0.3`, `2.0.4`**.

**npm (same actor, cloud-credential typosquats — wildcard `*` = all published versions):**

| | |
|---|---|
| Scoped | `@vpmdhaj/devops-tools`, `@vpmdhaj/elastic-helper`, `@vpmdhaj/opensearch-setup`, `@vpmdhaj/search-setup` |
| Unscoped | `app-config-utility`, `elastic-opensearch-helper`, `env-config-manager`, `opensearch-config-utility`, `opensearch-security-scanner`, `opensearch-setup`, `opensearch-setup-tool`, `search-cluster-setup`, `search-engine-setup`, `vpmdhaj-opensearch-setup`, `forge-jsx`, `forge-jsxy` |

> **Detection regex (npm names):**
> ```
> @vpmdhaj/|\b(app-config-utility|elastic-opensearch-helper|env-config-manager|opensearch-config-utility|opensearch-security-scanner|opensearch-setup|opensearch-setup-tool|search-cluster-setup|search-engine-setup|vpmdhaj-opensearch-setup|forge-jsxy?)\b
> ```

### Exposure window

The advisory does not publish exact start/end timestamps. **Treat the window as: first publish of `Sicoob.Sdk@2.0.0` → the NuGet takedown** (disclosure ~ late May 2026; the feed item is dated 2026-05-31). For the runtime-trigger risk, the relevant question is broader than the window: **has any build referencing `Sicoob.Sdk@2.0.x` ever been deployed and run with a real PFX?** — if yes, the certificate is exposed regardless of when the package was installed.

### Indicators of compromise

| IOC | Value | Where it shows up |
|---|---|---|
| Malicious NuGet package | `Sicoob.Sdk` `2.0.0`–`2.0.4` | `.csproj`, `packages.config`, `Directory.Packages.props`, `packages.lock.json`, NuGet cache, deployed `Sicoob.Sdk.dll` |
| Runtime trigger | `new SicoobClient(...)` instantiated with a client ID + PFX path + PFX password | C# source, decompiled binaries |
| Exfil channel | Outbound to a **Sentry ingest endpoint** (`*.ingest.sentry.io` / `sentry.io`) that is **not your own Sentry project**, carrying Base64 PFX + client ID + password | network/proxy logs, runtime egress |
| Data captured | Base64-encoded PFX bytes, PFX password, Sicoob client ID, raw Boleto API responses | exfil payloads |
| npm typosquats | `@vpmdhaj/*` + the unscoped names above, with `preinstall` hooks | `package.json`, install logs, npm cache |
| Stolen by npm side | AWS keys, HashiCorp Vault tokens, npm tokens, CI/CD secrets | env / proxy logs during npm install |
| Threat actor | `vpmdhaj` (npm publisher) | npm registry metadata |

> **Extract the exact Sentry DSN if you have a sample.** Decompile a cached `Sicoob.Sdk.dll` (ILSpy / dnSpy / `dotnet-ildasm`) and grep the strings for `ingest.sentry.io`, `sentry.io`, and `https://` literals to recover the precise exfil URL/DSN — then search network logs for that exact host. The package being pulled from NuGet does not remove copies already in your caches or deployed artifacts.

### What IS affected

- Any project that **references** `Sicoob.Sdk@2.0.0`–`2.0.4` in a NuGet manifest, **and** whose code path that instantiates `SicoobClient` with a real PFX **has run** (locally, in CI, or in production) → **PFX, password, and client ID are compromised.**
- Any deployed artifact / container image that **bundles** `Sicoob.Sdk.dll` 2.0.x and runs the banking integration.
- Any developer/CI host that ran `npm install` of a `vpmdhaj` typosquat → cloud/CI credentials on that host are compromised (install-time `preinstall` hook).

### What is NOT affected

- Projects that reference `Sicoob.Sdk@2.0.x` but where the `SicoobClient(...)` path **never executed with a real PFX** (e.g. compiled but never run, or only run in tests with a dummy cert) — still **remove the package**, but certificate exposure is limited. Verify the code path before clearing.
- Projects pinned (lock + `--locked-mode`) to a **clean** `Sicoob.Sdk` version that predates 2.0.0, if such a legitimate version exists — confirm against the official Sicoob source, as the whole package may be attacker-controlled.
- npm typosquats installed with `--ignore-scripts` **and** never otherwise executed — install-time hook didn't fire (verify; still remove).
- Source-only references / docs that name the packages without restoring or running them.

### Lock file protection

| Ecosystem | Does locking help? |
|---|---|
| **NuGet (`Sicoob.Sdk`)** | A `packages.lock.json` with `dotnet restore --locked-mode` (or `<RestoreLockedMode>true</RestoreLockedMode>`) prevents an *unexpected* resolution to a malicious version. **But it does not stop the runtime exfiltration** if the locked version is itself 2.0.0–2.0.4 — the theft is at runtime, not restore. Locking only helps by pinning you to a known-clean version. |
| **npm (`vpmdhaj` typosquats)** | `package-lock.json` + `npm ci` (frozen) prevents resolving a typosquat that isn't already locked. `--ignore-scripts` **does** block the `preinstall` exfil hook (unlike a runtime trigger). |

---

## Setup

```bash
export ORG="<your-github-org>"
# Sicoob.Sdk 2.0.0 first-publish → NuGet takedown (no exact timestamps published)
export SINCE="2026-05-01T00:00:00Z"
export UNTIL="2026-06-01T00:00:00Z"
export LOG_DIR="/tmp/supply-chain-scan-sicoob"
mkdir -p "$LOG_DIR"
```

**Write to files, not context.** Cache logs in `$LOG_DIR`. Check rate limits before scanning a large org:

```bash
gh api /rate_limit --jq '.resources.core | "\(.remaining)/\(.limit) (resets \(.reset|todate))"'
gh api /rate_limit --jq '.resources.code_search | "code-search: \(.remaining)/\(.limit)"'
```

For orgs over ~50 repos, shallow-clone and grep locally (recipe in Phase 1).

---

## Phase 1: Repo Analysis

**Goal:** Find every repo that references `Sicoob.Sdk` (NuGet) or a `vpmdhaj` npm typosquat, what versions are declared/locked, and — for NuGet — **whether the `SicoobClient` runtime path is actually used**.

### 1. Find NuGet references to `Sicoob.Sdk`

```bash
# Across all NuGet manifest shapes
for q in "Sicoob.Sdk"; do
  enc=$(printf '%s' "$q" | python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.stdin.read()))")
  gh api "search/code?q=${enc}+org:${ORG}&per_page=100" \
    --jq '.items[] | "\(.repository.full_name)\t\(.path)"' 2>/dev/null
done | sort -u > "$LOG_DIR/nuget-refs.tsv"
cat "$LOG_DIR/nuget-refs.tsv"
```

NuGet manifest shapes to expect:
- `*.csproj` / `*.fsproj` / `*.vbproj` → `<PackageReference Include="Sicoob.Sdk" Version="2.0.x" />`
- `packages.config` (legacy) → `<package id="Sicoob.Sdk" version="2.0.x" />`
- `Directory.Packages.props` (central package management) → `<PackageVersion Include="Sicoob.Sdk" Version="2.0.x" />`
- `packages.lock.json` (NuGet lock) → `"Sicoob.Sdk": { "resolved": "2.0.x" }`
- `paket.dependencies` / `paket.lock`

### 2. Find the runtime trigger (`SicoobClient` usage)

This is the highest-signal NuGet check — references without usage are lower-risk; usage means the PFX may have been exfiltrated.

```bash
for q in "SicoobClient" "new SicoobClient"; do
  enc=$(printf '%s' "$q" | python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.stdin.read()))")
  echo "=== $q ==="
  gh api "search/code?q=${enc}+org:${ORG}&per_page=100" \
    --jq '.items[] | "\(.repository.full_name)\t\(.path)"' 2>/dev/null
  sleep 2
done | sort -u > "$LOG_DIR/sicoobclient-usage.tsv"
cat "$LOG_DIR/sicoobclient-usage.tsv"
```

### 3. Find the `vpmdhaj` npm typosquats

```bash
for pkg in "@vpmdhaj" app-config-utility elastic-opensearch-helper env-config-manager \
           opensearch-config-utility opensearch-security-scanner opensearch-setup \
           opensearch-setup-tool search-cluster-setup search-engine-setup \
           vpmdhaj-opensearch-setup forge-jsx forge-jsxy; do
  enc=$(printf '%s' "$pkg" | python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.stdin.read()))")
  gh api "search/code?q=${enc}+org:${ORG}&per_page=100" \
    --jq '.items[] | "'"$pkg"'\t\(.repository.full_name)\t\(.path)"' 2>/dev/null
  sleep 2
done | sort -u > "$LOG_DIR/npm-refs.tsv"
cat "$LOG_DIR/npm-refs.tsv"
```

> **Large-org alternative:** shallow-clone and grep locally.
> ```bash
> mkdir -p "$LOG_DIR/clones" && cd "$LOG_DIR/clones"
> gh repo list "$ORG" --no-archived --limit 1000 --json nameWithOwner --jq '.[].nameWithOwner' | \
>   xargs -P 10 -I {} bash -c 'git clone --depth 1 --filter=blob:none "git@github.com:{}.git" 2>/dev/null || echo "FAIL: {}"'
> # NuGet refs + runtime usage
> grep -rilE 'Sicoob\.Sdk|SicoobClient' --include='*.csproj' --include='packages.config' \
>   --include='Directory.Packages.props' --include='packages.lock.json' --include='*.cs' . > "$LOG_DIR/nuget-local.txt"
> # npm typosquats
> grep -rE '@vpmdhaj/|app-config-utility|opensearch-(setup|config-utility|security-scanner)|env-config-manager|forge-jsxy?' \
>   --include='package.json' --include='package-lock.json' --include='yarn.lock' --include='pnpm-lock.yaml' . > "$LOG_DIR/npm-local.txt"
> ```

### 4. Classify each reference

| File | Category | Risk |
|---|---|---|
| `*.csproj` / `packages.config` / `Directory.Packages.props` | NuGet manifest | **HIGH** — check version vs 2.0.0–2.0.4 |
| `packages.lock.json` | NuGet lock | **CRITICAL** — confirm resolved `Sicoob.Sdk` version |
| `*.cs` with `new SicoobClient(...)` | Runtime usage | **CRITICAL** — PFX likely exfiltrated if run with a real cert |
| `package.json` | npm manifest | **HIGH** — typosquat referenced |
| `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` | npm lock | **CRITICAL** — typosquat resolved |
| `Dockerfile` | build | **HIGH** if it `dotnet restore`/`publish` or `npm install`s the above |
| `*.md`, docs | docs | **NOT AFFECTED** |

### 5. Write the repo evidence table

Write `$LOG_DIR/evidence-repos.csv`:

```
repo,path,ecosystem,package,declared_version,version_affected,has_lock,locked_version,runtime_usage,can_be_compromised
```

| Column | What to write |
|---|---|
| `ecosystem` | `nuget` / `npm` |
| `package` | `Sicoob.Sdk` / `@vpmdhaj/...` / etc. |
| `declared_version` | Version specifier as written; `transitive` if indirect |
| `version_affected` | `yes (2.0.3)` / `no (reason)` |
| `has_lock` | `yes (packages.lock.json)` / `yes (package-lock.json)` / `no` |
| `locked_version` | Resolved version, or `none` |
| `runtime_usage` | (NuGet only) `yes (new SicoobClient in <file>)` / `referenced-not-used` / `n/a (npm)` |
| `can_be_compromised` | `yes` if affected version referenced AND (NuGet: runtime usage present) or (npm: install hook can run); else `no` |

---

## Phase 2: Build / Restore & CI Log Analysis

### 1. Find runs during the window

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

### 3. Scan logs

```bash
# NuGet restore of the malicious package
echo "=== Sicoob.Sdk restore ==="
grep -rlinE "Sicoob\.Sdk" "$LOG_DIR"/run-*.log 2>/dev/null
grep -rlinE "Installed Sicoob\.Sdk 2\.0\.[0-4]|Restored .*Sicoob\.Sdk.*2\.0\.[0-4]|GET https://api\.nuget\.org/.*sicoob\.sdk" "$LOG_DIR"/run-*.log 2>/dev/null

# npm typosquat install + preinstall hook output
echo "=== vpmdhaj npm typosquats ==="
grep -rlinE "@vpmdhaj/|app-config-utility|opensearch-(setup|config-utility|security-scanner)|env-config-manager|forge-jsxy?" "$LOG_DIR"/run-*.log 2>/dev/null
grep -rlinE "preinstall|node .*postinstall|npm WARN .*preinstall" "$LOG_DIR"/run-*.log 2>/dev/null

# Exfil signal: unexpected Sentry traffic in build logs
echo "=== Sentry exfil endpoint ==="
grep -rlinE "ingest\.sentry\.io|sentry\.io/api/[0-9]+/store" "$LOG_DIR"/run-*.log 2>/dev/null
```

### 4. Classify hits

- **Real:** `Restored .../Sicoob.Sdk 2.0.x`, `Installed Sicoob.Sdk`, npm `added @vpmdhaj/...`, `preinstall` script output from a typosquat, or any outbound to a Sentry host that isn't your project.
- **False positives:** source references in build diagnostics, SAST/dependency-scan output naming the package, branch names, your own legitimate Sentry SDK traffic (verify the DSN/project).

### 5. Write `$LOG_DIR/evidence-ci-runs.csv`

```
repo,run_id,created_at,workflow,step,ecosystem,package_version,restored_or_installed,iocs_found,ci_compromised
```
One row per restore/install execution; verdict `clean` / `compromised` / `clean (not restored)`.

---

## Phase 3: Network Investigation

The defining exfil channel is **Sentry**. The npm typosquats add **cloud-credential exfil**.

| Signal | Where to search |
|---|---|
| Outbound to `*.ingest.sentry.io` / `sentry.io` from build hosts or app runtime that is **not your own Sentry project** | Proxy, NetFlow, VPC Flow Logs, DNS logs |
| The exact Sentry DSN/host recovered by decompiling `Sicoob.Sdk.dll` (see IOC note) | Proxy / SIEM — search the literal host |
| Anomalous AWS STS / Vault / npm-registry auth from a host that ran a `vpmdhaj` install | CloudTrail, Vault audit log, npm token usage |
| Egress carrying Base64 blobs (PFX) to a non-Sicoob, non-corporate endpoint | DLP / proxy body inspection if available |

**Where:** AWS VPC Flow Logs + Route 53 Resolver logs + CloudTrail; GCP/Azure equivalents; on-prem firewall/proxy/DNS; SIEM. **Time window:** from first possible install of the package forward **at least 30 days** — runtime exfil recurs every time the integration runs, so it is not confined to a short burst.

**Example (Splunk):**
```
index=proxy (url="*ingest.sentry.io*" OR url="*sentry.io/api/*") NOT sentry_project="<your-project-id>"
| stats count by src_ip, url, _time
```

---

## Phase 4: Runtime & Host Investigation

Because `Sicoob.Sdk` fires at **runtime**, check **deployed artifacts and hosts**, not just source.

### 4a. Deployed binaries & container images

```bash
# Local build output / published artifacts
find ~ /srv /opt /var/www -type f -iname 'Sicoob.Sdk.dll' 2>/dev/null
# Container images — list images, inspect layers for the DLL
docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | while read img; do
  docker run --rm --entrypoint sh "$img" -c 'find / -iname "Sicoob.Sdk.dll" 2>/dev/null' 2>/dev/null | sed "s|^|$img: |"
done
```

### 4b. NuGet global package cache

```bash
ls -d ~/.nuget/packages/sicoob.sdk/2.0.* 2>/dev/null         # package id is lowercased on disk
find ~/.nuget/packages/sicoob.sdk -iname '*.dll' 2>/dev/null
# HTTP cache
find ~/.local/share/NuGet ~/.nuget -iname '*sicoob*' 2>/dev/null
```

### 4c. npm cache (typosquats)

```bash
npm cache ls 2>/dev/null | grep -iE "@vpmdhaj/|opensearch-setup|app-config-utility|env-config-manager|forge-jsxy?"
grep -liE "@vpmdhaj/|preinstall" ~/.npm/_logs/*.log 2>/dev/null
```

### 4d. PFX certificate exposure (the actual loss)

For every repo with `runtime_usage = yes`, enumerate which PFX files were passed to `SicoobClient` and whether that code ran in an environment with a **real** certificate (prod/staging), not a test stub.

```bash
# Find PFX paths fed to SicoobClient in source
grep -rinE "new SicoobClient\s*\(" --include='*.cs' . 2>/dev/null
grep -rinE "\.pfx|LoadPfx|X509Certificate2\s*\(" --include='*.cs' . 2>/dev/null | grep -i sicoob
```

Any PFX used with `Sicoob.Sdk@2.0.x` in a run path → **assume the cert, its password, and the client ID are in the attacker's hands.**

### 4e. Sicoob API / Boleto audit logs

Pull Sicoob authentication and Boleto API logs for the exposure period and look for: logins/API calls from unfamiliar IPs or ASNs, Boleto operations the team didn't initiate, and token issuance outside business hours.

---

## Phase 5: Present Results

1. **Repo Analysis table** (`evidence-repos.csv`) — references + runtime usage + lock posture, per repo, both ecosystems.
2. **CI Runs table** (`evidence-ci-runs.csv`) — restores/installs in the window, IOCs, verdict.
3. **Executive Summary** — verdict (`clean` / `compromised`); how many repos reference `Sicoob.Sdk` and how many actually instantiate `SicoobClient`; which PFX certificates must be treated as compromised; npm-typosquat exposure (which hosts, which cloud creds); Sentry exfil evidence from network logs; Sicoob/Boleto audit-log findings; one-sentence bottom line.

**Action needed** if any: a repo references `Sicoob.Sdk@2.0.x` with runtime usage; a deployed artifact/container bundles the DLL; a `vpmdhaj` typosquat was installed; or Sentry exfil / anomalous banking activity is observed.

---

## Phase 6: Hardening & Remediation (User Approval Required)

**Do NOT proceed without explicit user approval.** Present findings first.

### Remediation — `Sicoob.Sdk` (banking-credential exposure)

If any project referenced `Sicoob.Sdk@2.0.x` and the `SicoobClient` path ran with a real PFX, treat it as a **confirmed banking-credential breach**:

1. **Remove the package** from every project, deployed artifact, and container image. Rebuild and redeploy clean.
2. **Treat every PFX certificate used with the affected version as compromised** — revoke and **replace the certificates** with new ones.
3. **Rotate all PFX passwords.**
4. **Change or disable affected Sicoob client IDs** and re-issue.
5. **Audit Sicoob authentication & Boleto API logs** for unauthorized activity throughout the exposure period; report suspected fraud to Sicoob.
6. **Block the Sentry exfil host** (the recovered DSN/host) at the network edge.
7. Purge the NuGet cache entry: `dotnet nuget locals all --clear` (or remove `~/.nuget/packages/sicoob.sdk/`).

### Remediation — `vpmdhaj` npm typosquats (cloud-credential exposure)

For any host/CI that installed a typosquat:

1. **Remove the packages**; `rm -rf node_modules`; `npm cache clean --force`.
2. **Rotate** AWS keys (and any STS-derived sessions), HashiCorp Vault tokens, npm tokens, and **every CI/CD secret** the host could read.
3. Audit CloudTrail / Vault audit logs / npm token usage for abuse during the window.

### Hardening

| Surface | Fix |
|---|---|
| Unverified NuGet sources | Enable **package source mapping** (`nuget.config` `<packageSourceMapping>`) so each package can only come from its trusted feed; pin to `api.nuget.org` |
| No NuGet lock | Commit `packages.lock.json`; enforce `<RestoreLockedMode>true</RestoreLockedMode>` / `dotnet restore --locked-mode` in CI |
| Unsigned packages accepted | Require **signed package validation** (`<trustedSigners>` / repository signature checks) |
| Typo-prone npm installs | Commit `package-lock.json`; use `npm ci`; add `--ignore-scripts` (blocks the `preinstall` exfil — effective for *this* npm campaign) |
| New-dependency review | Enable `actions/dependency-review-action`; alert on newly-added packages, especially finance/banking-named SDKs and `opensearch-*` lookalikes |
| Outbound from build/runtime | Allow-list egress; block unexpected `*.sentry.io` destinations from banking-integration services |
| Secrets reachable by CI | Scope CI secrets least-privilege; prefer short-lived OIDC over long-lived AWS/Vault/npm tokens |

### Upgrade path

There is **no safe `2.0.x` version** — the entire `Sicoob.Sdk` package is attacker-controlled and was removed by NuGet. Do not pin to any 2.0.x release. Integrate with Sicoob using the **official, vendor-confirmed** SDK/source only, verified against Sicoob's own documentation. For the npm typosquats, replace with the genuine intended packages (confirm exact names with the maintainers) and pin + lock them.

---

## References

- The Hacker News — "Malicious 'Sicoob.Sdk' NuGet steals banking credentials" — https://thehackernews.com/2026/05/malicious-sicoob-nuget-steals-banking.html
- NuGet package source mapping — https://learn.microsoft.com/en-us/nuget/consume-packages/package-source-mapping
- NuGet lock files / `--locked-mode` — https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files#locking-dependencies
- OSSF malicious-packages database — https://github.com/ossf/malicious-packages
