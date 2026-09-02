# Shai-Hulud "Trinitite" npm Wave (`@7nohe/openapi-react-query-codegen`, August 28 2026) — Investigation Playbook

Playbook for investigating whether a GitHub org was affected by the **28 August 2026 compromise of `@7nohe/openapi-react-query-codegen`** — a TanStack Query codegen package at **~150K weekly downloads**. The attacker did not steal an npm token or hijack a maintainer account. Three flaws chained in `release.yml`: it triggered on **`issue_comment`** with **no author-association check** (any comment containing `npm publish` fired a release), it **checked out the untrusted pull-request head**, and it ran that attacker-controlled code in a job holding **`id-token: write`**. A GitHub user named `p00paboot` opened pull requests **#215** and **#216** from a fork, posted the trigger comment, and the workflow minted a **trusted-publishing OIDC token** and shipped **ten malicious versions across every maintained release line** in twenty minutes. The package sees roughly **150K downloads per week / 671K per month**. The payload is a self-replicating credential worm that JFrog tracks as **Trinitite**, a new Mini Shai-Hulud wave.

> **CI/CD platform note:** This playbook targets GitHub Actions. For other platforms (GitLab CI, Jenkins, CircleCI, Bitbucket, Azure DevOps), adapt the log-collection commands — the investigation logic is unchanged: find references to the package, collect run logs from the exposure window, search for the malicious versions and this wave's IOCs, verify lock-file protection, then check hosts for persistence.

> **⚠️ Critical — remove persistence BEFORE revoking any token.** The worm installs a monitor (`~/.local/share/diaper/poopy.py`) kept alive by user services. If the stolen GitHub token starts returning a 40x, the monitor **wipes `~/` and `~/Documents`**. Revoking credentials first will destroy the victim's home directory and your evidence. Order is: **isolate the host → stop the services → delete the persistence artifacts → only then rotate, from a clean machine.**

> **⚠️ Critical — valid provenance is NOT a safety signal.** The malicious tarballs were published through the project's own trusted-publishing pipeline and carry **genuine GitHub Actions Sigstore signatures and provenance**. "Signed / has provenance" means nothing for this wave.

> **⚠️ Trigger model is install-time, and `--ignore-scripts` does NOT protect you.** The payload has two independent entry points: a `preinstall` lifecycle script (`node 3FWCvzduYZg.js`) **and** `binding.gyp`, which abuses **node-gyp's Python evaluation** during `node-gyp rebuild` — a class-hierarchy traversal reaching `os.system()` with no plain-text import — invoking the same loader even when lifecycle scripts are disabled. **Analyses disagree on which versions carried which path** (some report `preinstall` on all eight stable versions; others report it only on wave 2, with wave 1 relying on `binding.gyp`). Treat all ten as fully malicious; the distinction changes no action. A clean lock file plus a frozen installer is the only install-side defense.

---

## Incident Details

### CVE / advisory

- **CVE:** none assigned as of this writing.
- **GitHub advisory:** none published as of this writing (recheck the GitHub Advisory Database for `@7nohe/openapi-react-query-codegen`).
- **Root-cause fix:** all three conditions must be closed — verify the commenter's association (`OWNER` / `MEMBER` / `COLLABORATOR`) and not just the comment body; do not check out the untrusted pull-request head in a privileged job; and do not grant `id-token: write` to any job that executes untrusted code.
- **Attribution context:** the people behind **TeamPCP** were arrested in Australia in late August; this package appeared on npm roughly a day later, using the same kit with new RSA keys. Per JFrog this could be leftover access or a different actor reusing the toolkit — treat attribution as unresolved.

### Affected packages

All ten malicious versions have been **unpublished** from npm, and `latest` has reverted to `3.0.2`. Any environment that resolved one from a cache, lock file, mirror, or container layer during the window is still in scope.

```bash
# Malicious package-versions (the detection-time source of truth)
export PKG='@7nohe/openapi-react-query-codegen'
export AFFECTED='0.5.4 0.5.5 1.6.3 1.6.4 2.2.1 2.2.2 3.0.3 3.0.4 0.0.0-365d4eb738d3146583431948d3ba6e27a32556be 0.0.0-ec7876d6c917dad516ba69bbfafc948b834bf0ab'
```

| Release line | Malicious version(s) | Last safe version | Last safe published |
|---|---|---|---|
| 0.5.x | `0.5.4`, `0.5.5` | `0.5.3` | 2024-02-04 |
| 1.6.x | `1.6.3`, `1.6.4` | `1.6.2` | 2025-01-22 |
| 2.2.x | `2.2.1`, `2.2.2` | `2.2.0` | 2026-07-10 |
| 3.0.x | `3.0.3`, `3.0.4` | `3.0.2` | 2026-08-11 |
| prerelease | `0.0.0-365d4eb7…`, `0.0.0-ec7876d6…` | n/a | n/a |

**Every maintained line was hit.** A consumer pinned to an older major is not automatically safe — check the line, not just the highest version.

### Exposure window

Timestamps below are the npm registry's own publish times (retained after unpublish), so they are authoritative rather than reconstructed.

| Event | Time (UTC, 28 Aug 2026) |
|---|---|
| Wave 1 — `0.5.4` published (first malicious artifact) | 20:00:43 |
| Wave 1 — `1.6.3`, `2.2.1` | 20:00:48, 20:00:53 |
| Wave 1 — prerelease `0.0.0-365d4eb7…` | 20:01:03 |
| Wave 1 — `3.0.3` | 20:02:08 |
| Wave 2 — `3.0.4`, `1.6.4`, `2.2.2` | 20:19:29, 20:19:38, 20:19:41 |
| Wave 2 — prerelease `0.0.0-ec7876d6…` | 20:20:13 |
| Wave 2 — `0.5.5` (last malicious artifact) | 20:20:53 |
| Registry last modified — consistent with the unpublish | 23:11:37 |

**Recommended scan window (padded):** `2026-08-28T19:30:00Z` to `2026-08-29T00:30:00Z`. The artifacts were installable for roughly **three hours and ten minutes**. Pad both sides to catch a build that resolved a version just before the unpublish propagated to mirrors, and any late-firing beacon.

### Indicators of compromise

| IOC | Value | Where it shows up |
|---|---|---|
| Loader (primary) | `3FWCvzduYZg.js` — single-line obfuscated, 4.3–6.4 MB. Decodes through XOR → AES-128-GCM → `javascript-obfuscator`. *(JFrog reports XOR key `9`, Endor reports `77` for the outer layer; the layer naming differs between analyses, so do not key detection on the constant.)* | inside the malicious tarball; `preinstall` runs `node 3FWCvzduYZg.js` |
| Loader (prerelease test) | `is_it_this_simple.js` | prerelease tarballs only |
| Native-build entry | `binding.gyp` — SHA256 `d3246926b20a8d021ed7de0ac8e9eee1dda986088f84ba18f31cb2042a121f5d` | tarball root; fires via `node-gyp rebuild`, even with `--ignore-scripts` |
| Build-env canaries | `WORKFLOW_ID=release.yml`, `REPO_ID_SUFFIX=7nohe/openapi-react-query-codegen`, `TARGET_PACKAGES=@7nohe/openapi-react-query-codegen` | embedded in the payload |
| Token monitor / wipe trap | `~/.local/share/diaper/poopy.py` | infected host |
| State file | `/var/tmp/.shit` | infected host |
| Staging paths | `/tmp/.sshu-<random>`, `/tmp/pcfg/` | infected host |
| Bun cache | `trinnyyyy-*/bun` (Windows variant uses 6 random characters) | infected host |
| Linux services | `systemd-detect-fash.service`, `sysvinit-detect-fash.service` | `systemctl --user list-units` |
| macOS agents | `com.user.systemd-detect-fash.plist`, `com.user.sysvinit-detect-fash.plist` | `~/Library/LaunchAgents/` |
| Exfil repos | public repos whose description contains `Trinitite: Sponsored by Preview 2 Effects` | victim's GitHub account |
| Commit search marker | `firedalazer` | GitHub commit search across the org |
| Campaign strings | `doubletrinnys-`, `IfYouRevokeThisTokenYourABadUser`, `meow meow meow`, `poopy.com`, `v1/idk` | payload, repo/commit metadata |
| Malicious workflow | a workflow named `ClaudeCode Review` that serializes all repository secrets into an env var and writes `res.txt`, then uploads it as an artifact | `.github/workflows/`, Actions artifacts |
| Bun download | `github.com/oven-sh/bun/releases/download/bun-v1.4.0/`, `raw.githubusercontent.com/oven-sh/bun/refs/heads/main/src/runtime/cli/install.sh` | CI/host egress |
| Registry abuse | `upload.pypi.org/legacy/`, `registry.npmjs.org/-/npm/v1/oidc/token/exchange/package/` | CI/host egress |
| GitHub API abuse | `api.github.com/user/repos`, `api.github.com/search/commits` | CI/host egress |

> **Commit-message prefix.** Exfiltration commits use a fixed attacker prefix followed by `<base64-url>.<base64-signature>`. The literal prefix is **`n1ggatr1n`** — reproduced verbatim only because exact-match search requires it; it is an attacker-chosen string containing a racial slur. Search for it, do not repeat it in customer-facing writeups.

> **Shared-infrastructure caveat.** The Bun download URLs and `api.github.com` endpoints appear in entirely legitimate CI configuration. They are IOCs only as **runtime egress from a host or runner that also matches a file or service indicator above** — never as a static match in a repo file. A workflow that legitimately installs Bun is not compromise.

### What IS affected

- Any `npm` / `pnpm` / `yarn` install that **resolved** one of the ten malicious versions between 20:00:43 and ~23:11 UTC on 28 August 2026 — directly or transitively.
- CI runners that executed such an install. The payload fires at install time through either `preinstall` or `binding.gyp`, so the runner itself is compromised and its secrets are in scope, including anything only present in Actions Runner memory (the worm scrapes for `"isSecret":true`).
- Container images **built** during the window that installed an affected version — the payload ran at build time and the poisoned code is baked into a layer.
- Developer workstations that installed or updated the package during the window — check the host persistence in Phase 3.
- Any registry account whose credentials were present on an affected host. **Note the distinction:** the only package actually compromised in this wave is `@7nohe/openapi-react-query-codegen` itself — Mend, SafeDep and Endor all confirm no other npm, PyPI or RubyGems package was republished. The payload *carries* handlers to validate stolen PyPI tokens against the real upload endpoint and generate 20 typosquats (`-mcp` / `-mpc` suffixes, gated on `TYPO_MODE === '1'`), and to repack and resubmit RubyGems owned by a validated account; Artifactory is also targeted. So this is a risk to **your** registry credentials and **your** published packages, not a list of third-party packages to hunt.

### What is NOT affected

- Installs from a **committed lock file** with `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --immutable` where the lock pins `0.5.3`, `1.6.2`, `2.2.0` or `3.0.2` (any pre-window resolution) — the malicious tarball is never resolved.
- **Source-only references** — a TypeScript `import` in a file that was never installed during the window; docs, `values.yaml` or Terraform naming the package without installing it.
- **Pre-built images pulled, not rebuilt**, during the window, whose lock state predates it.
- Repos that reference the package only in a **`devDependencies` block that CI never installs** (e.g. a job that runs `npm ci --omit=dev`) — verify the actual install command rather than assuming.

### Lock file protection

Lock files **do protect** if used correctly: `npm ci`, `pnpm install --frozen-lockfile` and `yarn install --immutable` install exactly what is pinned, and a lock file generated before 28 Aug 20:00:43 UTC pins a safe version.

They do **not** protect if: no lock file is committed; CI runs `npm install` / `pnpm install` / `yarn install` without a frozen flag and the manifest carries a floating range (`^3.0.2` resolves `3.0.3`); the lock file was regenerated during the window; or a Dependabot/Renovate PR merged during the window bumped the dependency.

> **`--ignore-scripts` is NOT protection.** The `binding.gyp` path runs through the native-build step, not the lifecycle-script step.

---

## Setup

```bash
export ORG="<your-github-org>"
export PKG='@7nohe/openapi-react-query-codegen'
export SINCE="2026-08-28T19:30:00Z"
export UNTIL="2026-08-29T00:30:00Z"
export LOG_DIR="/tmp/supply-chain-scan-trinitite"
mkdir -p "$LOG_DIR"
```

**Log caching:** if `$LOG_DIR` already holds logs from a previous run, reuse them and skip the download step.

**Write to files, not context:** write structured evidence (CSV) into `$LOG_DIR` as you go rather than accumulating findings in conversation.

**Rate limits** — check the budget before scanning a large org:

```bash
gh api /rate_limit --jq '.resources.core | "\(.remaining)/\(.limit) core remaining (resets \(.reset|todate))"'
gh api /rate_limit --jq '.resources.code_search | "code-search: \(.remaining)/\(.limit) remaining"'
```

Code search is ~30 req/min; REST is 5,000/hr and log downloads count against it. Use `xargs -P 10` and cache everything.

---

## Phase 1: Repo Analysis

**Goal:** find every repo that references the package and decide whether it *could* have resolved a malicious version. Window-agnostic.

### 1. Find references across the org

```bash
gh api -X GET search/code --paginate \
  -f q="openapi-react-query-codegen org:${ORG}" \
  --jq '.items[]? | "\(.repository.full_name)\t\(.path)"' | sort -u | tee "$LOG_DIR/refs.tsv"
```

> **Positive control** — prove the search works before trusting a zero-hit result:
> `gh api -X GET search/code -f q="react org:${ORG}" --jq '.total_count'` should be non-zero for any org with JS repos. A broken query and a clean org look identical.

### 2. Classify each hit

| File type | Meaning |
|---|---|
| `package.json` | declared dependency — check whether the range is floating (`^`, `~`) or exact |
| `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` | resolved version — **this is the decisive evidence** |
| `Dockerfile` | image build — check whether the build ran in the window |
| `.github/workflows/*` | the install command; is it `npm ci` or `npm install`? |
| docs / config | not exposure on its own |

### 3. Extract version data per repo

```bash
cut -f1 "$LOG_DIR/refs.tsv" | sort -u | while read -r repo; do
  for f in package.json package-lock.json pnpm-lock.yaml yarn.lock; do
    gh api "repos/$repo/contents/$f" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null \
      | grep -n -A3 "openapi-react-query-codegen" | sed "s|^|$repo/$f: |"
  done
done | tee "$LOG_DIR/versions.txt"
```

Flag any resolved version in `$AFFECTED`. Flag any floating range on a repo whose CI uses a non-frozen installer.

---

## Phase 2: CI Run Analysis

**Goal:** determine whether any pipeline actually installed a malicious version inside the window.

### 1. Find runs in the window

```bash
cut -f1 "$LOG_DIR/refs.tsv" | sort -u | while read -r repo; do
  gh run list --repo "$repo" --created "${SINCE}..${UNTIL}" \
    --json databaseId,name,createdAt,conclusion --jq \
    ".[] | \"$repo\t\(.databaseId)\t\(.createdAt)\t\(.name)\t\(.conclusion)\"" 2>/dev/null
done | tee "$LOG_DIR/runs.tsv"
```

### 2. Download logs in parallel

```bash
awk -F'\t' '{print $1" "$2}' "$LOG_DIR/runs.tsv" | \
  xargs -P 10 -n 2 sh -c 'gh run view --repo "$0" "$1" --log > "'"$LOG_DIR"'/$1.log" 2>/dev/null || true'
```

### 3. Scan logs for install lines and this wave's IOCs

```bash
# Install-resolution lines — install-only patterns, not source imports
grep -rnE "openapi-react-query-codegen@(0\.5\.[45]|1\.6\.[34]|2\.2\.[12]|3\.0\.[34]|0\.0\.0-)" "$LOG_DIR"/*.log

# Runtime IOCs
grep -rnE "3FWCvzduYZg|is_it_this_simple|binding\.gyp|node-gyp rebuild|trinnyyyy-|doubletrinnys-|IfYouRevokeThisToken|firedalazer" "$LOG_DIR"/*.log

# Egress signatures — only meaningful alongside a file/service indicator
grep -rnE "oven-sh/bun/releases/download/bun-v1\.4\.0|upload\.pypi\.org/legacy|oidc/token/exchange" "$LOG_DIR"/*.log
```

### 4. Classify hits

A log line showing `added @7nohe/openapi-react-query-codegen@3.0.3` is a confirmed install and the runner is compromised. A line that merely names the package in a source path or a lint warning is not. Record one row per run.

### 5. Check for the secret-exfiltration workflow

```bash
gh api -X GET search/code --paginate \
  -f q="\"ClaudeCode Review\" org:${ORG} path:.github/workflows" \
  --jq '.items[]? | "\(.repository.full_name)\t\(.path)"'

# Artifacts named res.txt on runs in the window
awk -F'\t' '{print $1" "$2}' "$LOG_DIR/runs.tsv" | while read -r repo id; do
  gh api "repos/$repo/actions/runs/$id/artifacts" --jq '.artifacts[]? | select(.name|test("res")) | "'"$repo"' \(.name) \(.created_at)"' 2>/dev/null
done
```

Either hit means repository secrets were serialized and staged for exfiltration — treat **every** secret in that repo as disclosed.

---

## Phase 3: Host and Workstation Persistence Check

Run on every developer machine and self-hosted runner that installed the package in the window. **Do this before revoking anything** — see the wipe-trap warning at the top.

```bash
# 1. Services (Linux)
systemctl --user list-units --all | grep -E "systemd-detect-fash|sysvinit-detect-fash"

# 2. Launch agents (macOS)
ls -la ~/Library/LaunchAgents/ | grep -E "systemd-detect-fash|sysvinit-detect-fash"

# 3. Persistence and state artifacts
ls -la ~/.local/share/diaper/ ~/.config/sysvinit-detect-fash/ /var/tmp/.shit 2>/dev/null
ls -d /tmp/pcfg /tmp/.sshu-* /tmp/trinnyyyy-* 2>/dev/null

# 4. Loader remnants in package caches
grep -rl "3FWCvzduYZg" ~/.npm/_cacache 2>/dev/null | head
find ~ -maxdepth 6 -name "3FWCvzduYZg.js" -o -maxdepth 6 -name "is_it_this_simple.js" 2>/dev/null

# 5. AI-agent config tampering (the worm hooks these)
ls -la ~/.claude/ ~/.cursor/ ~/.config/Code/User/ ~/.gemini/ ~/.aider* 2>/dev/null
```

### If anything matches

1. **Isolate the machine from the network.** Do not revoke tokens yet.
2. Stop and disable the services: `systemctl --user stop systemd-detect-fash sysvinit-detect-fash && systemctl --user disable systemd-detect-fash sysvinit-detect-fash` (macOS: `launchctl bootout gui/$(id -u)/<label>`).
3. Delete `~/.local/share/diaper/`, `~/.config/sysvinit-detect-fash/`, `/var/tmp/.shit`, `/tmp/pcfg`, `/tmp/.sshu-*`, `trinnyyyy-*`.
4. Confirm the monitor process is gone: `pgrep -fa poopy.py`.
5. **Only now** proceed to rotation, from a different clean machine.

---

## Phase 4: Blast Radius

For each confirmed install, enumerate what the payload could reach. The worm harvests **GitHub, npm, PyPI, RubyGems, cloud-provider, SSH, HashiCorp Vault and Kubernetes** credentials, and scrapes Actions Runner memory.

- **CI runs:** every `secrets.*` reference in the workflow, OIDC-issued cloud credentials, registry credentials, and any secret masked in logs (masking is not protection against memory scraping).
- **Workstations:** `~/.npmrc`, `~/.pypirc`, `~/.gem/credentials`, `~/.ssh/`, `~/.aws/`, `~/.config/gcloud/`, `~/.kube/config`, Vault tokens, and `.env` files.
- **Your own published packages:** if an npm, PyPI or RubyGems credential was present, check whether *your* packages were republished. A `scripts.preinstall` you did not author, or an unexpected `binding.gyp`, is conclusive.

```bash
# Did the worm create exfiltration repos under the victim's account?
gh api -X GET search/repositories -f q="Trinitite in:description" --jq '.items[]? | "\(.full_name)\t\(.created_at)"'
gh api -X GET search/commits -f q="firedalazer org:${ORG}" -H "Accept: application/vnd.github.cloak-preview" --jq '.items[]? | "\(.repository.full_name)\t\(.sha)"' 2>/dev/null
```

---

## Phase 5: Remediation, in order

1. **Isolate** affected hosts and runners.
2. **Remove persistence** (Phase 3) — before any credential action.
3. **Pin to the last safe version for your line** (`0.5.3` / `1.6.2` / `2.2.0` / `3.0.2`) and regenerate lock files on a clean host. Purge caches: `npm cache clean --force`, `pnpm store prune`, `yarn cache clean`. Rebuild container images with `--no-cache`.
4. **Rotate every credential** reachable from an affected host or run, from a clean machine: GitHub tokens (PATs, OAuth, App installation, deploy keys), npm/PyPI/RubyGems tokens, cloud credentials, SSH keys, Vault tokens, Kubernetes service-account tokens, and every Actions secret in an affected repo.
5. **Switch to frozen installs** — `npm ci`, `pnpm install --frozen-lockfile`, `yarn install --immutable`. Note that `--ignore-scripts` is *not* sufficient for this wave.
6. **Fix the class of vulnerability in your own workflows** — this is the durable lesson. Any workflow triggered by `issue_comment` (or `pull_request_target`) that acts on comment text must verify the commenter's association:

```yaml
# Minimum gate for a comment-triggered release workflow
if: |
  github.event.issue.pull_request &&
  contains(github.event.comment.body, 'npm publish') &&
  contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)
```

Audit for the pattern org-wide:

```bash
gh api -X GET search/code --paginate \
  -f q="issue_comment org:${ORG} path:.github/workflows" \
  --jq '.items[]? | "\(.repository.full_name)\t\(.path)"'
```

Then read each hit and confirm it gates on `author_association` (or an equivalent permission check) and not only on the comment body.

---

## Evidence table

Record one row per repo:

| Repo | Reference type | Declared range | Resolved version | Install cmd | Ran in window? | Log hit | Persistence found | Verdict |
|---|---|---|---|---|---|---|---|---|
| | | | | | | | | affected / not affected |

## Wrap-up

Deliverables: the evidence table above; a list of hosts cleaned and the order in which persistence removal and rotation happened; the set of credentials rotated; confirmation that your own published packages were not republished; and the list of `issue_comment`-triggered workflows audited and gated. For orgs with no hits, record the negative result together with the positive-control output that proves the search actually ran.
