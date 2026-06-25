# codfish/semantic-release-action Compromise (Miasma) — Detection Playbook

> **Note for AI agents:** This playbook is written for **GitHub Actions** CI/CD. If the target org uses a different platform (GitLab CI, Jenkins, CircleCI, Bitbucket, Azure DevOps), adapt the log-collection and action-reference commands — the detection logic is the same: find every reference to `codfish/semantic-release-action`, classify it as tag-pinned (vulnerable) vs SHA-pinned (safe), collect CI run logs from the exposure window, confirm whether the poisoned step actually executed, then hunt the worm's org-side and host-side footprint.

> **Trigger model — build-step, not install-time.** The payload runs as a GitHub Action *step inside the CI runner* during a workflow run. It does **not** ride `npm install` and is **not** in any dependency manifest or lock file. So `npm ci` / lock files / `--ignore-scripts` are irrelevant defenses here — the only thing that protects you is **pinning the `uses:` reference to an immutable commit SHA that predates the compromise**. Detection centers on `.github/workflows/**` and CI build logs.

## Variables — Fill These In First

```bash
# Your GitHub organization name
export ORG="your-org-name"

# Exposure window. Start = the malicious force-push timestamp. End is open until you
# confirm no workflow referenced a compromised tag after the start and the maintainer
# restored clean tags — pad the UNTIL forward generously.
export SINCE="2026-06-24T15:39:06Z"
export UNTIL="2026-07-01T00:00:00Z"

# Directory to store downloaded logs / evidence
export LOG_DIR="/tmp/supply-chain-scan-codfish"
mkdir -p "$LOG_DIR"
```

All commands below use `$ORG`, `$SINCE`, `$UNTIL`, and `$LOG_DIR`.

**Rate limits.** Code search is ~30 req/min; REST is 5,000 req/hr; log downloads count against REST. Use `xargs -P 10` and cache everything to `$LOG_DIR`. Check budget first:

```bash
gh api /rate_limit --jq '.resources.core | "\(.remaining)/\(.limit) core (resets \(.reset|todate))"'
gh api /rate_limit --jq '.resources.code_search | "code-search: \(.remaining)/\(.limit)"'
```

---

## Background

On **24 June 2026 at 15:39:06 UTC**, an attacker force-pushed a malicious commit to `codfish/semantic-release-action` (the original semantic-release GitHub Action, 100+ stars, used since 2019) and repointed sixteen version tags (v2–v5, including the floating `v2`/`v3`/`v4`/`v5`) to it. The action was converted from Docker-based to a **composite action** that runs the legitimate step for cover, installs Bun, and executes the **Miasma** worm payload (`index.js`, ~512 KB) inside the runner. Miasma is part of the **TeamPCP / UNC6780** campaign (Trivy, LiteLLM, TanStack, axios, Grafana, Nx Console).

### Affected references

| Reference style | Status |
|---|---|
| Tags `v5.0.0, v5, v4.0.1, v4.0.0, v4, v3.5.0, v3.4.1, v3.4.0, v3.3.0, v3.2.0, v3.1.1, v3.1.0, v3.0.0, v3, v2.2.1, v2` | **COMPROMISED** — repointed to `6b9501e1889cc45c91726729610cf69c2442b8c5` |
| Older tags `v2.0.0, v1.9.0, v1, v1.8.0, v1.7.0, v1.6.2, v1.6.1` | **DISPUTED** — one vendor flags them compromised, another reports `v1.0.0`–`v1.10.0` + `v2.0.0` clean. Treat as suspect. |
| **Any** `uses: codfish/semantic-release-action@<tag-or-branch>` | **VULNERABLE** — tags are mutable; do not trust any tag |
| `uses: codfish/semantic-release-action@<40-char-SHA>` predating 2026-06-24 15:39 UTC | **SAFE** — immutable, can't be repointed |
| Legitimate `v5` branch / GHCR Docker image (digest-pinned) | Reported clean |

### Exposure window

| Event | Time (UTC) |
|---|---|
| Malicious force-push | 2026-06-24 15:39:06 |
| End | Not officially published — treat as open; pad `$UNTIL` forward |

### Indicators of compromise

| IOC | Value |
|---|---|
| Malicious commit | `6b9501e1889cc45c91726729610cf69c2442b8c5` (also reported `5792aba0e2180b9b80b77644370a6889d5817456`, `bcb6b1d409144318e8fad2171d6fe06d02299d1a`) |
| Payload `index.js` SHA256 | `9f93d77d32833a515bc406c46da477142bb1ac2babeecb6aa42f98669a6db015` |
| Bun installer (pinned by attacker) | `oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6` |
| Dead-drop markers (GitHub commit-search C2) | `RevokeAndItGoesKaboom`, `TheBeautifulSandsOfTime` |
| Hardcoded AES-256-CBC key | `bd8035203526735490e4bd5cdcede581b9d3a3f7a5df7725859844d8dcc8eb49` |
| Propagation commit marker | `chore: update dependencies` + `skip-checks:[[:space:]]*true` |
| Lateral-movement payload | `~/.config/index.js` (run via Bun) |
| AI-config tamper artifacts | `.claude/settings.json` (`SessionStart` hook → `.claude/index.js`), `.vscode/tasks.json`, `.vscode/setup.mjs`, `.cursorrules`, `.windsurfrules`, `.github/copilot-instructions.md` |
| Targeted secrets | `GITHUB_TOKEN`, OIDC, PATs, `NPM_TOKEN`/`.npmrc`, `~/.pypirc`, RubyGems creds, Anthropic/AI API keys |

> **Why `api.github.com` is a tricky IOC.** Miasma uses GitHub's own commit-search API as C2 and `api.github.com` for exfil — both are normal CI destinations. The signal is **context**: writes to `api.github.com` (repo/branch creation, content push) or SSH/`scp` egress **from a runner during a `semantic-release` step**, plus a Bun install that step has no reason to do. Don't flag the bare domain.

---

## Phase 1: Find & Classify Every Reference to the Action

### 1a. Search all workflows in the org

```bash
gh api "search/code?q=codfish/semantic-release-action+org:${ORG}&per_page=100" \
  --jq '.items[] | "\(.repository.full_name)\t\(.path)"' 2>/dev/null | sort -u \
  > "$LOG_DIR/refs.tsv"
wc -l "$LOG_DIR/refs.tsv"
```

> **Faster for large orgs (>50 repos):** shallow-clone and grep locally.
> ```bash
> mkdir -p "$LOG_DIR/clones" && cd "$LOG_DIR/clones"
> gh repo list "$ORG" --no-archived --limit 1000 --json nameWithOwner --jq '.[].nameWithOwner' | \
>   xargs -P 10 -I {} bash -c 'git clone --depth 1 --filter=blob:none "git@github.com:{}.git" 2>/dev/null || echo "FAIL: {}"'
> grep -rEn --include='*.yml' --include='*.yaml' "codfish/semantic-release-action" . \
>   > "$LOG_DIR/refs-from-clone.txt"
> ```

### 1b. Classify each `uses:` reference — tag/branch (vulnerable) vs SHA (safe)

```bash
# Pull the actual uses: line for each hit and classify the ref
while IFS=$'\t' read -r repo path; do
  content=$(gh api "repos/${repo}/contents/${path}" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null)
  echo "$content" | grep -nE "uses:[[:space:]]*codfish/semantic-release-action@" | while read -r line; do
    ref=$(echo "$line" | sed -E 's/.*@([^[:space:]"'"'"']+).*/\1/')
    if echo "$ref" | grep -qE '^(6b9501e1889cc45c91726729610cf69c2442b8c5|5792aba0e2180b9b80b77644370a6889d5817456|bcb6b1d409144318e8fad2171d6fe06d02299d1a)$'; then
      verdict="*** MALICIOUS SHA — COMPROMISED ***"   # fail closed: pinned directly to the bad commit
    elif echo "$ref" | grep -qE '^[a-f0-9]{40}$'; then
      verdict="SHA-PINNED (verify date)"
    else
      verdict="*** TAG/BRANCH — VULNERABLE ***"
    fi
    echo -e "${repo}\t${path}\t@${ref}\t${verdict}"
  done
done < "$LOG_DIR/refs.tsv" | tee "$LOG_DIR/classified-refs.tsv"
```

### 1c. For any SHA-pinned ref, confirm the commit predates the compromise

```bash
# Replace <SHA> with each 40-char hash from 1b
gh api "/repos/codfish/semantic-release-action/commits/<SHA>" \
  --jq '.commit.committer.date'
# A commit date before 2026-06-24T15:39:06Z is safe. The malicious commit
# 6b9501e1889cc45c91726729610cf69c2442b8c5 (and 5792aba.../bcb6b1d...) is NOT safe.
```

**Positive control:** before trusting an empty result from 1a, prove the search works — run the same query for an action you *know* the org uses (e.g. `actions/checkout`) and confirm it returns hits. A zero-hit search and a broken query look identical.

---

## Phase 2: Confirm Whether the Poisoned Step Actually Ran (CI Logs)

Phase 1 finds repos that *reference* the action by tag. Only the CI logs prove the poisoned tag actually **resolved and executed** during the window.

### 2a. List all runs during the exposure window

```bash
gh api "/orgs/${ORG}/repos" --paginate --jq '.[].name' | while read repo; do
  gh api "repos/${ORG}/${repo}/actions/runs?created=${SINCE}..${UNTIL}&per_page=100" \
    --jq ".workflow_runs[] | \"${repo}|\(.id)|\(.created_at)|\(.name)|\(.conclusion)\"" 2>/dev/null
done > "$LOG_DIR/all_runs.txt"
echo "Total runs to scan: $(wc -l < "$LOG_DIR/all_runs.txt")"
```

### 2b. Download run logs in parallel

```bash
cat "$LOG_DIR/all_runs.txt" | while IFS='|' read repo run_id rest; do echo "$repo $run_id"; done | \
  xargs -P 10 -L 1 bash -c \
  'gh run view "$1" --repo "${ORG}/$0" --log > "${LOG_DIR}/run-$1.log" 2>/dev/null && echo "OK: $0 $1" || echo "FAIL: $0 $1"'
```

### 2c. Scan logs for action execution + payload IOCs

```bash
# The action actually executing (vs merely named in config)
echo "=== action execution ==="
grep -rlnE "Run codfish/semantic-release-action|Download action repository 'codfish/semantic-release-action" "$LOG_DIR"/run-*.log 2>/dev/null

# HIGHEST-CONFIDENCE SIGNAL: a tag that *resolved to* a known-malicious commit.
# GitHub Actions prints the resolved SHA on the "Download action repository" line.
echo "=== tag resolved to a known-malicious commit ==="
grep -rlnE "6b9501e1889cc45c91726729610cf69c2442b8c5|5792aba0e2180b9b80b77644370a6889d5817456|bcb6b1d409144318e8fad2171d6fe06d02299d1a" "$LOG_DIR"/run-*.log 2>/dev/null

# Anomalous Bun install pulled in by the poisoned composite action
echo "=== unexpected Bun install during the run ==="
grep -rlnE "oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6|setup-bun|installing bun|bun\.sh/install" "$LOG_DIR"/run-*.log 2>/dev/null

# Dead-drop C2 markers / exfil
echo "=== Miasma dead-drop markers ==="
grep -rlnE "RevokeAndItGoesKaboom|TheBeautifulSandsOfTime" "$LOG_DIR"/run-*.log 2>/dev/null

# Lateral-movement / payload path / propagation marker
echo "=== lateral movement + propagation ==="
grep -rlnE "~/.config/index\.js|/\.config/index\.js|skip-checks:[[:space:]]*true|scp .*known_hosts|ssh .*-o StrictHostKeyChecking" "$LOG_DIR"/run-*.log 2>/dev/null
```

### 2d. Classify hits — real execution vs false positives

**Real execution indicators**
- `Run codfish/semantic-release-action@<tag>` (the action ran) — cross-check the ref was a **tag**, not a pre-compromise SHA.
- A Bun install (`oven-sh/setup-bun@0c5077e...`) inside a run whose workflow has no legitimate Bun step.
- Any dead-drop marker, `api.github.com` write, or SSH/`scp` egress during the `semantic-release` step.

**False positives (ignore)**
- The action name in comments, branch names (`origin/feat/bump-semantic-release-action`), or docs.
- A run that referenced the action **by a pre-compromise SHA** (immutable — safe even if it executed).
- Legitimate `semantic-release` output (changelog/version lines) with no Bun install and no marker.
- A repo that legitimately uses Bun for its own build — correlate Bun with the action step + a marker before flagging.

---

## Phase 3: Hunt the Worm's Org-Side Footprint

Miasma self-propagates. Even repos that never used the action can be poisoned by a stolen token.

### 3a. Propagation commits (the CI-bypass marker)

```bash
gh api "search/commits?q=org:${ORG}+%22chore:+update+dependencies%22" \
  --jq '.items[]? | "\(.repository.full_name) | \(.sha[0:10]) | \(.commit.author.date) | \(.commit.message|split("\n")[0])"' 2>/dev/null
# Then inspect any hit's diff for `skip-checks:[[:space:]]*true` and an injected index.js / .config payload:
#   gh api "/repos/<repo>/commits/<sha>" --jq '.files[].filename'
```

### 3b. AI-assistant config tampering committed into repos

```bash
for f in ".claude/settings.json" ".vscode/tasks.json" ".vscode/setup.mjs" ".cursorrules" ".windsurfrules" ".github/copilot-instructions.md"; do
  q=$(printf '%s' "$f" | python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.stdin.read()))")
  echo "=== $f ==="
  gh api "search/code?q=path:${q}+org:${ORG}&per_page=50" \
    --jq '.items[]? | "\(.repository.full_name)\t\(.path)"' 2>/dev/null
  sleep 2
done
# Inspect hits for SessionStart hooks executing index.js, or invisible appended commands.
```

### 3c. Dead-drop / exfil repos and unfamiliar pushes in the window

```bash
gh api --paginate "/orgs/${ORG}/repos?per_page=100&sort=created&direction=desc" \
  --jq ".[] | select(.created_at > \"${SINCE}\" and .created_at < \"${UNTIL}\") | \"\(.name) | \(.created_at) | \(.visibility)\""
```

### 3d. Did the worm republish *your* packages?

If any maintainer's token was exposed, Miasma can republish the org's own npm/PyPI/RubyGems packages. Enumerate packages published in the window and inspect tarballs for an injected `index.js` referencing the markers above / Bun / `eval()`. (See `miasma_supply_chain/playbook.md` Phase 2b for the npm forward-propagation procedure — the same logic applies.)

---

## Phase 4: Workstation / Lateral-Movement Check

The payload spreads over SSH and hijacks local AI-assistant configs, so a developer or self-hosted-runner host reachable from a compromised runner can be hit even though it never ran the action.

```bash
# Dropped lateral-movement payload
ls -la ~/.config/index.js 2>/dev/null

# Local AI-assistant config tampering
grep -rliE "SessionStart|index\.js|bun |oven-sh/bun" \
  ~/.claude/settings.json ~/.vscode/tasks.json ~/.vscode/setup.mjs \
  ~/.cursorrules ~/.windsurfrules 2>/dev/null

# Shell history for the attack chain
grep -iE "oven-sh/bun|RevokeAndItGoesKaboom|TheBeautifulSandsOfTime|~/.config/index\.js|skip-checks:[[:space:]]*true" \
  ~/.bash_history ~/.zsh_history ~/.local/share/fish/fish_history 2>/dev/null

# Is gh authenticated on this host? (its token is a theft target)
gh auth status 2>/dev/null
```

### AI-agent conversation logs

> **Exclude the investigating agent's own session.** If you're running this playbook through an AI coding agent, its transcript contains these IOC strings because you've been *reading* them — that's evidence of investigation, not compromise. Exclude the current session dir.

```bash
CURRENT_SESSION_PROJECT=$(echo "$PWD" | sed 's|/|-|g')
grep -rliE "RevokeAndItGoesKaboom|TheBeautifulSandsOfTime|6b9501e1889cc45c91726729610cf69c2442b8c5|9f93d77d32833a515bc406c46da477142bb1ac2babeecb6aa42f98669a6db015" \
  "$HOME/.claude/projects" \
  "$HOME/Library/Application Support/Cursor" \
  "$HOME/Library/Application Support/Windsurf" \
  "$HOME/.config/github-copilot" 2>/dev/null | \
  grep -v "${CURRENT_SESSION_PROJECT}" | grep -v "paste-cache" | grep -v "file-history"
```

---

## Phase 5: Document Findings

Per repo, write `$LOG_DIR/evidence.csv`:

| Field | Value |
|---|---|
| repo | |
| workflow path(s) referencing the action | |
| ref style | tag / branch / SHA |
| ref value | |
| SHA predates 2026-06-24 15:39 UTC? | yes / no / n/a |
| ran during window? | yes / no |
| poisoned step executed (Bun + payload IOC)? | yes / no |
| secrets exposed to that workflow | list |
| worm footprint (propagation commit / AI-config tamper / dead-drop repo)? | yes / no |
| rotation completed? | yes / no / n/a |

**Verdict:** `clean` if every reference is SHA-pinned to a pre-compromise commit OR no run executed the action in the window with no worm footprint; `compromised` if any run executed the poisoned tag, or any propagation/AI-config/dead-drop signal is present.

---

## Phase 6: Next Steps — Hardening & Remediation

- **Any run executed the poisoned tag, or any worm footprint found** → treat as compromised. Proceed immediately to **[hardening.md](hardening.md)** (rotate-first ordering) and rotate every secret the affected workflows could reach.
- **References are tag/branch-pinned but no run executed in the window** → vulnerable-but-not-hit. Proceed to hardening to pin to SHAs before the next run.
- **All references already SHA-pinned to pre-compromise commits** → hardened; no action beyond confirming the maintainer restores clean tags before un-pinning.

Present the evidence table to the user, then ask whether to proceed with **[hardening.md](hardening.md)**.

---

## Pitfalls & Fixes

- **Tag looks like a version but is mutable.** `@v3.5.0` *reads* like a pinned release but is a tag the attacker repointed. Only a 40-char SHA is immutable. Classify on ref shape, not on whether it "looks specific."
- **A pre-compromise SHA that executed is safe.** If a run shows `Run codfish/semantic-release-action@<40-char-sha>` and that commit predates 2026-06-24 15:39 UTC, the run is clean even though the action executed — don't flag it.
- **Bun alone is not proof.** Some repos legitimately use Bun. Flag a Bun install only when it appears *inside the action's run* in a workflow with no legitimate Bun step, or alongside a dead-drop marker.
- **`api.github.com` / `github.com` are normal.** Flag only writes/creation or runtime-download behavior correlated with the action step, never the bare domain.
- **Self-pollution.** When grepping AI-agent logs, exclude the current investigating session (it will "hit" on every IOC string you just read).
- **Trust the resolved-SHA line over the tag.** A tag ref that *resolved to* a known-malicious commit (printed on the `Download action repository '...' (SHA:…)` log line) is the single highest-confidence, lowest-false-positive signal — it proves the bad code ran, not just that a tag was referenced. The malicious-SHA grep in Phase 2c is what cleanly separates a poisoned run from one pinned to a benign SHA.
- **Broad grep is recall-only; classify on `uses:` lines.** A bare `grep -r "codfish/semantic-release-action" .` matches README/doc prose too — that's fine for *finding* candidate repos, but only the `uses:…@`-anchored regex feeds the tag-vs-SHA verdict. Don't flag a docs-only mention.

## References

- StepSecurity — codfish/semantic-release-action compromise advisory (primary): https://www.stepsecurity.io/blog/supply-chain-compromise-codfish-semantic-release-action
- Related same-campaign playbooks in this repo: `miasma_supply_chain/playbook.md`, `nx_console/playbook.md`, `trivy/detection.md`
- GitHub Actions tag-pinning guidance — https://docs.github.com/en/actions/security-for-github-actions
