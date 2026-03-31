# Trivy Supply Chain Compromise — Detection & Response Playbook

> **Note for AI agents:** This playbook has been tested against **GitHub Actions** CI/CD infrastructure. If the target organization uses a different CI/CD platform (GitLab CI, Jenkins, CircleCI, Bitbucket Pipelines, Azure DevOps, etc.), adapt the steps accordingly — the detection logic remains the same: identify all trivy usage, collect CI run logs from the exposure window, search for compromised versions and IOCs, and verify pinning. Substitute the platform-equivalent commands for fetching workflow runs, downloading logs, and inspecting action/plugin references.

## Variables — Fill These In First

Set these before running any commands in this playbook:

```bash
# Your GitHub organization name
export ORG="your-org-name"

# Exposure window (from the advisory timeline — adjust if needed)
export SINCE="2026-03-19T00:00:00Z"
export UNTIL="2026-03-23T00:00:00Z"

# Directory to store downloaded logs
export LOG_DIR="$LOG_DIR"
mkdir -p "$LOG_DIR"
```

All commands below use `$ORG`, `$SINCE`, `$UNTIL`, and `$LOG_DIR`.

---

## Background

On March 19-22, 2026, a threat actor compromised multiple Trivy distribution channels (GHSA-69fq-xp46-6x23). The attacker:

1. Published a **malicious trivy binary v0.69.4** via GitHub Releases, Deb/RPM repos, GHCR, ECR Public, and Docker Hub
2. **Force-pushed 76 of 77 trivy-action tags** with credential-stealing malware
3. **Replaced all setup-trivy tags** with malicious commits
4. Published **malicious Docker Hub images** v0.69.5 and v0.69.6

The injected infostealer dumped process memory, scanned 50+ filesystem paths for credentials (SSH keys, AWS/GCP/Azure tokens, Docker configs), encrypted data with AES-256-CBC + RSA-4096, and exfiltrated to attacker infrastructure.

### Affected Versions

| Component | Compromised | Safe |
|---|---|---|
| Trivy binary | v0.69.4 (all channels), v0.69.5/v0.69.6 (Docker Hub only) | ≤ v0.69.3 |
| trivy-action | All tags except v0.35.0 (76/77 tags force-pushed) | Commits pinned before March 19 |
| setup-trivy | All 7 existing tags replaced | Commits pinned before March 19 |

> **Note:** The attacker also attempted to publish a malicious v0.70.0 release, but it was stopped before the tag or release was pushed. If you see any reference to v0.70.0 in your logs, treat it as suspicious.

### Exposure Window

| Component | Start (UTC) | End (UTC) | Duration |
|---|---|---|---|
| trivy v0.69.4 | March 19, 18:22 | March 19, ~21:42 | ~3 hours |
| trivy-action tags | March 19, ~17:43 | March 20, ~05:40 | ~12 hours |
| setup-trivy tags | March 19, ~17:43 | March 19, ~21:44 | ~4 hours |
| Docker Hub v0.69.5/v0.69.6 | March 22, 15:43 | March 22, ~01:40 | ~10 hours |

---

## Step 1: Identify All Trivy Usage Across the Org

### 1a. Search all code for trivy references

```bash
gh search code "trivy" --owner $ORG --json repository,path -L 100 | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data:
    repo = item['repository']['nameWithOwner']
    path = item['path']
    if '.github' in path or 'Dockerfile' in path or 'Chart' in path:
        print(f'{repo} | {path}')
" | sort -u
```

### 1b. For each file, classify the trivy reference

For each file found, determine:
- **Is it a trivy-action call?** → Check if pinned by commit hash or by tag. Extract the hash/tag.
- **Is it an APT install?** → Check if version is pinned and which APT repo is used
- **Is it a Docker image?** → Check the image tag and whether a digest is specified
- **Is it a setup-trivy call?** → Check if pinned by commit hash or by tag
- **Is it just a config reference?** (TRIVY_IGNORE, etc.) → Not directly vulnerable, but note it

---

## Step 2: Collect All GitHub Actions Runs During the Exposure Window

### 2a. Get all runs from March 19-22

```bash
SINCE="2026-03-19T00:00:00Z"
UNTIL="2026-03-23T00:00:00Z"

gh api --paginate "/orgs/$ORG/repos?per_page=100&sort=pushed" --jq '.[].name' | while read repo; do
  gh api "/repos/$ORG/$repo/actions/runs?per_page=100&created=$SINCE..$UNTIL" \
    --jq '.workflow_runs[] | "'$repo'|\(.id)|\(.created_at)|\(.name)|\(.conclusion)"' 2>/dev/null
done > $LOG_DIR/all-runs.txt

echo "Total runs: $(wc -l < $LOG_DIR/all-runs.txt)"
```

### 2b. Download all run logs in parallel

```bash
mkdir -p $LOG_DIR

cat $LOG_DIR/all-runs.txt | while IFS='|' read repo run_id rest; do
  echo "$repo $run_id"
done | xargs -P 10 -L 1 bash -c \
  'gh run view "$1" --repo "$ORG/$0" --log > "$LOG_DIR/run-$1.log" 2>/dev/null && echo "OK: $0 $1" || echo "FAIL: $0 $1"'
```

### 2c. Search logs for compromised versions

```bash
# Check for compromised trivy binary versions
for ver in "0.69.4" "0.69.5" "0.69.6"; do
  echo "=== Searching for trivy $ver ==="
  grep -rlE "trivy.*(${ver})|trivy_${ver}|\(${ver}\)" $LOG_DIR/run-*.log 2>/dev/null
done

# Check for trivy-action referenced by TAG (vulnerable to tag poisoning)
# This is the primary attack vector — force-pushed tags pulled malicious code
grep -rl "trivy-action@v" $LOG_DIR/run-*.log 2>/dev/null

# Also check for branch-based references (equally dangerous)
grep -rl "trivy-action@main\|trivy-action@master" $LOG_DIR/run-*.log 2>/dev/null

# Check for setup-trivy referenced by TAG (all tags were replaced)
grep -rl "setup-trivy@v" $LOG_DIR/run-*.log 2>/dev/null

# Check for Docker image pulls of compromised versions
for ver in "0.69.4" "0.69.5" "0.69.6"; do
  grep -rl "aquasecurity/trivy:${ver}" $LOG_DIR/run-*.log 2>/dev/null
done
```

### 2d. Verify your versions are safe

For each run that used trivy, extract the version and confirm it is ≤ v0.69.3:

```bash
# Extract trivy binary versions from APT install logs
# Common formats: "trivy amd64 X.Y.Z", "trivy_X.Y.Z_amd64.deb", "trivy (X.Y.Z)"
grep -rE "trivy[_ (]+[0-9]+\.[0-9]+\.[0-9]+" $LOG_DIR/run-*.log | \
  grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | sort | uniq -c | sort -rn

# Any version > 0.69.3 is compromised
```

### 2e. Map trivy-action commit hashes to known versions

```bash
# Extract all trivy-action hashes from logs
grep -roE "trivy-action@[a-f0-9]+" $LOG_DIR/run-*.log | \
  awk -F: '{print $NF}' | sort | uniq -c | sort -rn

# For each unique hash, look up the version:
# gh api "/repos/aquasecurity/trivy-action/commits/<HASH>" --jq '.commit.message'
# Cross-reference with the advisory to confirm it predates the compromise
```

### 2f. Check entrypoint.sh execution sources

The malware was injected into `entrypoint.sh` inside trivy-action. If any run executed `entrypoint.sh`, verify it came from a **hash-pinned** action (safe) and not a **tag-based** one (compromised):

```bash
grep -rl "entrypoint.sh" $LOG_DIR/run-*.log 2>/dev/null | while read f; do
  run_id=$(basename "$f" .log | sed 's/run-//')
  # Check if entrypoint.sh was from a hash-pinned action
  hash_ref=$(grep -oE "trivy-action@[a-f0-9]{40}" "$f" | head -1)
  tag_ref=$(grep -oE "trivy-action@v[0-9]+" "$f" | head -1)
  if [ -n "$tag_ref" ]; then
    echo "ALERT: $run_id — entrypoint.sh executed from TAG ref: $tag_ref"
  elif [ -n "$hash_ref" ]; then
    echo "OK: $run_id — entrypoint.sh executed from hash-pinned: $hash_ref"
  fi
done
```

### 2g. Check Docker image pulls — distinguish tag-only vs digest-pinned

Docker tags are mutable. A pull with a **digest** (`@sha256:...`) is safe; a pull with only a **tag** (`:0.52.2`) could have been tampered:

```bash
grep -rn "FROM.*aquasecurity/trivy:\|docker pull.*aquasecurity/trivy:" $LOG_DIR/run-*.log 2>/dev/null | while read line; do
  if echo "$line" | grep -q "@sha256:"; then
    echo "OK (digest-pinned): $(echo "$line" | grep -oE 'aquasecurity/trivy:[^ ]+' | head -1)"
  else
    echo "WARNING (tag-only): $(echo "$line" | grep -oE 'aquasecurity/trivy:[^ ]+' | head -1)"
  fi
done | sort | uniq -c | sort -rn
```

### 2h. Check for process memory access (infostealer IOC)

The malware dumped runner process memory via `/proc/<pid>/mem`:

```bash
grep -rl "/proc.*mem\|Runner\.Worker.*mem" $LOG_DIR/run-*.log 2>/dev/null
# Any match here is highly suspicious
```

### Reducing false positives

When grepping for "trivy" across logs, you'll encounter many non-actionable mentions. These are safe to ignore:

- **Branch names**: `origin/feat/fix-trivy`, `origin/trivy-tmp` — just git branch names in fetch output
- **Environment variables**: `TRIVY_IGNORE:`, `TRIVY_SKIP_FILES:`, `TRIVY: true` — workflow input parameters, not trivy execution
- **Internal action references**: `your-org/common-workflows/.github/actions/trivy-scan@main` — this is your own org's wrapper action, not aquasecurity's. Verify it calls trivy-action by hash internally.
- **Trivy scan output**: `Total: 5 (HIGH: 3, CRITICAL: 2)`, vulnerability tables — these are scan results, not installation indicators

Focus on: `trivy-action@`, `setup-trivy@`, `apt-get install.*trivy`, `FROM.*aquasecurity/trivy:`, and `entrypoint.sh`.

---

## Step 3: Check for Indicators of Compromise

### 3a. Search for exfiltration repos

The malware created public `tpcp-docs` repositories as a fallback exfiltration method:

```bash
gh api "/orgs/$ORG/repos?per_page=100" --jq '.[].name' | grep -i "tpcp"
```

Also search for any repos created during the exposure window:

```bash
gh api --paginate "/orgs/$ORG/repos?per_page=100&sort=created&direction=desc" \
  --jq '.[] | select(.created_at > "$SINCE" and .created_at < "$UNTIL") | "\(.name) | \(.created_at) | \(.visibility)"'
```

### 3b. Check if any workflow used the compromised APT repo during the window

If workflows used `sudo apt-get install -y trivy` (unpinned) between March 19 18:22 UTC and March 19 21:42 UTC, they would have installed v0.69.4.

```bash
# Find runs in the 3-hour APT window
# Filter runs within the APT compromise window (March 19 18:22-21:42 UTC)
grep -E "2026-03-19T(18|19|20|21):" $LOG_DIR/all-runs.txt | while IFS='|' read repo run_id rest; do
  grep -l "apt-get install.*trivy" "$LOG_DIR/run-${run_id}.log" 2>/dev/null && echo "AT RISK: $repo $run_id"
done
```

### 3c. Check Docker image pulls during the window

```bash
# Find all Docker pulls of aquasecurity/trivy images and check if digest-pinned
grep -rl "aquasecurity/trivy:" $LOG_DIR/run-*.log 2>/dev/null | while read f; do
  run_id=$(basename "$f" .log | sed 's/run-//')
  meta=$(grep "|${run_id}|" $LOG_DIR/all-runs.txt | head -1)
  has_digest=$(grep "aquasecurity/trivy:" "$f" | grep -c "@sha256:")
  tag_only=$(grep "aquasecurity/trivy:" "$f" | grep -cv "@sha256:")
  echo "$meta | digest-pinned: $has_digest | tag-only: $tag_only"
done
# Runs with tag-only Docker pulls during the window are at higher risk
```

### 3d. Check for typosquatted domains or suspicious network activity

The malware downloaded payloads from typosquatted domains and exfiltrated data:

```bash
grep -rliE "tpcp|trivy-.*release.*asset" $LOG_DIR/run-*.log 2>/dev/null
```

---

## Step 4: If Compromised — Rotate Secrets

If ANY workflow ran with a compromised version during the exposure window:

1. **Rotate ALL secrets** accessible to that workflow:
   - GitHub tokens (GITHUB_TOKEN is auto-rotated, but any PATs are not)
   - AWS credentials (access keys, session tokens, role assumptions)
   - Docker/container registry credentials
   - Slack webhooks
   - Any secrets fetched from secret managers during the workflow
   - SSH keys used by runners or deploy keys

2. **Review audit logs** for unusual API activity during and after the exposure window

3. **Check for unauthorized commits**, pull requests, or releases created during the window

4. **Review GitHub Actions permissions** — the malware had access to whatever GITHUB_TOKEN could do

---

## Step 5: Document Findings

For each repo, document:

| Field | Value |
|---|---|
| Repo name | |
| Trivy component used | binary / action / Docker image |
| Version / commit hash | |
| Pinned by | hash / tag / unpinned |
| Any runs during exposure window? | yes / no |
| Compromised version detected? | yes / no |
| Secrets at risk? | list |
| Rotation completed? | yes / no / n/a |

---

## Step 6: Next Steps — Hardening & Remediation

After completing the detection and documenting findings, review the results with the user:

- If **compromised versions were detected** or **tag-based (unpinned) references** were found: strongly recommend proceeding to the hardening playbook immediately to eliminate the vulnerable patterns.
- If **no compromised versions were detected** but workflows still use **mutable tag references** or **unpinned APT installs**: recommend the hardening playbook as a preventive measure — these patterns remain vulnerable to future supply chain attacks.
- If all references are already **hash-pinned with SHA256 verification**: the org's trivy usage is already hardened. No further action needed.

Present a summary of findings to the user, then ask:

> Based on the detection results, would you like to proceed with the **[Trivy Hardening & Prevention playbook](trivy-hardening-playbook.md)**? It will pin all action references to immutable commit hashes, replace APT repo installs with direct `.deb` downloads verified by SHA256 checksums, and bypass the compromised `setup-trivy` dependency entirely.
