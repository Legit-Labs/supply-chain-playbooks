# LiteLLM Supply Chain Compromise — Detection & Assessment Playbook

> **Note for AI agents:** This playbook has been tested against **GitHub Actions** CI/CD infrastructure. If the target organization uses a different CI/CD platform (GitLab CI, Jenkins, CircleCI, Bitbucket Pipelines, Azure DevOps, etc.), adapt the steps accordingly — the detection logic remains the same: identify all litellm references, collect CI run logs from the exposure window, search for compromised versions and IOCs, and classify hits. Substitute the platform-equivalent commands for fetching workflow runs, downloading logs, and inspecting dependency resolution output.

## Variables — Fill These In First

Set these before running any commands in this playbook:

```bash
# Your GitHub organization name
export ORG="your-org-name"

# Exposure window (official: 10:39–16:00 UTC; padded 10:00–17:00 for safety)
export SINCE="2026-03-24T10:00:00Z"
export UNTIL="2026-03-24T17:00:00Z"

# Directory to store downloaded logs
export LOG_DIR="/tmp/litellm-scan"
mkdir -p "$LOG_DIR"
```

All commands below use `$ORG`, `$SINCE`, `$UNTIL`, and `$LOG_DIR`.

---

## Background

On March 24, 2026, two compromised versions of the `litellm` package — **v1.82.7** and **v1.82.8** — were [published directly to PyPI](https://docs.litellm.ai/blog/security-update-march-2026), bypassing LiteLLM's official CI/CD pipeline. The compromise originated from the Trivy dependency used in LiteLLM's CI/CD security scanning workflow — the attacker leveraged this to upload malicious packages directly to PyPI. The GitHub repository and Docker images were never compromised. LiteLLM has engaged **Google Mandiant** for forensic analysis.

Any CI/CD pipeline or developer machine that installed `litellm` from PyPI during the exposure window may have leaked secrets. This includes **transitive installs** — if any package in your dependency tree pulls in `litellm`, even indirectly, the malicious code would execute.

### Affected Versions

| Version | Payload | Status |
|---------|---------|--------|
| **v1.82.7** | Malicious code injected into `proxy_server.py` | Yanked from PyPI |
| **v1.82.8** | Malicious code in `proxy_server.py` + `litellm_init.pth` dropped into site-packages | Yanked from PyPI |
| v1.82.6 and earlier | Clean | Safe |

### Exposure Window

| Event | Time (UTC) |
|-------|-----------|
| Malicious v1.82.7 published to PyPI | March 24, 10:39 |
| Malicious v1.82.8 published to PyPI | March 24 (during window) |
| Packages yanked from PyPI | March 24, ~16:00 |
| Recommended scan window (padded) | March 24, 10:00 – 17:00 |

### Attack Vector

The compromised versions contained a credential stealer injected into `proxy_server.py`. v1.82.8 also dropped a persistent `.pth` file (`litellm_init.pth`) into the Python `site-packages` directory, which executes automatically on any Python startup. The payload:

1. Collected environment variables, SSH keys, cloud provider credentials (AWS, GCP, Azure), Kubernetes tokens, and database passwords
2. Encrypted the data and exfiltrated it via HTTPS POST to `models.litellm.cloud` — an attacker-controlled domain not affiliated with LiteLLM

### Indicators of Compromise

| Category | Indicator |
|----------|-----------|
| Exfiltration domain | `models.litellm.cloud` |
| Malicious versions | `litellm==1.82.7`, `litellm==1.82.8` |
| Persistent file | `litellm_init.pth` in Python site-packages |
| Malicious code location | `litellm/proxy/proxy_server.py` |

### What IS Affected

- Any `pip install litellm` that resolved **v1.82.7 or v1.82.8** from PyPI during the window
- `poetry install`, `uv sync`, `pipenv install`, or similar that resolved litellm from PyPI during the window
- Transitive installs — packages that declare litellm as a dependency
- Docker image builds that `pip install litellm` during the window
- Developer machines that installed or upgraded litellm during the window
- **Any Python environment where `litellm_init.pth` exists** — this file persists after uninstall and executes on every Python startup

### What is NOT Affected

- Pre-built Docker images pulled from **GHCR** (`ghcr.io/berriai/litellm`) — the GitHub repo and container images were never compromised
- Installations from the **GitHub repository** directly (not affected)
- Helm charts or Kubernetes configs that reference litellm by service name
- Terraform, ArgoCD, or infrastructure-as-code that references litellm
- Installs that used a pinned hash or cached/vendored copy from before the window
- Any version **v1.82.6 or earlier**

---

## Step 1: Identify All litellm References Across the Org

### 1a. Search all code for litellm

Cast a wide net first:

```bash
gh api "search/code?q=litellm+org:${ORG}&per_page=100" \
  --jq '.items[] | "\(.repository.full_name)\t\(.path)"' | sort -u
```

If more than 100 results, paginate with `&page=2`, `&page=3`, etc.

### 1b. Classify each reference

For each file found, determine the category:

| File pattern | Category | Risk |
|-------------|----------|------|
| `requirements*.txt`, `setup.py`, `setup.cfg`, `pyproject.toml`, `Pipfile` | PyPI direct dependency | **HIGH** — check if installed during window |
| `poetry.lock`, `Pipfile.lock`, `uv.lock` | Lock file | **HIGH** — litellm is in the dependency tree (even as an optional extra, it may be installed in some configurations) |
| `Dockerfile` | Docker build | **HIGH** if it runs `pip install litellm` |
| `.github/workflows/*.yml` | CI workflow | **CHECK** — does it install Python deps that include litellm? |
| `values.yaml`, `Chart.yaml`, `deployment.yaml` | Infrastructure config | **NOT AFFECTED** — service name reference |
| `*.tf`, `*.tfvars` | Terraform | **NOT AFFECTED** — infrastructure naming |
| `*.py` | Python source | **NOT AFFECTED** — import reference, not install |

### 1c. Check Python dependency files specifically

```bash
for pattern in "requirements" "setup.py" "setup.cfg" "pyproject.toml" "Pipfile"; do
  echo "=== ${pattern} ==="
  gh api "search/code?q=litellm+org:${ORG}+path:${pattern}&per_page=100" \
    --jq '.items[] | "\(.repository.full_name) | \(.path)"' 2>/dev/null
  sleep 1
done
```

For any results, read the file and confirm litellm is an actual dependency (not a comment):

```bash
gh api "repos/${ORG}/<repo>/contents/<path>" --jq '.content' | base64 -d | grep -in "litellm"
```

### 1d. Check Docker images

For any Dockerfile referencing litellm:

- `FROM ghcr.io/berriai/litellm...` → Pre-built image, **not affected** according to LiteLLM's advisory (GHCR images pin dependencies and were not rebuilt during the window)
- `RUN pip install litellm` → **Affected if built during the window**
- `COPY requirements.txt . && RUN pip install -r requirements.txt` → Check if requirements.txt includes litellm

For Helm chart deployments, check the image source:

```bash
gh api "repos/${ORG}/<repo>/contents/<values.yaml>" --jq '.content' | base64 -d | grep -A3 "image:"
```

- Image from `ghcr.io/berriai/litellm*` → Pre-built from GHCR, **not affected** per LiteLLM's advisory
- Image built internally → check that Dockerfile for `pip install litellm`

---

## Step 2: Scan GitHub Actions Workflow Logs

Even if no code explicitly declares litellm as a dependency, a transitive dependency could pull it in. The only way to be certain is to check actual CI logs.

### 2a. Find all repos with runs in the window

```bash
gh api "/orgs/${ORG}/repos" --paginate --jq '.[].name' | while read repo; do
  count=$(gh api "repos/${ORG}/${repo}/actions/runs?created=${SINCE}..${UNTIL}&per_page=1" \
    --jq '.total_count' 2>/dev/null)
  if [ "$count" != "0" ] && [ -n "$count" ]; then
    echo "${repo}: ${count} runs"
  fi
done
```

### 2b. Collect all run IDs

```bash
gh api "/orgs/${ORG}/repos" --paginate --jq '.[].name' | while read repo; do
  gh api "repos/${ORG}/${repo}/actions/runs?created=${SINCE}..${UNTIL}&per_page=100" \
    --jq ".workflow_runs[] | \"${repo}|\(.id)|\(.name)\"" 2>/dev/null
done > "$LOG_DIR/all_runs.txt"

echo "Total runs to scan: $(wc -l < "$LOG_DIR/all_runs.txt")"
```

### 2c. Download all run logs in parallel

Download logs first, then analyze locally. This avoids re-downloading for multiple grep passes:

```bash
cat "$LOG_DIR/all_runs.txt" | while IFS='|' read repo run_id name; do
  echo "$repo $run_id"
done | xargs -P 10 -L 1 bash -c \
  'gh run view "$1" --repo "${ORG}/$0" --log > "${LOG_DIR}/run-$1.log" 2>/dev/null && echo "OK: $0 $1" || echo "FAIL: $0 $1"'
```

### 2d. Scan logs for litellm references and compromised versions

```bash
# All litellm references
echo "=== litellm references ==="
grep -rlin "litellm" "$LOG_DIR"/run-*.log 2>/dev/null | while read f; do
  run_id=$(basename "$f" .log | sed 's/run-//')
  meta=$(grep "|${run_id}|" "$LOG_DIR/all_runs.txt" | head -1)
  echo "HIT: $meta"
  grep -in "litellm" "$f" | head -20
  echo "---"
done

# Compromised versions specifically
echo "=== Compromised version check ==="
grep -rlE "litellm.*(1\.82\.7|1\.82\.8)" "$LOG_DIR"/run-*.log 2>/dev/null | while read f; do
  run_id=$(basename "$f" .log | sed 's/run-//')
  meta=$(grep "|${run_id}|" "$LOG_DIR/all_runs.txt" | head -1)
  echo "*** COMPROMISED VERSION: $meta ***"
  grep -iE "litellm.*(1\.82\.7|1\.82\.8)" "$f" | head -10
  echo "---"
done

# Check for exfiltration domain IOC
echo "=== Exfiltration domain check ==="
grep -rli "models\.litellm\.cloud" "$LOG_DIR"/run-*.log 2>/dev/null | while read f; do
  run_id=$(basename "$f" .log | sed 's/run-//')
  echo "*** EXFILTRATION IOC: run $run_id ***"
done

# Check for .pth file references
echo "=== .pth file check ==="
grep -rli "litellm_init\.pth" "$LOG_DIR"/run-*.log 2>/dev/null | while read f; do
  run_id=$(basename "$f" .log | sed 's/run-//')
  echo "*** PTH FILE IOC: run $run_id ***"
done
```

> **Important:** Grep for `litellm` as a bare string (case-insensitive). Do NOT grep for `pip install litellm` — you'd miss transitive installs, resolver output, wheel downloads, etc.

### 2e. Classify the hits

For each hit, determine if it's a real PyPI download or just a name reference.

**PyPI download indicators** (COMPROMISED):
- `Downloading litellm`
- `Collecting litellm`
- `Installing collected packages: ... litellm`
- `Successfully installed ... litellm-`
- `Resolving litellm`
- `litellm-*.whl` or `litellm-*.tar.gz`
- `pypi.org/simple/litellm`
- `Built wheel for litellm`
- `Using cached litellm`

**Name-only indicators** (NOT AFFECTED):
- `Linting services/litellm` — Helm chart linting
- `BLACKLIST: ... litellm ...` — deploy configuration
- `LITELLM_API_KEY`, `LITELLM_ENDPOINT` — environment variable names
- `argocd app sync litellm` — ArgoCD sync of a pre-built image
- SAST rules that mention litellm as a detection target

### Reducing false positives

Most hits in large orgs will be infrastructure references (Helm values, Terraform, ArgoCD configs, env vars). Focus exclusively on pip/poetry/uv resolver output. If a hit doesn't look like Python package installer output, it's not a risk.

---

## Step 3: Check for Persistent Malware (`litellm_init.pth`)

v1.82.8 dropped a persistent `.pth` file into Python's `site-packages` directory. This file **survives uninstall/upgrade** and executes automatically on every Python startup.

This check cannot be run remotely via the GitHub API — share the following commands with the relevant teams to run on their environments:

```bash
# On any machine or server that may have installed litellm
python3 -c "import site; print(site.getsitepackages())" | tr ',' '\n' | while read dir; do
  if [ -f "${dir}/litellm_init.pth" ]; then
    echo "FOUND: ${dir}/litellm_init.pth"
    cat "${dir}/litellm_init.pth"
  fi
done
```

If `litellm_init.pth` is found, the environment is compromised. See the **[Hardening & Prevention playbook](litellm-hardening-playbook.md)** for remediation steps.

---

## Step 4: Assess Impact

### If PyPI downloads were found

1. **Identify which secrets were exposed.** The malicious package exfiltrated all environment variables. In GitHub Actions this includes:
   - `GITHUB_TOKEN` (short-lived, but usable during the run)
   - Repository secrets injected via `env:` or `with:`
   - Cloud credentials (AWS, GCP, Azure)
   - API keys, database passwords, signing keys

2. **Check the workflow file** to see which secrets were available:
   ```bash
   gh api "repos/${ORG}/<repo>/contents/.github/workflows/<workflow>.yml" \
     --jq '.content' | base64 -d | grep -iE "secrets\.|env:"
   ```

3. **Check if the compromised run produced artifacts** that were deployed (Docker images pushed, packages published, deployments triggered).

### If no PyPI downloads were found

The org is **not affected**. Document:
- Total repos checked
- Total workflow runs scanned
- How litellm is consumed (pre-built images, Helm charts, etc.)
- That log scanning confirmed no PyPI installs during the window

If affected, follow the **[LiteLLM Hardening & Prevention playbook](litellm-hardening-playbook.md)** for remediation and hardening.

---

## Step 5: Document Findings

For each repo, document:

| Field | Value |
|---|---|
| Repo name | |
| litellm consumption method | PyPI dependency / lock file / Docker build / config reference / none |
| Version (if pinned) | |
| CI runs during window? | yes / no |
| PyPI download detected in logs? | yes / no |
| Compromised version (1.82.7/1.82.8) detected? | yes / no |
| Secrets at risk (if affected) | list |

---

## Step 6: Next Steps — Hardening & Remediation

After completing the detection and documenting findings, review the results with the user:

- If **compromised versions (v1.82.7/v1.82.8) were detected** in CI logs or `litellm_init.pth` was found: strongly recommend proceeding to the hardening playbook immediately to rotate secrets, remove persistent malware, and pin dependencies.
- If **no compromised versions were detected** but litellm is consumed via **unpinned PyPI installs** (e.g. `pip install litellm` without version pinning or lock files): recommend the hardening playbook as a preventive measure — unpinned installs remain vulnerable to future supply chain attacks.
- If litellm is only consumed via **pre-built GHCR images** or **pinned versions with lock files**: the org's litellm usage is already safe. No further action needed.

Present a summary of findings to the user, then ask:

> Based on the detection results, would you like to proceed with the **[LiteLLM Hardening & Prevention playbook](litellm-hardening-playbook.md)**? It will pin litellm to an exact safe version, migrate from pip to uv or poetry for proper lock file support, remove any persistent `litellm_init.pth` files, and rebuild affected Docker images.
