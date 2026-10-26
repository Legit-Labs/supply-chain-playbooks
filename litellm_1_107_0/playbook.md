# LiteLLM 1.107.0 Release-Pipeline Compromise (PyPI + Docker, October 21 2026) — Investigation Playbook

> **CI/CD platform note:** This playbook targets GitHub Actions. For other platforms (GitLab CI, Jenkins, CircleCI, Bitbucket, Azure DevOps), adapt the log-collection commands — the investigation logic is unchanged: find every way the org consumes LiteLLM (PyPI package or container image), collect run logs from the exposure window, search for the malicious version, image digests and this incident's IOCs, then check hosts and running containers for the implant.

> **⚠️ Critical — do NOT run `python` or `pip` in a suspect environment.** The implant is a `.pth` file in `site-packages`, so **every Python interpreter start re-runs the credential stealer** — including `pip list`, `pip uninstall`, `python -c "import site"` and any health check. Inspect with shell tools (`find`, `ls`, `grep`, `lsof`) or from a known-clean host, and stop the backdoor process before cleaning.

> **⚠️ Critical — the official container images are in scope this time.** Unlike the March 2026 LiteLLM incident (1.82.7 / 1.82.8, PyPI only), the October build also went into `ghcr.io/berriai/litellm*` and `docker.io/litellm/litellm`, including the **floating tags `latest`, `main-latest` and `main-stable`**. Tags have since been repointed to clean images, so a tag name proves nothing — **check digests**.

> **⚠️ Trigger model is runtime, not install-time.** Nothing runs during `pip install` (the sdist and wheels carry no install hook). The payload fires the **first time any Python process starts** in the environment afterwards, whether or not `litellm` is ever imported. An install log is evidence of exposure; the running process is what steals.

---

## Incident Details

### CVE / advisory

- **CVE:** none (malicious release, not a vulnerability).
- **OSV:** [`MAL-2026-2144`](https://osv.dev/vulnerability/MAL-2026-2144) (alias `PYSEC-2026-2`) — now lists `1.82.7`, `1.82.8` **and `1.107.0`**.
- **Maintainer posts:** [incident post](https://docs.litellm.ai/blog/security-incident-oct-21-2026) and [root-cause analysis](https://docs.litellm.ai/blog/security-incident-oct-21-2026-attack-chain) (Oct 23, declared the canonical record; it replaces the earlier "tokens from deployment logs" theory).
- **Root cause (per LiteLLM's RCA):** an Agent Platform **master key** committed to the public repo `LiteLLM-Labs/lite-harness` (`opencode.json`) on **27 May 2026** was never revoked. On **10 Oct** the attacker used it to pull an organization owner's GitHub CLI token, then ran throwaway workflows on `BerriAI/litellm` (10 and 12 Oct) that posted about 20 CI secrets to `webhook.site` ([Socket](https://socket.dev/blog/litellm-attack-timeline)). On **21 Oct** the attacker overrode branch protection on `BerriAI/project-releaser`, pointed the release at the lookalike fork **`Berri-AI/litellm`**, approved the production gate with a second maintainer's token, and deleted the run records with a third.
- **Relationship to March 2026:** separate incident, different access path. The March playbook ([`litellm/`](../litellm/detection.md)) does not cover these IOCs.

### Affected artifacts

The git tag `v1.107.0` is clean; the payload exists only in the published wheels and images.

```bash
# Malicious package-version (the detection-time source of truth)
export PKG='litellm'
export AFFECTED='1.107.0'
# NOT affected: 1.107.0rc1, 1.107.0rc2, 1.107.0.dev*, 1.106.x — anchor every match on the exact final version
```

| Artifact | Malicious | Last version LiteLLM confirms safe |
|---|---|---|
| PyPI `litellm` | `1.107.0` — all seven wheels (`cp310-abi3`: macOS x86-64/arm64, manylinux x86-64/aarch64, musllinux x86-64/aarch64, win_amd64). The sdist has a tampered `pyproject.toml` (`data = "cook"` under `[tool.maturin]`) but no payload files. | `1.106.2` |
| `ghcr.io/berriai/litellm` | `v1.107.0`; `latest`, `main-latest`, `main-stable` during the window | `v1.106.2` (pin by digest) |
| `ghcr.io/berriai/litellm-database` | `v1.107.0`; floating tags during the window | `v1.106.2` (pin by digest) |
| `ghcr.io/berriai/litellm-non_root` | `v1.107.0`; floating tags during the window | `v1.106.2` (pin by digest) |
| `docker.io/litellm/litellm` | `v1.107.0`, `latest`, `main-latest`, `main-stable` | `v1.106.2` (pin by digest) |

LiteLLM's private enterprise release was not affected. `litellm-proxy-extras` and `litellm-enterprise` were not modified.

```bash
# Malicious image digests (index + per-platform manifests; runtimes report either)
export BAD_DIGESTS='1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e|bd1aeee419ea36da9aa2b657288da4101887be468f020ac63d22ba6ed84a3ea5|56b74573eed6e4aafe4b50603dbe7853e0345f188c8e44a09f1098caf1f4bcdf|24581ddc30767f16ecb69d2b0517556f2cd7dea56971adb42a3d1beb97d69523|827dd893c74cf621a860a66a3a447a5c732533f087589ce905573e285c0a239c|645a67d810628252d63df85dcc8824c58bcc77cf8383f4d3e6321f0ccc3ce9e4|f75c8edae59b72b1ebfd617295833f465c85bb2fab9c1d60f21b496db86cb8da'
```

| Image | Index | linux/amd64 | linux/arm64 |
|---|---|---|---|
| `ghcr.io/berriai/litellm:v1.107.0` (same as `docker.io/litellm/litellm`) | `sha256:1bbcb144…c339e` | `sha256:bd1aeee4…3ea5` | `sha256:56b74573…4bcdf` |
| `ghcr.io/berriai/litellm-database:v1.107.0` | `sha256:c00f9d92c427…` (published truncated) | `sha256:24581ddc…69523` | `sha256:827dd893…a239c` |
| `ghcr.io/berriai/litellm-non_root:v1.107.0` | `sha256:7b00e91cd2fe…` (published truncated) | `sha256:645a67d8…ce9e4` | `sha256:f75c8eda…cb8da` |

Full per-platform digests are in `$BAD_DIGESTS` above (from Chainguard and StepSecurity). The `litellm-database` and `litellm-non_root` index digests were only published truncated — match on the platform digests, or on the index prefix.

### Exposure window

Times are LiteLLM's own (RCA, Oct 23). Third-party posts differ by a few minutes (PyPI quarantine 13:20 vs 13:23; Docker removal 13:53 vs 14:20 vs 14:32) — the padded window below covers all of them.

| Event | Time (UTC, 21 Oct 2026) |
|---|---|
| Seven malicious wheels published to PyPI | 11:39:51 – 11:40:13 |
| Docker Hub and GHCR images published (incl. floating tags) | 11:46:56 |
| PyPI quarantines `1.107.0` | by 13:23 |
| GHCR tags unavailable | by 13:51 |
| Docker Hub tags removed or repointed to clean images | 14:20 |

**Recommended scan window (padded):** `2026-10-21T11:00:00Z` to `2026-10-21T15:00:00Z`.

**The window is not the whole exposure.** A container started from a malicious digest during the window keeps running (and polling) until it is replaced, and a pip/uv cache or internal mirror (Artifactory, Nexus, devpi) that fetched `1.107.0` can keep serving it after PyPI removed it. Phase 1 and Phase 3 are window-agnostic for that reason.

### Indicators of compromise

| IOC | Value | Where it shows up |
|---|---|---|
| Startup implant | `cook.pth` (one line: `import cook`) at the **root** of `site-packages` | any environment that installed the wheel |
| Stealer | `cook.py` at the root of `site-packages` (base64 + zlib-packed collector, "PRIVCOLLECT", 16 modules) | same |
| Backdoor | `sitecustomize.py` at the root of `site-packages` — forks a detached daemon (Linux/macOS only) | same |
| Wheel layout | `litellm-1.107.0.data/purelib/{cook.pth,cook.py,sitecustomize.py}` in the wheel `RECORD`; `litellm-1.107.0.dist-info/` | `site-packages`, pip/uv caches, mirrors |
| Run-once marker | `/tmp/.pc_once_72129118c59f5636c0bb` — written only after the exfiltration POST returns HTTP 200 | infected host — **present means data left**; absent does **not** mean clean |
| Backdoor lock | `/tmp/remote_code_loader.lock`, held by a detached Python process (PPID 1, own session, CWD `/`) | infected Linux/macOS host |
| Staging dirs | `.pc_sq_*`, `.pc_e_*` in the system temp directory (OpenSSL encryption staging uses `.pc_e_`) | infected host |
| Environment flag | `PRIVCOLLECT_ACTIVE=1` | process environments |
| Exfiltration | `http://www.litellm.dev/healthcheck` (plain-HTTP POST, `application/octet-stream`), domain `litellm.dev` registered 13 Oct 2026 | egress / DNS / proxy logs |
| Exfil headers | `X-Token: XWiA8gZNa7NcX2XRoAEb`, `X-SHA256: <body hash>`, a fake MSIE 7.0 User-Agent | proxy logs |
| Dead drop | `https://raw.githubusercontent.com/letters9813/pythonclient-test/main/domain.txt` (account and repo deleted 21 Oct; the file was empty when researchers checked) | egress logs |
| Second stage | `http://<domain-from-dead-drop>/codepy` — **any request to this path means remote code ran** | egress logs |
| Cloud metadata | Python-originated requests to `169.254.169.254` (AWS / GCP metadata credentials) | host / VPC flow logs |
| Lookalike source | `github.com/Berri-AI/litellm` (hyphenated), commit `20535d8fa11f786a6c24df7488a0e449ed5f09ad`; attacker author `Berri-AI <ckdi82fkoos@proton.me>` | provenance, build metadata |
| Encryption key | RSA-4096 public key, SPKI SHA-256 `a898fd08ad220fed52488906eb45d196f332b972ad5d85214e7726545ecc4218` | payload |

**Wheel SHA-256 (all seven, plus the sdist):**

```
7598727f209d717041db37f7dca271d3a7d328a279890e0e1d55375729aeb86d  litellm-1.107.0-cp310-abi3-macosx_10_12_x86_64.whl
0aaf7ba346d41ef2f40390436738b001180d5a1c03aa093f121078a9969d9a1a  litellm-1.107.0-cp310-abi3-macosx_11_0_arm64.whl
668169d35b87bf51324080390b1b1c5ab12bd335cfe5f1a99e3689abd5e02ae6  litellm-1.107.0-cp310-abi3-manylinux_2_28_aarch64.whl
462d0c9f67ca522d9e0e4acd245e90b36ce0d5353604a66bb7c43a1ec4a6fcf7  litellm-1.107.0-cp310-abi3-manylinux_2_28_x86_64.whl
c2e32d0ce2548aa662c18bf5001911a79fe5b30cf8357132275add02fdcde054  litellm-1.107.0-cp310-abi3-musllinux_1_2_aarch64.whl
1bbce8caa94f01c0aaa0b7ddae51553a8a32e1ce53d96d44fe583272aff7ad00  litellm-1.107.0-cp310-abi3-musllinux_1_2_x86_64.whl
12d4ccc5c6f8d35cf4f2cf233b7f3e418e863e657d81ff5f5fc9e210005b9484  litellm-1.107.0-cp310-abi3-win_amd64.whl
2befe2a79fb4fbbd9a543b5b40b530c8cffa8771bab22b8fb22b2e4ae3b1f819  litellm-1.107.0.tar.gz (tampered config, no payload)
```

**Implant SHA-256 (Linux/macOS, then Windows CRLF variant):**

```
7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb  cook.pth
84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d  cook.pth (Windows)
9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25  cook.py
03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea  cook.py (Windows)
34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa  sitecustomize.py
b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465  sitecustomize.py (Windows)
```

> **`sitecustomize.py` false-positive caveat.** `sitecustomize.py` is a legitimate Python hook that some base images and enterprise environments ship. The filename alone is not an IOC — confirm by hash, or by the strings `remote_code_loader` / `codepy` inside it.

> **Shared-infrastructure caveat.** `raw.githubusercontent.com` and `169.254.169.254` are used legitimately everywhere. They are IOCs only for the **exact dead-drop path** above, or for metadata requests from a host that also matches a file or process indicator — never as a static match in a repo file.

### What IS affected

- Any `pip` / `uv` / `poetry` / `pipenv` install that **resolved `litellm==1.107.0`** from PyPI or a mirror — directly or **transitively** (litellm has more than 2,000 dependent packages).
- Every environment where that wheel was installed and Python then ran: CI runners, developer workstations, servers and notebooks. The payload steals everything the process and user can read (see Phase 4).
- Container images **built** with a `pip install` that resolved `1.107.0` — the implant is baked into a layer and runs whenever the container starts.
- Containers **pulled and started** from `ghcr.io/berriai/litellm*` or `docker.io/litellm/litellm` at `v1.107.0`, or at `latest` / `main-latest` / `main-stable` between 11:46:56 and 14:20 UTC on 21 Oct — including Kubernetes pods that restarted during the window with `imagePullPolicy: Always`. A LiteLLM **proxy** container is the worst case: the stealer also reads provider keys from the proxy database when `DATABASE_URL` is set.
- Windows hosts run the stealer (`cook.py`) but not the backdoor daemon (it needs `os.fork`).

### What is NOT affected

- `litellm` **`1.106.2` and earlier**, and the pre-releases **`1.107.0rc1` / `1.107.0rc2`** — confirmed clean.
- Installs from a **committed lock file with a frozen installer** (`uv sync --frozen`, `poetry install` from `poetry.lock`, `pip install --require-hashes -r requirements.txt`) whose lock pins a version other than `1.107.0` — the malicious wheel is never resolved.
- Images **pinned by digest** to a pre-incident build, or pulled outside 11:46:56–14:20 UTC by tag (the tags were repointed to clean images by 14:20).
- **Source-only references** — `import litellm`, `LITELLM_API_KEY` / `LITELLM_MASTER_KEY` environment-variable names, Helm `values.yaml`, Terraform, or ArgoCD apps that name LiteLLM without installing or pulling it during the window.
- Building from the **GitHub source tag `v1.107.0`** — the tag is clean.

### Lock file protection

Lock files **do protect** if used correctly: `uv.lock` + `uv sync --frozen`, `poetry.lock` + `poetry install`, or a fully hashed `requirements.txt` + `pip install --require-hashes`, generated before 11:39:51 UTC on 21 Oct, install exactly the pinned (clean) version.

They do **not** protect if: CI runs `pip install litellm` / `pip install -r requirements.txt` with a floating specifier (`litellm`, `litellm>=1.100`, `litellm~=1.106`) during the window; the lock file was regenerated during the window (`uv lock --upgrade`, `poetry update`, a Dependabot/Renovate PR); or the image is pulled by a floating tag rather than a digest.

---

## Setup

```bash
export ORG="<your-github-org>"
export PKG='litellm'
export SINCE="2026-10-21T11:00:00Z"
export UNTIL="2026-10-21T15:00:00Z"
export LOG_DIR="/tmp/supply-chain-scan-litellm-1.107.0"
mkdir -p "$LOG_DIR"

# Exact-version anchor: matches 1.107.0 but not 1.107.0rc1 / 1.107.0.dev3 / 1.107.01
export BAD_VER='1\.107\.0($|[^.0-9a-z])'
export IMG_RE='(ghcr\.io/berriai/litellm(-database|-non_root)?|(docker\.io/)?litellm/litellm)'
export IOC_RE='cook\.pth|remote_code_loader|\.pc_once_72129118c59f5636c0bb|PRIVCOLLECT_ACTIVE|litellm\.dev|letters9813|pythonclient-test|/codepy|XWiA8gZNa7NcX2XRoAEb|Berri-AI/litellm'
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

**Goal:** find every repo that consumes LiteLLM — as a Python package **or** as a container image — and decide whether it *could* have resolved the malicious build. Window-agnostic.

### 1. Find references across the org

```bash
# Python package references
gh api -X GET search/code --paginate -f q="litellm org:${ORG}" \
  --jq '.items[]? | "\(.repository.full_name)\t\(.path)"' | sort -u | tee "$LOG_DIR/refs.tsv"

# Container image references (Dockerfiles, compose, Kubernetes, Helm)
for q in "berriai/litellm" "litellm/litellm"; do
  gh api -X GET search/code --paginate -f q="\"${q}\" org:${ORG}" \
    --jq '.items[]? | "\(.repository.full_name)\t\(.path)"'
  sleep 2
done | sort -u | tee "$LOG_DIR/image-refs.tsv"
```

> **Positive control** — prove the search works before trusting a zero-hit result:
> `gh api -X GET search/code -f q="requests org:${ORG}" --jq '.total_count'` should be non-zero for any org with Python repos. A broken query and a clean org look identical.

### 2. Classify each hit

| File type | Meaning |
|---|---|
| `requirements*.txt`, `pyproject.toml`, `setup.py`, `setup.cfg`, `Pipfile` | declared dependency — is the specifier exact (`==1.106.2`) or floating (`>=`, `~=`, bare)? |
| `uv.lock`, `poetry.lock`, `Pipfile.lock`, hashed `requirements.txt` | resolved version — **the decisive evidence** |
| `Dockerfile` with `pip install` | image build — did the build run in the window? |
| `Dockerfile` `FROM`, `docker-compose*.yml`, Kubernetes / Helm values with `image:` | image consumption — **tag or digest?** A floating tag (`latest`, `main-latest`, `main-stable`) is in scope if anything pulled it during the window |
| `.github/workflows/*` | the install command (`pip install` vs `uv sync --frozen`) and any `docker pull` / `services:` image |
| `*.py`, docs, env-var names (`LITELLM_*`) | not exposure on its own |

### 3. Extract version and image data per repo

```bash
# Resolved / declared litellm versions
cut -f1 "$LOG_DIR/refs.tsv" | sort -u | while read -r repo; do
  for f in uv.lock poetry.lock Pipfile.lock requirements.txt pyproject.toml; do
    gh api "repos/$repo/contents/$f" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null \
      | grep -n -A2 -iE '^name = "litellm"|"litellm"|^litellm|litellm[=<>~!]' | sed "s|^|$repo/$f: |"
  done
done | tee "$LOG_DIR/versions.txt"

grep -E "$BAD_VER" "$LOG_DIR/versions.txt"          # pinned to the malicious version
grep -iE 'litellm *($|[<>~]|>=)' "$LOG_DIR/versions.txt"   # floating specifiers — check CI for the window

# Image tags and digests in use
cut -f1,2 "$LOG_DIR/image-refs.tsv" | while IFS=$'\t' read -r repo path; do
  gh api "repos/$repo/contents/$path" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null \
    | grep -noE "${IMG_RE}[:@][A-Za-z0-9._:-]+" | sed "s|^|$repo/$path: |"
done | tee "$LOG_DIR/images.txt"
```

Flag: any lock or requirement pinned to `1.107.0`; any floating specifier on a repo whose CI uses a non-frozen installer; any image reference at `v1.107.0`, `latest`, `main-latest` or `main-stable`; any digest in `$BAD_DIGESTS`.

---

## Phase 2: CI Run Analysis

**Goal:** determine whether any pipeline actually installed the malicious wheel or pulled the malicious image inside the window. Because LiteLLM is often a **transitive** dependency, scan every repo with runs in the window, not only the repos from Phase 1.

### 1. Find runs in the window

```bash
gh api "orgs/${ORG}/repos" --paginate --jq '.[] | select(.archived|not) | .full_name' | while read -r repo; do
  gh run list --repo "$repo" --created "${SINCE}..${UNTIL}" --limit 200 \
    --json databaseId,name,createdAt,conclusion --jq \
    ".[] | \"$repo\t\(.databaseId)\t\(.createdAt)\t\(.name)\t\(.conclusion)\"" 2>/dev/null
done | tee "$LOG_DIR/runs.tsv"
```

### 2. Download logs in parallel

```bash
awk -F'\t' '{print $1" "$2}' "$LOG_DIR/runs.tsv" | \
  xargs -P 10 -n 2 sh -c 'gh run view --repo "$0" "$1" --log > "'"$LOG_DIR"'/$1.log" 2>/dev/null || true'
```

### 3. Scan logs for install lines, image pulls and this incident's IOCs

```bash
# Install-resolution lines for the exact malicious version (pip, uv, poetry) — not source imports
grep -rniE "(Collecting|Downloading|Using cached|Successfully installed|Installing collected packages|Installing|Resolved|Prepared|\+ ).*litellm" "$LOG_DIR"/*.log \
  | grep -iE "litellm[-=_ (]+${BAD_VER}|litellm-1\.107\.0-cp310"

# Image pulls of the affected images, then compare any digest against $BAD_DIGESTS
grep -rnE "${IMG_RE}:(v1\.107\.0|latest|main-latest|main-stable)" "$LOG_DIR"/*.log
grep -rnE "$BAD_DIGESTS" "$LOG_DIR"/*.log

# Runtime / implant IOCs (a runner that installed the wheel and then ran Python)
grep -rnE "$IOC_RE" "$LOG_DIR"/*.log
```

### 4. Classify hits

- `Successfully installed ... litellm-1.107.0`, `+ litellm==1.107.0` (uv), `Installing litellm (1.107.0)` (poetry), or `litellm-1.107.0-cp310-abi3-*.whl` → **confirmed install; the runner ran the stealer** the next time Python started in that job (every `python`/`pip`/`pytest` step after it).
- An image pull showing a digest in `$BAD_DIGESTS`, or a floating tag pulled between 11:46:56 and 14:20 UTC → the container ran the implant on start.
- `litellm==1.107.0rc1`, `1.107.0rc2`, `1.106.x` → clean; `LITELLM_*` variable names, Helm lint, ArgoCD sync of a pinned image → name only.

Record one row per run in `$LOG_DIR/evidence-ci-runs.csv`.

---

## Phase 3: Host, Container and Workstation Check

Run on every host, self-hosted runner, developer machine and container that installed `1.107.0` or ran an affected image — and on any long-running LiteLLM proxy deployment regardless of the window. **Use shell tools only** (see the warning at the top).

```bash
# 1. Implant files at the site-packages root (do not use python/pip to locate site-packages)
find / -xdev \( -name cook.pth -o -name cook.py \) -path "*site-packages*" 2>/dev/null
find / -xdev -name sitecustomize.py -path "*site-packages*" -exec grep -l -E "remote_code_loader|codepy" {} + 2>/dev/null
find / -xdev -type d -name "litellm-1.107.0.dist-info" 2>/dev/null

# 2. Markers, lock and staging dirs
ls -la /tmp/.pc_once_72129118c59f5636c0bb /tmp/remote_code_loader.lock 2>/dev/null
ls -d /tmp/.pc_sq_* /tmp/.pc_e_* "${TMPDIR:-/tmp}"/.pc_sq_* "${TMPDIR:-/tmp}"/.pc_e_* 2>/dev/null

# 3. The backdoor daemon (Linux/macOS)
lsof /tmp/remote_code_loader.lock 2>/dev/null || fuser -v /tmp/remote_code_loader.lock 2>/dev/null
grep -l "PRIVCOLLECT_ACTIVE" /proc/*/environ 2>/dev/null            # Linux

# 4. Cached copies of the malicious wheel (pip / uv / poetry caches)
find ~/.cache/pip ~/.cache/uv ~/.cache/pypoetry ~/Library/Caches/pip ~/Library/Caches/pypoetry \
  -iname "litellm-1.107.0*" 2>/dev/null
```

Windows (PowerShell) — the stealer runs on Windows even though the daemon does not:

```powershell
Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue -Include cook.pth,cook.py |
  Where-Object { $_.FullName -match 'site-packages' } | Select-Object FullName, LastWriteTime
```

Containers and clusters:

```bash
# Local images and running containers
docker images --digests | grep -E 'berriai/litellm|litellm/litellm'
docker ps --format '{{.ID}}\t{{.Image}}' | grep -iE 'litellm' | while read -r id img; do
  echo "$id $img $(docker inspect --format '{{.Image}}' "$id")"
  docker exec "$id" sh -c 'find / -xdev -name cook.pth -path "*site-packages*" 2>/dev/null; ls /tmp/.pc_once_* /tmp/remote_code_loader.lock 2>/dev/null'
done

# Kubernetes: every running image ID, compared against the malicious digests
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\t"}{range .status.containerStatuses[*]}{.imageID}{" "}{end}{"\n"}{end}' \
  | grep -iE 'litellm' | grep -E "$BAD_DIGESTS"
```

Also check images you **built** that install litellm: `docker run --rm --entrypoint sh <image> -c 'find / -xdev -name cook.pth -path "*site-packages*"'` (overrides the entrypoint so Python never starts).

### If anything matches

1. **Isolate** the host or pod from the network. Do not run `python` or `pip` on it.
2. **Stop the backdoor:** kill the process holding `/tmp/remote_code_loader.lock` (`kill <pid>` from step 3), then confirm nothing holds the lock.
3. **Preserve evidence:** copy `cook.pth`, `cook.py`, `sitecustomize.py` (hash them against the list above), the `/tmp` markers and the process list before deleting anything.
4. **Remove** `cook.pth`, `cook.py` and the malicious `sitecustomize.py` from every `site-packages`, or — preferred — destroy and rebuild the environment or image from a verified artifact.
5. **Then** move to Phase 4 and rotate, from a different clean machine.

---

## Phase 4: Blast Radius

For each confirmed install or affected container, enumerate what the stealer could read. It collects:

- **Cloud and workload:** AWS, Azure and GCP CLI credentials and caches; **instance-metadata credentials** (it queries `169.254.169.254`); ECS/GCP/Azure tokens; Kubernetes service-account tokens and kubeconfigs; Docker config; mounted secrets (`/run/secrets`); Vault and Terraform credentials.
- **Source control and registries:** Git credentials, GitHub CLI tokens, npm / PyPI / Maven / Cargo tokens, `.env` files.
- **Keys:** SSH, GPG and TLS private keys.
- **CI/CD:** GitLab Runner, Jenkins and other CI configs; on Linux, the **environment of every readable process** (`/proc/<pid>/environ`) — so masked CI secrets are in scope.
- **AI tools:** Claude Code, Cursor, Copilot, Gemini CLI, Codex and other assistant/IDE configs and tokens.
- **Browsers and history:** Chromium-family and Firefox credential stores, cookies and history; shell and database-client history.
- **LiteLLM proxy:** when `DATABASE_URL` is set, up to 500 rows per query from `LiteLLM_CredentialsTable` and `LiteLLM_ProxyModelTable` — i.e. **every upstream model-provider key stored in the proxy**.

Then look for use of what was taken:

```bash
# Egress / DNS / proxy logs, 21 Oct onwards
#   www.litellm.dev | litellm.dev | /healthcheck with X-Token: XWiA8gZNa7NcX2XRoAEb
#   raw.githubusercontent.com/letters9813/pythonclient-test/main/domain.txt
#   any request path ending in /codepy  → second stage ran: escalate to full incident response
```

- **AWS CloudTrail:** `sts:GetCallerIdentity` from an instance or task role around the install time, and any use of that role's credentials from outside your infrastructure. Researchers reported the attacker validating stolen AWS role credentials about 4.5 hours after exfiltration (`GetCallerIdentity`, Bedrock model listing, and IAM enumeration in some environments).
- **Model providers:** usage spikes or new keys on OpenAI, Anthropic, Bedrock, Azure OpenAI, Vertex and other providers whose keys sat in the proxy database.
- **GitHub:** audit-log activity for tokens that were present on an affected host.

---

## Phase 5: Remediation, in order

1. **Isolate** affected hosts, runners and pods. Do not run Python there.
2. **Stop the backdoor and remove the implant** (Phase 3) — or destroy the environment.
3. **Pin and rebuild:** `litellm==1.106.2` (LiteLLM's confirmed-safe version) in every manifest and lock file, regenerated on a clean host. Pin images by **digest** after verifying them, never by `latest` / `main-latest` / `main-stable`. Purge `1.107.0` from pip/uv/poetry caches and from internal mirrors (Artifactory, Nexus, devpi). Rebuild images with `--no-cache`.
4. **Rotate every credential** reachable from an affected host or run, from a clean machine: cloud keys and instance/task roles, Kubernetes service-account tokens, CI secrets, GitHub and registry tokens, SSH/GPG/TLS keys, AI-tool tokens, and browser sessions. On proxy hosts also rotate the LiteLLM master key and salt key, all virtual keys, every provider key in `LiteLLM_CredentialsTable`, and the `DATABASE_URL` password. **Revoke sessions, not just keys.**
5. **Block** `litellm.dev` (and `www.litellm.dev`) at DNS/egress, and alert on any request to a `/codepy` path.
6. **Harden:** frozen, hash-pinned installs (`uv sync --frozen`, `poetry install`, `pip install --require-hashes`); digest-pinned images; an egress allowlist for CI runners and proxy hosts. For your own release pipelines, the LiteLLM chain is the lesson: revoke any secret ever committed (history rewrites do not revoke), keep owner-level tokens out of automation, and restrict release workflows to approved source repositories and branches.

---

## Pitfalls & Fixes

- **`1.107.0rc1`, `1.107.0rc2` and `1.107.0.dev*` are clean.** A naive `grep 1.107.0` flags them — always use `$BAD_VER`, which requires the version to end there.
- **`litellm` matches everywhere.** `LITELLM_API_KEY`, Helm chart names, ArgoCD apps and `import litellm` are not exposure. Match installer output and image pulls, not the bare name.
- **Tags lie.** `latest` today points to a clean image; what matters is the digest a container actually ran. Use `docker inspect` / pod `imageID`, not the tag in a manifest.
- **`sitecustomize.py` exists legitimately** in some images — confirm by hash or by its contents.
- **Absence of the run-once marker is not a clean bill of health.** It is only written after a successful upload; a host whose exfiltration failed re-runs the stealer on every Python start and may still have succeeded later.
- **Self-pollution:** if you search AI-agent conversation logs or shell history on the investigating machine, exclude the current investigation session — it will always "hit" on the IOC strings it just read.

---

## Evidence table

Record one row per repo (`$LOG_DIR/evidence-repos.csv`):

| Repo | Consumption (PyPI / image / both) | Declared specifier | Resolved version or image digest | Install cmd / pull ref | Ran in window? | Log hit | Implant found | Verdict |
|---|---|---|---|---|---|---|---|---|
| | | | | | | | | affected / not affected |

## Wrap-up

Deliverables: the evidence table; the list of hosts, runners and pods checked (with the Phase 3 output); the order in which implant removal and rotation happened; the credentials rotated (including LiteLLM proxy provider keys where relevant); egress-log results for `litellm.dev` and `/codepy`; and confirmation that caches, mirrors and images were purged and rebuilt. For orgs with no hits, record the negative result together with the positive-control output that proves the search actually ran.
