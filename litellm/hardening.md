# LiteLLM Supply Chain Compromise — Hardening & Prevention Guide

## Context: Why This Matters

Two compromised versions of the `litellm` Python package — v1.82.7 and v1.82.8 — were [published directly to PyPI](https://docs.litellm.ai/blog/security-update-march-2026) on March 24, 2026, bypassing LiteLLM's official CI/CD pipeline. The compromise originated from the Trivy dependency used in LiteLLM's CI/CD security scanning workflow — the attacker leveraged this to upload malicious packages directly to PyPI. The payload exfiltrated environment variables, SSH keys, cloud credentials, and Kubernetes tokens to `models.litellm.cloud`.

This guide covers each attack surface exploited in the compromise and how to eliminate it.

---

## Prerequisites: Version Resolution

### Fetch all available versions and determine the safe pin

The compromised versions are **v1.82.7** and **v1.82.8** — all other versions are safe.

First, fetch the full version list from PyPI so you have it ready for all repos:

```bash
# Fetch all litellm versions from PyPI API
curl -s "https://pypi.org/pypi/litellm/json" | \
  python3 -c "import sys,json; vs=list(json.load(sys.stdin)['releases'].keys()); [print(v) for v in vs]" \
  > /tmp/litellm-all-versions.txt

# These are the compromised versions — never pin to these
export COMPROMISED_VERSIONS="1.82.7 1.82.8"
```

Then, for each repo, the agent should:

1. **Read the existing version specifier** from `requirements.txt`, `pyproject.toml`, `setup.cfg`, or `Pipfile`
2. **Resolve the latest safe version** that satisfies the specifier by filtering the version list — exclude 1.82.7 and 1.82.8, then pick the highest match

```bash
# The agent should parse the specifier and select the highest safe version
# from /tmp/litellm-all-versions.txt that satisfies the range
export LITELLM_VERSION="<resolved safe version>"
```

**Version selection rules** (litellm follows [semver](https://semver.org/) — the agent can fetch the full version list from the PyPI API above if unsure about ordering or range boundaries):

| Existing specifier | Action |
|---|---|
| `litellm` (bare) | Pin to latest safe version available |
| `litellm>=1.80` | Pin to highest safe version >=1.80 |
| `litellm>=1.80,<1.83` | Pin to 1.82.6 (highest safe in range) |
| `litellm~=1.82` | Pin to 1.82.6 (highest safe in ~= range) |
| `litellm>=1.70,<1.80` | Pin to latest in range — already safe, no compromised versions in this range |
| `litellm==1.82.7` or `==1.82.8` | Downgrade to 1.82.6 |

---

## Hardening 1: Pin PyPI Package Versions

### The Problem

The most common install pattern pulls whatever version is latest from PyPI:

```bash
# VULNERABLE
pip install litellm
```

Or in requirements.txt:

```
# VULNERABLE — unpinned or loosely pinned
litellm
litellm>=1.0
litellm~=1.82
```

This has **two problems**:

1. **Unpinned version**: `pip install litellm` gets whatever is latest. During the attack window, this installed v1.82.7 or v1.82.8 (malicious).

2. **Transitive exposure**: Other packages in your dependency tree may declare litellm as a dependency. You might not even know you're installing it.

### The Fix

Pin to an **exact version** using the version resolved in the Prerequisites section above. PyPI package files are immutable — once uploaded, a file cannot be replaced — so an exact version pin (`==`) is the primary defense.

```
# In requirements.txt — SAFE
litellm==1.82.6
```

For **poetry** or **uv** users, the lock file already pins exact versions. See Hardening 2 below for migrating to a lock file.

---

## Hardening 2: Migrate to a Lock File

### The Problem

`pip` does not have a lock file. A `requirements.txt` is a wish list, not a contract — it does not capture the full resolved dependency tree. This means:

1. **Transitive dependencies are invisible.** `pip install litellm` pulls dozens of sub-dependencies, and none of them are pinned unless you manually add every single one to requirements.txt.

2. **Reproducibility is not guaranteed.** Two `pip install` runs on the same requirements.txt can produce different environments if any transitive dependency published a new version between runs.

### The Fix

**Migrate from pip to a tool with proper lock file support.** Both **uv** and **poetry** generate lock files that pin every transitive dependency to an exact version.

#### Option A: uv (recommended — fastest, pip-compatible)

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Initialize from existing requirements.txt
uv init
uv add litellm==${LITELLM_VERSION}

# Generate lock file (hashes included automatically)
uv lock

# Install from lock file in CI
uv sync --frozen
```

`uv.lock` pins every transitive dependency. `--frozen` ensures CI fails if the lock file is out of date.

#### Option B: poetry

```bash
# Initialize
poetry init
poetry add litellm==${LITELLM_VERSION}

# Lock file is generated automatically (hashes included)
poetry lock

# Install from lock file in CI
poetry install --no-root
```

`poetry.lock` pins every resolved package.

#### If you must stay on pip

Use `pip-compile` from [pip-tools](https://github.com/jazzband/pip-tools) to generate a fully resolved requirements.txt:

```bash
pip install pip-tools

# Create requirements.in with your direct dependencies
echo "litellm==1.82.6" > requirements.in

# Generate pinned requirements.txt for ALL dependencies
pip-compile requirements.in -o requirements.txt

# Install in CI
pip install --no-cache-dir -r requirements.txt
```

This pins all transitive dependencies, but you must re-run `pip-compile` on every dependency change. uv or poetry handle this automatically.

---

## Remediation (only if affected)

The steps below are only needed if the detection playbook confirmed that your org installed v1.82.7 or v1.82.8 during the exposure window. If you were not affected, skip this section.

### Remove persistent `.pth` malware

v1.82.8's `litellm_init.pth` **survives package uninstall/upgrade**. Check all environments and delete it:

```bash
# Find and remove
python3 -c "import site; print('\n'.join(site.getsitepackages()))" | while read dir; do
  if [ -f "${dir}/litellm_init.pth" ]; then
    echo "FOUND: ${dir}/litellm_init.pth"
    rm -f "${dir}/litellm_init.pth"
  fi
done
```

### Rebuild Docker images built during the window

Any Docker image that ran `pip install litellm` during the window may contain the malicious package and `.pth` file baked into a layer. Upgrading litellm inside the image is not enough — the `.pth` file persists in cached layers.

1. **Identify affected images**:

```bash
gh api "search/code?q=litellm+org:${ORG}+filename:Dockerfile&per_page=100" \
  --jq '.items[] | "\(.repository.full_name) | \(.path)"'
```

2. **Rebuild from scratch**:

```bash
docker build --no-cache -t your-image .
```

---

## Summary

### Hardening (everyone)

| Attack Surface | Mitigation |
|---|---|
| Unpinned PyPI install | Pin exact version (`==`) — PyPI files are immutable |
| pip has no lock file | Migrate to uv or poetry (lock files pin all transitive deps) |

### Remediation (only if affected)

| Action | When needed |
|---|---|
| Delete `litellm_init.pth` from all environments | If v1.82.8 was ever installed |
| Rebuild Docker images with `--no-cache` | If images were built during the exposure window |

---

## General Recommendations

Beyond the litellm-specific steps above, consider hardening your broader supply chain:

- **Pin Docker base images to digest** — Docker tags are mutable. Pin to `@sha256:<digest>` to ensure reproducible builds.
- **Enable dependency review** on PRs with [actions/dependency-review-action](https://github.com/actions/dependency-review-action) to catch unexpected version changes before they merge.

---

## Updating litellm Version

When upgrading to a new litellm version:

1. Update the exact version pin in all requirements/lock files
2. If using uv or poetry, run `uv lock` or `poetry lock` to regenerate the lock file
3. Rebuild any Docker images that include litellm
