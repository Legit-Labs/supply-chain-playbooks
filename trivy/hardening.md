# Trivy Supply Chain Compromise — Hardening & Prevention Guide

## Context: Why This Matters

The Trivy ecosystem was compromised on March 19-22, 2026 (GHSA-69fq-xp46-6x23). A threat actor exploited compromised credentials to poison multiple distribution channels simultaneously — GitHub Action tags, APT repositories, Docker images, and the setup-trivy installer. This guide explains each attack surface and how to eliminate it.

---

## Variables — Fill These In First

Run the script below to determine your safe versions and checksums, then set the variables.

### Step 1: Choose a safe trivy version and compute checksums

Any trivy version ≤ v0.69.3 is safe. Check the [Trivy releases page](https://github.com/aquasecurity/trivy/releases).

```bash
# Set your chosen safe version
export TRIVY_VERSION="<pick a version <= 0.69.3>"

# Download .deb files
wget -q "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb"
wget -q "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-ARM64.deb"

# Compute SHA256 checksums
export SHA_AMD64=$(sha256sum "trivy_${TRIVY_VERSION}_Linux-64bit.deb" | awk '{print $1}')
export SHA_ARM64=$(sha256sum "trivy_${TRIVY_VERSION}_Linux-ARM64.deb" | awk '{print $1}')
echo "TRIVY_VERSION=${TRIVY_VERSION}"
echo "SHA_AMD64=${SHA_AMD64}"
echo "SHA_ARM64=${SHA_ARM64}"

# Optionally cross-check against the release checksums file
wget -q "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt"
grep "Linux-64bit.deb\|Linux-ARM64.deb" "trivy_${TRIVY_VERSION}_checksums.txt"
```

### Step 2: Identify a safe trivy-action commit hash

Pin to a commit hash that predates the compromise (March 19, 2026):

```bash
# List recent tags and their commits
gh api "/repos/aquasecurity/trivy-action/git/refs/tags" --paginate \
  --jq '.[] | "\(.ref) \(.object.sha)"' | tail -10

# Look up a specific tag's commit
gh api "/repos/aquasecurity/trivy-action/git/ref/tags/<TAG>" --jq '.object.sha'

# IMPORTANT: Verify the commit date is BEFORE March 19, 2026
export ACTION_HASH="<the commit hash>"
gh api "/repos/aquasecurity/trivy-action/commits/${ACTION_HASH}" --jq '.commit.committer.date'
```

### Your variables

After running the above, you should have:

```bash
export TRIVY_VERSION="..."   # e.g. 0.69.3
export SHA_AMD64="..."       # SHA256 of Linux-64bit.deb
export SHA_ARM64="..."       # SHA256 of Linux-ARM64.deb
export ACTION_HASH="..."     # trivy-action commit hash (pre-compromise)
```

All examples below use `$TRIVY_VERSION`, `$SHA_AMD64`, `$SHA_ARM64`, and `$ACTION_HASH`.

---

## Attack Surface 1: GitHub Action Tag Poisoning

### The Problem

GitHub Action tags (e.g., `@v0.28.0`) are **mutable**. The attacker force-pushed 76 of 77 trivy-action version tags to point to malicious commits. Any workflow using a tag reference silently started running the attacker's code.

### The Fix

Pin all GitHub Actions to **full commit SHA hashes**, not tags:

```yaml
# VULNERABLE — mutable tag, can be force-pushed
uses: aquasecurity/trivy-action@v0.28.0

# SAFE — immutable commit hash
uses: aquasecurity/trivy-action@$ACTION_HASH # <version>
```

Use [ratchet](https://github.com/sethvargo/ratchet) to automate hash pinning across your workflows.

---

## Attack Surface 2: Transitive Action Dependencies (setup-trivy)

### The Problem

`trivy-action` internally calls `aquasecurity/setup-trivy` to install the trivy binary. Even if you pin trivy-action by commit hash, the action itself may reference setup-trivy by **tag** — which the attacker also poisoned.

The chain of trust looks like:

```
Your workflow
  → trivy-action@<commit-hash>     (pinned — safe)
    → setup-trivy@v0.2.1           (TAG — poisoned!)
      → downloads trivy binary      (from attacker-controlled source)
```

Different trivy-action versions handle this differently. Some pin setup-trivy by commit hash (safer), others by tag (vulnerable). Check the `action.yaml` inside the trivy-action commit you're using:

```bash
gh api "/repos/aquasecurity/trivy-action/contents/action.yaml?ref=$ACTION_HASH" --jq '.content' | base64 -d | grep "setup-trivy"
```

If you see `setup-trivy@v<tag>` (no commit hash), your transitive dependency is vulnerable.

### The Fix

Bypass setup-trivy entirely. Install trivy yourself and tell the action to skip its own installation:

```yaml
- name: Install Trivy
  run: |
    ARCH=$(dpkg --print-architecture)
    TRIVY_VERSION="$TRIVY_VERSION"
    if [ "$ARCH" = "arm64" ]; then
      DEB="trivy_${TRIVY_VERSION}_Linux-ARM64.deb"
      SHA="$SHA_ARM64"
    else
      DEB="trivy_${TRIVY_VERSION}_Linux-64bit.deb"
      SHA="$SHA_AMD64"
    fi
    wget -q "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${DEB}"
    echo "${SHA}  ${DEB}" | sha256sum -c
    sudo dpkg -i "${DEB}"

- name: Run Trivy
  uses: aquasecurity/trivy-action@$ACTION_HASH
  with:
    skip-setup-trivy: true
    # ... other options
```

This completely eliminates the setup-trivy dependency. You control exactly which binary runs.

---

## Attack Surface 3: Unpinned APT Binary Install

### The Problem

A common installation pattern adds Aqua Security's APT repository and installs trivy from it:

```bash
# VULNERABLE — three separate problems
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install -y trivy
```

This has **three problems**:

1. **Unpinned version**: `apt-get install -y trivy` gets whatever is latest. During the attack window, this installed v0.69.4 (malicious).

2. **Third-party APT repo as attack surface**: Adding `aquasecurity.github.io/trivy-repo/deb` as an APT source means ANY package in that repo could be installed. The repo is hosted on GitHub Pages — anyone with push access to the gh-pages branch controls the entire package index.

3. **Dependency confusion risk**: Once the repo is added, `apt-get` can resolve dependencies from it. A malicious repo could serve higher-versioned packages for common tools (wget, curl, openssl) that would be preferred over official ones.

Even pinning the version (`apt-get install -y trivy=X.Y.Z`) only solves problem #1. Problems #2 and #3 remain.

### The Fix

Download the `.deb` directly from GitHub Releases with a **hardcoded SHA256 checksum**:

```bash
# SAFE — no APT repo, hardcoded SHA256
ARCH=$(dpkg --print-architecture)
TRIVY_VERSION="$TRIVY_VERSION"
if [ "$ARCH" = "arm64" ]; then
  DEB="trivy_${TRIVY_VERSION}_Linux-ARM64.deb"
  SHA="$SHA_ARM64"
else
  DEB="trivy_${TRIVY_VERSION}_Linux-64bit.deb"
  SHA="$SHA_AMD64"
fi
wget -q "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${DEB}"
echo "${SHA}  ${DEB}" | sha256sum -c
sudo dpkg -i "${DEB}"
```

This eliminates all three problems:
- Version is hardcoded in the URL
- No APT repo is added — no package index pollution possible
- SHA256 is hardcoded in your workflow code — even if the attacker replaces the `.deb` on GitHub Releases, the checksum will reject it

### Why GitHub Releases Is Safer Than the APT Repo

| | APT Repo (github.io) | GitHub Releases |
|---|---|---|
| Can serve other packages | Yes (any package name) | No (scoped to one repo) |
| Can silently update | Yes (apt-get gets latest) | No (URL has version) |
| Checksum control | GPG key controlled by repo owner | SHA256 hardcoded in your code |
| Dependency confusion | Yes (can override system packages) | Not possible |

Note: GitHub Release assets are mutable (repo owners can delete and re-upload), but the **hardcoded SHA256 in your workflow is immutable** — it's in your git history and under your control.

---

## Attack Surface 4: Docker Image Tag Poisoning

### The Problem

Older trivy-action versions use Dockerfiles that pull trivy as a Docker image:

```dockerfile
FROM ghcr.io/aquasecurity/trivy:<version>
```

Docker/OCI tags are mutable. Anyone with push access can overwrite a tag with a different image. The attacker published malicious images to Docker Hub as v0.69.5 and v0.69.6.

### The Fix

Two options:

1. **Pin Docker images to digest** (if you must use Docker-based action versions):
   ```dockerfile
   FROM ghcr.io/aquasecurity/trivy:<version>@sha256:<digest>
   ```

2. **Upgrade to a composite trivy-action version** (v0.34.1+) — no Docker image involved at all. This eliminates the attack surface entirely.

Option 2 is recommended.

---

## Complete Hardened Workflow Example

Replace the placeholder values with the ones you computed in the Prerequisites section.

```yaml
- name: Login to ECR
  id: ecr-login
  uses: aws-actions/amazon-ecr-login@$ECR_LOGIN_HASH # v2

- name: Install Trivy
  run: |
    ARCH=$(dpkg --print-architecture)
    TRIVY_VERSION="$TRIVY_VERSION"
    if [ "$ARCH" = "arm64" ]; then
      DEB="trivy_${TRIVY_VERSION}_Linux-ARM64.deb"
      SHA="$SHA_ARM64"
    else
      DEB="trivy_${TRIVY_VERSION}_Linux-64bit.deb"
      SHA="$SHA_AMD64"
    fi
    wget -q "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${DEB}"
    echo "${SHA}  ${DEB}" | sha256sum -c
    sudo dpkg -i "${DEB}"

- name: Run Trivy vulnerability scanner
  id: trivy_scan
  uses: aquasecurity/trivy-action@$ACTION_HASH # <version>
  with:
    image-ref: "your-image"
    output: "trivy-results"
    severity: "CRITICAL,HIGH"
    exit-code: "1"
    ignore-unfixed: true
    skip-setup-trivy: true
  env:
    TRIVY_DB_REPOSITORY: ${{ steps.ecr-login.outputs.registry }}/github/aquasecurity/trivy-db
    TRIVY_JAVA_DB_REPOSITORY: ${{ steps.ecr-login.outputs.registry }}/github/aquasecurity/trivy-java-db
```

---

## Summary: Defense in Depth

| Attack Surface | Mitigation |
|---|---|
| trivy-action tag poisoning | Pin to commit hash |
| setup-trivy tag poisoning | `skip-setup-trivy: true` — bypass entirely |
| Unpinned APT binary | Direct `.deb` download from GitHub Releases |
| APT repo dependency confusion | Don't add the APT repo at all |
| Docker image tag poisoning | Upgrade to composite action (no Docker) or pin to digest |
| Trivy binary tampering | Hardcoded SHA256 checksum in workflow code |

---

## Updating Trivy Version

When upgrading to a new trivy version:

1. Download the new `.deb` files from GitHub Releases (amd64 + arm64)
2. Compute SHA256: `sha256sum trivy_X.Y.Z_Linux-64bit.deb` and `sha256sum trivy_X.Y.Z_Linux-ARM64.deb`
3. Optionally verify the sigstore signature (`.sigstore.json` available on each release)
4. Update the URL, version, and SHA256 in all workflow files
5. Test in one repo first, then roll out across the org
