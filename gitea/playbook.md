# Gitea Docker Image Auth Bypass (CVE-2026-20896) — Detection & Response Playbook

> **Note for AI agents:** This playbook detects a **vulnerable configuration state**, not a one-time poisoned install. There is no "exposure window" to scan CI logs against — an instance running the affected image with the dangerous default config is exploitable *right now*. Adapt the discovery step to wherever your org defines Gitea deployments (IaC repos, Helm charts, Kubernetes manifests, `docker-compose.yml`, `app.ini` files) and adapt the log-review step to wherever your Gitea instances write request/access logs. The detection logic is the same on any platform.

## Variables — Fill These In First

```bash
# Your GitHub organization name
export ORG="your-org-name"

# Known in-the-wild scanner IP (ProtonVPN exit node) — recon observed ~mid-July 2026
export IOC_IP="159.26.98.241"

# When public probing began (Gitea security release was late June 2026;
# in-the-wild probing observed ~13 days later). Treat "since the release" as the review window.
export SINCE="2026-06-25T00:00:00Z"

export LOG_DIR="/tmp/gitea-cve-2026-20896"
mkdir -p "$LOG_DIR"
```

---

## Background

**CVE-2026-20896** (CVSS 9.8, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, GHSA-f75j-4cw6-rmx4).

The **official Gitea Docker image** ships an `app.ini` template that hard-codes:

```ini
REVERSE_PROXY_TRUSTED_PROXIES = *
```

(in `docker/root/etc/templates/app.ini` and `docker/rootless/etc/templates/app.ini`). The safe upstream default is `127.0.0.0/8,::1/128` (loopback only). With the wildcard, Gitea trusts the `X-WEBAUTH-USER` header from **any** source IP. If an admin has enabled reverse-proxy authentication, an unauthenticated attacker who can reach the HTTP port directly can impersonate **any user, including an administrator**, with a single header and no password or token:

```
curl -H "X-WEBAUTH-USER: admin" http://<gitea-host>:3000/
```

Because Gitea is an SCM, a successful bypass exposes source code, CI secrets, tokens, SSH/deploy keys and webhook secrets — a supply-chain foothold. ~6,200 instances were internet-exposed during the first probing wave.

### Affected / Fixed

| | Version |
|---|---|
| Affected | Official Gitea Docker image **≤ 1.26.2** in default config |
| Fixed | **1.26.3** (security fix, but shipped a repo-code-page regression) → **upgrade straight to 1.26.4** |

In the fix, reverse-proxy authentication is opt-in and the trusted-proxy default is restricted.

### Exploitation preconditions (ALL must be true)

1. Image ≤ 1.26.2 (or an unpinned `:latest` pulled before 1.26.3 shipped).
2. `REVERSE_PROXY_TRUSTED_PROXIES` is unset (Docker image defaults it to `*`) or explicitly `*`.
3. An admin enabled `ENABLE_REVERSE_PROXY_AUTHENTICATION = true` — common when Gitea sits behind an SSO proxy (oauth2-proxy, Authelia, etc.).
4. The container's HTTP port is reachable **directly** by untrusted clients (i.e. not exclusively through a header-stripping proxy).

`ENABLE_REVERSE_PROXY_AUTO_REGISTRATION = true` raises the impact further — the attacker can create arbitrary accounts.

### What IS affected

- Gitea run from `gitea/gitea:<=1.26.2>` (or unpinned tag) **with reverse-proxy auth enabled** and the port directly reachable.

### What is NOT affected

- Instances on **1.26.3 / 1.26.4 or later**.
- Instances with `ENABLE_REVERSE_PROXY_AUTHENTICATION = false` (the default) — the `X-WEBAUTH-USER` header is ignored regardless of the trusted-proxies value.
- Instances where `REVERSE_PROXY_TRUSTED_PROXIES` is explicitly restricted to the real proxy IP(s) / loopback, **and** the container port is only reachable through that proxy (which strips/overwrites `X-WEBAUTH-USER` from clients).
- **Binary / package installs** (non-Docker) that use the upstream `app.example.ini` default (`127.0.0.0/8,::1/128`) — the `*` default is specific to the Docker image's shipped template.

---

## Phase 1 — Discover Gitea Deployments Across the Org

Find every place the org defines or runs Gitea. Look in IaC, container definitions, Helm, and raw config.

```bash
# Image references, Helm chart usage, and the two telltale config keys
for q in "gitea/gitea" "REVERSE_PROXY_TRUSTED_PROXIES" "ENABLE_REVERSE_PROXY_AUTHENTICATION" "chart: gitea"; do
  echo "=== $q ==="
  gh search code "$q" --owner "$ORG" --json repository,path -L 100 2>/dev/null | \
    python3 -c "import json,sys; [print(i['repository']['nameWithOwner'],'|',i['path']) for i in json.load(sys.stdin)]" | sort -u
done
```

**Positive control:** before trusting a clean result, confirm the search actually reaches your code — run `gh search code "FROM" --owner "$ORG" -L 5` and verify it returns known Dockerfiles. A zero-hit search and a broken search look identical.

Classify each hit:

- `Dockerfile` / `docker-compose.yml` / `*.yaml` k8s manifest / Helm `values.yaml` → a deployment definition; go to Phase 2.
- `app.ini` committed to a repo → read the config directly in Phase 2.
- Docs / READMEs / example snippets → note but not a live deployment.

---

## Phase 2 — Determine the Vulnerable State (version + config)

For each deployment definition found, answer three questions.

### 2a. Image version

```bash
# Pull image tags out of the deployment files you found
grep -rhoE "gitea/gitea:[^ \"']+" . 2>/dev/null | sort -u
```

- Tag `≤ 1.26.2` → **vulnerable version**.
- `:latest` / no tag / floating tag → **treat as vulnerable** unless you can prove the running image digest is ≥ 1.26.3 (`docker inspect --format '{{.Config.Image}}' <container>` on the host, or check the deployment's pinned digest).
- Tag `≥ 1.26.3` → version-safe (prefer 1.26.4).

### 2b. Trusted-proxies config

```bash
# Find the trusted-proxies setting in app.ini OR as a GITEA__security__ env var
grep -rniE "REVERSE_PROXY_TRUSTED_PROXIES" . 2>/dev/null
```

- **Not present anywhere** in a Docker deployment → the image default `*` applies → **vulnerable**.
- Present and set to `*` → **vulnerable**.
- Present and restricted to loopback / the real proxy IP → config-safe for this key.

### 2c. Reverse-proxy auth enabled?

```bash
grep -rniE "ENABLE_REVERSE_PROXY_AUTHENTICATION|ENABLE_REVERSE_PROXY_AUTO_REGISTRATION" . 2>/dev/null
```

- `ENABLE_REVERSE_PROXY_AUTHENTICATION = true` (or `GITEA__service__ENABLE_REVERSE_PROXY_AUTHENTICATION=true`) → the precondition that makes the header bypass live.
- Not set / `false` → the header is ignored; the instance is **not exploitable** via this CVE even on a vulnerable image (but still upgrade).

**Verdict for the instance = vulnerable only if 2a (version) AND 2b (`*`) AND 2c (auth enabled) all hold, AND the port is directly reachable (Phase 3).**

---

## Phase 3 — Check Exposure & Review Logs for Exploitation

### 3a. Is the port directly reachable?

Confirm on the host / in the network policy whether the Gitea HTTP port (default 3000) is reachable by anything other than the intended proxy. If clients can hit it directly, the header is attacker-controlled. (This lives on the host/network, outside repo scanning — have the deployment owner confirm.)

### 3b. Review Gitea request logs for header abuse

On each affected instance, inspect access/request logs since the release for the `X-WEBAUTH-USER` header arriving from untrusted source IPs, and for the known scanner:

```bash
# On the Gitea host (adapt the log path to your setup)
grep -aiE "X-WEBAUTH-USER" /var/lib/gitea/log/*.log 2>/dev/null
grep -a "$IOC_IP" /var/lib/gitea/log/*.log 2>/dev/null
```

### 3c. Look for the effects of a successful bypass

Signs an impersonation succeeded — check the Gitea admin panel and audit log since `$SINCE`:

- New / unexpected **admin users** (auto-registration abuse).
- New **access tokens**, **SSH / deploy keys**, or **OAuth apps** you didn't create.
- New or altered **webhooks** (exfiltration channel).
- Unexpected **repository reads, clones, commits, or releases** from unfamiliar sessions.

Any hit → treat the instance as compromised and proceed to remediation with credential rotation.

---

## Phase 4 — Remediation & Hardening

1. **Upgrade to 1.26.4** (not 1.26.3 — it carries a repo-code-page regression). Pull by digest, not a floating tag.
2. **Restrict trusted proxies** — set the real value explicitly, don't rely on the default:
   ```ini
   [security]
   REVERSE_PROXY_TRUSTED_PROXIES = 127.0.0.0/8,::1/128
   ```
   or `GITEA__security__REVERSE_PROXY_TRUSTED_PROXIES=127.0.0.0/8,::1/128`. Use the actual proxy's IP/CIDR if it isn't loopback-adjacent.
3. **Disable reverse-proxy auth if you don't use it** — `ENABLE_REVERSE_PROXY_AUTHENTICATION = false`. If you do use it, ensure the fronting proxy **strips/overwrites** `X-WEBAUTH-USER` on inbound client requests and is the only path to the port.
4. **Network-isolate the port** — the container HTTP port must not be directly reachable by untrusted clients; only the authenticating proxy should reach it.
5. **If any Phase 3 sign was found, rotate everything an impersonated admin could reach:** all repo/CI secrets, personal access tokens, OAuth app secrets, SSH & deploy keys, and webhook secrets. Then review commits/releases/settings changed since `$SINCE` for tampering.

---

## Evidence Table

Record one row per Gitea deployment:

| Field | Value |
|---|---|
| Repo / deployment source | |
| Image tag / digest | |
| Version safe? (≥1.26.3) | yes / no |
| `REVERSE_PROXY_TRUSTED_PROXIES` | `*` / restricted / unset(→`*`) |
| Reverse-proxy auth enabled? | yes / no |
| Port directly reachable? | yes / no / unknown |
| Exploitable now? | yes / no |
| Signs of abuse in logs? | list |
| Upgraded + config fixed? | yes / no |
| Secrets rotated? | yes / no / n/a |

---

## Pitfalls & Fixes

- **`X-WEBAUTH-USER` / `REVERSE_PROXY_TRUSTED_PROXIES` in docs or examples** — matches in READMEs, upstream example configs, or blog snippets are not a live deployment. Only deployment definitions (compose/k8s/Helm/`app.ini` actually applied) count.
- **A restricted trusted-proxies value reads as a "hit" but is safe** — `REVERSE_PROXY_TRUSTED_PROXIES = 127.0.0.0/8,::1/128` or a specific proxy CIDR is the *fix*, not the vuln. Read the value, don't just grep for the key.
- **Reverse-proxy auth disabled ⇒ not exploitable** — a vulnerable image + `*` is not exploitable via this CVE if `ENABLE_REVERSE_PROXY_AUTHENTICATION` is false. Still upgrade, but don't flag it as active exposure.
- **Binary installs ≠ Docker default** — the `*` default is shipped by the Docker image template only. A non-Docker install using the upstream default is not vulnerable on this basis; verify its actual `app.ini`.
- **Floating tags hide the real version** — `:latest` in a manifest tells you nothing about what's running. Check the running container's image digest on the host, not just the manifest.
