# WordPress Core Unauthenticated LFI → RCE (CVE-2026-87902) — Detection & Response Playbook

> **Note for AI agents:** This playbook detects a **vulnerable deployed application**, not a poisoned dependency. Three things make it different from a normal SCA follow-up. First, **dependency scanning will not find this** — WordPress core is almost never installed as a package; it is unzipped from wordpress.org, baked into a container image, or dropped on a host, so no `composer.json` or lock file references it. Second, **the container image tag is not the running version** — WordPress updates itself in place, so a pod built from `wordpress:6.4-apache` may be running something else entirely. Read the version off disk. Third, reaching RCE needs **two preconditions**, and the official PHP Docker image satisfies one of them by default — which makes containerised WordPress the *high-risk* population, not the safe one.

## Variables — Fill These In First

```bash
# Your GitHub organization name
export ORG="your-org-name"

# Patch released 2026-09-22. First exploitation attempt recorded 11:49 UTC the
# same day. Use the patch date as the start of the log-review window — the bug
# existed since 4.7.0 (2016), but targeted scanning began here.
export SINCE="2026-09-22T00:00:00Z"

# Published attacker IPs (updated 2026-09-24). Opportunistic scanning, no named
# actor — treat as a starting point, not a complete list.
export ATTACKER_IPS="104.194.9.227|43.250.53.42|180.251.159.243|195.178.110.247|107.189.14.87|45.61.184.170|92.246.130.76"

# Second-stage payload host observed in live attacks
export PAYLOAD_URL="raw.githubusercontent.com/MrG3P5/web-shell"

# Dropped-file names observed in the wild
export DROP_NAMES="wp-pear-rce-flag\.php|poc87902\.php|luci_.*\.php|zeta_.*\.php"

export LOG_DIR="/tmp/wordpress-cve-2026-87902"
mkdir -p "$LOG_DIR"
```

---

## Background

**CVE-2026-87902** — CVSS 4.0 **9.2**, CWE-98 (improper control of filename for an include statement). Reported by Robert Ressl, disclosed privately July 2026, patched **2026-09-22** in WordPress 7.1.2.

The flaw is in `get_page_template()`, the function that picks which theme file renders a page. WordPress builds a list of candidate template filenames, and one of them is taken directly from the `pagename` segment of the URL. On affected versions that value was never run through WordPress's own `../` traversal check, so an unauthenticated request can steer the template lookup to **any readable `.php` file on the server**.

No account is needed and no logged-in user has to do anything.

Local file inclusion is not by itself attacker-chosen code execution — it runs whatever that file happens to do. The documented escalation includes **PEAR's `pearcmd.php`** and supplies it parameters through the query string, which works when PHP's `register_argc_argv` is enabled.

### Affected / Fixed

| | Version |
|---|---|
| Affected | **4.7.0 through 7.1.1** — effectively every WordPress release from 2016 until the patch |
| Fixed | **7.1.2**, plus a backport to every branch still eligible for security fixes |

WordPress backported to **all 25 supported branches**. The patched tip of each:

```
4.7.37   4.8.32   4.9.33   5.0.29   5.1.26   5.2.28   5.3.25   5.4.23
5.5.22   5.6.21   5.7.19   5.8.17   5.9.18   6.0.16   6.1.14   6.2.13
6.3.12   6.4.12   6.5.12   6.6.9    6.7.9    6.8.10   6.9.9    7.0.6
7.1.2  ← current
```

Any version below its branch tip is affected. Authoritative check for any single version:

```bash
curl -s https://api.wordpress.org/core/stable-check/1.0/ \
  | python3 -c "import json,sys; d=json.load(sys.stdin); v='6.4.7'; print(v, '→', d.get(v,'unknown'))"
# "insecure" = affected · "outdated" = patched tip of an old branch · "latest" = current
```

### Exploitation preconditions

**File inclusion alone** works against any affected version. **Escalation to RCE** needs both of these:

1. **The active theme has a top-level directory whose name begins with `page-`** — `page-templates` is the common one. Legacy bundled themes and a number of popular third-party themes ship one.
2. **PHP `register_argc_argv = On`.**

⚠️ **Precondition 2 is on by default in the official PHP Docker images**, and in cPanel environments on PHP below 8.5. Per Patchstack: *"'unusual configuration' undersells how common it is."* If you run WordPress in a container and have not explicitly hardened this setting, you are in the highest-risk category — this is the opposite of the usual assumption that containerised means hardened.

### What IS affected

- Any WordPress core install between 4.7.0 and 7.1.1 that is reachable over HTTP, including sites behind a CDN or reverse proxy.
- Containerised WordPress built on the official `wordpress:*` or `php:*` images — by default these satisfy the `register_argc_argv` precondition.

### What is NOT affected

- Installs on their branch's patched tip (see the list above) or on 7.1.2.
- **`@wordpress/*` npm packages** — `@wordpress/scripts`, `@wordpress/element`, `@wordpress/escape-html` and the rest are the **Gutenberg JavaScript toolchain**. They contain none of the vulnerable code and are unaffected by a PHP core flaw. They are not even a reliable fingerprint that core is deployed — teams use them to build blocks for sites hosted elsewhere.
- **WordPress-adjacent tooling** — `wordpress-exporter` (Prometheus metrics), `gatsby-source-wordpress`, `stylelint-config-wordpress`, `psalm-plugin-wordpress`. These talk *about* WordPress; they are not WordPress. An exporter does suggest an instance exists nearby — treat it as a lead for Phase 1, not as a finding.
- Managed/hosted WordPress where the provider patches core (WordPress.com, WP Engine, Pressable and similar). Confirm which you are looking at before raising a finding.

### Exploitation status — updated 2026-09-24

Active and escalating. First exploitation attempt **2026-09-22 11:49 UTC**, the same day the patch
shipped. Traffic has since moved from reconnaissance against harmless core files to **payload
delivery**, roughly a **tenfold increase**, with **68 exploitation attempts** logged from
2026-09-23 in honeypot telemetry. No named threat actor — opportunistic mass scanning. No publicly
confirmed compromises yet; the expectation is relatively few, because WordPress auto-updates are on
by default.

**The observed chain, end to end:**

1. Template lookup is steered to `/usr/local/lib/php/pearcmd.php`.
2. `pearcmd` is driven via query-string arguments to write a PHP file to **`/tmp/`** or
   **`/var/tmp/`**.
3. That file is included, which fetches a second-stage uploader from
   `raw.githubusercontent[.]com/MrG3P5/web-shell/refs/heads/main/uploader.php`.

Dropped filenames seen in the wild: `wp-pear-rce-flag.php`, `poc87902.php`, `luci_<random>.php`,
`zeta_<random>.php`.

This is why Phase 4 checks `/tmp` before the webroot — the first write lands outside
`wp-content/`, so a webroot-only search misses an attack in progress.

---

## Phase 1 — Discover WordPress Deployments Across the Org

WordPress will not appear in a dependency manifest. Search three ways; any one alone misses deployments.

**1a. Image references and deployment definitions**

```bash
for q in "image: wordpress" "FROM wordpress" "wordpress:" "wp-config.php" \
         "WORDPRESS_DB_HOST" "WORDPRESS_DB_PASSWORD" "chart: wordpress" \
         "bitnami/wordpress" "wp-content" "define('DB_NAME'"; do
  echo "=== $q ==="
  gh search code "$q" --owner "$ORG" --json repository,path -L 100 2>/dev/null | \
    python3 -c "import json,sys; [print(i['repository']['nameWithOwner'],'|',i['path']) for i in json.load(sys.stdin)]" | sort -u
done
```

**Positive control:** before trusting a clean result, confirm the search reaches your code — run `gh search code "FROM" --owner "$ORG" -L 5` and verify known Dockerfiles come back. A zero-hit search and a broken search look identical.

**1b. Composer-managed WordPress — the minority case that IS in a manifest**

A small share of teams install core via Composer. When they do, it is genuinely visible:

```bash
for q in "johnpbloch/wordpress-core" "johnpbloch/wordpress" "roots/wordpress" \
         "roots/bedrock" "wpackagist-plugin" "wpackagist-theme"; do
  echo "=== $q ==="
  gh search code "$q" --owner "$ORG" --json repository,path -L 100 2>/dev/null | \
    python3 -c "import json,sys; [print(i['repository']['nameWithOwner'],'|',i['path']) for i in json.load(sys.stdin)]" | sort -u
done
```

Note that even here most SCA tooling will not flag it — there is no published advisory with package coordinates for this CVE (see Pitfalls).

**1c. Running workloads**

Repo search misses anything deployed from a registry without committed manifests.

```bash
# Kubernetes — match the image, not the workload name
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{range .spec.containers[*]}{.image}{" "}{end}{"\n"}{end}' \
  | grep -iE "wordpress|wp-|bitnami/wordpress" | tee "$LOG_DIR/k8s-candidates.txt"

# Container registries (AWS ECR example; adapt for GCR/ACR/Harbor)
aws ecr describe-repositories --query 'repositories[].repositoryName' --output text \
  | tr '\t' '\n' | grep -iE "wordpress|wp"
```

⚠️ Grep for **`wordpress`**, not `wp`. A bare `%wp%` pattern matches unrelated images — a real sweep surfaced `cwp:*` images as false positives purely on those two letters.

Classify each hit:

- Kubernetes workload / compose service / Helm release → live deployment; go to Phase 2.
- Dockerfile that builds *from* a WordPress base → your pipeline ships WordPress; go to Phase 2.
- Composer manifest → go to Phase 2, resolve the pinned version.
- Exporter, Gatsby source plugin, `@wordpress/*` npm → **not** a deployment. A lead at most.

---

## Phase 2 — Determine the Running Core Version

**The image tag is not the answer.** WordPress writes itself to `/var/www/html` on first run and then **updates itself in place** — minor-version auto-updates are on by default. With a persisted volume, the core on disk can be newer *or* older than the image that created it. A pod from `wordpress:6.4-apache` may be running 6.4.2 or 6.4.12; the tag cannot tell you which, and that difference is exactly the difference between vulnerable and patched.

**2a. Read it off disk — the reliable method**

```bash
# Kubernetes
kubectl exec -n <ns> <pod> -- sh -c \
  'grep "\$wp_version =" /var/www/html/wp-includes/version.php'

# Plain Docker
docker exec <container> sh -c \
  'grep "\$wp_version =" /var/www/html/wp-includes/version.php'

# WP-CLI, if present
kubectl exec -n <ns> <pod> -- wp core version --allow-root
```

Some images root the site elsewhere. If the path above is empty, locate it first:

```bash
kubectl exec -n <ns> <pod> -- sh -c 'find / -name version.php -path "*wp-includes*" 2>/dev/null'
```

**2b. From outside, when you cannot exec**

WordPress emits its version in the page source unless a hardening plugin strips it. Useful as a first pass, never as proof:

```bash
curl -s https://<site>/ | grep -iE '<meta name="generator" content="WordPress'
curl -s https://<site>/readme.html | grep -iE "Version [0-9]"
```

A stripped generator tag proves nothing either way — fall back to 2a.

**2c. Verdict**

Compare the resolved version against its branch tip in the table above, or query the stable-check API directly. `insecure` → vulnerable, regardless of configuration.

---

## Phase 3 — Check the Two RCE Preconditions

A vulnerable version is already a finding. These two determine whether it reaches **code execution** rather than file disclosure, and they set the urgency.

**3a. `register_argc_argv`**

```bash
kubectl exec -n <ns> <pod> -- php -i | grep -i register_argc_argv
# On  → precondition met (the DEFAULT for official PHP images)
# Off → LFI still possible, the pearcmd RCE path is not
```

**3b. Active theme with a top-level `page-*` directory**

```bash
# Which theme is active
kubectl exec -n <ns> <pod> -- sh -c \
  'wp option get template --allow-root 2>/dev/null || grep -rh "template" /var/www/html/wp-content/themes/*/style.css | head'

# Does any installed theme carry a top-level page-* directory
kubectl exec -n <ns> <pod> -- sh -c \
  'find /var/www/html/wp-content/themes -maxdepth 2 -type d -name "page-*"'
```

Only the **active** theme matters for exploitation, but list them all — themes get switched.

**3c. Is the PEAR gadget present?**

```bash
kubectl exec -n <ns> <pod> -- sh -c \
  'ls -la /usr/local/lib/php/pearcmd.php /usr/share/php/pearcmd.php 2>/dev/null'
```

Present **and** `register_argc_argv=On` **and** an affected version → treat as remotely exploitable for RCE.

**3d. Reachability**

Determine who can reach the site. Internet-facing affected instances are the priority — probing has been continuous since 2026-09-22 17:44 UTC. In Kubernetes check for a `Service` of type `LoadBalancer`/`NodePort` and any `Ingress` fronting the workload.

---

## Phase 4 — Review for Exploitation

The attack is a GET with traversal sequences in the `pagename` parameter. Hunt request logs since `$SINCE`:

```bash
# Container logs
kubectl logs -n <ns> <pod> --since-time="$SINCE" 2>/dev/null \
  | grep -aE "pagename=[^ ]*(\.\.|%2e%2e|%252e)" | tee "$LOG_DIR/traversal-hits.txt"

# Access log on a host
grep -aE "pagename=[^ ]*(\.\.|%2e%2e|%252e)" /var/log/apache2/access.log* 2>/dev/null \
  | tee -a "$LOG_DIR/traversal-hits.txt"

# The pearcmd escalation specifically
grep -aiE "pearcmd|pear/|config-create|download_dir" "$LOG_DIR/traversal-hits.txt"
```

Case- and encoding-variants matter: check `..%2f`, `%2e%2e%2f`, and double-encoded `%252e%252e`.

Cross-reference the published attacker IPs and the second-stage payload host:

```bash
grep -aE "$ATTACKER_IPS" "$LOG_DIR"/*.txt 2>/dev/null
grep -aiE "$PAYLOAD_URL|uploader\.php" "$LOG_DIR"/*.txt 2>/dev/null
```

An IP hit is corroboration, not proof, and its absence proves nothing — the list is a snapshot of
opportunistic scanners, not a closed set.

Then look for the effects of successful execution:

- **Dropped PHP files. Check `/tmp` and `/var/tmp` FIRST** — that is where the observed chain
  actually writes, before pulling the second stage. Checking only the webroot misses live attacks:
  ```bash
  kubectl exec -n <ns> <pod> -- sh -c \
    'find /tmp /var/tmp -name "*.php" -newermt "2026-09-22" -ls 2>/dev/null'

  # the specific names seen in the wild
  kubectl exec -n <ns> <pod> -- sh -c \
    'find / -regextype posix-extended -regex ".*/('"$DROP_NAMES"')" 2>/dev/null'
  ```
- PHP files written under `wp-content/uploads/` or anywhere outside the expected theme/plugin tree since `$SINCE`:
  ```bash
  kubectl exec -n <ns> <pod> -- sh -c \
    'find /var/www/html/wp-content/uploads -name "*.php" -newermt "2026-09-22" 2>/dev/null'
  ```
- Outbound connections from the pod that do not match its known integrations.
- New admin users, or unexpected plugin installs, in the WordPress database.
- Modified core files: `wp core verify-checksums --allow-root` (WP-CLI) flags any core file that does not match the official release.

Any hit → treat the instance as compromised, and proceed to Phase 5 with full credential rotation.

---

## Phase 5 — Remediation & Hardening

1. **Update core to the branch tip or to 7.1.2.** For `6.4.x`, the fixed version is **6.4.12**. Re-pulling a floating tag such as `wordpress:6.4-apache` gets you the current 6.4.x — but confirm with Phase 2a afterwards rather than assuming the pull took effect.
2. **Verify after deploying.** Re-read `wp-includes/version.php` in the *running* pod. A rebuild that silently failed, or a rollout that did not complete, leaves you exposed while the ticket says fixed.
3. **Turn off `register_argc_argv`** in your PHP config. It is on by default in the official images, is not needed by WordPress, and removes the documented RCE path even if a future inclusion bug appears. This is the single highest-value hardening step here.
4. **Pin images by digest**, not by a floating tag — and rebuild deliberately rather than relying on in-place auto-update, which is what makes tag-based version reasoning unreliable in the first place.
5. **Enable core auto-updates** where in-place updating is the deployment model, so the next backport lands without a rebuild.
6. **If any Phase 4 sign was found**, rotate everything the instance could reach: database credentials, the pod's cloud role, any API keys in `wp-config.php` or plugin settings, and all administrator passwords. Then re-verify core checksums after cleanup.

---

## Evidence Table

Record one row per WordPress deployment:

| Field | Value |
|---|---|
| Deployment source (repo / cluster / registry) | |
| Image reference + tag | |
| Resolved core version (from `version.php`, not the tag) | |
| Version affected? (below its branch tip) | yes / no |
| `register_argc_argv` | On / Off |
| Active theme has top-level `page-*` dir? | yes / no |
| `pearcmd.php` present? | yes / no |
| RCE-exploitable (all three above)? | yes / no |
| Reachable from | internet / internal / restricted |
| Traversal attempts in logs since `$SINCE`? | yes / no |
| Unexpected PHP files / modified core? | list |
| Updated to branch tip? | yes / no |
| Version re-verified after deploy? | yes / no |
| Secrets rotated? | yes / no / n/a |

---

## Pitfalls & Fixes

- **Dependency scanning will not find this, and neither will your advisory feed.** There is no GitHub advisory for CVE-2026-87902 (`gh api /advisories?cve_id=CVE-2026-87902` returns nothing), no OSV record, and Packagist `wordpress/wordpress` reports zero vulnerabilities. A referenced `GHSA-7hp8-65ch-5whp` returns **404**. Nobody has converted this into an ecosystem coordinate, because core is not distributed as a package. A clean SCA report says nothing about your exposure — Phase 1 is the only discovery path.
- **`@wordpress/*` npm packages are not WordPress.** They are the Gutenberg JavaScript toolchain. In one full customer-base sweep, *every* WordPress hit in dependency inventory was `@wordpress/scripts`, `@wordpress/element`, `@wordpress/escape-html` and similar — across several organisations, none of which had core in a manifest. Reporting these as exposure is a false positive.
- **Grep `wordpress`, never `wp`.** A `%wp%` pattern matched unrelated `cwp:*` container images in a real sweep. Two letters are not a signal.
- **The image tag is not the running version.** WordPress auto-updates in place on a persisted volume. `wordpress:6.4-apache` tells you the branch at build time and nothing about today. Always read `wp-includes/version.php` from the running container.
- **Containerised is the high-risk case here, not the safe one.** `register_argc_argv` is on by default in the official PHP images. The instinct that "it's in a container, so it's hardened" is backwards for this CVE.
- **"Not in the affected range" needs the branch tip, not the major version.** 6.4 is not a version — 6.4.2 is affected, 6.4.12 is not. Resolve to the full version and check it against the stable-check API.
- **A stripped generator tag is not evidence of patching.** Hardening plugins remove the version from page source. Absence of a version externally means you have to exec in, not that you are safe.
- **Exporters and source plugins are leads, not findings.** `wordpress-exporter` scraping metrics means an instance exists somewhere — possibly owned by another team, possibly an external property. Chase it to a real deployment before recording it.
- **File inclusion is a finding even without RCE.** If `register_argc_argv` is Off, do not close the ticket — an unauthenticated attacker can still read arbitrary readable `.php` on the host, which includes `wp-config.php` and its database credentials.
- **Searching only the webroot for dropped files misses the live attack.** The observed chain writes its first stage to `/tmp` or `/var/tmp`, not `wp-content/uploads` — the webroot only gets touched later, if the uploader succeeds. The first version of this playbook checked `wp-content/uploads` alone and would have returned clean against an in-progress compromise. Check `/tmp` first.
- **`/tmp` is also noisy.** Legitimate PHP session files, caches and build artifacts live there. Filter by the observed names (`$DROP_NAMES`) and by mtime after `$SINCE` before calling anything a hit.
- **The attacker IP list is a snapshot, not a boundary.** Seven addresses are published for opportunistic scanners that rotate. A hit corroborates; absence proves nothing. Hunt on request shape first, IPs second.
