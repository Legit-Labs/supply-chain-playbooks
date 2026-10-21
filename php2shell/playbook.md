# php2shell — PHP Core Unauthenticated RCE (CVE-2026-109618, CVE-2026-109619) — Detection & Response Playbook

> **Note for AI agents:** This playbook detects a **vulnerable deployed runtime**, not a poisoned dependency. The flaw is in the PHP interpreter itself, so the thing to find is **every place PHP serves web requests** — container images, Kubernetes workloads, hosts — and the **exact PHP patch level each one runs**. Three things make it different from a normal SCA follow-up. First, **dependency scanning will not find it**: the PHP runtime is not a package in any lock file, and the `"php"` entry in `composer.json` is a *constraint* (`>=8.1`), not the installed version. Second, **floating image tags are not versions**: `php:8.3-apache` pulled last week is 8.3.35 (vulnerable); pulled today it is 8.3.36 (patched). Resolve the version from the image itself. Third, **this is actively exploited and attacks began before the fix shipped** — on any internet-facing server that ran a vulnerable build, Phase 4 (compromise review) is not optional.
>
> Commands use the GitHub CLI and `kubectl` by default. Adapt the discovery step for GitLab / Bitbucket and the runtime steps for ECS, Nomad, or plain Docker hosts — the logic is the same.

## Scope — What This Playbook Covers and What It Doesn't

Read this before running it, so a clean result is read for what it is.

**Covered and validated** — every command below was run as written against a lab of 10 Kubernetes workloads on 2026-10-21 (vulnerable, patched and non-PHP controls), plus the GitHub discovery searches against a real organization:

| Area | What is checked |
|---|---|
| Discovery | GitHub org: Dockerfiles, Kubernetes / Helm / compose manifests, nginx-to-FPM configs, `composer.json`. Kubernetes: every running image |
| Runtimes | Official `php:*` images (Debian and Alpine based; Apache mod_php, PHP-FPM, CLI); Debian / Ubuntu `apt` PHP; Alpine `apk` PHP; Red Hat UBI / RHEL PHP; applications that embed PHP (WordPress) |
| Version and SAPI | From the image config without running it, and from inside the running container; distro package versions |
| Exposure | Interim mitigation settings as the web worker actually sees them |
| Compromise | Processes spawned by PHP workers (including ones orphaned when the worker dies), PHP files written since the leak, worker crashes and out-of-memory fatals in logs |

**Covered by instructions, not lab-tested** — the same commands apply, adapted as noted:

- Plain Docker hosts (`docker exec` instead of `kubectl exec`) and Linux hosts / VMs (run the in-container commands over SSH / SSM).
- Bitnami, FrankenPHP and LiteSpeed images.
- GitLab / Bitbucket instead of GitHub (same search terms, that platform's code search).

**Not covered** — a clean result from this playbook says nothing about these:

- **Exploit-specific detection.** No exploit code or IOCs are public. Detection here is behavioral (what a successful or failed attack leaves behind), based on the advisories, not on observed attack traffic. Add IOCs to the variables block when vendors publish them.
- **Images that are not running.** Phase 2a checks the images you give it; the playbook does not enumerate container registries. Feed your registry's image list into 2a to cover built-but-not-deployed images.
- **Serverless and managed runtimes:** AWS Lambda PHP (Bref layers), ECS / Fargate without ECS Exec enabled, Google Cloud Run, Azure App Service, and managed PHP hosting. Check the runtime version with the provider.
- **Windows** (IIS with `php-cgi.exe`, PHP on Windows Server). All commands are Linux-only.
- **Network and edge controls.** WAF / CDN rules are mentioned as a stopgap, not audited.
- **Remediation automation.** The playbook tells you what to patch and verify; it does not patch anything.

---

## Variables — Fill These In First

```bash
# Your GitHub organization name
export ORG="your-org-name"

# Details leaked 2026-10-20 and watchTowr confirmed working RCE that day.
# Cloudflare recorded the first attacks at 2026-10-21 07:43 UTC; the fix shipped
# 14:00 UTC the same day. Start the log-review window at the leak.
export SINCE="2026-10-20T00:00:00Z"
# Same window in whole days, for find -mtime (BusyBox find on Alpine has no -newermt)
export SINCE_DAYS=$(python3 -c 'import datetime; print((datetime.date.today() - datetime.date(2026, 10, 20)).days + 1)')

# No attacker IPs, domains, hashes or dropped-file names have been published yet
# (as of 2026-10-21). Hunt on behavior and request shape - see Phase 4.

export LOG_DIR="/tmp/supply-chain-scan-php2shell"
mkdir -p "$LOG_DIR"
```

Version classifier used throughout — paste it once:

```bash
cat > "$LOG_DIR/classify.py" <<'EOF'
import re, sys
FIXED = {(8, 5): 12, (8, 4): 27, (8, 3): 36, (8, 2): 35}
for raw in sys.argv[1:]:
    m = re.match(r"^\D*(\d+)\.(\d+)\.(\d+)", raw)
    if not m:
        print(f"{raw}\tUNKNOWN (no x.y.z - floating tag? resolve it)"); continue
    maj, mnr, pat = map(int, m.groups())
    if (maj, mnr) in FIXED:
        v = "PATCHED" if pat >= FIXED[(maj, mnr)] else "VULNERABLE"
    elif (maj, mnr) < (8, 2):
        v = "VULNERABLE-EOL (no official fix; check vendor backport)"
    else:
        v = "UNKNOWN (newer branch - check php.net)"
    if re.search(r"(ubuntu|deb|el\d|\.module|alpine|-r\d)", raw):
        v += " | distro build: confirm against the distro tracker"
    print(f"{raw}\t{v}")
EOF
python3 "$LOG_DIR/classify.py" 8.3.35 8.3.36 8.1.33   # sanity check
```

---

## Background

Two critical memory-safety flaws in the PHP core, both **CVSS 4.0 9.2**, disclosed and fixed **2026-10-21**. Found by Calif, Wiz Research and OpenAI.

- **CVE-2026-109618 — RCE via OOM corruption** ([GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)). PHP aborts a request with `longjmp()` when memory runs out, which can leave request data half-initialized; request shutdown then treats it as valid. Multipart parsing lets an attacker reach that out-of-memory condition while staying inside PHP's apparent limits.
- **CVE-2026-109619 — RCE via stale global state** ([GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)). Worker-global state (session upload progress, error backtraces, unserialize bookkeeping) can keep pointing at memory freed with the previous request. A later request on the same worker uses it before reinitialization — a use-after-free turned into code execution. Session upload progress is **on by default and needs no `session_start()`**.

The result is **unauthenticated remote code execution as the PHP worker user** from ordinary HTTP requests. On Apache mod_php it fires **before any application code runs**.

### Affected / Fixed

| Branch | Affected | Fixed |
|---|---|---|
| 8.5 | 8.5.0 – 8.5.11 | **8.5.12** |
| 8.4 | 8.4.0 – 8.4.26 | **8.4.27** |
| 8.3 | 8.3.0 – 8.3.35 | **8.3.36** |
| 8.2 | 8.2.0 – 8.2.34 | **8.2.35** |
| 8.1, 8.0, 7.x, 5.4+ | all | **No official release.** Source backports exist for 8.1 / 8.0 / 7.4 only; otherwise a distro / LTS vendor backport or an upgrade |

The vulnerable code dates back to PHP 5.4.0 (2012).

Distribution packages that carry the fix (where published so far): Debian bookworm `php8.2` **8.2.35-1~deb12u1**, Debian trixie `php8.4` **8.4.27-1~deb13u1**. Ubuntu, RHEL and Alpine: check the vendor tracker — distro builds often **backport the patch without changing the upstream version number** (see Pitfalls).

### Server APIs (SAPIs)

| SAPI | Status |
|---|---|
| **Apache mod_php** (`php:*-apache` images, `libapache2-mod-php*`) | RCE demonstrated **before application code runs**. Highest risk. |
| **PHP-FPM** (nginx, `mod_proxy_fcgi`, Caddy; `php:*-fpm` images) | RCE demonstrated (nginx + FPM). Needs a reachable session / unserialize path — present in WordPress, Drupal, Joomla, Magento, Laravel, Symfony, MediaWiki, Nextcloud, phpMyAdmin, Roundcube, WHMCS. |
| **FrankenPHP, php-cgi, LiteSpeed (LSAPI)** | Listed at risk by the PHP project. |
| **PHP CLI** (cron jobs, queue workers, build steps) | Not exposed to HTTP — not the target. A CLI-only image that never serves requests is not a finding, but confirm nothing runs `php -S` in it. |

### What IS affected

- Any vulnerable PHP build that serves HTTP traffic, behind a CDN or reverse proxy included.
- **Every container image built from `php:*` before 2026-10-21**, and every image that installs PHP from a distro repo without the fixed package — until it is rebuilt.
- Images that **embed PHP** without saying "php" in their name: official `wordpress`, `drupal`, `joomla`, `nextcloud`, `matomo`, `phpmyadmin`, `mediawiki`, `friendica`; `bitnami/*` PHP apps; `serversideup/php`, `webdevops/php*`, `thecodingmachine/php`, `linuxserver/*` PHP apps (nextcloud, bookstack, …).
- Control panels and appliances that bundle PHP (cPanel, Plesk).

### What is NOT affected

- Builds at or above the fixed version for their branch (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35), or distro builds the vendor's tracker marks fixed.
- **Composer packages.** No package in `composer.lock` contains the vulnerable code — the flaw is in the interpreter. A `"php": ">=8.1"` constraint tells you the repo *runs on* PHP; it is a lead for Phase 1, not a version.
- PHP used only from the CLI in CI build steps (`composer install`, `phpunit`) — no HTTP request reaches it. These runners are not a deployment.
- Managed PHP hosting where the provider patches the runtime (check the provider's status page before raising a finding).

### Exploitation status — as of 2026-10-21

**Active.** Details leaked 2026-10-20; watchTowr confirmed RCE the same day and reports in-the-wild exploitation on its honeypot network. Cloudflare saw attacks from **07:43 UTC on 2026-10-21 — over six hours before the fix shipped**. A brief exploit demo video circulated and was removed. **No public exploit code and no published IOCs yet.** No named actor. Sansec expects mass exploitation now that patches and write-ups are public. Not yet in CISA KEV.

---

## Phase 1 — Discover PHP Deployments Across the Org

PHP is rarely visible to SCA. Search four ways; any one alone misses deployments.

GitHub code search allows **10 requests per minute**. Phase 1 makes ~15, so a plain loop gets `HTTP 403: API rate limit exceeded` part-way through — and with stderr hidden, a rate-limited search looks exactly like "no PHP here". Define this helper once; it paces requests, waits out the limit, and fails loudly on anything else:

```bash
ghs() {
  local out i
  for i in 1 2 3 4 5; do
    if out=$(gh search code "$@" --json repository,path,textMatches -L 1000 2>&1); then
      printf '%s\n' "$out"; sleep 7; return 0
    fi
    case "$out" in
      *"rate limit"*) echo "rate-limited on [$*], waiting 60s" >&2; sleep 60 ;;
      *) echo "SEARCH FAILED [$*]: $out" >&2; return 1 ;;
    esac
  done
  echo "SEARCH FAILED [$*]: still rate-limited after 5 tries" >&2; return 1
}
```

**1a. Dockerfiles and image references**

GitHub code search ignores punctuation, so `"FROM php:"` matches any file mentioning "from" and "php". Scope by filename and post-filter with a regex:

```bash
# Positive control first — must return results, or the search is broken
ghs "FROM" --owner "$ORG" --filename Dockerfile | python3 -c "import json,sys; print('control hits:', len(json.load(sys.stdin)))"

for f in Dockerfile Containerfile; do
  ghs "php" --owner "$ORG" --filename "$f"
done | python3 -c "
import json, sys, re
pat = re.compile(r'(FROM\s+\S*(php|wordpress|drupal|joomla|nextcloud|matomo|phpmyadmin|mediawiki)\S*|apt-get install[^\n]*\bphp|apk add[^\n]*\bphp|(dnf|yum) install[^\n]*\bphp|libapache2-mod-php|php-fpm|docker-php-ext)', re.I)
seen = set()
for line in sys.stdin:
    for i in json.loads(line):
        frag = ' '.join(m.get('fragment', '') for m in i.get('textMatches', []))
        if pat.search(frag):
            k = (i['repository']['nameWithOwner'], i['path'])
            if k not in seen:
                seen.add(k); print(k[0], '|', k[1])
" | tee "$LOG_DIR/dockerfile-hits.txt"
```

**1b. Deployment manifests (Kubernetes, Helm, compose)**

```bash
for q in "image: php" "image: wordpress" "image: drupal" "image: nextcloud" \
         "bitnami/wordpress" "bitnami/drupal" "serversideup/php" "webdevops/php" \
         "php-fpm" "PHP_FPM" "fastcgi_pass"; do
  echo "=== $q ==="
  ghs "$q" --owner "$ORG" | \
    python3 -c "import json,sys,re; [print(i['repository']['nameWithOwner'],'|',i['path']) for i in json.load(sys.stdin) if not re.search(r'(\.(md|rst|txt|php)$|(^|/)(tests?|docs?)/)', i['path'])]" | sort -u
done | tee "$LOG_DIR/manifest-hits.txt"
```

`fastcgi_pass` finds nginx configs fronting FPM — the image name may not mention PHP at all.

**1c. Repositories that declare a PHP runtime**

```bash
ghs "php" --owner "$ORG" --filename composer.json | \
  python3 -c "import json,sys; [print(i['repository']['nameWithOwner'],'|',i['path']) for i in json.load(sys.stdin)]" | \
  sort -u | tee "$LOG_DIR/composer-repos.txt"
```

These are PHP applications. Find where each one is **deployed** (its Dockerfile, its Helm chart, its host) — the constraint itself is not a version.

**1d. Running workloads and registries — the source of truth**

Repo search misses images deployed from a registry with no committed manifest.

```bash
# Kubernetes: every distinct image currently running
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{range .spec.containers[*]}{.image}{" "}{end}{"\n"}{end}' \
  > "$LOG_DIR/k8s-pods.tsv"
cut -f3 "$LOG_DIR/k8s-pods.tsv" | tr ' ' '\n' | sort -u | grep -v '^$' > "$LOG_DIR/k8s-images.txt"
wc -l "$LOG_DIR/k8s-images.txt"
```

Do **not** filter this list by name — Phase 2a checks every image for a PHP runtime, which is the only way to catch images like `acme/billing-portal:v42` that are PHP inside.

Classify each Phase 1 hit:

- Running workload, compose service, Helm release → live deployment; go to Phase 2.
- Dockerfile that builds from a PHP base or installs PHP → your pipeline ships PHP; find the deployed image and go to Phase 2.
- `composer.json` only → a PHP app; locate its deployment.
- Dockerfile that only runs `composer install` / `phpunit` in a build stage and ships no PHP in the final stage (multi-stage) → **not** a deployment. Check the final `FROM`.

---

## Phase 2 — Resolve the PHP Version Each Deployment Actually Runs

**The tag is not the answer.** `php:8.3-apache` is a moving tag. Resolve the version from the image or the running process.

**2a. From the image, without running it (fast, covers every image in 1d)**

Official `php:*` images — and every image built `FROM` them — carry `PHP_VERSION` in their environment. The image `Cmd` tells you the SAPI.

```bash
# Reads the image config from the registry with crane (https://github.com/google/go-containerregistry);
# falls back to `docker image inspect` for images already pulled locally
while read -r img; do
  cfg=$(crane config "$img" 2>/dev/null || docker image inspect "$img" 2>/dev/null) || { echo -e "$img\tUNREADABLE"; continue; }
  echo "$cfg" | python3 -c "
import json, sys
d = json.load(sys.stdin); d = d[0] if isinstance(d, list) else d
c = d.get('config') or d.get('Config') or {}
env = dict(e.split('=', 1) for e in c.get('Env') or [] if '=' in e)
v = env.get('PHP_VERSION')
if v:
    cmd = ' '.join((c.get('Entrypoint') or []) + (c.get('Cmd') or []))
    sapi = 'mod_php' if 'apache2' in cmd else 'fpm' if 'php-fpm' in cmd else 'frankenphp' if 'frankenphp' in cmd else 'other:' + cmd
    print('$img', v, sapi, sep='\t')
"
done < "$LOG_DIR/k8s-images.txt" | tee "$LOG_DIR/image-php-versions.tsv"

awk -F'\t' 'NF == 3 {print $2}' "$LOG_DIR/image-php-versions.tsv" | sort -u | xargs python3 "$LOG_DIR/classify.py"
grep UNREADABLE "$LOG_DIR/image-php-versions.tsv"   # resolve these by hand: registry auth, or pull them first
```

An image with no `PHP_VERSION` may still contain PHP (distro packages, bitnami, custom builds) — 2b covers those.

**2b. From the running container (authoritative)**

```bash
# Version of every PHP binary present
kubectl exec -n <ns> <pod> -- sh -c \
  'for b in php php-cgi frankenphp /opt/bitnami/php/bin/php $(ls /usr/bin/php[0-9]* /usr/sbin/php-fpm* /usr/local/sbin/php-fpm 2>/dev/null); do command -v $b >/dev/null 2>&1 && echo "$b: $($b -v 2>/dev/null | head -1)"; done; true'

# Which SAPI is actually RUNNING — binaries present are not binaries in use
kubectl exec -n <ns> <pod> -- sh -c \
  'for p in /proc/[0-9]*; do cat $p/comm 2>/dev/null; done | grep -E "^(php|apache2|httpd|frankenphp|lsphp)" | sort | uniq -c; true'

# Distro-packaged PHP — installed packages only, with the full distro version
kubectl exec -n <ns> <pod> -- sh -c \
  'dpkg-query -W -f="\${db:Status-Abbrev}\t\${Package}\t\${Version}\n" "php*" "libapache2-mod-php*" 2>/dev/null | grep "^ii"; apk info -v 2>/dev/null | grep -E "^php"; rpm -qa "php*" 2>/dev/null; true'
```

Running `apache2`/`httpd` with a PHP version present → mod_php; `php-fpm` → FPM; only `php` running a script (queue worker, cron) or nothing at all → CLI-only, not serving HTTP.

Hosts and VMs: run the same commands over SSH / SSM, plus `apache2ctl -M 2>/dev/null | grep -i php` (mod_php loaded?) and `systemctl list-units "php*fpm*"`.

**2c. Verdict**

Run every resolved version through `classify.py`. `VULNERABLE` or `VULNERABLE-EOL` → finding. For **distro builds**, the upstream number can lie in either direction: look the full package version up in the distro tracker (Debian: `https://security-tracker.debian.org/tracker/CVE-2026-109618`; Ubuntu: `https://ubuntu.com/security/CVE-2026-109618`; RHEL: `https://access.redhat.com/security/cve/CVE-2026-109618`).

---

## Phase 3 — Exposure and Interim Mitigations

A vulnerable version that serves HTTP is already a finding. This phase sets urgency and records which partial mitigations are in place on anything that cannot be patched today.

**3a. Reachability.** Internet-facing first. In Kubernetes, check for a `Service` of type `LoadBalancer`/`NodePort` or an `Ingress` routing to the workload. Note whether a CDN/WAF sits in front — it may block `multipart/form-data` (every known trigger uses it), which buys time but is not a fix.

**3b. SAPI.** mod_php > FPM in urgency (pre-application RCE). Record which one from 2a/2b.

**3c. Effective interim settings — read them from the right layer.** Three layers decide the value a web worker sees: the ini files loaded for that SAPI, then FPM pool or Apache vhost overrides (`php_admin_value` / `php_value`). A setting that appears nowhere is at its **default — `session.upload_progress.enabled` defaults to On**.

```bash
# Layer 1, official php:* images: one ini dir shared by every SAPI, so the CLI value is the base value
kubectl exec -n <ns> <pod> -- sh -c \
  'P=$(command -v php || ls /usr/bin/php[0-9]* 2>/dev/null | head -1); [ -n "$P" ] && $P -r '"'"'foreach (["session.upload_progress.enabled","memory_limit","post_max_size","log_errors"] as $k) echo $k, " = ", var_export(ini_get($k), true), "\n";'"'"'; true'

# Layer 1, distro packages: Debian/Ubuntu give each SAPI its own ini dir (/etc/php/<ver>/fpm, /apache2, /cli) — read the web one.
# RHEL: /etc/php.ini + /etc/php.d. Alpine: /etc/php<NN>/php.ini + conf.d
kubectl exec -n <ns> <pod> -- sh -c \
  'grep -rHiE "^[^;]*(session\.upload_progress\.enabled|memory_limit|post_max_size|log_errors|fatal_error_backtraces)" /etc/php/*/fpm /etc/php/*/apache2 /etc/php.ini /etc/php.d /etc/php[0-9]* 2>/dev/null; true'

# Layer 2, FPM: dump the effective pool config including php_admin_value overrides (works for php-fpm and php-fpm8.x)
kubectl exec -n <ns> <pod> -- sh -c \
  'for f in $(ls /usr/sbin/php-fpm* /usr/local/sbin/php-fpm 2>/dev/null); do $f -tt 2>&1 | grep -iE "php_(admin_)?value\[(session\.upload_progress|memory_limit|post_max_size|fatal_error_backtraces)"; done; true'

# Layer 2, Apache vhost / .htaccess-style overrides
kubectl exec -n <ns> <pod> -- sh -c \
  'grep -rHiE "php_(admin_)?(value|flag).*(upload_progress|memory_limit|post_max_size|fatal_error_backtraces)" /etc/apache2 /etc/httpd 2>/dev/null; true'
```

`php.ini-development` and `php.ini-production` shipped in official images are **templates, never loaded** — don't read values from them. `session.upload_progress.enabled = false` (not `'0'`) means the session extension is not installed at all, which removes the confirmed CVE-2026-109619 session path but not CVE-2026-109618.

| Setting | Interim value | Blocks |
|---|---|---|
| `session.upload_progress.enabled` | `0` (in php.ini, FPM pool, or vhost — **not** `ini_set()` / `.user.ini`) | The confirmed CVE-2026-109619 session path |
| `memory_limit` | `-1`, set with `php_admin_value` so apps can't override | Reduces CVE-2026-109618; an allocation failure can still reach it |
| `post_max_size` | `8M` (`32M` if uploads needed), `upload_max_filesize` below it | Narrows the OOM trigger |
| `fatal_error_backtraces` (PHP 8.5 only) | `0` | The confirmed 8.5 backtrace path |

None of these makes an installation safe. Record them; do not close a finding on them.

---

## Phase 4 — Review for Compromise

Mandatory for every internet-facing deployment that ran a vulnerable build at any point since `$SINCE`. No IOCs are published, so hunt on **behavior**.

**4a. Processes spawned by PHP workers.** A web worker should not be running shells or network tools. Most slim images have no `ps`, so read `/proc`. Two cases are flagged:

- a non-server process whose parent is a **worker** — the direct case (`sh` under `apache2` / `php-fpm`);
- a non-server process whose parent is the **master** — what an attacker's process becomes once its worker exits, crashes or is recycled (`pm.max_requests`) and it is re-parented. Apache piped loggers (`cat`, `rotatelogs`, `logger`, `cronolog`) legitimately live under the master and are skipped.

```bash
kubectl exec -n <ns> <pod> -- sh -c '
srv() { case "$1" in php*|lsphp*|apache2|httpd|frankenphp) return 0;; esac; return 1; }
pp() { awk "/^PPid:/{print \$2}" /proc/$1/status 2>/dev/null; }
for p in /proc/[0-9]*; do
  pid=${p#/proc/}; comm=$(cat $p/comm 2>/dev/null); ppid=$(pp $pid)
  pcomm=$(cat /proc/$ppid/comm 2>/dev/null); gcomm=$(cat /proc/$(pp $ppid)/comm 2>/dev/null)
  srv "$pcomm" && ! srv "$comm" || continue
  cmd=$(tr "\0" " " < $p/cmdline)
  if srv "$gcomm"; then echo "SUSPICIOUS pid=$pid parent=worker:$pcomm($ppid) cmd=$cmd"
  else case "$comm" in cat|rotatelogs|logger|cronolog) ;; *) echo "SUSPICIOUS pid=$pid parent=master:$pcomm($ppid) (orphaned from a worker?) cmd=$cmd";; esac
  fi
done; true' | tee -a "$LOG_DIR/process-hits.txt"
```

Look especially for `sh`, `bash`, `python`, `perl`, `curl`, `wget`, `nc`, `busybox`, and command lines containing `/dev/tcp/`, `fsockopen`, `mkfifo`, `whoami`, `id`, `uname -a`. Hosts with EDR: query the same parent/child relationship (`php-fpm`, `php-cgi`, `php-cgi.exe`, `httpd`, `apache2` → shell / interpreter / `certutil.exe`). On Linux hosts, Florian Roth's [process-watcher](https://github.com/Neo23x0/process-watcher/blob/main/emerging-threats/php-rce-october-26/README.md) watches for exactly this.

**4b. Dropped files.** New PHP files outside the deploy, in the webroot and in temp dirs:

```bash
# -mtime works in GNU and BusyBox find. Errors are left visible on purpose — a find that
# fails on an unsupported option prints nothing to stdout and looks exactly like "clean".
kubectl exec -n <ns> <pod> -- sh -c \
  'for d in /var/www /opt/app-root/src /tmp /var/tmp /dev/shm /opt/bitnami; do [ -d "$d" ] && find "$d" -type f -name "*.php*" -mtime -'"$SINCE_DAYS"' ! -path "*/..*" -exec ls -l {} +; done; true'
```

Focus on files **owned by the PHP worker user** (`www-data` in official and Debian images, `apache` / `nginx` / `daemon` elsewhere) — code written through the exploit runs as that user, while deployed code is normally owned by root or a build user. Anything the worker wrote under `/tmp` or the webroot with a `.php` extension needs an explanation. The `-not -path "*/..*"` filter drops Kubernetes ConfigMap/Secret mount internals (`..data`, `..2026_10_21_…`), which are re-stamped on every rollout.

Container filesystems are rebuilt on redeploy — for a pod that has restarted since `$SINCE`, look at persisted volumes (uploads, sessions) and at hosts, not the fresh container.

**4c. Error-log signal.** The trigger exhausts memory and grooms the heap, so attempts leave out-of-memory fatals and, when they misfire, crashed workers. A burst of these from one client, on endpoints that never normally hit the limit, is the clearest log signature available:

```bash
kubectl logs -n <ns> <pod> --all-containers --since-time="$SINCE" 2>/dev/null \
  | grep -aE "Allowed memory size of [0-9]+ bytes exhausted|Out of memory|exited on signal (11|6)|exit signal (Segmentation fault|Aborted)|SIGSEGV|zend_mm_heap corrupted" \
  | tee "$LOG_DIR/fatal-hits.txt"

# Distro-packaged FPM / Apache often log to FILES inside the container, not stdout — read them there too
# (on hosts and VMs, run the same grep over SSH / SSM)
kubectl exec -n <ns> <pod> -- sh -c \
  'grep -aHE "Allowed memory size|zend_mm_heap corrupted|exited on signal (11|6)|exit signal (Segmentation fault|Aborted)" \
     /var/log/php*-fpm.log /var/log/php*/*.log /var/log/php-fpm/*.log /var/log/apache2/error.log* /var/log/httpd/error_log* 2>/dev/null; true' \
  | tee -a "$LOG_DIR/fatal-hits.txt"
```

- **Crashed workers are logged by the server, regardless of PHP settings.** FPM: `WARNING: [pool www] child 123 exited on signal 11 (SIGSEGV)`. Apache: `AH00051: child pid 123 exit signal Segmentation fault (11)`. Rare in normal operation, consistent with failed heap grooming.
- **PHP fatals are only logged if `log_errors` is on — and it is OFF in the official `php:*` images**, which ship no `php.ini`. There the out-of-memory fatal goes to the client only and the access log records it as **HTTP 200**. Check `log_errors` (3c, layer 1) before trusting an empty result.

**4d. Request shape.** Every known trigger is a `multipart/form-data` POST. Access logs rarely record content type, but you can still look for POST bursts from a single client to endpoints that don't take forms, and — if your proxy logs them — chunked or length-less multipart bodies, requests with many empty file parts and deeply nested field names, or `PHP_SESSION_UPLOAD_PROGRESS` fields.

**4e. Persistence and access.** New cron entries (`crontab -l` for the worker user, `/etc/cron*`), new system or application admin users, unexpected outbound connections from the workload, and modified application code (WordPress: `wp core verify-checksums --allow-root`).

Any hit → treat the deployment as compromised: isolate it, preserve web-server and PHP logs, and go to Phase 5 step 5.

---

## Phase 5 — Remediation & Hardening

1. **Upgrade to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35** (or the vendor's fixed package). Internet-facing first, mod_php first.
2. **Rebuild every PHP image with `--pull --no-cache`** and redeploy. A plain rebuild can reuse a cached vulnerable base layer. Then **re-run Phase 2a/2b against the running pod** — a rollout that didn't complete leaves you exposed while the ticket says fixed.
3. **EOL PHP (8.1 and older):** move to a supported branch, or use a distro/LTS backport or the PHP team's source backports (`PHP-8.1-CVE-2026-109618-109619`, `PHP-8.0-…`, `PHP-7.4-…` branches in php-src). Until then, take it off the internet.
4. **Keep `session.upload_progress.enabled=0`** after patching unless the app needs it — the PHP team recommends this.
5. **If Phase 4 found anything:** rotate **every secret the PHP worker could read** — database credentials, environment variables, cloud role credentials attached to the pod or instance, API keys in `.env` / `wp-config.php` / `config/*.php`, and session/signing keys (`APP_KEY` in Laravel, salts in WordPress). Then rebuild from a clean image rather than cleaning in place.
6. **Pin base images by digest** and rebuild deliberately, so "which PHP is running" has one answer. Watch php.net security releases for the next one.

---

## Evidence Table

Record one row per PHP deployment (`$LOG_DIR/evidence-repos.csv`):

| Field | Value |
|---|---|
| Deployment source (repo / cluster / registry / host) | |
| Image reference (tag **and** digest) | |
| Resolved PHP version (from `PHP_VERSION` / `php -v` / package) | |
| Distro package + version (if distro-built) | |
| SAPI | mod_php / fpm / frankenphp / cgi / lsapi |
| Verdict (`classify.py` / distro tracker) | VULNERABLE / VULNERABLE-EOL / PATCHED |
| Reachable from | internet / internal / restricted |
| `session.upload_progress.enabled` (effective, web SAPI) | |
| PHP-worker child processes found? | yes / no / not checked |
| New PHP files since 2026-10-20? | list |
| Memory-exhaustion / segfault bursts in logs? | yes / no |
| Upgraded + re-verified in running pod? | yes / no |
| Secrets rotated? | yes / no / n/a |

---

## Pitfalls & Fixes

- **SCA cannot see the runtime.** No advisory maps these CVEs to a Composer package, and the PHP interpreter is not in `composer.lock`. A clean SCA report says nothing about exposure. The `"php"` key in `composer.json` is a constraint like `>=8.1` — it identifies PHP apps (useful for Phase 1), never a version.
- **GitHub code search is rate-limited and capped.** 10 requests per minute: an unpaced Phase 1 hit `HTTP 403: API rate limit exceeded` on the ninth query, and with stderr hidden the remaining searches returned nothing — indistinguishable from "no PHP". Each search also returns at most 100 results unless you raise `-L`; against a real PHP organization `composer.json` hits were cut from 162 to 100. The `ghs` helper paces requests, retries on the limit and asks for up to 1,000 results (GitHub's hard cap — split by repository if you hit it).
- **Manifest searches return documentation and source code.** Terms like `php-fpm` and `fastcgi_pass` match READMEs, PHP source and test fixtures. 1b drops `.md` / `.rst` / `.txt` / `.php` files and `test` / `docs` directories; review what is left by hand.
- **GitHub code search ignores punctuation.** `"FROM php:"` returned 16 hits in a dry run — all Python, TypeScript and Markdown files that merely mention both words, none of them Dockerfiles. Always scope with `--filename` and post-filter with a regex, as in 1a, and run the positive control.
- **Floating tags moved under you.** On 2026-10-21 the official `php:8.3-apache` and `php:8.4-fpm-alpine` tags were rebuilt onto 8.3.36 / 8.4.27. The same tag string is vulnerable in an image pulled before that and patched after. Resolve `PHP_VERSION` from the image config (2a) or the running process (2b).
- **`PHP_VERSION` is inherited, not guaranteed.** Images built `FROM php:*` keep it; images that install distro PHP, bitnami images and custom builds don't have it. Absence of the variable is not absence of PHP — exec in (2b).
- **Distro version numbers don't follow upstream.** Ubuntu and RHEL usually backport fixes into the original upstream version (`8.3.6-0ubuntu0.24.04.x` can be patched while "8.3.6" reads as vulnerable), and an Alpine `-rN` release can carry a patch the same way. For distro builds the tracker is authoritative, not `classify.py`.
- **`php -i` in a shell reads the CLI config.** In official images that is the same ini as the web SAPI, but FPM pools and Apache vhosts still apply their own `php_admin_value` overrides on top; in distro packages the CLI reads a different file altogether (`/etc/php/<ver>/cli/`). Use the layered checks in 3c.
- **The official images ship ini *templates*.** `php.ini-development` / `php.ini-production` in `$PHP_INI_DIR` are never loaded; a recursive grep of that dir returns their values (`memory_limit = 128M`, `;session.upload_progress.enabled = On`) and looks like configuration. It isn't — with no `php.ini`, every setting is at its built-in default.
- **Out-of-memory fatals are invisible on default official images.** `log_errors` is off when no `php.ini` exists, so the fatal is only shown to the client and the request is logged as **200**. In a lab run the trigger script produced the fatal and the pod logs held nothing. Worker crash lines (`exited on signal 11`, `AH00051 … Segmentation fault`) come from FPM/Apache themselves and are still logged — hunt on those, and on 4a.
- **A PHP binary present is not a PHP server.** Every official `php:*` image ships `php-cgi`, and FPM images also ship the CLI. Decide the SAPI from what is running (2b), not from which binaries exist.
- **BusyBox `find` has no `-newermt` or `-ls` — and fails silently if you hide stderr.** On the official Alpine images, `find … -newermt 2026-10-20 -ls 2>/dev/null` printed nothing while a freshly dropped PHP file sat in `/tmp`. Use `-mtime -$SINCE_DAYS -exec ls -l {} +` and keep stderr visible, as in 4b.
- **Apache's piped loggers are children of `httpd`.** On Red Hat UBI images `httpd` keeps several `cat` processes (log pipes) as children of its master; a naive "child of httpd" check flagged all of them. 4a skips known piped loggers under the master.
- **Killing or recycling the worker hides the attacker's process from a "child of a worker" check.** In a lab run, crashing the FPM worker that had spawned a shell re-parented the shell to the FPM master, and a worker-only check stopped seeing it. 4a therefore also flags non-logger children of the master.
- **UBI / s2i images look wrong from the outside.** `registry.access.redhat.com/ubi9/php-8x` sets `PHP_VERSION=8.2` (branch only, so 2a reports UNKNOWN) and its image `Cmd` is a usage script, not the server. The real version (`8.2.33-1.module+el9…`) and SAPI (httpd + php-fpm) only show up in 2b.
- **Alpine packages version-suffix the binaries.** `apk add php84-fpm` installs `php84` and `php-fpm84`, not `php` / `php-fpm`; FPM logs to `/var/log/php84/error.log`, not stdout. The 2b, 3c and 4c commands glob for these names.
- **`dpkg-query -W 'php*'` lists packages that are *not installed*.** Without the status filter, a Debian image returned 90+ `php*` rows with empty versions (every name apt has heard of). Filter on `ii`, as in 2b.
- **Multi-stage Dockerfiles over-match.** A build stage `FROM composer:2` or `FROM php:8.3-cli` that only runs `composer install` doesn't ship PHP. Classify by the **final** stage.
- **PHP hides inside app images.** `wordpress`, `nextcloud`, `drupal`, `matomo`, `phpmyadmin`, bitnami and linuxserver images are PHP runtimes. Name-filtering the running-image list for "php" misses them — 2a checks every image for a reason.
- **Restarted pods erase the evidence.** A container that was redeployed after the attack has a fresh filesystem; Phase 4b on it proves nothing. Look at persisted volumes, logs shipped off-box, and cloud audit logs for the worker's credentials.
- **No IOCs yet is not "nothing to find".** With no published IPs or hashes, behavior is the only signal. Hunt on worker child processes and memory-exhaustion / segfault bursts first; add IOCs to the variables block as vendors publish them.
