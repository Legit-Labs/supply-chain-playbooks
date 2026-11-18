# nginx2root — NGINX HTTP/2 Unauthenticated RCE (CVE-2026-123007, CVE-2026-123633) — Detection & Response Playbook

> **Note for AI agents:** This playbook detects a **vulnerable deployed server**, not a poisoned dependency. The flaws are in NGINX itself, so the thing to find is **every place NGINX terminates HTTP/2** — container images, Kubernetes ingress controllers, hosts — plus the **exact NGINX version** each one runs and **whether HTTP/2 is actually enabled**. Three things make it different from a normal SCA follow-up. First, **dependency scanning will not find it**: NGINX is not a package in any lock file, and scanners only flag it once their vulnerability database carries these brand-new CVEs. Second, **floating image tags are not versions**: `nginx:stable` pulled yesterday is 1.30.6 (vulnerable); pulled today it is 1.30.7 (patched). Resolve the version from the image itself. Third, **a vulnerable version is only exploitable with HTTP/2 enabled** — Phase 3 decides that from the configuration NGINX actually loaded, not from the files in the repo.
>
> Commands use the GitHub CLI and `kubectl` by default. Adapt the discovery step for GitLab / Bitbucket and the runtime steps for ECS, Nomad, or plain Docker hosts — the logic is the same.

## Scope — What This Playbook Covers and What It Doesn't

Read this before running it, so a clean result is read for what it is.

**Validated** on 2026-11-18:

| Area | What was checked |
|---|---|
| Version from image config (2a) | Registry configs of `nginx:1.31.8`, `nginx:1.31.9-alpine`, `nginx:stable`, `bitnami/nginx`, `openresty/openresty:alpine`, `registry.k8s.io/ingress-nginx/controller:v1.13.7`: official images expose `NGINX_VERSION`, Bitnami exposes `APP_VERSION`, OpenResty and ingress-nginx expose **no version** (→ 2b) |
| HTTP/2 check script (3a) | Run against sample `nginx -T` dumps: finds `http2 on;` (including several directives on one line), `listen [::]:443 ssl http2 default_server;`, `proxy_pass` / `grpc_pass` and `worker_connections`. Ignores commented-out `http2`, `http2 off;` and `location /http2/`. Refuses an empty dump |
| Classifier (`classify.py`) | Sanity-checked against the version boundaries below |

**Covered by instructions, not lab-tested** — the in-container commands (2b, 3, 4) use standard `nginx -v` / `nginx -T` / `/proc` reads; run them on one known-vulnerable workload first as a positive control.

**Not covered** — a clean result from this playbook says nothing about these:

- **Managed load balancers and CDNs** (AWS ALB, CloudFront, Cloudflare, Azure Front Door) — they are not NGINX; check the provider.
- **Appliances and products that embed NGINX without exposing it** (some WAFs, API gateways, vendor virtual appliances). Check the vendor's advisory.
- **Exploit-specific detection.** Only one exploit (Rapid7, CVE-2026-123007) is public, and no in-the-wild IOCs exist. Phase 4 hunts on behavior. Add IOCs to the variables block when vendors publish them.
- **Images that are not running.** Phase 2a checks the images you give it; feed your registry's image list into it to cover built-but-not-deployed images.
- **Windows** NGINX builds. All commands are Linux-only.

---

## Variables — Fill These In First

```bash
# Your GitHub organization name
export ORG="your-org-name"

# Disclosure and fix: 2026-11-18. No in-the-wild exploitation reported as of that date;
# Rapid7's PoC for CVE-2026-123007 is public from the same day. Start log review at disclosure.
export SINCE="2026-11-18T00:00:00Z"
export SINCE_DAYS=$(python3 -c 'import datetime; print((datetime.date.today() - datetime.date(2026, 11, 18)).days + 1)')

# No attacker IPs, domains or hashes published (as of 2026-11-18). Hunt on behavior — Phase 4.

export LOG_DIR="/tmp/supply-chain-scan-nginx2root"
mkdir -p "$LOG_DIR"
```

Version classifier used throughout — paste it once:

```bash
cat > "$LOG_DIR/classify.py" <<'EOF'
import re, sys
for raw in sys.argv[1:]:
    if re.search(r"plus|-r3[3-7]\b|^r3[3-7]", raw, re.I):
        print(f"{raw}\tNGINX PLUS: R33-R36 vulnerable (no fix); 37.x needs 37.0.8.1+ or 37.3.0.1+ - check F5 K000163926"); continue
    m = re.match(r"^\D*(\d+)\.(\d+)\.(\d+)", raw)
    if not m:
        print(f"{raw}\tUNKNOWN (no x.y.z - floating tag? resolve it)"); continue
    v = tuple(map(int, m.groups()))
    if v < (1, 9, 5):
        verdict = "NOT AFFECTED (predates the HTTP/2 module)"
    elif v[:2] == (1, 30):
        verdict = "PATCHED" if v[2] >= 7 else "VULNERABLE"
    elif v[:2] == (1, 31):
        verdict = "PATCHED" if v[2] >= 9 else "VULNERABLE"
    elif v >= (1, 32, 0):
        verdict = "NEWER BRANCH - assume patched, confirm on nginx.org"
    else:
        verdict = "VULNERABLE (branch has no fix - upgrade to 1.30.7+ / 1.31.9+)"
    if re.search(r"(ubuntu|deb\d|\+deb|el\d|\.module|amzn|-r\d+$)", raw):
        verdict += " | distro build: confirm against the distro tracker"
    print(f"{raw}\t{verdict}")
EOF
python3 "$LOG_DIR/classify.py" 1.31.8 1.31.9 1.30.6 1.30.7 1.27.1.2 1.22.1-9+deb12u10 1.9.4   # sanity check
```

Expected: `1.31.8` / `1.30.6` / `1.27.1.2` (OpenResty core) VULNERABLE, `1.31.9` / `1.30.7` PATCHED, the Debian build VULNERABLE + "confirm against the distro tracker", `1.9.4` NOT AFFECTED.

---

## Background

Two critical memory-safety flaws in NGINX's HTTP/2 module, both **CVSS 4.0 9.2** (CVSS 3.1 8.1), disclosed and fixed **2026-11-18** in NGINX 1.30.7 / 1.31.9. Reported by Xint, Wiz Research, Rapid7, Metnir and others.

- **CVE-2026-123007 — HTTP/2 flow-control memory corruption** ([F5 K000163926](https://my.f5.com/manage/s/article/K000163926)). A crafted `WINDOW_UPDATE` / `SETTINGS` sequence pushes a stream's send window past its limit and corrupts heap memory in the worker. Needs only HTTP/2 — reachable on a server that just serves static files. Rapid7's public PoC needs ~128 GB of HTTP/2 traffic on one connection and a specific x86-64 glibc `memcpy` path.
- **CVE-2026-123633 — HTTP/2 use-after-free** ([F5 K000163928](https://my.f5.com/manage/s/article/K000163928)). When NGINX proxies HTTP/2 client requests to a backend and the worker runs low on `worker_connections`, a connection still in use is freed and reused.

Result: **unauthenticated remote code execution as the NGINX worker user** (`nginx` / `www-data`). F5 notes code execution needs ASLR to be disabled or bypassed; Wiz reports doing so reliably. Xint reached **host root** only by chaining a separate, unpatched Linux kernel SCTP flaw — including from inside a Docker container.

### Affected / Fixed

| Product | Affected | Fixed |
|---|---|---|
| NGINX Open Source | CVE-2026-123007: 1.9.5 – 1.31.8. CVE-2026-123633: 1.19.7 – 1.31.8 | **1.30.7** (stable) / **1.31.9** (mainline). Older branches get no fix — upgrade |
| NGINX Plus | R33 and later | **37.0.8.1** or **37.3.0.1** (covers both). R33 – R36: no fix |
| F5 NGINX Ingress Controller | before 5.8.0; LTS `2026-lts-r11` (builds NGINX 1.31.0) | **5.8.0** (builds NGINX 1.31.9 / Plus R37.3) |
| Community `ingress-nginx` | all (repo archived, bundles a vulnerable NGINX) | **None — will not be patched** |
| Forks: OpenResty, Tengine, Angie, freenginx | share the vulnerable code | per project — check its advisory |
| Official Docker images | every `nginx:*` image pulled before 2026-11-18 | `nginx:1.30.7`, `nginx:1.31.9` and variants; `stable` / `mainline` / `latest` now point at fixed builds |

Distribution packages: at disclosure Debian (bookworm, trixie, sid) listed both CVEs **unfixed**; Ubuntu, RHEL, Alpine, SUSE, Amazon Linux had shipped no fix. Distros backport fixes **without changing the upstream version** (Debian 12 ships 1.22.1, Ubuntu 24.04 ships 1.24.0) — use the distro tracker, not the version string.

The same release fixes eight other NGINX CVEs, including CVE-2026-118899 (TLS 1.3 request-body loop) and CVE-2026-113425 (mail proxy use-after-free), both rated *major* by nginx.org. Disabling HTTP/2 does not cover those — upgrading does.

### What IS affected

- Any NGINX in the affected range **with HTTP/2 enabled on a listener an attacker can reach**, behind a CDN or load balancer included (unless that layer terminates HTTP/2 and speaks HTTP/1.1 to NGINX — see Pitfalls).
- **Every container image built from `nginx:*` before 2026-11-18**, and every image that installs NGINX from a distro repo, until rebuilt on a fixed package.
- Images that **embed NGINX** without saying so: `bitnami/nginx`, `openresty/*`, ingress controllers (`ingress-nginx/controller`, `nginx/nginx-ingress`), and many application images that ship NGINX as a front proxy.

### What is NOT affected

- Versions at or above 1.30.7 / 1.31.9, NGINX Plus 37.0.8.1 / 37.3.0.1, or distro builds the vendor tracker marks fixed.
- NGINX with HTTP/2 **disabled on every listener** — not exploitable through these two CVEs (still upgrade for the other fixes).
- NGINX that only receives HTTP/1.1 from a front proxy that terminates HTTP/2 (e.g. an ALB with HTTP/1.1 to targets). Confirm what the front layer forwards.
- Go / Java / npm libraries named after NGINX (`nginx-prometheus-exporter`, `nginx-plus-go-client`) — clients, not the server.

### Exploitation status — as of 2026-11-18

**No confirmed in-the-wild exploitation; not in CISA KEV.** Rapid7 published a working RCE PoC for CVE-2026-123007 against a Docker `nginx:1.31.8` image. Wiz and Xint withheld their exploits. Expect scanning to start quickly — NGINX is one of the most exposed servers on the internet.

---

## Phase 1 — Discover NGINX Deployments Across the Org

NGINX is rarely visible to SCA. Search three ways; any one alone misses deployments.

GitHub code search allows **10 requests per minute**. Define this helper once — it paces requests, waits out the limit, and fails loudly (a rate-limited search with stderr hidden looks exactly like "no NGINX here"):

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

**1a. Dockerfiles that ship NGINX**

GitHub code search ignores punctuation, so scope by filename and post-filter with a regex:

```bash
# Positive control first — must return results, or the search is broken
ghs "FROM" --owner "$ORG" --filename Dockerfile | python3 -c "import json,sys; print('control hits:', len(json.load(sys.stdin)))"

for f in Dockerfile Containerfile; do
  ghs "nginx" --owner "$ORG" --filename "$f"
  ghs "openresty" --owner "$ORG" --filename "$f"
done | python3 -c "
import json, sys, re
pat = re.compile(r'(FROM\s+\S*(nginx|openresty|tengine|angie)\S*|apt-get install[^\n]*\bnginx|apk add[^\n]*\bnginx|(dnf|yum|microdnf) install[^\n]*\bnginx)', re.I)
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

**1b. Deployment manifests and ingress controllers**

```bash
for q in "image: nginx" "nginx:1." "bitnami/nginx" "openresty" "ingress-nginx" \
         "nginx-ingress" "ingressClassName: nginx" "kubernetes.io/ingress.class: nginx" "use-http2"; do
  echo "=== $q ==="
  ghs "$q" --owner "$ORG" | \
    python3 -c "import json,sys,re; [print(i['repository']['nameWithOwner'],'|',i['path']) for i in json.load(sys.stdin) if not re.search(r'(\.(md|rst|txt)$|(^|/)(tests?|docs?)/)', i['path'])]" | sort -u
done | tee "$LOG_DIR/manifest-hits.txt"
```

`ingressClassName: nginx` finds workloads routed through an NGINX ingress — the controller itself may be installed by a platform team in a different repo.

**1c. Running workloads — the source of truth**

```bash
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{range .spec.containers[*]}{.image}{" "}{end}{"\n"}{end}' \
  > "$LOG_DIR/k8s-pods.tsv"
cut -f3 "$LOG_DIR/k8s-pods.tsv" | tr ' ' '\n' | sort -u | grep -v '^$' > "$LOG_DIR/k8s-images.txt"
wc -l "$LOG_DIR/k8s-images.txt"

# Ingress controllers in the cluster
kubectl get pods -A -o wide | grep -iE "ingress-nginx|nginx-ingress" | tee "$LOG_DIR/ingress-controllers.txt"
```

Do **not** filter the image list by name — Phase 2a checks every image, and 2b catches NGINX inside images whose name doesn't mention it.

Classify each Phase 1 hit:

- Running workload / ingress controller / Helm release → live deployment; go to Phase 2.
- Dockerfile that builds from an NGINX base or installs NGINX → find the deployed image; go to Phase 2.
- Multi-stage Dockerfile where NGINX appears only in a build stage → classify by the **final** `FROM`.

---

## Phase 2 — Resolve the NGINX Version Each Deployment Actually Runs

**The tag is not the answer.** `nginx:stable`, `nginx:1.31-alpine` and `nginx:latest` are moving tags.

**2a. From the image, without running it (fast, covers every image in 1c)**

Official `nginx:*` images — and every image built `FROM` them — carry `NGINX_VERSION`; Bitnami images carry `APP_VERSION`.

```bash
# crane (https://github.com/google/go-containerregistry) reads the config from the registry;
# falls back to `docker image inspect` for images already pulled locally
while read -r img; do
  cfg=$(crane config "$img" 2>/dev/null || docker image inspect "$img" 2>/dev/null) || { echo -e "$img\tUNREADABLE"; continue; }
  echo "$cfg" | python3 -c "
import json, sys
d = json.load(sys.stdin); d = d[0] if isinstance(d, list) else d
c = d.get('config') or d.get('Config') or {}
env = dict(e.split('=', 1) for e in c.get('Env') or [] if '=' in e)
v = env.get('NGINX_VERSION') or ('$img'.find('bitnami/nginx') >= 0 and env.get('APP_VERSION'))
if v: print('$img', v, sep='\t')
"
done < "$LOG_DIR/k8s-images.txt" | tee "$LOG_DIR/image-nginx-versions.tsv"

awk -F'\t' 'NF == 2 {print $2}' "$LOG_DIR/image-nginx-versions.tsv" | sort -u | xargs python3 "$LOG_DIR/classify.py"
```

An image with no `NGINX_VERSION` may still run NGINX — OpenResty, ingress-nginx, distro-installed NGINX and custom builds all lack it. 2b covers those.

**2b. From the running container (authoritative)**

```bash
# Which NGINX binary is running, and its version (nginx -v prints to stderr)
kubectl exec -n <ns> <pod> -- sh -c \
  'for p in /proc/[0-9]*; do c=$(cat $p/comm 2>/dev/null); case "$c" in nginx|openresty) readlink $p/exe;; esac; done | sort -u | while read b; do echo "$b: $($b -v 2>&1)"; done; true'

# Distro-packaged NGINX — installed packages only, with the full distro version
kubectl exec -n <ns> <pod> -- sh -c \
  'dpkg-query -W -f="\${db:Status-Abbrev}\t\${Package}\t\${Version}\n" "nginx*" "libnginx*" 2>/dev/null | grep "^ii"; apk info -v 2>/dev/null | grep -E "^nginx"; rpm -qa "nginx*" 2>/dev/null; true'
```

Ingress controllers: the community `ingress-nginx` controller is **affected regardless of version** (no fix will ship). For F5 NGINX Ingress Controller, read the image tag of the controller pod — 5.8.0 or later is fixed; `2026-lts-r11` is not.

Hosts and VMs: run the same commands over SSH / SSM.

**2c. Verdict**

Run every resolved version through `classify.py`. For **distro builds**, look the full package version up in the distro tracker (Debian: `https://security-tracker.debian.org/tracker/CVE-2026-123007`; Ubuntu: `https://ubuntu.com/security/CVE-2026-123007`; RHEL: `https://access.redhat.com/security/cve/CVE-2026-123007`).

---

## Phase 3 — Is HTTP/2 Enabled? (Exposure)

A vulnerable version is exploitable through these CVEs only if HTTP/2 is on. Read the configuration NGINX **actually loaded** (`nginx -T` dumps every included file), not the repo copy.

**3a. HTTP/2 listeners**

```bash
kubectl exec -n <ns> <pod> -- sh -c 'nginx -T 2>/dev/null || openresty -T 2>/dev/null' > "$LOG_DIR/<ns>_<pod>_nginx-T.conf"

python3 - "$LOG_DIR/<ns>_<pod>_nginx-T.conf" <<'EOF'
import re, sys
raw = open(sys.argv[1]).read()
if "configuration file" not in raw:
    sys.exit("EMPTY DUMP - nginx -T failed (permissions? different binary name?) - do not read as 'no HTTP/2'")
conf = re.sub(r'#[^\n]*', '', raw)   # drop comments (incl. the dump's own file headers)
d = r'(?:^|[;{}])\s*'                 # start of a directive, even with several on one line
h2 = re.findall(d + r'(http2\s+on\s*;|listen\s+[^;]*\bhttp2\b[^;]*;)', conf, re.M)
proxy = re.findall(d + r'(proxy_pass|grpc_pass)\s', conf, re.M)
wc = re.findall(d + r'worker_connections\s+(\d+)', conf, re.M)
print("HTTP/2 directives:", h2 or "NONE")
print("proxying to a backend:", bool(proxy), "| worker_connections:", wc or "default (512)")
EOF
```

- Any HTTP/2 directive → **exposed to CVE-2026-123007**.
- HTTP/2 **and** `proxy_pass` / `grpc_pass` → **also exposed to CVE-2026-123633** (more likely when `worker_connections` is low relative to traffic).
- `nginx -T` also prints `# configuration file …` headers — the script refuses an empty dump rather than reporting "no HTTP/2".

**3b. Ingress controllers.** Community `ingress-nginx` enables HTTP/2 by default (`use-http2: "true"`):

```bash
kubectl get configmap -A -o json | python3 -c "
import json,sys
for cm in json.load(sys.stdin)['items']:
    d = cm.get('data') or {}
    if 'use-http2' in d or cm['metadata']['name'].endswith(('ingress-nginx-controller','nginx-configuration')):
        print(cm['metadata']['namespace'], cm['metadata']['name'], 'use-http2 =', d.get('use-http2', 'unset (default: true)'))
"
```

**3c. Reachability.** Internet-facing first: a `Service` of type `LoadBalancer` / `NodePort` or an `Ingress` in front of the workload, or a public host. Record what the front layer forwards — an L4 load balancer (NLB, TCP passthrough) forwards HTTP/2 as-is; an L7 one may downgrade to HTTP/1.1.

---

## Phase 4 — Review for Compromise

For every internet-facing deployment that ran a vulnerable build with HTTP/2 enabled since `$SINCE`. No IOCs are published, so hunt on **behavior**.

**4a. Processes spawned by NGINX workers.** NGINX workers never fork shells or tools in normal operation (unless you run the `perl` module or `lua` code that shells out — know which before reading results):

```bash
kubectl exec -n <ns> <pod> -- sh -c '
pp() { awk "/^PPid:/{print \$2}" /proc/$1/status 2>/dev/null; }
for p in /proc/[0-9]*; do
  pid=${p#/proc/}; comm=$(cat $p/comm 2>/dev/null); ppid=$(pp $pid); pcomm=$(cat /proc/$ppid/comm 2>/dev/null)
  case "$pcomm" in nginx|openresty) case "$comm" in nginx|openresty) ;; *) echo "SUSPICIOUS pid=$pid parent=$pcomm($ppid) cmd=$(tr "\0" " " < $p/cmdline)";; esac;; esac
done; true' | tee -a "$LOG_DIR/process-hits.txt"
```

Also look for processes running as the worker user (`nginx` / `www-data`) that are not NGINX: `sh`, `bash`, `python`, `perl`, `curl`, `wget`, `nc`, `busybox`. On hosts with EDR, query `nginx` → shell / interpreter parent-child pairs.

**4b. Worker crashes in the error log.** The exploits corrupt the heap; failed attempts crash workers, and the NGINX master logs every one:

```bash
kubectl logs -n <ns> <pod> --all-containers --since-time="$SINCE" 2>/dev/null \
  | grep -aE "worker process [0-9]+ exited on signal (11|6|7)|heap corruption|double free|malloc\(\): " \
  | tee "$LOG_DIR/crash-hits.txt"

# Distro-packaged NGINX often logs to files, not stdout
kubectl exec -n <ns> <pod> -- sh -c \
  'grep -aHE "exited on signal (11|6|7)" /var/log/nginx/error.log* 2>/dev/null; true' | tee -a "$LOG_DIR/crash-hits.txt"
```

`[alert] … worker process 1234 exited on signal 11` is rare in normal operation. A burst — especially correlated with one client — is the clearest signal available.

**4c. Traffic shape (CVE-2026-123007).** The public exploit holds one HTTP/2 connection open and pushes ~128 GB through it. Look for single connections with extreme byte counts or durations in load-balancer / flow logs, and unusually many `WINDOW_UPDATE` frames if you have an HTTP/2-aware sensor.

**4d. Files and persistence.** New files written by the worker user since `$SINCE` in writable paths, new cron entries, unexpected outbound connections:

```bash
kubectl exec -n <ns> <pod> -- sh -c \
  'for d in /tmp /var/tmp /dev/shm /var/cache/nginx /usr/share/nginx/html; do [ -d "$d" ] && find "$d" -type f -mtime -'"$SINCE_DAYS"' ! -path "*/..*" -exec ls -l {} +; done; true'
```

`/var/cache/nginx` holds proxy cache and temp body files — expect churn there; look for executables and scripts, not cache entries.

Any hit → treat the deployment as compromised: isolate it, preserve logs, and go to Phase 5 step 5. Because the published root chain goes through the host kernel, **also review the node** the pod ran on.

---

## Phase 5 — Remediation & Hardening

1. **Upgrade NGINX** to 1.30.7 / 1.31.9 (Plus: 37.0.8.1 / 37.3.0.1), then **restart** it — `nginx -s reload` keeps the old binary running. Internet-facing first.
2. **Rebuild every NGINX image with `--pull`** (and `--no-cache` if your base is a floating tag), redeploy, then **re-run 2a/2b against the running pod** — an incomplete rollout leaves you exposed while the ticket says fixed.
3. **Ingress controllers:** F5 NGINX Ingress Controller → 5.8.0. Community `ingress-nginx` → set `use-http2: "false"` in the controller ConfigMap now and plan a migration (no fix will ship).
4. **Can't upgrade today:** disable HTTP/2 (`http2 off;` on 1.25.1+, or remove `http2` from `listen`), then restart. Test gRPC first — it requires HTTP/2. This blocks only the two HTTP/2 CVEs.
5. **If Phase 4 found anything:** rotate every secret the NGINX worker could read — TLS private keys, upstream credentials in the config, `auth_basic` files, environment variables, and cloud credentials attached to the pod or instance. Rebuild from a clean image rather than cleaning in place.
6. **Reduce blast radius:** run NGINX containers non-privileged with dropped capabilities, and block the SCTP kernel module on hosts that don't need it (`install sctp /bin/false` in `/etc/modprobe.d/`) — the published root chain depends on it.
7. **Pin base images by digest** and rebuild deliberately, so "which NGINX is running" has one answer.

---

## Evidence Table

Record one row per NGINX deployment (`$LOG_DIR/evidence-repos.csv`):

| Field | Value |
|---|---|
| Deployment source (repo / cluster / registry / host) | |
| Image reference (tag **and** digest) | |
| Resolved NGINX version (`NGINX_VERSION` / `nginx -v` / package) | |
| Distro package + version (if distro-built) | |
| Product (OSS / Plus / ingress-nginx / F5 IC / OpenResty / other fork) | |
| Verdict (`classify.py` / distro tracker) | VULNERABLE / PATCHED / NOT AFFECTED |
| HTTP/2 enabled (from `nginx -T`) | yes / no |
| Proxies to a backend (`proxy_pass` / `grpc_pass`) | yes / no |
| Reachable from | internet / internal / restricted |
| Worker child processes found? | yes / no / not checked |
| Worker crashes since 2026-11-18? | yes / no |
| Upgraded + re-verified in running pod? | yes / no |
| Secrets rotated? | yes / no / n/a |

---

## Pitfalls & Fixes

- **SCA cannot see the server.** NGINX is not in any lock file. Libraries with "nginx" in their name (`nginx-prometheus-exporter`, `nginx-plus-go-client`, `nginxreceiver`) are clients and exporters — not findings.
- **Scanner findings lag.** Container scanners flag these CVEs only after their vulnerability database ingests them, often days after disclosure. "No findings for CVE-2026-123007" on day one means nothing — resolve versions yourself (Phase 2).
- **Floating tags moved under you.** On 2026-11-18 `nginx:stable` moved to 1.30.7 and `nginx:mainline` / `latest` to 1.31.9. The same tag string is vulnerable in an image pulled earlier.
- **`NGINX_VERSION` is inherited, not guaranteed.** OpenResty, ingress-nginx controller images and distro-installed NGINX have no such variable (verified: `openresty/openresty:alpine`, `ingress-nginx/controller:v1.13.7`). Absence of the variable is not absence of NGINX — exec in (2b).
- **OpenResty versions have four parts.** `1.27.1.2` is NGINX core 1.27.1 plus an OpenResty patch level — `classify.py` reads the first three parts, which is the core version.
- **Distro version numbers don't follow upstream.** Debian's `1.22.1-9+deb12u11` may carry the fix while "1.22.1" reads as vulnerable. For distro builds the tracker is authoritative, not `classify.py`.
- **The repo config is not the running config.** Helm values, ConfigMaps and `include` files change what NGINX loads. Read `nginx -T` from the running process (3a).
- **`nginx -T` can fail silently.** Without read access to every included file, or when the binary is `openresty`, the dump is empty — which looks like "no HTTP/2". The 3a script refuses an empty dump.
- **`http2` in a path or comment is not HTTP/2.** A grep for the bare word matches `location /http2/` and `# listen 443 ssl http2;`. The 3a script strips comments and only matches `http2 on;` and `listen … http2`.
- **Directives don't have to start a line.** `server { listen 443 ssl; http2 on; … }` on one line is valid NGINX. A line-anchored regex (`^\s*http2 on`) missed it in the dry run; 3a matches after `;`, `{` or `}` too.
- **A reload is not a restart.** `nginx -s reload` re-reads config but keeps the old binary. After a package upgrade on a host, restart the service.
- **The ingress controller is often someone else's.** Workloads behind an NGINX ingress inherit its exposure even if they don't run NGINX themselves. Find the controller (1c) and its owner.
