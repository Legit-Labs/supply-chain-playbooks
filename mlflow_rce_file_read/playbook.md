# MLflow Unauthenticated RCE (CVE-2026-116692) & Arbitrary File Read (CVE-2026-116690) — Detection & Response Playbook

> **Note for AI agents:** This playbook detects a **vulnerable running MLflow tracking server**, not a vulnerable dependency. Both flaws live in the server's HTTP handlers. Finding `mlflow` in a `requirements.txt` or lock file is only a lead: most code that installs `mlflow` uses it as a **client** to log runs to a server somewhere else, and that code is not exploitable. The full test is **a running `mlflow server` + a vulnerable version + an HTTP port an attacker can reach**. The attack happens at application runtime over HTTP, so CI install logs show nothing. Look at deployments, the server host, the tracking database and the server's access logs. **Do not run Python on a suspect server** (see Phase 2).

## Variables — Fill These In First

```bash
# Your GitHub organization name
export ORG="your-org-name"

# Start of the review window. The RCE advisory (GHSA-26p8-2jq9-3vq9), which
# ships a working proof of concept, went public 2026-10-09 08:20 UTC. The
# file-read advisory (GHSA-m65p-9j7q-6w33) followed 2026-10-13 05:56 UTC.
# CVE IDs were assigned 2026-10-27, and Previdian honeypots recorded
# exploitation of the file read (CVE-2026-116690) within a day of that.
# No in-the-wild exploitation of the RCE is confirmed. Treat 2026-10-09 as the start.
export SINCE="2026-10-09T00:00:00Z"
export SINCE_MS=1791504000000   # $SINCE in epoch milliseconds, for tracking-DB queries

# No public IOC IP list exists. Hunt on request shape, tracking-DB contents
# and files on disk, not on an IP allowlist.

export LOG_DIR="/tmp/mlflow-cve-2026-116692"
mkdir -p "$LOG_DIR"
```

GitHub code search allows **10 requests per minute**, and Phase 1 makes more than that. A plain loop gets `HTTP 403: API rate limit exceeded` part-way through, and with stderr hidden a rate-limited search looks exactly like "no MLflow here". Define this helper once:

```bash
ghs() {
  local out i
  for i in 1 2 3 4 5; do
    if out=$(gh search code "$@" --json repository,path -L 1000 2>&1); then
      printf '%s\n' "$out"; sleep 7; return 0
    fi
    case "$out" in
      *"rate limit"*) echo "rate-limited on [$*], waiting 60s" >&2; sleep 60 ;;
      *) echo "SEARCH FAILED [$*]: $out" >&2; return 1 ;;
    esac
  done
  echo "SEARCH FAILED [$*]: still rate-limited after 5 tries" >&2; return 1
}
hits() { python3 -c "import json,sys; [print(i['repository']['nameWithOwner'],'|',i['path']) for i in json.load(sys.stdin)]" | sort -u; }
```

---

## Background

| | CVE-2026-116692 | CVE-2026-116690 |
|---|---|---|
| Advisory | GHSA-26p8-2jq9-3vq9 | GHSA-m65p-9j7q-6w33 |
| CVSS 3.1 | **9.8** | **7.5** (CWE-22) |
| Impact | Unauthenticated **Python code execution** as the server process | Unauthenticated **read of any file** the server process can read |
| Affected | **3.12.0rc0 – 3.16.x** | **3.10.0 – 3.16.1** |
| Exploited in the wild | Not confirmed (public PoC in the advisory) | **Yes** — honeypot hits within a day of CVE assignment |
| Fixed | **3.17.0** (on PyPI 2026-10-07) | **3.17.0** |

**CVE-2026-116692 (RCE).** MLflow 3.12.0 added third-party scorers. To deserialize a scorer, the server imports a module path taken from the request, as long as it starts with one of four allowed prefixes (`mlflow.genai.scorers.ragas`, `.deepeval`, `.trulens`, `.phoenix`). It then instantiates a class from that module. An attacker chains MLflow's own endpoints to plant a module under one of those prefixes:

1. `POST /api/2.0/mlflow/experiments/create` with `artifact_location` = `file://<site-packages>/mlflow/genai/scorers/trulens`
2. `POST /api/2.0/mlflow/runs/create` — MLflow creates `<artifact_location>/<run_id>/artifacts/`
3. `POST /ajax-api/2.0/mlflow/upload-artifact?run_uuid=<run_id>&path=<x>.py` — the attacker's Python file lands inside the `mlflow` package
4. `POST /ajax-api/3.0/mlflow/scorer/invoke` referencing `mlflow.genai.scorers.trulens.<run_id>.artifacts.<x>` — the module is imported and its constructor runs

**CVE-2026-116690 (file read).** For a model version tagged `mlflow.prompt.is_prompt`, the server rejects `file://` and absolute paths but does not validate a schemeless relative `source`:

1. `POST /api/2.0/mlflow/registered-models/create`
2. `POST /api/2.0/mlflow/model-versions/create` with `"source": "../../../tmp"` and tag `mlflow.prompt.is_prompt`
3. `GET /model-versions/get-artifact?name=<model>&version=<n>&path=<file>` — returns the file

Documented read targets: `/etc/passwd`, SQLite tracking and auth databases (`mlflow.db`, `basic_auth.db` — including the admin password hash), configuration and secrets on disk, shell history.

### Exploitation preconditions

1. A running **MLflow tracking server** (`mlflow server`, or `mlflow ui`, which runs the same server) in an affected version.
2. Its **HTTP port is reachable** by the attacker (default port 5000). The server runs **without authentication by default**. With `--app-name basic-auth`, **any authenticated user** — including low-privilege accounts — can still exploit both flaws.
3. **RCE only:** the server process can write into its own Python package directory. This holds in the **official `ghcr.io/mlflow/mlflow` image**, which runs as root with a writable `site-packages`. A read-only root filesystem, or a non-root server user that cannot write to a root-owned `site-packages`, blocks this RCE chain. **It does not block the file read.**

### What IS affected

- Any self-hosted MLflow tracking server in the affected range that attackers can reach. This covers official images, images your pipelines build with `pip install mlflow`, and long-running `mlflow server` processes on VMs or notebook hosts.

### What is NOT affected

- **Code that uses MLflow only as a client** — `mlflow.log_metric(...)`, `mlflow.set_tracking_uri(...)`, training jobs that log to a remote server. The vulnerable handlers run only inside the server process. Such repos matter only as a *fingerprint* that points to a server (Phase 1b).
- **`mlflow-skinny`** and **`mlflow-tracing`** — client-only packages that ship no server (PyPI: "without SQL storage, server, UI").
- **Model-serving containers** from `mlflow models serve` / `mlflow models build-docker`. That scoring server exposes only `/ping`, `/health`, `/version` and `/invocations` — none of the vulnerable endpoints.
- **Managed MLflow** (Databricks, Amazon SageMaker, Azure ML). The vendor runs the server; confirm patch status with them rather than with this playbook.
- Servers on **3.17.0 or later**.
- Versions **below 3.10.0** are not affected by these two CVEs but are **not safe**: CVE-2026-64849 (unauthenticated full-read SSRF, fixed in 3.15.0) affects them. Upgrade regardless.

---

## Phase 1 — Discover MLflow Tracking Servers Across the Org

Search three ways; any one alone misses deployments.

**1a. Deployment definitions and image references**

```bash
# Positive control first — must return results, or the search is broken
ghs "FROM" --owner "$ORG" --filename Dockerfile | python3 -c "import json,sys; print('control hits:', len(json.load(sys.stdin)))"

for f in Dockerfile docker-compose.yml docker-compose.yaml compose.yaml; do
  echo "=== mlflow server in $f ==="; ghs "mlflow server" --owner "$ORG" --filename "$f" | hits
done
for q in "mlflow server" "mlflow ui" "ghcr.io/mlflow/mlflow" "backend-store-uri" "default-artifact-root" "artifacts-destination"; do
  echo "=== $q (yaml) ==="; ghs "$q" --owner "$ORG" --extension yaml | hits
  echo "=== $q (yml) ===";  ghs "$q" --owner "$ORG" --extension yml | hits
done
for f in Chart.yaml values.yaml; do
  echo "=== mlflow in $f ==="; ghs "mlflow" --owner "$ORG" --filename "$f" | hits
done
```

**1b. Client fingerprints — they point to the server**

Nobody sets a tracking URI unless a server exists. The value says where it is:

```bash
for q in "MLFLOW_TRACKING_URI" "set_tracking_uri"; do
  echo "=== $q ==="; ghs "$q" --owner "$ORG" | hits
done
```

Open the hits and read the URI. `http(s)://<host>:5000`, an internal hostname or a Kubernetes service name → **a self-hosted server; go find it**. `databricks` / `databricks-uc` or a SageMaker ARN → managed MLflow, not covered here. `file:` or `./mlruns` → local logging, no server.

A Legit SCA finding for `mlflow` in a manifest belongs here too: it is a **lead to a server**, not a finding by itself.

**1c. Running workloads**

```bash
# Kubernetes — image name AND container command (custom images often install mlflow into a generic base)
kubectl get pods -A -o json | python3 -c "
import json,sys
for p in json.load(sys.stdin)['items']:
    for c in p['spec']['containers']:
        blob=' '.join([c.get('image','')]+c.get('command',[])+c.get('args',[]))
        if 'mlflow' in blob.lower():
            print(p['metadata']['namespace'], p['metadata']['name'], c['name'], '|', blob[:200])
" | tee "$LOG_DIR/k8s-candidates.txt"

# Container registries (AWS ECR example; adapt for GCR/ACR/Harbor)
aws ecr describe-repositories --query 'repositories[].repositoryName' --output text | tr '\t' '\n' | grep -i mlflow

# VMs, notebook hosts, shared GPU boxes — a long-running server process
ps -eo pid,user,args | grep -E "mlflow (server|ui)|mlflow\.server|uvicorn.*mlflow|gunicorn.*mlflow" | grep -v grep
```

Classify each hit:

- Kubernetes workload / compose service / Helm release / host process running `mlflow server` or `mlflow ui` → **a live server**; go to Phase 2.
- Dockerfile or build definition that ends in `mlflow server` → your pipeline builds a server image; go to Phase 2 and check what the build produces.
- Tracking URI pointing at a self-hosted host → a server exists; keep hunting until you find it.
- `mlflow models serve` / `build-docker`, `mlflow-skinny`, client-only code, docs and examples → note it; not affected.

---

## Phase 2 — Determine the Running Version

⚠️ **Read the version with shell commands, not Python.** On a server hit by the RCE, the attacker ran code as the server user — root in the official image, with a writable `site-packages`. A dropped `.pth` file or `sitecustomize.py` runs on **every Python start**, and `mlflow --version`, `pip show mlflow` and `python -c "import mlflow"` all start Python.

**2a. From the installed package metadata (reliable)**

```bash
# Kubernetes (use `docker exec <ctr>` for compose, or run directly on a VM)
kubectl exec -n <ns> <pod> -- sh -c 'ls -d /usr/local/lib/python3*/site-packages/mlflow-*.dist-info /usr/lib/python3*/*-packages/mlflow-*.dist-info /opt/*/lib/python3*/site-packages/mlflow-*.dist-info 2>/dev/null'
# → e.g. /usr/local/lib/python3.10/site-packages/mlflow-3.14.0.dist-info

# An image you have not deployed
docker run --rm --entrypoint sh <image> -c 'ls -d /usr/local/lib/python3*/site-packages/mlflow-*.dist-info'
```

If the server runs from a virtualenv or conda env, locate it from the process: `kubectl exec ... -- sh -c 'cat /proc/1/cmdline | tr "\0" " "'`, then look for `mlflow-*.dist-info` next to that interpreter.

**2b. From the server itself (no shell access needed)**

From a machine that can reach it: `curl -s http://<host>:5000/version` returns the version string. This only reads a value and is safe to run.

**2c. From the image tag**

Official images are tagged by version (`ghcr.io/mlflow/mlflow:v3.14.0`). Custom images and `latest` tell you nothing — use 2a.

**Verdict:**

| Resolved version | Status |
|---|---|
| 3.12.0rc0 – 3.16.x | **Vulnerable to both** (RCE + file read) |
| 3.10.0 – 3.11.x | **Vulnerable to the file read** |
| ≥ 3.17.0 | Not affected by these CVEs |
| < 3.10.0 | Not affected by these CVEs; vulnerable to CVE-2026-64849 — upgrade anyway |

---

## Phase 3 — Check Exposure

**3a. Who can reach the port?** This lives in network policy and ingress, outside repo scanning — have the deployment owner confirm. In Kubernetes, check for a `Service` of type `LoadBalancer`/`NodePort`, any `Ingress` in front of the workload, and whether a `NetworkPolicy` actually restricts ingress. On cloud VMs, check the security group or firewall for port 5000 (or whatever `--port` is set to).

- Reachable from the internet → highest urgency; assume it was probed.
- Reachable from a broad internal network → exploitable by anything that gets a foothold.
- Bound to `127.0.0.1` or reachable only by a fixed set of callers → lower urgency, still patch.

**3b. Is authentication on?**

```bash
kubectl exec -n <ns> <pod> -- sh -c 'cat /proc/1/cmdline | tr "\0" " "; echo'
```

No `--app-name basic-auth` and no authenticating proxy in front → **unauthenticated**: anyone who reaches the port can exploit both flaws. With `basic-auth`, every account that can log in can still exploit them — list who has accounts.

**3c. RCE precondition — can the server write into its own package?**

```bash
kubectl exec -n <ns> <pod> -- sh -c 'id; SP=$(dirname $(ls -d /usr/local/lib/python3*/site-packages/mlflow-*.dist-info | head -1)); test -w "$SP/mlflow/genai/scorers/trulens" && echo "SCORER DIR WRITABLE -> RCE chain possible" || echo "scorer dir not writable"'
```

Writable → the RCE chain works as published. Not writable → the published RCE chain is blocked, but the file read is not.

---

## Phase 4 — Review for Exploitation

Run every check below on each vulnerable, reachable server. **The tracking database and the filesystem are the primary evidence.** Access logs do not record request bodies, so a malicious `model-versions/create` looks exactly like a legitimate one in the log (4c).

**4a. Tracking / registry database**

The backend store is whatever `--backend-store-uri` points to (from 3b). For SQLite, copy the file out and query it on your own machine. Do not run the server's Python to read it:

```bash
kubectl cp <ns>/<pod>:/path/to/mlflow.db "$LOG_DIR/mlflow.db"     # or: docker cp <ctr>:/path/to/mlflow.db "$LOG_DIR/"
DB="sqlite3 -header -column $LOG_DIR/mlflow.db"                   # for PostgreSQL/MySQL, run the same SQL with psql/mysql (read-only user)
```

RCE staging — experiments whose artifact location points into a Python package directory:

```sql
SELECT experiment_id, name, artifact_location, lifecycle_stage, creation_time
FROM experiments
WHERE artifact_location LIKE '%-packages/%'
   OR artifact_location LIKE '%/mlflow/genai/scorers%';
```

Any row is the RCE attack, whatever its date. No legitimate setup stores experiment artifacts inside `site-packages`. Then list the runs in those experiments; their `run_uuid` values are the planted module directories in 4b and the `run_uuid=` in 4c:

```sql
SELECT run_uuid, experiment_id, start_time, artifact_uri
FROM runs
WHERE experiment_id IN (SELECT experiment_id FROM experiments
                        WHERE artifact_location LIKE '%-packages/%'
                           OR artifact_location LIKE '%/mlflow/genai/scorers%');
```

File-read staging — prompt-tagged model versions with a non-placeholder source:

```sql
SELECT mv.name, mv.version, mv.source, t.value AS is_prompt, mv.creation_time
FROM model_versions mv
JOIN model_version_tags t ON t.name = mv.name AND t.version = mv.version
WHERE t.key = 'mlflow.prompt.is_prompt'
  AND (mv.source IS NULL OR mv.source <> 'dummy-source');
```

Legitimate prompts registered through MLflow's prompt API store the placeholder `dummy-source` (observed on 3.14.0). Treat as malicious any row whose `source` is a relative path (`..`, `.`, a bare directory name), a percent-encoded path or a Windows drive path. The vulnerable check looked only at whether the tag **exists**, so rows tagged `false` count too.

Absence of rows is not proof. An attacker can delete the registered model or experiment afterwards, so also run 4b and 4c.

**4b. Filesystem — planted modules and persistence**

Every file the `mlflow` package installed is listed in its `RECORD`. A file under `mlflow/` that is not in `RECORD` was added after install:

```bash
kubectl exec -n <ns> <pod> -- sh -c '
SP=$(dirname $(ls -d /usr/local/lib/python3*/site-packages/mlflow-*.dist-info | head -1)); cd "$SP"
cut -d, -f1 mlflow-*.dist-info/RECORD | sort -u > /tmp/.rec
find mlflow -type f | sort > /tmp/.fs
echo "--- files under mlflow/ not installed by pip:"; comm -13 /tmp/.rec /tmp/.fs | grep -v "/__pycache__/"
echo "--- run-id directories inside scorer packages:"
find mlflow/genai/scorers -mindepth 2 -maxdepth 2 -type d | grep -E "/[0-9a-f]{32}$"
echo "--- .pth / sitecustomize changed since SINCE:"
find "$SP" -maxdepth 1 \( -name "*.pth" -o -name "sitecustomize.py" -o -name "usercustomize.py" \) -newermt "2026-10-09"
rm -f /tmp/.rec /tmp/.fs'
```

A planted RCE module looks like `mlflow/genai/scorers/<ragas|deepeval|trulens|phoenix>/<32-hex run_id>/artifacts/<name>.py`. **Preserve it before you remove anything** — it is the attacker's payload and shows what ran. The official image ships exactly one `.pth` file (`distutils-precedence.pth`) and no `sitecustomize.py`.

**4c. Access logs**

The default server logs one line per request to stdout (`<client-ip>:<port> - "<METHOD> <path> HTTP/1.1" <status>`):

```bash
kubectl logs -n <ns> <pod> --since-time="$SINCE" > "$LOG_DIR/server.log"   # or docker logs / journalctl / your log platform
grep -E "scorer/invoke|upload-artifact|model-versions/(create|get-artifact)|experiments/create|registered-models/create" "$LOG_DIR/server.log" \
  | tee "$LOG_DIR/suspect-requests.txt"
```

How to read the hits:

- **`POST /ajax-api/3.0/mlflow/scorer/invoke`** from an unexpected client, especially returning **500** → RCE trigger. The published chain throws a 500 *after* the attacker's code has already run, so a 500 is not a failed attempt.
- **`POST /ajax-api/2.0/mlflow/upload-artifact?run_uuid=<id>`** where `<id>` is a run from the 4a query → module upload.
- **`GET /model-versions/get-artifact?name=<m>&version=<v>&path=<file>`** where `<m>/<v>` matches a 4a file-read row → **a file was read**. The `path=` value is the file the attacker took; list every one.
- `POST .../model-versions/create` and `.../experiments/create` lines alone prove nothing — legitimate clients make the same calls. Correlate them with 4a.

Behind a reverse proxy or load balancer, the client IP in the server log is the proxy. Pull the proxy's logs for the real source.

**4d. Effects of successful execution**

- Processes spawned by the MLflow server (shells, `curl`, `wget`, interpreters) other than its own uvicorn/gunicorn workers.
- Outbound connections from the server host or pod that do not match its artifact store (S3/GCS/Azure) and backend database.
- Use of the pod's or VM's cloud credentials from unfamiliar source IPs — check CloudTrail or the equivalent since `$SINCE`.
- New files in `/tmp`, the home directory, cron or systemd since `$SINCE`.

Any hit in 4a–4d → treat the server as compromised and do the full rotation in Phase 5.

---

## Phase 5 — Remediation & Hardening

1. **Upgrade to 3.17.0 or later.** Official image: `ghcr.io/mlflow/mlflow:v3.17.0` or newer. Custom images: pin `mlflow>=3.17.0` and rebuild.
2. **Verify after deploying.** Re-run the 2a check against the *running* pod. A rebuild that silently used a cached layer, or a rollout that did not finish, leaves you exposed.
3. **Take the server off untrusted networks** and put authentication in front of it. `basic-auth` alone did not stop either flaw for logged-in users — prefer an authenticating proxy or SSO, plus a network policy.
4. **If you cannot upgrade today**, block these at the proxy/WAF: `/ajax-api/3.0/mlflow/scorer/invoke`, `/ajax-api/2.0/mlflow/upload-artifact` and `/model-versions/get-artifact`. Note the last path has **no `/api/2.0/mlflow` prefix** (see Pitfalls). Blocking it breaks model-artifact downloads in the UI until you upgrade.
5. **Reduce blast radius:** run the server as a non-root user with a read-only root filesystem (or at least a `site-packages` it cannot write).
6. **If Phase 4 found anything:**
   - Preserve evidence (DB copy, planted files, logs).
   - **Rebuild the server from a clean image.** Do not clean it in place — the attacker ran code as root.
   - Delete the malicious experiments and model versions.
   - Rotate everything the server process could read: `basic-auth` user passwords (the auth DB holds the hashes), the backend database credentials, the artifact-store cloud credentials, and every secret in its environment variables and config files. If 4c showed which `path=` files were read, start with those.

---

## Evidence Table

Record one row per MLflow tracking server:

| Field | Value |
|---|---|
| Deployment source (repo / cluster / registry / host) | |
| Image reference + tag | |
| Resolved version (from `dist-info`, not tag) | |
| Vulnerable to RCE (3.12.0rc0–3.16.x) / file read (3.10.0–3.16.1)? | yes / no |
| Reachable from | internet / internal / localhost only |
| Authentication | none / basic-auth / proxy-SSO |
| Scorer package writable by server user? | yes / no |
| Experiments with artifact location in `site-packages`? | list |
| Prompt model versions with non-placeholder source? | list |
| Files under `mlflow/` not in `RECORD`? | list |
| `scorer/invoke` / `get-artifact` hits since `$SINCE`? | list, with `path=` values |
| Signs of command execution or credential use? | list |
| Upgraded to ≥ 3.17.0 and re-verified? | yes / no |
| Secrets rotated? | yes / no / n/a |

---

## Pitfalls & Fixes

These come from a lab run against the official `ghcr.io/mlflow/mlflow:v3.14.0` image and a dry run of the Phase 1 searches.

- **A dependency hit is not a server.** `mlflow` in `requirements.txt`, `pyproject.toml` or a lock file usually means client code. Report a server only after Phase 1 finds something actually running `mlflow server`/`mlflow ui`. Treat SCA hits as leads.
- **The advisory's file-read path returns 404.** The advisory's PoC uses `GET /api/2.0/mlflow/model-versions/get-artifact`, but on 3.14.0 that path returned **404**. The working route is **`/model-versions/get-artifact`** with no API prefix, and it returned the file. A WAF rule or log search for the advisory's path misses the real attack. Match on `model-versions/get-artifact` alone.
- **Access logs do not show request bodies.** A legitimate `mlflow.genai.register_prompt(...)` call and a malicious relative-`source` request produced identical `POST /api/2.0/mlflow/model-versions/create ... 200` lines in the lab. Only the tracking DB (4a) tells them apart.
- **The legitimate prompt source is the placeholder `dummy-source`.** Don't flag every prompt-tagged model version — flag those whose `source` isn't the placeholder.
- **Don't trust Python on a suspect server.** In the lab, the upload endpoint wrote into `site-packages` as root without any further exploit. Anyone who reached the RCE can also drop a `.pth` file there, and it runs on every Python start. That includes `mlflow --version`, `pip show` and the MLflow CLI. Use the shell-only checks in 2a and 4b, and copy the SQLite DB out before querying it.
- **A 500 from `scorer/invoke` is a success.** The published chain errors *after* the planted constructor has run. Don't dismiss failed-looking requests.
- **GitHub code search runs out quickly.** The dry run hit `HTTP 403: API rate limit exceeded` on the eighth unpaced query. Every later search came back empty and looked like "no MLflow". Use the `ghs` helper.
- **`--filename` matches more than the exact name.** `--filename Dockerfile` also returned `Dockerfile.mlflow`, `Dockerfile-mlflow` and `Dockerfile.vulnerable`. `--filename docker-compose.yml` returned `.bak`, `.disabled`, `.j2` and `.OLDv2` copies. Templates, backups and disabled files are not deployments — check that the file is actually used before reporting it.
- **GitHub code search ignores punctuation.** `"ghcr.io/mlflow/mlflow"` matches any file containing those words. Confirm each hit by opening the file.
- **Managed MLflow is not yours to patch.** A tracking URI of `databricks` or a SageMaker ARN points at a vendor-run server. Confirm which kind you're looking at before raising a finding.
- **No public IOC IP list exists.** The exploitation report gives no addresses. Hunting for a specific IP produces a false negative; hunt on the DB rows, planted files and request shapes above.
