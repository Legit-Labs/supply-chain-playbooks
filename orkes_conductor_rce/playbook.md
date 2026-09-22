# Orkes Conductor Unauthenticated RCE (CVE-2026-58138) — Detection & Response Playbook

> **Note for AI agents:** This playbook detects a **vulnerable deployed version**, not a poisoned dependency. Two things make it different from a normal SCA follow-up. First, **dependency scanning will not find this** — the affected Conductor versions (3.21.21–3.30.1) were never published to Maven Central by either publisher, so no `pom.xml`, `build.gradle` or lock file can reference one. You must look at *deployments*: container registries, Kubernetes workloads, Helm values, compose files. Second, **the vulnerable setting was hardcoded in Conductor's own source**, not a config option — so unlike a misconfiguration CVE there is no "safe configuration" to check for. Version plus reachability is the whole test.

## Variables — Fill These In First

```bash
# Your GitHub organization name
export ORG="your-org-name"

# When public exploitation became possible. A public PoC repository appeared
# 2026-07-22; honeypot hits were recorded from 2026-07-24, two days later.
# Treat this as the start of the log-review window.
export SINCE="2026-07-22T00:00:00Z"

# No public IOC IP list exists for this campaign. FortiGuard reported source
# geographies only (Germany, Hong Kong, Indonesia, UAE, India) — not addresses.
# Hunt on behaviour and request shape, not on an IP allowlist.

export LOG_DIR="/tmp/conductor-cve-2026-58138"
mkdir -p "$LOG_DIR"
```

---

## Background

**CVE-2026-58138** (CVSS 3.1 **9.8** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, CVSS 4.0 **9.3**, CWE-94, GHSA-7x5q-8f6h-rjrc).

Conductor lets workflow definitions embed small JavaScript or Python expressions, evaluated by a GraalVM scripting context. In the affected versions that context was created with **full host access**, hardcoded in Conductor's own source:

```java
// JavaScript evaluator
Context.newBuilder("js").allowHostAccess(HostAccess.ALL)
// Python evaluator
Context.newBuilder("python").allowAllAccess(true)
```

A submitted expression therefore reaches arbitrary Java classes and runs operating-system commands — via reflection or direct subprocess creation — as the Conductor process user. **The workflow API accepts definitions without authentication**, so no credentials are needed.

Conductor is a workflow orchestrator, which raises the stakes above a typical application RCE. It concentrates credentials by design: database logins, the cloud IAM role attached to its pod, queue credentials, and API tokens for every downstream service it drives. Code execution there is both a credential haul and a pivot. An attacker also gains read/write over workflow definitions and execution history — **business logic can be altered with no commit, no pull request and no code review**.

This is a re-introduction, not a new class of bug: CVE-2025-26074 described the same weakness in the older Nashorn evaluator at v3.21.11. It was fixed, the scripting engine was swapped for GraalJS, and the hole came back.

### Affected / Fixed

| | Version |
|---|---|
| Affected | **3.21.21 – 3.30.1** (Orkes Conductor and open-source `conductor-oss/conductor`) |
| Fixed | **3.30.2** (released 2026-06-03). Current line is 3.32.4 / 3.33.0-rc5 |

The unsafe evaluator arrived with the Nashorn → GraalJS migration, which first shipped in **v3.21.21** — exactly where the affected range begins.

The fix required two passes: the first denied reflection plus `Runtime`, `ProcessBuilder`, `Process`, `System` and `Thread`, and removed the Python evaluator's blanket access; the second disabled host class loading, native access, thread and process creation, file I/O and environment access, and turned off `js.load` / `js.print` / `js.console`.

### Exploitation preconditions (BOTH must be true)

1. A running Conductor server in the **3.21.21 – 3.30.1** range.
2. Its **workflow API is reachable** by the attacker. Internet-exposed instances are at highest risk; an attacker already inside the network only needs internal reachability.

There is no third condition. Because the unsafe evaluator was hardcoded, **every instance in the range is exploitable out of the box** — there is no setting an operator could have got wrong or right.

### What IS affected

- Any self-hosted Conductor server in the affected range whose workflow API can be reached — including images your own pipeline builds from `conductor-oss` source.

### What is NOT affected

- Instances on **3.30.2 or later**.
- **Orkes Cloud** tenants — the vendor patched the hosted service.
- **Client SDKs.** `@io-orkes/conductor-javascript`, `conductor-python`, `org.conductoross:conductor-client`, `io.orkes.conductor:orkes-conductor-client` and similar do **not** contain the vulnerable code. They matter only as a *fingerprint* that your org talks to a Conductor deployment somewhere — see Phase 1.
- Note that versions **below 3.21.21** are not "safe" in general — they predate this flaw but CVE-2025-26074 covers the same weakness in the older Nashorn evaluator. Upgrade regardless.

---

## Phase 1 — Discover Conductor Deployments Across the Org

This is the hard part of this CVE, and the reason a playbook exists. Conductor will not appear in any
dependency manifest, and **images built in-house are rarely named after the upstream project**.
Observed real-world naming across three separate organisations:

```
ipfx-conductor-oss          bifrost-conductor           tf-conductor
phoenix-dev/conductor       stork-production/conductor  global-conductor
conductor-ui                simple-conductor-worker     conductor-server-oss
conductor-backend           conductor-frontend          odmc/conductor
```

Note that some of the strongest signals are not the server at all — `conductor-ui` is Conductor's
own UI module, and `*-conductor-worker` names come from Conductor's worker terminology. Both mean a
server exists nearby.

Search three ways, because any one of them alone misses deployments.

**1a. Deployment definitions and image references**

```bash
for q in "orkes/conductor" "conductoross/conductor" "conductor-server" "conductor-oss" \
         "conductor-ui" "conductor-worker" \
         "chart: conductor" "CONDUCTOR_SERVER_URL" "conductor.properties"; do
  echo "=== $q ==="
  gh search code "$q" --owner "$ORG" --json repository,path -L 100 2>/dev/null | \
    python3 -c "import json,sys; [print(i['repository']['nameWithOwner'],'|',i['path']) for i in json.load(sys.stdin)]" | sort -u
done
```

**Positive control:** before trusting a clean result, confirm the search reaches your code — run `gh search code "FROM" --owner "$ORG" -L 5` and verify known Dockerfiles come back. A zero-hit search and a broken search look identical.

**1b. Client SDKs — the fingerprint that finds hidden deployments**

Nobody imports a Conductor client unless something is talking to a Conductor server. This is how a deployment gets found when the image name gives nothing away.

```bash
for q in "@io-orkes/conductor-javascript" "orkes-workflow-visualizer" "conductor-python" \
         "org.conductoross" "io.orkes.conductor" "conductor-sdk"; do
  echo "=== $q ==="
  gh search code "$q" --owner "$ORG" --json repository,path -L 100 2>/dev/null | \
    python3 -c "import json,sys; [print(i['repository']['nameWithOwner'],'|',i['path']) for i in json.load(sys.stdin)]" | sort -u
done
```

A hit here does **not** mean that repo is vulnerable. It means *someone in the org runs or calls a Conductor server* — go find it.

**1c. Running workloads**

Repo search misses anything deployed from a registry without committed manifests. Check what is actually running:

```bash
# Kubernetes — match on image name AND on the typical container/app naming
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{range .spec.containers[*]}{.image}{" "}{end}{"\n"}{end}' \
  | grep -iE "conductor|workflow" | tee "$LOG_DIR/k8s-candidates.txt"

# Container registries — list repositories and grep loosely, custom names are common
# (AWS ECR example; adapt for GCR/ACR/Harbor)
aws ecr describe-repositories --query 'repositories[].repositoryName' --output text \
  | tr '\t' '\n' | grep -iE "conductor|workflow|orchestr"
```

Classify each hit:

- Kubernetes workload / compose service / Helm release → a live deployment; go to Phase 2.
- Dockerfile or image build definition → your pipeline builds Conductor; go to Phase 2 and check what the build produces.
- Client SDK in a manifest → evidence a deployment exists somewhere; keep hunting until you find it.
- Docs, READMEs, examples → note, not a deployment.

---

## Phase 2 — Determine the Running Version

**The tag will usually not tell you.** Real deployments are commonly tagged `latest` or `main-sha-<commit>`, which carry no version information at all. Assume you need to look inside.

**2a. From the image tag, if you are lucky**

```bash
grep -rhoE "(orkes|conductoross)/conductor[^ \"']*:[^ \"']+" . 2>/dev/null | sort -u
```

- Tag in **3.21.21 – 3.30.1** → **vulnerable**.
- Tag ≥ **3.30.2** → version-safe.
- `latest`, `main-sha-*`, a bare digest, or any non-semver tag → **treat as vulnerable until proven otherwise** and continue to 2b.

**2b. From inside the image — the reliable method**

⚠️ **The top-level jar filename does not carry the version.** The official Dockerfile renames the
build output on the way in:

```
COPY --from=builder /conductor/server/build/libs/*boot*.jar /app/libs/conductor-server.jar
```

So you get `/app/libs/conductor-server.jar` — a versionless Spring Boot fat jar. Searching for
`conductor-core-*.jar` at the top level returns nothing and reads as a false negative.

The version lives in two places inside that jar. Check both:

```bash
# Locate the jar first (path may differ in a custom-built image)
kubectl exec -n <ns> <pod> -- sh -c 'find / -name "conductor*.jar" 2>/dev/null'
# → typically /app/libs/conductor-server.jar

# (1) The manifest — fastest
kubectl exec -n <ns> <pod> -- sh -c \
  'unzip -p /app/libs/conductor-server.jar META-INF/MANIFEST.MF | grep -i -E "version|title"'

# (2) Nested module jars — a Boot fat jar carries its dependencies in BOOT-INF/lib/,
#     and the sibling Conductor modules there DO carry versions
kubectl exec -n <ns> <pod> -- sh -c \
  'unzip -l /app/libs/conductor-server.jar | grep -E "BOOT-INF/lib/conductor.*\.jar"'
```

Same commands work against an image directly with `docker run --rm --entrypoint sh <image> -c '...'`.

If an image SBOM is available (Syft or any scanner that descends into nested archives), the
`conductor-*` components and their versions will be in it — that is the least invasive route, and
it works even where you cannot exec into the pod.

**2c. For images your own pipeline builds**

If the image is built from `conductor-oss` source, the tag refers to *your* build, not to a Conductor release. Find the upstream version the build pulled — check the pinned git ref, submodule commit, or Gradle version property in the build repo, then map that commit to a release tag.

**Verdict for the instance = vulnerable if the resolved version is 3.21.21–3.30.1, regardless of configuration.**

---

## Phase 3 — Check Exposure & Review for Exploitation

### 3a. Is the workflow API reachable?

Determine who can reach the Conductor HTTP port (commonly 8080). This lives in network policy and ingress, outside repo scanning — have the deployment owner confirm.

- Reachable from the internet → highest urgency. Treat as actively targeted; scanning for this has been continuous since late July 2026.
- Reachable from a broad internal network → still exploitable by anything that gets a foothold.
- Reachable only from a tightly controlled set of callers → lower urgency, still patch.

In Kubernetes, check for `Service` type `LoadBalancer`/`NodePort` and any `Ingress` fronting the workload, and confirm whether a network policy actually restricts ingress to it.

### 3b. Review workflow definitions for injected scripts

This is the highest-signal check. The attack leaves its payload in a registered workflow definition.

Pull the definitions from the metadata API (adapt host/auth to your deployment) and look for script expressions in the four affected task types:

```bash
curl -s "http://<conductor-host>:8080/api/metadata/workflow" \
  | tee "$LOG_DIR/workflow-defs.json" \
  | python3 -c "
import json,sys
defs=json.load(sys.stdin)
HOT={'INLINE','LAMBDA','DO_WHILE','SWITCH'}
for w in defs:
    for t in w.get('tasks',[]):
        if t.get('type') in HOT:
            print(w.get('name'), '|', t.get('type'), '|', json.dumps(t.get('inputParameters',{}))[:300])
"
```

Review every result against what your teams actually registered. Treat as suspicious any definition that:

- nobody on the team recognises or can attribute to a change request;
- contains script expressions invoking Java classes, reflection, `Runtime`, `ProcessBuilder`, or subprocess calls;
- was created or modified after `$SINCE`.

### 3c. Review request logs

On each instance, look at access logs since `$SINCE` for definition-creating requests from unexpected sources:

```bash
# Adapt the log path / use `kubectl logs` for containerised deployments
grep -aE "POST .*/api/(metadata/workflow|workflow)" <access-log> 2>/dev/null | tee "$LOG_DIR/api-posts.txt"
```

Unauthenticated POSTs to the metadata or workflow endpoints from outside your expected caller set are the exploitation signature.

### 3d. Look for the effects of successful execution

- Shell or subprocess execution parented to the Conductor JVM.
- Outbound network connections from the Conductor host or pod that do not match its known downstream integrations.
- New files, cron entries or systemd units on the host since `$SINCE`.
- Use of the pod's cloud credentials from unfamiliar source IPs — check cloud audit logs (CloudTrail and equivalents) for the pod's role since `$SINCE`.

Any hit → treat the instance as compromised and proceed to Phase 4 with full credential rotation.

---

## Phase 4 — Remediation & Hardening

1. **Upgrade to 3.30.2 or later** (prefer the current 3.32.x line). For images your pipeline builds, rebuild against a patched upstream ref — bumping the image tag alone changes nothing if the build still pulls vulnerable source.
2. **Verify after deploying.** Re-run the Phase 2b jar check against the *running* pod. A rebuild that silently failed, or a rollout that did not complete, leaves you exposed while the ticket says fixed.
3. **Remove the workflow API from untrusted networks.** No instance should be internet-reachable. Put authentication and network policy in front of it even after patching — this API accepts definitions unauthenticated by design, so the next evaluator bug lands the same way.
4. **Pin images by digest, not by `latest` or a branch-sha tag.** The floating tags are why version determination took three phases.
5. **If any Phase 3 sign was found, rotate everything the instance could reach:** the pod's cloud role credentials, database credentials, message-queue credentials, and API tokens for every downstream service Conductor calls. An orchestrator's credential set is typically broader than any single service it invokes.
6. **Audit workflow definitions for tampering** since `$SINCE`, and compare against whatever source of truth you have. Definitions live outside source control, so altered business logic leaves no trace in commit history or code review — this is the step most likely to be skipped and most likely to matter.

---

## Evidence Table

Record one row per Conductor deployment:

| Field | Value |
|---|---|
| Deployment source (repo / cluster / registry) | |
| Image reference + tag | |
| Resolved version (from jar, not tag) | |
| Version vulnerable? (3.21.21–3.30.1) | yes / no |
| Workflow API reachable from | internet / internal / restricted |
| Suspicious workflow definitions found? | list |
| Unexpected POSTs to metadata API since `$SINCE`? | yes / no |
| Signs of command execution? | list |
| Upgraded to ≥ 3.30.2? | yes / no |
| Version re-verified after deploy? | yes / no |
| Secrets rotated? | yes / no / n/a |

---

## Pitfalls & Fixes

- **Dependency scanning will not find this.** The affected versions were never published to Maven Central — `org.conductoross` server modules stop at 3.21.16, `io.orkes.conductor` at 3.9.31-orkes. A clean SCA report says nothing about your exposure here. Phase 1 is the only discovery path.
- **Custom image names hide deployments.** Real instances have been found as `ipfx-conductor-oss`,
  `bifrost-conductor`, `stork-production/conductor` and `conductor-server-oss`. Grep loosely and
  cross-check with the client-SDK fingerprint in 1b.
- **But "conductor" is a badly overloaded word — expect mostly noise.** A loose grep will surface
  far more unrelated software than real Conductor. The recurring false positives:
  - **OpenStack** names many of its services `*-conductor` — `nova-conductor`, `ironic-conductor`,
    `magnum-conductor`, `cyborg-conductor`, `senlin-conductor`, `solum-conductor`,
    `tacker-conductor`, `trove-conductor`, `cinder-conductor`. None are related.
  - **AWS Billing Conductor** — `billingconductor`, `aws-java-sdk-billingconductor`,
    `software.amazon.awssdk:billingconductor`, `AWSSDK.BillingConductor`.
  - **Bioconductor** — `bioconductor/bioconductor_docker`, the R bioinformatics project.
  - Assorted one-offs such as `logstash-conductor` and vendor services that simply use the word.

  In one sweep across a full customer base, a raw `%conductor%` match returned 99 rows; excluding
  the three families above left 50, which resolved to **three** organisations actually running
  Conductor. Filter first, then investigate — and do not report a hit until you have confirmed it
  is not one of the above.
- **A client SDK hit is not a vulnerable component.** `@io-orkes/conductor-javascript` and friends contain none of the vulnerable code. Do not report them as the finding — use them to locate the server.
- **`latest` and `main-sha-*` tags tell you nothing.** Always resolve the version from inside the
  running container, not from the deployment manifest.
- **The jar filename is versionless too.** `/app/libs/conductor-server.jar` carries no version —
  the Dockerfile renames it on copy. A search for `conductor-core-*.jar` at the top level returns
  empty and looks like "not vulnerable." Read `META-INF/MANIFEST.MF` or list `BOOT-INF/lib/` inside
  the jar instead.
- **There is no safe configuration to look for.** Unlike misconfiguration CVEs, the unsafe evaluator was hardcoded. Do not waste time hunting for a toggle — version and reachability are the entire test.
- **Orkes Cloud is not your problem.** If a team uses the hosted service rather than self-hosting, the vendor patched it. Confirm which one you are looking at before raising a finding.
- **No public IOC IP list exists.** Reporting gives source geographies only. Hunting for a specific address will produce a false negative; hunt on request shape and on the contents of workflow definitions instead.
