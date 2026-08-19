# CopyEscape — `docker cp` Destination Escape (CVE-2026-17106) — Detection & Response Playbook

> **Note for AI agents:** This playbook detects a **vulnerable version state**, not a one-time poisoned install. There is no exposure window to scan CI logs against — any host running an affected Docker version is exploitable *right now*, and any host that ran `docker cp` out of an untrusted container since **2026-06-24** (when a working public PoC landed) may already have been hit. There are **two independent surfaces** and they need different checks: (1) the **Docker version installed on hosts and baked into CI images** — where the real risk lives, and (2) the **`github.com/moby/go-archive` Go module in `go.mod`** — where SCA will flag you, usually as a harmless transitive pull. Do not conflate them. Adapt the discovery step to wherever your org defines runners and container images (GitHub Actions workflows, GitLab CI, Jenkins agents, Dockerfiles, Helm values).

## Variables — Fill These In First

```bash
# Your GitHub organization name
export ORG="your-org-name"

# First public PoC (moby/moby#52948). Anything before this is pre-exploit;
# anything after is a window in which a working exploit existed in the wild.
export POC_DATE="2026-06-24"

# Security fix shipped in Docker Engine / CLI 29.7.0 (go-archive v0.3.0).
export FIXED_ENGINE="29.7.0"      # security boundary
export TARGET_ENGINE="29.7.2"     # what to actually install — see Background
export FIXED_DESKTOP="4.86.0"
export FIXED_SANDBOXES="0.38.0"
export FIXED_GO_ARCHIVE="v0.3.0"

export LOG_DIR="/tmp/copyescape-cve-2026-17106"
mkdir -p "$LOG_DIR"
```

**No IOCs are published for this CVE.** There are no exfil domains, C2 IPs, or file hashes — the vulnerability writes attacker-chosen bytes to attacker-chosen paths, so the artifacts are whatever the attacker picked. Detection is version state plus local tamper evidence, not indicator matching. Do not invent IOCs to fill this gap.

---

## Background

**CVE-2026-17106** ("CopyEscape", GHSA-hfg8-hc9c-6c3h, CVSS 4.0 **7.1 High** — `CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`). Reported privately to Docker by the **Imperva Red Team** on 2026-04-11; remediated upstream by thaJeztah. CWE-22 (path traversal) and CWE-59 (link following).

The tar-extraction functions in `github.com/moby/go-archive` do not re-establish confinement to the destination directory after resolving a symlink. During `docker cp <container>:<path> <host-path>`, a malicious container:

1. Uses an `LD_PRELOAD` interposer so the pivot path looks like a *regular file* to processes inside the container, while the daemon sees the underlying path as a **directory** and walks the attacker-controlled tree beneath it.
2. Gets a clock rather than racing blind: a large file is placed immediately before the pivot directory and watched with filesystem notifications. When the daemon opens that file the walk has arrived, and the large file widens the timing window. The switch is then two `rename` calls — a repeatable sequence, not a coin flip.
3. Swaps the directory for an **absolute symlink** mid-build.
4. The daemon emits a tar containing *both* the symlink entry and child entries whose paths traverse through it — `WalkDir` recorded the entry as a directory, then `addTarFile` re-`Lstat`s the same pathname and sees a symlink. One path answers two questions at two different times.
5. The client validates one constructed path but creates the original absolute symlink from different values: the containment check evaluates a `filepath.Join`-built `targetPath`, while `os.Symlink` receives the raw `hdr.Linkname` from the archive. Confinement is never re-applied to the child entries. (The same check also uses a string prefix, which is not path containment — `/safe/output-elsewhere` begins with `/safe/output`.)
6. Child entries get written **through** the symlink, landing outside the destination with the permissions of whoever ran the copy.

The result is an arbitrary file create/overwrite primitive. The published PoC escalates it to root by replacing `/usr/bin/runc` with a shell script, which a later Docker lifecycle operation executes as root. On macOS the same primitive reaches shell startup files, `~/.ssh/config`, credential helpers, source trees, cloud configuration, and `~/Library/LaunchAgents` persistence — the archive crosses the Docker Desktop VM boundary and the symlink is resolved in the **Mac's** filesystem namespace, so the container never needs to escape the VM.

**Two bugs, only one of which got the CVE.** The chain needs both the producer-side TOCTOU (step 4) and the extraction flaw (step 5). Imperva's timeline records that on 2026-07-27 Docker confirmed **the source-walk TOCTOU would not receive its own CVE** and would be handled as defence-in-depth hardening; the security fix hardened the extraction library. Treat the producer-side race as still live, which is why the stopped-container workaround below matters.

### Timeline

| Date | Event |
|---|---|
| 2026-04-11 | Imperva Red Team reports privately to Docker (acknowledged 04-14, confirmed valid 04-15) |
| 2026-06-24 | A **working PoC is already public** in a third-party repo (`bikini/exploitarium`); a public issue is filed the same day (moby/moby#52948) explicitly noting the exploit is public. Reproduced there on Docker 29.4.0, rootful **and** rootless |
| 2026-07-10 | The 90-day disclosure period elapses with **no public patch** |
| 2026-07-24 | CVE-2026-17106 assigned; an **August 3** coordinated release is targeted |
| 2026-07-30 | **Security fix ships** — `go-archive` v0.3.0 → Docker Engine / CLI **29.7.0**. It causes significant functional regressions; Docker requests an extension to August 10 |
| 2026-08-06 | Docker Sandboxes 0.38.0; Docker Engine / CLI 29.7.2 (`go-archive` v0.3.3) |
| 2026-08-10 | Final coordinated release — Docker Desktop **4.86.0** |
| 2026-08-18 | GHSA published to the global advisory database — GHSA/OSV-based scanners begin flagging |

Note the ordering, because it governs what your evidence is worth. Docker knew from **11 April**. A working exploit was public from **24 June — sixteen days before the disclosure deadline even elapsed**, and more than five weeks before any patch existed. No advisory database mentioned it until **18 August**, nearly eight weeks after the exploit went public and four months after the initial report. **A clean SCA report dated before 2026-08-18 is not evidence of safety** — every GHSA/OSV-based scanner was silent through the entire exposure period.

### Affected / Fixed

| Component | Affected | Fixed |
|---|---|---|
| `github.com/moby/go-archive` | `< 0.3.0` | `v0.3.0` |
| Docker Engine / CLI | `< 29.7.0` | **29.7.0** (install **29.7.2** — see below) |
| Docker Desktop | `< 4.86.0` | `4.86.0` |
| Docker Sandboxes | `< 0.38.0` † | `0.38.0` † |

† Sandboxes figures come from the Imperva write-up. `docker/sandboxes` is not a public repository and the GHSA cites no Sandboxes reference, so these cannot be independently verified — treat as vendor-reported. Skip Phase 2c entirely if your org does not use Sandboxes.

**There are no backports — the fix exists only on the 29.7 line.** Verified 2026-08-19: the newest release on every older line predates the 30 July fix (29.6.2 = 2026-07-16, 29.5.3 = 2026-06-03, 28.5.2 = 2025-11-05, and the 28.x line has not shipped since Nov 2025). The 25.x LTS line *did* receive backports on 2026-08-13 for the sibling `docker cp` CVEs — CVE-2026-41567, CVE-2026-41568, CVE-2026-42306 — but **not** CVE-2026-17106, which suggests a backport is not coming. So for anything below 29.7 the remediation is a **line jump to 29.7.2**, not a patch bump. Plan for that: it is a materially bigger change than a point release, especially for images pinned to 26.x/27.x/28.x tags.

**Install 29.7.2, not 29.7.0.** The security fix is in 29.7.0 (`go-archive` v0.3.0) and 29.7.0 is **not** vulnerable to this CVE. But Imperva records that the 29.7.0 fix "caused significant functional regressions," which is why Docker extended the coordinated release to August 10. Every `go-archive` release after v0.3.0 is labelled a regression fix for v0.3.0: **v0.3.2** restored extraction through absolute symlinks inside the destination root (`var/run` → `/run`), **v0.3.3** restored absolute hardlink targets and device-node permissions (and set close-on-exec on the Linux permission-fallback descriptors). Version mapping: 29.7.0 → v0.3.0, 29.7.1 → v0.3.2, 29.7.2 → v0.3.3. Upgrade to 29.7.2 to get the fix without the regressions — and note 29.7.2 also carries unrelated changes (a `docker service create` panic fix, BuildKit v0.32.2, nftables compatibility), so it is not purely a regression release.

### Exploitation preconditions (ALL must be true)

1. Docker Engine / CLI below 29.7.0 (or Desktop below 4.86.0, or Sandboxes below 0.38.0).
2. An attacker controls code running **inside a container** — a PR-supplied image, a third-party base image, an untrusted build, a multi-tenant runner.
3. A **`docker cp` (or `sbx cp`) copy-*out* of that container** is then executed — by a human at a shell, by a CI step, a Makefile target, a release script, a runner entrypoint, or by code shelling out via `subprocess`/`exec.Command`. Copy-*in* is not this bug. **No human needs to be at the keyboard:** an unattended CI step is both the likelier and the more dangerous form, because nobody is watching it and the source image content came from whoever opened the PR.
4. The copy runs with permissions worth stealing — `sudo docker cp` gives root; an unprivileged user still gets their own dotfiles and SSH config.

### What IS affected

- CI jobs that build or run a third-party/PR-supplied image and then `docker cp` artifacts (test results, coverage reports, build outputs) out of it.
- Developer laptops on Docker Desktop below 4.86.0 that pull and poke at untrusted images.
- Docker-in-Docker (`docker:*-dind`, `docker:*-cli`) images baked into pipelines at a tag below 29.7.0 — the vulnerable CLI/daemon ships *inside the image*.
- Self-hosted or multi-tenant runners where one tenant's container can influence another's copy.

### What is NOT affected

- Hosts on Engine/CLI 29.7.0+, Desktop 4.86.0+, or Sandboxes 0.38.0+.
- `docker cp` **into** a container (`docker cp ./file container:/path`) — the escape is in the copy-out extraction path.
- Copying out of a container whose contents you fully control and built yourself from trusted sources — precondition 2 fails, so there is no attacker to win the race.
- Go programs that merely have `github.com/moby/go-archive` as an `// indirect` dependency and never call its tar-extraction functions. **This is the common case and it is not exposure** — but confirm which bucket you are in per Phase 3, because "indirect" alone does not clear you.
- Code that pulls a container archive from the Engine API and extracts it with a **different** tar implementation (stdlib `archive/tar`, Python `tarfile`, Node `tar`). Not this CVE — those need their own traversal review.

---

## Phase 1 — Discover the Docker Version Surface Across the Org

This is the surface that matters. Find every place a Docker version is pinned or a copy-out happens.

```bash
# Docker-in-Docker / CLI images pinned in CI and Dockerfiles.
# NOTE (dry-run 2026-08-19, LegitSecurity org): `gh search code` does NOT tokenise a
# bare "docker:dind" or "docker:cli" usefully — both returned 0 hits on an org that
# demonstrably runs dind. Use the forms below, which returned 35 and 2 hits respectively.
for q in "FROM docker:" "docker-dind" "dind" "docker/library/docker"; do
  echo "=== $q ==="
  gh search code "$q" --owner "$ORG" --json repository,path -L 100 2>/dev/null | \
    python3 -c "import json,sys; [print(i['repository']['nameWithOwner'],'|',i['path']) for i in json.load(sys.stdin)]" | sort -u
done

# Actual copy-out invocations — the trigger. Note the container:path -> host direction.
# Automation is the primary path, not the exception: CI steps, Makefile targets,
# release scripts, runner entrypoints, and code shelling out all count.
for q in "docker cp" "docker container cp" "sbx cp"; do
  echo "=== $q ==="
  gh search code "$q" --owner "$ORG" --json repository,path -L 100 2>/dev/null | \
    python3 -c "import json,sys; [print(i['repository']['nameWithOwner'],'|',i['path']) for i in json.load(sys.stdin)]" | sort -u
done
```

In a checkout, sweep the automation directly — this catches the Makefile targets and
entrypoint scripts that `gh search code` indexes unevenly, and the wrapped invocations:

```bash
# The copy-OUT form specifically: a container ref followed by a colon.
grep -rnE "(docker (container )?cp|sbx cp)[[:space:]]+[^[:space:]]+:" \
  --include="Makefile" --include="*.mk" --include="*.sh" --include="*.bash" \
  --include="*.yml" --include="*.yaml" --include="Jenkinsfile*" --include="Dockerfile*" . 2>/dev/null

# Code shelling out to it.
grep -rnE "(subprocess|exec\.Command|execSync|Popen|system)\(.{0,80}docker (container )?cp" . 2>/dev/null
```

**Positive control:** before trusting a clean result, confirm the search actually reaches your code. `gh search code "FROM" --owner "$ORG" -L 5` works but is noisy — on the dry-run it returned 4 non-Dockerfiles (a README, three `.py` files) out of 5 hits, so read the paths rather than the count. A zero-hit search and a broken search look identical.

**Pitfall proven on the dry-run:** two of the four original image queries (`docker:dind`, `docker:cli`) returned **zero** hits against an org that runs dind in `runner-scale-set` Helm values. The colon defeats GitHub's code-search tokeniser. If you only ran those, you would have concluded the org was clean. Always corroborate an image search with the checkout-level `grep` below.

Classify each hit:

- `Dockerfile`, `.gitlab-ci.yml`, `.github/workflows/*.yml`, Jenkinsfile, Makefile, release/entrypoint shell script, Helm `values.yaml`, k8s manifest → a real version pin or a real copy-out; carry to Phase 2.
- A copy-out reached through `subprocess` / `exec.Command` / `execSync` → same as a direct CLI call. The extraction still happens in the `docker` client the wrapper invokes.
- A `docker cp` in a README, a comment, or a docs snippet → note it, but it is not an execution site.
- A `docker cp` copying **into** a container → not affected, drop it.

**The intersection is what matters.** A copy-out site is only exposure if its *source image* is built from third-party or PR-supplied content. Produce that intersection explicitly — for each copy-out site, trace back to how the source image was built. No dependency scanner will produce this list for you.

---

## Phase 2 — Determine the Vulnerable Version State

### 2a. Runner and workstation Docker version

Ask each runner owner and each developer to report:

```bash
docker version --format 'client={{.Client.Version}} server={{.Server.Version}}'
# Docker Desktop users:
docker desktop version 2>/dev/null || echo "check Docker Desktop > About"
```

- Client **or** server below `29.7.0` → **vulnerable**. Both halves of the flow matter: the daemon builds the archive, the client extracts it.
- Desktop below `4.86.0` → vulnerable.
- Note that distro packages lag upstream badly. A "current" `apt`/`yum` Docker is very often below 29.7.0.

### 2b. Docker version baked into CI images

For every `docker:*` image tag found in Phase 1:

```bash
# Resolve the tag to the CLI version it actually contains
docker run --rm docker:<tag> docker --version 2>/dev/null
```

- Tag encodes a version below 29.7.0 (`27.5.1-dind`, `28.0.4-dind`, `26.1.3-cli`, `29.6.2-dind`, …) → **vulnerable**.
- Floating tag (`dind`, `cli`, `latest`, or no tag) → **treat as vulnerable** until you resolve the running digest. A floating tag pulled and cached months ago is whatever it was then, not what it is now.
- Tag at 29.7.2+ → version-safe.

> **Tag values are not a version field.** In inventory and registry APIs the *version* of these images is frequently a `sha256:` digest, with the human-readable tag stored separately. If you are querying an inventory system rather than reading manifests, confirm you are reading the tag, or you will compare a version range against a digest and get silence.

### 2c. Sandboxes

If the org uses Docker Sandboxes, check for `sbx` below `0.38.0` — the `sbx cp` copy-out path shares the flaw.

**Verdict for a host/runner = vulnerable if 2a or 2b puts it below the fixed version AND Phase 1 shows it copies out of containers it does not fully control.**

---

## Phase 3 — The Go Module Surface (expect false positives here)

SCA will flag `github.com/moby/go-archive < 0.3.0` in `go.mod`. Almost always this is **not** exposure, and treating it as exposure will burn your remediation budget on the wrong thing.

```bash
# Where is it declared, and is it direct or indirect?
gh search code "moby/go-archive" --owner "$ORG" --json repository,path -L 100 2>/dev/null | \
  python3 -c "import json,sys; [print(i['repository']['nameWithOwner'],'|',i['path']) for i in json.load(sys.stdin)]" | sort -u

# In a checkout — the "// indirect" marker is the whole question
grep -n "moby/go-archive" go.mod
```

Classify:

An `// indirect` marker is **a hint to triage, not a verdict.** The parents split into two very different buckets, and collapsing them is how a real call site gets waved off as a scanner artifact.

**Bucket A — transitively vendored, extraction never reached.** `go mod why github.com/moby/go-archive` lands on an OpenTelemetry Collector distribution build (`otelcol`, the `docker_stats` receiver) or Grafana Alloy: go-archive arrives inside a large vendored tree and the untar functions are not on any code path your service executes. **Version-true, exposure-false.** Bump opportunistically; do not page anyone.

`testcontainers-go` also belongs here, despite appearances. It requires go-archive **directly** in its root `go.mod` (its `modules/*/go.mod` carry it `// indirect`), but it uses it for the build-context / copy-*in* side. Its copy-out helper `CopyFileFromContainer` calls `client.CopyFromContainer` and then extracts with **stdlib `archive/tar`** — verified against `docker.go` on 2026-08-19. Its copy-out is not the vulnerable path. Bump it; don't hunt call sites that cannot be reached.

**Bucket B — the parent hands you a raw container tar stream.** `go mod why` lands on `moby/moby/client` or the older `docker/docker/client`. Their `CopyFromContainer` returns the archive stream and performs **no extraction** — your code decides what untars it, and that choice decides exposure. Do not dismiss these on the `// indirect` marker.

```bash
# Who consumes a container archive stream?
#   current:  moby/moby/client  -> CopyFromContainer(ctx, id, CopyFromContainerOptions) (CopyFromContainerResult, error), stream in .Content
#   pre-v28:  docker/docker/client -> CopyFromContainer(ctx, id, srcPath) (io.ReadCloser, container.PathStat, error)
# Either way the client does NO extraction — it hands back a stream.
grep -rnE "CopyFromContainer" --include="*.go" .

# What extracts it? These are the PACKAGE-LEVEL go-archive entry points = the vulnerable path.
grep -rnE "archive\.(Untar|UntarUncompressed|Unpack|UnpackLayer|ApplyLayer|ApplyUncompressedLayer|CopyTo|CopyResource|PrepareArchiveCopy)\(" \
  --include="*.go" .

# Archiver METHODS reach the same code but never match an "archive." prefix —
# CopyWithTar / CopyFileWithTar / UntarPath / TarUntar are methods on *Archiver.
grep -rnE "(NewDefaultArchiver|\.(CopyWithTar|CopyFileWithTar|UntarPath|TarUntar)\()" --include="*.go" .

# stdlib extraction = not this CVE (but review it on its own merits).
grep -rnE "tar\.NewReader" --include="*.go" .
```

**Positive control for these greps:** run `grep -rnE "archive\.(Tar|TarWithOptions)\(" --include="*.go" .` first. If a repo uses go-archive at all it almost certainly tars *somewhere*, so a zero result there means your grep or your `--include` is wrong, not that you're clean.

A go-archive extraction whose source container is built from untrusted content is the CLI case — treat it as real exposure, not a false positive. An extraction via stdlib `archive/tar`, Python `tarfile`, or Node `tar` is **not vulnerable to this CVE**; those libraries have their own path-traversal history and need their own review, so a clean result here is not a clean result there.

- **No `// indirect` marker** (a direct requirement) → run the same call-site greps above. A hit that extracts an archive from an untrusted source needs the bump.
- Already at `v0.3.0`+ → safe.

---

## Phase 4 — Look for Evidence It Already Happened

There is no IOC list. Look for tamper evidence on hosts that (a) ran a vulnerable version and (b) copied out of an untrusted container since `$POC_DATE`.

```bash
# Binaries the PoC targets — unexpected mtime is the signal
ls -la --time-style=full-iso /usr/bin/runc /usr/sbin/runc /usr/bin/docker* 2>/dev/null

# Package manager's opinion vs reality (Debian/Ubuntu)
dpkg -V runc containerd.io docker-ce docker-ce-cli 2>/dev/null
# RPM equivalent
rpm -Va runc containerd.io docker-ce docker-ce-cli 2>/dev/null

# User-level persistence on workstations
ls -la --time-style=full-iso ~/.bashrc ~/.zshrc ~/.profile ~/.ssh/config ~/.docker/config.json 2>/dev/null
```

- A package-verification mismatch on `runc`, `containerd`, or the Docker binaries on a host that ran a vulnerable `docker cp` → **treat as compromised.** Rebuild the host; do not attempt surgical cleanup of a root-code-execution primitive.
- Dotfile or `~/.ssh/config` mtime that lands right after a known `docker cp` of an untrusted image → investigate the diff.
- Clean results are weak evidence, not proof. An attacker who got root could have fixed the mtimes. Weight this by whether preconditions 2 and 3 ever actually held on that host.

---

## Phase 5 — Remediation & Hardening

1. **Upgrade to Engine/CLI 29.7.2+** (not 29.7.0 — see Background), Desktop **4.86.0+** (4.87.0 is current as of 2026-08-19), Sandboxes **0.38.0+**. Where the distro package lags, use Docker's own repository. **Expect a line jump, not a patch bump** — there is no fix on 29.6 or below, so anything on 26.x/27.x/28.x/29.3–29.6 moves version lines. Treat that as a scheduled change with testing, not a same-day patch, and use the Phase 1 copy-out inventory to prioritise which runners jump first.
2. **Rebuild every dind/CLI image pinned below 29.7.2** — this is what replaces the vulnerable client and daemon **inside the image**, which step 1 cannot reach. A pipeline running `docker:27.5.1-dind` runs a vulnerable Docker regardless of the host's version, because the image carries its own. Rebuild against a current tag with `--no-cache` and re-pull by **digest**: a floating tag pulled months ago still resolves from cache to that same old image, so a rebuild can hand you the vulnerable binary back without any error.
3. **Bump `github.com/moby/go-archive` to `v0.3.0`+** in any Go module that requires it directly — this closes a path Docker is not part of. The flaw lives in the library's own extraction functions, so code that untars an archive from an untrusted source through them is vulnerable independently of any Docker version. For `// indirect` entries, fold it into routine dependency maintenance and triage per Phase 3 rather than treating it as an incident.
4. **Where you cannot upgrade yet — stop the container before copying.** This is the highest-value workaround and it applies directly to everything stuck below 29.7. Docker supports copying from a **stopped** container, and a stopped container has no live process to run the rename race, so the producer half of the chain cannot fire. Imperva's own mitigation list leads with this. Caveat from the same source: it blocks *this* race but does not make extraction safe — any archive from an untrusted source is still hostile input.
5. **Other interim controls**, also from the vendor write-up: avoid copying from running, untrusted, or compromised containers onto a sensitive client; avoid `sudo docker cp` and root-run copy automation; run the CLI with the least privilege the workflow needs; and retrieve data from suspicious containers using a disposable account, VM, or similarly isolated environment.
6. **Stop copying out of containers you do not control.** Where a pipeline must retrieve artifacts from a third-party or PR-supplied image, prefer a bind-mounted output directory the job owns over `docker cp`, and never run the copy under `sudo`.
7. **Treat `sudo docker cp` as a privileged operation** in runbooks and CI. The difference between "attacker rewrote a file I own" and "attacker replaced `/usr/bin/runc`" is only that `sudo`.
8. **If Phase 4 found tamper evidence:** rebuild the host from a known-good image, then rotate every credential that lived on it — SSH keys, cloud credentials, registry credentials, CI tokens, signing keys — since root on the runner reads all of them.

---

## Evidence Table

Record one row per host, runner, or image:

| Field | Value |
|---|---|
| Host / runner / image | |
| Docker client version | |
| Docker server version | |
| Desktop version (if applicable) | |
| Version safe? (≥29.7.0) | yes / no / unknown |
| Copies out of untrusted containers? | yes / no / unknown |
| Runs the copy as root/`sudo`? | yes / no |
| Exploitable now? | yes / no |
| `go-archive` in `go.mod`? | direct / indirect / absent |
| Tamper evidence (Phase 4)? | list |
| Upgraded to 29.7.2+? | yes / no |
| Credentials rotated? | yes / no / n/a |

---

## Pitfalls & Fixes

- **The `// indirect` OpenTelemetry pattern is the dominant false positive.** In practice, most `go-archive` hits sit in `generated/otelcol-*/go.mod`, `alloy/go.mod`, `packages/otel-collector/go.mod`, `otel-podman/dist/go.mod`, or `tests/e2e/go.mod` — OTel Collector builds and `testcontainers-go`. Version-true, exposure-false. Run `go mod why` before escalating anything from `go.mod`.
- **…but `// indirect` is not a clearance.** The marker only tells you *you* didn't ask for it. If the parent is `moby/moby/client` / `docker/docker/client`, that parent hands your code a raw container tar stream and your own extractor decides exposure — check the call sites (Phase 3, bucket B) rather than closing it on the marker. Bucketing every indirect hit as noise is the mirror-image mistake of treating every one as exposure.
- **`testcontainers-go` looks like bucket B and isn't.** It requires go-archive *directly* and exposes a copy-out helper, which reads as a live call site. But `CopyFileFromContainer` extracts with stdlib `archive/tar`, so it is not the vulnerable path. Verified against `docker.go` on 2026-08-19 — re-verify if testcontainers changes its extraction.
- **"Operator" does not mean "human."** The preconditions read like they need someone at a shell. The common shape is an unattended CI step copying test results out of a PR-built image — no human, worse blast radius. Grep the automation, not just the interactive history.
- **`gh search code` swallows colons.** `docker:dind` and `docker:cli` return zero on orgs that plainly run dind — proven on the 2026-08-19 dry-run. Use `FROM docker:`, `docker-dind`, and bare `dind`, then corroborate in a checkout.
- **`dind` / `docker-dind` matches documentation and identifiers.** The dry-run's hits included two `CLAUDE.md` files and two source files handling MCP identifiers (`mcp_identifier.py`, `mcp.go`) that merely contain the string. The real hits were Helm `values.yaml` files under `runner-scale-set` — self-hosted runner config. Classify by path, not by hit count.
- **A shared GitHub Action doing `docker cp` is the highest-value hit shape.** The dry-run's three `docker cp` hits included `common-workflows/.github/actions/common_container/action.yaml` — a composite action that many repos call. One vulnerable shared action multiplies across every consumer, so trace callers (`gh search code "common_container" --owner "$ORG"`) rather than treating it as one finding.
- **Half of go-archive's copy surface is methods, not package functions.** `CopyWithTar`, `CopyFileWithTar`, `UntarPath`, and `TarUntar` hang off `*Archiver` (`NewDefaultArchiver()`), so an `archive\.CopyWithTar` pattern matches nothing while the code is plainly using it. An earlier draft of this playbook shipped exactly that dead name and omitted `Unpack`, `UnpackLayer`, `ApplyUncompressedLayer`, `CopyResource`, and `PrepareArchiveCopy` — the last being what the CLI's own copy-out path calls. Verified against `moby/go-archive` main on 2026-08-19. Run the positive control in Phase 3 before believing a clean result.
- **Image "version" is often a digest, not a tag.** Inventory systems and registry APIs commonly store `sha256:…` as the version and keep the readable tag (`27.5.1-dind`) in a separate field. A version-range check against a digest silently matches nothing — which looks exactly like "no exposure."
- **29.7.0 vs 29.7.2.** 29.7.0 is the security boundary; recommending it alone hands the customer three regressions (hardlink pulls, `/var/run` → `/run` symlink copies, permissions on old kernels). Recommend 29.7.2. Conversely, do not tell people 29.7.0 is vulnerable — it is not.
- **Distro packages look current and are not.** `apt`/`yum` Docker frequently sits several minor versions behind. "We're on the latest package" is not "we're ≥ 29.7.0" — read `docker version`.
- **`docker cp` direction matters.** Half the grep hits will be copy-*in* (`docker cp ./x container:/y`), which this CVE does not touch. Read the argument order before counting a hit.
- **A `docker cp` in documentation is not an execution site.** README examples and comments match the same grep as pipeline steps.
- **A clean SCA report predating 2026-08-18 proves nothing.** The GHSA only reached the global advisory database that day; every OSV/GHSA-based scanner was silent on this for the eight weeks a public exploit existed.
- **`dpkg -V` / `rpm -Va` error on packages that are not installed.** The Phase 4 commands list several package names because the Docker and runc packaging differs by install method (`docker-ce` vs distro `docker.io`, `runc` standalone vs bundled in `containerd.io`). A "package not installed" error is not a finding — read the output, and re-run against only the names `dpkg -l` / `rpm -qa` shows present.
- **Not yet dry-run.** The commands here have not been validated against a live org or host. Run Phase 1 read-only against a real org first, and Phase 4 against one known-clean host to establish what a clean baseline looks like, then fold whatever false positives surface back into this section.

## References

- GitHub Advisory (GHSA-hfg8-hc9c-6c3h): <https://github.com/advisories/GHSA-hfg8-hc9c-6c3h>
- Maintainer advisory: <https://github.com/moby/go-archive/security/advisories/GHSA-hfg8-hc9c-6c3h>
- Imperva Red Team writeup (mechanism, timeline, attribution): <https://www.imperva.com/blog/copyescape-taking-over-docker-hosts-with-docker-cp/>
- GitLab advisory database: <https://advisories.gitlab.com/golang/github.com/moby/go-archive/CVE-2026-17106/>
- Public issue on the Docker repo: <https://github.com/moby/moby/issues/52948>
- Docker Engine 29.7.0 (security fix) / 29.7.2 (recommended): <https://github.com/moby/moby/releases/tag/docker-v29.7.0> · <https://github.com/moby/moby/releases/tag/docker-v29.7.2>
- `go-archive` releases (v0.3.0 fix, v0.3.2 / v0.3.3 regression repairs): <https://github.com/moby/go-archive/releases>
- Docker Desktop 4.86.0 release notes: <https://docs.docker.com/desktop/release-notes/#4860>
- NHS England cyber alert CC-4828: <https://digital.nhs.uk/cyber-alerts/2026/cc-4828>
