# crates.io Maintainer Compromise (arrayref / internment / append-only-vec, August 2026) — Investigation Playbook

Playbook for investigating whether a GitHub org was affected by the **20 August 2026 crates.io compromise**, in which a hijacked maintainer account republished three widely-used Rust crates with a malicious dependency that executes at **build time** and installs a persistent cross-platform implant.

> **CI/CD platform note:** This playbook targets GitHub Actions. For other platforms (GitLab CI, Jenkins, CircleCI, Buildkite, Azure DevOps), adapt the log-collection commands — the investigation logic is unchanged: find references to the affected crates, collect build logs from the exposure window, search for the dropper crate and the IOCs, and verify lock-file protection.

> **Trigger model: build time, not run time.** The payload lives in a `build.rs` build script in the `proc-macro1` dropper crate. It executes during `cargo build`, `cargo check` and `cargo test` — as part of dependency *compilation*, before any application code runs. Consequences that shape this entire investigation:
>
> - **A lock-file match alone is not compromise.** A repo can pin a poisoned version and never have been exposed, if no build ran during the window.
> - **A build during the window with no lock-file match is still worth checking.** Fresh resolution could have pulled the poisoned version without it ever being committed.
> - `cargo fetch` and `cargo tree` do **not** run build scripts. `cargo build`, `cargo check`, `cargo test`, `cargo clippy`, `cargo doc` and `cargo install` do.

> **⚠️ `cargo audit` does find this — but only on an untouched lock file.** All three poisoned versions carry RustSec advisories (RUSTSEC-2026-0260 / -0262 / -0266) merged into `rustsec/advisory-db`. `cargo audit` matches `Cargo.lock` against that database and never contacts the registry, so deletion from crates.io is irrelevant. Run `cargo audit fetch` first — a database cached before 2026-08-21 will miss them.
>
> The real trap is that the evidence is perishable. Because the versions were **deleted** rather than yanked, any rebuild or `cargo update` after the window silently re-resolves the lock file to a clean version, after which `cargo audit` reports clean on a host that was genuinely exposed. Read a clean run as *"not currently pinned"*, never as *"not exposed"*. The Cargo cache (Phase 3) is the durable evidence.

---

## Incident Details

On **20 August 2026**, an attacker controlling a legitimate crates.io maintainer account published poisoned releases of three real crates, each adding a dependency on **`proc-macro1`** — an attacker-owned typosquat of `proc-macro2` whose `build.rs` downloads and runs a payload.

**The yank trick.** Within 40 seconds of publishing `arrayref` 0.3.10, the compromised account yanked 0.3.9 back through 0.3.5. That left the malicious release as the only version Cargo would resolve without printing a yank warning — Cargo's own safety signal was turned into a funnel.

**Blast radius.** `arrayref` had roughly **245M all-time downloads, some 54M in the preceding 90 days, and over 400 direct dependents.** It is reached transitively via `winit` → `sctk-adwaita` → `tiny-skia` → `arrayref`, covering most of the Rust GUI ecosystem (`egui`/`eframe`, `iced`). `blake3`, `blake2b_simd` and `blake2s_simd` dropped the dependency after the incident. Confirmed downloads of the malicious `arrayref` were roughly **2,285** — under 10% of normal volume for the period.

### Advisories

- **RUSTSEC-2026-0260** — `arrayref` 0.3.10, *malicious code*: https://rustsec.org/advisories/RUSTSEC-2026-0260.html
- **RUSTSEC-2026-0266** — `internment` 0.8.7, *malicious code*: https://rustsec.org/advisories/RUSTSEC-2026-0266.html
- **RUSTSEC-2026-0262** — `append-only-vec` 0.1.9, *malicious code*: https://rustsec.org/advisories/RUSTSEC-2026-0262.html
- **Rust Security Response Team advisory:** https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/
- **Tracking issue:** https://github.com/rustsec/advisory-db/issues/3161
- **No CVE was assigned.**

> **What the advisories do and do not claim.** RUSTSEC-2026-0260 records 2,285 downloads of the malicious `arrayref` — under 10% of the crate's traffic across all versions — and notes that "most users had older versions of `arrayref` in their lockfiles." That is a statement of *limited* exposure, not of *no* exposure: the version was demonstrably pulled, and a download only fails to become a compromise where a lock file pinned an older version and the build respected it. Neither the `internment` nor the `append-only-vec` advisory makes any exposure assessment. Do not treat "RustSec found limited impact" as a reason to skip Phase 2 — it is a statement about the ecosystem in aggregate, not about this customer.

### Affected crates

**Hijacked legitimate crates** — one poisoned version each, since deleted from crates.io:

| Crate | Malicious version | Safe versions |
|---|---|---|
| `arrayref` | **0.3.10** | 0.3.9 and earlier |
| `internment` | **0.8.7** | 0.8.6 and earlier |
| `append-only-vec` | **0.1.9** | 0.1.8 and earlier |

The maliciously-yanked clean versions (`arrayref` 0.3.5–0.3.9) have been **unyanked** by the Rust Security Response Team and are safe to use.

**Attacker-owned crates — every version malicious**, all deleted:

`proc-macro1`, `proc-macro-en`, `aovine`, `arone`, `aronenao`, `tinymember`

`proc-macro1` **1.0.107** carried the payload. **1.0.106** was a verbatim clean copy of `proc-macro2` published five hours earlier as staging — not itself malicious, but its presence is still an indicator that the dropper was being set up against your build.

```bash
export AFFECTED_CRATES='arrayref internment append-only-vec'
export DROPPER_CRATES='proc-macro1 proc-macro-en aovine aronenao arone tinymember'
export MALICIOUS_VERSIONS_RE='arrayref v?0\.3\.10|internment v?0\.8\.7|append-only-vec v?0\.1\.9'
export DROPPER_RE='proc-macro1|proc-macro-en|aovine|aronenao|arone|tinymember'
```

**These four are referenced by the commands in every phase below — set them once in each shell you work from.** They are also the only place to edit the crate list: change it here and the whole playbook follows.

> **`arone` is a substring of `aronenao`.** Order the alternation with the longer name first (as above) or you will mis-attribute hits. `arone` is also short enough to appear inside unrelated words — always review its hits in context rather than counting them.

> **Pair each crate with *its own* malicious version — never cross-match.** `MALICIOUS_VERSIONS_RE` binds each name to its own bad version for exactly this reason. A check that collects crate names into one set and bad versions into another will fire on clean code: **`internment` has a real, legitimate release `0.3.10`**, which is `arrayref`'s malicious version string. A lock file holding `internment 0.3.10` and `arrayref 0.3.9` is entirely clean and an unpaired check calls it poisoned.

### Exposure window

All times UTC on **2026-08-20**.

| Event | Time |
|---|---|
| Malicious `proc-macro1` 1.0.107 published | 07:11:15 |
| `arrayref` 0.3.10 published | 07:15:00 |
| `arrayref` 0.3.9 → 0.3.5 yanked (forcing upgrade) | 07:15:24 – 07:15:40 |
| `internment` 0.8.7 published | 07:34:07 |
| `append-only-vec` 0.1.9 published | 07:37:49 |
| `arrayref` 0.3.10 deleted | 08:41:40 |
| `internment` 0.8.7 deleted | 09:04:11 |
| `append-only-vec` 0.1.9 deleted | 09:25:24 |

**Recommended scan window (padded):** `2026-08-20T07:00:00Z` to `2026-08-20T10:00:00Z`.

### Indicators of compromise

| IOC | Value | Where it shows up |
|---|---|---|
| Payload host | `23.254.165.112:9089` | Build logs, network logs |
| Primary C2 | `23.254.165.112:443` | Network logs |
| Secondary C2 | `23.254.167.107` | Network logs |
| Stage-2 C2 (infected Linux hosts) | `23.254.167.216` | Network logs |
| Hostname | `hwsrv-798836.hostwindsdns.com` | DNS logs |
| C2 request path | `/49890878` | Proxy logs |
| Actor netblocks | `23.254.165.0/24`, `23.254.167.0/24`, `23.254.164.0/23` (Hostwinds) | Network logs |
| DGA fallback domains (20–24 Aug) | `rasGThauFD`, `feVVKIiEiU`, `phrpjTNckF`, `PrOkXLgfjW`, `ackeoTaWtl`, `GAFWVCMAja`, `RNSsddnEgK`, `pfHlVOqEeg`, `aBEcOrkups`, `epOdIaTMaM` — each `.com` | DNS logs |
| TLS issuer (campaign link) | `WIN-A6QF8AHPQH1\Administrator@WIN-A6QF8AHPQH1` | TLS inspection |
| Dropped file (Unix/macOS) | `/tmp/rust-setup` | Runner and workstation filesystems |
| Dropped files (Windows) | `%TEMP%\rust-setup.ps1`, `%TEMP%\rust-setup.ps1.cfg`, `%TEMP%\rust-setup-launch.vbs`, `%TEMP%\ps-<GUID>.ps1` | Runner and workstation filesystems |
| Windows persistence script | `%APPDATA%\<operator-chosen folder>\<name>.ps1` | Workstations, persistent runners |
| Downloaded binaries | `rust-crate_0.1.0` (Linux x86-64) … `_0.2.0` (Windows) … `_0.3.0` (macOS x86-64) … `_0.4.0` (macOS ARM64) | Workstations, persistent runners |
| SHA-256 | `25ad700976873c76af785cb99b33c48db7df8b81f21d1e9e06b3676b9a9373ae` | `arrayref-0.3.10.crate` |
| SHA-256 | `61198155da51b838772eecf5bfaac6cbc4dcc388dccc56658fc28a8e831b34d4` | `proc-macro1-1.0.107.crate` |
| SHA-256 | `b5c1b5b0763a8809a644a8f92224653f0aca623a98eecc714d27f74b80fbe436` | `proc-macro1-1.0.106.crate` |
| SHA-256 | `cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568` | Shared malicious `build.rs` — `proc-macro1` 1.0.107 **and** `proc-macro-en` 1.0.10 |
| SHA-256 (stage 2) | `408ef22050ffc5a67e005802809026b29f297a8019f8fda91a2afa8e877ba434` | Implant, Linux x86-64 |
| SHA-256 (stage 2) | `492f2ab86f8d8911adc79c10ec1541704f5311d207d9d799b0d2a57fcc6a4391` | Implant, Windows x86-64 |
| SHA-256 (stage 2) | `c9561a3b00a0fa38b7772675d987f84bd429c55cd024fc08a98245c2d1632848` | Implant, macOS x86-64 |
| SHA-256 (stage 2) | `74d3447e7cf99c99ea01a16332ec27432dfb0f491e10e67cd118065a60483306` | Implant, macOS ARM64 |
| Stage-2 directories — *lower confidence* | `$HOME/.config/AzureKits`, `$HOME/.config/ServiceKit` | Workstations, persistent runners |
| Stage-2 binaries — *lower confidence* | `MonoService`, `MonoXpc` | Workstations, persistent runners |
| Impersonator account | crates.io user `dtolney` (id 438608) | Registry metadata |
| Compromised owner | `droundy` (user 2402, David Roundy) | Registry metadata |
| Forged email | `rchaitm@gmail.com` | Registry metadata |
| Build-log signature | `Compiling proc-macro1`, `Downloaded proc-macro1` | CI logs |

> **Confidence split in the stage-2 rows.** All four implant binaries were recovered and analysed, so the stage-2 **hashes** are firm. The stage-2 **filesystem names** (`AzureKits`, `ServiceKit`, `MonoService`, `MonoXpc`) are not: they come from reports by infected developers rather than from the recovered binaries, and do not appear in the published payload analysis. A variant may drop different names, so a clean result on those four names clears nothing — hash any suspect binary instead.

> **The C2 is not baked into the implant.** The dropper passes the C2 address to the payload as a runtime argument, so the operator can rotate infrastructure without rebuilding anything, and the implant falls back to the date-derived DGA domains when the primary is unreachable. Blocking the listed addresses is containment; it is not detection. Search the DGA domains too (Phase 4).

**Attribution.** Wiz reports substantial infrastructure overlap with campaigns previously attributed to North Korean actors — the Mastra npm compromise (Sapphire Sleet, per Microsoft) and the axios npm compromise (MIDNIGHT NEPTUNE / UNC1069, per Google GTIG). No named actor is confirmed for the crates.io incident itself. Treat this as context for prioritisation, not as a finding.

### What IS affected

- Any host that ran `cargo build`, `cargo check`, `cargo test`, `cargo clippy`, `cargo doc` or `cargo install` during the window **and** resolved one of the poisoned versions — directly or transitively.
- CI runners and build hosts, including ephemeral ones. Ephemeral runners lose the persistence artifact but **not** the exfiltrated secrets.
- Self-hosted or persistent runners — these keep the implant across jobs and are the highest-priority hosts in this investigation.
- Container images built during the window that ran a `cargo` build step.
- Developer workstations that built Rust code during the window — see `workstation-playbook.md`.
- Any host with the persistence artifact present, regardless of whether the crate has since been removed.

### What is NOT affected

- Builds using `cargo build --locked` or `--offline` against a `Cargo.lock` committed **before 2026-08-20T07:15:00Z** that pins `arrayref` ≤ 0.3.9 / `internment` ≤ 0.8.6 / `append-only-vec` ≤ 0.1.8. The poisoned version is never resolved.
- Repos that merely *name* an affected crate in source, docs, or a comment without a build having run in the window.
- `cargo fetch` and `cargo tree` runs — these download and resolve but do **not** execute build scripts.
- Builds that ran entirely outside 07:00–10:00 UTC on 2026-08-20.
- Vendored dependency trees (`cargo vendor` committed to the repo) whose vendored `arrayref` predates the window — resolution never reaches the registry.
- Pre-built container images not rebuilt during the window.

### Lock file protection

`Cargo.lock` **does** protect, if used correctly:

- `cargo build --locked` fails rather than silently updating the lock file. `--offline` refuses network resolution entirely.
- A lock file committed before the window pinning a safe version means the poisoned version is never fetched.

`Cargo.lock` does **NOT** protect if:

- No lock file is committed. **This is the common case for library crates** — Cargo's own guidance has historically been that libraries should not commit `Cargo.lock`, so a large fraction of Rust *libraries* build unlocked by default. Do not assume a missing lock file is a misconfiguration.
- CI runs plain `cargo build` (without `--locked`) and the lock file is absent or out of date.
- `cargo update` ran during the window.
- A dependency-bump PR (Dependabot, Renovate) merged during the window.
- The manifest uses a caret range — `arrayref = "0.3"` and `arrayref = "^0.3.9"` both permit 0.3.10.

---

## Setup

```bash
export ORG="<your-github-org>"
export SINCE="2026-08-20T07:00:00Z"
export UNTIL="2026-08-20T10:00:00Z"
export LOG_DIR="/tmp/supply-chain-scan-arrayref"
mkdir -p "$LOG_DIR"
```

**Log caching:** if `$LOG_DIR` already holds logs from a previous run, reuse them — skip the download step.

**Write to files, not context:** write structured evidence (CSV) into `$LOG_DIR` as you go rather than accumulating findings in conversation.

**Rate limits:**

```bash
gh api /rate_limit --jq '.resources.core | "\(.remaining)/\(.limit) core remaining"'
gh api /rate_limit --jq '.resources.code_search | "code-search: \(.remaining)/\(.limit)"'
```

Code search ~30 req/min; REST 5,000 req/hr. Use `xargs -P 10` for log downloads.

---

## Phase 1: Repo Analysis

**Goal:** for every repo that builds Rust, establish what is declared, what is locked, and what the CI build command is. Window-agnostic — this describes posture, not exposure.

### 1. Find every Rust repo and every reference to an affected crate

```bash
# All repos containing a Cargo.toml — the full Rust surface, including transitive-only consumers
gh api "search/code?q=filename:Cargo.toml+org:${ORG}&per_page=100" \
  --jq '.items[] | "\(.repository.full_name)\t\(.path)"' | sort -u > "$LOG_DIR/rust-repos.tsv"
wc -l "$LOG_DIR/rust-repos.tsv"

# Direct references to affected + dropper crates
for crate in $AFFECTED_CRATES $DROPPER_CRATES; do
  echo "=== $crate ==="
  gh api "search/code?q=${crate}+org:${ORG}&per_page=100" \
    --jq '.items[] | "'"$crate"'\t\(.repository.full_name)\t\(.path)"' 2>/dev/null
  sleep 2   # code-search rate limit
done | sort -u > "$LOG_DIR/refs.tsv"
wc -l "$LOG_DIR/refs.tsv"
```

> **Positive control — run this before trusting any zero-hit result.** A broken query and a clean org look identical. Search for a crate that is certainly present if the org writes Rust at all:
>
> ```bash
> gh api "search/code?q=serde+org:${ORG}&per_page=1" --jq '.total_count'
> ```
>
> If this returns `0` while `rust-repos.tsv` is non-empty, your query or auth is broken — fix that before concluding anything from the crate searches above.

> **Faster for orgs over ~50 repos:** shallow-clone and grep locally.
>
> ```bash
> mkdir -p "$LOG_DIR/clones" && cd "$LOG_DIR/clones"
> gh repo list "$ORG" --no-archived --limit 1000 --json nameWithOwner --jq '.[].nameWithOwner' | \
>   xargs -P 10 -I {} bash -c 'git clone --depth 1 --filter=blob:none "git@github.com:{}.git" 2>/dev/null || echo "FAIL: {}"'
>
> grep -rEn --include='Cargo.toml' --include='Cargo.lock' \
>   'arrayref|internment|append-only-vec|proc-macro1|proc-macro-en|aovine|aronenao|arone|tinymember' . \
>   > "$LOG_DIR/refs-from-local-clone.txt"
> wc -l "$LOG_DIR/refs-from-local-clone.txt"
> ```

### 2. Classify each reference

| File pattern | Category | Risk |
|---|---|---|
| `Cargo.lock` | Lock file | **CRITICAL** — check the pinned version against the malicious list |
| `Cargo.toml` | Manifest | **HIGH** — check whether the range permits the malicious version |
| `Dockerfile` | Container build | **HIGH** if it runs a `cargo` build step |
| `.github/workflows/*.yml` | CI workflow | **CHECK** — does it build Rust, and with `--locked`? |
| `vendor/**` | Vendored deps | **CHECK** — vendored version, and when it was vendored |
| `*.rs` | Source code | **NOT AFFECTED** — a `use arrayref::...` is not a build |
| `*.md`, `README*` | Docs | **NOT AFFECTED** |

### 3. Extract version data per repo

```bash
REPO="<repo>"

# Cargo.lock — resolved versions of the affected crates
gh api "repos/${ORG}/${REPO}/contents/Cargo.lock" --jq '.content' 2>/dev/null | base64 -d | \
  grep -A1 -E '^name = "(arrayref|internment|append-only-vec|proc-macro1|proc-macro-en|aovine|aronenao|arone|tinymember)"'

# Cargo.toml — declared ranges
gh api "repos/${ORG}/${REPO}/contents/Cargo.toml" --jq '.content' 2>/dev/null | base64 -d | \
  grep -nE 'arrayref|internment|append-only-vec'

# CI build commands — is --locked used?
gh api "repos/${ORG}/${REPO}/contents/.github/workflows" --jq '.[].path' 2>/dev/null | while read -r wf; do
  echo "--- $wf"
  gh api "repos/${ORG}/${REPO}/contents/${wf}" --jq '.content' | base64 -d | \
    grep -nE 'cargo (build|check|test|clippy|doc|install|update)'
done

# Dockerfile build steps
gh api "repos/${ORG}/${REPO}/contents/Dockerfile" --jq '.content' 2>/dev/null | base64 -d | \
  grep -nE 'RUN.*cargo.*(build|check|test|install)'
```

> **`Cargo.lock` stores name and version on separate lines** in a `[[package]]` block — `name = "arrayref"` then `version = "0.3.10"`. A single-line grep for `arrayref.*0\.3\.10` finds **nothing** in a real lock file. Use `grep -A1` on the name line (as above), or search for the version line and check the preceding line.

### 4. Write the repo evidence table

Write `$LOG_DIR/evidence-repos.csv`:

```
repo,path,source_type,manifest_range,range_allows_malicious,has_lockfile,lockfile_version,lock_protects,build_command,uses_locked_flag,can_be_compromised
```

| Column | What to write |
|---|---|
| `repo` | Repo name, no org prefix |
| `path` | Full path of the reference |
| `source_type` | `manifest` / `lockfile` / `ci-workflow` / `dockerfile` / `vendored` |
| `manifest_range` | Exact range as written (`"0.3"`, `"^0.3.9"`, `"=0.3.9"`). `transitive` if not declared directly |
| `range_allows_malicious` | `yes (allows 0.3.10)` or `no (pinned =0.3.9)` |
| `has_lockfile` | `yes` / `no`. A missing lock file on a library crate is normal, not necessarily a misconfiguration |
| `lockfile_version` | Exact pinned version, or `none` |
| `lock_protects` | `yes` if the pinned version is not malicious; `no` if it is; `n/a (no lockfile)` |
| `build_command` | Exact command from CI (`cargo build --locked --release`, `cargo test`, …) |
| `uses_locked_flag` | `yes` / `no` / `n/a (no rust build in CI)` |
| `can_be_compromised` | `no` if lock protects AND `--locked` is used; `yes` otherwise |

### Cargo command cheat sheet

| Command | Runs build scripts? | Respects lock file? |
|---|---|---|
| `cargo build --locked` / `--offline` | Yes | **Yes** — fails rather than updating |
| `cargo build` (no flag) | Yes | Partially — updates the lock file if stale or absent |
| `cargo check` / `cargo test` / `cargo clippy` / `cargo doc` | **Yes** | Same as `cargo build` |
| `cargo install <crate>` | Yes | **No** — resolves fresh unless `--locked` |
| `cargo update` | No (resolution only) | **No** — rewrites the lock file |
| `cargo fetch` | **No** | Respects lock if present |
| `cargo tree` | **No** | Respects lock if present |

**Key insight:** a repo with a pre-window `Cargo.lock` pinning safe versions **and** `--locked` in CI cannot have been compromised through CI. That combination closes the investigation for that repo quickly — bank the time for the workstation sweep.

---

## Phase 2: CI Build Log Analysis

**Why this phase is decisive:** Phase 1 finds repos that *name* an affected crate. `arrayref` is most often pulled in **transitively** (through `tiny-skia`, `blake3`, `winit`), so a repo can be exposed without ever naming it. Only the build logs show what was actually compiled.

### 1. Find runs during the window

```bash
gh api "/orgs/${ORG}/repos" --paginate --jq '.[].name' | while read -r repo; do
  gh api "repos/${ORG}/${repo}/actions/runs?created=${SINCE}..${UNTIL}&per_page=100" \
    --jq ".workflow_runs[] | \"${repo}|\(.id)|\(.created_at)|\(.name)|\(.conclusion)\"" 2>/dev/null
done > "$LOG_DIR/all_runs.txt"

echo "Runs in window: $(wc -l < "$LOG_DIR/all_runs.txt")"
```

The window is only three hours, so on most orgs this is a small set — often small enough to review every run individually.

### 2. Download run logs in parallel

```bash
cat "$LOG_DIR/all_runs.txt" | while IFS='|' read -r repo run_id rest; do
  echo "$repo $run_id"
done | xargs -P 10 -L 1 bash -c \
  'gh run view "$1" --repo "${ORG}/$0" --log > "${LOG_DIR}/run-$1.log" 2>/dev/null && echo "OK: $0 $1" || echo "FAIL: $0 $1"'
```

### 3. Scan logs

```bash
cd "$LOG_DIR"

echo "=== Dropper crate compiled or downloaded (STRONGEST SIGNAL) ==="
grep -rlE '(Compiling|Downloaded|Adding) proc-macro1( |$|v)' run-*.log 2>/dev/null

echo "=== Any dropper crate name ==="
grep -rlE "$DROPPER_RE" run-*.log 2>/dev/null

echo "=== Poisoned versions in resolution output ==="
grep -rlE "$MALICIOUS_VERSIONS_RE" run-*.log 2>/dev/null

echo "=== C2 / payload host ==="
grep -rlE '23\.254\.16[4-7]\.|hwsrv-798836\.hostwindsdns\.com|/49890878' run-*.log 2>/dev/null

echo "=== DGA fallback domains ==="
grep -rlE 'rasGThauFD|feVVKIiEiU|phrpjTNckF|PrOkXLgfjW|ackeoTaWtl|GAFWVCMAja|RNSsddnEgK|pfHlVOqEeg|aBEcOrkups|epOdIaTMaM' run-*.log 2>/dev/null

echo "=== Dropped payload filenames ==="
grep -rlE 'rust-setup|rust-crate_0\.[1-4]\.0|MonoService|MonoXpc|AzureKits|ServiceKit' run-*.log 2>/dev/null

echo "=== Which runs built Rust at all (scoping) ==="
grep -rlE 'cargo (build|check|test|clippy|doc|install)' run-*.log 2>/dev/null
```

> **Positive control for the log corpus.** Before trusting a clean result, confirm the logs actually contain Cargo output:
>
> ```bash
> grep -rlE 'Compiling serde|Compiling libc|Finished .*(dev|release)' run-*.log | wc -l
> ```
>
> Zero hits here on an org that builds Rust means the log download failed or the runs in the window were not Rust builds — not that you are clean.

### 4. Classify hits — real compilation vs noise

**Real exposure indicators:**

- `Compiling proc-macro1 v1.0.107` — definitive. The dropper was compiled, so `build.rs` ran.
- `Downloaded proc-macro1 v1.0.107` followed by any `Compiling` line in the same job.
- `Compiling arrayref v0.3.10` / `internment v0.8.7` / `append-only-vec v0.1.9`.
- `Updating crates.io index` followed by `cargo build` without `--locked` in a job inside the window.
- Any outbound reference to `23.254.165.112` or the Hostwinds ranges.

**False positives — do not count these:**

- `arrayref` appearing in a `cargo tree` or `cargo fetch` step only. Resolution without compilation does not execute `build.rs`.
- Source-code matches in a lint, `grep`, or SAST step's output.
- Branch and PR names such as `chore/bump-arrayref`.
- `Cargo.lock` diff output printed by a dependency-review or `git diff` step.
- Documentation builds that render the crate name as text.
- `arone` matching inside an unrelated word — always inspect the surrounding line.
- **`Blocking waiting for file lock` / `Compiling` lines from a *cached* target directory.** A restored `~/.cargo` or `target/` cache can surface crate names from a build that happened *before* the window. Check the job's own timestamps, not just the crate name.

### 5. Write the CI evidence table

Write `$LOG_DIR/evidence-ci-runs.csv`:

```
repo,run_id,created_at,workflow,runner_type,build_command,used_locked,log_line,dropper_compiled,poisoned_version,iocs_found,ci_compromised
```

| Column | What to write |
|---|---|
| `runner_type` | `github-hosted` / `self-hosted`. **Self-hosted is the priority** — persistence survives there |
| `build_command` | Exact command from the log |
| `used_locked` | `yes` / `no` |
| `log_line` | Line number(s) in `run-<id>.log` |
| `dropper_compiled` | `yes (proc-macro1 v1.0.107)` / `no` |
| `poisoned_version` | e.g. `arrayref 0.3.10`, or `none` |
| `iocs_found` | `yes (which IOC)` / `no` |
| `ci_compromised` | `clean` / `compromised` / `clean (no rust build)` / `inconclusive (logs expired)` |

One row per build-command execution. No blank cells.

> **Expired logs.** GitHub retains Actions logs for 90 days by default. This incident is recent enough that logs should exist — but if a run in the window returns 404, record `inconclusive (logs expired)` rather than `clean`, and fall back to the repo's lock-file state and the runner's own filesystem.

---

## Phase 3: Self-Hosted Runner and Build Host Forensics

**Run this before Phase 4 if the org uses self-hosted runners.** Ephemeral GitHub-hosted runners are destroyed after each job — the secrets they held are exposed, but the implant is gone. A self-hosted or persistent runner keeps the implant, and it is a high-value host.

On each persistent runner that built Rust during the window:

```bash
# Dropped payload files.
# NOTE the -H: on macOS /tmp is a symlink to private/tmp, and find will NOT descend a
# symlinked starting point. Without -H this returns nothing even when the file is there.
find -H /tmp /var/tmp -maxdepth 2 \
  \( -name 'rust-setup*' -o -name 'rust-crate_0.[1-4].0' \) 2>/dev/null

# Stage-2 persistence directories and binaries (lower-confidence names — hash any hit)
find "$HOME/.config" -maxdepth 1 \( -name 'AzureKits' -o -name 'ServiceKit' \) 2>/dev/null
find "$HOME" -maxdepth 4 \( -name 'MonoService' -o -name 'MonoXpc' \) 2>/dev/null

# Linux persistence — systemd USER units created on the day of the incident
systemctl --user list-unit-files --no-pager 2>/dev/null
find "$HOME/.config/systemd/user" /etc/systemd/system /etc/systemd/user \
  -name '*.service' -newermt '2026-08-20' ! -newermt '2026-08-22' 2>/dev/null

# macOS persistence — LaunchAgent (self-hosted macOS runners are in scope)
find -H ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons \
  -newermt '2026-08-20' ! -newermt '2026-08-22' 2>/dev/null
launchctl list 2>/dev/null | grep -viE 'com\.apple\.'

# The malicious .crate file survives registry deletion
find "$HOME/.cargo/registry/cache" -type f \
  \( -name 'arrayref-0.3.10.crate' -o -name 'internment-0.8.7.crate' \
     -o -name 'append-only-vec-0.1.9.crate' -o -name 'proc-macro1-*.crate' \
     -o -name 'proc-macro-en-*.crate' -o -name 'aovine-*.crate' \
     -o -name 'arone-*.crate' -o -name 'aronenao-*.crate' -o -name 'tinymember-*.crate' \) 2>/dev/null

# Verify any hit against the published hashes
#   .crate archives
# 25ad700976873c76af785cb99b33c48db7df8b81f21d1e9e06b3676b9a9373ae  arrayref-0.3.10.crate
# 61198155da51b838772eecf5bfaac6cbc4dcc388dccc56658fc28a8e831b34d4  proc-macro1-1.0.107.crate
# b5c1b5b0763a8809a644a8f92224653f0aca623a98eecc714d27f74b80fbe436  proc-macro1-1.0.106.crate
# cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568  shared malicious build.rs
#   stage-2 implants — hash ANY suspect binary against these, the names vary
# 408ef22050ffc5a67e005802809026b29f297a8019f8fda91a2afa8e877ba434  Linux x86-64
# 492f2ab86f8d8911adc79c10ec1541704f5311d207d9d799b0d2a57fcc6a4391  Windows x86-64
# c9561a3b00a0fa38b7772675d987f84bd429c55cd024fc08a98245c2d1632848  macOS x86-64
# 74d3447e7cf99c99ea01a16332ec27432dfb0f491e10e67cd118065a60483306  macOS ARM64
sha256sum <found-file>   # shasum -a 256 on macOS
```

**Windows self-hosted runners** — run these in PowerShell on the runner:

```powershell
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Format-List
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' | Format-List
Get-ChildItem $env:TEMP -Filter 'rust-setup*' -ErrorAction SilentlyContinue
Get-ChildItem $env:TEMP -Filter 'ps-*.ps1' -ErrorAction SilentlyContinue
Get-ChildItem $env:APPDATA -Recurse -Filter '*.ps1' -Depth 2 -ErrorAction SilentlyContinue |
  Where-Object { $_.CreationTime -gt '2026-08-20' -and $_.CreationTime -lt '2026-08-22' }
```

> **The Cargo cache is the best surviving evidence.** `~/.cargo/registry/cache` retains the downloaded `.crate` archive even though crates.io deleted the version. On a host where build logs have rotated away, this may be the only proof either way.

---

## Phase 4: Network Investigation

Search from **2026-08-20 forward**, not only during the exposure window — the implant persists, so beaconing can begin long after the build.

| IOC | Where to search |
|---|---|
| `23.254.165.112` (ports 9089, 443) | Firewall, proxy, VPC/NSG flow logs |
| `23.254.167.107`, `23.254.167.216` | Flow logs |
| `23.254.165.0/24`, `23.254.167.0/24`, `23.254.164.0/23` | Flow logs — catches rotated addresses in the same netblocks |
| `hwsrv-798836.hostwindsdns.com` | DNS query logs |
| The ten DGA `.com` domains | DNS query logs — **the only way to see a host that failed over off the Hostwinds ranges** |
| HTTP path `/49890878` | Proxy logs |
| TLS to any of the above with a failed/absent chain validation | Proxy, TLS inspection |
| TLS issuer `WIN-A6QF8AHPQH1\Administrator@WIN-A6QF8AHPQH1` | TLS inspection |

**Cloud:** AWS VPC Flow Logs + Route 53 Resolver query logs; GCP VPC Flow Logs + Cloud DNS logs; Azure NSG Flow Logs + DNS Analytics.
**Corporate:** firewall, web proxy, DNS server logs, SIEM.

**Splunk:**
```
index=* (cidrmatch("23.254.164.0/23", dest_ip) OR cidrmatch("23.254.165.0/24", dest_ip)
         OR cidrmatch("23.254.167.0/24", dest_ip))
| stats count by src_ip, dest_ip, dest_port
```
```
index=* (query="rasGThauFD.com" OR query="feVVKIiEiU.com" OR query="phrpjTNckF.com"
         OR query="PrOkXLgfjW.com" OR query="ackeoTaWtl.com" OR query="GAFWVCMAja.com"
         OR query="RNSsddnEgK.com" OR query="pfHlVOqEeg.com" OR query="aBEcOrkups.com"
         OR query="epOdIaTMaM.com" OR query="hwsrv-798836.hostwindsdns.com")
| stats count by src_ip, query
```

**Elastic:**
```
destination.ip : ("23.254.164.0/23" or "23.254.165.0/24" or "23.254.167.0/24")
  or dns.question.name : ("hwsrv-798836.hostwindsdns.com" or "rasGThauFD.com" or
      "feVVKIiEiU.com" or "phrpjTNckF.com" or "PrOkXLgfjW.com" or "ackeoTaWtl.com" or
      "GAFWVCMAja.com" or "RNSsddnEgK.com" or "pfHlVOqEeg.com" or "aBEcOrkups.com" or
      "epOdIaTMaM.com")
```

**AWS CloudWatch Insights:**
```
filter dstAddr like /23\.254\.16[4-7]\./
| stats count(*) as hits by srcAddr, dstAddr, dstPort
```

**Interpreting results:** any successful outbound connection to these addresses means the payload ran and reached its C2 — treat the source host as compromised and rotate every credential it held.

No hits is weaker evidence here than it looks. It is consistent with a clean Phase 1–3 result, but it does not cover hosts outside your network visibility (laptops on home networks, cloud runners with unlogged egress), and it does not cover a host that failed over to a DGA domain unless you searched those too. DNS-log coverage of the ten domains is the difference between "no beaconing" and "no beaconing to the addresses I happened to list".

---

## Phase 5: Impact Assessment

For every run marked `compromised` in `evidence-ci-runs.csv`, enumerate what that job could reach:

- `secrets.*` referenced anywhere in the workflow, including via reusable workflows and composite actions.
- OIDC-issued cloud credentials and their assumed-role permissions.
- `GITHUB_TOKEN` and its `permissions:` scope for that job.
- crates.io publish tokens, container registry credentials, package-registry tokens.
- SSH deploy keys and signing keys mounted into the job.
- Any `.env` or credentials file materialised during the build.

Record one row per compromised run: `run_id, repo, workflow, secrets_reachable, oidc_roles, rotation_status`.

**Treat build-host secrets as exposed the moment `Compiling proc-macro1` appears in a log** — the build script had full access to the job's environment. Do not wait for evidence of exfiltration before rotating.

---

## Phase 6: Present Results

1. **Repo posture** — `evidence-repos.csv`.
2. **CI runs** — `evidence-ci-runs.csv`.
3. **Runner/host forensics** — findings from Phase 3.
4. **Executive summary** — Rust repos in the org; how many built during the window; how many compiled the dropper; whether any persistence artifact was found; which credentials need rotation.

State the verdict plainly. If no Rust build ran between 07:00 and 10:00 UTC on 2026-08-20 and no cached `.crate` file is present, the org was not exposed — say so without hedging.

---

## Phase 7: Hardening and Remediation (User Approval Required)

**Remediation — only where compromise is confirmed:**

1. **Remove persistence first.** Deleting the crate does not remove the `HKCU` Run key, LaunchAgent or systemd *user* service. Remove the persistence entry, then the stage-2 directories (`$HOME/.config/AzureKits`, `$HOME/.config/ServiceKit`) and binaries (`MonoService`, `MonoXpc`), then reboot and re-verify. Because those names are lower-confidence, also hash anything unexpected the implant may have dropped against the four stage-2 hashes.
2. **Rotate every credential** the affected build could reach — see Phase 5. Include crates.io publish tokens: an attacker with those repeats this attack from your namespace.
3. **Rebuild affected container images with `--no-cache`**, then re-push. A poisoned layer is reused silently otherwise.
4. **Clear the Cargo cache** on affected hosts: `rm -rf ~/.cargo/registry/cache ~/.cargo/registry/src` and re-fetch.
5. **Consider full reimaging** for any persistent runner or workstation where the implant was found. Stage 2 *has* been enumerated — it is a command-driven backdoor whose command set includes downloading and running arbitrary further scripts — so what a given host actually received depends on what the operator chose to send it, and that is not recoverable from the binary. Reimaging is the defensible choice for any host with production access.

**Hardening — everywhere `can_be_compromised` = yes:**

1. **Commit `Cargo.lock` and build with `--locked` in CI.** For applications this is unambiguous. For libraries, Cargo's convention is not to commit the lock file — in that case pin in CI with a checked-in lock file used only for the CI job, or accept the exposure consciously rather than by default.
2. **Pin to exact safe versions** where the crate is a direct dependency: `arrayref = "=0.3.9"`, `internment = "=0.8.6"`, `append-only-vec = "=0.1.8"`.
3. **Restrict build-script execution.** Run untrusted builds in a sandbox with no outbound network. Build scripts are arbitrary code executed at compile time — this incident is the canonical demonstration.
4. **Deny egress from build runners by default**, allow-listing only crates.io, the registry index and your artifact store. The payload download fails closed.
5. **Scope `GITHUB_TOKEN` per job** and prefer short-lived OIDC over long-lived secrets in Rust build jobs.
6. **Vendor dependencies** (`cargo vendor`) for high-assurance builds — resolution never touches the registry.

---

## Pitfalls & Fixes

Seed list — grow it from each live run.

1. **A clean `cargo audit` means "not currently pinned", not "not exposed".** The advisories exist and are merged, so `cargo audit` *does* flag a lock file that still pins a poisoned version — run `cargo audit fetch` first, since a pre-2026-08-21 database misses them. But because the versions were deleted rather than yanked, any rebuild after the window rewrites the lock file to a clean version and the run goes green on a host that really was exposed. Use it as a fast positive detector, never as the closing evidence.
2. **`Cargo.lock` splits name and version across two lines.** `grep 'arrayref.*0\.3\.10' Cargo.lock` returns nothing even on a poisoned lock file. Use `grep -A1 '^name = "arrayref"'`.
3. **`arone` is a substring of `aronenao`** and short enough to appear inside unrelated identifiers. Put the longer name first in any alternation and review hits in context.
4. **A lock-file hit is not exposure.** The build script must have *run*. Cross-reference against Phase 2 before calling a repo compromised.
5. **A missing `Cargo.lock` on a library crate is normal.** Cargo's own convention has been not to commit it for libraries. Do not report it as a misconfiguration finding — report it as an unlocked build surface.
6. **`cargo tree` and `cargo fetch` do not execute build scripts.** A job that only resolves is not exposed. Read the actual command, not just the crate name.
7. **Restored Cargo/target caches replay old crate names into fresh logs.** `Compiling arrayref` in a job inside the window may come from a cache restored from a build before it. Check the job's own timestamps.
8. **GitHub Actions log lines are tab-prefixed** (`<workflow>\t<step>\t<timestamp> <content>`). Do not anchor grep patterns with `^`.
9. **`gh search code` caps at 100 results per page and does not paginate cleanly past 1000.** Above ~50 repos, shallow-clone and grep locally.
10. **Ephemeral runners hide the implant but not the breach.** No persistence artifact on a GitHub-hosted runner is expected and proves nothing — the secrets that job held were still reachable by the build script.
11. **AI-agent self-pollution.** If you are running this playbook through an AI coding agent, the agent's own session transcript will contain every IOC string in this file. Exclude the current session before treating any hit in `~/.claude/projects` or an editor's log directory as evidence — see Check 8 in `workstation-playbook.md`. Confirmed on a dry run of this playbook: the raw scan returned exactly one hit, the investigating session's own transcript, and the filter reduced it to zero.

12. **Unmatched shell globs abort under zsh.** On macOS (zsh by default), `ls -d ~/.cargo/registry/cache/*/` fails with `no matches found` instead of returning empty, and `2>/dev/null` does not suppress it because zsh fails before the command runs. A broken command and a clean machine then look identical. Use `find` for every filesystem probe in this investigation — caught on the dry run of Check 1's positive control.

13. **`find /tmp` silently finds nothing on macOS.** `/tmp` is a symlink to `private/tmp`, and `find` does not descend a symlinked starting point. `find /tmp -name 'rust-setup*'` returns empty on a machine where `/private/tmp/rust-setup` exists — the same false-clean as pitfall 12. Always pass `-H` (or target `/private/tmp` directly). Verified by test: `find /tmp` → empty, `find -H /tmp` → the file.

14. **Never cross-match crate names against the bad-version list.** A check that greps the three crate names into one set and the three bad versions into another will fire on clean code, because **`internment` has a real, legitimate `0.3.10` release** — `arrayref`'s malicious version string. Verified by test: a lock file with `internment 0.3.10` + `arrayref 0.3.9` is entirely clean and an unpaired check reports `POISONED VERSION PINNED`. Bind each crate to its own version.

15. **The Actions API `created` range filter does work** — `created=2026-08-20T07:00:00Z..2026-08-20T10:00:00Z` returns only in-window runs (verified against a high-volume public repo: 7 runs in window vs 32,431 total). If you get suspiciously many results, the problem is elsewhere; do not assume the filter was ignored.

---

## Workstation Investigation

Developer machines that built Rust during the window are in scope and need a different procedure — the customer is checking their own machine rather than the org. See **[`workstation-playbook.md`](./workstation-playbook.md)**.

---

## References

- Rust Security Response Team advisory: https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/
- RUSTSEC-2026-0260: https://rustsec.org/advisories/RUSTSEC-2026-0260.html
- RustSec advisory-db tracking issue: https://github.com/rustsec/advisory-db/issues/3161
- StepSecurity analysis: https://www.stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack
- Wiz analysis (DPRK infrastructure overlap): https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
- Socket — all four stage-2 implants recovered and analysed; hashes, persistence, DGA domains: https://socket.dev/blog/popular-rust-crates-compromised
- JFrog — dropper analysis (its own stage-2 retrieval failed on a dead payload URL): https://research.jfrog.com/post/arrayref-proc-macro1-crates-io/
- Aikido — macOS LaunchAgent detail and stage-2 hashes: https://www.aikido.dev/blog/two-popular-rust-crates-arrayref-and-append-only-vec-compromised-in-supply-chain-attack
- Nextron researcher — static analysis of the Windows stage-2 implant: https://gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf
- The Hacker News coverage: https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html
