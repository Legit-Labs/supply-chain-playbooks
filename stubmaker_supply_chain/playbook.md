# StubMaker RubyGems + npm Typosquat Campaign — Investigation Playbook

Playbook for investigating whether a GitHub org and its developers were affected by
the **StubMaker** typosquatting campaign (RubyGems: 15–16 August 2026; npm:
16 August 2026) — 53 malicious packages across two ecosystems delivering a Windows
credential and cryptocurrency stealer.

> **Note for AI agents:** This playbook targets GitHub for org-wide asset discovery.
> For other SCMs (GitLab, Bitbucket, Azure DevOps), adapt the search commands — the
> logic is the same: find every project that references a malicious package name in
> a Ruby or JavaScript manifest or lock file, scan CI logs from the exposure window,
> then pivot to **[workstation-playbook.md](workstation-playbook.md)** for the
> machines that installed them.

> **⚠️ Typosquat, not a hijack.** No legitimate package was compromised, so **there is no
> transitive exposure** — a malicious name only enters a project if somebody typed it. That
> also means **any hit is actionable on its own**: you do not need to prove a version resolved.
>
> **⚠️ Every OS beacons; only Windows gets the payload.** The installer POSTs the detected OS
> to `http://193.70.34.101:20099/vote` on Windows, macOS **and** Linux; only Windows then
> fetches and runs the stealer. **Windows → full compromise. macOS/Linux → beacon only**
> (platform + public IP disclosed, install proven, no credential theft). On those hosts the
> beacon is the *only* artifact, so network logs are the only place to find it.
>
> **⚠️ No second-stage download to catch.** After the single fetch of `main.exe` everything is
> embedded and decrypted in memory. Detection keyed on "payload fetches more payload" never fires.

---

## Incident Details

On **15 August 2026**, OpenSourceMalware discovered malicious gems on RubyGems and
named the campaign **StubMaker**. It grew to **16 gems across three attacker accounts**
within a day. OpenSourceMalware later connected a wave of **37 typosquatted npm
packages** (16 August) to the same actor —
same payload, same C2.

### The "StubMaker" signature

RubyGems runs `extconf.rb` to configure native C extensions during `gem install`.
StubMaker builds nothing: it writes a `Makefile` with empty `all`, `install` and
`clean` targets plus no-op Unix and Windows compiler stand-ins — **`make_stub`** and
**`make_stub.bat`** — that simply return success. The extension phase therefore reports
a clean build with no compiler output while the real work (beacon, Windows loader
fetch, execution) happens inside the hook. The campaign is named after those stubs.

> A native-extension hook that performs network operations and then manufactures an
> empty `Makefile` is the highest-value detection point in this campaign.

### Compromised packages

**npm — 37 packages, all at `1.0.0` and only `1.0.0`** (verified against `registry.npmjs.org`
packuments). They imitate `axios`, `chalk`, `commander`, `lodash`, `typescript` and `react`,
plus the actor's test package `testingsmthb1g`. Full list in `NPM_PKGS` under Setup.

**RubyGems — 16 gems, every version malicious.** No version list was published, all releases
are yanked, and one name shipped malicious code under two accounts. They imitate `bundler`,
`i18n`, `rake` and `activesupport`; `joxn` and `reaker` have no clear target. Downloads were
56–339 per gem, ~1,222 total — expect one or two developers, not a fleet. Full list in
`GEM_PKGS` under Setup.

> **The `.gemspec` `authors` field is fabricated.** All 15 gems from `mod8rz41mje` declare
> different author names. Only the **"Pushed by" owner** is enforced identity.

### ⚠️ Namespace reclaim defeated the first takedown

The campaign began with `brumdler` and `brundlef` under **`gemlewqqhu1`**
("Taylor Moore"). RubyGems.org has a known, maintainer-acknowledged behaviour: **once
all versions of a gem are yanked, the namespace opens for any account to claim** — the
original owner has no reclaim right and there is no reservation period
(`rubygems/rubygems.org` issue #1226, discussion #2787). The actor used exactly this:

- **`mod8rz41mje`** ("Riley Miller") pushed 15 further gems, *including a reclaimed
  `brumdler`*. Its history shows `1.0.44290` and `1.0.86147` pushed and yanked on
  15 August, then `1.0.0` on 16 August.
- **`rbq95bwt6q`** ("Alex Davis") is the current owner of `brundlef`.

**This is why the gems are matched by name, not by version.** Do not scope a gem search
to a version range.

### Exposure window

**npm — `2026-08-16 02:28` to `04:13` UTC.** First package (`testingsmthb1g`) 02:28:18, main
wave 02:48–02:56, all 37 unpublished 04:07:40–04:12:36. From the registry packuments, so exact.

**RubyGems — `2026-08-15` to `2026-08-16`, both whole days.** `gemlewqqhu1` published the first
two gems on the 15th; `mod8rz41mje` pushed 15 more and reclaimed `brumdler` across the 15th–16th.
Exact publish/yank times were never published and the reclaim means the window is not contiguous.

### Indicators of compromise

| IOC | Value | Confidence |
|---|---|---|
| **Beacon C2** | `193.70.34.101:20099`, `POST /vote`, JSON `{"platform":"..."}`, `User-Agent: Ruby`. **All operating systems.** OVH (FR) | **High** — no legitimate reason to see this |
| **Exfil webhook** | `dresslee.com:20027`, `POST /xf39jMJ9P1`. Resolves `51.83.103.21`, OVH (FR) | **High** |
| **Loader URL** | `https://github.com/bebraz1/qPzM50V1AKG0rVlH/releases/download/null/main.exe` | **High** |
| Release-asset CDN path | `release-assets.githubusercontent.com/github-production-release-asset/1334756299/1fccddb3-ab7e-408d-afbb-b139111b0b50` | High |
| **Dropped loader** | **`main.exe` in the user's `Downloads` directory**, ~22 MB, executed from there | **High** |
| **ABE bypass DLL** | `abe_payload.dll` (unsigned 64-bit, single export `ABEPayload`) | **High** |
| **Stub artifacts** | `make_stub`, `make_stub.bat`, `Makefile` with empty `all`/`install`/`clean` | **High** |
| Stealer identity | Go binary self-identifies as `wincfg`; symbols `ExtractKeysWithABE`, `ReadPasswords`, `ScanSeeds`, `UploadGofileBytes` | High |
| Exfil archive | ZIP password `hLumBaC2Kr1lZ_hk`; members `passwords.txt`, `cookies.txt`, `cards.txt`, `wallets.txt`, `seeds.txt`, `history.txt`, `extensions.txt`, `SystemInfo.txt` | High |
| Upload endpoint | `https://upload.gofile.io/uploadfile`, share link `https://gofile.io/d/<code>` | **Low alone** — legitimate service; IOC only as an upload *from a build/dev host* |
| IP lookup | `https://api.ipify.org` | **Low alone** — widely used legitimately |

**SHA-256:**

| Artifact | Hash |
|---|---|
| `extconf.rb` | `a280b369c95b04530af11598f15a58328722af0325509fe1c55028c3fa873111` |
| Ruby installation runner | `2edf1494951ea52eb86c606212668822081b3c589b821e8ec33cde59b65141a7` |
| `main.exe` (Rust loader) | `6f088ade49456db2422c3edfbb9998f4a3e9cce7c4c00a7279fb45d672a82b7d` |
| Go infostealer (`wincfg`) | `1afff50ca4064310d3492c652e1c3168216dcb42063e0b26c223038db46b8731` |
| `abe_payload.dll` | `67719fa6fcaa97936bf678565d6777db5c194e14efeba16864be8dac966e24bc` |

### Current status — verified 2026-08-19

Packages are gone: **0 of 37 npm installable** (all unpublished, none re-registered) and
**0 of 16 gems hosted**, so a fresh install fails to resolve. The loader is gone too:
`github.com/bebraz1/...` returns **404**, so even a *cached* install cannot run the stealer.

**But both C2 endpoints still answer.** `193.70.34.101:20099/vote` returns HTTP 422 to a
malformed POST and `dresslee.com:20027` returns 405 to a GET — the applications are up. A
cached install would still beacon successfully on any OS.

**What this does and does not change:**

- **A cached install today still beacons but cannot steal.** Stage 2 works, stage 3 is
  dead. The attacker would learn a host exists and its platform; no credentials move.
- **The C2 being live matters.** Do not describe this campaign as fully dismantled. The
  operator retains working infrastructure; only the GitHub-hosted payload is gone.
- **Purge caches anyway** (Hardening 1) so a restored release cannot revive the chain.
- **Nothing changes about the retrospective damage.** Anything exfiltrated during the
  window is gone and stays compromised until rotated.
- **The names are not protected.** npm did **not** squat these 37 with a
  `0.0.1-security` placeholder (contrast `@apexfdn/apex`, which carries one), and
  RubyGems already demonstrated namespace reclaim in this campaign. Re-check
  installability before treating a hit as inert.

### What IS affected

- **Windows** workstations and Windows / self-hosted CI runners that resolved a listed package
  during the window → **full compromise**.
- **macOS / Linux** hosts that did the same → **beacon only** (platform + public IP disclosed,
  install proven, no credential theft).
- Any project whose `Gemfile`, `Gemfile.lock`, `package.json`, `package-lock.json`, `yarn.lock` or
  `pnpm-lock.yaml` names a listed package.

### What is NOT affected

- **Credentials on macOS and Linux.** The loader is Windows-only and never fetched elsewhere, so
  no stealer runs and nothing is read. The beacon is still a real finding — it names the developer.
- **Any project that references none of the 53 names.** No transitive path exists.
- **Installs from a pre-window lock file** via `npm ci` or `bundle install --frozen`/`--deployment`.
- **npm versions other than `1.0.0`.** That is the only version ever published for all 37; a
  different one would mean a new wave — re-triage.
- **Host persistence.** Explicitly confirmed absent: no scheduled task, Run key, service or
  startup entry. Don't hunt an implant — but see below.

> **No persistence ≠ no compromise.** The stealer collects and exits, so a clean artifact scan
> does not clear a host. Cache, manifest, shell-history and beacon evidence carry the weight.

### Lock file protection

A lock file only protects packages it **already contains**, and that is not the risk here. `npm ci`
and `bundle install --frozen`/`--deployment` install exactly what the lock pins, so a lock predating
the window cannot hold these names. But the realistic path for a typosquat is an ad-hoc
`npm install lodahs-cli` or `gem install joxn` — a *named* package, resolved straight from the
registry, which no lock file covers. Lock files also don't help with no lock committed, or if
`npm install`/`bundle update` regenerated it during the window.

**A lock file naming a malicious package is a historical IOC, not a control** — all packages are
removed now, so a fresh install fails, but the machine that wrote that entry already ran it.

---

## Pitfalls & Fixes (from validating this playbook against a real machine and org)



- **Some typosquat names are plausible real package names.** `chalk-lib`, `chalk-util`,
  `commander-lib`, `lodash-lib` and `commandor-core` read like ordinary scoped-utility
  packages, and `comand` / `comander` appear as **ordinary misspellings of the English
  word "command"** in prose, commit messages, branch names and comments. Scope every
  search to `filename:package.json` / `filename:Gemfile` / lock files, and confirm the
  hit sits in a dependency block.
- **`joxn`, `orakw`, `ie18u` and friends are near-unique strings.** Essentially zero
  false-positive rate. If one hits, believe it and escalate.
- **Do not grep CI logs for the *legitimate* names.** `chalk`, `lodash`, `commander`,
  `typescript`, `axios`, `rake`, `json` and `bundler` appear in nearly every build log.
  Phase 2c deliberately matches only full typosquat names alongside install verbs.
- **`gofile.io` and `api.ipify.org` are legitimate services.** Neither is an IOC as a
  static string — plenty of tools call ipify, and Gofile appears in legitimate
  file-sharing workflows. They count only as **runtime egress from a build runner or
  developer host**, alongside a stronger indicator. Never open a finding on either alone.
- **The loader lands in `Downloads`, not `%TEMP%`.** An early draft of this playbook
  guessed `%TEMP%` / `%PROGRAMDATA%`; the analysis is explicit that the Ruby stage saves
  `main.exe` to the user's **`Downloads`** directory and executes it from there. Hunting
  the wrong directory returns a confident false negative.
- **A clean Windows result does not mean nothing happened.** macOS and Linux hosts still
  beaconed to `193.70.34.101:20099`. That beacon is the only artifact on those platforms
  and the only proof the install ran there.
- **Do not wait for a second-stage download.** Everything after the single `main.exe`
  fetch is embedded and decrypted in memory. Detection logic keyed on "payload fetches
  more payload" will never fire.
- **The C2 is live; the payload host is not.** Verified 2026-08-19:
  `193.70.34.101:20099/vote` answers (HTTP 422 to a malformed POST) and
  `dresslee.com:20027` answers (HTTP 405 to a GET), while the GitHub release is 404. Do
  not report this campaign as fully dismantled — and note that probing only ports 80/443
  makes both endpoints look dead. Use the documented ports.
- **A post-takedown commit does not mean the install failed.** All packages are removed,
  so a fresh resolve errors — but a machine with a warm `~/.npm/_cacache` or gem cache
  can install from cache. Confirm with the developer.
- **npm `1.0.0` is the only published version — but don't hard-code that for gems.** The
  npm side is version-pinnable (verified against the registry). The RubyGems side is
  **not**: no full version list was published and `brumdler` carried malicious code
  under two accounts via namespace reclaim. Search gems **by name only**.
- **`.gemspec` `authors` values are fabricated.** All 15 gems from `mod8rz41mje` declare
  different author names. Only "Pushed by" is enforced identity — don't chase author
  strings as if they were accounts.

- **Code search is 10 req/min, not 30.** `code_search` is its own rate-limit bucket,
  separate from the 30/min `search` bucket (verified: `{"code_search":{"limit":10}}`). The
  full 180-query sweep takes ~18–20 minutes. Budget for it or narrow the filename filters
  and declare the narrowing.
- **A positive control must match the org's languages.** A dry-run against a
  JavaScript-only org returned `lodash` = 1 but `rake` = 0. That is not a broken query —
  there is no Ruby there. You need one working control **per ecosystem you scan**.
- **`gh api /user/keys` and `/user/gpg_keys` need extra scopes; `/user/installations` can't
  work at all.** Verified: 404 + "needs the admin:public_key scope", and a 403 on
  installations because it requires a GitHub App user token. Run
  `gh auth refresh -h github.com -s admin:public_key -s admin:gpg_key`, and use the UI for
  Apps and OAuth grants. **A 404/403 there is "check did not run", not "nothing found".**
- **Never append `|| echo "no matches"` to an `xargs grep` pipeline.** `xargs` exits 123 when
  any batch finds nothing, so the fallback fires even when other batches matched. A dry-run
  of that construct printed nine matching transcripts and then "No IOC matches" underneath.
  Capture output to a variable and test it.
- **macOS `log show --last 14d` does not return in reasonable time** — still running after
  25s in testing. Scope it with `--start`/`--end` to the exposure window, and remember
  unified-log retention is usually only days, so an August-15 record is likely already gone.
  Prefer proxy/firewall logs (Phase 3).
- **Don't loop `npm ls -g` per package.** ~600ms of node startup each — 37 names took ~22s.
  One `npm ls -g --depth=0 --parseable` plus a grep does the same in ~260ms.
- **Dedupe transcripts by realpath before scanning.** The same session file is often
  reachable under two project-dir names, which double-reports every hit and makes the scan
  count disagree with `find | wc -l` (201 raw paths vs 131 unique files on the test machine).
- **A CI log with no install lines has three possible causes, not two.** Harvested from a live run
  against a 72-repo org: both in-window workflow runs returned zero hits *and* the Phase 2c
  positive control returned zero. That was not a broken grep and not a clean install — the runs had
  **failed/cancelled at provisioning** (`conclusion: failure`, `steps: 1`), so the logs held only
  runner boilerplate. Check the run conclusion and job step count before recording a verdict, and
  log it as "clean, control inapplicable" rather than "clean, control passed".
- **A wrong `PROJECT_ROOT` produces a silent false all-clear.** Harvested from a dry-run:
  the workstation scan's template default (`~/projects`) did not exist on the machine at
  all, and real checkouts lived under `~/dev/<org>/<repo>/` **and** `~/Documents/legit/`.
  The scan printed "clean" having examined **zero files**. Workstation Check 4 now discovers
  candidate roots and prints a file count before the verdict — **never accept "clean" without
  a non-zero count.**
- **`-maxdepth 6` is too shallow for nested checkouts.** Same dry-run: a
  `~/dev/<org>/<repo>/` layout puts manifests near the limit and monorepo subprojects push
  past it. Check 4 uses `-maxdepth 8`.
- **Self-pollution, and don't trust `CLAUDE_SESSION_FILE`.** The agent's own transcript
  contains every IOC string above. `CLAUDE_SESSION_FILE` was **unset** on the test machine,
  which silently disabled the exclusion — Check 8 now falls back to excluding the
  most-recently-modified transcript and prints which one it dropped.

---

## Setup



```bash
export ORG="<your-github-org>"
export SCAN_DIR="/tmp/supply-chain-scan-stubmaker"
mkdir -p "$SCAN_DIR"

# npm exposure window (precise — from registry packuments)
export NPM_SINCE="2026-08-16T02:28:00Z"
export NPM_UNTIL="2026-08-16T04:13:00Z"

# RubyGems exposure window (whole days — exact timestamps unpublished)
export GEM_SINCE="2026-08-15"
export GEM_UNTIL="2026-08-16"

# --- Malicious package inventory ---
NPM_PKGS="axois-http axious-core chalk-core chalk-lib chalk-util chalk-es \
comand comander-cli comanderjs commandorjs commandor-cli commandor-core \
comander-lib commandor-lib commander-lib loadashjs lodash-lib ladash-cli \
lodahsjs lodsh-cli lodahs-cli lodhash-cli typescirpt-cli typscript-cli \
typesript-cli typscript-core typescriptt-cli typescrip-cli typescipt-cli \
tyepescript-cli typescirpt-core tyepescript-core typesript-core \
typescipt-core typescriptt-core raectjs testingsmthb1g"

GEM_PKGS="ubnuler ubnlder ri18nr reaker rakier orakw joxn ise18n ioe18n \
ie18u iai8n i1l8n i18om activesupmport brumdler brundlef"

# --- Network IOCs (high confidence) ---
BEACON_IP="193.70.34.101"          # :20099 POST /vote — fires on ALL platforms
BEACON="193.70.34.101:20099"
EXFIL_HOST="dresslee.com"          # :20027 POST /xf39jMJ9P1
LOADER_REPO="bebraz1/qPzM50V1AKG0rVlH"

# --- File IOCs ---
DROP_PATH="Downloads/main.exe"     # NOT %TEMP% — the loader lands in Downloads
ABE_DLL="abe_payload.dll"
STUBS="make_stub make_stub.bat"

# --- SHA-256 ---
HASHES="a280b369c95b04530af11598f15a58328722af0325509fe1c55028c3fa873111
2edf1494951ea52eb86c606212668822081b3c589b821e8ec33cde59b65141a7
6f088ade49456db2422c3edfbb9998f4a3e9cce7c4c00a7279fb45d672a82b7d
1afff50ca4064310d3492c652e1c3168216dcb42063e0b26c223038db46b8731
67719fa6fcaa97936bf678565d6777db5c194e14efeba16864be8dac966e24bc"

# Combined pattern for scanning logs
IOC_PATTERN="193\.70\.34\.101|dresslee\.com|bebraz1|qPzM50V1AKG0rVlH|abe_payload\.dll|make_stub|wincfg"
```

**Write to files, not context:** org scans get large. Write structured data to CSV/TSV
in `$SCAN_DIR` as you go.

**Rate limits.** GitHub **code search is its own bucket at 10 requests/minute**, not the 30/min of
the general `search` bucket. The full sweep is ~180 queries ≈ **18–20 minutes**. Pace the loops
(`sleep 6`) or accept the backoff. If you narrow the filename filters to go faster, **say so in the
Phase 5 summary** — a narrowed sweep is a coverage limit, not a clean result. Verify first:

```bash
gh api /rate_limit --jq '.resources | {code_search, search}'
# -> {"code_search":{"limit":10,...},"search":{"limit":30,...}}   <- confirmed 2026-08-19
```

Pace the loops (`sleep 6` between queries) or accept the 403 backoff. If you need it
faster, cut the filename filters to `package.json` + `package-lock.json` + `Gemfile` +
`Gemfile.lock` (the four that matter most) and **say so in the Phase 5 summary** — a
narrowed sweep is a coverage limit, not a clean result.

---

## Phase 1: Repo Analysis



**Goal:** find every project that names a malicious package in a Ruby or JavaScript
manifest or lock file. This is the surface Legit's SCA sees, and the shortlist of teams
to route to the workstation playbook.

### 1a. Code search across the org

```bash
: > "$SCAN_DIR/manifest-hits.tsv"

# npm names — manifests and all three lock file formats
for pkg in $NPM_PKGS; do
  for fn in package.json package-lock.json yarn.lock pnpm-lock.yaml; do
    gh api -X GET search/code \
      -f q="\"$pkg\" org:${ORG} filename:$fn" \
      --jq ".items[] | \"npm\t$pkg\t\(.repository.full_name)\t\(.path)\"" 2>/dev/null
  done
done | sort -u | tee -a "$SCAN_DIR/manifest-hits.tsv"

# gem names — Gemfile and Gemfile.lock
for pkg in $GEM_PKGS; do
  for fn in Gemfile Gemfile.lock; do
    gh api -X GET search/code \
      -f q="\"$pkg\" org:${ORG} filename:$fn" \
      --jq ".items[] | \"rubygems\t$pkg\t\(.repository.full_name)\t\(.path)\"" 2>/dev/null
  done
done | sort -u | tee -a "$SCAN_DIR/manifest-hits.tsv"

wc -l < "$SCAN_DIR/manifest-hits.tsv"
```

**Positive control — run this before trusting a clean result.** A broken query and a
genuinely clean org both return zero rows. Prove the search works:

```bash
gh api -X GET search/code -f q="\"lodash\" org:${ORG} filename:package.json" --jq '.items | length'
gh api -X GET search/code -f q="\"rake\" org:${ORG} filename:Gemfile" --jq '.items | length'
```

If these return `0` too, your query, token scope, or org name is wrong — fix that before
concluding anything. `lodash` and `rake` are the *legitimate* packages these typosquats
imitate, so they exercise the same query shape as the real scan.

> **Pick a control the org actually uses.** A dry-run against a JavaScript-only org
> returned `lodash` = 1 but `rake` = 0 — not a broken query, just no Ruby in that org. If a
> control returns zero, confirm the org really uses that language before assuming the query
> is at fault, and swap in a package you know is present (`react`, `rspec`, `rails`, …).
> **You need one working control per ecosystem you're scanning** — a passing npm control
> says nothing about whether your `Gemfile` queries work.

### 1b. Probe which manifest types exist before sweeping (saves queries, loses nothing)

Six cheap queries can eliminate whole filename filters. On a real 72-repo org this cut the sweep
from 180 queries to **106** — `yarn.lock` and `pnpm-lock.yaml` did not exist anywhere, so scanning
37 npm names against them was 74 wasted queries at 10/min.

```bash
for fn in package.json package-lock.json yarn.lock pnpm-lock.yaml Gemfile Gemfile.lock; do
  sleep 7
  n=$(gh api -X GET search/code -f q="org:${ORG} filename:${fn}" --jq '.total_count' 2>/dev/null)
  printf "  %-20s %s\n" "$fn" "${n:-ERR}"
  echo "$fn ${n:-0}" >> "$SCAN_DIR/manifest-types.txt"
done
```

Drop any filter that returns `0` **org-wide** — that is evidence, not an assumption, so it is not the
silent narrowing the rate-limit note warns about. Still record it in the Phase 5 summary.

> This also hands you a **content control for each ecosystem**. If `Gemfile` returns 3, read one and
> pick a real gem from it (`gh api repos/<r>/contents/Gemfile --jq .content | base64 -d`), then query
> that name. A filename filter proving reachable is weaker than a content match proving the query
> shape works — on the validated org `jekyll` in `Gemfile` returned 3 where `rspec`/`rails` returned 0.

### 1c. Classify each hit

Because these are typosquats, **any** occurrence is a real finding. What you are
classifying is how it got there and which machines to chase.

```bash
while IFS=$'\t' read -r eco pkg repo path; do
  content=$(gh api "repos/${repo}/contents/${path}" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null)
  line=$(echo "$content" | grep -nE "(^|[^a-zA-Z0-9_-])${pkg}([^a-zA-Z0-9_-]|$)" | head -3)
  echo "=== ${repo}/${path}  [${eco}: ${pkg}]"
  echo "$line" | sed 's/^/    /'
  gh api "repos/${repo}/commits?path=${path}&per_page=1" \
    --jq '.[0] | "    last-modified: \(.commit.author.date) by \(.commit.author.name)"' 2>/dev/null
done < "$SCAN_DIR/manifest-hits.tsv" | tee "$SCAN_DIR/manifest-classified.txt"
```

Classify each hit as:

- **Named in a lock file** → **strongest signal.** The package was resolved and
  downloaded. Identify every machine and runner that installed against this repo during
  the window and route them to [workstation-playbook.md](workstation-playbook.md).
- **Named in a manifest only**, no lock entry → a developer typed it; the install may
  have failed (after takedown) or succeeded (during the window). Check the commit date,
  then route the committing developer's machine.
- **Committed after takedown** (npm: after 2026-08-16 04:13 UTC; gems: after
  2026-08-16) → the install would fail to resolve. Still confirm with the developer —
  **a warm package-manager cache can serve a removed package.**
- **Present in prose, docs, or a comment** → see Pitfalls & Fixes. Not a dependency.

### 1d. Write the repo evidence table

Write `$SCAN_DIR/evidence-repos.csv` — one row per repo/file hit. This describes the
dependency posture and is independent of the exposure window.

```
repo,ecosystem,package,file,file_type,in_lock_file,committed_at,committed_by,installer_respects_lock,needs_action
org/app,npm,lodahs-cli,package-lock.json,lockfile,yes,2026-08-16T03:11:00Z,dev@example.com,no (npm install),yes
org/api,rubygems,joxn,Gemfile,manifest,no,2026-08-18T09:02:00Z,dev2@example.com,yes (bundle --deployment),verify
```

Column notes:
- `in_lock_file` — `yes` is the strongest signal: the package actually resolved.
- `installer_respects_lock` — `npm ci` / `bundle --deployment` = yes; `npm install` /
  bare `gem install` = no.
- `needs_action` — `yes` for any lock-file hit or any manifest hit dated inside the
  window; `verify` for post-takedown commits (a warm cache can still install).

---

## Phase 2: CI Run Analysis



The npm window is narrow and precisely known, which makes this scan cheap and
conclusive.

### 2a. Pre-filter: does the org have any Windows or self-hosted runner?

Do this first — it is cheap and it bounds everything below. **The stealer only runs on Windows**, so
if no workflow targets `windows-*` or `self-hosted`, CI exposure is **beacon-only by definition** and
you can treat the log scan as corroboration rather than the deciding evidence.

```bash
win=0
while read -r repo; do
  for wf in $(gh api "repos/${repo}/contents/.github/workflows" --jq '.[].name' 2>/dev/null); do
    body=$(gh api "repos/${repo}/contents/.github/workflows/${wf}" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null)
    if echo "$body" | grep -qiE "runs-on:.*(windows|self-hosted)"; then
      echo "WINDOWS/SELF-HOSTED: ${repo}/.github/workflows/${wf}"; win=$((win+1))
    fi
  done
done < "$SCAN_DIR/repos.txt"
echo "workflows on windows/self-hosted: $win"
[ "$win" -eq 0 ] && echo "-> CI exposure is beacon-only by definition; prioritise workstations."
```

> Also try `gh api "orgs/${ORG}/actions/runners"` for registered self-hosted runners — but note it
> needs the **`admin:org`** scope and returns **403** without it (verified). A 403 there means the
> check did not run; fall back to the workflow-file scan above, which needs no extra scope.

### 2b. Find workflow runs inside the windows

```bash
gh api "orgs/${ORG}/repos?per_page=100" --paginate --jq '.[].full_name' > "$SCAN_DIR/repos.txt"

while read -r repo; do
  gh api "repos/${repo}/actions/runs?created=${NPM_SINCE}..${NPM_UNTIL}&per_page=100" \
    --jq ".workflow_runs[] | \"${repo}\t\(.id)\t\(.created_at)\t\(.name)\"" 2>/dev/null
done < "$SCAN_DIR/repos.txt" | tee "$SCAN_DIR/runs-npm-window.tsv"

while read -r repo; do
  gh api "repos/${repo}/actions/runs?created=${GEM_SINCE}..${GEM_UNTIL}&per_page=100" \
    --jq ".workflow_runs[] | \"${repo}\t\(.id)\t\(.created_at)\t\(.name)\"" 2>/dev/null
done < "$SCAN_DIR/repos.txt" | tee "$SCAN_DIR/runs-gem-window.tsv"
```

### 2c. Download logs in parallel

```bash
mkdir -p "$SCAN_DIR/logs"
cat "$SCAN_DIR/runs-npm-window.tsv" "$SCAN_DIR/runs-gem-window.tsv" \
  | awk -F'\t' '{print $1"\t"$2}' | sort -u \
  | xargs -P 8 -n 1 sh -c '
      set -- $0
      repo="$1"; run="$2"
      out="'"$SCAN_DIR"'/logs/$(echo "$repo" | tr "/" "_")_${run}.zip"
      gh api "repos/${repo}/actions/runs/${run}/logs" > "$out" 2>/dev/null
    '
echo "downloaded: $(ls "$SCAN_DIR/logs" | wc -l) log archives"
```

### 2d. Grep for install-time markers and network IOCs

**Match installs, not imports.** `grep -r "chalk" logs/` matches every
`import chalk from 'chalk'` in a build transcript and drowns the signal.

```bash
cd "$SCAN_DIR/logs"
for z in *.zip; do
  unzip -p "$z" 2>/dev/null | grep -inE \
    "added (${NPM_PKGS// /|})@1\.0\.0|\
npm (warn |http fetch GET ).*(${NPM_PKGS// /|})|\
(Installing|Fetching) (${GEM_PKGS// /|})|\
Successfully installed (${GEM_PKGS// /|})|\
${IOC_PATTERN}" \
    && echo "  ^^^ HIT in $z"
done | tee "$SCAN_DIR/ci-hits.txt"
```

> The `IOC_PATTERN` half of that grep is the more valuable one: `193.70.34.101`,
> `dresslee.com`, `bebraz1` or `make_stub` in a build log is unambiguous, whereas a
> package name could still be a false positive.

**If the grep returns zero AND the positive control also returns zero, check whether the run even
reached an install step** before concluding anything. A run that failed or was cancelled during
provisioning contains only runner boilerplate — no install lines to find, which looks identical to a
broken grep.

```bash
while IFS=$'\t' read -r repo run _; do
  [ -z "$run" ] && continue
  gh api "repos/${repo}/actions/runs/${run}" \
    --jq "\"${repo} ${run} \(.conclusion) event=\(.event)\"" 2>/dev/null
  gh api "repos/${repo}/actions/runs/${run}/jobs" \
    --jq '.jobs[] | "    job=\(.conclusion) steps=\(.steps|length)"' 2>/dev/null
done < <(cat "$SCAN_DIR/runs-npm-window.tsv" "$SCAN_DIR/runs-gem-window.tsv" | sort -u)
```

`conclusion: failure` or `cancelled` with `steps: 1` means the job died at provisioning. Verdict:
**clean, control inapplicable** — record it that way, not as "clean, control passed".

### 2e. Look for the StubMaker build signature

A gem install that ran the malicious `extconf.rb` reports a **successful native
extension build with no compiler output**:

```bash
cd "$SCAN_DIR/logs"
for z in *.zip; do
  unzip -p "$z" 2>/dev/null \
    | grep -A6 -iE "Building native extensions|extconf\.rb" \
    | grep -iE "Nothing to be done for|make_stub|is up to date" \
    && echo "  ^^^ possible stub-build signature in $z (inspect manually)"
done | tee "$SCAN_DIR/ci-stubbuild.txt"
```

> `make_stub` in that output is conclusive. "Nothing to be done for" alone is **weak** —
> plenty of legitimate gems build no-op extensions. It matters only in a log that also
> names one of the 16 gems.

### 2f. Classify

- **`added <name>@1.0.0`** / **`Successfully installed <gem>`** → installed on that
  runner. Note the runner OS: **`windows-*` or self-hosted Windows → treat as
  compromised**; `ubuntu-*` / `macos-*` → beacon only, but the developer who introduced
  the name still needs their workstation checked.
- **`193.70.34.101` / `dresslee.com` / `bebraz1` / `make_stub` / `abe_payload.dll` in a
  log** → the malicious hook ran. Escalate immediately regardless of runner OS.
- **Package name in an import, README, or scan-tool table** → false positive.

### 2g. Write the CI evidence table

Write `$SCAN_DIR/evidence-ci-runs.csv` — one row per workflow run inspected.

```
repo,run_id,created_at,workflow,runner_os,install_cmd,package_installed,ioc_hit,verdict
org/app,123456,2026-08-16T03:11:00Z,ci.yml,windows-latest,npm install,lodahs-cli@1.0.0,193.70.34.101,compromised
org/api,123457,2026-08-16T03:20:00Z,test.yml,ubuntu-latest,bundle install,joxn,none,beacon-only
org/web,123458,2026-08-16T02:55:00Z,build.yml,ubuntu-latest,npm ci,none,none,clean
```

Verdict values:
- `compromised` — Windows runner installed a listed package, or any IOC hit in the log.
- `beacon-only` — non-Windows runner installed a listed package. The beacon fired; no
  stealer ran.
- `clean` — no listed package installed and no IOC hit.

---

## Phase 3: Network Investigation (Firewall / Proxy / DNS Logs)


**This is the highest-value org-level phase for StubMaker, and the only one that reaches
non-Windows machines.** The installer beacons on **every** platform, so a macOS or Linux
developer who installed a malicious package left no host artifact except a single
plaintext HTTP POST. Your proxy, firewall and DNS logs are where that shows up.

Both endpoints were **still live when last checked (2026-08-19)**, so a hit here is not
necessarily historical.

### What to look for

| IOC | Where to search | Platform |
|---|---|---|
| Connection to `193.70.34.101` | Firewall logs, VPC flow logs, proxy logs | **All** — Windows, macOS, Linux |
| Connection to port `20099` on that IP | Firewall, proxy logs | **All** |
| `POST /vote` with JSON body `{"platform":"Windows\|MacOS\|Linux"}` | Proxy logs with body inspection (plaintext HTTP — no TLS to strip) | **All** |
| `User-Agent: Ruby` to an external IP on a non-standard port | Proxy logs — highly anomalous | **All** |
| DNS resolution of `dresslee.com` | DNS logs, DNS proxy, Pi-hole, Cloudflare Gateway | Windows |
| Connection to `51.83.103.21` or port `20027` | Firewall, proxy, VPC flow logs | Windows |
| `POST /xf39jMJ9P1` | Proxy logs, WAF logs | Windows |
| Download of `main.exe` from `github.com/bebraz1/qPzM50V1AKG0rVlH` or `release-assets.githubusercontent.com/.../1334756299/...` | Proxy logs | Windows |
| `POST https://upload.gofile.io/uploadfile` **from a build runner or developer host** | Proxy logs | Windows |

> **Do not alert on `gofile.io` or `api.ipify.org` alone** — both are used legitimately.
> They matter only in sequence: a Gofile upload immediately followed by traffic to
> `dresslee.com:20027` is the exfiltration signature.

### Where to check

**Cloud:**
- AWS: VPC Flow Logs, Route 53 Resolver query logs
- GCP: VPC Flow Logs, Cloud DNS query logs
- Azure: NSG Flow Logs, Azure DNS Analytics

**On-premise / corporate network:**
- Firewall (Palo Alto, Fortinet, …) — destination IP `193.70.34.101` or `51.83.103.21`,
  or destination ports `20099` / `20027`
- Web proxy (Zscaler, Squid, …) — domain `dresslee.com`, and the raw IP beacon
- DNS server logs — `dresslee.com` resolution
- SIEM (Splunk, Elastic, …) — correlate across sources

**CI runners:**
- Self-hosted runners: check the host's network logs
- GitHub-hosted runners: no direct log access, but the network edge may have captured
  egress if traffic was routed through a corporate proxy

### Time window

Search from `2026-08-15T00:00:00Z` to at least `2026-08-17T00:00:00Z`. Extend to the
present if you want to catch a cached install still beaconing — stage 2 works even though
stage 3 is dead.

### Example queries

**Splunk:**
```
index=firewall (dest_ip="193.70.34.101" OR dest_port=20099 OR dest_port=20027)
| stats count by src_ip, dest_ip, dest_port, action
```
```
index=proxy (uri_path="/vote" OR uri_path="/xf39jMJ9P1" OR http_user_agent="Ruby")
| stats count by src_ip, dest_host, uri_path, http_user_agent
```
```
index=dns query="dresslee.com" | stats count by src_ip, query, answer
```

### Interpreting a hit

- **Beacon only (`193.70.34.101:20099`)** → that host ran the install. On macOS/Linux
  that is the whole story. On Windows it means stage 2 completed — check stage 3.
- **Beacon + `dresslee.com:20027`** → theft completed and data was exfiltrated. Treat as
  confirmed compromise and go straight to Phase 6 credential rotation.
- **Nothing** → note the coverage limit honestly. Absence of proxy logs for a host (BYOD,
  home network, unmanaged Mac) is not absence of the beacon. Say which hosts you could
  and could not cover.

---

## Phase 4: Workstation Investigation



The payload only detonates on **Windows**, and typosquats are typed by people rather
than pulled transitively — so the developer machine is where compromise is confirmed or
ruled out.

Route to **[workstation-playbook.md](workstation-playbook.md)**:

- Every developer who committed a manifest or lock file naming a listed package.
- Everyone on a team whose repo showed a Phase 1 hit — the same typo often gets shared
  in a chat message or a copied command.
- Anyone who may have run an ad-hoc `npm install` / `gem install` of a listed name
  during the window, whether or not it was ever committed.

**Prioritise Windows machines**, but run it on macOS and Linux too — those hosts
beaconed, and the cache, shell history and agent logs prove *who* typed it.

---

## Phase 5: Present Results


Produce three deliverables and return them to the user.

### 1. Repo Analysis table (`evidence-repos.csv`)

From Phase 1d — every repo that names a malicious package, its file type, whether it
reached a lock file, and whether the installer respects the lock.

### 2. CI Runs table (`evidence-ci-runs.csv`)

From Phase 2g — what actually ran during the windows, on which runner OS, and the
`compromised` / `beacon-only` / `clean` verdict per run.

### 3. Executive Summary

Short prose for incident-response leads:

- **Verdict** — `clean`, `beacon-only`, or `compromised`
- **Scope** — repos scanned, CI runs analysed, logs downloaded, workstations triaged, and
  **which hosts network logs could not cover** (BYOD, unmanaged Macs, home networks)
- **Repo analysis** — how many repos name one of the 53 packages, how many reached a lock
  file, and how many were committed inside the window
- **CI analysis** — how many runs installed a listed package, split by runner OS
  (Windows = compromise, non-Windows = beacon only)
- **Network** — whether `193.70.34.101:20099` or `dresslee.com:20027` appears in
  firewall / proxy / DNS logs, and for which hosts
- **Workstations** — Windows: loader/stub/cache artifacts found? non-Windows: beacon
  evidence found?
- **Credential exposure** — which browser profiles, wallets and Telegram sessions were on
  confirmed-compromised Windows hosts (Phase 5b)
- **Attacker-created persistence** — anything minted since 2026-08-15 (Phase 5d)
- **Bottom line** — one sentence

### 4. Verdict per repo and host

- **No action** — no repo names any of the 53 packages **and** Phase 1's positive control proved
  the search worked; no CI run installed one; no network hit **with proxy coverage confirmed**.
- **Attention** — a lock file names one (it resolved), or a Windows runner/workstation installed
  one, or a hit on `193.70.34.101` / `dresslee.com`.
- **Beacon-only** — a non-Windows host installed one. Not a credential incident for that host;
  use it to find the Windows machines the same developer used.
- **Vulnerable but not hit** — `npm install` / bare `gem install` with no lock file, no activity
  in the window. Flag for Hardening 4.

Return `$SCAN_DIR/evidence-repos.csv`, `$SCAN_DIR/evidence-ci-runs.csv` and the executive
summary to the user.

---

### Supporting analysis

**5a. Secrets exposed to affected CI workflows.**

```bash
while IFS=$'\t' read -r repo _; do
  echo "=== $repo"
  gh api "repos/${repo}/actions/secrets"   --jq '.secrets[].name'   2>/dev/null | sed 's/^/    secret: /'
  gh api "repos/${repo}/actions/variables" --jq '.variables[].name' 2>/dev/null | sed 's/^/    var:    /'
done < <(awk -F'\t' '{print $1}' "$SCAN_DIR/ci-hits.txt" | sort -u) | tee "$SCAN_DIR/exposed-secrets.txt"

gh api "orgs/${ORG}/actions/secrets" --jq '.secrets[].name' 2>/dev/null
```

Also enumerate OIDC-issued cloud credentials and every `secrets.*` reference in the workflows
that ran during the window.

**5b. Credentials exposed on affected Windows hosts** — browser-resident data, not CI secrets, is
the target: saved passwords, cookies and session tokens (ABE-decrypted, not just copied), payment
cards and stored CVCs, wallet files and BIP-39 seed phrases, Telegram `tdata`. Workstation Check 7
enumerates the exact profiles present on each machine — use it to scope rotation. Cookies are the
sharpest edge: they bypass MFA, so invalidate sessions **server-side**.

**5c. What still hurts.** No stealer can run today (loader host 404), so what persists is what was
already taken. Irreversible: **seed phrases** — new wallet, move funds. Not closed by a password
change: **session cookies** and **Telegram `tdata`** — revoke server-side. Rotate: saved passwords
(from a clean device), payment cards (reissue). Not rotatable: history, extension data, host info.
The host itself has **no implant** — persistence is confirmed absent — but a clean artifact scan
still does not clear it, because the stealer collects and exits.

#### Audit for attacker-created persistence — the step rotation misses

Credentials stolen 15–16 August have been usable since. **Anything the attacker created
with a stolen session survives the credential being rotated** — revoking a cookie does
not delete a PAT that cookie minted. Scope to 2026-08-15 onward:

> **These three need scopes the default `gh` login does not have.** Verified 2026-08-19:
> `/user/keys` returns `404` + *"needs the admin:public_key scope"*, `/user/gpg_keys` needs
> `admin:gpg_key`, and `/user/installations` returns `403` because it requires a GitHub
> App user-access token — a normal `gh` login cannot call it at all. Grant the first two
> and skip the third:
>
> `gh auth refresh -h github.com -s admin:public_key -s admin:gpg_key`
>
> For installed Apps and OAuth grants, use the UI instead:
> **Settings → Integrations → Applications**, and
> **Settings → Security log** filtered to `created:>=2026-08-15`.
> Do not read a `404`/`403` here as "no attacker-created keys" — it means the check did not
> run.

```bash
gh api /user/keys          --jq '.[] | "ssh-key\t\(.created_at)\t\(.title)"'   # needs admin:public_key
gh api /user/gpg_keys      --jq '.[] | "gpg-key\t\(.created_at)\t\(.key_id)"'  # needs admin:gpg_key
# /user/installations requires a GitHub App token — use the UI (Settings → Applications)

gh api "orgs/${ORG}/audit-log?phrase=created:>=2026-08-15&per_page=100" --paginate \
  --jq '.[] | "\(.created_at)\t\(.actor)\t\(.action)"' 2>/dev/null \
  | grep -iE "oauth|pat|token|key|hook|runner|member_invit|repo.add_member|protected_branch" \
  || echo "(audit-log needs GitHub Enterprise Cloud; use the UI Security log otherwise)"

while read -r repo; do
  gh api "repos/${repo}/keys"  --jq ".[] | select(.created_at > \"2026-08-15\") | \"deploy-key\t${repo}\t\(.created_at)\t\(.title)\"" 2>/dev/null
  gh api "repos/${repo}/hooks" --jq ".[] | select(.created_at > \"2026-08-15\") | \"webhook\t${repo}\t\(.created_at)\t\(.config.url)\"" 2>/dev/null
done < "$SCAN_DIR/repos.txt" | tee "$SCAN_DIR/attacker-persistence.tsv"
```

Then check per platform:

- **Your own published packages** — any npm/RubyGems version published from a stolen
  publish token since 15 Aug? A compromised maintainer laptop is how this campaign's
  next wave would start. Check `npm view <pkg> time --json` and the RubyGems owner list.
- **Cloud** — IAM users, access keys, roles or trust-policy edits created since 15 Aug.
  A console session can mint a long-lived key that outlives it.
- **Email / chat** — forwarding rules and OAuth app grants added in the window.
- **Git history** — commits, force-pushes or workflow-file edits authored with a stolen
  token. Diff `.github/workflows/**` especially.

---

## Phase 6: Hardening & Remediation (User Approval Required)



### Hardening 1 — Remove the packages and purge caches

Removal alone is not enough: **the malicious tarball survives in the package-manager
cache**, and a warm cache can serve a package the registry has already removed.

> **Destructive — this is the approval-gated phase.** The `rm -rf` and `find -delete`
> below remove cache state. Confirm with the user before running, and take the Phase 4
> evidence copies first.

Run from the repo root of each affected project. `NPM_PKGS` / `GEM_PKGS` come from Setup,
so these loops are safe to paste as-is — they no-op for packages that aren't installed.

```bash
# npm — uninstall from this project, then purge the cache
for p in $NPM_PKGS; do
  npm uninstall "$p" 2>/dev/null
done
npm cache verify && npm cache clean --force
ls ~/.npm/_cacache 2>/dev/null || echo "npm cache cleared"

# RubyGems / Bundler
for g in $GEM_PKGS; do
  gem uninstall "$g" -a -x 2>/dev/null
done
rm -rf ~/.gem/specs ~/.bundle/cache
find . -name "*.gem" -path "*vendor*" -print -delete
```

Then reinstall from a trusted, pre-window lock file.

### Hardening 2 — Rotate credentials

Order matters:

1. **Invalidate browser and Telegram sessions server-side first** — before any password change.
   ABE-decrypted cookies bypass MFA and survive a password reset. Force IdP re-authentication and
   revoke refresh tokens.
2. **Browser-saved passwords**, changed **from a clean device**, reused ones first.
3. **Cryptocurrency** — new wallet from a trusted device. A leaked seed phrase cannot be rotated.
4. **Telegram** — terminate all other sessions.
5. **Payment cards** — reissue; CVCs were taken too.
6. **Every secret reachable from an affected CI runner** — the `secrets.*` / `variables.*` from
   5a, OIDC cloud credentials, npm/RubyGems publish tokens, registry credentials, SSH deploy keys.

### Hardening 3 — Block egress

Deny **`193.70.34.101`** and **`dresslee.com`** at the proxy/DNS layer. **Both are live
as of 2026-08-19**, so this is an active control, not hygiene. Alert (don't block) on
Gofile uploads from build runners or developer machines — Gofile is legitimate, but a CI
runner uploading to it is anomalous by definition.

### Hardening 4 — Make typosquats hard to install

This campaign needed one typo. Controls that address that:

- **Enforce lock-file installs**: `npm ci` in CI, never `npm install`;
  `bundle install --deployment` / `--frozen`, never bare `gem install`.
- **`npm ci --ignore-scripts`** as defence-in-depth — it neutralises the npm hook
  entirely. Note the limit: it does **not** stop a RubyGems native-extension hook, so
  it is weaker protection on the gem side.
- **Route installs through a registry proxy** (Artifactory, Verdaccio, a private
  RubyGems mirror) that can block known-malicious names and enforce an allowlist.
- **Require review on any PR that adds a new direct dependency.** A human reading
  `lodahs-cli` in a diff catches what tooling misses.
- **Enable dependency-review / SCA gating on PRs** so a new direct dependency matching a
  known-malicious name fails the check rather than merging.

### Hardening 5 — Re-image on confirmed Windows compromise

An infostealer that ran with user privileges and decrypted the browser credential store
read everything that user could read. Where a Windows workstation is confirmed
compromised, **re-imaging is the defensible call** — this playbook enumerates known
artifacts but cannot prove the absence of others.

---

## Sources



- OpenSourceMalware, *StubMaker RubyGems Campaign Delivers a Windows Infostealer* —
  primary analysis, full IOC set and hashes:
  <https://opensourcemalware.com/blog/stubmaker-rubygems-windows-infostealer>
- OpenSourceMalware, *Windows Infostealer Hits npm and Ruby* — links the npm wave to the
  same actor: <https://opensourcemalware.com/windows-infostealer-stubmaker-npm-ruby>
- The Hacker News coverage:
  <https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html>
- npm registry packuments — authoritative for the `1.0.0` pin and the exposure window
- RubyGems namespace-reclaim behaviour: `rubygems/rubygems.org` issue #1226,
  discussion #2787
