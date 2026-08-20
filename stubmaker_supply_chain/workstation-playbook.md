# StubMaker Typosquat Campaign — Workstation Investigation Playbook

Playbook for checking whether a **developer workstation** was affected by the
**StubMaker** typosquatting campaign (RubyGems: 15–16 August 2026; npm:
16 August 2026). Run this on each machine that may have run `gem install`,
`bundle install`, `npm install` or `npm i <name>` during the exposure window.

> **Run this on every OS, but the verdicts differ.**
> The installer beacons the detected platform to `193.70.34.101:20099` on **Windows,
> macOS and Linux**; only Windows then fetches and runs the stealer.
> - **Windows** → full compromise possible. Checks 1, 3, 5, 7 are decisive.
> - **macOS / Linux** → **beacon only.** No stealer runs, no credentials are read. But
>   Checks 3, 4, 5, 6 and 8 still prove the install happened and identify who ran it.
>   Do not skip these machines — on them the beacon is the *only* artifact.

> **Verified 2026-08-19 — the payload can no longer be delivered, but the C2 is live.**
> All 53 packages are removed and the loader host `github.com/bebraz1/...` returns HTTP
> 404, so even a cached install cannot run the stealer today. However
> `193.70.34.101:20099/vote` and `dresslee.com:20027` **both still answer**. You are
> looking for evidence of a **past** detonation during the 15–16 August window — and
> anything exfiltrated then is already gone. Browser session cookies bypass MFA until
> invalidated server-side.

> **No persistence exists — and that is not reassuring.** The published analysis
> explicitly confirms no scheduled task, Run key, service or startup-folder entry. This
> is a rapid collect-and-exfiltrate stealer. **A clean artifact scan does not clear a
> host** — Checks 3, 4, 5, 6 and 8 carry the weight.

> **Designed for AI agent execution.** Each check is self-contained with commands to run
> and expected output to interpret.

---

## Incident Reference

| Field | Value |
|---|---|
| Malicious npm packages | 37 names, **all at `1.0.0` only** — full table in [playbook.md](playbook.md) |
| Malicious gems | 16 names, **all versions malicious** (no full version list published; `brumdler` carried malicious code under two accounts via RubyGems namespace reclaim) |
| npm exposure window | `2026-08-16 02:28` – `04:13` UTC (~1h45m, from registry packuments) |
| RubyGems exposure window | `2026-08-15` – `2026-08-16` (whole days) |
| **Beacon C2 (all platforms)** | `POST http://193.70.34.101:20099/vote`, JSON `{"platform":"Windows\|MacOS\|Linux"}`, `User-Agent: Ruby`, retried 3× |
| **Exfil webhook** | `POST http://dresslee.com:20027/xf39jMJ9P1` (resolves `51.83.103.21`) |
| Loader URL | `https://github.com/bebraz1/qPzM50V1AKG0rVlH/releases/download/null/main.exe` |
| **Dropped loader** | **`main.exe` in the user's `Downloads` directory** (~22 MB), executed from there |
| ABE bypass DLL | `abe_payload.dll` — unsigned 64-bit, single export `ABEPayload` |
| Stub artifacts | `make_stub`, `make_stub.bat`, `Makefile` with empty `all`/`install`/`clean` |
| Exfil archive | ZIP password `hLumBaC2Kr1lZ_hk`; members `passwords.txt`, `cookies.txt`, `cards.txt`, `wallets.txt`, `seeds.txt`, `history.txt`, `extensions.txt`, `SystemInfo.txt` |
| Upload endpoint | `https://upload.gofile.io/uploadfile` → `https://gofile.io/d/<code>` |
| Persistence | **None** — explicitly confirmed absent |
| Payload OS | **Windows only** (beacon fires everywhere) |

**SHA-256:** `extconf.rb` `a280b369…873111` · runner `2edf1494…5141a7` · `main.exe`
`6f088ade…a82b7d` · Go stealer `1afff50c…6b8731` · `abe_payload.dll` `67719fa6…6e24bc`
(full values in [playbook.md](playbook.md)).

---

## Setup

### macOS / Linux

```bash
NPM_PKGS="axois-http axious-core chalk-core chalk-lib chalk-util chalk-es \
comand comander-cli comanderjs commandorjs commandor-cli commandor-core \
comander-lib commandor-lib commander-lib loadashjs lodash-lib ladash-cli \
lodahsjs lodsh-cli lodahs-cli lodhash-cli typescirpt-cli typscript-cli \
typesript-cli typscript-core typescriptt-cli typescrip-cli typescipt-cli \
tyepescript-cli typescirpt-core tyepescript-core typesript-core \
typescipt-core typescriptt-core raectjs testingsmthb1g"

GEM_PKGS="ubnuler ubnlder ri18nr reaker rakier orakw joxn ise18n ioe18n \
ie18u iai8n i1l8n i18om activesupmport brumdler brundlef"

NPM_RE=$(echo $NPM_PKGS | tr ' ' '|')
GEM_RE=$(echo $GEM_PKGS | tr ' ' '|')
ALL_RE="${NPM_RE}|${GEM_RE}"

# Network IOCs
BEACON_IP="193.70.34.101"
EXFIL_HOST="dresslee.com"
IOC_PATTERN="193\.70\.34\.101|dresslee\.com|bebraz1|qPzM50V1AKG0rVlH|abe_payload\.dll|make_stub|wincfg"

# SHA-256 of known artifacts
HASHES="a280b369c95b04530af11598f15a58328722af0325509fe1c55028c3fa873111
2edf1494951ea52eb86c606212668822081b3c589b821e8ec33cde59b65141a7
6f088ade49456db2422c3edfbb9998f4a3e9cce7c4c00a7279fb45d672a82b7d
1afff50ca4064310d3492c652e1c3168216dcb42063e0b26c223038db46b8731
67719fa6fcaa97936bf678565d6777db5c194e14efeba16864be8dac966e24bc"
```

### Windows (PowerShell)

```powershell
$NpmPkgs = @('axois-http','axious-core','chalk-core','chalk-lib','chalk-util','chalk-es',
  'comand','comander-cli','comanderjs','commandorjs','commandor-cli','commandor-core',
  'comander-lib','commandor-lib','commander-lib','loadashjs','lodash-lib','ladash-cli',
  'lodahsjs','lodsh-cli','lodahs-cli','lodhash-cli','typescirpt-cli','typscript-cli',
  'typesript-cli','typscript-core','typescriptt-cli','typescrip-cli','typescipt-cli',
  'tyepescript-cli','typescirpt-core','tyepescript-core','typesript-core',
  'typescipt-core','typescriptt-core','raectjs','testingsmthb1g')

$GemPkgs = @('ubnuler','ubnlder','ri18nr','reaker','rakier','orakw','joxn','ise18n',
  'ioe18n','ie18u','iai8n','i1l8n','i18om','activesupmport','brumdler','brundlef')

$AllRe = ($NpmPkgs + $GemPkgs) -join '|'
$IocRe = '193\.70\.34\.101|dresslee\.com|bebraz1|qPzM50V1AKG0rVlH|abe_payload\.dll|make_stub|wincfg'

$Hashes = @(
  'A280B369C95B04530AF11598F15A58328722AF0325509FE1C55028C3FA873111',
  '2EDF1494951EA52EB86C606212668822081B3C589B821E8EC33CDE59B65141A7',
  '6F088ADE49456DB2422C3EDFBB9998F4A3E9CCE7C4C00A7279FB45D672A82B7D',
  '1AFFF50CA4064310D3492C652E1C3168216DCB42063E0B26C223038DB46B8731',
  '67719FA6FCAA97936BF678565D6777DB5C194E14EFEBA16864BE8DAC966E24BC')
```

### Prerequisite check — run this before any Check

Five of the checks read variables defined in Setup. Skipping Setup does **not** fail loudly in
every case: an unset `$Hashes` makes `$Hashes -contains $h` return `$false`, silently downgrading
a confirmed hash match to "verify", and an unset `$NpmPkgs` collapses the cache pattern to
`registry.npmjs.org/()`, which matches **every** entry. Verify first.

```bash
for v in NPM_PKGS GEM_PKGS ALL_RE IOC_PATTERN HASHES; do
  eval "val=\$$v"
  if [ -z "$val" ]; then echo "MISSING: \$$v — re-run the Setup block before continuing"; fail=1; fi
done
[ -n "${fail:-}" ] && echo "STOP: Setup not applied in this shell." || echo "Setup OK: $(echo $NPM_PKGS | wc -w | tr -d ' ') npm + $(echo $GEM_PKGS | wc -w | tr -d ' ') gem names loaded"
```

```powershell
$missing = @()
foreach ($v in 'NpmPkgs','GemPkgs','AllRe','IocRe','Hashes') {
  if (-not (Get-Variable -Name $v -Scope Global -ErrorAction SilentlyContinue) -and
      -not (Get-Variable -Name $v -ErrorAction SilentlyContinue)) { $missing += $v }
}
if ($missing.Count -gt 0) {
  Write-Host ("STOP: Setup not applied in this session. Missing: {0}" -f ($missing -join ', ')) -ForegroundColor Red
} else {
  Write-Host ("Setup OK: {0} npm + {1} gem names, {2} hashes loaded" -f $NpmPkgs.Count, $GemPkgs.Count, $Hashes.Count)
}
```

---

---

## Check 1: Loader and Stealer Artifacts (Windows — decisive)

The Ruby stage saves the Rust loader as **`main.exe` in the user's `Downloads`
directory** and executes it from there. The stealer then loads `abe_payload.dll` from
memory. Hash-match anything you find.

```powershell
# The documented drop location — check this FIRST
$dl = "$env:USERPROFILE\Downloads\main.exe"
if (Test-Path $dl) {
  Write-Host "FOUND - main.exe in Downloads: $dl" -ForegroundColor Red
  Get-Item $dl | Select-Object FullName, Length, CreationTime, LastWriteTime
  $h = (Get-FileHash $dl -Algorithm SHA256).Hash
  Write-Host "  SHA256: $h"
  if ($Hashes -contains $h) { Write-Host "  *** HASH MATCHES A KNOWN STUBMAKER ARTIFACT - CONFIRMED ***" -ForegroundColor Red }
} else { Write-Host "Downloads\main.exe: not present" }

# Named artifacts anywhere in the usual locations
$paths = @("$env:USERPROFILE\Downloads", $env:TEMP, $env:PROGRAMDATA, $env:LOCALAPPDATA, $env:APPDATA)
foreach ($p in $paths) {
  if (Test-Path $p) {
    Get-ChildItem -Path $p -Recurse -ErrorAction SilentlyContinue -Include 'abe_payload.dll','main.exe','wincfg','wincfg.exe' |
      ForEach-Object {
        $hh = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        $tag = if ($Hashes -contains $hh) { "HASH MATCH - CONFIRMED" } else { "name match - verify" }
        Write-Host "FOUND [$tag]: $($_.FullName)  sha256=$hh" -ForegroundColor Red
      }
  }
}

# Is the stealer running?
Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match 'wincfg|^main$' }
Get-Process -ErrorAction SilentlyContinue |
  Where-Object { $_.Path -and $_.Path -match 'abe_payload|wincfg|Downloads\\main\.exe' } |
  Select-Object Id, ProcessName, Path
```

A hash match on any of the five known artifacts is **conclusive**. `main.exe` present in
`Downloads` with an August 15–16 timestamp is conclusive in practice even without a hash
match (the file may differ if the actor rebuilt).

> **Do not hunt `%TEMP%` as the primary location.** The analysis is explicit that the
> drop path is the user's `Downloads` directory. `%TEMP%` is checked above only as a
> secondary sweep.

### macOS / Linux

The loader is never fetched on these platforms, so these artifacts should be absent. A
hit would mean the analysis is incomplete — preserve and escalate.

```bash
find "$HOME" /tmp /var/tmp -maxdepth 4 \
  \( -name "main.exe" -o -name "abe_payload.dll" -o -name "wincfg" \) 2>/dev/null \
  && echo "UNEXPECTED - loader artifact on a non-Windows host; preserve and escalate" \
  || echo "loader artifacts: clean (expected on this OS)"
```

---

## Check 2: The StubMaker Stub Artifacts (all platforms)

The install hook writes fake compiler stand-ins. These are the campaign's namesake and
they are left on disk by the gem build — **on every platform**, because the stubs are
written before the Windows-only branch.

```bash
# Look inside installed gem trees and build dirs for the fake toolchain
for dir in "$HOME/.gem" "$(ruby -e 'print Gem.dir' 2>/dev/null)" "$HOME/.bundle" ./vendor/bundle; do
  [ -n "$dir" ] && [ -d "$dir" ] || continue
  find "$dir" -maxdepth 8 \( -name "make_stub" -o -name "make_stub.bat" \) 2>/dev/null \
    | while read -r f; do echo "FOUND - StubMaker stub: $f"; done
done

# An extconf.rb that requires an install_core runner is the hook signature
for dir in "$HOME/.gem" "$(ruby -e 'print Gem.dir' 2>/dev/null)"; do
  [ -n "$dir" ] && [ -d "$dir" ] || continue
  grep -rlE "install_core/runner|InstallCore::Runner" "$dir" 2>/dev/null \
    | while read -r f; do echo "FOUND - malicious extconf runner: $f"; done
done
echo "(stub artifact scan complete)"
```

**Windows:**

```powershell
Get-ChildItem "$env:USERPROFILE\.gem", "$env:LOCALAPPDATA\gem" -Recurse -ErrorAction SilentlyContinue `
  -Include 'make_stub','make_stub.bat' | Select-Object FullName, CreationTime
```

Any `make_stub` / `make_stub.bat` is a **high-confidence** indicator — legitimate gems do
not manufacture no-op compiler stubs.

---

## Check 3: Package-Manager Cache (all platforms — proves the install ran)

**The most reliable "did the install happen here" check, and it works identically on
every OS.** All 53 packages are removed from both registries, so a fresh install fails
today — but the cached tarball from the original install persists.

```bash
# --- npm ---
# ONE global listing, then grep. Timed on a real machine: `npm ls -g <pkg>` costs ~600ms of
# node startup per call, so looping it over 37 names takes ~22s; this takes ~260ms.
npm ls -g --depth=0 --parseable 2>/dev/null | grep -E "/(${NPM_RE})$" \
  && echo "  ^ globally installed (see above)" || echo "no malicious global npm packages"

if [ -d "$HOME/.npm/_cacache" ]; then
  grep -rlE "registry\.npmjs\.org/(${NPM_RE})" "$HOME/.npm/_cacache/index-v5" 2>/dev/null \
    && echo "  ^ COMPROMISED tarball referenced in npm cache" \
    || echo "npm cache: clean"
  # POSITIVE CONTROL — prove the cache grep works before trusting "clean"
  echo -n "  positive control (grep cache index for a real package): "
  grep -rlE "registry\.npmjs\.org/lodash" "$HOME/.npm/_cacache/index-v5" 2>/dev/null | head -1 \
    | sed 's/.*/FOUND -> grep works/' || echo "NO HIT -> control inconclusive, cache may be sparse"
fi

for d in "$HOME/.cache/yarn" "$HOME/Library/Caches/Yarn" "$(pnpm store path 2>/dev/null)"; do
  [ -n "$d" ] && [ -d "$d" ] && find "$d" -maxdepth 6 2>/dev/null | grep -iE "(${NPM_RE})" \
    && echo "  ^ COMPROMISED artifact in $d"
done

# --- RubyGems / Bundler ---
for g in $GEM_PKGS; do
  gem list -e "$g" 2>/dev/null | grep -v "^$" | grep -q . && echo "  ^ installed gem: $g"
done

for dir in "$HOME/.gem" "$(ruby -e 'print Gem.dir' 2>/dev/null)" "$HOME/.bundle" ./vendor/bundle; do
  [ -n "$dir" ] && [ -d "$dir" ] && find "$dir" -name "*.gem" 2>/dev/null \
    | grep -iE "(${GEM_RE})" && echo "  ^ COMPROMISED tarball in $dir"
done
echo "(cache scan complete)"
```

**Windows equivalent:**

```powershell
$cacache = "$env:APPDATA\npm-cache\_cacache"
if (Test-Path $cacache) {
  Get-ChildItem "$cacache\index-v5" -Recurse -File -ErrorAction SilentlyContinue |
    Select-String -Pattern "registry.npmjs.org/($($NpmPkgs -join '|'))" |
    ForEach-Object { Write-Host "FOUND - compromised tarball in npm cache: $($_.Path)" -ForegroundColor Red }
}
```

A cached tarball or installed package means **the install ran on this machine**. On
Windows, proceed as compromised. On macOS/Linux, it means this host beaconed.

---

## Check 4: Local Project Manifests and Lock Files

**First, discover where code actually lives.** Do not assume — a wrong root is the
easiest way to get a false all-clear (a dry-run of this playbook found the template
default `~/projects` did not exist at all, with real repos under `~/dev/<org>/<repo>/`):

```bash
for c in "$HOME/dev" "$HOME/projects" "$HOME/src" "$HOME/code" "$HOME/work" \
         "$HOME/repos" "$HOME/git" "$HOME/Documents" "$HOME/Developer"; do
  [ -d "$c" ] && echo "candidate root: $c"
done
find "$HOME" -maxdepth 4 -name ".git" -type d 2>/dev/null \
  | sed 's|/[^/]*/\.git$||' | sort -u | head -20
```

Set `PROJECT_ROOTS` from that, then scan:

```bash
PROJECT_ROOTS="$HOME/dev $HOME/projects"   # <-- set from the discovery step above

for root in $PROJECT_ROOTS; do
  [ -d "$root" ] || { echo "SKIP (does not exist): $root"; continue; }

  # POSITIVE CONTROL: confirm the find reaches real files before trusting a clean result
  n=$(find "$root" -maxdepth 8 \
        \( -name "package.json" -o -name "package-lock.json" -o -name "yarn.lock" \
           -o -name "pnpm-lock.yaml" -o -name "Gemfile" -o -name "Gemfile.lock" \) \
        -not -path "*/node_modules/*" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
  echo "$root: $n manifest/lock files reached"
  [ "$n" -eq 0 ] && echo "  ⚠️  ZERO files reached — 'clean' here is MEANINGLESS. Fix the root or raise -maxdepth."

  find "$root" -maxdepth 8 \
    \( -name "package.json" -o -name "package-lock.json" -o -name "yarn.lock" \
       -o -name "pnpm-lock.yaml" -o -name "Gemfile" -o -name "Gemfile.lock" \) \
    -not -path "*/node_modules/*" -not -path "*/vendor/*" 2>/dev/null | while read -r f; do
    hit=$(grep -oE "(${ALL_RE})" "$f" 2>/dev/null | sort -u | tr '\n' ' ')
    [ -n "$hit" ] && echo "MALICIOUS PACKAGE NAMED: $f  ->  $hit"
  done
done
echo "(manifest scan complete)"
```

> **`-maxdepth 8`, not 6.** A common layout nests two levels before the repo
> (`~/dev/<org>/<repo>/`), and monorepo subprojects add more.

Any hit is a finding — these names have no legitimate use. A **lock file** naming one is
stronger: the package was actually resolved and downloaded, not merely typed.

> **False-positive note:** the grep is scoped to manifest and lock files deliberately.
> Do not widen it — `comand`, `comander`, `chalk-lib` and `commander-lib` occur as
> ordinary misspellings and plausible strings in comments, READMEs and commit messages.


### Windows (PowerShell)

Bash is unavailable on a plain Windows host, so this is the native form. It keeps the two
behaviours that matter: **discover the roots** rather than assume them, and **print a file count**
before any verdict.

```powershell
# --- 1. Discover project roots. A wrong root is the easiest way to get a false all-clear. ---
$candidates = @("$env:USERPROFILE\dev", "$env:USERPROFILE\projects", "$env:USERPROFILE\src",
                "$env:USERPROFILE\source", "$env:USERPROFILE\source\repos", "$env:USERPROFILE\code",
                "$env:USERPROFILE\work", "$env:USERPROFILE\repos", "$env:USERPROFILE\git",
                "$env:USERPROFILE\Documents", "C:\src", "C:\dev") |
              Where-Object { Test-Path $_ }
$candidates | ForEach-Object { Write-Host "candidate root: $_" }

# Cross-check against where .git directories actually are
Get-ChildItem $env:USERPROFILE -Directory -Filter ".git" -Recurse -Depth 4 -Force -ErrorAction SilentlyContinue |
  ForEach-Object { Split-Path $_.FullName -Parent } | Sort-Object -Unique | Select-Object -First 20

# --- 2. Scan. Set $ProjectRoots from the discovery output above. ---
$ProjectRoots = @("$env:USERPROFILE\dev")
$manifests = @('package.json','package-lock.json','yarn.lock','pnpm-lock.yaml','Gemfile','Gemfile.lock')

foreach ($root in $ProjectRoots) {
  if (-not (Test-Path $root)) { Write-Host "SKIP (does not exist): $root"; continue }

  # -Filter is provider-level and far faster than filtering after a full recurse
  $files = @()
  foreach ($m in $manifests) {
    $files += Get-ChildItem $root -Recurse -Depth 8 -File -Filter $m -Force -ErrorAction SilentlyContinue
  }
  $files = $files | Where-Object { $_.FullName -notmatch '\\(node_modules|vendor)\\' }

  # POSITIVE CONTROL: a count of zero makes "clean" meaningless
  Write-Host "$root : $($files.Count) manifest/lock files reached"
  if ($files.Count -eq 0) {
    Write-Host "  ZERO files reached - 'clean' here is MEANINGLESS. Fix the root or raise -Depth." -ForegroundColor Yellow
  }

  foreach ($f in $files) {
    $hit = Select-String -LiteralPath $f.FullName -Pattern $AllRe -AllMatches -ErrorAction SilentlyContinue |
           ForEach-Object { $_.Matches.Value } | Sort-Object -Unique
    if ($hit) {
      Write-Host "MALICIOUS PACKAGE NAMED: $($f.FullName)  ->  $($hit -join ' ')" -ForegroundColor Red
    }
  }
}
Write-Host "(manifest scan complete)"
```

---

## Check 5: Network Indicators — the beacon is the key artifact

Two distinct endpoints, **both still live as of 2026-08-19**:

- **`193.70.34.101:20099`** — the platform beacon. **Fires on Windows, macOS and Linux.**
  On non-Windows hosts this is the *only* network artifact.
- **`dresslee.com:20027`** — the exfil webhook. Windows only, and only after theft.

### All platforms — hosts file and connections

```bash
grep -iE "dresslee|193\.70\.34\.101" /etc/hosts 2>/dev/null && echo "FOUND - in hosts file" || echo "not in hosts file"
netstat -an 2>/dev/null | grep -E "193\.70\.34\.101|:20099|:20027" \
  && echo "FOUND - active connection to StubMaker C2" || echo "no active C2 connection"
```

### macOS — DNS + connection history

> **Bound the window and expect this to be slow.** Timed on a real machine:
> `log show --last 14d` had **not returned after 25 seconds** and kept going — the unified
> log is expensive to query over long spans. Always pass `--start`/`--end` scoped to the
> exposure window rather than `--last 14d`. Also note macOS unified-log **retention is
> usually only a few days**, so on 2026-08-19 an August-15 DNS record has very likely
> already rolled off. Treat an empty result as "no data", not "no beacon", and get the
> answer from proxy/firewall logs instead (Phase 3 of [playbook.md](playbook.md)).

```bash
# Scoped to the exposure window. Add `| head -20` and be patient; this can still take ~30s.
log show --start "2026-08-15" --end "2026-08-18" \
  --predicate 'composedMessage CONTAINS "dresslee" OR composedMessage CONTAINS "193.70.34.101"' \
  2>/dev/null | head -20 || echo "log show: no data in retention window"
```

If you need a cheap first pass, check the live DNS cache and current connections instead —
both return instantly:

```bash
dscacheutil -cachedump -entries Host 2>/dev/null | grep -iE "dresslee" || echo "not in live DNS cache"
lsof -nP -iTCP 2>/dev/null | grep -E "193\.70\.34\.101|:20099|:20027" || echo "no live C2 socket"
```

### Linux

```bash
journalctl --since "2026-08-15" 2>/dev/null | grep -E "dresslee|193\.70\.34\.101" | head -20
```

### Windows

```powershell
Get-DnsClientCache -ErrorAction SilentlyContinue |
  Where-Object { $_.Entry -match 'dresslee|gofile|ipify' } | Select-Object Entry, Data

Get-NetTCPConnection -ErrorAction SilentlyContinue |
  Where-Object { $_.RemoteAddress -eq '193.70.34.101' -or $_.RemotePort -in 20099,20027 } |
  Select-Object RemoteAddress, RemotePort, State, OwningProcess
```

> **`193.70.34.101` or `dresslee.com` in DNS cache, connection history or a proxy log is
> a strong indicator** — there is no legitimate reason for a developer machine to reach
> either. **`gofile.io` or `api.ipify.org` alone is NOT a finding** — both are widely used
> legitimately. Escalate on Gofile only alongside a Check 1, 2 or 3 hit.
>
> Because the beacon is plaintext HTTP on port 20099, your **proxy or firewall logs** are
> often a better source than the host itself — the host may have rotated its DNS cache
> long ago.

---

## Check 6: Shell History

```bash
grep -nE "(npm (i|install|add)|gem install|bundle add) .*(${ALL_RE})" \
  ~/.zsh_history ~/.bash_history ~/.local/share/fish/fish_history 2>/dev/null \
  || echo "No malicious install commands in shell history"
```

**Windows (PowerShell history):**

```powershell
$h = (Get-PSReadlineOption).HistorySavePath
if (Test-Path $h) { Select-String -Path $h -Pattern "(npm (i|install|add)|gem install|bundle add).*($AllRe)" }
```

Often the check that identifies **who** typed the name and **when** — the detail that
turns a manifest hit into a specific machine.

---

## Check 7: Browser Credential-Store Exposure (Windows only)

If Check 1, 2 or 3 confirmed the install ran on a **Windows** machine, assume the stores
below were read **and decrypted** — defeating App-Bound Encryption is the whole purpose of
`abe_payload.dll`. Enumerate profiles to scope the rotation in
[playbook.md](playbook.md) Hardening 2.

```powershell
$roots = @(
  "$env:LOCALAPPDATA\Google\Chrome\User Data",
  "$env:LOCALAPPDATA\Microsoft\Edge\User Data",
  "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data",
  "$env:LOCALAPPDATA\Vivaldi\User Data",
  "$env:LOCALAPPDATA\Yandex\YandexBrowser\User Data",
  "$env:APPDATA\Opera Software\Opera Stable",
  "$env:APPDATA\Opera Software\Opera GX Stable"
)
foreach ($r in $roots) {
  if (Test-Path $r) {
    Get-ChildItem $r -Directory -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile*' } |
      ForEach-Object {
        Write-Host "PROFILE: $($_.FullName)"
        foreach ($db in 'Login Data','Network\Cookies','Web Data') {
          if (Test-Path (Join-Path $_.FullName $db)) { Write-Host "   $db present (assume exfiltrated)" }
        }
      }
  }
}

# Telegram Desktop session (standard + UWP locations)
foreach ($tg in @("$env:APPDATA\Telegram Desktop\tdata",
                  "$env:LOCALAPPDATA\Packages\TelegramMessengerLLP.TelegramDesktop_*\LocalCache\Roaming\Telegram Desktop\tdata")) {
  if (Test-Path $tg) { Write-Host "Telegram tdata present (assume exfiltrated - terminate other sessions)" }
}

# Wallet directories
Get-ChildItem $env:APPDATA, $env:LOCALAPPDATA -Recurse -Depth 3 -Directory -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match 'MetaMask|Coinbase|Phantom|Solflare|Exodus|Electrum|Atomic|Guarda|Trezor|Monero|Wallet' } |
  Select-Object FullName
```

**These profiles define rotation scope, not evidence** — their presence is expected on
any developer machine. Use them only once Check 1/2/3 establishes the install ran.

Note the stealer also reads `credit_cards` **and `local_stored_cvc`** — treat saved cards
as fully compromised, CVC included.

---

## Check 8: AI Agent Conversation Logs

AI coding agents store conversation histories including full tool output — every shell
command and its stdout/stderr. If an agent ran an install during the window, the resolved
names and any IOC-bearing output are captured there. These logs persist far longer than
npm or gem logs, and often record ad-hoc installs never committed anywhere.

| Tool | Session log location | Format |
|---|---|---|
| Claude Code | `~/.claude/projects/**/*.jsonl` | JSONL — tool calls in `content[].input.command` |
| Cursor | `~/.cursor/conversations/` or `~/.cursor-server/data/` | JSON |
| Windsurf | `~/.windsurf/` or `~/.codeium/` | JSON |
| GitHub Copilot Chat | `~/.vscode/` (output channel logs) | Text |

> **Do not append `|| echo "no matches"` to an `xargs grep` pipeline.** `xargs` exits
> non-zero (123) when *any* batched `grep` finds nothing, so the `||` branch fires even when
> other batches matched — a dry-run of exactly that construct printed nine matching files
> and then "No IOC matches in Claude Code sessions" directly underneath. Capture the output
> and test it instead:

```bash
matches=$(find ~/.claude/projects -name "*.jsonl" -print0 2>/dev/null \
  | xargs -0 grep -lE "(${ALL_RE})|193\.70\.34\.101|dresslee\.com|abe_payload|make_stub|wincfg" 2>/dev/null)

if [ -n "$matches" ]; then
  echo "$matches" | sed 's|^|  candidate: |'
  echo "  ^ Expect this list to include the session running this playbook — it has read every"
  echo "    IOC string above. Use the classifier below to separate real installs from mentions."
else
  echo "No IOC matches in Claude Code sessions"
fi
```

This bash pass is only a **pre-filter** — it has no self-pollution exclusion. The Python
classifier below is the one that skips the current session and separates `INVESTIGATE` from
`REFERENCE ONLY`. On a real machine this grep took ~35s across all transcripts; that is the
slowest step in this playbook.

```python
import json, glob, os

PKG_STRINGS = [
    'axois-http','axious-core','chalk-core','chalk-lib','chalk-util','chalk-es',
    'comand','comander-cli','comanderjs','commandorjs','commandor-cli','commandor-core',
    'comander-lib','commandor-lib','commander-lib','loadashjs','lodash-lib','ladash-cli',
    'lodahsjs','lodsh-cli','lodahs-cli','lodhash-cli','typescirpt-cli','typscript-cli',
    'typesript-cli','typscript-core','typescriptt-cli','typescrip-cli','typescipt-cli',
    'tyepescript-cli','typescirpt-core','tyepescript-core','typesript-core',
    'typescipt-core','typescriptt-core','raectjs','testingsmthb1g',
    'ubnuler','ubnlder','ri18nr','reaker','rakier','orakw','joxn','ise18n','ioe18n',
    'ie18u','iai8n','i1l8n','i18om','activesupmport','brumdler','brundlef',
]
HOST_IOCS = ['193.70.34.101', 'dresslee.com', 'abe_payload.dll', 'make_stub',
             'wincfg', 'bebraz1', 'qPzM50V1AKG0rVlH']
INSTALL_COMMANDS = ['npm install', 'npm i ', 'npm add', 'yarn add', 'pnpm add',
                    'gem install', 'bundle install', 'bundle add', 'bundle update']

# --- Self-pollution exclusion ---
# CLAUDE_SESSION_FILE is often NOT set (verified unset on a real machine), so relying on it
# alone silently disables the exclusion. Fall back to excluding the most recently modified
# transcript, which is the live session in practice.
# Dedupe by realpath. The same transcript is commonly reachable under two project-dir names
# (e.g. a workdir that is itself a symlink), which otherwise double-reports every hit and
# makes the scan count look inconsistent with `find | wc -l`.
_seen, paths = set(), []
for p in glob.glob(os.path.expanduser('~/.claude/projects/**/*.jsonl'), recursive=True):
    if not os.path.exists(p):
        continue
    rp = os.path.realpath(p)
    if rp in _seen:
        continue
    _seen.add(rp)
    paths.append(p)

CURRENT = os.environ.get('CLAUDE_SESSION_FILE', '')
excluded = set()
if CURRENT and os.path.exists(CURRENT):
    excluded = {os.path.realpath(CURRENT)}
elif paths:
    newest = max(paths, key=lambda p: os.path.getmtime(p))
    excluded = {os.path.realpath(newest)}
    print(f"[self-pollution] CLAUDE_SESSION_FILE unset; excluding newest transcript: {newest}")

scanned = skipped = 0
for fpath in paths:
    if os.path.realpath(fpath) in excluded:
        continue
    hits, has_install = set(), False
    try:
        fh = open(fpath, errors='replace')
    except OSError:
        # Transcripts rotate while this runs; a vanished path must not abort the whole scan.
        skipped += 1
        continue
    scanned += 1
    for line in fh:
        try:
            obj = json.loads(line)
        except Exception:
            continue
        text = json.dumps(obj)
        for ioc in PKG_STRINGS + HOST_IOCS:
            if ioc in text:
                hits.add(ioc)
        content = obj.get('content', '')
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    cmd = block.get('input', {}).get('command', '') or ''
                    if any(x in cmd.lower() for x in INSTALL_COMMANDS):
                        has_install = True
    fh.close()
    if hits and has_install:
        print(f"INVESTIGATE: {fpath}\n    matched: {sorted(hits)}")
    elif hits:
        print(f"REFERENCE ONLY: {fpath}\n    matched: {sorted(hits)[:8]}"
              + (f" (+{len(hits)-8} more)" if len(hits) > 8 else ""))

print(f"[scan] {scanned} unique transcripts scanned, {len(excluded)} excluded as self, "
      f"{skipped} unreadable")
```

**Check the `[scan]` line before believing the result.** Compare it against the number of
*unique* transcripts, not the raw file count — the same transcript is often reachable under
two project-dir names:

```bash
find ~/.claude/projects -name '*.jsonl' | wc -l                                  # raw paths
find ~/.claude/projects -name '*.jsonl' -exec realpath {} \; | sort -u | wc -l   # unique files
```

On the machine this was validated against those were **201** and **131**, and the script
reported `130 scanned + 1 excluded` — complete. Comparing 130 against the raw 201 would have
raised a false alarm.

Two failure modes this line exists to catch, both found during validation: an earlier version
**crashed with `FileNotFoundError`** partway through (a transcript rotated between `glob` and
`open`), printing six results then exiting — which reads exactly like a completed scan; and it
**double-reported** every hit because duplicate paths were not deduped.

**Interpreting results:**

- **`INVESTIGATE`** — a malicious name AND an install command in the same session. Open it
  and look for `added <name>@1.0.0`, `Installing <gem>`, `Building native extensions`, a
  GitHub release download, or a POST to `193.70.34.101`.
- **`REFERENCE ONLY`** — mentions the strings but never installed. Typically a
  conversation *about* the incident, or a session running this playbook. Not compromise.

> **Self-pollution:** the session running this playbook will always match on the IOC
> strings it just read. The script skips `$CLAUDE_SESSION_FILE`; if that is unset, identify
> and exclude the current transcript manually before believing a hit.


### Windows (PowerShell)

Use this only when Python is unavailable on the host. **Prefer the Python classifier above** — it
parses each JSONL record properly, whereas this matches at line level and can over-report
`hasInstall` when an install command appears in prose rather than in a tool call. It keeps the
three behaviours that matter: dedupe by resolved path, exclude the current session, and never
abort the whole scan on one unreadable file.

```powershell
$projRoot = "$env:USERPROFILE\.claude\projects"
if (-not (Test-Path $projRoot)) {
  Write-Host "No Claude Code transcripts found"
} else {
  $PkgStrings  = $NpmPkgs + $GemPkgs
  $HostIocs    = @('193.70.34.101','dresslee.com','abe_payload.dll','make_stub','wincfg','bebraz1','qPzM50V1AKG0rVlH')
  $AllIocs     = $PkgStrings + $HostIocs
  $InstallCmds = @('npm install','npm i ','npm add','yarn add','pnpm add','gem install','bundle install','bundle add','bundle update')

  # Dedupe by resolved path - the same transcript is often reachable under two project-dir names
  $seen = @{}; $paths = @()
  foreach ($f in Get-ChildItem $projRoot -Recurse -File -Filter *.jsonl -ErrorAction SilentlyContinue) {
    try { $rp = (Resolve-Path -LiteralPath $f.FullName -ErrorAction Stop).ProviderPath } catch { continue }
    if ($seen.ContainsKey($rp)) { continue }
    $seen[$rp] = $true; $paths += $f
  }

  # Self-pollution exclusion. CLAUDE_SESSION_FILE is often unset, so fall back to the newest file.
  $excluded = @{}
  if ($env:CLAUDE_SESSION_FILE -and (Test-Path $env:CLAUDE_SESSION_FILE)) {
    $excluded[(Resolve-Path -LiteralPath $env:CLAUDE_SESSION_FILE).ProviderPath] = $true
  } elseif ($paths.Count -gt 0) {
    $newest = $paths | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $excluded[$newest.FullName] = $true
    Write-Host "[self-pollution] CLAUDE_SESSION_FILE unset; excluding newest transcript: $($newest.FullName)"
  }

  $scanned = 0; $skipped = 0
  foreach ($f in $paths) {
    if ($excluded.ContainsKey($f.FullName)) { continue }
    try { $lines = Get-Content -LiteralPath $f.FullName -ErrorAction Stop } catch { $skipped++; continue }
    $scanned++
    $hits = @{}; $hasInstall = $false
    foreach ($line in $lines) {
      foreach ($ioc in $AllIocs) { if ($line -like "*$ioc*") { $hits[$ioc] = $true } }
      if (-not $hasInstall -and $line -like '*"command"*') {
        foreach ($c in $InstallCmds) { if ($line -like "*$c*") { $hasInstall = $true; break } }
      }
    }
    if ($hits.Count -gt 0 -and $hasInstall) {
      Write-Host "INVESTIGATE: $($f.FullName)" -ForegroundColor Red
      Write-Host "    matched: $(($hits.Keys | Sort-Object) -join ', ')"
    } elseif ($hits.Count -gt 0) {
      Write-Host "REFERENCE ONLY: $($f.FullName)"
      Write-Host "    matched: $((($hits.Keys | Sort-Object) | Select-Object -First 8) -join ', ')"
    }
  }
  Write-Host "[scan] $scanned unique transcripts scanned, $($excluded.Count) excluded as self, $skipped unreadable"
}
```

---

## Results Summary

| # | Check | IOC | Weight | Applies to |
|---|---|---|---|---|
| 1 | Loader / stealer artifacts | `Downloads\main.exe`, `abe_payload.dll`, hash match | **conclusive** | Windows |
| 2 | StubMaker stub artifacts | `make_stub`, `make_stub.bat`, `InstallCore::Runner` | **high** | all |
| 3 | Package-manager cache | malicious tarball in `_cacache` / gem cache | **strong** (proves install ran) | all |
| 4 | Manifests / lock files | malicious name present | strong (lock) / moderate (manifest) | all |
| 5 | Network — beacon | `193.70.34.101:20099` | **strong** | **all** |
| 5 | Network — exfil | `dresslee.com:20027` | **strong** | Windows |
| 5b | Network — corroborating | `gofile.io`, `api.ipify.org` | weak — never alone | Windows |
| 6 | Shell history | install command naming a listed package | strong (who + when) | all |
| 7 | Browser stores | Chromium profiles, Telegram `tdata`, wallets | scope, not evidence | Windows |
| 8 | Agent conversation logs | IOC + install in the same session | strong | all |

### Verdict guide

- **Windows + any Check 1 / 2 / 5 hit** → confirmed compromise. Go to the response steps.
- **Windows + Check 3 / 4 / 6 / 8 hit, Checks 1 and 5 clean** → the install ran and the
  payload very likely executed. **Persistence is confirmed absent and the stealer
  finishes and exits, so clean artifacts do NOT clear the host.** Treat as compromised
  and rotate.
- **macOS / Linux + any hit** → the install ran and this host **beaconed** its platform
  and public-facing IP. No credential theft; no rotation needed for this host. Use it as a
  routing signal — find the Windows machines the same developer used and run this there.
- **All checks clean, and Check 3's positive control confirmed the cache scan works, and
  Check 4 reached a non-zero file count** → no evidence this machine was involved.

### If any check returns "found" on Windows

1. **Isolate the machine.** The beacon and exfil endpoints are **still live**, so isolate
   before anything else.
2. **Preserve evidence first** — copy `Downloads\main.exe`, `abe_payload.dll`, the
   `make_stub` files, cache entries, and relevant shell/agent logs before deleting.
   Record SHA-256 of each.
3. **Invalidate browser and Telegram sessions server-side** — *before* password rotation.
   ABE-decrypted cookies bypass MFA and survive a password change. Force IdP
   re-authentication and revoke refresh tokens for every account used on this machine.
4. **Rotate every browser-saved password from a clean device** (Check 7 lists profiles).
   Never from the compromised host.
5. **Move cryptocurrency to a newly generated wallet** using a trusted device. A leaked
   BIP-39 seed phrase cannot be rotated.
6. **Terminate all other Telegram sessions.**
7. **Reissue saved payment cards** — numbers and CVCs were both taken.
8. **Rotate developer credentials** — cloud, git and registry tokens, SSH keys, and any
   secret this user could reach from CI.
9. **Remove the packages and purge caches** — [playbook.md](playbook.md) Hardening 1.
10. **Audit for attacker-created persistence in the accounts** — see
    [playbook.md](playbook.md) 5c. The host has no implant, but a PAT or access key minted
    with a stolen session outlives every rotation above.
11. **Consider re-imaging.** A stealer that ran with user privileges and decrypted the
    browser credential store read everything that user could read.
