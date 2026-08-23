# crates.io Maintainer Compromise (arrayref, August 2026) — Workstation Investigation Playbook

For a developer checking **their own machine**. Run this if you built Rust code on **20 August 2026** — or if you are not sure whether you did.

For the org-wide investigation (repos, CI logs, self-hosted runners), see [`playbook.md`](./playbook.md).

> **Why persistence matters more than the crate.** The payload installs a Registry Run key (Windows), a LaunchAgent (macOS) or a systemd user service (Linux). Removing the dependency and rebuilding does **not** remove it. Check 2 is the most important check in this file — run it even if every other check comes back clean.

> **Run `cargo audit` first — it is the cheapest check — but do not close on it.** All three poisoned versions now have RustSec advisories, so `cargo audit` flags any `Cargo.lock` that still pins one. Run `cargo audit fetch` first, since a database cached before 2026-08-21 misses them. The catch: the versions were **deleted** rather than yanked, so any rebuild since 20 August rewrote your lock file to a clean version and the run goes green even if you were exposed. A hit is proof; a clean run proves only that nothing is pinned right now. Checks 1–3 are what actually settle it.

---

## Incident Reference

| | |
|---|---|
| **Date** | 2026-08-20, roughly 07:11–09:25 UTC |
| **Poisoned crates** | `arrayref` 0.3.10 · `internment` 0.8.7 · `append-only-vec` 0.1.9 |
| **Safe versions** | `arrayref` ≤ 0.3.9 · `internment` ≤ 0.8.6 · `append-only-vec` ≤ 0.1.8 |
| **Dropper crates (all versions)** | `proc-macro1` · `proc-macro-en` · `aovine` · `arone` · `aronenao` · `tinymember` |
| **Trigger** | `build.rs` build script — runs on `cargo build`, `check`, `test`, `clippy`, `doc`, `install` |
| **Not a trigger** | `cargo fetch`, `cargo tree` — these resolve but do not run build scripts |
| **Payload host / C2** | `23.254.165.112` (ports 9089, 443) · `23.254.167.107` · `23.254.167.216` · netblocks `23.254.164.0/23`, `23.254.165.0/24`, `23.254.167.0/24` |
| **DGA fallback (20–24 Aug)** | `rasGThauFD` · `feVVKIiEiU` · `phrpjTNckF` · `PrOkXLgfjW` · `ackeoTaWtl` · `GAFWVCMAja` · `RNSsddnEgK` · `pfHlVOqEeg` · `aBEcOrkups` · `epOdIaTMaM` — each `.com` |
| **Persistence** | `HKCU` Run key (Windows) · LaunchAgent (macOS) · systemd **user** service (Linux) |

**Did you build Rust that day?** If you genuinely did not touch Rust on 20 August, you are almost certainly unaffected — but still run **Check 1** (Cargo cache) and **Check 2** (persistence). The cache check is cheap and definitive, and a transitive pull through `tiny-skia`/`winit`/`blake3` can happen in a project you do not think of as "a Rust project".

---

## Setup

```bash
# Poisoned versions and dropper crates
export POISONED_RE='arrayref[^0-9]*0\.3\.10|internment[^0-9]*0\.8\.7|append-only-vec[^0-9]*0\.1\.9'
export DROPPER_RE='proc-macro1|proc-macro-en|aovine|aronenao|arone|tinymember'

# Network IOCs — the 16[4-7] range covers all three actor netblocks
export NET_RE='23\.254\.16[4-7]\.|hwsrv-798836\.hostwindsdns\.com|/49890878'

# DGA fallback domains — the only way to spot a host that failed over off the Hostwinds ranges
export DGA_RE='rasGThauFD|feVVKIiEiU|phrpjTNckF|PrOkXLgfjW|ackeoTaWtl|GAFWVCMAja|RNSsddnEgK|pfHlVOqEeg|aBEcOrkups|epOdIaTMaM'

# Dropped-file and stage-2 artifact names
export FILE_RE='rust-setup|rust-crate_0\.[1-4]\.0|MonoService|MonoXpc|AzureKits|ServiceKit'

# Combined pattern for scanning text logs
export ALL_IOC_RE="${POISONED_RE}|${DROPPER_RE}|${NET_RE}|${DGA_RE}|${FILE_RE}"

# Known-malicious SHA-256 hashes
#   .crate archives
# 25ad700976873c76af785cb99b33c48db7df8b81f21d1e9e06b3676b9a9373ae  arrayref-0.3.10.crate
# 61198155da51b838772eecf5bfaac6cbc4dcc388dccc56658fc28a8e831b34d4  proc-macro1-1.0.107.crate
# b5c1b5b0763a8809a644a8f92224653f0aca623a98eecc714d27f74b80fbe436  proc-macro1-1.0.106.crate
# cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568  shared malicious build.rs
#   stage-2 implants — the file NAMES vary, so hash any suspect binary against these
# 408ef22050ffc5a67e005802809026b29f297a8019f8fda91a2afa8e877ba434  Linux x86-64
# 492f2ab86f8d8911adc79c10ec1541704f5311d207d9d799b0d2a57fcc6a4391  Windows x86-64
# c9561a3b00a0fa38b7772675d987f84bd429c55cd024fc08a98245c2d1632848  macOS x86-64
# 74d3447e7cf99c99ea01a16332ec27432dfb0f491e10e67cd118065a60483306  macOS ARM64
```

> `arone` is a substring of `aronenao`, and short enough to appear inside unrelated words. The alternation above puts the longer name first — always read hits in context rather than counting them.

macOS uses `shasum -a 256` where Linux uses `sha256sum`. Substitute as needed.

---

## Check 1: Cargo Cache

**The single most reliable check.** `~/.cargo/registry/cache` keeps the downloaded `.crate` archive even though crates.io deleted the version — so this survives long after build logs have rotated away.

```bash
find "$HOME/.cargo/registry/cache" -type f \
  \( -name 'arrayref-0.3.10.crate' \
     -o -name 'internment-0.8.7.crate' \
     -o -name 'append-only-vec-0.1.9.crate' \
     -o -name 'proc-macro1-*.crate' \
     -o -name 'proc-macro-en-*.crate' \
     -o -name 'aovine-*.crate' \
     -o -name 'arone-*.crate' \
     -o -name 'aronenao-*.crate' \
     -o -name 'tinymember-*.crate' \) 2>/dev/null
```

Also check the unpacked source tree and the sparse-index metadata:

```bash
find "$HOME/.cargo/registry/src" -maxdepth 2 -type d \
  \( -name 'arrayref-0.3.10' -o -name 'internment-0.8.7' \
     -o -name 'append-only-vec-0.1.9' -o -name 'proc-macro1-*' \) 2>/dev/null
find "$HOME/.cargo/registry" -type d -name 'proc-macro1-*' 2>/dev/null
```

> **Use `find`, not a shell glob, throughout this file.** Under zsh (the macOS default), an unmatched glob such as `ls -d ~/.cargo/registry/cache/*/` aborts the command with `no matches found` — and `2>/dev/null` does not suppress it, because zsh fails before `ls` ever runs. A broken command and a clean machine then look identical.

Verify any hit against the published hashes:

```bash
sha256sum <found-file>   # macOS: shasum -a 256 <found-file>
```

**Positive control** — prove the search works before trusting a zero result:

```bash
command -v cargo || echo "cargo not installed on this machine"
find "$HOME/.cargo/registry/cache" -maxdepth 1 -type d 2>/dev/null | head
find "$HOME/.cargo/registry/cache" -name 'serde-*.crate' 2>/dev/null | head -3
```

Three distinct outcomes, and they do not mean the same thing:

- **`cargo` absent and no cache directory** — you never built Rust here. Not affected; you can stop after Check 2.
- **Cache directory present and `serde` (or another common crate) matches** — the search works, so a zero result from the malicious-crate search above is a genuine clean finding.
- **Cache directory missing but `cargo` is installed** — the cache lives elsewhere. Check `$CARGO_HOME` and re-run against that path before concluding anything.

**A hit here means the poisoned crate was downloaded.** It does not by itself prove the build script ran — but treat it as compromise until Check 3 and Check 2 say otherwise.

---

## Check 2: OS Persistence

**Run this even if everything else is clean.** The implant outlives the crate.

### macOS — LaunchAgents / LaunchDaemons

```bash
ls -la ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/ 2>/dev/null

# Anything created on the day of the incident
find ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons \
  -newermt '2026-08-20' ! -newermt '2026-08-22' 2>/dev/null

# Plists referencing the payload artifacts
grep -rlE "$FILE_RE" ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons 2>/dev/null

launchctl list | grep -viE 'com\.apple\.' | head -50
```

### Windows — Registry Run keys and Scheduled Tasks

```powershell
# Run keys — the documented persistence mechanism for this payload
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Format-List
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' | Format-List
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' | Format-List

# Dropped files — includes the .cfg and the ps-<GUID>.ps1 staging script
Get-ChildItem $env:TEMP -Filter 'rust-setup*' -ErrorAction SilentlyContinue
Get-ChildItem $env:TEMP -Filter 'rust-crate_0.*' -ErrorAction SilentlyContinue
Get-ChildItem $env:TEMP -Filter 'ps-*.ps1' -ErrorAction SilentlyContinue

# Persistence script the implant writes under %APPDATA% (operator-chosen folder name)
Get-ChildItem $env:APPDATA -Recurse -Filter '*.ps1' -Depth 2 -ErrorAction SilentlyContinue |
  Where-Object { $_.CreationTime -gt '2026-08-20' -and $_.CreationTime -lt '2026-08-22' }

# Scheduled tasks created around the incident
Get-ScheduledTask | Where-Object { $_.Date -gt '2026-08-19' -and $_.Date -lt '2026-08-22' } |
  Select-Object TaskName, TaskPath, Date

# Startup folder
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
```

### Linux — systemd user units and cron

```bash
# User units created on the day of the incident
find ~/.config/systemd/user /etc/systemd/system /etc/systemd/user \
  -name '*.service' -newermt '2026-08-20' ! -newermt '2026-08-22' 2>/dev/null

systemctl --user list-unit-files --no-pager 2>/dev/null | grep -v '^UNIT FILE'
systemctl --user list-units --type=service --no-pager 2>/dev/null

# Units referencing payload artifacts
grep -rlE "$FILE_RE" ~/.config/systemd/user /etc/systemd/system 2>/dev/null

# cron and autostart
crontab -l 2>/dev/null
ls -la /etc/cron.d/ ~/.config/autostart/ 2>/dev/null

# Shell profile tampering
grep -nE "$FILE_RE" ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc 2>/dev/null
```

### All platforms — stage-2 artifacts

```bash
find "$HOME/.config" -maxdepth 1 \( -name 'AzureKits' -o -name 'ServiceKit' \) 2>/dev/null
find "$HOME" -maxdepth 5 \( -name 'MonoService' -o -name 'MonoXpc' \) 2>/dev/null

# NOTE the -H. On macOS /tmp is a symlink to private/tmp, and find will NOT descend a
# symlinked starting point — without -H this returns nothing even when the file is there.
find -H /tmp /var/tmp -maxdepth 2 \
  \( -name 'rust-setup*' -o -name 'rust-crate_0.[1-4].0' \) 2>/dev/null
```

> **These four artifact names are lower-confidence.** `AzureKits`, `ServiceKit`, `MonoService` and `MonoXpc` come from reports by infected developers, not from the recovered implants, and a variant may use different names. A clean result on the names clears nothing — hash anything suspicious against the four stage-2 hashes in Setup instead.

**Any hit here is a confirmed compromise.** Do not delete it yet — capture the file, its contents and its timestamps first, then follow the remediation steps at the end of this file.

---

## Check 3: Did a Build Actually Run in the Window?

The build script only executes during compilation. Establish whether you compiled anything between **07:00 and 10:00 UTC on 2026-08-20**.

```bash
# Target directories modified that day — evidence of a build
find ~/projects ~/code ~/repos ~/work ~/src "$HOME" -maxdepth 4 -type d -name 'target' \
  -newermt '2026-08-20 07:00' ! -newermt '2026-08-20 10:00' 2>/dev/null

# Compiled build-script output for the dropper — definitive
find ~ -type d -path '*/target/*/build/proc-macro1-*' 2>/dev/null
find ~ -type d -path '*/target/*/build/*' -name 'arrayref-*' 2>/dev/null

# Cargo's own timing/output artifacts from that day
find ~ -path '*/target/*' -name '*.d' -newermt '2026-08-20 07:00' ! -newermt '2026-08-20 10:00' 2>/dev/null | head -20
```

A `target/*/build/proc-macro1-*/` directory is **proof the dropper's build script was compiled and run on this machine**. Treat it as confirmed compromise.

> Timestamps here are in **local time**, while the exposure window is UTC. Convert before filtering, or widen the range to the whole of 20–21 August and narrow afterwards.

---

## Check 4: Lock Files and Manifests in Local Projects

```bash
# Cargo.lock stores name and version on SEPARATE lines — a single-line grep finds nothing.
# Each crate must be paired with ITS OWN bad version: `internment` has a real, clean 0.3.10
# release, which is arrayref's malicious version string. Matching any name against any bad
# version reports a clean lock file as poisoned.
find ~ -name 'Cargo.lock' -not -path '*/target/*' -not -path '*/.cargo/registry/*' 2>/dev/null | \
while read -r lock; do
  for pair in 'arrayref:0\.3\.10' 'internment:0\.8\.7' 'append-only-vec:0\.1\.9'; do
    crate="${pair%%:*}"; ver="${pair##*:}"
    if grep -A1 -E "^name = \"${crate}\"\$" "$lock" 2>/dev/null | \
       grep -qE "^version = \"${ver}\"\$"; then
      echo "POISONED VERSION PINNED: $lock -> ${crate} $(echo "$ver" | tr -d '\\')"
    fi
  done
done

# Dropper crate present in any lock file — always malicious, no version is clean
find ~ -name 'Cargo.lock' -not -path '*/target/*' -not -path '*/.cargo/registry/*' 2>/dev/null | \
  xargs grep -lE "^name = \"($DROPPER_RE)\"" 2>/dev/null

# Manifests declaring an affected crate — check whether the range permits the bad version
find ~ -name 'Cargo.toml' -not -path '*/target/*' -not -path '*/.cargo/registry/*' 2>/dev/null | \
  xargs grep -lE 'arrayref|internment|append-only-vec' 2>/dev/null
```

A caret range such as `arrayref = "0.3"` or `"^0.3.9"` permits 0.3.10. An exact pin `="0.3.9"` does not.

**A lock-file hit alone is not compromise** — it means the version was *pinned*, not that it was ever built. Cross-reference with Check 3.

---

## Check 5: Network Indicators

```bash
# Active connections
lsof -i -n -P 2>/dev/null | grep -E '23\.254\.16[4-7]\.' || echo "no active connections to IOC ranges"
netstat -an 2>/dev/null | grep -E '23\.254\.16[4-7]\.'

# hosts file tampering
grep -nE "$NET_RE|$DGA_RE" /etc/hosts 2>/dev/null

# macOS — DNS cache / unified log. Search the DGA domains too: a host that failed over
# off the Hostwinds ranges shows up ONLY here.
log show --predicate 'process == "mDNSResponder"' --last 7d 2>/dev/null | \
  grep -E "hostwindsdns|23\.254\.16[4-7]\.|$DGA_RE" | head

# Linux — systemd-resolved
resolvectl statistics 2>/dev/null
journalctl -u systemd-resolved --since '2026-08-20' 2>/dev/null | \
  grep -iE "hostwinds|23\.254\.16[4-7]\.|$DGA_RE" | head
```

```powershell
# Windows
Get-NetTCPConnection | Where-Object { $_.RemoteAddress -match '^23\.254\.16[4-7]\.' }
Get-DnsClientCache | Where-Object {
  $_.Entry -like '*hostwindsdns*' -or
  $_.Entry -match 'rasGThauFD|feVVKIiEiU|phrpjTNckF|PrOkXLgfjW|ackeoTaWtl|GAFWVCMAja|RNSsddnEgK|pfHlVOqEeg|aBEcOrkups|epOdIaTMaM'
}
```

**A clean result here is weaker than it looks.** The DNS cache is short-lived and the implant rotates C2 addresses at runtime, so no hits means "not beaconing right now to something I listed" — not "never beaconed". Checks 1–3 carry the verdict.

---

## Check 6: Shell History

```bash
grep -nE 'cargo (build|check|test|clippy|install|update)' ~/.bash_history ~/.zsh_history 2>/dev/null | tail -40
grep -nE "$ALL_IOC_RE" ~/.bash_history ~/.zsh_history ~/.local/share/fish/fish_history 2>/dev/null
```

Most shells do not timestamp history by default, so this establishes *whether* you run cargo builds, not *when*. Use Check 3 for timing.

---

## Check 7: Container Images Built Locally

An image built during the window with a `cargo` build step may carry the payload in a layer.

```bash
docker images --format '{{.Repository}}:{{.Tag}}\t{{.CreatedAt}}' 2>/dev/null | grep '2026-08-20'

# Inspect a suspect image
docker history --no-trunc <image> 2>/dev/null | grep -iE 'cargo|rust'
docker run --rm --entrypoint sh <image> -c \
  'ls -la /tmp/rust-setup 2>/dev/null; find / -name "*.crate" -path "*proc-macro1*" 2>/dev/null' 2>/dev/null
```

Rebuild any affected image with `--no-cache` after pinning safe versions.

---

## Check 8: AI Agent Conversation Logs

If you use an AI coding agent, its session logs record commands it ran and files it read — including any cargo build during the window.

> **⚠️ Self-pollution.** If you are running *this playbook* through an AI agent, that agent's current session transcript contains every IOC string in this file and **will always match**. That is evidence of investigation, not compromise. Exclude the current session first.

```bash
CURRENT_SESSION_PROJECT=$(echo "$PWD" | sed 's|/|-|g')

grep -rliE "$ALL_IOC_RE" \
  "$HOME/.claude/projects" \
  "$HOME/Library/Application Support/Cursor" \
  "$HOME/Library/Application Support/Windsurf" \
  "$HOME/.config/github-copilot" 2>/dev/null | \
  grep -v "${CURRENT_SESSION_PROJECT}" | grep -v 'paste-cache' | grep -v 'file-history'
```

Hits that survive the filter are worth reading: a transcript from an unrelated earlier session showing `cargo build` output containing `Compiling proc-macro1` is a real signal.

---

## Results Summary

| Check | Result |
|---|---|
| 1. Cargo cache (`.crate` files) | ☐ clean ☐ found |
| 2. OS persistence | ☐ clean ☐ found |
| 3. Build ran in window (`target/*/build/proc-macro1-*`) | ☐ no build ☐ built |
| 4. Lock files / manifests | ☐ clean ☐ poisoned version pinned |
| 5. Network indicators | ☐ clean ☐ found |
| 6. Shell history | ☐ clean ☐ cargo build around that date |
| 7. Local container images | ☐ clean ☐ suspect image |
| 8. AI agent logs (self-pollution excluded) | ☐ clean ☐ found |

**Reading the result:**

- **All clean** — you were not affected. The strongest single signal is Check 1 combined with Check 3: no cached `.crate` and no build-script output means the poisoned code never reached this machine.
- **Check 4 only** — a poisoned version is pinned in a lock file but nothing was built from it. Not compromised; update the pin and move on.
- **Check 1 or 3 positive** — the poisoned crate reached the machine. Treat as compromised and follow the steps below.
- **Check 2 positive** — confirmed compromise with an active implant. Highest urgency.

---

## If Any Check Returns "Found"

1. **Do not delete evidence yet.** Capture the persistence entry, dropped files, and their timestamps. Copy them somewhere safe before removal.
2. **Disconnect from the network** if Check 2 or Check 5 is positive.
3. **Report to your security team** with the specific artifacts found.
4. **Remove persistence before touching dependencies** — the Run key / LaunchAgent / systemd unit, then `$HOME/.config/AzureKits`, `$HOME/.config/ServiceKit`, `MonoService`, `MonoXpc`, `/tmp/rust-setup`. Reboot and re-run Check 2 to confirm.
5. **Rotate every credential this machine held**, publishing credentials first — crates.io and registry tokens, signing keys, anything that can publish an artifact, since those turn your incident into your users'. Then SSH keys, cloud credentials, GitHub PATs and `.env` contents. The build script ran with your user's full access.
6. **Reset accounts saved in Chrome, Brave or Edge.** The implant inventories Chromium login origins, usernames and extension IDs — it does **not** decrypt the stored passwords, so this is an enumeration of which accounts you have, not a dump of them. Treat those accounts as known to the attacker and at elevated risk of targeted phishing rather than as already breached.
7. **Clear the Cargo cache** — `rm -rf ~/.cargo/registry/cache ~/.cargo/registry/src` — and pin safe versions: `arrayref = "=0.3.9"`, `internment = "=0.8.6"`, `append-only-vec = "=0.1.8"`.
8. **Consider reimaging.** Stage 2 has been fully analysed — it is a command-driven backdoor that can fetch and run arbitrary further scripts — so what *your* machine actually received depends on what the operator sent it, which cannot be recovered from the binary. For a machine with production access, reimaging is the defensible choice.
