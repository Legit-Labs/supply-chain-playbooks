# AsyncAPI / Miasma Compromise — Workstation Investigation Playbook

Playbook for checking whether a developer workstation (or self-hosted CI runner) was affected by the July 14, 2026 `@asyncapi` npm compromise. Run this on each machine that may have installed or updated `@asyncapi/*` — and then run the generator, parser, tests, or any code importing it — during the exposure window.

> **Designed for AI agent execution.** Each check is self-contained with commands to run and expected output to interpret.

> **⚠️ Import-time trigger.** The payload runs when a poisoned package is **imported/`require()`d**, not from a `postinstall` hook. `--ignore-scripts` provides no protection. A machine is at risk if it *loaded* an affected version — e.g. ran `asyncapi generate ...`, executed tests, or started a service that pulls `@asyncapi/specs` transitively.

---

## Incident Reference

| Field | Value |
|---|---|
| Malicious versions | `@asyncapi/generator@3.3.1`, `@asyncapi/generator-helpers@1.1.1`, `@asyncapi/generator-components@0.7.1`, `@asyncapi/specs@6.11.2`, `@asyncapi/specs@6.11.2-alpha.1` |
| Safe versions | `@asyncapi/generator@3.3.0`, `@asyncapi/generator-helpers@1.1.0`, `@asyncapi/generator-components@1.0.0` (or `0.7.0`), `@asyncapi/specs@6.11.1` |
| Exposure window | `2026-07-14T06:00:00Z` to `2026-07-14T12:30:00Z` (padded) |
| Dropped loader | `sync.js` under an OS-specific `NodeJS/` dir (see Check 1) |
| Runtime lock file | `~/.config/.miasma/run/node.lock` |
| Persistence (Linux) | `miasma-monitor.service` |
| Persistence (Windows) | HKCU `...\Run` value `miasma-monitor` |
| Service advertisement | mDNS `_miasma._tcp` |
| HTTP C2 | `85.137.53.71` (`:8080` cmd, `:8081` upload, `:8091` mgmt) |
| Stage-2 IPFS CIDs | `QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9`, `Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf` |
| Token exfil | `rentry.co/elzotebo999` |
| Nostr relays | `wss://relay.damus.io`, `wss://relay.nostr.com/` |
| Injected-file SHA-256 | specs `index.js`: `d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7` (alpha) / `9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b` (stable); generator `validator.js`: `bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4`; generator-components `ErrorHandling.js`: `082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab`; generator-helpers `utils.js`: `34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1` |

For full incident details, see [playbook.md](playbook.md).

---

## Setup

```bash
# Malicious version markers (grep pattern; anchored to package name to cut noise)
VERSIONS_RE='@asyncapi/generator[^-].*3\.3\.1|@asyncapi/generator-helpers.*1\.1\.1|@asyncapi/generator-components.*0\.7\.1|@asyncapi/specs.*6\.11\.2(-alpha\.1)?'

# Network / payload IOCs
C2_IP="85.137.53.71"
EXFIL="rentry.co/elzotebo999"
CID_GEN="QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9"
CID_SPECS="Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf"

# Injected-file SHA-256 (search caches / node_modules by hash)
SHA_SPECS_ALPHA="d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7"
SHA_SPECS_STABLE="9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b"
SHA_GEN="bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4"
SHA_COMP="082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab"
SHA_HELP="34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1"

# Combined IOC pattern for text logs
IOC_RE="${C2_IP}|${EXFIL}|${CID_GEN}|${CID_SPECS}|NodeJS/sync\.js|miasma-monitor|_miasma\._tcp|\.miasma/run"
```

---

## Check 1: Dropped Loader (`sync.js`) & Runtime Lock

The second-stage loader is written to an OS-specific `NodeJS/` directory, with a fallback under `~/.config`. The Miasma runtime also keeps a lock file.

### macOS
```bash
for p in "$HOME/Library/Application Support/NodeJS/sync.js" "$HOME/.config/NodeJS/sync.js"; do
  [ -f "$p" ] && echo "FOUND — $p (COMPROMISED)" || echo "clean — $p"
done
[ -f "$HOME/.config/.miasma/run/node.lock" ] && echo "FOUND — miasma runtime lock" || echo "clean — no miasma lock"
```

### Linux
```bash
for p in "$HOME/.local/share/NodeJS/sync.js" "$HOME/.config/NodeJS/sync.js"; do
  [ -f "$p" ] && echo "FOUND — $p (COMPROMISED)" || echo "clean — $p"
done
[ -f "$HOME/.config/.miasma/run/node.lock" ] && echo "FOUND — miasma runtime lock" || echo "clean — no miasma lock"
```

### Windows (PowerShell)
```powershell
$paths = @("$env:LOCALAPPDATA\NodeJS\sync.js", "$env:APPDATA\NodeJS\sync.js")
foreach ($p in $paths) { if (Test-Path $p) { "FOUND — $p (COMPROMISED)" } else { "clean — $p" } }
```

If `sync.js` is present, optionally hash it and compare — but its content is downloaded from IPFS and may vary; **presence at these paths is itself the signal.**

---

## Check 2: OS Persistence (`miasma-monitor`)

### macOS — LaunchAgents / LaunchDaemons
```bash
grep -rli "miasma" ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/ 2>/dev/null \
  && echo "FOUND — persistence" || echo "clean"
launchctl list 2>/dev/null | grep -i miasma
```

### Linux — systemd / cron
```bash
systemctl --user status miasma-monitor 2>/dev/null | head -3
ls -la ~/.config/systemd/user/miasma-monitor.service /etc/systemd/system/miasma-monitor.service 2>/dev/null
grep -rli "miasma\|NodeJS/sync.js" /etc/systemd/ ~/.config/systemd/ 2>/dev/null
crontab -l 2>/dev/null | grep -iE "miasma|NodeJS/sync\.js"
```

### Windows — Registry Run keys / Scheduled Tasks
```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" 2>$null | Select-String "miasma"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" 2>$null | Select-String "miasma"
Get-ScheduledTask 2>$null | Where-Object { $_.TaskName -like "*miasma*" -or $_.Actions.Execute -like "*sync.js*" }
```

---

## Check 3: Package-Manager Cache

The malicious tarballs may still sit in the local cache even after `node_modules` was cleaned (they are unpublished from npm, so they won't re-download — the cache is the artifact).

```bash
# npm — content store, searched by injected-file hash
NPM_CACHE=$(npm config get cache 2>/dev/null)
if [ -d "$NPM_CACHE/_cacache" ]; then
  for h in "$SHA_SPECS_ALPHA" "$SHA_SPECS_STABLE" "$SHA_GEN" "$SHA_COMP" "$SHA_HELP"; do
    grep -rl "$h" "$NPM_CACHE/_cacache" 2>/dev/null && echo "FOUND — $h in npm cache" || true
  done
  npm cache ls 2>/dev/null | grep -E "@asyncapi/(specs|generator|generator-helpers|generator-components)" | grep -E "6\.11\.2|3\.3\.1|1\.1\.1|0\.7\.1"
fi

# pnpm
PNPM_STORE=$(pnpm store path 2>/dev/null)
[ -n "$PNPM_STORE" ] && ls "$PNPM_STORE" 2>/dev/null | grep -iE "asyncapi"

# yarn (classic + berry)
ls ~/.yarn/cache ./.yarn/cache 2>/dev/null | grep -iE "asyncapi.*(6.11.2|3.3.1|1.1.1|0.7.1)"
```

---

## Check 4: Lock Files & node_modules in Local Projects

```bash
PROJECT_ROOTS=(~/projects ~/code ~/repos ~/work "$HOME")
for root in "${PROJECT_ROOTS[@]}"; do
  [ -d "$root" ] || continue
  find "$root" -maxdepth 6 \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) \
    -not -path "*/node_modules/*" 2>/dev/null | while read lf; do
      grep -qE "$VERSIONS_RE" "$lf" 2>/dev/null && echo "COMPROMISED: $lf"
  done
done
echo "(lock file scan complete)"

# Injected files present in an installed @asyncapi tree
for root in "${PROJECT_ROOTS[@]}"; do
  [ -d "$root" ] || continue
  find "$root" -path '*/node_modules/@asyncapi/specs/index.js' \
       -o -path '*/node_modules/@asyncapi/generator/lib/templates/config/validator.js' \
       -o -path '*/node_modules/@asyncapi/generator-components/lib/utils/ErrorHandling.js' \
       -o -path '*/node_modules/@asyncapi/generator-helpers/src/utils.js' 2>/dev/null | while read f; do
    echo "check: $f  -> $(shasum -a 256 "$f" 2>/dev/null | awk '{print $1}')"
  done
done
```

Compare any printed hash against the injected-file SHA-256 values in Setup. A match = the malicious version was installed on this machine.

---

## Check 5: Network Indicators

```bash
# Active connections to the HTTP C2
netstat -an 2>/dev/null | grep "85.137.53.71" && echo "FOUND — active C2 connection" || echo "no active C2 connection"
lsof -i -P 2>/dev/null | grep -iE "85\.137\.53\.71|node.*sync"

# hosts file tampering
grep -iE "85\.137\.53\.71|rentry\.co" /etc/hosts 2>/dev/null

# macOS DNS query history
log show --predicate 'process == "mDNSResponder"' --last 7d 2>/dev/null | grep -iE "ipfs\.io|dweb\.link|relay\.damus|relay\.nostr|rentry\.co" | head -20

# Linux systemd-resolved
journalctl -u systemd-resolved --since "2026-07-14" 2>/dev/null | grep -iE "ipfs\.io|dweb\.link|relay\.damus|relay\.nostr|rentry\.co"
```

> IPFS gateways and Nostr relays are shared infrastructure — only escalate on a hit that also involves `85.137.53.71`, a specific CID, or `rentry.co/elzotebo999`.

---

## Check 6: Shell History

```bash
grep -iE "$VERSIONS_RE|asyncapi generate|NodeJS/sync\.js|miasma" \
  ~/.zsh_history ~/.bash_history ~/.local/share/fish/fish_history 2>/dev/null \
  || echo "No relevant references in shell history"
```

---

## Check 7: npm Debug Logs

```bash
NPM_LOGS="${HOME}/.npm/_logs"
if [ -d "$NPM_LOGS" ]; then
  grep -rlE "$VERSIONS_RE" "$NPM_LOGS"/ 2>/dev/null && echo "FOUND — IOC in npm debug logs" || echo "No IOC in npm logs"
else
  echo "No npm log directory"
fi
```

**Limitation:** npm rotates these aggressively; a clean result here doesn't rule out compromise. Checks 1, 2, and 4 are the reliable signals.

---

## Check 8: AI-Agent Conversation Logs

Miasma includes an **AI-tool-poisoning** capability, and agent session logs capture every shell command + output. Scan them — but **exclude the current investigating session**, which will always "hit" on the IOC strings it just read.

| Tool | Session log location |
|---|---|
| Claude Code | `~/.claude/projects/**/*.jsonl` |
| Cursor | `~/Library/Application Support/Cursor/User/History/` (macOS) / `~/.config/Cursor/User/History/` (Linux) |
| Windsurf | `~/.windsurf/` or `~/.codeium/` |
| Copilot CLI | `~/.config/github-copilot/` |

```bash
# Exclude this session's own project dir to avoid self-pollution
CURRENT_SESSION_PROJECT=$(echo "$PWD" | sed 's|/|-|g')
grep -rliE "85\.137\.53\.71|rentry\.co/elzotebo999|${CID_GEN}|${CID_SPECS}|NodeJS/sync\.js|miasma-monitor|@asyncapi/specs.*6\.11\.2" \
  "$HOME/.claude/projects" \
  "$HOME/Library/Application Support/Cursor" \
  "$HOME/.config/github-copilot" 2>/dev/null | \
  grep -v "${CURRENT_SESSION_PROJECT}" | grep -v "paste-cache" | grep -v "file-history"
```

For each remaining hit, open the session and check whether it also **ran** an install/codegen command (`npm install`, `asyncapi generate`, `npm test`) resolving/importing an affected version — co-occurrence in one session is the signal; a discussion-only mention is not.

---

## Results Summary

| Check | IOC | Status |
|---|---|---|
| Dropped loader | `NodeJS/sync.js`, `.miasma/run/node.lock` | found / clean |
| OS persistence | `miasma-monitor` (LaunchAgent / systemd / Run key) | found / clean |
| Package-manager cache | injected-file SHA-256 / malicious versions | found / clean |
| Lock files & node_modules | malicious versions / injected files in local projects | found / clean |
| Network | `85.137.53.71`, CIDs, `rentry.co/elzotebo999` | found / clean |
| Shell history | references to malicious versions / `sync.js` / `miasma` | found / clean |
| npm debug logs | IOC strings in install logs | found / clean |
| Agent conversations | IOC + install/codegen in same session | found / reference only / clean |

### If any check returns "found"

1. **Treat the workstation as compromised.** Rotate every credential stored on or reachable from it — npm tokens (`~/.npmrc`), GitHub PATs, SSH keys, cloud creds, signing keys, and browser-stored npm/GitHub/cloud sessions.
2. **Preserve evidence** (copy `sync.js`, `node.lock`, persistence unit, shell history) before cleanup.
3. **Remove persistence:**
   ```bash
   # macOS
   launchctl bootout gui/$(id -u)/miasma-monitor 2>/dev/null; rm -f ~/Library/LaunchAgents/*miasma* 2>/dev/null
   # Linux
   systemctl --user disable --now miasma-monitor 2>/dev/null; rm -f ~/.config/systemd/user/miasma-monitor.service 2>/dev/null
   # Windows (PowerShell)
   # Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name miasma-monitor
   rm -f ~/.local/share/NodeJS/sync.js "$HOME/Library/Application Support/NodeJS/sync.js" ~/.config/NodeJS/sync.js 2>/dev/null
   rm -rf ~/.config/.miasma 2>/dev/null
   ```
4. **Clean caches:** `npm cache clean --force`; `pnpm store prune`; `yarn cache clean`.
5. **Block C2 at the network edge:** `85.137.53.71`, `rentry.co/elzotebo999`, the two IPFS CIDs.
6. **Consider re-imaging** — Miasma installs multiple persistence + C2-discovery paths; in-place cleaning may miss a foothold. Note the **dead-man's-switch**: revoking the stolen token can trigger a directory wipe, so rotate credentials and remove persistence together, after snapshotting.
