# PostCSS Typosquat → Windows RAT — Workstation Investigation Playbook

Run this on each developer machine that may have imported one of the three malicious
`abdrizak` PostCSS-lookalike packages (disclosed June 2026). The RAT payload is
**Windows-only**, so the host-forensics checks below are Windows-centric — but the
package/cache/lock-file checks apply on any OS (a non-Windows host can still have the
malicious package on disk even though the RAT chain did not run).

> **Designed for AI agent execution.** Each check is self-contained with commands to
> run and expected output to interpret.

> **Trigger reminder:** the payload runs when the package is **imported (`require`)**,
> not on `npm install`. `--ignore-scripts` does not protect. So "package on disk" =
> possible; "RAT artifacts present" (Windows) = confirmed execution.

---

## Incident Reference

| Field | Value |
|---|---|
| Malicious packages | `postcss-minify-selector-parser`, `postcss-minify-selector`, `aes-decode-runner-pro` (all versions) |
| Payload OS | Windows only |
| C2 | `95.216.92.207:8080` |
| Payload host | `nvidiadriver[.]net` (file `winpatch-xd7d.win`) |
| Dropped artifacts | `%TEMP%\winPatch`, `%TEMP%.store`, `%TEMP%.host`, `settings.ps1`, `update.vbs`, `dll.zip`, `chost.exe`, `loader.py` |
| Registry persistence | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value `csshost` |
| RAT module hashes (SHA-256) | `164e322d6fbc62e254d73583acd7f39444c884d3f5e6a5d27db143fc25bc88b3`, `50ffce607867d8fa8eaf6ef5cd25a3c0e7e4415e881b9e55c04a67bcddb74fdf`, `17832aa629524ef6e8d8d6e9b6b902a8d324b559e3c36dbd0e221ab1690be871`, `c8075bbff748096e1c6a1ea0aa67bb6762fdd7551427a12425b35b94c1f1ecf2`, `f6669bd504ce6b0e303be7ee47f2ebbc062989c88c41f0a3f436044a24869798`, `282b9bc318ad1234cbd1b86424b784299b8be31545802a7c6b751166b814b990` |

For full incident details, see [playbook.md](playbook.md).

---

## Setup

Define IOC patterns used throughout. The PowerShell blocks assume a Windows host;
the bash blocks (npm cache, lock files, agent logs) run on any OS.

```bash
# Malicious package names (grep alternation)
PKGS="postcss-minify-selector-parser|postcss-minify-selector|aes-decode-runner-pro"

# Network + payload IOCs
C2_IP="95.216.92.207"
PAYLOAD_HOST="nvidiadriver.net"

# RAT module SHA-256 hashes
HASHES="164e322d6fbc62e254d73583acd7f39444c884d3f5e6a5d27db143fc25bc88b3 50ffce607867d8fa8eaf6ef5cd25a3c0e7e4415e881b9e55c04a67bcddb74fdf 17832aa629524ef6e8d8d6e9b6b902a8d324b559e3c36dbd0e221ab1690be871 c8075bbff748096e1c6a1ea0aa67bb6762fdd7551427a12425b35b94c1f1ecf2 f6669bd504ce6b0e303be7ee47f2ebbc062989c88c41f0a3f436044a24869798 282b9bc318ad1234cbd1b86424b784299b8be31545802a7c6b751166b814b990"
```

---

## Check 1: RAT Artifacts (Windows)

The dropper extracts the payload under `%TEMP%\winPatch` and runs `chost.exe loader.py`.

```powershell
Test-Path "$env:TEMP\winPatch"
Test-Path "$env:TEMP\winPatch\chost.exe"
Get-ChildItem "$env:TEMP" -Force -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -in @('winPatch','.store','.host','settings.ps1','update.vbs','dll.zip') }

# Is the RAT running?
Get-Process | Where-Object { $_.Path -like "*winPatch*chost.exe" } |
  Select-Object Id, Path, StartTime
```

### Hash-match any suspected modules

```powershell
$known = @(
  '164e322d6fbc62e254d73583acd7f39444c884d3f5e6a5d27db143fc25bc88b3',
  '50ffce607867d8fa8eaf6ef5cd25a3c0e7e4415e881b9e55c04a67bcddb74fdf',
  '17832aa629524ef6e8d8d6e9b6b902a8d324b559e3c36dbd0e221ab1690be871',
  'c8075bbff748096e1c6a1ea0aa67bb6762fdd7551427a12425b35b94c1f1ecf2',
  'f6669bd504ce6b0e303be7ee47f2ebbc062989c88c41f0a3f436044a24869798',
  '282b9bc318ad1234cbd1b86424b784299b8be31545802a7c6b751166b814b990'
)
Get-ChildItem "$env:TEMP\winPatch" -Recurse -Include *.pyd -ErrorAction SilentlyContinue |
  ForEach-Object {
    $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    if ($known -contains $h) { Write-Output "FOUND — $($_.FullName) [$h]" }
  }
```

Any hit = **COMPROMISED**.

---

## Check 2: Persistence (Windows)

The RAT persists via a Run key valued `csshost`.

```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
  Select-Object csshost
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
  Format-List

# Scheduled tasks pointing at the payload
Get-ScheduledTask | Where-Object {
  $_.Actions.Execute -like "*winPatch*" -or
  $_.Actions.Execute -like "*chost.exe*" -or
  $_.Actions.Arguments -like "*loader.py*"
}
```

A `csshost` value (especially one pointing into `%TEMP%\winPatch`) = persistence
installed. **Remove this FIRST during cleanup** — uninstalling the npm package does
not touch it.

---

## Check 3: npm Cache (any OS)

The malicious tarballs may remain in the npm cache even after `node_modules` cleanup.

```bash
npm cache ls 2>/dev/null | grep -E "$PKGS" || echo "No malicious packages in npm cache (ls)"

NPM_CACHE=$(npm config get cache 2>/dev/null)
if [ -d "$NPM_CACHE/_cacache" ]; then
  grep -rlE "$PKGS" "$NPM_CACHE/_cacache/index-v5" 2>/dev/null \
    && echo "FOUND — malicious package in npm cache index" \
    || echo "npm cache index: clean"
else
  echo "npm cache not found at $NPM_CACHE"
fi
```

---

## Check 4: Lock Files & node_modules in Local Projects (any OS)

```bash
PROJECT_ROOT="${HOME}/projects"   # adjust to actual project root

find "$PROJECT_ROOT" -maxdepth 5 \
  \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" -o -name "package.json" \) \
  -not -path "*/node_modules/*" 2>/dev/null | while read f; do
  if grep -qE "$PKGS" "$f" 2>/dev/null; then echo "FOUND: $f"; fi
done
echo "(lock/manifest scan complete)"

# Installed on disk?
for p in postcss-minify-selector-parser postcss-minify-selector aes-decode-runner-pro; do
  find "$PROJECT_ROOT" -maxdepth 6 -path "*/node_modules/$p" -type d 2>/dev/null
done
```

Any hit means the package was installed on this machine. On Windows, pair this with
Check 1/2 to see if the RAT actually ran.

---

## Check 5: Network Indicators (any OS)

### Active connections / DNS

```bash
# macOS / Linux
netstat -an 2>/dev/null | grep "95.216.92.207" \
  && echo "FOUND — active C2 connection" || echo "C2 IP not in active connections"
grep "nvidiadriver.net" /etc/hosts 2>/dev/null && echo "FOUND in hosts file" || echo "not in hosts file"
```

```powershell
# Windows
Get-NetTCPConnection | Where-Object { $_.RemoteAddress -eq "95.216.92.207" }
Get-Content "$env:WINDIR\System32\drivers\etc\hosts" | Select-String "nvidiadriver.net"
Resolve-DnsName nvidiadriver.net -CacheOnly -ErrorAction SilentlyContinue   # is it in the DNS cache?
```

Any connection to `95.216.92.207:8080` or DNS for `nvidiadriver.net` = the payload
stage was reached.

---

## Check 6: Chrome Credential-Theft Exposure

The RAT steals Chrome saved logins (with an app-bound-encryption bypass) and extension
data. If Check 1/2 found RAT artifacts on a machine where Chrome was signed in, treat
**all Chrome-saved credentials as exfiltrated**.

```powershell
# Windows — confirm a Chrome profile with a login store exists on this host
Test-Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
```

Action if RAT confirmed: rotate every credential saved in Chrome, sign out all Chrome
sessions, and revoke OAuth tokens granted via the browser.

---

## Check 7: AI Agent Conversation Logs (any OS)

AI coding agents store full tool output — every shell command and its stdout/stderr.
A session that ran `npm install`/imported the package during the window will have the
resolved package names and any IOC-bearing output captured. These logs persist longer
than npm debug logs.

> **Self-pollution exclusion (read this first).** If you are running this playbook
> *through* an AI agent, that agent's own session log already contains every IOC
> string above — because it just read them. Those are evidence of investigation, not
> compromise. Exclude the current session before trusting any hit.

```bash
CURRENT_SESSION_PROJECT=$(echo "$PWD" | sed 's|/|-|g')

grep -rliE "postcss-minify-selector-parser|aes-decode-runner-pro|nvidiadriver\.net|95\.216\.92\.207|winpatch-xd7d|csshost" \
  "$HOME/.claude/projects" \
  "$HOME/Library/Application Support/Cursor" \
  "$HOME/Library/Application Support/Windsurf" \
  "$HOME/.config/github-copilot" 2>/dev/null \
  | grep -v "${CURRENT_SESSION_PROJECT}" | grep -v "paste-cache" | grep -v "file-history" \
  || echo "No IOC matches in other AI-agent sessions"
```

For Claude Code `.jsonl` hits, open the file and check whether the same session
also **ran an install/import** (a `npm install`, `npm ci`, or `node`/`require` of one
of the packages) — co-occurrence in one session is the real signal. A session that
only *discussed* the incident is `REFERENCE ONLY`, not compromise.

---

## Results Summary

| Check | IOC | Status |
|---|---|---|
| RAT artifacts (Windows) | `%TEMP%\winPatch`, `chost.exe`, `.pyd` hashes | found / clean |
| Persistence (Windows) | Run key `csshost`, scheduled task | found / clean |
| npm cache | three malicious packages | found / clean |
| Lock files / node_modules | three malicious packages | found / clean |
| Network | `95.216.92.207`, `nvidiadriver.net` | found / clean |
| Chrome exposure | RAT present + Chrome profile signed in | exposed / n/a |
| AI-agent logs | IOC + install/import in same session | found / reference only / clean |

### If any check returns "found"

1. **Remove persistence FIRST** — delete the `csshost` Run key and `%TEMP%\winPatch`
   (+ `.store`, `.host`) artifacts. (Windows.)
2. **Treat the workstation as compromised** — rotate every credential stored on or
   reachable from it, starting with Chrome-saved logins.
3. **Preserve evidence** before cleanup (copy `%TEMP%\winPatch`, the Run-key value).
4. **Remove the npm packages**, then `npm cache clean --force`.
5. **Block IOCs** at the network edge: `nvidiadriver.net`, `95.216.92.207`.
6. **Re-image** the host — in-place cleaning may miss additional persistence.
