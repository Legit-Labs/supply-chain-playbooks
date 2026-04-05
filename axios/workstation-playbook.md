# Axios Supply Chain Compromise — Workstation Investigation Playbook

Playbook for checking whether a developer workstation was affected by the axios
npm supply chain compromise (March 31, 2026). Run this on each developer machine
that may have run `npm install` or `npm update` during the exposure window.

> **Designed for AI agent execution.** This playbook can be executed directly by
> an AI coding agent on a developer's machine. Each check is self-contained with
> commands to run and expected output to interpret.

---

## Incident Reference

| Field | Value |
|---|---|
| Compromised versions | `axios@1.14.1`, `axios@0.30.4` |
| Phantom dependency | `plain-crypto-js@4.2.1` |
| Exposure window | `2026-03-31T00:00:00Z` to `2026-03-31T05:00:00Z` |
| C2 domain | `sfrclak.com` |
| C2 IP | `142.11.206.73` |
| C2 port | `8000` |
| C2 endpoint | `/6202033` |
| Compromised shasums | axios 1.14.1: `2553649f2322049666871cea80a5d0d6adc700ca`, axios 0.30.4: `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71`, plain-crypto-js: `07d889e2dadce6f3910dcbc253317d28ca61c766` |

For full incident details, see [playbook.md](playbook.md).

---

## Setup

Define the IOC patterns used throughout this playbook:

```bash
# Compromised package versions (grep pattern)
VERSIONS_PATTERN="1\.14\.1|0\.30\.4"

# Phantom dependency
PHANTOM_DEP="plain-crypto-js"

# Network IOCs
C2_DOMAIN="sfrclak.com"
C2_IP="142.11.206.73"

# Known compromised shasums
SHASUM_AXIOS_1141="2553649f2322049666871cea80a5d0d6adc700ca"
SHASUM_AXIOS_0304="d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71"
SHASUM_PLAIN_CRYPTO="07d889e2dadce6f3910dcbc253317d28ca61c766"

# Combined IOC grep pattern (for scanning text-based logs)
IOC_PATTERN="axios.*(${VERSIONS_PATTERN})|${PHANTOM_DEP}|${C2_DOMAIN}|${C2_IP}"

# RAT paths per OS
RAT_MACOS="/Library/Caches/com.apple.act.mond"
RAT_LINUX="/tmp/ld.py"
# Windows: %PROGRAMDATA%\wt.exe, %TEMP%\6202033.vbs, %TEMP%\6202033.ps1
```

---

## Check 1: RAT Artifacts

The malware deploys a platform-specific RAT binary. Check for its presence
and whether it is running.

### macOS

```bash
ls -la /Library/Caches/com.apple.act.mond 2>/dev/null \
  && echo "FOUND — COMPROMISED" || echo "clean"

ps aux | grep -i "com.apple.act.mond" | grep -v grep
```

### Windows

```powershell
Test-Path "$env:PROGRAMDATA\wt.exe"
Test-Path "$env:TEMP\6202033.vbs"
Test-Path "$env:TEMP\6202033.ps1"
Get-Process | Where-Object { $_.Path -like "*wt.exe" -and $_.Path -like "*ProgramData*" }
```

### Linux

```bash
ls -la /tmp/ld.py 2>/dev/null \
  && echo "FOUND — COMPROMISED" || echo "clean"

ps aux | grep "ld.py" | grep -v grep
```

---

## Check 2: OS Persistence Mechanisms

The RAT may have installed persistence beyond the initial binary. Check for
launch-time persistence entries that reference the known RAT paths or IOCs.

### macOS — LaunchAgents / LaunchDaemons

```bash
grep -rl "com.apple.act.mond\|sfrclak\|142.11.206.73" \
  ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/ 2>/dev/null \
  && echo "FOUND — persistence mechanism detected" || echo "clean"

ls -la ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/ 2>/dev/null \
  | grep -iE "act\.mond|apple\.act"
```

### Windows — Scheduled Tasks / Registry Run Keys

```powershell
Get-ScheduledTask | Where-Object {
  $_.Actions.Execute -like "*wt.exe*" -or $_.Actions.Execute -like "*6202033*"
}

Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" 2>$null | Select-String "wt.exe|6202033"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" 2>$null | Select-String "wt.exe|6202033"
```

### Linux — cron / systemd

```bash
crontab -l 2>/dev/null | grep -E "ld\.py|sfrclak|142\.11\.206\.73"
grep -rl "ld.py\|sfrclak\|142.11.206.73" \
  /etc/cron.d/ /etc/systemd/system/ ~/.config/systemd/user/ 2>/dev/null
```

---

## Check 3: npm Cache

The npm cache may retain compromised tarballs even after `node_modules` was
cleaned. Check both the high-level package listing and the content-addressable
store by shasum.

### Package listing

```bash
npm cache ls 2>/dev/null | grep -E "axios.*(1\.14\.1|0\.30\.4)" \
  || echo "No compromised axios versions in npm cache"

npm cache ls 2>/dev/null | grep "plain-crypto-js" \
  || echo "No plain-crypto-js in npm cache"
```

### Content-addressable store (shasum search)

`npm cache ls` is not available in all npm versions. Search the cache directly
by the known compromised shasums — this is more reliable:

```bash
NPM_CACHE=$(npm config get cache 2>/dev/null)
if [ -d "$NPM_CACHE/_cacache" ]; then
  echo "Searching npm cache at $NPM_CACHE/_cacache for compromised shasums..."

  grep -rl "2553649f2322049666871cea80a5d0d6adc700ca" "$NPM_CACHE/_cacache" 2>/dev/null \
    && echo "FOUND — axios 1.14.1 shasum in cache" || echo "axios 1.14.1 shasum: clean"

  grep -rl "d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71" "$NPM_CACHE/_cacache" 2>/dev/null \
    && echo "FOUND — axios 0.30.4 shasum in cache" || echo "axios 0.30.4 shasum: clean"

  grep -rl "07d889e2dadce6f3910dcbc253317d28ca61c766" "$NPM_CACHE/_cacache" 2>/dev/null \
    && echo "FOUND — plain-crypto-js shasum in cache" || echo "plain-crypto-js shasum: clean"
else
  echo "npm cache not found at $NPM_CACHE"
fi
```

---

## Check 4: Lock Files in Local Projects

Scan all lock files under the user's project directories for compromised
versions or the phantom dependency.

```bash
PROJECT_ROOT="${HOME}/projects"  # adjust to actual project root

find "$PROJECT_ROOT" -maxdepth 5 \
  \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) \
  -not -path "*/node_modules/*" 2>/dev/null | while read lockfile; do
  if grep -qE "axios.*(1\.14\.1|0\.30\.4)|plain-crypto-js" "$lockfile" 2>/dev/null; then
    echo "COMPROMISED: $lockfile"
  fi
done
echo "(lock file scan complete)"
```

Also check for the phantom dependency in `node_modules`:

```bash
find "$PROJECT_ROOT" -maxdepth 5 -path "*/node_modules/plain-crypto-js" -type d 2>/dev/null
```

Any result means the compromised version was installed on this machine.

---

## Check 5: Network Indicators

Check for active connections to C2 infrastructure and DNS evidence of domain
resolution.

### Active connections

```bash
netstat -an 2>/dev/null | grep "142.11.206.73" \
  && echo "FOUND — active C2 connection" || echo "C2 IP not in active connections"
```

### DNS / hosts file

```bash
grep "sfrclak.com" /etc/hosts 2>/dev/null \
  && echo "FOUND — C2 domain in hosts file" || echo "C2 domain not in hosts file"
```

### macOS DNS query log

```bash
log show --predicate 'process == "mDNSResponder" && composedMessage contains "sfrclak.com"' \
  --last 7d 2>/dev/null | head -20
```

### Linux DNS cache (systemd-resolved)

```bash
journalctl -u systemd-resolved --since "2026-03-30" 2>/dev/null | grep "sfrclak"
```

---

## Check 6: Shell History

```bash
grep -E "axios@(1\.14\.1|0\.30\.4)|plain-crypto-js" \
  ~/.zsh_history ~/.bash_history ~/.local/share/fish/fish_history 2>/dev/null \
  || echo "No compromised package references in shell history"
```

---

## Check 7: npm Debug Logs

npm writes debug logs for install operations to `~/.npm/_logs/`. These are
retained for a limited time but may contain evidence of compromised package
resolution during the exposure window.

```bash
NPM_LOGS="${HOME}/.npm/_logs"
if [ -d "$NPM_LOGS" ]; then
  LOG_COUNT=$(ls "$NPM_LOGS"/*.log 2>/dev/null | wc -l)
  OLDEST=$(ls -lt "$NPM_LOGS"/*.log 2>/dev/null | tail -1)
  echo "npm logs: ${LOG_COUNT} files, oldest: ${OLDEST}"

  grep -rl "axios.*\(1\.14\.1\|0\.30\.4\)\|plain-crypto-js\|sfrclak\|142\.11\.206\.73" \
    "$NPM_LOGS"/ 2>/dev/null \
    && echo "FOUND — IOC match in npm debug logs" || echo "No IOC matches in npm logs"
else
  echo "No npm log directory found"
fi
```

**Limitation:** npm rotates debug logs aggressively. If the exposure window was
more than a few days ago, the relevant logs may have been purged. A clean result
here does not rule out compromise — the lock file and npm cache checks are more
reliable signals.

---

## Check 8: AI Agent Conversation Logs

AI coding agents store conversation histories that include full tool outputs —
every shell command executed and its stdout/stderr. If an agent session ran
`npm install` during the exposure window, the resolved package versions and
any IOC-bearing output are captured in these logs.

**Why this matters for forensics:**

- Agent conversation logs typically persist much longer than package manager
  debug logs (which rotate aggressively)
- They capture full stdout/stderr of every command the agent executed,
  including successful installs that leave no npm error log
- They record the exact command that was run (e.g. `npm install` vs `npm ci`),
  not just the result

### Where to find session logs

AI coding agents store session data in the user's home directory. The table
below lists known locations — scan whichever tools are installed on the machine:

| Tool | Session log location | Format |
|---|---|---|
| Claude Code | `~/.claude/projects/**/*.jsonl` | JSONL — one JSON object per message, tool calls in `content[].input.command` |
| Cursor | `~/.cursor/conversations/` or `~/.cursor-server/data/` | JSON |
| Windsurf | `~/.windsurf/` or `~/.codeium/` | JSON |
| GitHub Copilot Chat | `~/.vscode/` (output channel logs) | Text |

### Step 1: Discover session files

```bash
# Claude Code
CLAUDE_COUNT=$(find ~/.claude/projects -name "*.jsonl" 2>/dev/null | wc -l)
echo "Claude Code sessions: $CLAUDE_COUNT"

# Cursor
CURSOR_COUNT=$(find ~/.cursor ~/.cursor-server -name "*.json" 2>/dev/null | wc -l)
echo "Cursor sessions: $CURSOR_COUNT"
```

### Step 2: Scan all sessions for IOC strings

Use grep to find any session file that contains IOC strings. This is a broad
first pass — matches will be classified in the next step.

```bash
# Claude Code
find ~/.claude/projects -name "*.jsonl" -print0 2>/dev/null \
  | xargs -0 grep -lE "axios.*(1\.14\.1|0\.30\.4)|plain-crypto-js|sfrclak\.com|142\.11\.206\.73" 2>/dev/null \
  || echo "No IOC matches in Claude Code sessions"
```

Adapt the `find` path and file pattern for other tools.

### Step 3: Classify matches — real installs vs references

A match does NOT automatically mean compromise. The IOC strings may appear
in sessions where the agent was *discussing* the incident, *reading* an
advisory, or *authoring* detection rules. The key signal is whether the
session also contains **actual package install commands executed via shell**.

For Claude Code `.jsonl` files, each line is a JSON message. Tool calls
(including shell commands) are stored in `content` blocks with an `input.command`
field. The following script checks each matched session for both IOC presence
and npm install commands:

```python
import json, glob

IOC_STRINGS = ['1.14.1', '0.30.4', 'plain-crypto-js', 'sfrclak', '142.11.206.73']
INSTALL_COMMANDS = ['npm install', 'npm ci', 'npm add', 'npm update']

for fpath in glob.glob('$HOME/.claude/projects/**/*.jsonl', recursive=True):
    has_ioc = False
    has_install = False
    for line in open(fpath, errors='replace'):
        try:
            obj = json.loads(line)
        except:
            continue
        text = json.dumps(obj)
        if not has_ioc and any(ioc in text for ioc in IOC_STRINGS):
            has_ioc = True
        content = obj.get('content', '')
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    cmd = block.get('input', {}).get('command', '')
                    if any(x in cmd.lower() for x in INSTALL_COMMANDS):
                        has_install = True
    if has_ioc and has_install:
        print(f"INVESTIGATE: {fpath}")
    elif has_ioc:
        print(f"REFERENCE ONLY: {fpath}")
```

**Interpreting results:**

- **`INVESTIGATE`** — The session contains IOC strings AND executed npm install
  commands. Open the file and search for the bash tool outputs to determine
  whether a compromised version was actually resolved. Look for lines like
  `added axios@1.14.1` or `npm http fetch ...axios-1.14.1.tgz`.
- **`REFERENCE ONLY`** — The session mentions IOC strings but never ran npm
  install. Typically a conversation about the incident or playbook authoring.
  Not evidence of compromise.

### Adapting for other agent tools

The classification logic is the same for any agent tool — the difference is
the file format and where shell commands are stored:

1. Find all session/conversation files for the tool
2. Grep for the IOC pattern (broad pass)
3. For matches, parse the file to check whether any shell command in the
   session ran a package install (`npm install`, `pip install`, etc.)
4. Classify as `INVESTIGATE` or `REFERENCE ONLY`

For tools that store conversations as plain text or markdown (e.g. VS Code
output logs), grep for IOC patterns near lines containing `npm install` or
`npm ci` — co-occurrence in the same session is the signal.

---

## Check 9: Docker Images Built Locally

```bash
docker images --format '{{.Repository}}:{{.Tag}} {{.CreatedAt}}' 2>/dev/null \
  | grep "2026-03-31" \
  && echo "WARNING — Docker images built on exposure date found" \
  || echo "No Docker images built on 2026-03-31"
```

Rebuild suspicious images with `docker build --no-cache`.

---

## Results Summary

After running all checks, summarize findings in a table:

| Check | IOC | Status |
|---|---|---|
| RAT binary | Platform-specific path | found / clean |
| OS persistence | LaunchAgents / Scheduled Tasks / cron | found / clean |
| npm cache (package listing) | axios 1.14.1, 0.30.4, plain-crypto-js | found / clean |
| npm cache (shasum) | Known compromised shasums | found / clean |
| Lock files | Compromised versions in local projects | found / clean |
| node_modules | plain-crypto-js directory | found / clean |
| Network (active connections) | C2 IP 142.11.206.73 | found / clean |
| Network (DNS / hosts) | C2 domain sfrclak.com | found / clean |
| Shell history | References to compromised packages | found / clean |
| npm debug logs | IOC strings in install logs | found / clean |
| Agent conversations | IOC + install commands in same session | found / reference only / clean |
| Docker images | Images built on exposure date | found / clean |

### If any check returns "found"

1. **Treat the workstation as compromised** — rotate all credentials stored on
   or accessible from this machine (SSH keys, cloud tokens, npm tokens, API keys)
2. **Preserve evidence** — copy the relevant logs/artifacts before cleanup
3. **Remove RAT artifacts** (see Check 1 for paths per OS)
4. **Clean npm cache**: `npm cache clean --force`
5. **Block C2 at network level**: add `sfrclak.com` and `142.11.206.73` to
   firewall/proxy deny lists
6. **Consider re-imaging** — the RAT may have installed additional persistence
   mechanisms not covered by this playbook
