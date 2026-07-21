# SleeperGem RubyGems Compromise — Workstation Investigation Playbook

Playbook for checking whether a **developer workstation** was affected by the
**SleeperGem** RubyGems supply-chain compromise (July 18, 2026). Run this on each
machine that may have run `gem install` or `bundle install` during the exposure
window.

> **This is the primary detection surface.** The malware deliberately exits on
> CI/CD runners and only detonates on developer machines. If a project's
> `Gemfile` / `Gemfile.lock` referenced a malicious gem
> (see [playbook.md](playbook.md)), the machines that installed it are where the
> backdoor actually lives.

> **Designed for AI agent execution.** Each check is self-contained with commands
> to run and expected output to interpret.

---

## Incident Reference

| Field | Value |
|---|---|
| Malicious gems | `git_credential_manager` 2.8.0–2.8.3, `Dendreo` 1.1.3/1.1.4, `fastlane-plugin-run_tests_firebase_testlab` 0.3.2 |
| Secondary vectors | `slackHtmlToMarkdown`, `seo_optimizer`, `array_fast_methods` |
| Exposure window | `2026-07-18` to `2026-07-20` |
| Second-stage host | `git.disroot.org/git-ecosystem` |
| Backdoor daemon | `~/.local/share/gcm/` |
| Setuid-root shell | `/usr/local/sbin/ping6` |
| Persistence | cron entry + systemd user service; second-stage `deploy.sh` |

For full incident details, see [playbook.md](playbook.md).

---

## Setup

Define the IOC patterns used throughout this playbook:

```bash
# Malicious gem versions (grep pattern)
GEM_VERSIONS="git_credential_manager.*(2\.8\.0|2\.8\.1|2\.8\.2|2\.8\.3)|Dendreo.*(1\.1\.3|1\.1\.4)|fastlane-plugin-run_tests_firebase_testlab.*0\.3\.2"

# Gem names (any occurrence worth inspecting)
GEM_NAMES="git_credential_manager|Dendreo|fastlane-plugin-run_tests_firebase_testlab|slackHtmlToMarkdown|seo_optimizer|array_fast_methods"

# Host/file IOCs
C2_HOST="git.disroot.org"
DAEMON_DIR="$HOME/.local/share/gcm"
SETUID_SHELL="/usr/local/sbin/ping6"

# Combined pattern for scanning text logs
IOC_PATTERN="${GEM_VERSIONS}|git\.disroot\.org|/usr/local/sbin/ping6|\.local/share/gcm|deploy\.sh"
```

---

## Check 1: Backdoor Daemon

The loader drops a native daemon that masquerades as Git Credential Manager under
`~/.local/share/gcm/`. Check for its presence and whether it is running.

### macOS / Linux

```bash
ls -la "$DAEMON_DIR" 2>/dev/null \
  && echo "FOUND — COMPROMISED (backdoor daemon dir present)" || echo "daemon dir: clean"

# Is it running?
ps aux | grep -iE "gcm|git-credential" | grep -v grep
```

### Windows

```powershell
Test-Path "$env:LOCALAPPDATA\gcm"
Test-Path "$env:USERPROFILE\.local\share\gcm"
Get-Process | Where-Object { $_.Path -like "*\gcm\*" }
```

> The legitimate Microsoft Git Credential Manager does **not** install a daemon
> under `~/.local/share/gcm/` — treat any daemon there as malicious.

---

## Check 2: Setuid-Root Shell

The backdoor plants a setuid-root shell to retain privileged access. This is one
of the strongest single indicators.

```bash
ls -la "$SETUID_SHELL" 2>/dev/null \
  && echo "FOUND — COMPROMISED (inspect the setuid bit below)" || echo "ping6 shell: clean"

# Confirm the setuid bit + root ownership
if [ -e "$SETUID_SHELL" ]; then
  stat -f '%Sp %Su' "$SETUID_SHELL" 2>/dev/null || stat -c '%A %U' "$SETUID_SHELL" 2>/dev/null
  echo ">> A setuid-root ('-rwsr-xr-x root') shell at this path is the SleeperGem backdoor, NOT the real ping6."
fi
```

The real `ping6` lives at `/sbin/ping6` or `/bin/ping6` and is not a shell. A
setuid-root executable at **`/usr/local/sbin/ping6`** is the IOC.

---

## Check 3: OS Persistence (cron / systemd)

The backdoor installs persistence beyond the initial binary.

### Linux / macOS — cron

```bash
crontab -l 2>/dev/null | grep -iE "gcm|disroot|ping6|deploy\.sh" \
  && echo "FOUND — malicious cron entry" || echo "user crontab: clean"

grep -rlE "gcm|disroot|ping6" /etc/cron.d/ /etc/crontab 2>/dev/null
```

### Linux — systemd user service

```bash
systemctl --user list-units --all 2>/dev/null | grep -iE "gcm|credential"
grep -rlE "gcm|disroot|\.local/share/gcm" ~/.config/systemd/user/ /etc/systemd/system/ 2>/dev/null \
  && echo "FOUND — malicious systemd unit" || echo "systemd units: clean"
```

### macOS — LaunchAgents / LaunchDaemons

```bash
grep -rlE "gcm|disroot|ping6" \
  ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/ 2>/dev/null \
  && echo "FOUND — persistence mechanism detected" || echo "launch agents: clean"
```

### Windows — Scheduled Tasks / Run keys

```powershell
Get-ScheduledTask | Where-Object { $_.Actions.Execute -like "*gcm*" -or $_.Actions.Execute -like "*deploy*" }
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" 2>$null | Select-String "gcm|disroot"
```

---

## Check 4: Second-Stage Script

```bash
find "$HOME" /tmp /var/tmp -maxdepth 4 -name "deploy.sh" 2>/dev/null \
  | while read f; do
      grep -lE "disroot|gcm|ping6" "$f" 2>/dev/null && echo "  ^ matches SleeperGem IOCs: $f"
    done
```

---

## Check 5: RubyGems / Bundler Cache

The malicious gem tarballs may remain in the gem cache even after `node_modules`-
equivalent cleanup. Check installed gems and cached `.gem` files.

```bash
# Installed gems
for g in git_credential_manager Dendreo fastlane-plugin-run_tests_firebase_testlab slackHtmlToMarkdown seo_optimizer array_fast_methods; do
  gem list -e "$g" 2>/dev/null | grep -v "^$" && echo "  ^ installed: $g"
done

# Cached .gem tarballs (user + system gem dirs + Bundler)
for dir in "$HOME/.gem" "$(ruby -e 'print Gem.dir' 2>/dev/null)" "$HOME/.bundle" ./vendor/bundle; do
  [ -d "$dir" ] && find "$dir" -name "*.gem" 2>/dev/null \
    | grep -iE "git_credential_manager-2\.8\.|Dendreo-1\.1\.[34]|run_tests_firebase_testlab-0\.3\.2" \
    && echo "  ^ COMPROMISED tarball in $dir"
done
echo "(gem cache scan complete)"
```

Any installed malicious version, or a cached malicious `.gem`, means the install
ran on this machine — proceed as compromised.

---

## Check 6: Local Project Lock Files

```bash
PROJECT_ROOT="${HOME}/projects"  # adjust to actual project root

find "$PROJECT_ROOT" -maxdepth 5 \( -name "Gemfile.lock" -o -name "Gemfile" \) \
  -not -path "*/vendor/*" 2>/dev/null | while read f; do
  if grep -qE "$GEM_VERSIONS" "$f" 2>/dev/null; then
    echo "COMPROMISED VERSION PINNED: $f"
  elif grep -qE "$GEM_NAMES" "$f" 2>/dev/null; then
    echo "gem referenced (check version): $f"
  fi
done
echo "(lock file scan complete)"
```

A `Gemfile.lock` that pins a malicious version is a historical IOC — the machine
that generated it already ran the install.

---

## Check 7: Network Indicators

Check for evidence of the second-stage fetch from the attacker's Forgejo host.

### Active connections + hosts

```bash
netstat -an 2>/dev/null | grep -i "disroot" && echo "FOUND — active connection" || echo "no active disroot connection"
grep "git.disroot.org" /etc/hosts 2>/dev/null && echo "FOUND — in hosts file" || echo "not in hosts file"
```

### macOS DNS query log

```bash
log show --predicate 'process == "mDNSResponder" && composedMessage contains "disroot.org"' \
  --last 7d 2>/dev/null | head -20
```

### Linux DNS cache (systemd-resolved)

```bash
journalctl -u systemd-resolved --since "2026-07-18" 2>/dev/null | grep "disroot"
```

---

## Check 8: Shell History

```bash
grep -nE "gem install (git_credential_manager|Dendreo|fastlane-plugin-run_tests_firebase_testlab|slackHtmlToMarkdown|seo_optimizer|array_fast_methods)|disroot" \
  ~/.zsh_history ~/.bash_history ~/.local/share/fish/fish_history 2>/dev/null \
  || echo "No malicious install references in shell history"
```

---

## Check 9: AI Agent Conversation Logs

AI coding agents store conversation histories that include full tool outputs —
every shell command and its stdout/stderr. If an agent ran `gem install` /
`bundle install` during the window, the resolved versions and any IOC-bearing
output are captured there. These logs persist far longer than gem/Bundler logs.

### Where to find session logs

| Tool | Session log location | Format |
|---|---|---|
| Claude Code | `~/.claude/projects/**/*.jsonl` | JSONL — tool calls in `content[].input.command` |
| Cursor | `~/.cursor/conversations/` or `~/.cursor-server/data/` | JSON |
| Windsurf | `~/.windsurf/` or `~/.codeium/` | JSON |
| GitHub Copilot Chat | `~/.vscode/` (output channel logs) | Text |

### Scan + classify

```bash
find ~/.claude/projects -name "*.jsonl" -print0 2>/dev/null \
  | xargs -0 grep -lE "git_credential_manager|Dendreo|fastlane-plugin-run_tests_firebase_testlab|disroot\.org|\.local/share/gcm" 2>/dev/null \
  || echo "No IOC matches in Claude Code sessions"
```

```python
import json, glob, os

IOC_STRINGS = ['git_credential_manager', 'Dendreo', 'run_tests_firebase_testlab',
               'disroot.org', '.local/share/gcm', '/usr/local/sbin/ping6']
INSTALL_COMMANDS = ['gem install', 'bundle install', 'bundle update', 'bundle add']

# Exclude the current session to avoid self-pollution (this agent just read every IOC above)
CURRENT = os.environ.get('CLAUDE_SESSION_FILE', '')

for fpath in glob.glob(os.path.expanduser('~/.claude/projects/**/*.jsonl'), recursive=True):
    if CURRENT and os.path.samefile(fpath, CURRENT):
        continue
    has_ioc = has_install = False
    for line in open(fpath, errors='replace'):
        try:
            obj = json.loads(line)
        except Exception:
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

- **`INVESTIGATE`** — session has IOC strings AND ran a gem install. Open it and
  look for `Installing git_credential_manager 2.8.x` / `Fetching ... .gem` /
  a fetch to `git.disroot.org`.
- **`REFERENCE ONLY`** — mentions IOC strings but never installed. Typically a
  conversation about the incident (or running *this* playbook). Not compromise.

> **Self-pollution:** the session running this playbook will always "hit" on the
> IOC strings it just read. Exclude it (the script skips `$CLAUDE_SESSION_FILE`).

---

## Results Summary

| Check | IOC | Status |
|---|---|---|
| Backdoor daemon | `~/.local/share/gcm/` | found / clean |
| Setuid-root shell | `/usr/local/sbin/ping6` | found / clean |
| OS persistence | cron / systemd user service / LaunchAgents | found / clean |
| Second-stage script | `deploy.sh` matching IOCs | found / clean |
| Gem cache | malicious gem installed / cached `.gem` | found / clean |
| Local lock files | malicious version pinned | found / clean |
| Network | `git.disroot.org` in connections / DNS / hosts | found / clean |
| Shell history | malicious `gem install` references | found / clean |
| Agent conversations | IOC + install in same session | found / reference only / clean |

### If any check returns "found"

1. **Treat the workstation as compromised** — rotate every credential stored on or
   reachable from it (SSH keys, cloud tokens, git/registry tokens, API keys). The
   backdoor may have escalated to root.
2. **Preserve evidence** — copy the daemon dir, setuid shell, cron/systemd units,
   and `deploy.sh` before cleanup.
3. **Remove persistence FIRST** (see [playbook.md](playbook.md) Hardening 1):
   `~/.local/share/gcm/`, `/usr/local/sbin/ping6`, cron entry, systemd user service.
4. **Remove the malicious gems** and reinstall clean versions from a trusted lockfile.
5. **Clean the gem cache** and block `git.disroot.org` egress at the network layer.
6. **Consider re-imaging** — a root-escalated backdoor may have installed
   persistence beyond what this playbook enumerates.
