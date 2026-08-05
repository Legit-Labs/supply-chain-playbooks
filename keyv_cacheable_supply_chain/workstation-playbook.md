# August 2026 Shai-Hulud (keyv / cacheable) — Workstation Investigation Playbook

Playbook for checking whether a **developer workstation** was affected by the August 4, 2026 Shai-Hulud npm wave. Run this on each machine that may have installed JavaScript dependencies during the exposure window — **and on each machine that opened any repository from an affected org in VS Code or Claude Code**, because this wave detonates without an `npm install`.

> **Designed for AI agent execution.** Each check is self-contained: commands to run, plus what the output means.

> ⚠️ **This wave has a workstation-first detonation path.** The worm commits `.vscode/tasks.json`, `.vscode/setup.mjs`, `.claude/settings.json`, `.claude/setup.mjs`, and `.claude/math_init.js` into repositories. **Opening such a repo in VS Code, or starting a Claude Code session in it, executes the payload** — no package installation involved. Check 2 is therefore the highest-value check on this page, not Check 4.

---

## Incident Reference

| Field | Value |
|---|---|
| Malicious versions | `keyv@6.0.0`, `cacheable@2.5.1`, `flat-cache@6.1.24`, `file-entry-cache@11.1.6`/`11.1.7`, `cacheable-request@13.0.20`, `cache-manager@7.2.10`, `@cacheable/memory@2.2.1`, `@cacheable/node-cache@3.1.2`, `@cacheable/utils@2.5.1`, `@cacheable/net@2.1.1`, `ecto@5.0.1`, `@thiennq/docs-viewer@1.6.2` — **all since unpublished from npm** |
| Exposure window | `2026-08-03T00:00:00Z` → **ongoing** (campaign still active) |
| Loader file | `setup.mjs` (invoked as `preinstall: node setup.mjs`) |
| Payload file | `math_init.js`, `Math_Symbol.js` |
| Loader hashes (SHA-256) | `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668` (npm tarball), `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb` (repo-injected) |
| Payload hash (SHA-256) | `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc` |
| Injected `.vscode/tasks.json` hash | `927387d0cfac1118df4b383decc2ea6ba49c9d2f98b47098bcbcba1efc026e1f` |
| Injected `.claude/settings.json` hash | `14eb4ce01dd4307759887ff819359b70d7d9ff709ecde039a5abc1aac325b128` |
| C2 fallback domain | `npm-cache[.]com` (path `/router`) |
| C2 resolver | `eth-mainnet.nodereal[.]io` + contract `0xE1f2395ee43e45A1556EC6438a88c31B83493103` (selector `0x53ed5143`) |
| PID lock | `/tmp/tmp.dpkg_14527.lock` |
| Env marker | `_NODE_RUNTIME_INIT=1` |
| Bun runtime pulled | `github.com/oven-sh/bun/releases/download/bun-v1.3.13/` |
| Dead-drop marker | `Shai-Hulud: Here We Go Again` |
| Dormant persistence | `gh-token-monitor` (macOS LaunchAgent / Linux systemd) |

For full incident details, see [playbook.md](playbook.md).

---

## Setup

```bash
# Malicious package@version pairs
VERSIONS_PATTERN='keyv@6\.0\.0|cacheable@2\.5\.1|flat-cache@6\.1\.24|file-entry-cache@11\.1\.[67]|cacheable-request@13\.0\.20|cache-manager@7\.2\.10|ecto@5\.0\.1|@cacheable/(memory@2\.2\.1|node-cache@3\.1\.2|utils@2\.5\.1|net@2\.1\.1)'

# Payload file names
PAYLOAD_FILES='math_init\.js|Math_Symbol\.js|setup\.mjs'

# Network IOCs
C2_DOMAIN="npm-cache.com"
ETH_CONTRACT="0xE1f2395ee43e45A1556EC6438a88c31B83493103"
ETH_SELECTOR="0x53ed5143"

# Host artifacts
PID_LOCK="/tmp/tmp.dpkg_14527.lock"
ENV_MARKER="_NODE_RUNTIME_INIT"

# Known payload hashes
HASH_LOADER_NPM="54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668"
HASH_LOADER_REPO="fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb"
HASH_PAYLOAD="9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"

# Combined pattern for scanning text logs
IOC_PATTERN="${VERSIONS_PATTERN}|${PAYLOAD_FILES}|${C2_DOMAIN}|${ETH_CONTRACT}|${ENV_MARKER}|Shai-Hulud"
```

---

## Check 1: Payload Artifacts on Disk

The loader and payload are distinctively named. **Neither `math_init.js` nor `Math_Symbol.js` is a legitimate file in any ecosystem** — a hit is conclusive. `setup.mjs` is slightly more generic; verify by hash.

```bash
# Search common code roots plus node_modules trees
for root in ~/projects ~/code ~/repos ~/work ~/src "$HOME"; do
  [ -d "$root" ] || continue
  find "$root" -maxdepth 8 \( -name 'math_init.js' -o -name 'Math_Symbol.js' -o -name 'setup.mjs' \) 2>/dev/null
done | sort -u | tee /tmp/keyv-payload-files.txt

# Hash each hit against the known payloads
while read -r f; do
  h=$(shasum -a 256 "$f" 2>/dev/null | awk '{print $1}')
  case "$h" in
    "$HASH_LOADER_NPM"|"$HASH_LOADER_REPO"|"$HASH_PAYLOAD") echo "*** CONFIRMED MALICIOUS: $f ($h)" ;;
    *) echo "    unmatched hash (review manually): $f ($h)" ;;
  esac
done < /tmp/keyv-payload-files.txt
```

**Found:** any `math_init.js` / `Math_Symbol.js`, or a `setup.mjs` matching a known hash → machine executed or received the payload. An unmatched `setup.mjs` hash is not automatically clean — the worm rebuilds tarballs, so open the file and look for obfuscated content plus a Bun download URL.

---

## Check 2: Editor and Agent Backdoors — **highest priority**

These files survive `rm -rf node_modules` and package removal entirely, and they detonate on next editor/agent launch.

```bash
find ~ -maxdepth 8 \( \
     -path '*/.vscode/tasks.json' -o -path '*/.vscode/setup.mjs' \
  -o -path '*/.claude/settings.json' -o -path '*/.claude/setup.mjs' -o -path '*/.claude/math_init.js' \
  \) -not -path '*/node_modules/*' 2>/dev/null | while read -r f; do
  mtime=$(stat -f '%Sm' "$f" 2>/dev/null || stat -c '%y' "$f" 2>/dev/null)
  if grep -qE 'setup\.mjs|math_init|Math_Symbol' "$f" 2>/dev/null; then
    echo "*** SUSPICIOUS: $f (modified $mtime)"
    grep -nE 'setup\.mjs|math_init|SessionStart|Environment Setup' "$f" 2>/dev/null | head -5
  fi
done
```

**What malicious looks like:**

- `.claude/settings.json` — a **`SessionStart`** hook running `node .vscode/setup.mjs`
- `.vscode/tasks.json` — a task labelled **`Environment Setup`** running `node .claude/setup.mjs`

Note the deliberate cross-wiring: the VS Code task points into `.claude/`, and the Claude hook points into `.vscode/`. Cleaning only one directory leaves the other live.

Also check whether the infection arrived via git, on **any** branch:

```bash
for repo in $(find ~ -maxdepth 5 -name '.git' -type d 2>/dev/null | xargs -n1 dirname); do
  cd "$repo" 2>/dev/null || continue
  hits=$(git log --all --since="2026-08-03" --format='%H %an %s' 2>/dev/null | grep -i "chore: update config")
  [ -n "$hits" ] && { echo "=== $repo"; echo "$hits"; }
done
```

Confirm a hit by checking for the forged trailer:

```bash
git show --format='%B' -s <sha> | grep -i "claude@users.noreply.github.com"
```

**Found:** delete the injected files on every branch and treat the machine as compromised — proceed to the credential rotation in Check 10.

---

## Check 3: OS Persistence

> **Dormant capability.** `gh-token-monitor` is present in the payload but has **no observed call site**. Report a hit as a confirmed finding; report its absence as "not installed," not as "the payload lacked persistence."

### macOS — LaunchAgents / LaunchDaemons

```bash
ls -la ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/ 2>/dev/null | \
  grep -iE "gh-token|token-monitor|node|bun"
grep -rliE "gh-token-monitor|setup\.mjs|math_init" ~/Library/LaunchAgents/ /Library/LaunchAgents/ 2>/dev/null
launchctl list 2>/dev/null | grep -iE "gh-token|token-monitor"
```

### Linux — systemd / cron

```bash
systemctl --user list-units --all 2>/dev/null | grep -iE "gh-token|token-monitor"
ls -la ~/.config/systemd/user/ 2>/dev/null
grep -rliE "gh-token-monitor|setup\.mjs|math_init" ~/.config/systemd/user/ /etc/systemd/system/ 2>/dev/null
crontab -l 2>/dev/null | grep -iE "node|bun|setup\.mjs|math_init"
```

### Windows — Scheduled Tasks / Run keys

```powershell
Get-ScheduledTask | Where-Object { $_.TaskName -match 'gh-token|token-monitor' }
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Format-List
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' | Format-List
```

---

## Check 4: Runner / Process Artifacts

```bash
# PID lock — present while the payload holds the lock
ls -la "$PID_LOCK" 2>/dev/null && echo "*** PID LOCK PRESENT ***"

# Env marker used when relaunching outside CI
env | grep -i "$ENV_MARKER" && echo "*** ENV MARKER PRESENT ***"

# Stray Bun binary (the payload downloads v1.3.13 and normally deletes it)
which bun 2>/dev/null && bun --version 2>/dev/null
find /tmp "$HOME/.cache" -maxdepth 4 -name 'bun*' -newermt "2026-08-03" 2>/dev/null | head

# Live node/bun processes with unexpected parents
ps aux 2>/dev/null | grep -iE "setup\.mjs|math_init|bun " | grep -v grep
```

**Note:** the payload deletes its temporary Bun executable after running, so absence proves nothing. A Bun binary dated on or after August 4 on a machine that doesn't use Bun is a strong signal.

---

## Check 5: npm / pnpm / yarn Cache

The cache holds tarballs that were downloaded even if `node_modules` has since been wiped.

```bash
# Direct listing
npm cache ls 2>/dev/null | grep -iE "keyv|cacheable|flat-cache|file-entry-cache|cache-manager|\becto\b"

# Content-addressable store — search extracted payload names
grep -rl "math_init\|Math_Symbol" ~/.npm/_cacache/content-v2 2>/dev/null | head -20

# Cache index entries for the affected packages
grep -rhoE '"key":"[^"]*(keyv|cacheable|flat-cache|file-entry-cache|cache-manager)[^"]*"' \
  ~/.npm/_cacache/index-v5 2>/dev/null | sort -u | head -30

# pnpm / yarn
pnpm store path 2>/dev/null && pnpm store status 2>/dev/null | head
ls ~/Library/Caches/Yarn/v6 2>/dev/null | grep -iE "keyv|cacheable|flat-cache|file-entry-cache" | head
```

**Found:** clear the cache during remediation (`npm cache clean --force`, `pnpm store prune`, `yarn cache clean`) — a cached malicious tarball can be reinstalled offline even though npm has unpublished it.

---

## Check 6: Local Lock Files Pinning a Malicious Version

```bash
find ~ \( -name 'package-lock.json' -o -name 'pnpm-lock.yaml' -o -name 'yarn.lock' \) \
  -not -path '*/node_modules/*' 2>/dev/null | \
  xargs grep -lE 'keyv.*6\.0\.0|cacheable.*2\.5\.1|flat-cache.*6\.1\.24|file-entry-cache.*11\.1\.[67]|cacheable-request.*13\.0\.20|cache-manager.*7\.2\.10|ecto.*5\.0\.1' 2>/dev/null | \
  tee /tmp/keyv-bad-lockfiles.txt
```

For each hit, print the exact pinned version to avoid a substring false positive (`6.1.24` vs `6.1.2`):

```bash
while read -r lf; do
  echo "=== $lf"
  grep -nE '"(keyv|cacheable|flat-cache|file-entry-cache|cache-manager|cacheable-request|ecto)"|"version"' "$lf" | \
    grep -B1 -E '6\.0\.0|2\.5\.1|6\.1\.24|11\.1\.[67]|13\.0\.20|7\.2\.10|5\.0\.1'
done < /tmp/keyv-bad-lockfiles.txt
```

> **Remember `flat-cache` and `file-entry-cache` arrive via ESLint.** A repo can pin a malicious version transitively without naming it in `package.json`.

---

## Check 7: Network Indicators

```bash
# Active connections
netstat -an 2>/dev/null | grep ESTABLISHED | grep -v 127.0.0.1 | head -30
lsof -i -n -P 2>/dev/null | grep -iE "node|bun" | head -20

# hosts file tampering
grep -iE "npm-cache|nodereal" /etc/hosts 2>/dev/null

# macOS DNS cache
sudo dscacheutil -cachedump -entries Host 2>/dev/null | grep -iE "npm-cache|nodereal"

# Linux systemd-resolved
sudo resolvectl statistics 2>/dev/null
journalctl -u systemd-resolved --since "2026-08-03" 2>/dev/null | grep -iE "npm-cache|nodereal"
```

> **False positive:** `eth-mainnet.nodereal.io` is a legitimate public Ethereum RPC endpoint. On a machine doing blockchain work this is normal traffic. It is an IOC here only alongside the contract address `0xE1f2395ee43e45A1556EC6438a88c31B83493103`, the selector `0x53ed5143`, or on a machine with no blockchain workload. **`npm-cache.com` has no legitimate use** — treat any hit on it as confirmed.

---

## Check 8: Shell History and npm Debug Logs

```bash
grep -inE "${IOC_PATTERN}" ~/.bash_history ~/.zsh_history ~/.local/share/fish/fish_history 2>/dev/null | head -20

grep -liE "keyv@6\.0\.0|flat-cache@6\.1\.24|file-entry-cache@11\.1\.[67]|setup\.mjs|math_init" \
  ~/.npm/_logs/*.log 2>/dev/null

# Which installs ran during the window
ls -la ~/.npm/_logs/ 2>/dev/null | awk '$0 ~ /2026-08-0[3-9]|2026-08-[12][0-9]/'
```

npm debug logs are the most reliable record of what was actually installed and when, since they persist after `node_modules` is deleted.

---

## Check 9: AI Agent Conversation Logs

> **Self-pollution warning.** If you are running this playbook through an AI coding agent, its transcript **will** contain every IOC string on this page — because the agent has been reading them. That is evidence of investigation, not compromise. **Exclude the current session before interpreting any hit.**

```bash
CURRENT_SESSION_PROJECT=$(echo "$PWD" | sed 's|/|-|g')

grep -rliE "math_init|Math_Symbol|npm-cache\.com|0xE1f2395ee43e45A1556EC6438a88c31B83493103|Shai-Hulud: Here We Go Again|thebeautifulmarchoftime|IfYouBlockThisAPIKey" \
  "$HOME/.claude/projects" \
  "$HOME/Library/Application Support/Cursor" \
  "$HOME/Library/Application Support/Windsurf" \
  "$HOME/.config/github-copilot" 2>/dev/null | \
  grep -v "${CURRENT_SESSION_PROJECT}" | grep -v "paste-cache" | grep -v "file-history"
```

**Classify each surviving hit:**

- A `.jsonl` from a **prior, unrelated session** containing `added keyv@6.0.0` or `node setup.mjs` output → **real install evidence**
- A session discussing the incident (reading advisories, pasting IOC lists) → reference, not compromise
- Any session where the agent ran an install command during the window → check the surrounding output for actual resolution lines

This wave specifically targets **AI-service credentials** (OpenAI, Anthropic, Claude, Cursor, Codex, Gemini), so agent config directories are both an evidence source *and* a theft target — see Check 10.

---

## Check 10: Credential Exposure Inventory

If any check above returned a finding, **assume everything readable by the user account was taken.** The stealer walks hundreds of configured paths. Inventory what existed on this machine so rotation is complete rather than guessed:

```bash
ls -la ~/.npmrc ~/.yarnrc.yml ~/.pypirc 2>/dev/null
ls -la ~/.aws/credentials ~/.aws/config ~/.azure ~/.config/gcloud 2>/dev/null
ls -la ~/.kube/config ~/.vault-token 2>/dev/null
ls -la ~/.ssh/ 2>/dev/null
ls -la ~/.docker/config.json ~/.git-credentials ~/.config/gh/hosts.yml 2>/dev/null
ls -la ~/.config/claude* ~/.claude.json ~/.cursor ~/.codeium 2>/dev/null
find ~ -maxdepth 4 -name '.env' -o -maxdepth 4 -name '.env.*' 2>/dev/null | head -20
```

**Rotate every credential that appeared above**, plus: GitHub PATs and OAuth tokens, npm tokens (**prioritize any with `bypass_2fa` enabled**), AWS/Azure/GCP/Alibaba/Tencent/Hetzner keys, Kubernetes service-account tokens, HashiCorp Vault tokens, SSH keys, Stripe and Slack tokens, AI-service API keys, database connection strings, and any crypto wallet material. On Linux, `/etc/shadow` is also read if the payload had the access to do so.

---

## Check 11: Locally Built Container Images

```bash
docker images --format '{{.Repository}}:{{.Tag}} {{.CreatedAt}}' 2>/dev/null | \
  awk '$0 ~ /2026-08-0[3-9]|2026-08-[12][0-9]/'
```

For any image built during the window, inspect its dependency tree:

```bash
docker run --rm --entrypoint sh <image> -c \
  'ls node_modules/.package-lock.json 2>/dev/null && grep -E "keyv|flat-cache|file-entry-cache|cacheable" node_modules/.package-lock.json | head -20; find / -name "math_init.js" -o -name "Math_Symbol.js" 2>/dev/null | head'
```

Rebuild any affected image with `--no-cache` after the lock file is corrected — a malicious version baked into a layer survives every host-level cleanup.

---

## Results Summary

Report one line per check:

| Check | Surface | Result |
|---|---|---|
| 1 | Payload artifacts on disk | found / not found |
| 2 | **Editor & agent backdoors** | found / not found |
| 3 | OS persistence (`gh-token-monitor`) | found / not installed |
| 4 | Process & runner artifacts | found / not found |
| 5 | Package-manager cache | found / not found |
| 6 | Local lock files | found / not found |
| 7 | Network indicators | found / not found |
| 8 | Shell history & npm logs | found / not found |
| 9 | AI agent logs (post-exclusion) | found / not found |
| 10 | Credential exposure inventory | list of what existed |
| 11 | Locally built images | found / not found |

### If any check returns "found"

1. **Do not clean up first.** Snapshot the payload files, `.claude/` and `.vscode/` contents, npm debug logs, and shell history for forensics.
2. **Disconnect the machine from the network** if Check 7 shows contact with `npm-cache.com` — the C2 `eval()` path means live operator access is possible.
3. **Rotate everything in the Check 10 inventory**, npm tokens first.
4. **Remove the backdoors on every branch of every affected repo** (Check 2) — package removal does not touch them.
5. **Purge caches, delete `node_modules`, correct lock files, rebuild images with `--no-cache`.**
6. **Report upward** — if this machine held npm publish tokens, the org's own packages may have been republished. See Phase 2b in [playbook.md](playbook.md).
