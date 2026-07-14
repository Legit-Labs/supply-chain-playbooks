# Jscrambler npm Compromise — Workstation Investigation Playbook

Run this on each developer workstation that may have run `npm install` / `npm update` (or `pnpm`/`yarn`) on a `jscrambler`-consuming project during the exposure window. The July 2026 `jscrambler` infostealer's primary target is the developer machine — SSH/cloud credentials, npm/registry tokens, AI-tool configs, and crypto wallets.

> **Designed for AI agent execution.** Each check is self-contained. Run the commands and interpret the output inline.

> **No binary hashes published.** At drafting, the authoritative sources did not publish SHA-256s or fixed on-disk paths for the dropped Rust/Node stealer. This playbook therefore anchors on the **grounded** indicators — malicious package versions, the C2 endpoint, and the specific credential stores the malware targets — rather than guessing artifact filenames. If hashes/paths are published later, add them to Setup and add a RAT-artifact check.

---

## Incident Reference

| Field | Value |
|---|---|
| Compromised package | `jscrambler` (npm) |
| Malicious versions | `8.14.0`, `8.16.0`, `8.17.0`, `8.20.0` |
| Safe version | `8.22.0` |
| Trigger | `preinstall` hook → native Rust stealer (Win/WSL, macOS, Linux); Node.js stealer variant with WebSocket reverse shell |
| Exposure window | `2026-07-11T15:00:00Z` – `2026-07-11T19:00:00Z` (pad to full UTC day if timestamps are uncertain) |
| C2 / drop server | `216.126.225.243`, ports `8085` / `8086` / `8087` (TLS, multipart POST) |
| Targeted secrets | source code; Git/SSH keys, env vars, CI/CD tokens; cloud creds (AWS/Azure/GCP/K8s); npm/registry tokens; AI-tool configs (Claude/Cursor/Windsurf/VS Code/Zed); crypto wallets (MetaMask/Phantom/Coinbase/Exodus/Trust); browser data; messaging (Slack/Discord/Telegram) |

For full incident details, see [playbook.md](playbook.md).

---

## Setup

```bash
MAL_RE='jscrambler.*(8\.14\.0|8\.16\.0|8\.17\.0|8\.20\.0)'
C2_IP='216.126.225.243'
C2_RE='216\.126\.225\.243'
```

---

## Check 1: Malicious version in the npm cache

The cache may retain a compromised tarball even after `node_modules` was wiped.

```bash
# npm (cache ls not present on all versions — fall back to a grep of the cache dir)
npm cache ls 2>/dev/null | grep -E "$MAL_RE" || \
  grep -rlE "$MAL_RE" "$(npm config get cache 2>/dev/null)/_cacache/index-v5" 2>/dev/null || \
  echo "clean (no malicious jscrambler version in npm cache)"

# pnpm / yarn stores
grep -rlE "$MAL_RE" "$(pnpm store path 2>/dev/null)" 2>/dev/null || echo "clean (pnpm store)"
find ~/.cache/yarn ~/Library/Caches/Yarn -iname 'jscrambler-*' 2>/dev/null | grep -E "8\.14\.0|8\.16\.0|8\.17\.0|8\.20\.0" || echo "clean (yarn cache)"
```

## Check 2: Local lock files pinning a malicious version

```bash
for lf in package-lock.json pnpm-lock.yaml yarn.lock npm-shrinkwrap.json; do
  find ~ -name "$lf" -not -path '*/node_modules/*' 2>/dev/null | \
    xargs grep -lE "$MAL_RE" 2>/dev/null
done
# No output = no local project pins a malicious jscrambler version.
```

## Check 3: `jscrambler` in `node_modules` + preinstall script

```bash
for root in ~/projects ~/code ~/repos ~/work ~/src "$HOME"; do
  [ -d "$root" ] || continue
  find "$root" -path '*/node_modules/jscrambler/package.json' 2>/dev/null | while read pj; do
    ver=$(python3 -c "import json;print(json.load(open('$pj')).get('version'))" 2>/dev/null)
    echo "$pj -> version $ver"
    case "$ver" in 8.14.0|8.16.0|8.17.0|8.20.0) echo "  *** MALICIOUS VERSION ON DISK ***";; esac
    python3 -c "import json;s=json.load(open('$pj')).get('scripts',{});print('  preinstall:',s.get('preinstall')) if s.get('preinstall') else None" 2>/dev/null
  done
done
```

A `preinstall` script on the `jscrambler` package (the legitimate package has none) that references a bundled binary or a network call is a strong compromise signal.

## Check 4: Network indicators (C2 contact)

```bash
# Live/recent connections to the C2
(netstat -an 2>/dev/null || ss -an 2>/dev/null) | grep "$C2_IP" && echo "*** ACTIVE/RECENT C2 CONNECTION ***" || echo "clean (no live C2 connection)"

# C2 in shell history (a manual test or the payload writing to a log)
grep -rl "$C2_RE" ~/.bash_history ~/.zsh_history ~/.local/share/fish/fish_history 2>/dev/null || echo "clean (shell history)"
```

If your endpoint has host-based firewall / EDR telemetry, search it for outbound to `216.126.225.243:8085-8087` from **on/after 2026-07-11**.

## Check 5: Shell history — install during the window

```bash
grep -hE "npm (install|update|ci)|pnpm (install|add)|yarn( add| install)?" ~/.bash_history ~/.zsh_history 2>/dev/null | \
  grep -i jscrambler || echo "no explicit jscrambler install in shell history (may still have installed transitively)"
```

## Check 6: Targeted credential stores — review, then rotate if exposed

If any of Checks 1–5 indicate the malicious version ran on this host, treat **all** of the following as exposed and rotate them (do not just inspect):

```bash
# Presence check of the stores the stealer targets (existence ≠ theft, but these are what it reads)
ls -la ~/.ssh/id_* ~/.npmrc ~/.aws/credentials ~/.config/gcloud/ ~/.azure/ ~/.kube/config 2>/dev/null
ls -la ~/.config/solana ~/.electrum ~/.ethereum 2>/dev/null            # crypto wallets / keystores
ls -d ~/.config/Claude ~/.cursor ~/.codeium/windsurf ~/.config/Code 2>/dev/null  # AI-tool configs
```

**Rotate on confirmed exposure:** SSH keys, npm/registry tokens (`~/.npmrc`), GitHub PATs, AWS/GCP/Azure/K8s credentials, signing keys, browser-stored secrets, Slack/Discord/Telegram tokens, and **any crypto-wallet seed phrase stored on the host** (move funds if a hot-wallet seed was on disk).

## Check 7: AI-agent conversation logs

The stealer harvests AI-tool configs; also check whether IOC strings appear in agent logs — **but exclude the investigating agent's own current session**, which will always hit because it just read these IOCs.

```bash
CURRENT=$(echo "$PWD" | sed 's|/|-|g')
grep -rliE "216\.126\.225\.243|jscrambler.*(8\.14\.0|8\.16\.0|8\.17\.0|8\.20\.0)" \
  "$HOME/.claude/projects" \
  "$HOME/Library/Application Support/Cursor" \
  "$HOME/Library/Application Support/Windsurf" \
  "$HOME/.config/github-copilot" 2>/dev/null | \
  grep -v "$CURRENT" | grep -v "paste-cache" | grep -v "file-history" \
  || echo "clean (no IOC strings in other AI-agent sessions)"
```

Hits that survive the self-exclusion filter are worth reviewing — a prior unrelated session containing these IOC strings is a real signal.

---

## Interpretation

- **Any malicious version on disk / in cache / in a lockfile (Checks 1–3)** → this host resolved a backdoored `jscrambler`. Assume the `preinstall` payload ran and go to Check 6 rotation.
- **Any C2 contact (Check 4)** → exfiltration likely succeeded; full credential rotation, and treat wallet seeds as compromised.
- **All clean** → consistent with no exposure, provided installs used a lock file pinned to a safe version. If the host ran `npm install` (non-`ci`) against a floating `jscrambler` range during the window, verify the resolved version before clearing.
