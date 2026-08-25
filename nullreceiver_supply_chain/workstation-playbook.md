# NullReceiver npm Campaign — Workstation Investigation Playbook

Playbook for checking whether a developer workstation was affected by the **NullReceiver** npm campaign (July–August 2026). Run this on each machine that worked on JS/TS code, or ran `npx agentgui`, during either exposure window.

> **Designed for AI agent execution.** Each check is self-contained with commands to run and expected output to interpret.

> **Why workstations matter here.** The second stage is fetched from the C2 at import time and runs with the installing user's privileges from a **detached** `node -e` process that survives the install finishing. A clean `node_modules` does not clear the machine. The expected payload family is **BeaverTail**, a credential and cryptocurrency-wallet stealer — hunt for it, but note it is not confirmed for this specific loader, and because the fetched stage is attacker-controlled and rotates, **not finding BeaverTail does not make the host clean**.

---

## Incident Reference

| Field | Value |
|---|---|
| Wave 1 packages (typosquats) | `bianira-ui@1.27.0`, `fluid-type-ui@2.0.8/2.0.9`, `tailwindcss-anim@0.0.1/1.0.0/1.1.0/1.1.1/1.2.1/1.2.2/1.3.3/1.3.5`, `tailwind-anim@0.0.1/1.0.0/1.1.0/1.1.1/1.2.0/1.2.1/1.2.3/1.2.4/1.2.5`, `scrollbar-hide-plugin@1.0.1`, `tailwind-animation-founder@2.5.7`, `post-css-transfer@0.0.1` |
| Wave 2 packages (hijacked maintainer) | `agentgui@1.0.1127`, `fsbrowse@0.2.28`, `godot-kit@1.0.1786316795` |
| Wave 3 packages (later additions) | `@kolbo/mcp@1.57.1` (hijacked legitimate), `tailwindcss-motion-advanced@1.0.1`, `postcss-initial-provider@3.0.4`, `envpack-conf@1.0.1` |
| Wave 4 packages (2026-08-19, **different obfuscation**) | `@wizloft/harness-kernel@0.1.1-alpha.3`, `@wizloft/harness-plugin-repository-files@0.1.1-alpha.3`, `postcss-initialize-provider@3.0.4` (typosquat — a *second* one shadowing `postcss-initial`, distinct from `postcss-initial-provider`) |
| Wave 1 window | 28 July – 5 August 2026 |
| Wave 2 window | 9 August 2026 23:03 UTC – 24 August 2026 07:52 UTC (`agentgui` was live the full ~14 days) |
| Wave 3 window | advisories filed 7 – 13 August 2026 |
| Wave 4 window | advisories filed 19 August 2026 |
| Attacker wallet (durable IOC) | `0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a` |
| C2 IP — current (2026-08-25) | `23.27.13.135` |
| C2 IP — **primary for retrospective hunting** | `166.88.134.62` (ports 443 and 80) — live 28 days, 25 Jul → 22 Aug. Covers nearly every window a real install could fall in; this is the address your old logs hold. **Not** a superseded footnote. |
| C2 IP — bootstrap | `163.34.229.243` — single tx, 25 Jul 06:42, replaced 6 min later. Chain-only, unpublished elsewhere. |
| Cadence vs rotation | The ~3h20m transaction cycle **re-advertises the same pointer**; infrastructure changed only twice in 208 txs over a month. Blocking an IP is worthwhile (each held ~4 weeks) — just re-resolve from the wallet rather than trusting any published value. |
| Payload paths | `GET /0x/cls` and `GET /0x/ls` |
| Campaign marker | `global.i="A9-2057"` (identical in `agentgui` and `fsbrowse`) |
| XOR keys | `q4FZkxX{!h,Sr3=@` (`/0x/cls`), `y-p_>d$0B&@^1aQk` (`/0x/ls`) |
| Ethereum RPC hosts | `eth.blockscout.com`, `1rpc.io`, `eth.drpc.org`, `ethereum-rpc.publicnode.com`, `eth-mainnet.public.blastapi.io`, `blockscout.com/api` |
| RPC methods | `eth_getBlockByNumber`, `eth_getTransactionCount`, `eth_blockNumber` |
| **Spoofed browser User-Agent** | Loader sends a Chrome/Safari `Mozilla/5.0 … AppleWebKit/537.36 … Chrome/13x` UA to the RPC hosts. **A Node process presenting a browser UA to an Ethereum RPC endpoint** is high-confidence and appears in no published source. |
| Wave 4 tarball SHA-256 | `harness-kernel-0.1.1-alpha.3.tgz` → `c0a07e8dcfadfb307a49866439c1acf38f31203fef0f4229c4e5540766e05fd9`; `harness-plugin-repository-files-0.1.1-alpha.3.tgz` → `5c2c8e8ba15ff681d640e7af1f8d8ebb56176319bd81bc5f58f41f5977fe1505` |
| Advisory wallet renderings are **corrupted** | MAL-2026-14287 prints a 44-hex-char invalid address; MAL-2026-13938 prints a 40-char address that *looks* valid but has an extra `0` and a dropped trailing `a`. Use the wallet in the row above, never a string copied from an advisory. |
| `fsbrowse@0.2.28` `index.js` SHA-256 | `f2a3c35cd49fce09824cbebb3a6c065b2749a672312e38e49c17c47999660174` |
| `fsbrowse-0.2.28.tgz` SHA-1 | `2c8fc0f6f39897039c46cb48d19674423888cbf8` |
| `agentgui@1.0.1127` payload | end of `database.js`, after 507 spaces of padding |
| Second stage | Expected BeaverTail (credentials + crypto wallets), **not confirmed for this loader** — absence is not proof of clean |

**`spoint` is NOT in scope** — MAL-2026-13725 is an analyst-refuted false positive. Do not scan for it.

For full incident detail see [playbook.md](playbook.md).

---

## Setup

```bash
# Durable IOCs
WALLET="0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a"
# All three C2 addresses the wallet has ever advertised. Hunt for ALL of them —
# the ~3h20m tx cycle is a keepalive re-advertising the SAME pointer, not rotation,
# so these are long-lived rather than disposable:
#   163.34.229.243 — bootstrap, 1 tx on 25 Jul (chain-only, unpublished anywhere)
#   166.88.134.62  — live 28 days (25 Jul -> 22 Aug). Most likely to be in old logs.
#   23.27.13.135   — current as of 25 Aug
# Still resolve the live value from the wallet before trusting this list is complete.
C2_IP="163\.34\.229\.243|166\.88\.134\.62|23\.27\.13\.135"
MARKER='global\.i="A9-2057"'
RPC_HOSTS="eth\.blockscout\.com|1rpc\.io|eth\.drpc\.org|ethereum-rpc\.publicnode\.com|eth-mainnet\.public\.blastapi\.io"

# Malicious name@version pattern.
#
# FOUR traps are baked into this pattern — do not "simplify" it:
#  (a) An unanchored `tailwindcss-anim` MATCHES the legitimate, very common
#      `tailwindcss-animate` (verified: 1 hit on a clean manifest). The `[@-]`
#      delimiter before the version is what prevents that false positive.
#  (b) npm pretty-prints package-lock.json with the package key and its "version"
#      on SEPARATE lines, so a `"name" ... version` pattern silently returns ZERO
#      on a lock file that pins a malicious version. This pattern instead matches
#      the single-line COORDINATE forms that every lockfile format does emit:
#      `name@ver`, `name-ver.tgz` (inside the `resolved` URL), `/name@ver:` (pnpm).
#  (c) SCOPED packages need a third form. npm strips the scope from the tarball
#      filename, so `@kolbo/mcp@1.57.1` appears in a package-lock `resolved` URL
#      as `/@kolbo/mcp/-/mcp-1.57.1.tgz` — the name and version are separated by
#      `/-/mcp-`, which `[@-]` does NOT bridge. The extra `@kolbo/mcp/-/mcp-`
#      alternative below covers that. Without it, a pinned scoped package in a
#      package-lock.json returns ZERO.
#  (d) Wave-3 typosquats are the LONGER name of a legitimate pair
#      (`postcss-initial-provider` vs real `postcss-initial`;
#      `tailwindcss-motion-advanced` vs real `tailwindcss-motion`). Matching the
#      longer literal is inherently safe here, but never shorten these to the
#      legitimate stem — `postcss-initial@3.0.4` is a REAL, widely-installed
#      package and the malicious twin shares its exact version number.
#      Validated to hit package-lock.json, yarn.lock, pnpm-lock.yaml and
#      package.json while staying clean on the legitimate neighbours.
MAL_RE='(bianira-ui)[@-]1\.27\.0|"bianira-ui"\s*:\s*"[^"]*1\.27\.0|(fluid-type-ui)[@-]2\.0\.[89]|"fluid-type-ui"\s*:\s*"[^"]*2\.0\.[89]|(tailwindcss-anim)[@-](0\.0\.1|1\.0\.0|1\.1\.[01]|1\.2\.[12]|1\.3\.[35])|"tailwindcss-anim"\s*:\s*"[^"]*(0\.0\.1|1\.0\.0|1\.1\.[01]|1\.2\.[12]|1\.3\.[35])|(tailwind-anim)[@-](0\.0\.1|1\.0\.0|1\.1\.[01]|1\.2\.[01345])|"tailwind-anim"\s*:\s*"[^"]*(0\.0\.1|1\.0\.0|1\.1\.[01]|1\.2\.[01345])|(scrollbar-hide-plugin)[@-]1\.0\.1|"scrollbar-hide-plugin"\s*:\s*"[^"]*1\.0\.1|(tailwind-animation-founder)[@-]2\.5\.7|"tailwind-animation-founder"\s*:\s*"[^"]*2\.5\.7|(post-css-transfer)[@-]0\.0\.1|"post-css-transfer"\s*:\s*"[^"]*0\.0\.1|(agentgui)[@-]1\.0\.1127|"agentgui"\s*:\s*"[^"]*1\.0\.1127|(fsbrowse)[@-]0\.2\.28|"fsbrowse"\s*:\s*"[^"]*0\.2\.28|(godot-kit)[@-]1\.0\.1786316795|"godot-kit"\s*:\s*"[^"]*1\.0\.1786316795|(@kolbo/mcp)[@-]1\.57\.1|@kolbo/mcp/-/mcp-1\.57\.1|"@kolbo/mcp"\s*:\s*"[^"]*1\.57\.1|(tailwindcss-motion-advanced)[@-]1\.0\.1|"tailwindcss-motion-advanced"\s*:\s*"[^"]*1\.0\.1|(postcss-initial-provider)[@-]3\.0\.4|"postcss-initial-provider"\s*:\s*"[^"]*3\.0\.4|(envpack-conf)[@-]1\.0\.1|"envpack-conf"\s*:\s*"[^"]*1\.0\.1|(@wizloft/harness-kernel)[@-]0\.1\.1-alpha\.3|@wizloft/harness-kernel/-/harness-kernel-0\.1\.1-alpha\.3|"@wizloft/harness-kernel"\s*:\s*"[^"]*0\.1\.1-alpha\.3|(@wizloft/harness-plugin-repository-files)[@-]0\.1\.1-alpha\.3|@wizloft/harness-plugin-repository-files/-/harness-plugin-repository-files-0\.1\.1-alpha\.3|"@wizloft/harness-plugin-repository-files"\s*:\s*"[^"]*0\.1\.1-alpha\.3|(postcss-initialize-provider)[@-]3\.0\.4|"postcss-initialize-provider"\s*:\s*"[^"]*3\.0\.4'

# Combined IOC pattern for text logs
IOC_RE="${WALLET}|${C2_IP}|/0x/cls|/0x/ls|${MARKER}|${RPC_HOSTS}|eth_getBlockByNumber|eth_getTransactionCount"

# Adjust to the user's real project roots
PROJECT_ROOTS="$HOME/projects $HOME/code $HOME/repos $HOME/work $HOME/dev"
```

---

## Check 1: Installed Affected Packages in `node_modules`

The most direct evidence. Check both the package name and its resolved version.

```bash
for root in $PROJECT_ROOTS; do
  [ -d "$root" ] || continue
  find "$root" -maxdepth 8 -type d \( \
      -path '*/node_modules/agentgui' -o \
      -path '*/node_modules/fsbrowse' -o \
      -path '*/node_modules/godot-kit' -o \
      -path '*/node_modules/bianira-ui' -o \
      -path '*/node_modules/fluid-type-ui' -o \
      -path '*/node_modules/tailwindcss-anim' -o \
      -path '*/node_modules/tailwind-anim' -o \
      -path '*/node_modules/scrollbar-hide-plugin' -o \
      -path '*/node_modules/tailwind-animation-founder' -o \
      -path '*/node_modules/post-css-transfer' -o \
      -path '*/node_modules/@kolbo/mcp' -o \
      -path '*/node_modules/tailwindcss-motion-advanced' -o \
      -path '*/node_modules/postcss-initial-provider' -o \
      -path '*/node_modules/envpack-conf' -o \
      -path '*/node_modules/@wizloft/harness-kernel' -o \
      -path '*/node_modules/@wizloft/harness-plugin-repository-files' -o \
      -path '*/node_modules/postcss-initialize-provider' \
    \) 2>/dev/null | while read d; do
      v=$(python3 -c "import json;print(json.load(open('$d/package.json')).get('version','?'))" 2>/dev/null)
      echo "$d  version=$v"
    done
done
```

**Note the exact directory names** — `node_modules/tailwindcss-animate` is the *legitimate* package and must not be reported. The `-path` patterns above are exact, so they will not match it.

Any hit whose version is on the malicious list means the payload was installed **and executed** (import-time trigger).

---

## Check 2: Payload Fingerprints in Installed Packages

The payload is appended to an otherwise legitimate file. Waves 1–3 obfuscate with `\u00XX` unicode escapes; **Wave 4 does not** — see the second block below.

```bash
# fsbrowse — hash the entry file against the known-malicious SHA-256
for f in $(find $PROJECT_ROOTS -path '*/node_modules/fsbrowse/index.js' 2>/dev/null); do
  echo "$f"
  shasum -a 256 "$f"
done
# Compare to: f2a3c35cd49fce09824cbebb3a6c065b2749a672312e38e49c17c47999660174
# (source: MAL-2026-13722 database_specific.indicators.evidence_files[].sha256)

# godot-kit — payload lives in lang/gdscript.js
find $PROJECT_ROOTS -path '*/node_modules/godot-kit/lang/gdscript.js' 2>/dev/null

# Generic: the wallet address in any installed package file
grep -rl "$WALLET" $PROJECT_ROOTS --include='*.js' --include='*.cjs' --include='*.mjs' 2>/dev/null

# Generic: dense unicode-escape obfuscation in an affected package's files
for d in $(find $PROJECT_ROOTS -maxdepth 8 -type d \( -path '*/node_modules/fsbrowse' -o -path '*/node_modules/godot-kit' -o -path '*/node_modules/agentgui' \) 2>/dev/null); do
  grep -rlE '(\\u00[0-9a-f]{2}){10,}' "$d" 2>/dev/null
done
```

**Interpreting the unicode-escape check:** minified bundles legitimately contain escape sequences. A hit is meaningful when it appears in a **hand-written-looking entry file** (`index.js`, `lang/gdscript.js`) rather than a `dist/` bundle, or when it sits **after** `module.exports` or after a run of trailing whitespace at end of file.

**Wave 4 needs a different fingerprint — the check above is blind to it.** `@wizloft/harness-plugin-repository-files@0.1.1-alpha.3` appends a **~35 KB obfuscator.io-packed IIFE at line 209 of `dist/index.js`** (303-entry rotated string array `_0x240a`, decoder `_0x4963`, control-flow flattening, hex-named identifiers) after a small legitimate plugin — no `\u00XX` escapes at all.

```bash
# obfuscator.io signature in the Wave 4 packages specifically
for d in $(find $PROJECT_ROOTS -maxdepth 9 -type d \
    \( -path '*/node_modules/@wizloft/harness-kernel' \
    -o -path '*/node_modules/@wizloft/harness-plugin-repository-files' \) 2>/dev/null); do
  echo "== $d"
  grep -clE '_0x[0-9a-f]{4,6}' "$d/dist/index.js" 2>/dev/null
  wc -c "$d/dist/index.js" 2>/dev/null   # ~35KB of packed payload inflates this
done
```

Scope that pattern to the affected packages — `_0x`-style identifiers are common in legitimate minified output, so it is a triage signal on a known-affected package, never an org-wide verdict on its own.

---

## Check 3: Lock Files in Local Projects

A lock file pinning `fsbrowse@0.2.28` is a finding even if `agentgui` is absent — this is the transitive amplifier.

```bash
for root in $PROJECT_ROOTS; do
  [ -d "$root" ] || continue
  find "$root" -maxdepth 6 \
    \( -name 'package-lock.json' -o -name 'yarn.lock' -o -name 'pnpm-lock.yaml' -o -name 'npm-shrinkwrap.json' \) \
    -not -path '*/node_modules/*' 2>/dev/null | while read lf; do
      if grep -qE "$MAL_RE" "$lf" 2>/dev/null; then
        echo "COMPROMISED PIN: $lf"
        grep -nE "$MAL_RE" "$lf" | head -3
      fi
    done
done
echo "(lock file scan complete)"
```

**Positive control** — prove the scan actually reads these files:

```bash
find $PROJECT_ROOTS -maxdepth 6 -name 'package-lock.json' -not -path '*/node_modules/*' 2>/dev/null | \
  xargs grep -lE '"react"|"typescript"|"lodash"' 2>/dev/null | head -3
# Expect at least one hit on a JS developer's machine. Empty output means the
# find paths are wrong and the CLEAN result above is meaningless — fix PROJECT_ROOTS.
```

Also flag floating ranges, which mean the lock file cannot be trusted:

```bash
find $PROJECT_ROOTS -maxdepth 6 -name 'package.json' -not -path '*/node_modules/*' 2>/dev/null | \
  xargs grep -lE '"(agentgui|fsbrowse|godot-kit)"\s*:\s*"(latest|\*)"' 2>/dev/null
```

---

## Check 4: npm / pnpm / yarn Cache

Caches retain tarballs after `node_modules` is deleted.

```bash
NPM_CACHE=$(npm config get cache 2>/dev/null)
if [ -d "$NPM_CACHE/_cacache" ]; then
  echo "Searching $NPM_CACHE/_cacache ..."

  # By known tarball hash (most reliable)
  grep -rl "2c8fc0f6f39897039c46cb48d19674423888cbf8" "$NPM_CACHE/_cacache" 2>/dev/null \
    && echo "FOUND — fsbrowse@0.2.28 tarball shasum in cache" || echo "fsbrowse 0.2.28 shasum: clean"

  # By package coordinate in the cache index
  grep -rlE "fsbrowse-0\.2\.28\.tgz|agentgui-1\.0\.1127\.tgz|godot-kit-1\.0\.1786316795\.tgz" \
    "$NPM_CACHE/_cacache/index-v5" 2>/dev/null \
    && echo "FOUND — malicious tarball reference in cache index" || echo "cache index: clean"
else
  echo "npm cache not found at $NPM_CACHE"
fi

# pnpm store
pnpm store path 2>/dev/null | while read p; do
  [ -d "$p" ] && grep -rlE "fsbrowse|agentgui|godot-kit" "$p" 2>/dev/null | head -5
done

# yarn cache
yarn cache dir 2>/dev/null | while read y; do
  [ -d "$y" ] && ls "$y" 2>/dev/null | grep -E "fsbrowse-0\.2\.28|agentgui-1\.0\.1127|godot-kit-1\.0\.1786316795"
done
```

---

## Check 5: `npx` Execution History

`agentgui`'s documented install path is `npx agentgui` — no manifest, no lock file, no trace in `node_modules`. The `_npx` cache is the only local artifact.

```bash
# npx keeps per-invocation package trees here
NPX_DIR="$(npm config get cache 2>/dev/null)/_npx"
if [ -d "$NPX_DIR" ]; then
  find "$NPX_DIR" -maxdepth 3 -name 'package.json' 2>/dev/null | \
    xargs grep -lE '"(agentgui|fsbrowse|godot-kit)"' 2>/dev/null
  # Show resolved versions for any hit
  find "$NPX_DIR" -maxdepth 4 -type d \( -name 'agentgui' -o -name 'fsbrowse' -o -name 'godot-kit' \) 2>/dev/null | \
    while read d; do
      echo "$d  version=$(python3 -c "import json;print(json.load(open('$d/package.json')).get('version','?'))" 2>/dev/null)"
    done
else
  echo "no _npx cache directory"
fi
```

---

## Check 6: Network Indicators

```bash
# Active connections to the C2
netstat -an 2>/dev/null | grep "$C2_IP" \
  && echo "FOUND — active C2 connection" || echo "C2 IP not in active connections"

# hosts file tampering
grep -E "$C2_IP|blockscout" /etc/hosts 2>/dev/null \
  && echo "FOUND — IOC in hosts file" || echo "hosts file clean"
```

**macOS — DNS query log (last 7 days):**

```bash
log show --predicate 'process == "mDNSResponder"' --last 7d 2>/dev/null | \
  grep -E "blockscout|drpc|publicnode|blastapi|1rpc" | head -20
```

**Linux — systemd-resolved:**

```bash
journalctl -u systemd-resolved --since "2026-07-28" 2>/dev/null | \
  grep -E "blockscout|drpc|publicnode|blastapi|1rpc"
```

Any Ethereum RPC resolution from a machine that does not do Web3 development is a strong signal — it is how the loader finds its C2, and unlike the IP it cannot be rotated away.

---

## Check 7: Detached Payload Process

The loader spawns a **detached** `node -e` that outlives the install.

```bash
# Long-lived node processes running inline code
ps aux | grep -E "node\s+-e" | grep -v grep

# macOS/Linux: node processes with no controlling terminal and an unexpected parent
ps -eo pid,ppid,tty,etime,command 2>/dev/null | grep -E "node" | grep -E "\?\?|\s\?\s" | grep -v grep
```

A `node -e` process with no tty, running for longer than any build, is suspicious. Capture its command line and open files before killing it:

```bash
# Set PID to the suspicious process id from the previous step.
# Do NOT write the placeholder inline — bash reads `<PID>` as input redirection
# and the command dies with a syntax error before it runs.
PID=12345

ps -p "$PID" -o command=
lsof -p "$PID" 2>/dev/null | head -30
```

---

## Check 8: Shell History

```bash
grep -nE "npx\s+agentgui|agentgui|fsbrowse|godot-kit|tailwindcss-anim@|tailwind-anim@|post-css-transfer" \
  ~/.zsh_history ~/.bash_history ~/.local/share/fish/fish_history 2>/dev/null \
  || echo "No affected-package references in shell history"
```

Correlate any hit's position in the file against the exposure windows. Shell history is usually undated — if `HISTTIMEFORMAT`/`setopt extended_history` was not enabled, treat a hit as "at some point" and fall back to Check 3 and Check 4 for timing.

---

## Check 9: Package-Manager Debug Logs

```bash
NPM_LOGS="${HOME}/.npm/_logs"
if [ -d "$NPM_LOGS" ]; then
  echo "npm logs: $(ls "$NPM_LOGS"/*.log 2>/dev/null | wc -l | tr -d ' ') files"
  grep -rlE "$MAL_RE|$IOC_RE" "$NPM_LOGS"/ 2>/dev/null \
    && echo "FOUND — IOC match in npm debug logs" || echo "No IOC matches in npm logs"
else
  echo "No npm log directory"
fi
```

**Limitation:** npm rotates these aggressively. Wave 1 was up to four weeks before this playbook's publication, so relevant logs are very likely purged. A clean result here proves nothing — Checks 1, 3 and 4 are the reliable signals.

---

## Check 10: AI Agent Conversation Logs

Agent logs capture full stdout/stderr of every command an agent ran, and persist far longer than npm debug logs. They are the best remaining record of a Wave 1 install.

**`agentgui` is itself an AI-agent GUI** that wraps Claude Code, Gemini CLI and OpenCode, and depends on `ccsniff` (which reads Claude Code JSONL output). On a machine that ran it, these logs are both evidence *and* potentially attacker-read material.

| Tool | Location |
|---|---|
| Claude Code | `~/.claude/projects/**/*.jsonl` |
| Cursor | `~/.cursor/conversations/`, `~/.cursor-server/data/` |
| Windsurf | `~/.windsurf/`, `~/.codeium/` |
| Copilot Chat | `~/.config/github-copilot/`, VS Code output logs |

**Scan, excluding the current investigating session** (it will always hit — it has been reading these IOCs):

```bash
CURRENT_SESSION_PROJECT=$(echo "$PWD" | sed 's|/|-|g')
grep -rliE "$IOC_RE|agentgui@1\.0\.1127|fsbrowse@0\.2\.28" \
  "$HOME/.claude/projects" \
  "$HOME/Library/Application Support/Cursor" \
  "$HOME/Library/Application Support/Windsurf" \
  "$HOME/.config/github-copilot" 2>/dev/null | \
  grep -v "${CURRENT_SESSION_PROJECT}" | grep -v "paste-cache" | grep -v "file-history"
```

**Classify surviving hits** — IOC mention alone is not compromise; co-occurrence with an executed install is:

```python
import json, glob, os

IOC = ['0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a',
       '163.34.229.243', '166.88.134.62', '23.27.13.135', '/0x/cls', '/0x/ls',
       'agentgui@1.0.1127', 'fsbrowse@0.2.28', 'eth.blockscout.com']
INSTALL = ['npm install', 'npm ci', 'npm add', 'npx agentgui', 'npx ', 'pnpm add',
           'yarn add', 'pnpm install', 'yarn install', 'bun install']
CURRENT = os.environ.get('PWD', '').replace('/', '-')

for fpath in glob.glob(os.path.expanduser('~/.claude/projects/**/*.jsonl'), recursive=True):
    if CURRENT and CURRENT in fpath:
        continue                     # skip the investigating session
    has_ioc = has_install = False
    for line in open(fpath, errors='replace'):
        try:
            obj = json.loads(line)
        except Exception:
            continue
        text = json.dumps(obj)
        if not has_ioc and any(i in text for i in IOC):
            has_ioc = True
        content = obj.get('content', '')
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    cmd = (block.get('input') or {}).get('command', '') or ''
                    if any(x in cmd.lower() for x in INSTALL):
                        has_install = True
    if has_ioc and has_install:
        print(f'INVESTIGATE: {fpath}')
    elif has_ioc:
        print(f'REFERENCE ONLY: {fpath}')
```

- **`INVESTIGATE`** — open the file and look for the install output. Search for `added fsbrowse@0.2.28`, `agentgui@1.0.1127`, or any `/0x/cls` fetch in a tool result.
- **`REFERENCE ONLY`** — the session discussed the incident but ran no install. Not evidence of compromise.

---

## Check 11: Locally Built Docker Images

```bash
docker images --format '{{.Repository}}:{{.Tag}} {{.CreatedAt}}' 2>/dev/null | \
  grep -E "2026-07-2[89]|2026-07-3[01]|2026-08-0[1-9]|2026-08-1[0-9]|2026-08-2[0-4]" \
  && echo "WARNING — images built during an exposure window" \
  || echo "No images built during the windows"
```

Rebuild any match with `docker build --no-cache`. The payload is baked into the layer; correcting the manifest does not remove it.

---

## Results Summary

| Check | IOC | Status |
|---|---|---|
| 1. Installed packages | Affected name at malicious version in `node_modules` | found / clean |
| 2. Payload fingerprints | `index.js` SHA-256, wallet string, unicode-escape blocks | found / clean |
| 3. Lock files | Malicious version pinned (incl. transitive `fsbrowse`) | found / clean |
| 4. Package-manager cache | Malicious tarball shasum / coordinate | found / clean |
| 5. `npx` cache | `agentgui` / `fsbrowse` / `godot-kit` tree | found / clean |
| 6. Network | C2 IP, hosts file, Ethereum RPC DNS | found / clean |
| 7. Detached process | Long-lived `node -e` with no tty | found / clean |
| 8. Shell history | `npx agentgui`, affected package installs | found / clean |
| 9. npm debug logs | IOC strings (likely purged) | found / clean / purged |
| 10. Agent conversations | IOC + install in same session | investigate / reference only / clean |
| 11. Docker images | Built during a window | found / clean |

### If any check returns "found"

1. **Treat the workstation as fully compromised.** The payload fetches and runs attacker-supplied code that the attacker can rotate at will — you cannot bound its behaviour from the loader alone.
2. **Preserve evidence first** — copy the affected `node_modules` tree, lock files, cache entries, and the detached process's command line before cleaning.
3. **Rotate every credential resident on or reachable from this machine, from a different machine:** SSH keys, cloud credentials, npm tokens, GitHub PATs, registry credentials, signing keys, browser-stored credentials, and — because BeaverTail targets them specifically — **any cryptocurrency wallet keys or seed phrases**.
4. **Rotate credentials that appeared in AI-agent sessions on this host**, not just those in files. Agent logs contain command output, and `agentgui` reads Claude Code JSONL by design.
5. **Kill the detached process and clean caches:** `npm cache clean --force`, remove `node_modules`, clear the `_npx` cache.
6. **Block at the network edge:** all three known C2 addresses — `163.34.229.243`, `166.88.134.62`, `23.27.13.135` — and alert on Ethereum RPC egress from developer subnets. Blocking is genuinely worthwhile here (each address held for weeks, not hours), but re-resolve the live value from the wallet periodically rather than treating the list as final.
7. **Consider re-imaging.** The second stage stages follow-on tooling; this playbook enumerates the loader's artifacts, not everything BeaverTail may have installed.
