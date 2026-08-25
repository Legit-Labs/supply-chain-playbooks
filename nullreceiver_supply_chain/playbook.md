# NullReceiver npm Campaign (July–August 2026) — Investigation Playbook

Playbook for investigating whether a GitHub org was affected by the **NullReceiver** npm campaign — **17 packages, 33 malicious versions across four waves** that resolve their C2 address from an attacker-controlled **Ethereum wallet** and execute a fetched second stage at module-import time. Attributed to the DPRK-linked **Contagious Interview** campaign (also tracked as UNC5342).

> **Wallet still live as of 2026-08-25.** The attacker wallet was still broadcasting C2 pointer transactions on a **~3h20m cycle**, most recently `2026-08-25 08:24 UTC`. This is not a retrospective clean-up exercise — the delivery channel is actively maintained, so a host that was compromised during a window and only superficially cleaned will still resolve C2 and fetch a **current** second stage on its next execution.
>
> **The ~3h20m cycle is a keepalive, NOT rotation — and this changes your response.** Reading the wallet's full outbound history (208 transactions, 2026-07-25 → 2026-08-25) shows it **re-advertises the same pointer** every ~3h20m and has changed infrastructure only **twice in a month**:
>
> | C2 IP | Txs | First seen | Last seen | Held for |
> |---|---|---|---|---|
> | `163.34.229.243` | 1 | 2026-07-25 06:42:35 | 2026-07-25 06:42:35 | 6 minutes (bootstrap) |
> | `166.88.134.62` | 178 | 2026-07-25 06:48:35 | 2026-08-22 00:08:11 | **28 days** |
> | `23.27.13.135` | 29 | 2026-08-22 01:28:47 | 2026-08-25 08:24:59 | current |
>
> Two consequences:
>
> - **IP blocklisting is worth doing.** An address holds for roughly four weeks, which is real protective value. Just re-resolve from the wallet periodically rather than treating a blocklist entry as permanent.
> - **`166.88.134.62` is the most important IOC for retrospective hunting, not a footnote.** It was the live C2 for the whole of 2026-07-25 → 2026-08-22 — essentially every window in which a real install could have happened. Do not skip it as "superseded"; it is the address your archived flow logs will actually contain.
>
> Note that the wallet's first transaction (2026-07-25 06:42) predates the first advisory (`bianira-ui`, 2026-07-28) by three days — infrastructure was staged before the packages went live.

> **CI/CD platform note:** This playbook targets GitHub Actions. For other platforms (GitLab CI, Jenkins, CircleCI, Bitbucket, Azure DevOps), adapt the log-collection commands — the investigation logic is unchanged: find references to the affected packages, resolve what was *actually installed*, collect run logs from the exposure windows, and search for the package versions plus the Ethereum-RPC network IOCs.

> **Trigger model — read this before choosing where to look.** The payload runs **at module load / import time**, reachable via the package entry point, its `bin` wrapper, or any module that `require()`s it. It is **not** confined to a lifecycle hook.
>
> - **`--ignore-scripts` does NOT mitigate this.** Do not treat "we disable install scripts" as a clean finding.
> - A build that merely **bundles or compiles** an affected package is exposed, even with no install hook running.
> - Detection therefore spans **manifests + lock files + CI install logs + runtime/network egress** — not install logs alone.

> **Related incidents in this repo — check all three, they are NOT the same campaign.** This is the third blockchain-resolved-C2 npm compromise in five weeks, and the mechanisms differ in ways that change what you grep for:
>
> | Incident | Chain mechanism | Address | Second stage |
> |---|---|---|---|
> | [joyfill](../joyfill_supply_chain/playbook.md) (28 Jul) | Tron + Aptos + BNB Smart Chain transactions | — | DEV#POPPER RAT (`ss_*`, `/$/boot`) |
> | [keyv / cacheable](../keyv_cacheable_supply_chain/playbook.md) (4 Aug) | Ethereum **contract** storage | `0xE1f2395ee43e45A1556EC6438a88c31B83493103` | Shai-Hulud worm (`math_init.js`) |
> | **NullReceiver** (this playbook) | Ethereum **wallet's latest outbound transaction recipient bytes** — zero-value, zero-data, **no contract interaction** | `0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a` | BeaverTail expected, unconfirmed for this loader |
>
> Do not substitute one playbook's IOCs for another's — every C2 address, fetch path, and payload family is different. What **does** generalise is the detection primitive: **any blockchain RPC egress from build infrastructure or a developer workstation**. If you are hunting one of these, hunt all three at the network layer in a single pass (Phase 3).

---

## Incident Details

An attacker published malicious versions of **17 npm packages across four waves** — and pivoting on the wallet across the OSSF malicious-packages corpus surfaces **37 records / 67 versions spanning 2026-06-24 → 2026-08-19**, so treat the 16 below as the analysed subset rather than the campaign's full extent (Phase 0 re-checks this). Rather than hardcoding a C2 address, the loader reads the **most recent outbound transaction from a fixed attacker Ethereum wallet** and decodes IPv4 addresses out of the transaction's recipient (`to`) field. The transactions are zero-value, zero-data transfers with no smart-contract interaction — which is what separates **NullReceiver** from the older **EtherHiding** technique, and which limits the channel to a few bytes.

With the decoded IP, the loader fetches XOR-encrypted JavaScript over plaintext HTTP from **two** paths — `/0x/cls` and `/0x/ls`, each with its own XOR key — and executes it twice over: via `eval`, and via a **detached** `spawn('node', ['-e', ...], { detached: true, stdio: 'ignore', windowsHide: true })` that survives the parent process exiting.

**On the second stage.** The fetched code is attacker-supplied at request time and is *not* fixed in the package, so what actually ran on a given host depends on what the C2 was serving at that moment. **BeaverTail** — the credential and crypto-wallet stealer that is the hallmark of Contagious Interview — is the expected family and the right thing to hunt for on the endpoint, but it has been directly tied to a *different* loader in this campaign cluster (XORIndex, via `eth-auditlog`) rather than confirmed as the payload of this specific NullReceiver loader. The primary source (OpenSourceMalware) calls it only a "Node.js RAT" and publishes no payload inventory. Hunt for BeaverTail artifacts, but do not treat their absence as proof a host is clean, and do not report "BeaverTail confirmed" on the strength of a NullReceiver package match alone.

> **Do not scope this down to "crypto theft" — it is the most common way this incident gets under-triaged.** Two corrections. **(1) The package steals nothing on its own**: it is a general-purpose loader that executes arbitrary attacker code with the privileges of the developer or build agent that imported it, so the exposure is bounded by what that identity can reach, not by what the payload happened to be. **(2) BeaverTail is not wallet-only**: its documented collection covers browser credentials and profiles, **cloud credentials, SSH material, shell history**, and the **macOS login keychain** (saved passwords, certificates, application secrets), and it chains to **InvisibleFerret**, a modular backdoor with remote access. Contagious Interview's *victimology* skews crypto/fintech, but victimology is not capability — scope the investigation to every credential reachable from the affected host, and treat an org with no cryptocurrency exposure as fully in scope.

The attacker can repoint the loader at new infrastructure by broadcasting one transaction, so **no published IP is authoritative** — resolve the current one from the wallet yourself. In practice, though, the observed IPs have been long-lived (28 days for `166.88.134.62`), so blocklisting is still worthwhile; it just needs periodic re-resolution. The **wallet address** and the **Ethereum-RPC egress pattern** are the indicators that cannot be rotated away at all, and they are what detection should key on.

### Advisories

| Package | Advisory | Payload detail |
|---|---|---|
| `fsbrowse@0.2.28` | MAL-2026-13722 | **Fullest analysis** — read this one first |
| `godot-kit@1.0.1786316795` | MAL-2026-13723 | Same payload, second package |
| `agentgui@1.0.1127` | MAL-2026-14402 / GHSA-3g4v-p5hc-83qm | Boilerplate only, no payload detail |
| Wave 1 packages | MAL-2026-11132, -11136, -11487, -11500, -12192, -12218, -12417 | Per-package records |
| `tailwindcss-motion-advanced@1.0.1` | MAL-2026-13604 | Wave 3; details cite the same wallet |
| `postcss-initial-provider@3.0.4` | MAL-2026-13696 | Wave 3; details cite the same wallet |
| `envpack-conf@1.0.1` | MAL-2026-13921 | Wave 3; details cite the same wallet |
| `@kolbo/mcp@1.57.1` | MAL-2026-13938 | Wave 3; hijacked legitimate package |

### Affected packages

**Wave 1 — typosquats of popular Tailwind / PostCSS plugins (28 July – 5 August 2026).** These shadow real, widely-installed packages: `tailwindcss-anim` / `tailwind-anim` sit beside the legitimate **`tailwindcss-animate`**, and `scrollbar-hide-plugin` shadows **`tailwind-scrollbar`**. Expect the legitimate neighbours to be present in customer orgs — that is the point of the typosquat, and it is also your false-positive risk.

**Wave 2 — hijacked maintainer account (9 August 2026, 23:03–23:07 UTC).** Three packages from a single prolific npm publisher (`lanmower` / GitHub `AnEntrypoint`), published **within a three-minute span** — consistent with an automated publish from a stolen credential rather than a hand-cut release.

```bash
# Wave 1 — typosquats
export W1_PKGS='bianira-ui fluid-type-ui tailwindcss-anim tailwind-anim scrollbar-hide-plugin tailwind-animation-founder post-css-transfer'
# Wave 2 — hijacked maintainer (9 Aug burst)
export W2_PKGS='agentgui fsbrowse godot-kit'
# Wave 3 — later additions, advisories filed 7–13 Aug. @kolbo/mcp is a hijacked
# legitimate package; the other three are typosquats.
export W3_PKGS='@kolbo/mcp tailwindcss-motion-advanced postcss-initial-provider envpack-conf'
# Wave 4 — 2026-08-19, the most recent known additions. Obfuscation CHANGED here (see below).
export W4_PKGS='@wizloft/harness-kernel @wizloft/harness-plugin-repository-files postcss-initialize-provider'
export ALL_PKGS="$W1_PKGS $W2_PKGS $W3_PKGS $W4_PKGS"
```

> **The affected list is provisional.** New advisories referencing this same wallet were still being filed as late as 13 August 2026. Before running this playbook, re-check for newer members: query OSV for any npm advisory whose details cite `0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a`, and treat the wallet — not the package list — as the campaign's identity.

| Package | Malicious versions | Wave |
|---|---|---|
| `bianira-ui` | `1.27.0` | 1 |
| `fluid-type-ui` | `2.0.8`, `2.0.9` | 1 |
| `tailwindcss-anim` | `0.0.1`, `1.0.0`, `1.1.0`, `1.1.1`, `1.2.1`, `1.2.2`, `1.3.3`, `1.3.5` | 1 |
| `tailwind-anim` | `0.0.1`, `1.0.0`, `1.1.0`, `1.1.1`, `1.2.0`, `1.2.1`, `1.2.3`, `1.2.4`, `1.2.5` | 1 |
| `scrollbar-hide-plugin` | `1.0.1` | 1 |
| `tailwind-animation-founder` | `2.5.7` | 1 |
| `post-css-transfer` | `0.0.1` | 1 |
| `agentgui` | `1.0.1127` | 2 |
| `fsbrowse` | `0.2.28` | 2 |
| `godot-kit` | `1.0.1786316795` | 2 |
| `@kolbo/mcp` | `1.57.1` | 3 |
| `tailwindcss-motion-advanced` | `1.0.1` | 3 |
| `postcss-initial-provider` | `3.0.4` | 3 |
| `envpack-conf` | `1.0.1` | 3 |
| `@wizloft/harness-kernel` | `0.1.1-alpha.3` | 4 |
| `@wizloft/harness-plugin-repository-files` | `0.1.1-alpha.3` | 4 |
| `postcss-initialize-provider` | `3.0.4` | 4 |

> **⚠️ Wave 4 (2026-08-19) changed the obfuscation — the unicode-escape fingerprint will MISS it.** MAL-2026-14287 / -14288. Earlier waves hid strings as `\u00XX` escape sequences; `@wizloft/harness-plugin-repository-files` instead appends a **~35 KB obfuscator.io-packed IIFE at line 209 of `dist/index.js`** — 303-entry rotated string array (`_0x240a`) with a decoder function (`_0x4963`), control-flow flattening, and hex-named identifiers — after a small legitimate plugin. The RPC endpoint set also shifted (`eth.drpc.org`, `eth.publicnode.com`, `ethereum-rpc.publicnode.com`, blockscout, plus an Etherscan-style API). Same `/0x/…` XOR-payload retrieval and same import-time async IIFE, so it is the same campaign — but **any detection keyed only on `\u00XX` density is blind to it.** Grep for obfuscator.io artifacts as well:
>
> ```bash
> # obfuscator.io signature: hex-named identifiers + large rotated string array
> grep -rlE '_0x[0-9a-f]{4,6}' --include='*.js' --include='*.mjs' --include='*.cjs' . 2>/dev/null
> ```
>
> That pattern has a real false-positive rate — plenty of legitimate minified bundles use hex identifiers — so treat it as a triage signal on an *affected package's* files, not as a standalone org-wide verdict.
>
> **Two campaign advisories print a corrupted wallet address. Do not grep either as published — verified against the tarballs.**
>
> The obfuscator splits every string into 10-character chunks reassembled at runtime. In both Wave 4 packages the chunks are `0xa322E5f3` + `D311D3080e` + `6f0121063e` + `9aDC2490Ef` + `1a`, which concatenate to exactly `0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a` — **the same wallet as every other wave, confirmed by static inspection of both `dist/index.js` files.** Wave 4 is definitively the same campaign; there is no second marker address to hunt.
>
> | Advisory | Prints | Problem |
> |---|---|---|
> | MAL-2026-14287 | `0xa322E5f39aDC2490Ef6f0121063e358050D311D3080e` | **44 hex chars** — structurally invalid. The chunks were reassembled out of order, with a spurious `358050` inserted and the trailing `1a` dropped. |
> | MAL-2026-13938 (`@kolbo/mcp`) | `0xa322E5f3D311D3080e6f01210063e9aDC2490Ef1` | **40 hex chars — looks valid but is not.** An extra `0` inside `6f0121` → `6f01210` and the trailing `a` dropped. **This is the more dangerous of the two:** a length check passes, so it silently matches nothing. |
>
> Always use the reassembled value above, never a string copied from an advisory.

> ### ⚠️ Never match on version number alone
>
> These typosquats **deliberately reuse the version numbers of the packages they shadow**, so a version-only match produces confident false positives on entirely clean projects.
>
> The sharpest case: malicious **`postcss-initial-provider@3.0.4`** shadows legitimate **`postcss-initial`**, which has a real, widely-installed **`3.0.4`**. Matching `3.0.4` in the `postcss-initial*` namespace flags clean consumers of the legitimate package. Same trap for `tailwindcss-anim` / `tailwind-anim` against legitimate `tailwindcss-animate`.
>
> Always match the **exact full package name AND the version together**. When reporting a hit, quote the full name.

> **`spoint` is NOT in scope.** `spoint@0.1.695–0.1.700` carries MAL-2026-13725, but Amazon Inspector's own write-up **refutes** it: the record fired on keyword co-occurrence (`curl`, `ping`, `POST`, `GET`) in a legitimate room/region orchestration SDK, with no attacker C2, no secret access, and no require-time execution path demonstrated — "keyword co-occurrence in networking code … cannot by itself establish exfiltration intent." `spoint` has ~60k downloads/month. **Do not scan for it**; you will generate false positives on clean customers.

### ⚠️ The floating-range amplifier — a clean direct version is not enough

`agentgui` declared its dependency as **`"fsbrowse": "latest"`**. While `fsbrowse@0.2.28` was live, installing even the **clean** `agentgui@1.0.1126` resolved the malicious `fsbrowse` **transitively**.

Consequences for this investigation:

- **Version-matching the packages a customer named directly will miss real exposure.** You must resolve what was actually installed.
- `agentgui`'s documented install path is **`npx agentgui`** — no manifest, no lock file, no protection at all.
- `agentgui`'s `postinstall` runs `node scripts/patch-fsbrowse.js`, which imports the compromised module.
- Any package anywhere in the tree with a floating `latest` / `*` / unbounded range on an affected name has the same problem.

### ⚠️ Unpublished does not mean unavailable

The malicious versions no longer resolve through `npm install` — but **the tarballs are still served by the registry CDN**. Verified 2026-08-25: `GET https://registry.npmjs.org/@wizloft/harness-kernel/-/harness-kernel-0.1.1-alpha.3.tgz` returns **HTTP 200** with a 33,136-byte body, and the same holds for `harness-plugin-repository-files-0.1.1-alpha.3.tgz` (17,032 bytes), even though neither version appears in the packument's `versions` map.

Two implications:

- **Any lock file, cache entry, mirror, or CI config that pins an exact malicious version can still fetch it and re-execute the payload.** "It was removed from npm" is not remediation and not a reason to skip the lock-file scan.
- **You can hash-verify your own findings.** Download by direct tarball URL and compare against the SHA-256 values in the IOC table rather than trusting a version string.

```bash
# Retrieve for analysis only. Do NOT npm install, and do not run node against it.
curl -s -o /tmp/w4.tgz "https://registry.npmjs.org/@wizloft/harness-kernel/-/harness-kernel-0.1.1-alpha.3.tgz"
shasum -a 256 /tmp/w4.tgz   # expect c0a07e8dcfadfb307a49866439c1acf38f31203fef0f4229c4e5540766e05fd9
mkdir -p /tmp/w4 && tar xzf /tmp/w4.tgz -C /tmp/w4   # extraction is inert; execution is not
```

### Exposure windows

| Package | Published (UTC) | Removed from npm (UTC) | Live for |
|---|---|---|---|
| Wave 1 packages | 28 Jul – 5 Aug 2026 | 28 Jul – 5 Aug 2026 (per package) | days |
| `fsbrowse@0.2.28` | 9 Aug 23:06 | 10 Aug 16:08 | ~17 hours |
| `godot-kit` | 9 Aug 23:06 | 10 Aug 16:29 | ~17 hours |
| **`agentgui@1.0.1127`** | **9 Aug 23:03** | **24 Aug 07:52** | **~14 days** |

`agentgui@1.0.1127` is the outlier and the most likely source of real exposure: npm did not remove it until **two weeks after** its siblings were pulled, and for that entire period it was the **highest version**, so `npm install agentgui` and `npx agentgui` resolved it by default.

**Recommended scan windows (padded):**

```bash
export W1_SINCE="2026-07-28T00:00:00Z"; export W1_UNTIL="2026-08-06T00:00:00Z"
export W2_SINCE="2026-08-09T22:00:00Z"; export W2_UNTIL="2026-08-24T12:00:00Z"
```

### Indicators of compromise

| IOC | Value | Where it shows up |
|---|---|---|
| **Attacker wallet (durable)** | `0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a` | package source, CI logs, agent logs |
| Decoded C2 IP — **current** | `23.27.13.135` (both decoded slots), read from the wallet's latest transaction on **2026-08-25** | network logs |
| Decoded C2 IP — **primary for retrospective hunting** | `166.88.134.62` (ports 443 **and** 80) — live 2026-07-25 → 2026-08-22, i.e. **28 days covering nearly every window in which a real install could have happened**. Not a footnote: this is the address archived flow logs will contain. | historical network logs |
| Decoded C2 IP — bootstrap | `163.34.229.243` — a single transaction at 2026-07-25 06:42:35, replaced 6 minutes later. **Not present in any published source**; chain-only. | historical network logs |
| **Cadence vs rotation** | The ~**3h20m** transaction cycle is a **keepalive that re-advertises the same pointer**, not rotation. Infrastructure changed only **twice in a month** across 208 transactions. So blocklisting an IP is worthwhile (each held ~4 weeks) — but re-resolve from the wallet periodically, and never assume a published IP is current. | — |
| Payload retrieval paths | `GET /0x/cls` **and** `GET /0x/ls` on a bare IP; **port 443 serving plaintext HTTP, not TLS** | proxy / NetFlow |
| XOR keys | `q4FZkxX{!h,Sr3=@` (for `/0x/cls`) and `y-p_>d$0B&@^1aQk` (for `/0x/ls`) | package source (after decoding `\u00XX` escapes) |
| Campaign / build marker | `global.i="A9-2057"` — **verified byte-identical in both `agentgui@1.0.1127` and `fsbrowse@0.2.28`**, so it is campaign-wide, not per-package. One of the strongest static strings to grep for. | package source |
| On-chain taunt string | Bytes of the pointer tx `to` field after the two encoded IPs decode to ASCII `helloipbot!!` | blockchain |
| Ethereum RPC endpoints | `eth.blockscout.com`, `1rpc.io/eth`, `eth.drpc.org`, `ethereum-rpc.publicnode.com`, `eth-mainnet.public.blastapi.io` | DNS / proxy / CI logs |
| JSON-RPC methods | `eth_getBlockByNumber`, `eth_getTransactionCount`, **`eth_blockNumber`** from a Node process | CI logs, host telemetry |
| **Spoofed browser User-Agent** | The loader sends a **Chrome/Safari `Mozilla/5.0 … AppleWebKit/537.36 … Chrome/13x` User-Agent** to the RPC hosts. A **Node.js process presenting a browser UA to an Ethereum RPC endpoint** is a high-confidence anomaly and appears in no published write-up — recovered from the Wave 4 string array. | proxy logs with UA capture |
| Block-explorer fallback | `blockscout.com/api` (reassembled from the chunk `ut.com/api`) | DNS / proxy |
| Prefix-strip regex | `/^0x/i` applied to the decoded address — an internal artifact, **not** a URL path | package source |
| Wave 4 tarball SHA-256 | `@wizloft/harness-kernel@0.1.1-alpha.3` → `c0a07e8dcfadfb307a49866439c1acf38f31203fef0f4229c4e5540766e05fd9`; `@wizloft/harness-plugin-repository-files@0.1.1-alpha.3` → `5c2c8e8ba15ff681d640e7af1f8d8ebb56176319bd81bc5f58f41f5977fe1505` | npm cache |
| Execution pattern | detached `node -e` child; `eval` of network-fetched content; `os.tmpdir()` staging | CI logs, EDR |
| Obfuscation fingerprint — **waves 1–3** | long runs of `\u00XX` unicode escapes; IIFE appended after `module.exports` or after whitespace padding at EOF | package files in `node_modules` |
| Obfuscation fingerprint — **wave 4 (different)** | obfuscator.io packing: rotated string array `_0x240a`, decoder `_0x4963`, control-flow flattening, hex-named `_0x`-style identifiers, strings split into **10-character chunks** concatenated at runtime. **No `\u00XX` escapes at all** — the wave 1–3 fingerprint does not fire on these. | `dist/index.js` in the `@wizloft/*` packages |
| `fsbrowse@0.2.28` `index.js` | SHA-256 `f2a3c35cd49fce09824cbebb3a6c065b2749a672312e38e49c17c47999660174` | `node_modules/fsbrowse/index.js` |
| `fsbrowse-0.2.28.tgz` | SHA-1 `2c8fc0f6f39897039c46cb48d19674423888cbf8` | npm cache |
| `agentgui@1.0.1127` payload location | End of `database.js`, appended after **507 spaces** of padding following `export default { queries };` | `node_modules/agentgui/database.js` |
| `agentgui-1.0.1127.tgz` | SHA-1 `c34ffd93876ee802d476e7ed981e5f38fcf15bbc` | npm cache |
| `godot-kit` payload location | `lang/gdscript.js` (reachable via `lang/loader.js`, `test.js`) | `node_modules/godot-kit/` |
| Second stage | Expected to be BeaverTail (credential + crypto-wallet stealer), but **not confirmed for this loader** — see the note in Incident Details | workstation |

> **Hash correction (2026-08-25).** The two `fsbrowse@0.2.28` hashes above were previously recorded as SHA-256 `f347ed56…` / SHA-1 `69ee7ef1…`. Those do not match the published artifact and would have produced a **false clean** for anyone scanning by hash. The values now listed were recomputed from the tarball and cross-checked against the registry-recorded `dist.shasum` for that exact version, which matches byte-for-byte.
>
> Note the `agentgui` and `fsbrowse` **tarball** SHA-1s are the registry-recorded `dist.shasum` values. A `.tgz` fetched through a mirror can be re-compressed and hash differently even when its contents are identical — so if a tarball hash misses, fall back to the **extracted-file** hash and the `A9-2057` marker, which are content-based and mirror-independent.

### What IS affected

- Any `npm install` / `pnpm install` / `yarn install` / `bun install` that resolved an affected version during a window — **direct or transitive**.
- Any `npx agentgui` invocation between 9 and 24 August 2026 (no lock file involved).
- CI runs and Docker builds that installed JS deps during a window, **including those using `--ignore-scripts`** (import-time trigger).
- Builds that only **bundled or compiled** an affected package — bundlers import modules to resolve them.
- Developer workstations that installed or ran any affected package.
- Container images built during a window — the payload is baked into the layer.
- Your **own published packages**, if their lock files pin an affected version, or if a maintainer's credentials were stolen.

### What is NOT affected

- Installs from a committed lock file with `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --frozen-lockfile` / `yarn install --immutable`, **provided the lock file pins a non-malicious version and was not regenerated during a window**.
- The **legitimate neighbour packages** these typosquats shadow: `tailwindcss-animate`, `tailwind-scrollbar`, `postcss`, `autoprefixer`. These are clean — finding them is not a finding.
- `fsbrowse@0.2.27` and earlier, and `fsbrowse@0.2.29`+ — only `0.2.28` is malicious.
- `agentgui@1.0.1126` and earlier **as a direct version match** — but see the floating-range amplifier: a `1.0.1126` install during the `fsbrowse@0.2.28` window still resolved a malicious transitive dep. Verify the resolved `fsbrowse` version before clearing.
- `spoint` (any version) — analyst-refuted false positive.
- Source-code-only references (an `import` in a `.ts` file with no install during a window).
- Pre-built Docker images not rebuilt during a window.

### Lock file protection

Lock files **do** protect here, with one important caveat.

They protect when: `npm ci` / `--frozen-lockfile` / `--immutable` is used, the lock file predates the window, and the pinned version is not on the malicious list.

They do **NOT** protect when:

- No lock file is committed.
- CI runs `npm install` / `pnpm install` / `yarn install` without a frozen flag.
- The lock file was regenerated **during** a window.
- A Dependabot / Renovate PR merged during a window.
- **A floating range (`latest`, `*`, unbounded) exists anywhere in the tree for an affected name** — this is the `agentgui` → `fsbrowse@latest` case, and it defeats lock-file reasoning about the *direct* dependency.
- The install path is `npx` — no lock file is consulted at all.

**Caveat specific to this incident:** a lock file that pins `fsbrowse@0.2.28` is itself the finding, even if `agentgui` is absent. Grep lock files for the malicious *versions*, not just the package names you expect.

---

## Pitfalls & Fixes

Read before starting.

1. **`--ignore-scripts` is not a clean finding.** The trigger is import-time. A customer saying "we always use `--ignore-scripts`" has not ruled anything out. Verify resolved versions instead.

2. **Do not clear a repo on the direct version alone.** `agentgui@1.0.1126` looks clean and is not. Always resolve the transitive `fsbrowse` version from the lock file or the CI log.

3. **The typosquat names are a prefix of legitimate packages in heavy use — and `package-lock.json` splits name from version across lines.** Two verified traps, both of which flip a verdict:

   **(a) Prefix collision — false POSITIVE.** `tailwindcss-anim` is a literal prefix of the legitimate, very widely installed `tailwindcss-animate`. Confirmed by dry-run: `grep -c "tailwindcss-anim"` on a clean manifest declaring only `tailwindcss-animate@1.0.7` returns **1**. Left unanchored, this reports "compromised" on a large share of frontend orgs. Always bind the name to a version with a delimiter:
   ```bash
   # WRONG — matches the legitimate tailwindcss-animate (verified: 1 hit on a clean file)
   grep -r "tailwindcss-anim" .
   # RIGHT — name must be followed by @ or - and then a malicious version
   grep -rE 'tailwindcss-anim[@-](1\.3\.5|1\.3\.3|1\.2\.[12]|1\.1\.[01]|1\.0\.0|0\.0\.1)' .
   ```
   The `[@-]` delimiter is what makes this safe: in `tailwindcss-animate-1.0.7.tgz` the character after the prefix is `a`, not `@` or `-`. Verified 0 hits.

   **(b) Split name/version — false NEGATIVE, and this one is worse.** npm pretty-prints `package-lock.json` with the package key and its version on **separate lines**:
   ```json
       "node_modules/fsbrowse": {
         "version": "0.2.28",
   ```
   A line-based grep for `"fsbrowse"` near a version therefore matches **nothing** — a lock file that pins the malicious `fsbrowse@0.2.28` returns **CLEAN**. Verified: an early draft of `$MAL_RE` built on the `"name" … version` shape scored 0 hits on exactly this fixture. What saves you is that all three lockfile formats still emit a **single-line coordinate** somewhere — the `resolved` tarball URL (`fsbrowse-0.2.28.tgz`) in npm and yarn, and the `/fsbrowse@0.2.28:` key in pnpm. `$MAL_RE` in Setup is built on those coordinate forms and is validated to hit `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` and `package.json` while staying clean on the legitimate neighbours. **Don't "simplify" it back to name-then-version.** For `package-lock.json` specifically, prefer the Phase 1.3 Python parser, which reads the structure rather than lines.

4. **Never pipe into a heredoc'd Python script.** `... | base64 -d | python3 <<'PY'` does **not** work: the heredoc becomes the process's stdin, so the piped JSON is discarded and `json.load(sys.stdin)` dies with `JSONDecodeError: Expecting value: line 1 column 1`. Verified during the dry-run of this playbook. **Fix:** write the script to a file once and pass the data as a **path argument** (`python3 scan.py data.json`), as Phase 1.3 does.

5. **Don't scan for `spoint`.** Analyst-refuted FP, ~60k downloads/month. Including it manufactures findings.

6. **`npm ci` and `yarn install --immutable` produce ZERO per-package output.** A grep for a package name returns nothing on a run that installed it. Do not conclude "no install happened" from "no package names in logs" — read the committed lock file instead.

7. **GitHub Actions log lines are tab-prefixed** (`<workflow>\t<step>\t<timestamp> <content>`). Don't anchor IOC patterns with `^`.

8. **`0x`-prefixed hex strings are everywhere in normal code.** Grepping for `0x` or even a truncated `0xa322` will hit legitimate constants, colour values, and checksums. Use the **full 42-character wallet address**, case-insensitively.

9. **Ethereum RPC egress is a genuine IOC only outside Web3 workloads.** If the customer builds blockchain software, `eth.blockscout.com` in a CI log may be legitimate. Confirm against the repo's purpose before escalating; correlate with the `/0x/cls` fetch or a detached `node -e` instead.

10. **Gate code-search on `total_count` first** (`?per_page=1 --jq .total_count`) before pulling items — halves rate-limit spend on orgs where most names return zero.

11. **AI-agent self-pollution.** Any session where an agent read this playbook will contain every IOC string. See the exclusion recipe in Phase 4.

---

## Setup

```bash
export ORG="<your-github-org>"
export LOG_DIR="/tmp/supply-chain-scan-nullreceiver"
mkdir -p "$LOG_DIR"

export W1_SINCE="2026-07-28T00:00:00Z"; export W1_UNTIL="2026-08-06T00:00:00Z"
export W2_SINCE="2026-08-09T22:00:00Z"; export W2_UNTIL="2026-08-24T12:00:00Z"

export WALLET="0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a"

# All three C2 addresses ever advertised by the wallet. Hunt for ALL of them:
#   163.34.229.243 — bootstrap, 1 tx on 2026-07-25 (chain-only, unpublished anywhere)
#   166.88.134.62  — live 28 days (2026-07-25 → 2026-08-22). THE one your archived logs hold.
#   23.27.13.135   — current as of 2026-08-25
# Resolve the live value yourself in Phase 0 — do not assume this list is complete.
export C2_IPS="163.34.229.243 166.88.134.62 23.27.13.135"
export C2_RE="163\.34\.229\.243|166\.88\.134\.62|23\.27\.13\.135"

# Malicious name+version regex. Matches the COORDINATE forms that actually appear on a
# single line in every lockfile format (`name@ver`, `name-ver.tgz` inside a `resolved`
# URL, `/name@ver:` in pnpm) plus the `"name": "ver"` manifest form.
# Do NOT rewrite this to match `"name" ... version` — npm pretty-prints package-lock.json
# with the name and version on SEPARATE lines, so a line-based grep silently returns
# zero on a lock file that pins a malicious version. See Pitfall 3.
export MAL_RE='(bianira-ui)[@-]1\.27\.0|"bianira-ui"\s*:\s*"[^"]*1\.27\.0|(fluid-type-ui)[@-]2\.0\.[89]|"fluid-type-ui"\s*:\s*"[^"]*2\.0\.[89]|(tailwindcss-anim)[@-](0\.0\.1|1\.0\.0|1\.1\.[01]|1\.2\.[12]|1\.3\.[35])|"tailwindcss-anim"\s*:\s*"[^"]*(0\.0\.1|1\.0\.0|1\.1\.[01]|1\.2\.[12]|1\.3\.[35])|(tailwind-anim)[@-](0\.0\.1|1\.0\.0|1\.1\.[01]|1\.2\.[01345])|"tailwind-anim"\s*:\s*"[^"]*(0\.0\.1|1\.0\.0|1\.1\.[01]|1\.2\.[01345])|(scrollbar-hide-plugin)[@-]1\.0\.1|"scrollbar-hide-plugin"\s*:\s*"[^"]*1\.0\.1|(tailwind-animation-founder)[@-]2\.5\.7|"tailwind-animation-founder"\s*:\s*"[^"]*2\.5\.7|(post-css-transfer)[@-]0\.0\.1|"post-css-transfer"\s*:\s*"[^"]*0\.0\.1|(agentgui)[@-]1\.0\.1127|"agentgui"\s*:\s*"[^"]*1\.0\.1127|(fsbrowse)[@-]0\.2\.28|"fsbrowse"\s*:\s*"[^"]*0\.2\.28|(godot-kit)[@-]1\.0\.1786316795|"godot-kit"\s*:\s*"[^"]*1\.0\.1786316795|(@kolbo/mcp)[@-]1\.57\.1|@kolbo/mcp/-/mcp-1\.57\.1|"@kolbo/mcp"\s*:\s*"[^"]*1\.57\.1|(tailwindcss-motion-advanced)[@-]1\.0\.1|"tailwindcss-motion-advanced"\s*:\s*"[^"]*1\.0\.1|(postcss-initial-provider)[@-]3\.0\.4|"postcss-initial-provider"\s*:\s*"[^"]*3\.0\.4|(envpack-conf)[@-]1\.0\.1|"envpack-conf"\s*:\s*"[^"]*1\.0\.1|(@wizloft/harness-kernel)[@-]0\.1\.1-alpha\.3|@wizloft/harness-kernel/-/harness-kernel-0\.1\.1-alpha\.3|"@wizloft/harness-kernel"\s*:\s*"[^"]*0\.1\.1-alpha\.3|(@wizloft/harness-plugin-repository-files)[@-]0\.1\.1-alpha\.3|@wizloft/harness-plugin-repository-files/-/harness-plugin-repository-files-0\.1\.1-alpha\.3|"@wizloft/harness-plugin-repository-files"\s*:\s*"[^"]*0\.1\.1-alpha\.3|(postcss-initialize-provider)[@-]3\.0\.4|"postcss-initialize-provider"\s*:\s*"[^"]*3\.0\.4'

# Network / behavioural IOC regex
export NET_RE='0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a|163\.34\.229\.243|166\.88\.134\.62|23\.27\.13\.135|eth\.blockscout\.com|1rpc\.io|eth\.drpc\.org|ethereum-rpc\.publicnode\.com|eth-mainnet\.public\.blastapi\.io|eth_getBlockByNumber|eth_getTransactionCount|/0x/cls|/0x/ls|global\.i="A9-2057"'
```

**Write to files, not context.** Results can be large — write evidence CSVs to `$LOG_DIR` as you go.

**Rate limits.** Check budget before scanning a large org:

```bash
gh api /rate_limit --jq '.resources.core | "\(.remaining)/\(.limit) core"'
gh api /rate_limit --jq '.resources.code_search | "\(.remaining)/\(.limit) code-search"'
```

---

## Phase 0: Resolve the live C2 from the chain

**Do this first, every run.** Every published source is pinned to an IP that was current when it was written. The loader resolves at runtime, so the only authoritative value is the wallet's latest outbound transaction. This read is **passive** — it queries a public block explorer, never the attacker's infrastructure.

```bash
curl -s "https://eth.blockscout.com/api/v2/addresses/${WALLET}/transactions?filter=from" \
  -H 'User-Agent: Mozilla/5.0' \
| python3 -c "
import json,sys
items=(json.load(sys.stdin).get('items') or [])
print(f'outbound txs returned: {len(items)}')
seen=[]
for t in items:
    to=(t.get('to') or {}).get('hash') or ''
    try: b=bytes.fromhex(to[2:])
    except Exception: continue
    ip1='.'.join(map(str,b[0:4])); ip2='.'.join(map(str,b[4:8]))
    tail=b[8:].decode('ascii','replace')
    seen.append((t.get('timestamp','')[:19], ip1, ip2, tail, t.get('value'), t.get('raw_input')))
for ts,ip1,ip2,tail,val,raw in seen[:5]:
    print(f'{ts}  {ip1:<16} / {ip2:<16} tail={tail!r}  value={val} input={raw}')
if seen:
    print()
    print('CURRENT C2 =', seen[0][1], '/', seen[0][2])
    print('distinct IPs in this page:', sorted({s[1] for s in seen}))
"
```

Expected shape of a genuine pointer transaction: `value=0`, `input=0x`, and the `to` field's trailing bytes decoding to ASCII `helloipbot!!`. If those three hold, the first four bytes are the live C2.

**Then export it** so the rest of the playbook hunts the current address alongside the historical ones:

```bash
export C2_LIVE="<ip from above>"
export C2_RE="${C2_RE}|$(echo "$C2_LIVE" | sed 's/\./\\./g')"
```

**Interpreting the history.** Paginate further (follow `next_page_params`) if you want the full picture. As of 2026-08-25 the wallet had made 208 outbound transactions since 2026-07-25 advertising only **three** addresses — so expect a long-lived IP re-advertised every ~3h20m, not a new one each cycle. If you find a fourth address, the infrastructure moved again and the item's IOC list needs updating.

**Also check whether the package list has grown.** New campaign packages appeared as late as 2026-08-19; the inventory in this playbook is a floor, not a ceiling:

```bash
gh api "/search/code?q=$(python3 -c "import urllib.parse;print(urllib.parse.quote('0x/cls'))")+repo:ossf/malicious-packages&per_page=100" \
  --jq '.items[].path' 2>/dev/null | sed 's|osv/malicious/npm/||;s|/MAL-.*||' | sort -u
```

Any package name in that output but absent from the inventory table is a new wave — add it to `$MAL_RE` and to the discovery loops before continuing.

---

## Phase 1: Repo Analysis

**Goal:** for every repo referencing an affected package name, determine the declared spec, the locked version, the install command, and whether the configuration is vulnerable in principle. Window-agnostic.

### 1. Find references to every affected package name

```bash
for pkg in $ALL_PKGS; do
  total=$(gh api "search/code?q=${pkg}+org:${ORG}&per_page=1" --jq '.total_count' 2>/dev/null)
  echo "=== $pkg: ${total:-0} hits"
  [ "${total:-0}" -gt 0 ] || { sleep 2; continue; }
  gh api "search/code?q=${pkg}+org:${ORG}&per_page=100" \
    --jq ".items[] | \"${pkg}\t\(.repository.full_name)\t\(.path)\"" 2>/dev/null
  sleep 2   # code search ~30 req/min
done | sort -u > "$LOG_DIR/refs.tsv"

wc -l "$LOG_DIR/refs.tsv"
```

> **Faster for orgs >50 repos:** shallow-clone and grep locally.
>
> ```bash
> mkdir -p "$LOG_DIR/clones" && cd "$LOG_DIR/clones"
> gh repo list "$ORG" --no-archived --limit 1000 --json nameWithOwner --jq '.[].nameWithOwner' | \
>   xargs -P 10 -I {} bash -c 'git clone --depth 1 --filter=blob:none "https://github.com/{}.git" 2>/dev/null || echo "FAIL: {}"'
>
> # Anchored name search — see Pitfall 3
> NAME_RE='"(bianira-ui|fluid-type-ui|tailwindcss-anim|tailwind-anim|scrollbar-hide-plugin|tailwind-animation-founder|post-css-transfer|@kolbo/mcp|tailwindcss-motion-advanced|postcss-initial-provider|envpack-conf|agentgui|fsbrowse|godot-kit)"'
> grep -rE --include='package.json' --include='package-lock.json' --include='pnpm-lock.yaml' --include='yarn.lock' \
>   "$NAME_RE" . > "$LOG_DIR/refs-local.txt"
> wc -l "$LOG_DIR/refs-local.txt"
> ```

**Positive control — run this before trusting any zero result.** Prove the search actually works by finding a package you know is present:

```bash
gh api "search/code?q=react+org:${ORG}&per_page=1" --jq '.total_count'
# Expect a non-zero number. If this returns 0 or errors, your auth/scope is wrong
# and every "clean" result above is meaningless.

# For the local-clone path:
grep -rlE '"react"' --include='package.json' "$LOG_DIR/clones" | head -3
```

### 2. Classify each reference

| File pattern | Category | Risk |
|---|---|---|
| `package.json` | npm manifest | **HIGH** — check spec range, and flag any `latest`/`*` |
| `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lockb` | Lock file | **CRITICAL** — check pinned version against the malicious list |
| `Dockerfile` | Docker build | **HIGH** if it installs JS deps |
| `.github/workflows/*.yml` | CI workflow | **CHECK** — installs? `npx`? |
| `*.ts`, `*.tsx`, `*.js`, `*.jsx` | Source code | **NOT AFFECTED** — import reference only |
| `*.md`, `README*` | Docs | **NOT AFFECTED** |

### 3. Extract version data per repo

Write the analyser to a file once — **do not pipe into a heredoc'd `python3 <<'PY'`**, the heredoc claims stdin and the piped JSON never arrives (see Pitfall 4).

```bash
cat > "$LOG_DIR/scan_manifest.py" <<'PY'
import sys, json
NAMES = {'bianira-ui','fluid-type-ui','tailwindcss-anim','tailwind-anim',
         'scrollbar-hide-plugin','tailwind-animation-founder','post-css-transfer',
         'agentgui','fsbrowse','godot-kit',
         '@kolbo/mcp','tailwindcss-motion-advanced','postcss-initial-provider','envpack-conf'}
MAL = {'bianira-ui':{'1.27.0'}, 'fluid-type-ui':{'2.0.8','2.0.9'},
       'tailwindcss-anim':{'0.0.1','1.0.0','1.1.0','1.1.1','1.2.1','1.2.2','1.3.3','1.3.5'},
       'tailwind-anim':{'0.0.1','1.0.0','1.1.0','1.1.1','1.2.0','1.2.1','1.2.3','1.2.4','1.2.5'},
       'scrollbar-hide-plugin':{'1.0.1'}, 'tailwind-animation-founder':{'2.5.7'},
       'post-css-transfer':{'0.0.1'}, 'agentgui':{'1.0.1127'},
       'fsbrowse':{'0.2.28'}, 'godot-kit':{'1.0.1786316795'},
       '@kolbo/mcp':{'1.57.1'}, 'tailwindcss-motion-advanced':{'1.0.1'},
       # NOTE: postcss-initial-provider@3.0.4 shares its version with the
       # LEGITIMATE postcss-initial@3.0.4. Exact-name keying (as here) is what
       # keeps that from firing on clean projects — never relax it to a prefix.
       'postcss-initial-provider':{'3.0.4'}, 'envpack-conf':{'1.0.1'}}

d = json.load(open(sys.argv[1]))

# manifest form
for section in ('dependencies','devDependencies','optionalDependencies','peerDependencies'):
    for k, v in (d.get(section) or {}).items():
        if k in NAMES:
            spec = str(v).strip()
            flag = '  <-- FLOATING, lock file cannot be trusted for this dep' \
                   if spec in ('latest','*','') or spec.startswith('>') else ''
            print(f'{section}: {k} = {v}{flag}')

# package-lock.json form (v2/v3) — catches TRANSITIVE resolutions too
for k, v in (d.get('packages') or {}).items():
    name = k.split('node_modules/')[-1]
    if name in NAMES:
        ver = v.get('version')
        print(f'locked: {name}@{ver}  ' +
              ('*** MALICIOUS ***' if ver in MAL.get(name, set()) else 'clean'))
PY

REPO="<repo>"

# Manifest — specs plus floating-range flags
gh api "repos/${ORG}/${REPO}/contents/package.json" --jq '.content' | base64 -d > "$LOG_DIR/pj.json"
python3 "$LOG_DIR/scan_manifest.py" "$LOG_DIR/pj.json"

# package-lock.json — resolved versions, direct AND transitive
gh api "repos/${ORG}/${REPO}/contents/package-lock.json" --jq '.content' | base64 -d > "$LOG_DIR/pl.json"
python3 "$LOG_DIR/scan_manifest.py" "$LOG_DIR/pl.json"

# pnpm / yarn
gh api "repos/${ORG}/${REPO}/contents/pnpm-lock.yaml" --jq '.content' | base64 -d | grep -nE "^\s+'?(agentgui|fsbrowse|godot-kit|tailwindcss-anim|tailwind-anim|bianira-ui|fluid-type-ui|scrollbar-hide-plugin|tailwind-animation-founder|post-css-transfer|@kolbo/mcp|tailwindcss-motion-advanced|postcss-initial-provider|envpack-conf)[@:']"
gh api "repos/${ORG}/${REPO}/contents/yarn.lock" --jq '.content' | base64 -d | grep -nE '^"?(agentgui|fsbrowse|godot-kit|tailwindcss-anim|tailwind-anim|bianira-ui|fluid-type-ui|scrollbar-hide-plugin|tailwind-animation-founder|post-css-transfer|@kolbo/mcp|tailwindcss-motion-advanced|postcss-initial-provider|envpack-conf)@'

# Install commands, including npx (which bypasses lock files entirely)
gh api "repos/${ORG}/${REPO}/contents/.github/workflows" --jq '.[].path' 2>/dev/null | while read wf; do
  gh api "repos/${ORG}/${REPO}/contents/${wf}" --jq '.content' | base64 -d | \
    grep -inE "npm ci|npm install|pnpm install|yarn install|bun install|npx |pnpm dlx|bunx"
done
```

### 4. Hunt floating ranges org-wide

This is the highest-yield Phase 1 query for this incident.

```bash
# Any manifest declaring an affected name with a floating spec
grep -rE --include='package.json' \
  '"(agentgui|fsbrowse|godot-kit|tailwindcss-anim|tailwind-anim|bianira-ui|fluid-type-ui|scrollbar-hide-plugin|tailwind-animation-founder|post-css-transfer|@kolbo/mcp|tailwindcss-motion-advanced|postcss-initial-provider|envpack-conf)"\s*:\s*"(latest|\*|>=?[^"]*)"' \
  "$LOG_DIR/clones" 2>/dev/null | tee "$LOG_DIR/floating-ranges.txt"
```

Every hit is a repo whose lock file cannot be trusted for that dependency.

### 5. Write the repo evidence table

`$LOG_DIR/evidence-repos.csv`:

```
repo,path,source_type,manifest_spec,spec_floating,has_lockfile,lockfile_version,transitive_fsbrowse_version,lock_protects,install_command,uses_npx,can_be_compromised
```

| Column | What to write |
|---|---|
| `manifest_spec` | Exact specifier as written (`^1.0.0`, `latest`) |
| `spec_floating` | `yes (latest)` / `yes (*)` / `no` |
| `lockfile_version` | Exact pinned version for the affected package; `none` if no lock file |
| `transitive_fsbrowse_version` | Resolved `fsbrowse` version, or `n/a (not in tree)` — **required column**, this is the amplifier |
| `lock_protects` | `yes` if pinned versions are all off the malicious list **and** no floating spec exists; else `no` |
| `uses_npx` | `yes (npx agentgui)` / `no` — `npx` means no lock-file protection |
| `can_be_compromised` | `no` only if lock protects AND install respects lock AND no npx |

No blank cells. Parenthetical reasons after values.

---

## Phase 2: CI Run Analysis

Phase 1 only finds repos that *name* an affected package. Transitive resolution and `npx` leave no manifest trace — CI logs are the only record of what actually ran.

### 1. Find runs in both windows

```bash
for w in W1 W2; do
  since_var="${w}_SINCE"; until_var="${w}_UNTIL"
  since="${!since_var}"; until="${!until_var}"
  gh api "/orgs/${ORG}/repos" --paginate --jq '.[].name' | while read repo; do
    gh api "repos/${ORG}/${repo}/actions/runs?created=${since}..${until}&per_page=100" \
      --jq ".workflow_runs[] | \"${repo}|\(.id)|\(.created_at)|\(.name)|\(.conclusion)\"" 2>/dev/null
  done
done | sort -u > "$LOG_DIR/all_runs.txt"

echo "Runs to scan: $(wc -l < "$LOG_DIR/all_runs.txt")"
```

> The Wave 2 window is ~14 days wide because `agentgui@1.0.1127` stayed live that long. On a busy org this can be thousands of runs. Narrow by first filtering to repos that Phase 1 flagged, or to workflows whose names suggest JS builds.

### 2. Download logs in parallel

```bash
cut -d'|' -f1,2 "$LOG_DIR/all_runs.txt" | tr '|' ' ' | \
  xargs -P 10 -L 1 bash -c \
  'gh run view "$1" --repo "'"${ORG}"'/$0" --log > "'"${LOG_DIR}"'/run-$1.log" 2>/dev/null && echo "OK $0 $1" || echo "FAIL $0 $1"'
```

### 3. Scan logs

```bash
cd "$LOG_DIR"

echo "=== Malicious name@version (install output) ==="
grep -rlE "$MAL_RE" run-*.log 2>/dev/null

echo "=== Install-only patterns for affected names ==="
# Built from $ALL_PKGS so waves 1-3 are always covered and this cannot drift
# out of sync with the package table. Install-only verbs deliberately — a bare
# name match would hit `import ... from 'fsbrowse'` in ordinary source output.
PKG_ALT=$(echo "$ALL_PKGS" | tr ' ' '\n' | sed 's/[+.]/\\&/g' | paste -sd'|' -)
grep -rlE "added ($PKG_ALT)@|Downloading ($PKG_ALT)|\+ ($PKG_ALT)@|registry\.npmjs\.org/($PKG_ALT)" run-*.log 2>/dev/null

echo "=== npx / dlx invocations of affected names ==="
# agentgui and godot-kit are the CLI-shaped ones, but check every name: an npx
# run leaves no manifest or lock-file trace at all, so this is the only record.
grep -rlE "(npx|pnpm dlx|bunx)\s+($PKG_ALT)" run-*.log 2>/dev/null

echo "=== Network / behavioural IOCs (highest confidence) ==="
grep -rliE "$NET_RE" run-*.log 2>/dev/null

echo "=== Detached node -e execution ==="
grep -rlE "node\s+-e\s|spawn\(.node.,\s*\[.-e." run-*.log 2>/dev/null
```

**Positive control:** prove the greps work against this corpus before trusting a clean result.

```bash
grep -rlE "added react@|registry\.npmjs\.org/react|\+ react@" run-*.log 2>/dev/null | head -3
# Non-empty expected on any org that builds JS. Empty here means your logs
# are quiet (npm ci / --immutable) — a clean MAL_RE result proves nothing.
# Fall back to reading committed lock files (Phase 1.3).
```

### 4. Classify hits

**Real install / execution:**
- `added fsbrowse@0.2.28`, `+ fsbrowse 0.2.28`, `Downloading fsbrowse-0.2.28.tgz`
- `npm http fetch GET https://registry.npmjs.org/fsbrowse`
- `npx agentgui` in a `run:` step
- Any `$NET_RE` hit on a non-Web3 repo

**False positives:**
- `tailwindcss-animate` matched by a careless `tailwindcss-anim` grep — **check every hit for the `ate` suffix** (Pitfall 3)
- Source imports in TypeScript output, SAST tool listings, dependency-review comments
- Branch names (`feat/bump-fsbrowse`), Dependabot PR titles
- `eth.blockscout.com` in a repo that genuinely builds blockchain tooling
- Any `0x`-prefixed hex that is not the full 42-char wallet

### 5. Write the CI evidence table

`$LOG_DIR/evidence-ci-runs.csv`:

```
repo,run_id,created_at,wave,workflow,install_command,ignore_scripts,log_line,version_installed,transitive_fsbrowse,net_ioc_found,ci_compromised
```

`ignore_scripts` is recorded for completeness only — **it does not make a run clean** (import-time trigger). `ci_compromised` verdict: `clean` / `compromised` / `clean (affected package not installed)` / `inconclusive (quiet logs — see lock file)`.

---

## Phase 3: Network Investigation

The strongest detection for this campaign, because it survives C2 rotation: **a build host or workstation talking to an Ethereum RPC endpoint**.

### What to look for

| IOC | Where |
|---|---|
| DNS for `eth.blockscout.com`, `1rpc.io`, `eth.drpc.org`, `ethereum-rpc.publicnode.com`, `eth-mainnet.public.blastapi.io` | DNS logs, resolver query logs |
| Outbound to `166.88.134.62` on **443 or 80** | proxy, NetFlow, VPC Flow Logs |
| **Plaintext HTTP on port 443** to any bare IP | proxy / TLS-inspection logs — strong standalone anomaly |
| HTTP GET with path `/0x/cls` | proxy logs |
| JSON-RPC bodies containing `eth_getBlockByNumber` / `eth_getTransactionCount` from CI egress | proxy with body logging |

### Where to check

- **AWS:** VPC Flow Logs, Route 53 Resolver query logs.
- **GCP:** VPC Flow Logs, Cloud DNS query logs.
- **Azure:** NSG Flow Logs, DNS Analytics.
- **Corporate:** firewall (Palo Alto, Fortinet), proxy (Zscaler, Netskope, Squid), DNS server logs, SIEM.
- **CI runners:** self-hosted → host egress + EDR. GitHub-hosted → network-edge logs only.

### Time window

From `2026-07-28T00:00:00Z` forward to **at least 7 days past the last install**. The detached `node -e` process persists beyond the build, and the second stage beacons on its own schedule.

### Example queries

**Splunk:**
```
index=dns query IN ("eth.blockscout.com","1rpc.io","eth.drpc.org","ethereum-rpc.publicnode.com","eth-mainnet.public.blastapi.io")
| stats count by src_ip, query
```

**Elastic:**
```
dns.question.name : ("eth.blockscout.com" or "1rpc.io" or "eth.drpc.org" or "ethereum-rpc.publicnode.com" or "eth-mainnet.public.blastapi.io")
```

**AWS CloudWatch Insights:**
```
filter @message like /blockscout|drpc\.io|publicnode|blastapi|166\.88\.134\.62/
| stats count(*) as hits by srcAddr, dstAddr
```

### Interpret

- **RPC endpoint contacted from a non-Web3 build host:** treat the host as suspect; correlate with Phase 2 install evidence.
- **Successful fetch of `/0x/cls`:** second stage was retrieved. Treat as compromised — full credential rotation.
- **No results:** consistent with a clean Phase 1–2 finding, but does not rule out a workstation on a network outside your visibility.

---

## Phase 4: Workstation Investigation

Run the dedicated [workstation-playbook.md](workstation-playbook.md) on each developer machine that worked on JS/TS code, or ran `npx agentgui`, during either window.

**AI-agent self-pollution — exclude the investigating session.** Any agent session that read this playbook contains every IOC string. Filter it out:

```bash
CURRENT_SESSION_PROJECT=$(echo "$PWD" | sed 's|/|-|g')
grep -rliE "0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a|23\.27\.13\.135|166\.88\.134\.62|/0x/cls|/0x/ls|A9-2057|fsbrowse@0\.2\.28|agentgui@1\.0\.1127|@kolbo/mcp@1\.57\.1" \
  "$HOME/.claude/projects" \
  "$HOME/Library/Application Support/Cursor" \
  "$HOME/Library/Application Support/Windsurf" \
  "$HOME/.config/github-copilot" 2>/dev/null | \
  grep -v "${CURRENT_SESSION_PROJECT}" | grep -v "paste-cache" | grep -v "file-history"
```

Hits surviving that filter are real signal — a `.jsonl` from an unrelated prior session containing these strings means an install or discussion happened outside this investigation.

> **`agentgui` specifically wraps AI coding agents** (Claude Code, Gemini CLI, OpenCode) and depends on `ccsniff`, which watches Claude Code JSONL output. On a machine that ran `agentgui`, agent conversation logs are both a forensic source **and** potentially attacker-readable. Prioritise rotating any credential that appeared in an agent session on that host.

---

## Phase 5: Your Own Published Packages

If the customer publishes npm packages, check whether any shipped a lock file pinning an affected version during a window.

```bash
# List the customer's published packages by scope and by maintainer
curl -s "https://registry.npmjs.org/-/v1/search?text=scope:${SCOPE}&size=250" | \
  python3 -c "import sys,json; [print(p['package']['name']) for p in json.load(sys.stdin)['objects']]" \
  > "$LOG_DIR/own-packages.txt"

# For each, find versions published in either window
while read pkg; do
  curl -s "https://registry.npmjs.org/${pkg}" | python3 -c "
import sys, json
d = json.load(sys.stdin); t = d.get('time', {})
for v, ts in t.items():
    if v in ('created','modified'): continue
    if ('2026-07-28' <= ts <= '2026-08-06') or ('2026-08-09' <= ts <= '2026-08-24'):
        print(f'${pkg}@{v}\t{ts}')
" 2>/dev/null
done < "$LOG_DIR/own-packages.txt" > "$LOG_DIR/own-published-in-window.tsv"
```

For each candidate, pull the tarball and check its lock file:

```bash
mkdir -p "$LOG_DIR/tarballs" && cd "$LOG_DIR/tarballs"
npm pack "${pkg}@${version}" 2>/dev/null && tar xzf *.tgz
for lf in package/package-lock.json package/npm-shrinkwrap.json package/pnpm-lock.yaml package/yarn.lock; do
  [ -f "$lf" ] && { echo "=== $lf"; grep -nE "$MAL_RE" "$lf" | head -5; }
done
```

A published lock file pinning an affected version means downstream consumers re-resolve it. Deprecate the version (`npm deprecate '<pkg>@<version>' 'Compromised transitive dependency — see advisory'`), publish a clean superseding version from a known-good host, and notify consumers.

---

## Phase 6: Hardening

Apply after the investigation, whatever the verdict.

### 1. Eliminate floating ranges

**The problem.** `"fsbrowse": "latest"` in `agentgui` is exactly how a clean direct version resolved a malicious transitive one. A floating spec means your lock file is one `npm install` away from irrelevance.

```json
// Vulnerable
{ "dependencies": { "fsbrowse": "latest", "some-tool": "*" } }

// Safe
{ "dependencies": { "fsbrowse": "0.2.27", "some-tool": "1.4.2" } }
```

Audit org-wide:

```bash
grep -rE --include='package.json' '"[^"]+"\s*:\s*"(latest|\*)"' "$LOG_DIR/clones" 2>/dev/null
```

### 2. Enforce lock-file-respecting installs

**The problem.** `npm install` in CI can re-resolve and update the lock file; `npx` skips it entirely.

| Replace | With |
|---|---|
| `npm install` | `npm ci` |
| `pnpm install` | `pnpm install --frozen-lockfile` |
| `yarn install` | `yarn install --immutable` (berry) / `--frozen-lockfile` (classic) |
| `npx <tool>` in CI | add as a pinned devDependency, invoke via `package.json` script |

### 3. Do not rely on `--ignore-scripts`

**The problem.** This campaign executes at import time. `--ignore-scripts` is worth keeping as defence-in-depth against *other* attacks, but it must not appear in a risk assessment as mitigation for this one.

### 4. Alert on Ethereum RPC egress from build infrastructure

**The problem.** The one signal the attacker cannot rotate away. Unless you genuinely build Web3 software, no CI runner should resolve a public Ethereum RPC host.

Add a detection rule for DNS/proxy egress to `eth.blockscout.com`, `1rpc.io`, `eth.drpc.org`, `ethereum-rpc.publicnode.com`, `eth-mainnet.public.blastapi.io` from CI and developer subnets. Also alert on **plaintext HTTP over port 443**, which this loader does and almost nothing legitimate does.

### 5. Rotate credentials in scope

Not "rotate exposed credentials" — rotate **every secret reachable from any CI workflow that ran during a window, and every credential resident on an affected workstation**: `secrets.*` referenced by those workflows, OIDC-issued cloud credentials, npm publish tokens, GitHub PATs and SSH keys, container registry credentials, package signing keys, and any cryptocurrency wallet keys or seed phrases on developer machines (BeaverTail targets these specifically).

### 6. Rebuild artifacts

```bash
npm cache clean --force
rm -rf node_modules && npm ci
docker build --no-cache -t <image> .
```

Rebuild any image produced during a window; the payload is baked into the layer and no amount of manifest correction removes it.
