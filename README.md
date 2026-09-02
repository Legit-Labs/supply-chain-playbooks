# Supply Chain Compromise Playbooks

Agent-ready playbooks for detecting and remediating supply chain compromises.
Each playbook is designed to be executed by an AI coding agent. The playbooks
target GitHub Actions by default but can be adapted to any CI/CD platform —
the investigation logic is the same.

## Usage

Give your AI coding agent this prompt:

```
Check the repo at https://github.com/Legit-Labs/supply-chain-playbooks for
available playbooks and ask me which one I want to run.
```

The agent will list the available compromises, ask which one to investigate,
then execute the playbook against your org.

Playbooks write structured evidence to `/tmp/supply-chain-scan-<component>/` —
CSV files that can be reused for follow-up analysis without re-downloading logs.

Each playbook produces:
- **Repo analysis table** (`evidence-repos.csv`) — dependency posture per repo
- **CI runs table** (`evidence-ci-runs.csv`) — what happened during the exposure window
- **Executive summary** — verdict and key findings

---

## Compromises

### Shai-Hulud "Trinitite" — `@7nohe/openapi-react-query-codegen` via a PR-comment release workflow (August 28, 2026)

A new **Mini Shai-Hulud** wave took over `@7nohe/openapi-react-query-codegen` — a TanStack
Query codegen at **~150K weekly / ~671K monthly downloads** — and published **ten malicious
versions across every maintained release line** in twenty minutes. **No npm token was stolen
and no maintainer account was hijacked.** Three flaws chained in `release.yml`: it triggered
on **`issue_comment`** with **no author-association check** (any comment containing
`npm publish` fired a release), it **checked out the untrusted pull-request head**, and it ran
that attacker code in a job holding **`id-token: write`** — so PRs **#215** and **#216** from
a fork were enough to mint an npm **trusted-publishing OIDC token**. The malicious tarballs
therefore carry **genuine Sigstore provenance**; attestation checks pass. Execution has **two
independent paths** — a `preinstall` hook running `3FWCvzduYZg.js`, and `binding.gyp` abusing
**node-gyp's Python evaluation** during `node-gyp rebuild` via a class-hierarchy traversal
reaching `os.system()` with no plain-text import — so **`--ignore-scripts` does not protect**.
The loader decodes XOR → AES-128-GCM → `javascript-obfuscator`, fetches **Bun v1.4.0**, and
harvests GitHub/npm/PyPI/RubyGems/cloud/SSH/Vault/Kubernetes credentials while **scraping
Actions Runner memory** for `"isSecret":true`; a recovered `ClaudeCode Review` workflow
serializes all repo secrets to `res.txt` and uploads it as an artifact. ⚠️ **A
token-revocation trap inverts the usual remediation order:** a monitor at
`~/.local/share/diaper/poopy.py`, kept alive by `systemd-detect-fash` /
`sysvinit-detect-fash`, **wipes `~/` and `~/Documents`** if the stolen token returns a 40x —
isolate and remove persistence *before* rotating anything. Cross-ecosystem republication to
**PyPI and RubyGems is payload capability, not observed activity**: PyPI typosquatting is
gated behind `TYPO_MODE === '1'`, and independent analyses agree this package was the **only**
one compromised. **All ten versions are unpublished and `latest` is back to `3.0.2` — which
is not remediation:** they persist in lock files, caches and built images. Installable window
**20:00:43 → ~23:11 UTC, roughly 3h10m**. **No CVE assigned.** JFrog notes the **TeamPCP**
arrests in Australia days earlier and the same kit with new RSA keys — attribution unresolved.

- [Playbook](trinitite_supply_chain/playbook.md) — org discovery with a `react` positive control, CI log analysis against the **npm-registry-derived exposure window** (publish times recovered from the retained `time` map, not reconstructed), **`node-gyp rebuild` as an install-log indicator**, host persistence checks in the **safe order (isolate → stop services → delete artifacts → only then rotate)**, blast-radius enumeration including your own published packages, and an **org-wide audit for the `issue_comment` + untrusted-checkout + `id-token: write` pattern** that caused this

---

### NullReceiver — DPRK npm campaign decoding C2 from Ethereum transaction recipient bytes (July 28 – August 24, 2026)

**Seventeen packages, 33 malicious versions across four waves**, whose loader resolves its C2 by reading the **most recent outbound transaction from a fixed attacker wallet** (`0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a`) and decoding IPv4 addresses **out of the recipient (`to`) address bytes**. **The wallet was still broadcasting C2 pointers as of 2026-08-25 08:24 UTC** — a live channel, not a cleanup exercise: a host compromised during a window and only superficially cleaned will still resolve C2 and fetch a *current* second stage on next execution. **The ~3h20m cycle is a keepalive, not rotation** — reading the wallet's full outbound history (208 txs, 25 Jul → 25 Aug) shows it re-advertises the *same* pointer and changed infrastructure only twice: `163.34.229.243` (1 tx, 25 Jul, chain-only and unpublished anywhere), then `166.88.134.62` for **28 days** (25 Jul → 22 Aug), then `23.27.13.135` (current). Two consequences the early coverage gets backwards: **IP blocklisting is worth doing** (each address held ~4 weeks, so this is real protective value — just re-resolve periodically), and **`166.88.134.62` is the primary IOC for retrospective hunting rather than a superseded footnote**, because it was live across essentially every window in which a real install could have happened and is the address archived flow logs will actually contain. Note also that the wallet's first transaction (25 Jul 06:42) predates the first advisory by three days — infrastructure was staged before the packages shipped. The transactions are zero-value, zero-data transfers with **no smart-contract interaction** — the distinction from EtherHiding, and the reason the channel carries only a few bytes. Researchers named the technique **NullReceiver**; attribution is DPRK-linked **Contagious Interview / UNC5342**. The retrieved second stage is *expected* to be **BeaverTail** (credential + cryptocurrency-wallet stealer) but is **not confirmed for this loader** — BeaverTail is directly tied to a sibling loader (XORIndex / `eth-auditlog`), and because the fetched stage is attacker-controlled and rotates, its absence on a host proves nothing. With the decoded IP the loader fetches XOR-encrypted JavaScript over **plaintext HTTP on port 443** from `/0x/cls` **and `/0x/ls`** (distinct XOR keys `q4FZkxX{!h,Sr3=@` and `y-p_>d$0B&@^1aQk`; campaign marker `global.i="A9-2057"`, byte-identical across `agentgui` and `fsbrowse`) and runs it twice over — `eval` plus a **detached** `spawn('node', ['-e', …], { detached: true })` that outlives the build. Wave 1 (28 Jul – 5 Aug) was seven **typosquats of heavily-used Tailwind/PostCSS plugins** — `tailwindcss-anim` and `tailwind-anim` shadow the legitimate `tailwindcss-animate`, `scrollbar-hide-plugin` shadows `tailwind-scrollbar`. Wave 2 (9 Aug, **23:03–23:07 UTC — three packages in under four minutes**, consistent with an automated publish from a stolen credential) hit one prolific publisher: `agentgui@1.0.1127`, `fsbrowse@0.2.28`, `godot-kit@1.0.1786316795`. Wave 3 (advisories filed 7–13 Aug) adds `@kolbo/mcp@1.57.1` — a second hijacked legitimate package — plus typosquats `tailwindcss-motion-advanced@1.0.1`, `postcss-initial-provider@3.0.4` and `envpack-conf@1.0.1`, all citing the same wallet. Wave 4 (advisories 19 Aug) adds `@wizloft/harness-kernel@0.1.1-alpha.3` and `@wizloft/harness-plugin-repository-files@0.1.1-alpha.3` — and **changes the obfuscation**, swapping the `\u00XX` escape scheme for a ~35 KB **obfuscator.io-packed IIFE** at line 209 of `dist/index.js` (303-entry rotated string array `_0x240a`, decoder `_0x4963`, control-flow flattening), so any detection keyed only on unicode-escape density is blind to it. **Two campaign advisories print a corrupted wallet and neither should be grepped as published:** MAL-2026-14287 renders a 44-hex-character structurally invalid address, and MAL-2026-13938 (`@kolbo/mcp`) renders a 40-character one that *looks* valid but carries an extra `0` and drops the trailing `a` — the sneakier failure, since a length check passes and the grep silently matches nothing. Static inspection of both Wave 4 `dist/index.js` files settles it: the obfuscator splits strings into 10-character chunks that reassemble to exactly `0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a`, so Wave 4 is confirmed the same campaign with no second marker address. The same inspection recovered three IOCs absent from every published source — a third RPC method (`eth_blockNumber`), a `blockscout.com/api` fallback, and a **spoofed Chrome/Safari User-Agent sent from Node to the RPC hosts**, which is a high-confidence network signal. Note also that **unpublished does not mean unavailable**: the Wave 4 tarballs still return HTTP 200 from the registry CDN despite being absent from the packument, so a lock file pinning an exact malicious version can still fetch and re-execute it. **Treat the affected list as provisional and pivot on the wallet, not the names** — publishing paused after 19 Aug while the C2 stayed warm, which reads as npm catching them faster rather than the operator standing down. **MAL-2026-11132 / -11136 / -11487 / -11500 / -12192 / -12218 / -12417 / -13604 / -13696 / -13722 / -13723 / -13921 / -13938 / -14287 / -14288 / -14402; GHSA-3g4v-p5hc-83qm; no CVE.** **Never match on version alone:** malicious `postcss-initial-provider@3.0.4` shares its exact version with the legitimate, widely-installed `postcss-initial@3.0.4`. Four things make this awkward to investigate. Execution is at **import time**, so **`--ignore-scripts` does not protect** and a build that merely bundles the package is exposed. **A clean direct version is not enough** — `agentgui` declared `"fsbrowse": "latest"`, so installing even the *safe* `agentgui@1.0.1126` resolved the malicious `fsbrowse` transitively, and `agentgui`'s documented entry point is `npx agentgui`, which consults no lock file at all. **The windows are wildly uneven** — `fsbrowse` and `godot-kit` were live ~17 hours, but **`agentgui@1.0.1127` stayed installable for ~14 days** (9 Aug 23:03 → 24 Aug 07:52 UTC) as the highest version, long after its siblings were pulled. And the **`agentgui` payload analysis does not exist**: its GHSA is npm's generic boilerplate, so the mechanism has to be read off `fsbrowse`'s Amazon Inspector write-up. **`spoint@0.1.695–0.1.700` (MAL-2026-13725) is explicitly excluded** — Amazon Inspector's own text refutes it as keyword co-occurrence in a legitimate networking SDK, and at ~60k downloads/month scanning for it manufactures findings.

- [Playbook](nullreceiver_supply_chain/playbook.md) — org discovery with **delimiter-anchored** name matching (an unanchored `tailwindcss-anim` grep matches the legitimate `tailwindcss-animate` and will produce a false compromise verdict on a large share of frontend orgs), a dedicated **floating-range hunt** and a mandatory `transitive_fsbrowse_version` evidence column, CI log scanning with a `react` positive control for the `npm ci` silent-install trap, `npx`/`dlx` invocation detection, **Ethereum-RPC egress as the rotation-proof network signal** (plus plaintext-HTTP-on-443 as a standalone anomaly), own-published-package lock-file checks, and hardening that refuses to credit `--ignore-scripts`
- [Workstation playbook](nullreceiver_supply_chain/workstation-playbook.md) — exact-path `node_modules` matching that cannot hit the legitimate neighbours, `index.js` SHA-256 and the unicode-escape-density fingerprint (with the `dist/`-bundle false-positive caveat), lock-file scan with its own positive control, the **`_npx` cache** as the only local trace of `npx agentgui`, detached-`node -e`-with-no-tty process hunting, and AI-agent transcript forensics with the self-pollution exclusion — noting that `agentgui` *is* an AI-agent GUI that reads Claude Code JSONL by design, so those logs are both evidence and attacker-readable
- Cross-links the two sibling blockchain-C2 incidents (**joyfill** — Tron/Aptos/BSC, DEV#POPPER; **keyv/cacheable** — Ethereum *contract* storage) with an explicit warning not to swap their IOCs, and the observation that the one thing that *does* generalise is hunting blockchain RPC egress from build infrastructure in a single pass

---

### CopyEscape — `docker cp` destination escape, CVE-2026-17106 (August 2026)

A path-traversal flaw in **`github.com/moby/go-archive`** (`< 0.3.0`), reached through Docker's `docker cp` copy-out path. A malicious container wins a race while the daemon builds the tar, swapping a directory for an absolute symlink; the resulting archive's child entries are written **through** that symlink, outside the destination, with the permissions of whoever ran the copy. The published PoC replaces `/usr/bin/runc` for root code execution. Fixed in Docker Engine/CLI **29.7.0** (install **29.7.2** — .1/.2 repair regressions the fix introduced), Docker Desktop **4.86.0**, Docker Sandboxes **0.38.0**. Reported privately to Docker by the **Imperva Red Team** on 2026-04-11. **No IOCs exist** — the attacker chooses both the bytes and the paths — so detection is version state plus local tamper evidence. Note the ordering: a working PoC was already public on **2026-06-24**, sixteen days before the 90-day disclosure deadline elapsed and over five weeks before any patch, while the GHSA did not reach the global advisory database until 2026-08-18 — so a clean SCA report predating that is not evidence of safety.

- [Playbook](docker_cp_copyescape/playbook.md) — org-wide discovery of dind/CLI image pins and `docker cp` copy-out sites, host/runner version determination (including the digest-vs-tag trap), a dedicated phase for triaging the `// indirect` `go.mod` false positives, package-verification tamper checks on `runc`/Docker binaries, and upgrade + rebuild remediation

---

### StubMaker — typosquatted RubyGems + npm packages dropping a Windows infostealer (August 15–16, 2026)

A cross-ecosystem typosquatting campaign named **StubMaker** by OpenSourceMalware: **16 malicious
gems across three attacker accounts** (from 15 Aug) and **37 malicious npm packages** (16 Aug, also
connected by OpenSourceMalware) sharing one payload and one C2. The gems abuse `extconf.rb`, the
native-extension hook, and the name comes from what it writes there: a `Makefile` with empty
`all`/`install`/`clean` targets plus the no-op compiler stand-ins **`make_stub`** and
**`make_stub.bat`**, so the build reports a clean compile with no compiler output while the hook
fetches a 22 MB Rust loader from `github[.]com/bebraz1/qPzM50V1AKG0rVlH` and saves it as
**`main.exe` in the user's `Downloads` folder**. That loader decrypts an **11 MB Go stealer
(`wincfg`)** from its own data section, which in turn carries **`abe_payload.dll`** to defeat
Chromium **App-Bound Encryption** — taking browser passwords and cookies, payment cards and CVCs,
crypto wallets and BIP-39 seed phrases, and Telegram `tdata`. Exfiltration is a password-protected
ZIP to Gofile, with the link POSTed to **`dresslee[.]com:20027`** over plaintext HTTP.

Four things shape the investigation. **It is a typosquat, not a hijack** — no legitimate package was
compromised, so there is no transitive exposure and any hit is actionable on its own. **Every OS
beacons; only Windows gets the payload** — the installer POSTs the detected platform to
`193.70.34.101:20099/vote` on Windows, macOS *and* Linux, so a Mac that installed one left exactly
one artifact and **network logs are the only place it appears**. **There is no second-stage download
to catch** — everything after the single `main.exe` fetch is embedded and decrypted in memory, so
detection keyed on "payload fetches more payload" never fires. And **RubyGems namespace reclaim
defeated the first takedown**: `brumdler` and `brundlef` came from `gemlewqqhu1`, and once all
versions were yanked the namespace reopened for anyone to claim — `mod8rz41mje` reclaimed `brumdler`
and `rbq95bwt6q` took `brundlef`, so the gems are indicated **by name, not by version**. The npm side
is version-precise by contrast: all 37 at **`1.0.0`** only, in a **1h45m window (2026-08-16
02:28–04:13 UTC)** verified against the registry packuments. Downloads were low — 56–339 per gem,
~1,222 total. **Persistence is explicitly confirmed absent**, so a clean artifact scan does not clear
a host. As of 2026-08-19 the GitHub loader release is **404**, but **both C2 endpoints still answer**
— probe the documented ports (20099 / 20027), not 80/443.

- [Playbook](stubmaker_supply_chain/playbook.md) — repo analysis across all 53 names (with a manifest-type probe that cut a real 72-repo sweep from 180 to 106 queries), a Windows-runner pre-filter that bounds the CI question up front, CI run analysis against both windows, **a network phase that is the only way to reach non-Windows hosts**, impact assessment, and an audit for attacker-created persistence that outlives credential rotation
- [Workstation Playbook](stubmaker_supply_chain/workstation-playbook.md) — per-OS host forensics in bash **and PowerShell** with SHA-256 matching: `Downloads\main.exe` and `abe_payload.dll` on Windows, the `make_stub` artifacts on every platform, package-manager cache as proof the install ran, beacon/exfil egress, and AI-agent conversation logs with self-pollution exclusion

---

### keyv / cacheable npm — Shai-Hulud worm with Ethereum-resolved C2 and Actions secret theft (August 4, 2026)

A compromised maintainer account behind **`keyv` and the `cacheable` family** published
trojanized patch releases carrying a `preinstall: node setup.mjs` hook, which downloads
**Bun 1.3.13** and runs a ~710 KB obfuscated payload (`math_init.js`). The worm spread to
**400+ packages across 1,300+ versions** with **2+ billion combined monthly installs** —
`flat-cache` and `file-entry-cache` sit **underneath ESLint**, so most repos are exposed
transitively. It harvests npm/GitHub/AWS/Azure/GCP/Kubernetes/Vault/SSH/AI-service
credentials, **scrapes `Runner.Worker` process memory on Linux Actions runners**, and
resolves its C2 domain list from **Ethereum mainnet contract
`0xE1f2395ee43e45A1556EC6438a88c31B83493103`** (fallback `npm-cache[.]com`), with C2
responses `eval()`d for full RCE. Three capabilities are new to this wave: it commits
five files (`.claude/`, `.vscode/`) to **up to 50 branches per repo** so that
**opening the repo in VS Code or starting a Claude Code session detonates the payload
with no npm install at all**; it steals **GitHub Actions secrets** via an injected
`codeql_analysis.yml` that serializes `${{ toJSON(secrets) }}`, then **deletes the
workflow and branch**; and it abuses **npm OIDC trusted publishing** to mint genuine
Sigstore provenance on malicious artifacts. **All malicious versions have since been
unpublished — which is not remediation:** they persist in committed lock files,
package-manager caches, and already-built images.

- [Playbook](keyv_cacheable_supply_chain/playbook.md) — org-wide manifest/lock discovery, ESLint transitive reach, **all-branch infection scan**, CI log analysis, **Actions secret-harvesting forensics via audit log and artifacts (the code self-deletes)**, forward-propagation check, network hunting, and rotation-first remediation
- [Workstation Playbook](keyv_cacheable_supply_chain/workstation-playbook.md) — the editor/agent backdoor surface first (`.claude/settings.json` `SessionStart` hook, `.vscode/tasks.json` `Environment Setup` task), payload hashes, npm cache, credential exposure inventory, AI-agent conversation scanning

---

### joyfill npm — import-time DEV#POPPER RAT with blockchain-resolved C2 (July 28, 2026)

Six malicious prerelease versions were published across two `@joyfill` npm packages
(`@joyfill/layouts` 0.1.2-2773.beta.0/1/2 and `@joyfill/components`
4.0.0-rc24-2773-beta.4/5/6, ~20,000 weekly downloads each). The implant was appended
to the packages' **built `dist/` bundles** and — unlike a lifecycle-hook compromise —
**executes when Node.js loads the entrypoint**, so `npm install --ignore-scripts`
provides no protection and install logs alone are not evidence. The loader resolves its
C2 address from **public Tron, Aptos and BNB Smart Chain transactions**, pulls a 77 KB
Socket.IO **remote access trojan of the DEV#POPPER family** (`ss_*` command set,
`Sec-V: A9-0135-3` header, `/$/boot` path), then stages a Python credential stealer that
exfiltrates npm/Git tokens, SSH keys, OS keychains and browser secrets to `/u/f`.
Persistence is injected into **developer tooling that survives `rm -rf node_modules`** —
`@vscode/deviceid` (VS Code, Cursor, Antigravity), Discord Desktop, GitHub Desktop, and
the **global npm CLI**, which re-executes the malware on every subsequent `npm` command.
Attributed to the **PolinRider** cluster (assessed related to North Korea-linked
Contagious Interview activity). **Four of the six versions have since been removed from
npm, but both `@joyfill/layouts` prereleases remain installable (status as of 30 July
2026) — and removal is not remediation: a pulled version still lives in committed lock
files, package-manager caches, and already-built images.**

- [Playbook](joyfill_supply_chain/playbook.md) — org-wide manifest/lock-file discovery, CI run analysis for *import-time* detonation (install evidence **plus** execution evidence, and cache-restore bypass), container-layer forensics, C2/blockchain egress hunting, inline developer-workstation checks, and persistence-first remediation

---

### SleeperGem RubyGems — dormant-maintainer backdoor targeting developer machines (July 18, 2026)

Three malicious gems published to RubyGems from **long-dormant maintainer accounts
reactivated within hours of each other** (`LR-DEV`, `pinkroom`) — a "sleeper"
tradecraft where an account quiet for six or seven years slips past reputation
checks. `git_credential_manager` (2.8.0–2.8.3, namesquats Microsoft's Git
Credential Manager), `Dendreo` (1.1.3/1.1.4), and
`fastlane-plugin-run_tests_firebase_testlab` (0.3.2) each ship an **install-time
loader** that fetches a second stage from an attacker Forgejo host
(`git.disroot[.]org/git-ecosystem`), drops a native daemon impersonating Git
Credential Manager (`~/.local/share/gcm/`), installs OS persistence (cron +
systemd user service + a setuid-root shell at `/usr/local/sbin/ping6`), escalates
to root via passwordless `sudo`, and steals credentials. **The loader deliberately
evades CI/CD** — it scans ~30 build-system env vars and exits on any runner,
targeting developer laptops instead. Secondary gems `slackHtmlToMarkdown`,
`seo_optimizer`, `array_fast_methods` declared the malicious `git_credential_manager`
as a transitive dependency. All malicious versions have been yanked.

- [Playbook](sleepergem_supply_chain/playbook.md) — org-wide `Gemfile`/`Gemfile.lock` asset discovery, why CI logs are NOT the evidence surface here, and per-machine remediation/hardening
- [Workstation Playbook](sleepergem_supply_chain/workstation-playbook.md) — the primary surface: daemon (`~/.local/share/gcm/`), setuid shell (`/usr/local/sbin/ping6`), cron/systemd persistence, RubyGems/Bundler cache, `git.disroot.org` egress, shell history, AI-agent conversation scanning

---

### AsyncAPI npm org — OIDC trusted-publisher hijack → Miasma loader (July 14, 2026)

An attacker abused a misconfigured `pull_request_target` workflow in `asyncapi/generator`
(it checked out and ran PR-head code with secrets in scope) to steal the npm publish token,
then let the projects' own OIDC trusted-publisher release pipelines publish **five malicious
versions across four `@asyncapi` packages** (`@asyncapi/specs` 6.11.2 + 6.11.2-alpha.1,
`@asyncapi/generator` 3.3.1, `@asyncapi/generator-components` 0.7.1, `@asyncapi/generator-helpers` 1.1.1)
— each with **valid provenance built from unauthorized commits**. The injected loader runs at
**import/`require()` time** (so `--ignore-scripts` does not help), pulls an encrypted `sync.js`
from IPFS, and runs the **Miasma** botnet (multi-channel C2, OS persistence, credential theft,
dead-man's-switch). `@asyncapi/specs` (~2.25M weekly downloads) is a transitive dep of much of
the AsyncAPI tooling ecosystem — most exposure is indirect. Distinct from the June 3 "Phantom Gyp"
Miasma worm ([miasma_supply_chain/](miasma_supply_chain/playbook.md)): different delivery, trigger,
package set, and C2.

- [Playbook](asyncapi_supply_chain/playbook.md) — repo analysis, CI log scan for import-time runtime egress (IPFS CIDs / HTTP C2 / `rentry.co`), own-org `pull_request_target` audit, deployed-artifact & network checks, and hardening
- [Workstation Playbook](asyncapi_supply_chain/workstation-playbook.md) — dev-machine/runner forensics: `sync.js` drop paths, `miasma-monitor` persistence, npm cache by injected-file hash, network indicators, AI-agent conversation scanning

---

### Gitea Docker Image Auth Bypass — CVE-2026-20896 (June 2026)

The official Gitea Docker image ships an `app.ini` template hard-coding
`REVERSE_PROXY_TRUSTED_PROXIES = *` (safe upstream default is
`127.0.0.0/8,::1/128`). With reverse-proxy authentication enabled, that wildcard
makes Gitea trust the `X-WEBAUTH-USER` header from any source IP — so an
unauthenticated attacker who can reach the HTTP port directly can impersonate any
user, including an admin, with a single header (`curl -H "X-WEBAUTH-USER: admin"`).
CVSS 9.8 (GHSA-f75j-4cw6-rmx4). Affects the Docker image ≤ 1.26.2; fixed in 1.26.3
(which shipped a repo-code-page regression) — upgrade straight to 1.26.4. Unlike an
install-time compromise, this is a **vulnerable configuration state**: no exposure
window, an affected instance is exploitable now. ~6,200 instances were
internet-exposed; in-the-wild probing was observed ~13 days after disclosure from a
ProtonVPN exit node (`159.26.98.241`).

- [Playbook](gitea/playbook.md) — org-wide discovery of Gitea deployments, version + config vulnerable-state check (image tag, `REVERSE_PROXY_TRUSTED_PROXIES`, `ENABLE_REVERSE_PROXY_AUTHENTICATION`), log review for header abuse, and remediation/hardening

---

### codfish/semantic-release-action — poisoned GitHub Action tags (June 24, 2026)

A TeamPCP/Miasma operator with push access to `codfish/semantic-release-action` (the
original semantic-release GitHub Action, used since 2019) force-pushed a malicious
commit and repointed sixteen version tags (`v2`–`v5`, including the floating majors)
to it. The action was converted to a composite action that runs the legitimate step
for cover, installs Bun, and executes the Miasma worm `index.js` inside the runner —
so any workflow referencing a poisoned tag runs the payload on its **next CI run**.
It steals `GITHUB_TOKEN`/OIDC/PATs/`NPM_TOKEN`/AI-tool keys, uses GitHub commit-search
as dead-drop C2 (markers `RevokeAndItGoesKaboom`, `TheBeautifulSandsOfTime`), hijacks
13 AI-assistant configs, and propagates over SSH and via `chore: update dependencies`
+ `skip-checks:true` commits. The fix is structural: pin `uses:` to a pre-compromise
commit SHA, not a tag.

- [Detection](codfish_semantic_release_action/detection.md) — find & classify every `uses:` reference (tag vs SHA), scan CI logs from the exposure window for the poisoned step actually executing, and hunt the worm's org-side + workstation footprint
- [Hardening](codfish_semantic_release_action/hardening.md) — rotate-first remediation, pin all actions to immutable SHAs (ratchet), least-privilege `GITHUB_TOKEN` + egress control, worm-footprint cleanup

---

### PostCSS Typosquat → Windows RAT (June 22, 2026)

Three malicious npm packages published by the npm user `abdrizak` —
`postcss-minify-selector-parser`, `postcss-minify-selector`, and
`aes-decode-runner-pro` — impersonate the popular `postcss-selector-parser`
library (150M+ weekly downloads). Every published version is attacker-authored
malware. The payload fires when the package is **imported** (not via `postinstall`,
so `--ignore-scripts` does not help): an AES-256-GCM-decoded JavaScript dropper
writes and runs a PowerShell script that downloads a Windows bundle from
`nvidiadriver[.]net`, which launches a Nuitka-compiled Python RAT. The RAT steals
Chrome credentials (bypassing app-bound encryption), opens a remote shell, and
persists via a registry Run key (`csshost`) that survives package uninstall.
Windows-only payload. Discovered by JFrog Security Research; npm removed all three
packages on June 24, 2026.

- [Playbook](postcss_supply_chain/playbook.md) — org-wide reference scan, CI log analysis scoped to Windows runners, network IOC checks, evidence tables, and remediation
- [Workstation Playbook](postcss_supply_chain/workstation-playbook.md) — Windows host forensics: RAT artifacts + `.pyd` hash matching, registry persistence, npm cache / lock-file scan, network indicators, Chrome credential-theft exposure, AI-agent conversation logs

---

### Miasma — npm worm via "Phantom Gyp" (June 3, 2026)

A self-replicating npm worm, "Miasma", compromised 57 npm packages across 286+
malicious versions in a sub-two-hour burst. It executes during `npm install`
through a malicious `binding.gyp` (the "Phantom Gyp" technique) — `node-gyp rebuild`
runs the payload with **no `package.json` lifecycle script**, so `--ignore-scripts`
does not stop it. The payload downloads the Bun runtime, steals GitHub tokens
(`gh auth token`), escalates via `sudo`, scrapes secrets from the Actions
`Runner.Worker` process memory (`/proc/<pid>/mem`), and exfiltrates to attacker
GitHub repos — then republishes the victim's own packages (self-propagation).

- [Playbook](miasma_supply_chain/playbook.md) — repo analysis, CI log scan for the gyp/Bun/`/proc/mem` chain, forward-propagation check on the customer's own packages, workstation forensics, and hardening

---

### AntV / Mini Shai-Hulud — npm worm wave (May 19, 2026)

A later TeamPCP "Mini Shai-Hulud" wave that compromised the `@antv` ecosystem (114
packages / 228+ malicious versions) plus `@lint-md/*`, `@openclaw-cn/*`,
`echarts-for-react`, `timeago.js`, `size-sensor`, and `canvas-nest.js` via
compromised maintainer accounts — 600+ malicious versions campaign-wide (317
packages in ~22 minutes). The stealer harvests 20+ credential types, attempts Docker
container escape via the host socket, backdoors `.vscode/tasks.json` and
`.claude/settings.json`, self-propagates through stolen npm tokens (`preinstall` →
`bun run index.js`), and forges Sigstore/SLSA provenance. New C2: `t.m-kosche[.]com`.

- [Playbook](antv_supply_chain/playbook.md) — repo analysis, CI log scan, forward-propagation check, network (`t.m-kosche.com`) + workstation forensics (`.vscode`/`.claude` backdoors, Docker socket), and hardening

---

### TanStack / Mini Shai-Hulud — npm worm wave (May 11, 2026)

A self-propagating npm worm (TeamPCP / Mini Shai-Hulud) that started with
`@tanstack/*` and spread to 19+ npm scopes — ~373 malicious package-versions across
~169 package names. The initial vector poisoned the GitHub Actions cache via a
`pull_request_target` workflow, dumped runner process memory for an OIDC token, and
published malicious tarballs carrying valid SLSA provenance. Installs persistence
(`gh-token-monitor`) and tampers with `.claude/` / `.vscode/` agent configs.

- [Playbook](tanstack_supply_chain/playbook.md) — multi-scope repo analysis, CI log scan, forward-propagation check, network/workstation forensics, and hardening. Part of the same TeamPCP Mini Shai-Hulud series as the [AntV wave](antv_supply_chain/playbook.md) (May 19) — distinct package set and a different C2.

---

### SAP CAP / Mini Shai-Hulud — npm wave (April 29, 2026)

An earlier TeamPCP "Mini Shai-Hulud" wave that backdoored four SAP npm packages
(`@cap-js/sqlite@2.2.2`, `@cap-js/postgres@2.2.2`, `@cap-js/db-service@2.10.1`,
`mbt@1.2.48`; ~1.2M monthly installs, enterprise SAP CI/CD). A `preinstall` hook
downloads the Bun runtime and runs an ~11.7 MB obfuscated stealer (`execution.js`)
harvesting GitHub/npm/cloud/Kubernetes/CI credentials (incl. from runner memory),
exfiltrating AES-256-GCM-encrypted to attacker GitHub repos ("A Mini Shai-Hulud has
Appeared"), with `.vscode/tasks.json` persistence and a Russian-locale guardrail.
Root cause: a compromised SAP dev account + over-broad npm OIDC trusted publishing.

- [Playbook](sap_supply_chain/playbook.md) — repo analysis across npm/pnpm/yarn, CI log scan, forward-propagation, network + workstation forensics, and hardening (incl. scoping npm OIDC trusted publishing). Functionally tested (29/29).

---

### Axios (March 31, 2026)

Two compromised versions of the `axios` npm package (v1.14.1 and v0.30.4) were
published using a hijacked maintainer account. Both inject a phantom dependency
`plain-crypto-js@4.2.1` whose `postinstall` script deploys a cross-platform RAT
targeting macOS, Windows, and Linux. The malware contacts a C2 server, delivers
platform-specific payloads, then self-deletes to evade forensic detection.

- [Playbook](axios/playbook.md) — detection, CI log analysis, persistence checks, evidence tables, and hardening
- [Workstation Playbook](axios/workstation-playbook.md) — dedicated workstation investigation: RAT artifacts, npm cache shasums, OS persistence, network indicators, npm debug logs, AI agent conversation scanning

---

### LiteLLM (March 24, 2026)

Two compromised versions of the `litellm` PyPI package (v1.82.7 and v1.82.8) were
published directly to PyPI, bypassing the project's CI/CD pipeline. The compromise
originated from the Trivy incident in LiteLLM's CI workflow. The payload exfiltrated
environment variables, SSH keys, cloud credentials, and Kubernetes tokens. v1.82.8
dropped a persistent `.pth` file that executes on every Python startup and survives
package uninstall.

- [Detection](litellm/detection.md) — search for litellm in dependency files, scan CI logs for compromised versions and IOCs, check for persistent `.pth` files
- [Hardening](litellm/hardening.md) — pin to exact safe version, migrate from pip to uv or poetry for lock file support, remove `.pth` files, rebuild Docker images

---

### Trivy (March 19-22, 2026)

A threat actor compromised multiple Trivy distribution channels simultaneously:
malicious binary v0.69.4 published to GitHub Releases, APT/RPM repos, and container
registries; 76 of 77 trivy-action tags force-pushed with credential-stealing malware;
all setup-trivy tags replaced. The infostealer dumped CI runner process memory,
harvested credentials from 50+ filesystem paths, and exfiltrated encrypted data
to attacker infrastructure.

- [Detection](trivy/detection.md) — identify all trivy usage, download CI logs from the exposure window, detect compromised versions and tag-poisoned action references
- [Hardening](trivy/hardening.md) — pin actions to commit hashes, replace APT installs with direct downloads + SHA256, bypass setup-trivy

---

## License

MIT
