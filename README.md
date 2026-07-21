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
