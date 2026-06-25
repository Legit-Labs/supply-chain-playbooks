# codfish/semantic-release-action Compromise (Miasma) — Hardening & Remediation

> **Do NOT proceed without explicit user approval.** Run **[detection.md](detection.md)** first, present findings, then execute the steps below in order. **Rotate before you scrub** — destroying artifacts before rotating credentials hands the attacker a head start with stolen tokens.

## Context

The compromise is **tag repointing** on a GitHub Action: mutable tags (`v2`–`v5`) were force-pushed to a malicious commit, and GitHub Actions resolves a tag at run time. So the durable fix is structural — **pin `uses:` references to immutable commit SHAs** — not "upgrade to a fixed version" (there is no trustworthy tag until the maintainer restores clean ones and you re-verify). The payload also self-propagates and steals long-lived credentials, so remediation has to cover credential rotation, worm-footprint cleanup, and AI-assistant config repair, not just the workflow file.

## Prerequisites — pick a safe ref before un-pinning

There is **no safe tag** while the compromise stands. Options, best first:

1. **Pin to a commit SHA verified to predate `2026-06-24 15:39:06 UTC`.** Find one and confirm its date:
   ```bash
   gh api "/repos/codfish/semantic-release-action/commits/<SHA>" --jq '.commit.committer.date'
   # Must be strictly before 2026-06-24T15:39:06Z. Never pin to
   # 6b9501e1889cc45c91726729610cf69c2442b8c5 / 5792aba... / bcb6b1d... (malicious).
   ```
2. **Use the digest-pinned GHCR Docker image** if your workflow consumed the action's published image (reported clean) — `@sha256:<digest>`, never a floating tag.
3. **Drop the action entirely** and call `semantic-release` directly (`npx semantic-release`) from a SHA-pinned setup, until the maintainer publishes verified-clean tags.

---

## Remediation — only if detection found execution or a worm footprint

### Remediation 1 — Quarantine & snapshot

**The Problem:** A live runner or host may still hold the payload, an authenticated `gh` session, or a `~/.config/index.js` foothold.

**The Fix:**
1. Drain/stop affected CI runners; terminate ephemeral ones.
2. Disconnect any developer/self-hosted host that detection flagged (SSH-reached or AI-config tampered).
3. Snapshot for forensics **before** cleanup: `ps aux`, `~/.config/index.js`, shell history, `~/.claude/settings.json`, `~/.vscode/tasks.json`, `~/.npmrc`, `~/.config/gh/hosts.yml`.

### Remediation 2 — Rotate credentials (GitHub tokens first)

**The Problem:** The payload exfiltrates `GITHUB_TOKEN`-reachable secrets, OIDC tokens, PATs, npm/PyPI/RubyGems creds, and AI-tool API keys. Anything a poisoned workflow could read during the window is burned.

**The Fix — rotate in this order:**
1. **GitHub tokens** — all PATs (fine-grained + classic), `gh` CLI tokens on affected hosts, deploy keys, GitHub App installation tokens. (`GITHUB_TOKEN` auto-expires, but anything it could reach is compromised.)
2. **OIDC trust** — review and, if needed, re-scope cloud trust relationships that the workflow's OIDC token could assume.
3. **Publish tokens** — `NPM_TOKEN`/`.npmrc`, PyPI (`~/.pypirc`), RubyGems. `npm token list` → revoke anything tied to a suspect host; re-issue with 2FA + provenance.
4. **AI-tool API keys** — Anthropic and any other AI key present in CI or on a tampered host.
5. **Any other `secrets.*`** referenced by an affected workflow (cloud keys, registry creds, signing keys, webhooks).

### Remediation 3 — Remove worm footprint

**The Problem:** Miasma commits malware to other repos and tampers AI-assistant configs to re-execute itself.

**The Fix:**
1. Revert/delete propagation commits (`chore: update dependencies` + `skip-checks:true`) and any injected `index.js` / `.config` payload; delete attacker branches.
2. Repair tampered AI-assistant configs in repos and on hosts: remove `SessionStart` hooks from `.claude/settings.json`, malicious `.vscode/tasks.json` / `.vscode/setup.mjs`, and appended commands in `.cursorrules` / `.windsurfrules` / `.github/copilot-instructions.md`. Restore from a known-good commit.
3. Delete dead-drop/exfil repos created in the window; revoke forks.
4. `rm -f ~/.config/index.js`; re-image hosts you can't certify clean.

---

## Hardening — wherever detection found a tag/branch reference (hit or not)

### Hardening 1 — Pin every action to an immutable commit SHA

**The Problem:** Tag and branch refs are mutable; a force-push silently swaps the code on the next run. This is the exact vector that was exploited.

**The Fix:**
```yaml
# VULNERABLE — mutable tag, can be repointed
- uses: codfish/semantic-release-action@v3

# SAFE — immutable SHA verified to predate the compromise, with a version comment
- uses: codfish/semantic-release-action@<pre-compromise-40-char-sha> # v3.x (verified < 2026-06-24)
```
Apply org-wide to **all** third-party actions, not just this one. Automate with [`ratchet`](https://github.com/sethvargo/ratchet) (`ratchet pin .github/workflows/*.yml`) or `pinact`, and enforce in review.

### Hardening 2 — Check transitive action refs

**The Problem:** Even a SHA-pinned action can internally `uses:` another action by tag (the poisoned `action.yml` itself pulled `oven-sh/setup-bun@<sha>` — pinned here, but the pattern is the risk).

**The Fix:** Inspect the `action.yml` at the commit you pin to and confirm its internal `uses:` are SHA-pinned. Where an action insists on installing tooling by mutable ref, install the tool yourself first and skip the action's setup step.

### Hardening 3 — Least-privilege `GITHUB_TOKEN` & restricted egress

**The Problem:** The payload monetizes whatever the workflow token and runner network can reach.

**The Fix:**
```yaml
permissions:
  contents: read   # grant write only to the specific job that needs it
```
- Set a restrictive top-level `permissions:` block; widen per-job only as needed.
- Use environment protection rules for publish/deploy jobs.
- Where supported (self-hosted runners, Harden-Runner-style egress control), allow-list build egress and block runtime downloads from `github.com` and writes to `api.github.com` from build steps — Miasma's C2 and exfil ride exactly those.

### Hardening 4 — Restore clean tags only after verification

**The Problem:** Un-pinning back to `@v3` the moment the repo "looks fixed" re-opens the hole.

**The Fix:** Keep SHA pins until the maintainer publishes a postmortem and verified-clean tags, then re-verify each tag's target commit date before relaxing — or simply keep SHA pinning permanently (recommended).

---

## References

- StepSecurity — codfish/semantic-release-action compromise advisory: https://www.stepsecurity.io/blog/supply-chain-compromise-codfish-semantic-release-action
- GitHub — security hardening for GitHub Actions: https://docs.github.com/en/actions/security-for-github-actions
- `ratchet` (pin actions to SHAs) — https://github.com/sethvargo/ratchet
- Same-campaign remediation references: `miasma_supply_chain/playbook.md`, `trivy/hardening.md`
