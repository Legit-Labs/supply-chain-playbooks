# SleeperGem RubyGems Compromise — Investigation Playbook

Playbook for investigating whether a GitHub org and its developers were affected
by the **SleeperGem** RubyGems supply-chain compromise (July 18, 2026).

> **Note for AI agents:** This playbook targets GitHub for org-wide asset
> discovery. For other SCMs (GitLab, Bitbucket, Azure DevOps), adapt the search
> commands — the logic is the same: find every project that references the
> malicious gems in a `Gemfile` / `Gemfile.lock`, then pivot to
> **[workstation-playbook.md](workstation-playbook.md)** for the machines that
> installed them.

> **⚠️ This malware deliberately evades CI/CD.** The loader scans for ~30 build-
> system environment variables (GitHub Actions, GitLab CI, CircleCI, Travis,
> Jenkins, Vercel) and **exits immediately if it detects one**. It targets
> developer laptops, not disposable CI runners. **Do not center this investigation
> on CI logs** — a clean CI log does not mean a developer's machine is clean. The
> two evidence surfaces that matter are (1) the **dependency manifest** (does any
> project reference the malicious gems?) and (2) **developer-workstation forensics**
> (did the backdoor actually detonate?).

---

## Incident Details

On **July 18, 2026**, three malicious gems were published to RubyGems. Two came
from **long-dormant maintainer accounts reactivated within hours of each other**
(`LR-DEV`, `pinkroom`) — a "sleeper" tradecraft: an account quiet for six or
seven years does not trip reputation checks. Each malicious release is an
**install-time loader** that fetches a second stage from an attacker-controlled
Forgejo host, drops a native daemon masquerading as Microsoft's Git Credential
Manager, installs OS persistence, escalates to root where possible, and harvests
credentials.

### Compromised gems

| Gem | Malicious versions | Notes |
|---|---|---|
| `git_credential_manager` | `2.8.0`, `2.8.1`, `2.8.2`, `2.8.3` | Namesquats Microsoft's Git Credential Manager. Published Jul 18, 2026. Fully yanked. |
| `Dendreo` | `1.1.3`, `1.1.4` | Dormant account (last legit release Oct 24, 2020) reactivated. Yanked — RubyGems now tops at `1.1.2`. |
| `fastlane-plugin-run_tests_firebase_testlab` | `0.3.2` | Dormant account (last legit release Mar 9, 2019) reactivated. Yanked — RubyGems now tops at `0.3.1`. |

**Secondary / transitive vectors** (maintained by the compromised `LR-DEV`
account, declared malicious `git_credential_manager` as a dependency — no specific
malicious version published, treat any install during the window as suspect):
`slackHtmlToMarkdown`, `seo_optimizer`, `array_fast_methods`.

### Staging vs. activation

- `git_credential_manager` **2.8.2** stages the payloads.
- `git_credential_manager` **2.8.3** downloads the next stage (via PowerShell on
  Windows), establishes the daemon, installs persistence, and **escalates to root
  if passwordless `sudo` is available**.

### Exposure window

| Event | Date |
|---|---|
| Malicious `git_credential_manager` 2.8.0–2.8.3 published | July 18, 2026 |
| `Dendreo` / `fastlane-plugin-run_tests_firebase_testlab` dormant accounts reactivated | July 18, 2026 (within hours) |
| Gems yanked from RubyGems (public disclosure) | ~July 20, 2026 |

**Recommended window:** `2026-07-18` to `2026-07-20`. Precise UTC publish/yank
timestamps were not officially published — treat the whole window as suspect.

### Indicators of compromise

| IOC | Value |
|---|---|
| Second-stage host (Forgejo) | `git.disroot[.]org/git-ecosystem` |
| Backdoor daemon dir | `~/.local/share/gcm/` |
| Setuid-root shell | `/usr/local/sbin/ping6` |
| Second-stage script | `deploy.sh` |
| Persistence | cron entry + systemd **user** service referencing the daemon |
| Root escalation | via passwordless `sudo` on install |

### What IS affected

- Any **developer workstation** (macOS / Linux / Windows) that ran
  `gem install` / `bundle install` and resolved a malicious version during the
  window — directly or transitively via a secondary gem.
- Any project whose `Gemfile` / `Gemfile.lock` references the malicious gems.

### What is NOT affected

- **CI/CD runners and build servers** — the loader detects the CI environment and
  exits without detonating. (The manifest may still *list* the gem, but the
  payload does not run there.)
- Installs strictly from a pre-window `Gemfile.lock` via `bundle install --frozen`
  / `--deployment` (only pinned versions resolve).
- Any gem version other than those in the Compromised gems table.

### Lock file protection

`Gemfile.lock` **DOES protect** — but only when installs are frozen:
- `bundle install --frozen` / `bundle install --deployment` installs exactly what
  the lockfile pins; if the lock predates the window, the malicious versions never
  resolve.
- Lock files do **NOT** help if: no `Gemfile.lock` is committed; a developer ran
  bare `gem install git_credential_manager` (bypasses Bundler entirely); `bundle
  update` regenerated the lock during the window; or a secondary gem not in the
  lock was installed ad-hoc and pulled the malicious dep transitively.

---

## Setup

```bash
export ORG="<your-github-org>"
export SINCE="2026-07-18"
export UNTIL="2026-07-20"
export SCAN_DIR="/tmp/supply-chain-scan-sleepergem"
mkdir -p "$SCAN_DIR"

# Malicious gem names (any version match is worth inspecting; the loader ran
# only for the versions in the Incident Details table)
GEMS_PRIMARY="git_credential_manager Dendreo fastlane-plugin-run_tests_firebase_testlab"
GEMS_SECONDARY="slackHtmlToMarkdown seo_optimizer array_fast_methods"

# Network IOC
C2_HOST="git.disroot.org"
```

**Write to files, not context:** org scans can be large. Write structured data to
CSV in `$SCAN_DIR` as you go.

**Rate limits:** check your GitHub API budget before a large org scan:
```bash
gh api /rate_limit --jq '.resources.code_search | "\(.remaining)/\(.limit) code-search remaining"'
```
Code search is ~30 req/min. Use `xargs -P 10` for parallelism and cache to `$SCAN_DIR`.

---

## Phase 1: Org-Wide Asset Discovery

**Goal:** find every project that references a malicious gem in a Ruby manifest.
This is the surface Legit's SCA sees, and the shortlist of teams to route to the
workstation playbook.

### 1a. Code search across the org

```bash
for gem in $GEMS_PRIMARY $GEMS_SECONDARY; do
  echo "=== $gem ==="
  gh api -X GET search/code \
    -f q="$gem org:${ORG} filename:Gemfile" \
    --jq '.items[] | "\(.repository.full_name)\t\(.path)"' 2>/dev/null
  gh api -X GET search/code \
    -f q="$gem org:${ORG} filename:Gemfile.lock" \
    --jq '.items[] | "\(.repository.full_name)\t\(.path)"' 2>/dev/null
done | sort -u | tee "$SCAN_DIR/manifest-hits.tsv"
```

> **Positive control:** before trusting a clean result, prove the search works.
> Run the same query for a gem you know the org uses (e.g. `rails` or `rspec`) and
> confirm it returns hits. A broken query and a genuinely-clean org both return
> zero rows — the control distinguishes them.

### 1b. Classify each hit

For every repo/file in `manifest-hits.tsv`, pull the file and check whether it
pins a **malicious version** (vs. merely naming the gem historically):

```bash
while IFS=$'\t' read -r repo path; do
  content=$(gh api "repos/${repo}/contents/${path}" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null)
  # Malicious version fingerprints
  echo "$content" | grep -nE \
    "git_credential_manager.*(2\.8\.0|2\.8\.1|2\.8\.2|2\.8\.3)|Dendreo.*(1\.1\.3|1\.1\.4)|fastlane-plugin-run_tests_firebase_testlab.*0\.3\.2" \
    && echo "  ^ MALICIOUS VERSION PINNED in ${repo}/${path}"
done < "$SCAN_DIR/manifest-hits.tsv" | tee "$SCAN_DIR/manifest-classified.txt"
```

Classify each hit as:
- **Malicious version pinned** in `Gemfile.lock` → strong signal the gem was
  resolved; route every developer/machine on this repo to the workstation playbook.
- **Gem named in `Gemfile` with a loose constraint** (e.g. `gem "git_credential_manager"`
  with no version, or `~> 2.8`) → could have resolved a malicious version on an
  unpinned `bundle install`; inspect the lockfile and route to the workstation
  playbook if the lock is missing or post-window.
- **Secondary gem present** (`slackHtmlToMarkdown` / `seo_optimizer` /
  `array_fast_methods`) → transitive vector; route to the workstation playbook.

---

## Phase 2: Workstation Triage (the primary surface)

Because the payload **only runs on developer machines**, org discovery just tells
you *who to ask*. The actual determination of compromise happens per-machine.

For every developer who works on a repo flagged in Phase 1 — and anyone who may
have run `gem install`/`bundle install` for the named gems during the window —
run **[workstation-playbook.md](workstation-playbook.md)** on their machine. It
checks for the daemon (`~/.local/share/gcm/`), the setuid shell
(`/usr/local/sbin/ping6`), cron/systemd persistence, RubyGems caches, C2 egress
to `git.disroot.org`, shell history, and AI-agent conversation logs.

### Why CI logs are not the answer here

If you still want to sanity-check CI, note that a **clean** result is expected and
proves nothing: the loader exits on any CI runner. A CI log showing
`Installing git_credential_manager 2.8.2` means the manifest resolved the
malicious version — but the payload **did not detonate on the runner**. The same
manifest resolving on a developer's laptop **would** detonate. So a CI install
line is a signal to investigate the *developers*, not evidence the runner is
infected.

---

## Phase 3: Remediation & Hardening

Run per-machine after the workstation playbook confirms (or to harden proactively).

### Hardening 1 — Remove persistence FIRST

Before removing the gems, kill the backdoor so it cannot re-establish:

```bash
# Daemon
rm -rf ~/.local/share/gcm/
# Setuid-root shell (requires sudo)
sudo rm -f /usr/local/sbin/ping6
# systemd user service
systemctl --user list-units --all 2>/dev/null | grep -i gcm
#   → systemctl --user disable --now <unit>; rm ~/.config/systemd/user/<unit>
# cron
crontab -l 2>/dev/null | grep -iE "gcm|disroot|ping6"   # then crontab -e to remove
```

### Hardening 2 — Remove the malicious gems

```bash
gem uninstall git_credential_manager -a -x 2>/dev/null
# Audit the dormant-account and secondary gems; remove if the malicious version is present
for g in Dendreo fastlane-plugin-run_tests_firebase_testlab slackHtmlToMarkdown seo_optimizer array_fast_methods; do
  gem list -e "$g" 2>/dev/null
done
```
Reinstall only from a trusted, pre-window `Gemfile.lock`.

### Hardening 3 — Rotate credentials

Treat every secret reachable from an affected machine as exposed: SSH keys, cloud
credentials (`~/.aws`, `~/.config/gcloud`, Azure), git/registry tokens
(`~/.netrc`, `~/.gem/credentials`, `bundle config`), and anything a root daemon
could read.

### Hardening 4 — Enforce lock-file-respecting installs

- CI and dev: prefer `bundle install --deployment` / `--frozen` over
  `bundle update` and bare `gem install`.
- Add a policy check that fails when a `Gemfile.lock` is missing or regenerated in
  a PR that also changes gem constraints.

### Hardening 5 — Block C2 egress

Temporarily deny `git.disroot.org` at the network/proxy layer until all affected
machines are cleaned.

---

## Pitfalls & Fixes

- **`git_credential_manager` is a real Microsoft product name.** Repos may
  reference "Git Credential Manager" in docs, git config, or CI setup steps that
  have **nothing to do** with the malicious gem. The RubyGems package
  `git_credential_manager` is the namesquat — a hit only matters when it appears
  as a **gem dependency** in a `Gemfile` / `Gemfile.lock`, not in prose or shell
  setup. Scope Phase 1 searches to `filename:Gemfile` / `filename:Gemfile.lock`.
- **A CI log install line is not a runner compromise.** See Phase 2 — the loader
  self-terminates on CI. Route the finding to developers, don't quarantine the
  runner.
- **Yanked gems still appear in old lockfiles.** All malicious versions are yanked,
  so `bundle install` today will fail to resolve them — but a `Gemfile.lock`
  committed during the window still *records* the malicious version, and the
  machine that generated it already ran the install. The lockfile is a historical
  IOC, not just an install-time control.
- **Self-pollution.** If you run this playbook with an AI agent, the agent's own
  session transcript will contain every IOC string above. When scanning AI-agent
  conversation logs (workstation Check 8), exclude the current session.
