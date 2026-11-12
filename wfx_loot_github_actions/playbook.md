# wfx-loot / WFX Phantom — Hijacked GitHub Accounts Push a Self-Erasing CI Secret Stealer — Investigation Playbook

Playbook for investigating whether a GitHub org was hit by the **wfx-loot** campaign (also tracked as **WFX Phantom**). Since **November 10, 2026, ~12:45 UTC**, a threat actor has used stolen GitHub tokens from about **4,800 accounts** to push a ~1,500-line credential stealer into **every repository each token can write to**. About **61,000+ repositories** received a probe pull request, **8,000+** received a malicious commit, and the payload confirmed ran in at least **1,800**. The campaign was **still active** when this playbook was written: new copies switched to Telegram-only exfiltration on November 12.

> **CI/CD platform note:** The attack targets **GitHub** repositories and **GitHub Actions**. Detection is GitHub-API-centric — repository activity, pull requests, workflow runs, and the org audit log. If your org also mirrors these repos into another CI (GitLab CI, Jenkins, CircleCI, Azure DevOps), the `chore: add ci helper` variant (an npm lifecycle hook) runs **wherever `npm install` runs** — include those pipelines' logs in Phase 3.

> **Trigger model — this is not a package compromise.** Nothing is installed from a registry. The attacker **pushes commits** using a stolen token, and the payload runs **on your own CI runners** when the pushed workflow, script, or `package.json` hook executes. Lock files, pinning, and dependency scanning do **not** protect you. Detection centers on **who pushed what to your repos since November 10**, **which workflow runs were deleted**, and **what your cloud accounts now trust**.

> **The attacker erases the evidence.** Each malicious commit is reverted in about a minute, and the workflow run **and its logs are deleted**. Maintainers who noticed it often **force-pushed the branch back**, which removes both the malicious commit and the revert from branch history. Do not conclude "clean" from the Actions UI or from `git log`. This playbook uses three sources that survive cleanup:
> 1. The **repository Activity API**: every push, force-push, branch creation, and deletion, with actor and SHAs.
> 2. **Gaps in per-workflow run numbers**: deleted runs leave holes.
> 3. **Commits fetched by SHA**: they stay readable after a revert or a force-push.

---

## Incident Details

### Attack chain

1. **Probe:** opens a PR titled `docs: dependency audit notes` from branch `wfx-docs`, adding `docs/wfx-audit.md` (git blob `ee6e5addfe591923fc385553cb66cf0d25634a6b`). This confirms the token can write. **A probe PR in your repo means the PR author's token is stolen and has write access — even if no payload followed.**
2. **Payload** (four forms):

| Form | Commit message | What changes |
|---|---|---|
| Workflow injection | `ci: refresh build cache` | Adds steps `Pass runtime` + `Restore cache <4 chars>` to an **existing** workflow, adds `statuses: write` |
| Existing script | `ci: refresh build cache` | Appends the stealer to an existing shell script the CI already runs (`update.sh`, `tests/retry_env.sh`, …) |
| New workflow | `chore: add dependency audit workflow` | Adds `.github/workflows/build-audit-<6 chars>.yml` on a throwaway `chore/<8 chars>` branch (`chore: initial commit` first, in empty repos) |
| npm hook | `chore: add ci helper` | Adds hidden `.ci-<6 chars>.sh` + wires it into `package.json` `postinstall` (also seen: `build`, `test`) — fires on **any** `npm install`, in CI **or on a developer laptop** |

3. **Cleanup:** reverts with `ci: restore` or `ci: cleanup`, then **deletes the workflow run and its logs**.

### What the payload does when it runs

- **Collects:** `${{ toJSON(secrets) }}` and `${{ toJSON(vars) }}` (**every** secret and variable visible to the job, not only those the workflow references); `GITHUB_TOKEN`; OIDC and Actions runtime tokens; the memory of `Runner.Worker` / `Runner.Listener` via `/proc/<pid>/mem`; the environment; credential files for AWS, Azure, GCP, Docker, Kubernetes, npm, PyPI, Git, SSH, GPG, Vault, and Terraform; AI-provider and coding-agent keys; shell histories; and `.env` / `.pem` / `.p12` / `.jks` / `.kdbx` / `kubeconfig` files under `$HOME`. **On self-hosted runners** it also takes cloud instance metadata credentials, Docker state, the runner's RSA registration parameters, and systemd units.
- **Escalates:** mints GitHub OIDC tokens for AWS, GCP, and Azure audiences (even in repos with no cloud setup) and exchanges them. **AWS:** chains into further roles and calls `iam:CreateAccessKey`. **GCP:** impersonates service accounts with `generateAccessToken` / `signJwt`. **Azure:** replays cached Azure CLI refresh tokens (FOCI) for Graph, ARM, and Key Vault. It also replays OIDC tokens against **Vault** and against **Kubernetes** API servers found in kubeconfig.
- **Persists (survives secret rotation):**
  - AWS role trust policy rewritten to `"Principal": {"AWS": "*"}`; STS session names `wfx-*`
  - Azure AD **federated identity credentials** named `wfx-ci-<n>` that trust the compromised repo
  - Forged `success` commit statuses posted under your **required-check names** (branch protection matches on the context name, not on the app that posted it). The code supports this, but it was off in every sampled copy, so check for it anyway.
- **Exfiltrates** one gzipped archive by HTTP POST or to Telegram. Its GitHub-native channels (Actions cache, a step summary between `<!--WFX-BEGIN-->` markers, an artifact named `wfx-loot-<run id>`) were **disabled** in observed copies, so **missing artifacts prove nothing**.

### Exposure window

| Event | Time (UTC) |
|---|---|
| First probe PRs / malicious commits | Nov 10, ~12:45 |
| Probe PR bursts via the Fly.io GitHub App (`fly-io`, app ID 34557) | Nov 11 10:02–10:36; Nov 12 06:20–06:30 |
| Telegram backup channel first seen | Nov 12, 01:10 |
| Telegram-only copies (HTTP callback set to `127.0.0.1`) | Nov 12, ~05:30 onward |
| Status | **Ongoing** — set `UNTIL` to "now" and re-run |

### Indicators of compromise

| IOC | Value | Where it shows up |
|---|---|---|
| Probe PR title | `docs: dependency audit notes` | PRs |
| Probe branch / file | `wfx-docs`, `docs/wfx-audit.md` | branches, PR files |
| Commit messages | `ci: refresh build cache`, `ci: restore`, `ci: cleanup`, `chore: add ci helper`, `chore: add dependency audit workflow`, `chore: initial commit` (empty repos) | Activity API → commit by SHA |
| Branch patterns | `chore/[a-z0-9]{8}`, `ci-check-[0-9]{4}` | Activity API (`branch_creation` / `branch_deletion`) |
| File patterns | `.github/workflows/build-audit-[a-z0-9]{6}.yml`, `.ci-[a-z0-9]{6}.sh` | commit file lists |
| Workflow step names | `Pass runtime`, `Restore cache <4 chars>`, `Run audit` | commit patches, surviving run logs |
| Payload env vars | `WF_CALLBACK`, `WF_CTOKEN`, `WF_SECRETS`, `WF_VARS`, `WF_EXFIL_*`, `WF_TG_BOTS`, `WF_RC_1`, `WF_RC_2` | commit patches, code search |
| Staging dir | `.wfx-$$` | runner filesystem, logs |
| Payload log notes | `memscan_files`, `archive_bytes`, `deliver_retry`, `selfhosted_collected`, `exfil_no_runtime_vars` | surviving run logs |
| Exfil endpoints | `194.150.166[.]244:8080/exfil`, `18.143.168[.]96:8080/exfil`, `153.75.82[.]159:8080/exfil` | egress / firewall / Harden-Runner logs |
| Telegram | `api.telegram.org` `sendDocument`; chat `-1004340163187`; bot IDs `8708988906`, `9196217635`, `9180059428`, `8902935164`, `8876515636` | egress logs, commit patches |
| Callback tokens (`t=`) | `b42d70a7aab9140ca19e8249`, `15f44heehnax8jdf41yx` | commit patches |
| AWS persistence | trust policy `"Principal": {"AWS": "*"}`; session names `wfx-*`; new access keys | IAM, CloudTrail |
| Azure persistence | federated credentials `wfx-ci-*` | Entra app registrations / managed identities |
| Script SHA-256 (one sample) | `89695abb392d5cfd4972672961e644bb46baa98aa1ed7173c2a2816c762735cf` | Limited value: each copy embeds its target repo |
| GhostAction overlap (Oct 2026) | `193.32.204[.]199` / `:8080`; leftover `security-audit.yml` / `audit.yml` / `ci-check.yml` workflows; `public/fonts/fa-solid-400.woff2` (JS); cron tag `#ghc2` | workflows, code search |

### Known downstream packages

Built or published from hit repos. Check `composer.lock` / `go.sum` / `go.mod`:

| Package | Ecosystem | Versions | Notes |
|---|---|---|---|
| `digitalelvis/neuronai-studio` | Packagist | `3.14.3` | Ships `.ci-*.sh` + `postinstall`. Runs on `npm install` inside `vendor/digitalelvis/neuronai-studio`, not on `composer require`. Safe: ≤ `3.14.2`; `3.14.4` was released after cleanup |
| `github.com/onuragtas/docker-env` / `github.com/onuragtas/redock` | Go | `v1.0.278`, `v1.0.280`, `v1.0.282` | Payload only in a workflow file; Go builds don't execute it |
| `github.com/vkuznet/gocurl` | Go | `v0.0.0-20261111095532-8d5aad0cb0da` | Workflow file only; cached in the Go module proxy |

### What IS affected

- Any repo in your org that a compromised account could write to (as owner, org member, team member, outside collaborator, or **bot / machine account**) on or after November 10. That includes **private** repos.
- Any **workflow run** that executed an injected workflow, script, or npm hook. The blast radius is every secret and variable that run could see, plus every cloud role, Vault role, or Kubernetes cluster that **trusts GitHub OIDC tokens from that repo**.
- **Self-hosted runners** that executed the payload: the host's own credentials and instance role, plus Docker state and the runner registration.
- **Developer machines** that ran `npm install` in an affected repo during the ~1-minute window before the revert (the `chore: add ci helper` form).
- **Packages you released** from an affected repo between the malicious commit and its revert.

### What is NOT affected

- Repos where **no compromised account had write access**, and that show no probe PR and no IOC commit in the Activity API since November 10.
- **Fork pull requests** from outside accounts. The campaign pushes **directly** with a token that has write access, and a fork PR's `pull_request` workflow gets no secrets. A `docs: dependency audit notes` PR whose **head repo is a fork** is still a probe, but it proves the *fork owner's* token is stolen, not that your repo was written to.
- Repos that consume the Go packages above **only** as a library. Go builds don't run the workflow file the payload lives in, so no install-time code runs. Remove the versions anyway.
- Lock-file pinning, action SHA pinning, and dependency scanners don't change the verdict either way. The attacker edits **your** workflow files directly.

---

## Pitfalls & Fixes

Found while dry-running this playbook against confirmed-hit public repos (`drunomics/nuxtjs-drupal-ce`, `EbukaLovesTech/*`) on November 12, 2026.

- **Branch history lies after maintainer cleanup.** In `drunomics/nuxtjs-drupal-ce` the maintainer **force-pushed** `2.x` back to the pre-attack commit. The malicious commit `deb537f3a701` (`ci: refresh build cache`) and its revert `b055f7373524` (`ci: restore`) no longer appear in `GET /repos/{r}/commits`. **Fix:** drive detection from the **Activity API** (Phase 2.1) and fetch commits by SHA, which still works.
- **Run numbers are per workflow, not per repo.** A gap is only meaningful within one `workflow_id`. Sorting all runs together produces false gaps. **Fix:** group by `workflow_id` (Phase 2.3). Confirmed: `ci` workflow run **#1964** missing between #1963 and the revert run #1965.
- **Workflows created by the attacker** (`build-audit-<6>.yml`) don't appear under your normal workflows once deleted, so they have no gap to find. **Fix:** catch them through `branch_creation` of `chore/<8>` in the Activity API and the commit file list.
- **`chore/[a-z0-9]{8}` collides with legitimate branches** (`chore/cleanups`, `chore/eslint9x`). **Fix:** treat a branch match as a candidate only, and confirm it by the commit message or file pattern of its head SHA.
- **Commit search and code search only index default branches**, and miss commits that were force-pushed away. Use them for **leftovers** only, never as the primary detector.
- **Don't put the IOC regex inside a jq `test()`.** jq string literals reject regex escapes such as `\.`, and the command fails with `invalid escape sequence`. In an `xargs` loop that error is silent and every repo looks clean. **Fix:** pipe the patch text out of jq and match with `grep -E` (as `check_sha` does).
- **The revert also matches on content.** `ci: restore` / `ci: cleanup` diffs contain the removed payload lines, so content match is `true` for both the malicious commit and its revert. That's expected: the pair together is the evidence.
- **Run the snippets in `bash`, not `zsh`.** They use `export -f`.
- **jq precedence gotcha** with `gh api search/issues`: `[.repository_url|sub(...), .number]` applies `sub` to the whole list and fails. Wrap each field in parentheses: `[(.repository_url|sub(".*/repos/";"")), .number]`.
- **`gh search prs` breaks on a quoted phrase that contains a colon.** Use `gh api -X GET search/issues -f q='"docs: dependency audit notes" in:title is:pr org:<ORG>'` instead.
- **Search API caps at 1,000 results per query.** The global PR count was over 65,000 on Nov 12. Always scope with `org:$ORG` (or `user:` for personal accounts), and split by `created:` date ranges if a single org exceeds 1,000.
- **The audit log endpoint needs GitHub Enterprise Cloud.** On Free or Team plans `/orgs/{org}/audit-log` returns 404, so rely on run-number gaps instead.
- **Positive control.** Before trusting a clean result, run the same Activity API loop with a commit message you know exists in the repo (a recent `chore(deps):` bump, for example) and confirm it matches. An empty result from a broken loop looks the same as an empty result from a clean repo.
- **Self-pollution.** If you run this through an AI agent and also scan local AI-agent conversation logs (Phase 6), exclude the current session. It contains every IOC string you just pasted.

---

## Setup

```bash
# Your GitHub organization (repeat the whole playbook for each org you own)
export ORG="your-org-name"

# Window — the campaign is ongoing; re-run with UNTIL=now
export SINCE="2026-11-10T00:00:00Z"
export UNTIL="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

export OUT="/tmp/supply-chain-scan-wfx-loot"
mkdir -p "$OUT/logs"

# IOC regexes
export IOC_MSG='^(ci: refresh build cache|ci: restore|ci: cleanup|chore: add ci helper|chore: add dependency audit workflow|chore: initial commit|docs: dependency audit notes)$'
export IOC_BRANCH='^refs/heads/(wfx-docs|chore/[a-z0-9]{8}|ci-check-[0-9]{4})$'
export IOC_FILE='(^|/)(\.ci-[a-z0-9]{6}\.sh|build-audit-[a-z0-9]{6}\.yml|wfx-audit\.md)$'
export IOC_CONTENT='WF_CTOKEN|WF_CALLBACK|WF_TG_BOTS|WF_EXFIL_|Pass runtime|Restore cache [a-z0-9]{4}|194\.150\.166\.244|18\.143\.168\.96|153\.75\.82\.159|b42d70a7aab9140ca19e8249|15f44heehnax8jdf41yx|-1004340163187|WFX-BEGIN|wfx-loot'
export IOC_LOG='memscan_files|archive_bytes|deliver_retry|selfhosted_collected|exfil_no_runtime_vars|194\.150\.166\.244|18\.143\.168\.96|153\.75\.82\.159|api\.telegram\.org'

# Token needs: repo, read:org (and admin:org / read:audit_log for the audit log on Enterprise Cloud)
gh auth status

# Repo inventory (include archived — the token could still write before archival)
gh api --paginate "/orgs/$ORG/repos?per_page=100&type=all" \
  --jq '.[] | [.full_name, .visibility, .default_branch, .pushed_at] | @tsv' > "$OUT/repos.tsv"
wc -l "$OUT/repos.tsv"

# Only repos pushed since SINCE can contain a malicious push
awk -F'\t' -v s="$SINCE" '$4 >= s {print $1}' "$OUT/repos.tsv" > "$OUT/repos-active.txt"
wc -l "$OUT/repos-active.txt"
```

---

## Phase 1: Probe Pull Requests (fast org-wide triage)

```bash
gh api -X GET search/issues --paginate \
  -f q="\"docs: dependency audit notes\" in:title is:pr org:$ORG created:>=${SINCE%%T*}" -f per_page=100 \
  --jq '.items[] | [(.repository_url|sub(".*/repos/";"")), .number, .user.login, .state, .created_at] | @tsv' \
  > "$OUT/probe-prs.tsv"
cat "$OUT/probe-prs.tsv"

# For each probe: head branch, head repo (same-repo = direct write; fork = fork owner's token stolen), files
while IFS=$'\t' read repo num author state created; do
  gh api "repos/$repo/pulls/$num" \
    --jq "[\"$repo\", .number, .user.login, .head.ref, .head.repo.full_name, .state, .created_at, (.performed_via_github_app.slug // \"-\")] | @tsv"
done < "$OUT/probe-prs.tsv" > "$OUT/probe-prs-detail.tsv"
```

**Interpretation**

- `head.repo == repo` and head branch `wfx-docs` → **the PR author's token wrote a branch to your repo.** Treat that account as compromised and investigate the repo fully in Phase 2.
- `performed_via_github_app.slug == fly-io` → opened through the Fly.io GitHub App with that user's authorization. The user's OAuth grant to the app is in scope for revocation.
- Every distinct PR author is a **compromised account**. List the **other** repos in your org that account can write to: they're in scope even without a probe PR, because the probe isn't always opened.

```bash
cut -f3 "$OUT/probe-prs-detail.tsv" | sort -u > "$OUT/compromised-accounts.txt"
cat "$OUT/compromised-accounts.txt"
```

---

## Phase 2: Repository Forensics (survives revert, run deletion, and force-push)

### 2.1 Activity API — every push since the window start

```bash
scan_repo() {
  local R="$1"
  gh api --paginate "repos/$R/activity?per_page=100&time_period=month" \
    --jq ".[] | select(.timestamp >= \"$SINCE\") \
               | select(.activity_type==\"push\" or .activity_type==\"force_push\" or .activity_type==\"branch_creation\" or .activity_type==\"branch_deletion\") \
               | [.timestamp, .activity_type, .ref, .actor.login, .before, .after] | @tsv" 2>/dev/null \
  | while IFS=$'\t' read ts typ ref actor before after; do
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$R" "$ts" "$typ" "$ref" "$actor" "$before" "$after"
    done
}
export -f scan_repo
xargs -P 6 -I{} bash -c 'scan_repo {}' < "$OUT/repos-active.txt" > "$OUT/activity.tsv"
wc -l "$OUT/activity.tsv"

# Branch-name IOCs (created or deleted)
awk -F'\t' -v re="$IOC_BRANCH" '$4 ~ re' "$OUT/activity.tsv" > "$OUT/activity-ioc-branches.tsv"
```

### 2.2 Resolve each pushed SHA → message, author, files, payload markers

```bash
check_sha() {
  local R="$1" SHA="$2"
  [ "$SHA" = "0000000000000000000000000000000000000000" ] && return
  local J; J=$(gh api "repos/$R/commits/$SHA" 2>/dev/null) || return
  # content match outside jq (jq string literals reject regex escapes like "\.")
  local HIT=false
  printf '%s' "$J" | jq -r '.files[]?.patch // empty' | grep -qE "$IOC_CONTENT" && HIT=true
  printf '%s' "$J" | jq -r --arg r "$R" --arg hit "$HIT" \
    '[$r, .sha, .commit.author.date, (.author.login // .commit.author.name), (.commit.message|split("\n")[0]), (.commit.verification.verified|tostring), ([.files[]?.filename]|join(",")), $hit] | @tsv'
}
export -f check_sha
cut -f1,7 "$OUT/activity.tsv" | sort -u | xargs -P 6 -L 1 bash -c 'check_sha "$0" "$1"' > "$OUT/pushed-commits.tsv"

# Hits: IOC commit message, IOC file name, or payload content in the patch
awk -F'\t' -v m="$IOC_MSG" -v f="$IOC_FILE" '$5 ~ m || $7 ~ f || $8 == "true"' "$OUT/pushed-commits.tsv" | tee "$OUT/ioc-commits.tsv"
```

A push carries only its head SHA. If one push contained several commits, list them all with `gh api repos/$R/compare/$before...$after --jq '.commits[] | [.sha, (.commit.message|split("\n")[0])] | @tsv'` and run each through `check_sha`.

**Positive control:** `awk -F'\t' '$5 ~ /^chore\(deps/' "$OUT/pushed-commits.tsv" | head -3` should return your own recent dependency bumps. If it returns nothing in a repo where you know they exist, the loop is broken; don't trust a zero.

**Interpretation**

- An IOC message **plus** payload content (`$8 == true`) → **malicious commit confirmed.** The commit author (`$4`) is a **compromised account**.
- `ci: restore` / `ci: cleanup` alone → the revert. Find the matching malicious commit as the push immediately before it.
- `verified == false` on a commit attributed to a human or bot that normally signs → supporting signal.

### 2.3 Deleted workflow runs (run-number gaps)

```bash
gaps_repo() {
  local R="$1"
  gh api --paginate "repos/$R/actions/runs?created=>=$SINCE&per_page=100" \
    --jq '.workflow_runs[] | [.workflow_id, .run_number, .created_at, .name, .head_sha, .event, .actor.login] | @tsv' 2>/dev/null \
  | sort -t$'\t' -k1,1n -k2,2n \
  | awk -F'\t' -v r="$R" '$1==w && $2>p+1 {printf "%s\t%s\t%s\tmissing %d..%d\tbefore %s\tafter %s\n", r, $1, $4, p+1, $2-1, $3, pt} {w=$1; p=$2; pt=$3}'
}
export -f gaps_repo
xargs -P 6 -I{} bash -c 'gaps_repo {}' < "$OUT/repos-active.txt" | tee "$OUT/run-gaps.tsv"
```

Treat a gap as **high-signal** when its time window contains a push from `ioc-commits.tsv` in the same repo. A gap with no nearby IOC commit may be ordinary maintainer cleanup. Note it, but it isn't a finding by itself.

### 2.4 Org audit log (GitHub Enterprise Cloud only)

```bash
# Who deleted workflow runs since the window start
gh api --paginate "/orgs/$ORG/audit-log?per_page=100&phrase=action:workflows.delete_workflow_run+created:>=${SINCE%%T*}" \
  --jq '.[] | [."@timestamp", .actor, .repo, .action] | @tsv' > "$OUT/audit-run-deletions.tsv"

# Everything the compromised accounts did in your org
while read acct; do
  gh api --paginate "/orgs/$ORG/audit-log?per_page=100&phrase=actor:$acct+created:>=${SINCE%%T*}" \
    --jq '.[] | [."@timestamp", .actor, .action, (.repo // "-"), (.programmatic_access_type // "-"), (.token_id // "-" | tostring)] | @tsv'
done < "$OUT/compromised-accounts.txt" > "$OUT/audit-compromised-actors.tsv"
```

`programmatic_access_type` / `token_id` identify **which token** was used (PAT, OAuth app, or GitHub App user-to-server). That's the one to revoke.

### 2.5 Leftovers still on default branches

```bash
for q in WF_CTOKEN WF_CALLBACK "Pass runtime" 194.150.166.244 b42d70a7aab9140ca19e8249 193.32.204.199; do
  gh api -X GET search/code -f q="\"$q\" org:$ORG" --jq ".items[] | [\"$q\", .repository.full_name, .path] | @tsv"
  sleep 7   # code search: 10 req/min
done | sort -u > "$OUT/code-leftovers.tsv"

# Hidden hook scripts and audit workflows still present
gh api -X GET search/code -f q="org:$ORG path:/ filename:.ci-" --jq '.items[] | [.repository.full_name, .path] | @tsv'
gh api -X GET search/code -f q="org:$ORG path:.github/workflows filename:build-audit-" --jq '.items[] | [.repository.full_name, .path] | @tsv'
# package.json scripts that call a hidden .ci-*.sh
gh api -X GET search/code -f q="org:$ORG filename:package.json \".ci-\"" --jq '.items[] | [.repository.full_name, .path] | @tsv'
```

Any hit is **live**: the payload is still committed and will run on the next CI trigger or `npm install`. Remove it first (see Phase 7), then continue.

### 2.6 Forged required-check statuses

For each malicious SHA, list the statuses posted on it. A `success` under a required-check name with no matching run, or created by a compromised account, is forged:

```bash
while IFS=$'\t' read R SHA rest; do
  gh api "repos/$R/commits/$SHA/statuses" --jq ".[] | [\"$R\", \"$SHA\", .context, .state, .creator.login, .created_at] | @tsv"
done < "$OUT/ioc-commits.tsv" > "$OUT/statuses-on-ioc-commits.tsv"
```

Then check whether anything was **merged** on the strength of those statuses: look for `pr_merge` events in `activity.tsv` for the same repo after the IOC commit.

---

## Phase 3: Surviving Run Logs

Some runs survive: a cleanup failed, a run was cancelled midway, or the push-triggered run on a different workflow wasn't deleted. Download logs for runs **on or right after** an IOC commit's SHA:

```bash
while IFS=$'\t' read R SHA rest; do
  gh api --paginate "repos/$R/actions/runs?head_sha=$SHA&per_page=100" --jq ".workflow_runs[] | [\"$R\", .id, .name, .conclusion, .created_at] | @tsv"
done < "$OUT/ioc-commits.tsv" | tee "$OUT/ioc-runs.tsv" | while IFS=$'\t' read R id rest; do
  gh run view "$id" --repo "$R" --log > "$OUT/logs/$(echo "$R" | tr / _)-$id.log" 2>/dev/null || echo "gone: $R $id"
done

grep -lE "$IOC_LOG" "$OUT"/logs/*.log 2>/dev/null
grep -hoE "$IOC_LOG" "$OUT"/logs/*.log 2>/dev/null | sort | uniq -c
```

`memscan_files`, `archive_bytes`, or `deliver_retry` in a log → **the payload ran and attempted exfiltration.** `exfil_no_runtime_vars` → it ran but couldn't reach the Actions runtime channels (the HTTP and Telegram channels still apply).

**Other CI systems** that build these repos and run `npm install` (Jenkins, GitLab, etc.): grep their console logs from the window for `.ci-[a-z0-9]{6}\.sh` and the IOC_LOG patterns.

---

## Phase 4: Impact — What the Payload Could Reach

For every repo with a confirmed malicious commit (or a high-signal run gap):

```bash
impact_repo() {
  local R="$1"
  echo "== $R"
  echo "-- repo secrets";  gh api "repos/$R/actions/secrets" --jq '.secrets[].name'
  echo "-- org secrets visible to repo"; gh api "repos/$R/actions/organization-secrets" --jq '.secrets[].name'
  echo "-- variables";     gh api "repos/$R/actions/variables" --jq '.variables[].name'
  for env in $(gh api "repos/$R/environments" --jq '.environments[].name' 2>/dev/null); do
    echo "-- env $env secrets"; gh api "repos/$R/environments/$env/secrets" --jq '.secrets[].name'
  done
  echo "-- default GITHUB_TOKEN permissions"; gh api "repos/$R/actions/permissions/workflow" --jq '.default_workflow_permissions'
  echo "-- self-hosted runners available to repo"; gh api "repos/$R/actions/runners" --jq '.runners[] | [.name, .os, (.labels|map(.name)|join(","))] | @tsv'
}
while IFS=$'\t' read R rest; do impact_repo "$R"; done < <(cut -f1 "$OUT/ioc-commits.tsv" | sort -u) | tee "$OUT/impact.txt"
```

Secrets don't need to be referenced in the workflow. `toJSON(secrets)` dumps everything the job can see. Count **all** of them.

**OIDC reach:** list every cloud trust that accepts GitHub OIDC tokens for the affected repos. That's the cloud blast radius, even when the repo has no cloud secrets:

```bash
# AWS — roles federated to GitHub OIDC; check the "sub" condition covers the affected repos (or is missing/wildcard)
aws iam list-roles --output json > "$OUT/aws-roles.json"
jq -r '.Roles[] | select(.AssumeRolePolicyDocument|tostring|test("token.actions.githubusercontent.com")) | [.RoleName, (.AssumeRolePolicyDocument|tostring)] | @tsv' "$OUT/aws-roles.json"
# GCP — workload identity pools/providers and their attribute conditions
gcloud iam workload-identity-pools list --location=global --format="value(name)"
# Azure — app registrations with federated credentials issued by GitHub
az ad app list --all --query "[].appId" -o tsv | while read app; do
  az ad app federated-credential list --id "$app" --query "[?issuer=='https://token.actions.githubusercontent.com'].{app:'$app',name:name,subject:subject}" -o tsv
done
```

---

## Phase 5: Cloud Persistence (check every account that trusts the affected repos)

**Do this before rotating secrets.** These backdoors survive rotation.

### AWS

```bash
# Roles whose trust policy allows ANY AWS principal (the wfx backdoor), including array and bare "*" forms
jq -r '.Roles[] | . as $r | [.AssumeRolePolicyDocument.Statement] | flatten | map(select(.Effect=="Allow")) | map(.Principal)
       | map(if type=="string" then . else (.AWS // empty) end) | flatten | select(any(.=="*")) | $r.RoleName' "$OUT/aws-roles.json"

# IAM access keys created since the window start
aws iam list-users --query 'Users[].UserName' --output text | tr '\t' '\n' | while read u; do
  aws iam list-access-keys --user-name "$u" --query "AccessKeyMetadata[?CreateDate>='${SINCE%%T*}'].[UserName,AccessKeyId,CreateDate,Status]" --output text
done

# CloudTrail (90-day lookup; STS via the global endpoint is logged in us-east-1 — also check regional endpoints you use)
for ev in AssumeRoleWithWebIdentity AssumeRole CreateAccessKey UpdateAssumeRolePolicy; do
  aws cloudtrail lookup-events --region us-east-1 --start-time "$SINCE" \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$ev --output json \
  | jq -r '.Events[] | .CloudTrailEvent | fromjson | [.eventTime, .eventName, (.userIdentity.arn // .userIdentity.principalId // "-"), (.requestParameters.roleSessionName // .requestParameters.roleName // .requestParameters.userName // "-"), .sourceIPAddress] | @tsv'
done | tee "$OUT/aws-cloudtrail.tsv" | grep -E 'wfx-|194\.150\.166\.244|18\.143\.168\.96|153\.75\.82\.159'
```

Hits: any role in the wildcard list that you didn't intentionally make public, any session named `wfx-*`, and any `CreateAccessKey` / `UpdateAssumeRolePolicy` that follows a GitHub OIDC assume-role from an affected repo.

### Azure

```bash
# Federated identity credentials on app registrations
az ad app list --all --query "[].{id:appId,name:displayName}" -o tsv | while IFS=$'\t' read app name; do
  az ad app federated-credential list --id "$app" --query "[?starts_with(name,'wfx-ci')].[name,subject,issuer]" -o tsv | sed "s|^|$app\t$name\t|"
done
# Federated credentials on user-assigned managed identities
az identity list --query "[].{n:name,g:resourceGroup}" -o tsv | while IFS=$'\t' read n g; do
  az identity federated-credential list --identity-name "$n" -g "$g" --query "[?starts_with(name,'wfx-ci')].[name,subject]" -o tsv | sed "s|^|$g/$n\t|"
done
```

Also check the Entra sign-in logs for non-interactive sign-ins by the Azure CLI / first-party client IDs from the exfil IPs (the payload replays cached refresh tokens).

### GCP

```bash
# Service-account impersonation through the GitHub workload identity pool (requires IAM Credentials Data Access audit logs)
gcloud logging read "timestamp>=\"$SINCE\" AND protoPayload.serviceName=\"iamcredentials.googleapis.com\" AND protoPayload.methodName=~\"GenerateAccessToken|SignJwt\" AND protoPayload.authenticationInfo.principalSubject:\"workloadIdentityPools\"" \
  --project="$GCP_PROJECT" --format="table(timestamp, protoPayload.methodName, protoPayload.authenticationInfo.principalSubject, protoPayload.resourceName, protoPayload.requestMetadata.callerIp)"
# New service-account keys since the window
gcloud iam service-accounts list --project="$GCP_PROJECT" --format="value(email)" | while read sa; do
  gcloud iam service-accounts keys list --iam-account="$sa" --managed-by=user --created-after="${SINCE%%T*}" --format="value(name,validAfterTime)"
done
```

If Data Access audit logs for `iamcredentials.googleapis.com` were not enabled, this check can't prove a negative. Rotate the reachable service-account keys anyway.

### Vault / Kubernetes

- Vault: audit-log `auth/jwt/login` (or your GitHub JWT mount) since the window start, with `iss` = `https://token.actions.githubusercontent.com` and `sub` naming an affected repo.
- Kubernetes: API server audit logs for authentications by OIDC tokens from `token.actions.githubusercontent.com`, and any RBAC binding created since the window start.

---

## Phase 6: Developer Machines and Published Packages

### 6a. Developer machines (npm-hook form only)

Anyone who ran `npm install` / `npm ci` in an affected repo between the `chore: add ci helper` commit and its revert executed the stealer locally, against their own `~/.aws`, `~/.ssh`, `~/.npmrc`, and AI-tool configs:

```bash
# On each developer machine with a clone of an affected repo
cd /path/to/affected/repo
git log --all --since="2026-11-10" --format='%h %ad %s' --date=iso | grep -E 'chore: add ci helper|ci: restore|ci: cleanup'
ls -la .ci-*.sh 2>/dev/null
ls -d .wfx-* /tmp/.wfx-* 2>/dev/null
# npm debug logs record lifecycle scripts that ran
grep -lE '\.ci-[a-z0-9]{6}\.sh' ~/.npm/_logs/*.log 2>/dev/null
# Packagist package installed via composer and then npm-installed inside vendor/
grep -n '"name": "digitalelvis/neuronai-studio"' -A3 composer.lock 2>/dev/null | grep '"version"'
```

If the hook ran, treat the machine's developer credentials as stolen and rotate them.

When grepping local AI-agent conversation logs (`~/.claude/projects/**/*.jsonl`, Cursor, etc.) for these IOCs, **exclude the session you're running this playbook from**.

### 6b. Packages you publish

```bash
# Releases and tags created in affected repos since the window start
while read R; do
  gh api "repos/$R/releases?per_page=30" --jq ".[] | select(.created_at >= \"$SINCE\") | [\"$R\", .tag_name, .created_at, .author.login] | @tsv"
  gh api --paginate "repos/$R/activity?per_page=100&time_period=month&activity_type=branch_creation" \
    --jq ".[] | select(.timestamp >= \"$SINCE\" and (.ref|startswith(\"refs/tags/\"))) | [\"$R\", .ref, .timestamp, .actor.login] | @tsv" 2>/dev/null
done < <(cut -f1 "$OUT/ioc-commits.tsv" | sort -u) > "$OUT/releases-in-window.tsv"
```

Any release built from a SHA between a malicious commit and its revert must be **rebuilt and republished**, and the bad version deprecated or yanked. Rotate the publishing token used by that workflow (npm, PyPI, Packagist, crates.io, container registry), even if no release happened. The payload stole it either way.

### 6c. Consumers of the known downstream packages

```bash
gh api -X GET search/code -f q="org:$ORG \"digitalelvis/neuronai-studio\"" --jq '.items[] | [.repository.full_name, .path] | @tsv'
for m in onuragtas/docker-env onuragtas/redock vkuznet/gocurl; do
  gh api -X GET search/code -f q="org:$ORG \"github.com/$m\" filename:go.sum" --jq '.items[] | [.repository.full_name, .path] | @tsv'; sleep 7
done
```

---

## Phase 7: Evidence & Executive Summary

### Repo evidence (`$OUT/evidence-repos.csv`)

| Field | Values |
|---|---|
| repo | `org/name` |
| probe_pr | none / open #N / closed #N (same-repo or fork) |
| ioc_commits | SHAs + messages |
| pushing_account | login(s) |
| payload_form | workflow / existing-script / new-workflow / npm-hook / none |
| run_gap | workflow + missing run numbers, or none |
| surviving_log_markers | e.g. `memscan_files`, or none |
| payload_ran | **confirmed** / **likely** (IOC commit + run gap) / **no evidence** |
| secrets_exposed | count + names (repo + org + environment) |
| oidc_reach | AWS roles / GCP providers / Azure apps that trust this repo |
| self_hosted | yes / no |
| leftovers_on_default_branch | yes / no |

### CI runs evidence (`$OUT/evidence-ci-runs.csv`)

| Field | Values |
|---|---|
| repo, workflow, run_number(s) | |
| status | deleted (gap) / surviving |
| head_sha | IOC commit SHA |
| actor | |
| log_markers | |

### Cloud evidence (`$OUT/evidence-cloud.csv`)

| Field | Values |
|---|---|
| provider / account | |
| finding | wildcard trust role / new access key / `wfx-*` session / `wfx-ci-*` federated credential / SA impersonation |
| resource | |
| first_seen | |

### Executive summary

- **Verdict:** NOT AFFECTED / PROBED ONLY (stolen tokens with write access, no payload) / PAYLOAD PUSHED (ran: unconfirmed) / **COMPROMISED** (payload ran, or cloud persistence found)
- Compromised accounts (and the tokens to revoke)
- Repos with the payload pushed / confirmed run
- Secrets and cloud roles to rotate
- Cloud persistence found and removed
- Packages to rebuild

---

## Phase 8: Remediation & Hardening (User Approval Required)

Do not run destructive steps without the user's approval. Order matters: **evict, then rotate.**

### Remediation — if anything beyond "NOT AFFECTED"

1. **Remove live payloads** found in Phase 2.5: revert the file or `package.json` hook on every branch where it still exists.
2. **Lock down every compromised account:** revoke its PATs (fine-grained and classic), OAuth app grants (including the Fly.io app if used for probes), SSH keys, and active sessions; require a password reset and 2FA re-enrollment; scan the owner's machine for an infostealer (the tokens came from somewhere). For org-owned tokens use `/orgs/$ORG/personal-access-tokens` to list and revoke fine-grained PATs. For bot or machine accounts (`drubot`, `wdio-bot` in public cases), rotate their tokens and review any branch-protection bypass they hold.
3. **Remove cloud persistence first:**
   - AWS: restore the original trust policy on every wildcard role; delete IAM access keys created since November 10; revoke active sessions on every affected role (IAM console → role → **Revoke active sessions**, which adds the `AWSRevokeOlderSessions` deny policy).
   - Azure: delete `wfx-ci-*` federated credentials; revoke refresh tokens for users whose Azure CLI cache was on an affected runner (`az ad user revoke-sign-in-sessions` or `Revoke-MgUserSignInSession`).
   - GCP: delete service-account keys created in the window; review and tighten workload identity provider attribute conditions.
   - Vault / Kubernetes: revoke tokens and leases issued to GitHub JWT logins from affected repos.
4. **Rotate:** every repo, org, and environment secret visible to affected repos' workflows; publishing tokens; registry credentials; webhook URLs; AI-provider keys; self-hosted runner host credentials (and re-register the runner).
5. **GitHub cleanup:** close probe PRs, delete `wfx-docs`, `chore/<8>` and `ci-check-<4>` branches, and revert any merge that passed on forged statuses.
6. **Rebuild and republish** packages released from an affected SHA.

### Hardening — wherever a probe or payload was found (and recommended org-wide)

| Weakness exploited | Fix |
|---|---|
| A stolen token can push straight to the default branch | Rulesets: require pull requests on default and release branches, block direct pushes and force-pushes, require signed commits; minimize bypass actors, especially bot accounts |
| `toJSON(secrets)` sees every secret | Move secrets into **environments** with required reviewers or deployment-branch rules, so a push to an arbitrary branch can't read them |
| OIDC trusted too broadly | Constrain AWS `sub` / GCP attribute conditions / Azure subject to `repo:<org>/<repo>:ref:refs/heads/<branch>` or an environment, never `repo:<org>/*` or a missing condition |
| Default `GITHUB_TOKEN` write permissions | Org setting: default workflow permissions = **read**; grant `statuses: write` / `id-token: write` per job only where needed |
| Required checks satisfied by any status poster | Bind required checks to a specific GitHub App (ruleset "required status checks" with an expected source) |
| Open egress from runners | Egress allowlists on runners (block raw IPs and `api.telegram.org`); runtime monitoring such as Harden-Runner on GitHub-hosted runners |
| Long-lived, broad user tokens | Enforce fine-grained PATs with expiry for the org; require approval for PAT access; restrict OAuth app access policies |
| Self-hosted runners with persistent credentials | Ephemeral (`--ephemeral`) runners, no instance-role credentials beyond what the job needs |

---

## References

- StepSecurity — [WFX Phantom: The GitHub Actions Secret Stealer That Deletes Its Tracks](https://www.stepsecurity.io/blog/wfx-phantom-the-github-actions-secret-stealer) (timeline, 101-copy exfil configuration analysis, full IOC list)
- SafeDep — [wfx: GitHub Actions Credential Stealer Hits 8,000 Repos](https://safedep.io/blog/github-actions-wfx-credential-stealer) (payload-commit counts, downstream package survey)
- Help Net Security — [Check your GitHub repos: A secret stealer hit tens of thousands of them](https://www.helpnetsecurity.com/2026/11/12/wfx-loot-github-actions-secret-stealer/)
- GitHub Docs — [Repository activities API](https://docs.github.com/en/rest/repos/repos#list-repository-activities), [Audit log events for your organization](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization)
