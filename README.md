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

### Axios (March 31, 2026)

Two compromised versions of the `axios` npm package (v1.14.1 and v0.30.4) were
published using a hijacked maintainer account. Both inject a phantom dependency
`plain-crypto-js@4.2.1` whose `postinstall` script deploys a cross-platform RAT
targeting macOS, Windows, and Linux. The malware contacts a C2 server, delivers
platform-specific payloads, then self-deletes to evade forensic detection.

- [Playbook](axios/playbook.md) — detection, CI log analysis, persistence checks, evidence tables, and hardening

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
