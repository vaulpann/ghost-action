<p align="center">
  <img src="./ghost-logo.png" alt="Ghost" width="88" />
</p>

<h1 align="center">Ghost Supply Chain Scan</h1>

<p align="center">
  <strong>Review new and updated dependencies in pull requests before they land.</strong>
  <br />
  <em>Ghost inspects npm and Python package changes, summarizes what changed, and blocks risky dependency updates.</em>
</p>

<p align="center">
  <a href="https://ghost.validia.ai">Ghost</a> &middot;
  <a href="https://github.com/vaulpann/ghost">Main Repo</a> &middot;
  <a href="./PUBLISHING.md">Publishing Guide</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/ecosystems-npm%20%7C%20PyPI-0f172a?style=flat-square" alt="Ecosystems" />
  <img src="https://img.shields.io/badge/pr_comments-enabled-2563eb?style=flat-square" alt="PR comments" />
  <img src="https://img.shields.io/badge/blocking-high%2B-dc2626?style=flat-square" alt="Blocking threshold" />
  <img src="https://img.shields.io/badge/runtime-node%2020+-16a34a?style=flat-square" alt="Node runtime" />
</p>

---

## What It Does

Ghost watches dependency changes in pull requests and only analyzes packages that actually changed relative to the base branch.

- Detects changed dependency files recursively in monorepos
- Supports npm and Python dependency manifests and lockfiles
- Pulls source for new dependencies and analyzes likely attack surfaces
- Diffs old and new package versions for updates
- Posts one PR comment with a short analysis summary for every changed dependency
- Fails the job only when a dependency meets your configured severity threshold

## Supported Files

- `package-lock.json`
- `yarn.lock`
- `pnpm-lock.yaml`
- `requirements.txt`
- `Pipfile.lock`
- `poetry.lock`

## Quick Start

```yaml
name: Ghost Supply Chain Scan

on:
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: vaulpann/ghost-action@v1
        with:
          fail-on: high
```

## Inputs

| Input | Description | Default |
|---|---|---|
| `api-url` | Ghost API endpoint | `https://ghost-api-495743911277.us-central1.run.app` |
| `fail-on` | Minimum severity that fails the job: `critical`, `high`, `medium`, `none` | `high` |
| `token` | GitHub token used to create or update the PR comment | `${{ github.token }}` |

## How It Behaves

- If a PR does not touch any supported dependency files, Ghost exits cleanly.
- If supported dependency files changed but no dependencies actually changed relative to the base branch, Ghost reports `No new or changed dependencies to scan.`
- If dependencies changed, Ghost posts a table with one row per changed dependency and a short analysis summary.
- Clean packages still get a summary so reviewers can see that Ghost inspected code or a version diff instead of only metadata.
- The job fails only when at least one result reaches the configured `fail-on` threshold.

## Example PR Output

```md
## 🔍 Ghost Supply Chain Scan

0 concerns found in 2 changed dependencies

| Package | Version | Risk | Analysis |
|---------|---------|------|----------|
| lodash | 4.17.21 | 🔵 Low | The lodash package version 4.17.21 does not contain any install scripts, obfuscated code, or suspicious outbound network calls. |
| zod | 3.23.8 -> 3.25.76 | 🔵 Low | The changes in the package primarily involve updates to the license and README files, with no new install scripts, obfuscated code, or suspicious network calls. |
```

## Repository Layout

Publish this action from its own public repository with this root layout:

- `action.yml`
- `README.md`
- `package.json`
- `LICENSE`
- `src/index.js`

Use [PUBLISHING.md](./PUBLISHING.md) for the release steps and Marketplace checklist.

## License

MIT
