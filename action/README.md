# vetlock GitHub Action

A composite Action that runs vetlock on every PR touching a lockfile (`package-lock.json`,
`pnpm-lock.yaml`, or `yarn.lock`) and posts the findings as a sticky comment, plus uploads
SARIF to code-scanning.

## Usage

### npm

```yaml
name: vetlock
on:
  pull_request:
    paths: ['**/package-lock.json']

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  vetlock:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: OJ-Uday/vetlock/action@v0.7.0
        id: vetlock
        with:
          before: package-lock.json
          fail-on: install.script-added,env.token-harvest,net.new-endpoint
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vetlock.sarif
```

### pnpm

```yaml
on:
  pull_request:
    paths: ['**/pnpm-lock.yaml']
# …
- uses: OJ-Uday/vetlock/action@v0.7.0
  with:
    before: pnpm-lock.yaml
    fail-on: install.script-added,env.token-harvest,net.new-endpoint
```

### yarn

```yaml
on:
  pull_request:
    paths: ['**/yarn.lock']
# …
- uses: OJ-Uday/vetlock/action@v0.7.0
  with:
    before: yarn.lock
    fail-on: install.script-added,env.token-harvest,net.new-endpoint
```

### Python (requirements.txt / poetry.lock / uv.lock)

> **Experimental — PyPI corpus validation in progress.** Detection works end-to-end;
> corpus benchmark score for PyPI attacks will be published when the PyPI corpus is
> complete. All npm-family detectors run unchanged on Python packages.

**requirements.txt:**
```yaml
name: vetlock
on:
  pull_request:
    paths:
      - '**/requirements*.txt'
      - '**/requirements/*.txt'

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  vetlock:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: OJ-Uday/vetlock/action@v0.7.0
        id: vetlock
        with:
          before: requirements.txt
          fail-on: install.script-added,env.token-harvest,net.new-endpoint
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vetlock.sarif
```

**poetry.lock:**
```yaml
on:
  pull_request:
    paths: ['**/poetry.lock']
# …
- uses: OJ-Uday/vetlock/action@v0.7.0
  with:
    before: poetry.lock
    fail-on: install.script-added,env.token-harvest,net.new-endpoint
```

**uv.lock:**
```yaml
on:
  pull_request:
    paths: ['**/uv.lock']
# …
- uses: OJ-Uday/vetlock/action@v0.7.0
  with:
    before: uv.lock
    fail-on: install.script-added,env.token-harvest,net.new-endpoint
```

**Behind an Artifactory proxy** (e.g. Lilly internal):
```yaml
- uses: OJ-Uday/vetlock/action@v0.7.0
  with:
    before: requirements.txt
  env:
    VETLOCK_PYPI_JSON_URL: https://lilly.jfrog.io/artifactory/api/pypi/pypi-remote
    VETLOCK_PYPI_AUTH: ${{ secrets.JF_AUTH }}
```

## Inputs

| Input | Default | What |
|---|---|---|
| `before` | `package-lock.json` | Path to the lockfile in the head ref. Set to `pnpm-lock.yaml`, `yarn.lock`, `requirements.txt`, `poetry.lock`, or `uv.lock` for those ecosystems. The Action preserves the file extension when fetching the base version, so vetlock's format dispatcher picks the right parser. |
| `base-ref` | `github.event.pull_request.base.sha` | Base commit to compare against. |
| `fail-on` | (empty) | Detector ids that force exit 2 regardless of verdict. |
| `sarif-out` | `vetlock.sarif` | Where to write the SARIF file. |
| `comment` | `true` | Post a sticky PR comment (updates the existing comment across pushes). |
| `version` | `latest` | vetlock version to install from npm. Pin to an exact version (e.g. `0.7.0`) for reproducible CI runs. |
| `pypi-registry` | (empty) | PyPI JSON API base URL for Artifactory or other proxies. If unset, vetlock falls back to `VETLOCK_PYPI_JSON_URL`, then `https://pypi.org`. |
| `pypi-auth` | (empty) | PyPI auth credential (Bearer token or `user:token` for Basic). Store this as a GitHub secret. |

## Outputs

| Output | What |
|---|---|
| `verdict` | `BLOCK` / `WARN` / `INFO` / `CLEAN` |
| `finding-count` | Number of findings |

## Exit codes

Same as the CLI: `0` clean, `1` ≥ WARN, `2` ≥ BLOCK (or forced by `--fail-on`).

## Version pinning

For reproducible CI runs, pin the vetlock version:

```yaml
- uses: OJ-Uday/vetlock/action@v0.7.0
  with:
    before: package-lock.json
    version: 0.7.0
```

`latest` (the default) tracks the newest release. This is convenient for keeping detections
fresh; use a pin when you need exact reproducibility (e.g. compliance audits).
