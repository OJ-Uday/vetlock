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
      - uses: OJ-Uday/vetlock/action@v0
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
- uses: OJ-Uday/vetlock/action@v0
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
- uses: OJ-Uday/vetlock/action@v0
  with:
    before: yarn.lock
    fail-on: install.script-added,env.token-harvest,net.new-endpoint
```

## Inputs

| Input | Default | What |
|---|---|---|
| `before` | `package-lock.json` | Path to the lockfile in the head ref. Set to `pnpm-lock.yaml` or `yarn.lock` for those ecosystems. The Action preserves the file extension when fetching the base version, so vetlock's format dispatcher picks the right parser. |
| `base-ref` | `github.event.pull_request.base.sha` | Base commit to compare against. |
| `fail-on` | (empty) | Detector ids that force exit 2 regardless of verdict. |
| `sarif-out` | `vetlock.sarif` | Where to write the SARIF file. |
| `comment` | `true` | Post a sticky PR comment (updates the existing comment across pushes). |
| `version` | `latest` | vetlock version to install from npm. Pin to an exact version (e.g. `0.3.0`) for reproducible CI runs. |

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
- uses: OJ-Uday/vetlock/action@v0
  with:
    before: package-lock.json
    version: 0.3.0
```

`latest` (the default) tracks the newest release. This is convenient for keeping detections
fresh; use a pin when you need exact reproducibility (e.g. compliance audits).
