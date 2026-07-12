# vetlock GitHub Action

A composite Action that runs vetlock on every PR touching `package-lock.json` and
posts the findings as a sticky comment, plus uploads SARIF to code-scanning.

## Usage

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

## Inputs

| Input | Default | What |
|---|---|---|
| `before` | `package-lock.json` | Path to the new lockfile in the head ref. |
| `base-ref` | `github.event.pull_request.base.sha` | Base commit to compare against. |
| `fail-on` | (empty) | Detector ids that force exit 2 regardless of verdict. |
| `sarif-out` | `vetlock.sarif` | Where to write the SARIF file. |
| `comment` | `true` | Post a sticky PR comment. |

## Outputs

| Output | What |
|---|---|
| `verdict` | `BLOCK` / `WARN` / `INFO` / `CLEAN` |
| `finding-count` | Number of findings |

## Exit codes

Same as the CLI: `0` clean, `1` ≥ WARN, `2` ≥ BLOCK (or forced by `--fail-on`).
