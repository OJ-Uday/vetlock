# Roadmap

## Now (v0.0.x — alpha)

- [x] Core: safe extract, cache, capability extraction (all NEVER-EXECUTE-guarded).
- [x] Recursive lockfile engine with closure-completeness invariant.
- [x] 9 built-in detectors (INSTALL, META, NET, EXEC, FS, ENV, CODE, OBF, DEPS-manifest,
  INTEG).
- [x] CLI: `vetlock diff` with TTY/JSON/SARIF/MD renderers.
- [x] GitHub Action (composite) with sticky PR comments + SARIF upload.
- [x] Historical corpus: Shai-Hulud 2025 defanged fixture + green acceptance test.
- [x] FP smoke: 3 benign bumps → 0 findings.

## Next (v0.1.x)

- [ ] **pnpm lockfile support** (`pnpm-lock.yaml` v5+). Highest-demand feature.
- [ ] **`scan` mode** (baseline scan of a single lockfile — self-labels as weaker, no diff frame).
- [ ] **Yarn classic + berry** lockfile support.
- [ ] **Broader historical corpus** — replay 8+ named attacks (event-stream, ua-parser-js,
  coa/rc, eslint-config-prettier, colors, node-ipc). Publish catches AND misses honestly.
- [ ] **FP study at scale** — run vetlock against the last N version bumps of the top 50 npm
  packages, measure FP rate, tune defaults, publish `BENCHMARK.md`.

## Later (v0.2.x — stability)

- [ ] **Detector plugin API** (external `.mjs` files loaded via `.vetlock.json`).
- [ ] **Config file** — per-package capability allowlists, severity overrides, path ignores.
- [ ] **Typosquat detector** — name-distance vs curated top-N list + zero-history publisher +
  very-recent publish date.
- [ ] **Publish-cadence META signal** — silent maintainer suddenly publishing after long
  dormancy.
- [ ] **Rich SARIF** — richer help URIs per detector, one help page per detector id.

## Someday (v1.x)

- [ ] **PyPI ecosystem** — the obvious #2. Different tarball shape, different parser, same
  detector taxonomy.
- [ ] **`sbom` companion** — emit CycloneDX SBOMs with vetlock-tagged capability metadata.
- [ ] **Optional Go engine** — a Go rewrite of just the graph/fetch layer for corporate-scale
  monorepos where the Node startup latency dominates.

## Never

- No dynamic/sandbox execution analysis. "Run malware to detect malware" inverts the safety
  model, and the FP + infrastructure costs are disqualifying at open-source scale.
- No hosted SaaS layer that sees your lockfiles.
- No telemetry. Ever.
