# Threat model

**Scope:** malicious/anomalous behavior changes in the transitive npm dependency graph, surfaced
at the moment they enter your lockfile — i.e. during a version bump, whether human or bot
(Renovate/Dependabot) opened the PR.

**Non-scope:** runtime attacks, network intrusion, secrets in *your* code, IaC misconfigurations,
vulnerabilities in already-shipped code (that's `npm audit`'s job — we complement, don't replace).

## Adversaries

### T1 — Maintainer-account takeover (compromised publish)

Attacker gains publish credentials for a legitimate package (via phishing, session cookie theft,
or npm token exfil elsewhere in the ecosystem — see T3) and pushes a patch release with a
payload.

- Real examples: `ua-parser-js` (2021), `coa` / `rc` (2021), `eslint-config-prettier` hijack (2025).
- Signatures we detect: new install script (INSTALL/BLOCK), new network endpoint (NET/BLOCK),
  obfuscated blob (OBF/WARN — BLOCK when co-occurring with NET/INSTALL), env-token read
  (ENV/BLOCK), publish-cadence / maintainer anomaly (META/WARN).

### T2 — Malicious transitive injection

A trusted direct dependency adds or re-points to a new tiny package controlled by the attacker.
The attacker owns *that* package; the trusted maintainer is unwitting.

- Real example: `event-stream` → `flatmap-stream` (2018). At depth 0 the tree change was
  invisible; the payload was in the newly-added transitive dep.
- **This is why the engine is recursive.** Depth-0 tooling was structurally blind to this
  attack.
- Signatures: `DEPS` new node in the tree; brand-new package with immediate capabilities;
  encrypted/obfuscated payload; new-node full-scan (not just diff — a new node has no baseline).

### T3 — Self-replicating worm

A compromised package steals npm/GitHub tokens from the victim's environment and republishes
itself into any package the victim controls, spreading laterally.

- Real example: **Shai-Hulud** wave (chalk, debug, and 100+ others, Sept 2025).
- Signatures: env enumeration (`NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_*`), outbound exfil endpoint,
  `postinstall` addition — the trio triggers a compound BLOCK finding.

### T4 — Protestware / maintainer sabotage

Maintainer weaponizes their own package (colors/faker infinite loop 2022; `node-ipc` targeted
geoIP wipe 2022).

- Signatures we CAN catch: FS writes outside package scope, entropy anomalies, new network
  calls to non-project domains.
- Signatures we CAN'T reliably catch: pure logic bombs using capabilities the package already
  had. **We publish this limitation** rather than claim otherwise.

### T5 — Registry / lockfile tamper

Same version string, different tarball. Either registry-side compromise or an in-flight MITM
against `.npmrc` lockdown.

- Signature: `INTEG` — version-unchanged but integrity hash changed → CRITICAL/BLOCK
  unconditionally, no content analysis required.

### T6 — Typosquat / lookalike adoption

A new direct or transitive dep is a lookalike name (`lodahs` for `lodash`, `noblox.js` for
`noblox-js`).

- Signature: `DEPS` name-distance (Damerau-Levenshtein ≤ 2) against a curated top-N list, +
  zero-history publisher, + very-recent publish date → BLOCK.

## Non-catches (explicit, honest, published in DETECTIONS.md and the README)

- **Logic bombs using existing capabilities.** A package that already writes files getting a
  date-triggered `rm -rf` addition is our hardest case. Mitigations: entropy jump / AST-shape
  anomaly flags. No promise.
- **Fully dynamic loading chains** where every string is computed at runtime. We flag
  unresolvable dynamic `require`/`import` as CODE findings rather than pretending to follow.
- **Malice in BOTH old and new versions.** We diff by design; baseline-scan mode exists but is
  explicitly weaker (marks itself so in output). We are a triage lens on updates, not a
  replacement for reviewing dependencies you already accepted.
- **Non-npm ecosystems.** PyPI is the obvious #2 and is roadmap. Today: npm only.

## Data flow / attack surface of the tool itself

- Inputs: two lockfiles (text), fetched tarballs (bytes).
- Fetch: `pacote` — same auth conventions as npm; supports `--registry` and `.npmrc` `authToken`.
- Extract: our own safe extractor rejecting zip-slip, symlinks, tarbombs (see ADR 0004).
- Analysis: static; ADR 0005 forbids execution.
- Outputs: TTY / JSON / SARIF / Markdown — all local file / stdout.
- Telemetry: **NONE.** No phone-home, no crash reporting, no version-check ping. The tool that
  audits your supply chain must not itself be a supply-chain risk.
- Provenance of the tool: `npm publish --provenance` (SLSA attestation) at every release, plus
  signed tags. Supply-chain hygiene symmetry.

## Adversary against vetlock

We assume an attacker who has read this document. Consequences:

- Detectors that rely on a specific literal ("check if `process.env.NPM_TOKEN` appears") will
  be trivially evaded (`process.env["N"+"PM_TOKEN"]`, `process.env[atob("Tk...")]`). Mitigations:
  scan for the string-building patterns themselves (charCode chains, base64 decode, string
  concat around `process.env` access) — CODE / OBF detectors.
- Attackers can split payloads across files, packages, or lifecycle scripts. Our finding schema
  allows cross-file evidence entries; we don't try to reconstruct the attack, just surface
  every part of it.
- The moment vetlock is popular enough to be worth evading, this document gets a section on
  observed evasions and the detectors added to counter them. Until then: assume the current
  detector set will lose an arms race and instrument for FP monitoring (P8 FP study) so we
  notice when we get quieter than we should be.

## The Completeness Doctrine (ADR 0011)

We answer the "next spelling" arms race by refusing to play it. Detectors target
capability *classes* via the CAPABILITY-MAP's enumerated sinks and entry-points,
prefer chokepoints (dataflow-aware convergence points) over enumeration where
possible, and a CI-enforced coverage gate fails when any enumerated sink/entry-
point lacks a detector + test binding. When a red-teamer or the ASSURANCE
harness finds a new evasion the response is procedural: add the sink to
`capability-map.json`, add its detector/test binding, coverage returns to 100%.

Consequence for THIS threat model: every T1–T6 adversary above eventually
maps onto specific `entry_point` and `capabilities_gained` values in the map.
The threat model names the classes; the doctrine ensures each named class is
*whole*.

## Scan-mode threats (ADR 0012)

`vetlock scan` operates on a single input (a package version or a whole
lockfile) — no diff frame. Everything above still applies, with two caveats:

- **No integrity tripwire.** Same-version-different-tarball attacks require a
  before/after to compare; scan mode structurally can't detect them. The
  README calls this out and points users to `vetlock diff` for that case.
- **Posture-framed severity, not diff-framed.** Scan mode can't say "started
  doing X"; it says "does X." A norm baseline can flag anomalies (a leaf
  utility that harvests tokens is anomalous even without a prior version),
  but until the norm-baseline dataset exists (v2 feature) scan mode honestly
  degrades to "capabilities reported, no norm comparison."

NEVER-EXECUTE (ADR 0005) and safe-extract (ADR 0004) still apply in scan mode.

## OSIF and the shared vocabulary (ADR 0013)

Every attack described above has a corresponding OSIF document — the industry
lacks a shared machine-readable vocabulary for how supply-chain attacks WORK
(the mechanics: entry point, capabilities gained, evasion techniques, delivery
through the graph, indicators). vetlock's corpus is the seed corpus of OSIF
documents; the spec is neutral (CC0, offered to OpenSSF).

Consequence for THIS threat model: when we add a new corpus fixture, it ships
with its OSIF document, and both cite the same `entry_point`/`capabilities_gained`
enumerations as the CAPABILITY-MAP. A threat that vetlock claims to catch is
therefore describable by anyone; a competitor's claim can be scored against
the same OSIF-described attacks (the public benchmark from §5.2).

