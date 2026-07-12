# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for security-sensitive reports. Instead, contact:

- **GitHub Security Advisories:** https://github.com/OJ-Uday/vetlock/security/advisories/new

We'll acknowledge receipt within 3 business days and aim to have a fix (or a documented
mitigation) within 30 days of receipt for high-severity issues, sooner for critical.

## Scope

vetlock is a static analyzer that never executes analyzed package code (see
[docs/adr/0005-never-execute.md](docs/adr/0005-never-execute.md)). The security-critical
surfaces we care most about:

- **Safe extraction** (`packages/core/src/extract.ts`). Zip-slip, symlinks, tarbombs. A
  regression here would let a malicious tarball write outside vetlock's temp dir.
- **NEVER-EXECUTE invariant.** If someone finds a code path that causes analyzer machinery
  to invoke content from an analyzed package, that's a critical issue.
- **Parser resilience.** Any input that panics vetlock hard (segfault, hang > 30 s) qualifies.
- **Cache poisoning.** The snapshot cache is content-addressed; anyone who can trick it into
  returning the wrong snapshot for a hash has changed our results.
- **Registry auth handling.** pacote does most of this; report configuration paths that could
  leak credentials.

## Not in scope

- **Correctness of the detector taxonomy itself.** Missing a novel attack shape is an FP/FN
  research issue, not a vulnerability. File it as a normal bug or a detector proposal.
- **Third-party dependency vulnerabilities.** Please report those upstream first; we'll
  bump quickly once fixed.

## Supply-chain hygiene of vetlock itself

- Releases go out with `npm publish --provenance` (SLSA attestation) — a security tool must
  not itself be a supply-chain risk.
- All commits are signed.
- CI has vetlock running on its own PRs (`vetlock-dogfood.yml`).
