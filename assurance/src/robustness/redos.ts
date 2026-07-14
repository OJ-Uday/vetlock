/**
 * ReDoS (catastrophic regex backtracking) generators (packet §2.1 threat family).
 *
 * These generators produce adversarial lockfile-shaped inputs designed to exercise
 * the backtracking path of a *specific* regex on the engine's public surface. Each
 * candidate names the target regex verbatim so the corpus reader can trace a finding
 * back to the source line without guessing.
 *
 * Enumeration of the engine's regex surface reachable from `parseLockfileText`
 * (the only regex-heavy public entrypoint that runs without network / disk / detectors):
 *
 *   lockfile-any.ts:57  `/^\s*__metadata:/m`            — anchored literal prefix. SAFE.
 *   lockfile-any.ts:63  `/^lockfileVersion:/m`          — anchored literal. SAFE.
 *   lockfile-any.ts:64  `/^__metadata:/m`               — anchored literal. SAFE.
 *   lockfile-any.ts:65  `/^# yarn lockfile v1/m`        — anchored literal. SAFE.
 *   lockfile-any.ts:65  `/^\w[\w./@-]*@[^:]+:\s*$/m`    — QUANTIFIER OVERLAP — probed.
 *   lockfile-any.ts:52  `filename.split(/[\\/]/)`       — trivial separator split. SAFE.
 *   lockfile-yarn.ts:53 `/^\s*__metadata:/m`            — anchored literal. SAFE.
 *   lockfile-yarn.ts:53 `/^__metadata\b/m`              — anchored literal + \b. SAFE.
 *   lockfile-yarn.ts:211 `/^[\^~><=*]/`                 — anchored single-char class. SAFE.
 *
 * Only `lockfile-any.ts:65` has a shape worth stressing: `[\w./@-]*@[^:]+` — the outer
 * greedy char class INCLUDES `@`, and the literal `@` that follows is thus a candidate
 * split point at every `@` in the run. Combined with `[^:]+` (greedy, matches newlines
 * because there is no `s` flag) an adversary can force the regex engine into
 * O(N * text_length) backtracking when the terminal `:` is absent.
 *
 * All other regexes in the direct surface are anchored to fixed literals or trivial
 * one-character classes and have no plausible catastrophic backtracking path. Regex-
 * heavy source-code analysis (capabilities.ts, extract.ts) is NOT reachable from
 * `parseLockfileText` — it runs only under `runDiff` behind network fetches which the
 * assurance harness disables.
 */

import type { LockfileInput } from './types.js';

export interface ReDosCandidate {
  /** Stable id used in test names and corpus paths. */
  readonly id: string;
  /** Human-readable pointer to the exact regex under test (pattern + source location). */
  readonly targetRegex: string;
  /**
   * Produce an input scaled to `scale` (roughly the size of the adversarial repetition).
   * Pure: same `scale` always yields byte-identical output — every timeout replays.
   */
  readonly generate: (scale: number) => LockfileInput;
}

export const redosCandidates: readonly ReDosCandidate[] = [
  {
    id: 'lockfile-any-yarn-classic-detect-many-ats',
    targetRegex:
      String.raw`/^\w[\w./@-]*@[^:]+:\s*$/m in packages/core/src/lockfile-any.ts:65 (yarn-classic content-only detector)`,
    generate(scale) {
      // The yarn-classic content-only detector hunts for a `name@spec:` header line.
      // Its shape `\w[\w./@-]*@[^:]+:\s*$` has three ambiguities an adversary can exploit:
      //   1. `[\w./@-]*` is greedy AND its char class INCLUDES `@`, then the literal `@`
      //      that follows must match too — so any `@` in a run can serve as the anchor.
      //      N `@`s → N candidate anchor positions the engine tries in turn.
      //   2. `[^:]+` is greedy AND matches newlines (no `s` flag), so input that never
      //      contains `:` forces `[^:]+` to consume all remaining bytes then backtrack
      //      character-by-character searching for a terminal `:` that isn't there.
      //   3. The `m` flag makes `^` re-anchor at every line start — every failed match
      //      restart pays for the full O(N * text_length) probe from that anchor.
      //
      // Adversarial construction: one long line of `a@@@@@@...@@` followed by a newline.
      // No `:` anywhere, no leading `{`, no `lockfileVersion:` / `__metadata:` /
      // `# yarn lockfile v1` — so every earlier short-circuit in detectKind() misses and
      // the vulnerable regex is the one carrying the load.
      const width = Math.max(1, scale);
      const line = 'a' + '@'.repeat(width);
      return {
        text: `${line}\n`,
        // A filename with no recognized basename — detectKind() falls straight through
        // the filename branch into content-only detection, running our target regex.
        filename: 'lockfile.txt',
        format: 'yarn-classic',
      };
    },
  },
];
