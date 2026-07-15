/**
 * REDTEAM S2/C1/C2/D1 FIX: config-trust boundary.
 *
 * The root cause of the S2/C1/C2/D1 exploit family is that the CLI reads
 * `.vetlock.json` from the current working directory — which in a PR-review
 * scenario is the checkout of the PR being reviewed.  An attacker can include
 * both a poisoned lockfile AND a config that silences every finding against
 * that lockfile.
 *
 * Fix: before applying a config, detect whether the config file itself
 * appeared in the changeset (i.e. its text differs from the HEAD~1 version).
 * If so, emit a BLOCK-tier synthetic finding and refuse to apply the config
 * (unless the operator explicitly opts in with --config-allow-in-diff).
 *
 * Public surface:
 *   decideConfigApplication()  — pure function; unit-testable without spawning
 *                                a process.  The CLI calls this and the tests
 *                                drive it directly.
 *
 * @security-critical
 */

import * as crypto from 'node:crypto';
import type { Finding } from './finding.js';
import type { VetlockConfig } from './config.js';
import { DEFAULT_CONFIG } from './config.js';

/** Result of loading the config text from disk (before parsing). */
export interface ConfigLoadContext {
  /** The raw JSON text of the current (working-tree) config.  null = file absent. */
  currentText: string | null;
  /** The raw JSON text of the baseline config (e.g. HEAD~1).  null = absent. */
  baselineText: string | null;
}

/** What decideConfigApplication returns. */
export interface ConfigDecision {
  /** The config to actually pass to applyConfig.  DEFAULT_CONFIG when blocked. */
  config: VetlockConfig;
  /** True when the config file is in the diff (current differs from baseline). */
  inDiff: boolean;
  /** 'baseline' — config was loaded and is safe;
   *  'in-diff'  — config is in the diff;
   *  'default'  — no config file present. */
  source: 'baseline' | 'in-diff' | 'default';
  /**
   * Synthetic findings produced by this decision.
   * Non-empty only when inDiff === true.
   */
  findings: Finding[];
  /** When true the caller should NOT apply the returned config to findings. */
  blocked: boolean;
}

/** SHA-256 hex of a string, or null if the input is null. */
export function hashConfigText(text: string | null): string | null {
  if (text === null) return null;
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

/**
 * Decide whether a loaded config can be trusted and applied.
 *
 * @param parsed     The parsed VetlockConfig (or null if no file was found).
 * @param ctx        The raw text of the current and baseline config.
 * @param strict     When true (the default), an in-diff config causes a BLOCK
 *                   synthetic finding and the DEFAULT_CONFIG is returned.
 *                   When false, a WARN synthetic finding is emitted but the
 *                   config is still applied (--config-allow-in-diff behaviour).
 *
 * Logic:
 *   - If currentText === null → source = 'default', inDiff = false.
 *   - Else if baselineText === null (config is newly added in this PR)
 *     OR sha256(currentText) !== sha256(baselineText) → inDiff = true.
 *   - Otherwise → source = 'baseline', inDiff = false.
 */
export function decideConfigApplication(
  parsed: VetlockConfig | null,
  ctx: ConfigLoadContext,
  strict: boolean = true,
): ConfigDecision {
  if (ctx.currentText === null) {
    // No config file at all — use defaults, nothing to decide.
    return {
      config: DEFAULT_CONFIG,
      inDiff: false,
      source: 'default',
      findings: [],
      blocked: false,
    };
  }

  const currentHash = hashConfigText(ctx.currentText);
  const baselineHash = hashConfigText(ctx.baselineText);
  const inDiff = baselineHash === null || currentHash !== baselineHash;

  if (!inDiff) {
    return {
      config: parsed ?? DEFAULT_CONFIG,
      inDiff: false,
      source: 'baseline',
      findings: [],
      blocked: false,
    };
  }

  // Config IS in the diff.
  const syntheticFinding: Finding = {
    detector: 'config.in-diff-untrusted',
    category: 'META',
    package: '<config>',
    from: ctx.baselineText === null ? null : 'baseline',
    to: 'changed',
    direction: ctx.baselineText === null ? 'added' : 'changed',
    severity: strict ? 'BLOCK' : 'WARN',
    confidence: 'high',
    message: strict
      ? '.vetlock.json is part of this diff — it cannot be trusted to filter findings from the same PR. ' +
        'Use --config-allow-in-diff to accept this risk explicitly.'
      : '.vetlock.json was accepted despite being modified in this diff (--config-allow-in-diff active). ' +
        'Review the config changes carefully.',
    evidence: [
      {
        file: '.vetlock.json',
        line: 1,
        snippet: ctx.baselineText === null
          ? '(file not present in baseline — added in this PR)'
          : '(file differs from baseline)',
      },
    ],
    provenance: [],
    // T1195.002 Compromise Software Supply Chain — the config-in-diff
    // shape is an attacker filtering out their own findings from the
    // scanner. Same supply-chain umbrella as the malicious package.
    mitre: ['T1195.002'],
  };

  if (strict) {
    return {
      config: DEFAULT_CONFIG,
      inDiff: true,
      source: 'in-diff',
      findings: [syntheticFinding],
      blocked: true,
    };
  }

  // Opt-in mode: apply the config but annotate.
  return {
    config: parsed ?? DEFAULT_CONFIG,
    inDiff: true,
    source: 'in-diff',
    findings: [syntheticFinding],
    blocked: false,
  };
}
