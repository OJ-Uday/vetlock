/**
 * TYPO detector — new direct or transitive dep whose name is a very-near
 * typosquat of a popular npm package.
 *
 * WARN by default; BLOCK when the added package also has BLOCK-tier
 * capabilities in the same snapshot (the classic typosquat-with-payload
 * signature). Escalation is applied by the runAll() layer.
 *
 * Implementation: we ship a small curated hot-list of ~200 top-download
 * packages (see TOP_NPM_NAMES) and compute Damerau-Levenshtein distance
 * against it for every ADDED package. A dep whose name is 1-2 edits away
 * from a top package is a typosquat candidate.
 */

import type { Detector, Finding, SnapshotPair } from '@vetlock/core';

// Curated slice of npm's top-1000 by download count (2025). Kept small to
// avoid ballooning the artifact; extend from an external list in a P0.2 pass.
const TOP_NPM_NAMES: readonly string[] = [
  'react', 'react-dom', 'lodash', 'axios', 'express', 'chalk', 'debug', 'commander',
  'cross-env', 'dotenv', 'ejs', 'eslint', 'esbuild', 'fs-extra', 'glob',
  'handlebars', 'http-proxy', 'inquirer', 'jest', 'js-yaml', 'jsdom', 'jsonwebtoken',
  'jquery', 'moment', 'mocha', 'mongoose', 'next', 'node-fetch', 'nodemon', 'ora',
  'passport', 'pg', 'prettier', 'querystring', 'react-native', 'react-router',
  'react-router-dom', 'redux', 'request', 'rimraf', 'sass', 'semver', 'sequelize',
  'sharp', 'shelljs', 'sinon', 'socket.io', 'styled-components', 'superagent',
  'ts-node', 'typescript', 'uuid', 'vite', 'vue', 'webpack', 'winston', 'ws',
  'yargs', 'zod', '@babel/core', '@types/node', 'ansi-styles', 'strip-ansi',
];

/** Damerau-Levenshtein distance (edit distance with adjacent transposition). */
function damerauLevenshtein(a: string, b: string): number {
  const la = a.length, lb = b.length;
  if (la === 0) return lb;
  if (lb === 0) return la;
  const dp: number[][] = Array.from({ length: la + 1 }, () => new Array(lb + 1).fill(0));
  for (let i = 0; i <= la; i++) dp[i]![0] = i;
  for (let j = 0; j <= lb; j++) dp[0]![j] = j;
  for (let i = 1; i <= la; i++) {
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i]![j] = Math.min(
        dp[i - 1]![j]! + 1,       // deletion
        dp[i]![j - 1]! + 1,       // insertion
        dp[i - 1]![j - 1]! + cost, // substitution
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        dp[i]![j] = Math.min(dp[i]![j]!, dp[i - 2]![j - 2]! + cost);
      }
    }
  }
  return dp[la]![lb]!;
}

/** Return the closest top-name (if within max-distance) and its distance. */
function closestTop(name: string, maxDist = 2): { target: string; distance: number } | null {
  if (TOP_NPM_NAMES.includes(name)) return null; // it IS a top package, not a typo of one
  let best: { target: string; distance: number } | null = null;
  for (const top of TOP_NPM_NAMES) {
    // Skip pairs where the length difference alone exceeds maxDist
    if (Math.abs(top.length - name.length) > maxDist) continue;
    const d = damerauLevenshtein(name, top);
    if (d <= maxDist && (!best || d < best.distance)) {
      best = { target: top, distance: d };
    }
  }
  return best;
}

export const typosquatDetector: Detector = {
  id: 'typo',
  category: 'DEPS',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    // Only fires on ADDED packages (pair.old === null).
    if (pair.old) return [];
    const near = closestTop(pair.new.name);
    if (!near) return [];
    return [
      {
        detector: 'deps.typosquat-candidate',
        category: 'DEPS',
        package: pair.new.name,
        from: null,
        to: pair.new.version,
        direction: 'added',
        severity: 'WARN', // escalated to BLOCK in runAll if package also has BLOCK-tier capability
        confidence: near.distance === 1 ? 'high' : 'medium',
        message: `Package name "${pair.new.name}" is edit-distance ${near.distance} from popular package "${near.target}". Typosquat candidate.`,
        evidence: [
          {
            file: 'package.json',
            line: 1,
            snippet: `"${pair.new.name}" (distance ${near.distance} from "${near.target}")`,
          },
        ],
        provenance: [],
      },
    ];
  },
};

// Exposed for tests
export { damerauLevenshtein, closestTop, TOP_NPM_NAMES };
