#!/usr/bin/env node
/**
 * Copy @vetlock/detectors' capability-map.json next to the bundled
 * dist/cli.js so getCapabilityMap()'s runtime file lookup (which searches
 * next to its own compiled module) finds it after bundling collapses
 * @vetlock/detectors' source into a single dist/cli.js.
 *
 * Source: packages/detectors/src/capability-map.json
 * Dest:   packages/cli/dist/capability-map.json
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI_PKG = path.resolve(HERE, '..');
const REPO_ROOT = path.resolve(CLI_PKG, '..', '..');
const SRC = path.join(REPO_ROOT, 'packages', 'detectors', 'src', 'capability-map.json');
const DEST = path.join(CLI_PKG, 'dist', 'capability-map.json');

if (!fs.existsSync(SRC)) {
  console.error(`copy-capability-map: source not found: ${SRC}`);
  process.exit(1);
}

fs.copyFileSync(SRC, DEST);
console.log(`copy-capability-map: capability-map.json → dist/capability-map.json`);
