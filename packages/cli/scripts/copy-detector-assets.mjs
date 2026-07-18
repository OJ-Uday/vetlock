#!/usr/bin/env node
/**
 * Copy detector JSON assets next to the bundled CLI entrypoints. Bundling
 * collapses @vetlock/detectors into dist/cli.js, so its import.meta.url-based
 * loaders resolve their production assets from packages/cli/dist/.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI_PKG = path.resolve(HERE, '..');
const REPO_ROOT = path.resolve(CLI_PKG, '..', '..');
const DETECTOR_SRC = path.join(REPO_ROOT, 'packages', 'detectors', 'src');
const CLI_DIST = path.join(CLI_PKG, 'dist');

const assets = [
  ['capability-map.json', 'capability-map.json'],
  [path.join('data', 'disposable-domains.json'), 'disposable-domains.json'],
  [path.join('data', 'top-1000-npm.json'), 'top-1000-npm.json'],
];

fs.mkdirSync(CLI_DIST, { recursive: true });
for (const [sourceRelative, destinationName] of assets) {
  const source = path.join(DETECTOR_SRC, sourceRelative);
  const destination = path.join(CLI_DIST, destinationName);
  if (!fs.existsSync(source)) {
    console.error(`copy-detector-assets: source not found: ${source}`);
    process.exit(1);
  }
  fs.copyFileSync(source, destination);
  console.log(`copy-detector-assets: ${sourceRelative} -> dist/${destinationName}`);
}
