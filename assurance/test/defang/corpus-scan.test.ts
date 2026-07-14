/**
 * The non-negotiable guard test (PACKET-VETLOCK-ASSURANCE rule #2).
 *
 * Scans every file under `assurance/corpus/` with a scannable extension and asserts every
 * file is defang-clean. When the corpus is empty (P0 → early P1) this passes trivially, but
 * the machinery is in place so that as generators land and produce committed fixtures, they
 * are checked from day one. A file that trips the guard fails the test with a report of
 * where and why.
 *
 * Scannable extensions: text-y formats we'd actually commit as fixtures. Binary tarballs are
 * NOT scanned by this test (they're built at run-time by generators; their construction
 * inputs are what we scan).
 */

import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanForDefangViolations } from '../../src/defang/index.js';

const CORPUS_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'corpus');

const SCANNABLE_EXTENSIONS = new Set([
  '.txt', '.md', '.json', '.js', '.mjs', '.cjs', '.ts',
  '.yaml', '.yml', '.lock', '.toml', '.ini', '.env',
  '.py', '.sh',
]);

/** Recursively walk a directory, yielding files that match the scannable extension list.
 *  Silently returns [] if the directory does not exist — early P1 has no corpus yet. */
function walkScannable(root: string): string[] {
  const out: string[] = [];
  let entries: string[];
  try {
    entries = readdirSync(root);
  } catch {
    return out;
  }
  for (const entry of entries) {
    const full = join(root, entry);
    let stat;
    try {
      stat = statSync(full);
    } catch {
      continue;
    }
    if (stat.isDirectory()) {
      // Skip node_modules and dot-dirs (build artifacts, git).
      if (entry === 'node_modules' || entry.startsWith('.')) continue;
      out.push(...walkScannable(full));
      continue;
    }
    if (!stat.isFile()) continue;
    const dotIdx = entry.lastIndexOf('.');
    if (dotIdx < 0) continue;
    const ext = entry.slice(dotIdx).toLowerCase();
    if (SCANNABLE_EXTENSIONS.has(ext)) out.push(full);
  }
  return out;
}

describe('assurance-defang-guard (packet rule #2, non-negotiable)', () => {
  it('every scannable file under assurance/corpus/ passes the defang guard', () => {
    const files = walkScannable(CORPUS_ROOT);
    const failures: {
      readonly file: string;
      readonly violations: readonly ReturnType<typeof scanForDefangViolations>['violations'][number][];
    }[] = [];
    for (const file of files) {
      const content = readFileSync(file, 'utf-8');
      const scan = scanForDefangViolations(content);
      if (!scan.clean) {
        failures.push({ file: relative(CORPUS_ROOT, file), violations: scan.violations });
      }
    }
    if (failures.length > 0) {
      // Emit a human-readable report so the failure message tells the fixture author exactly
      // what to change. This is the whole point of the guard.
      const report = failures
        .map(
          (f) =>
            `\n  ${f.file}:\n` +
            f.violations
              .map((v) => `    line ${v.line} [${v.category}] ${v.reason}`)
              .join('\n'),
        )
        .join('\n');
      throw new Error(`defang guard violations in ${failures.length} file(s):${report}`);
    }
    expect(failures).toEqual([]);
  });
});
