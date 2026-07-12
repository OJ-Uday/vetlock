/**
 * Auto-generate DETECTIONS.md from a live replay of every corpus fixture.
 *
 * Run with:  node packages/cli/dist/corpus/generate-detections.js
 *
 * The output is committed. Any drift between what the code actually does and
 * what DETECTIONS.md claims is caught by re-running this script.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runDiff, type Finding } from '@vetlock/core';
import { runAll } from '@vetlock/detectors';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');
const CORPUS_ROOT = path.join(REPO_ROOT, 'corpus');
const OUTPUT = path.join(REPO_ROOT, 'docs', 'DETECTIONS.md');

interface Manifest {
  id: string;
  title: string;
  year: number;
  threatClass: string;
  summary: string;
  provenance: 'PUBLISHED' | 'RECONSTRUCTED';
  topology: 'direct' | 'transitive';
  expect: {
    mustFire: string[];
    verdict: string;
    known_limitation?: string;
  };
}

async function main() {
  const dirs = fs
    .readdirSync(CORPUS_ROOT, { withFileTypes: true })
    .filter((d) => d.isDirectory() && !d.name.startsWith('_') && d.name !== 'fp-smoke')
    .map((d) => d.name)
    .sort();

  const entries: Array<{
    manifest: Manifest;
    result: {
      verdict: string;
      findings: Finding[];
      durationMs: number;
    };
  }> = [];

  for (const id of dirs) {
    const manifestPath = path.join(CORPUS_ROOT, id, 'manifest.json');
    if (!fs.existsSync(manifestPath)) continue;
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as Manifest;
    const before = fs.readFileSync(path.join(CORPUS_ROOT, id, 'lockfile.before.json'), 'utf8');
    const after = fs.readFileSync(path.join(CORPUS_ROOT, id, 'lockfile.after.json'), 'utf8');
    const fixtureDir = path.join(CORPUS_ROOT, id);
    const result = await runDiff(before, after, {
      runDetectors: (pair) => runAll(pair),
      fetchOverride: async (ref) => {
        if (!ref.resolved?.startsWith('file:')) {
          throw new Error(`should not need to fetch ${ref.name}@${ref.version}`);
        }
        // Corpus fixtures use RELATIVE resolved URLs (file:./...) so the corpus
        // is portable across machines; resolve them against the fixture dir.
        const raw = ref.resolved.slice('file:'.length);
        if (raw.startsWith('///')) return raw.slice(2);
        if (raw.startsWith('//')) return raw.slice(raw.indexOf('/', 2));
        if (raw.startsWith('/')) return raw;
        return path.resolve(fixtureDir, raw.replace(/^\.\//, ''));
      },
    });
    entries.push({ manifest, result });
  }

  const lines: string[] = [];
  lines.push('# DETECTIONS.md');
  lines.push('');
  lines.push('**Replay of historical npm supply-chain attacks through vetlock\'s behavioral differ.**');
  lines.push('');
  lines.push(
    'Every row in this document is reproducible from committed fixtures with `pnpm test` — no external network, no live registry. This file is **AUTO-GENERATED** by `packages/cli/src/corpus/generate-detections.ts`; edit that script, not this document.',
  );
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  const totalCatches = entries.filter((e) => e.result.verdict !== 'CLEAN').length;
  const honestMisses = entries.filter((e) => e.result.verdict === 'CLEAN').length;
  lines.push(
    `Out of **${entries.length}** corpus fixtures: **${totalCatches} caught** (verdict ≠ CLEAN), **${honestMisses} honest miss(es)** (published limitation).`,
  );
  lines.push('');

  // Catch/miss table
  lines.push('| Attack | Year | Threat | Verdict | Findings | Detectors |');
  lines.push('|---|---|---|---|---|---|');
  for (const { manifest, result } of entries) {
    const detectors = [...new Set(result.findings.map((f) => f.detector))].sort();
    const verdictBadge =
      result.verdict === 'BLOCK'
        ? '🚫 **BLOCK**'
        : result.verdict === 'WARN'
        ? '⚠️ WARN'
        : result.verdict === 'INFO'
        ? 'ℹ️ INFO'
        : '✅ CLEAN _(honest miss)_';
    lines.push(
      `| \`${manifest.id}\` | ${manifest.year} | ${manifest.threatClass} | ${verdictBadge} | ${result.findings.length} | ${detectors.map((d) => `\`${d}\``).join(', ') || '—'} |`,
    );
  }
  lines.push('');

  // Per-attack detail
  for (const { manifest, result } of entries) {
    lines.push(`## ${manifest.title}`);
    lines.push('');
    lines.push(`**Year:** ${manifest.year} · **Threat class:** ${manifest.threatClass} · **Topology:** ${manifest.topology} · **Provenance:** ${manifest.provenance}`);
    lines.push('');
    lines.push(manifest.summary);
    lines.push('');

    if (result.findings.length === 0) {
      lines.push(`vetlock output: **✅ CLEAN — honest miss.**`);
      lines.push('');
      if (manifest.expect.known_limitation) {
        lines.push(`> **Known limitation:** ${manifest.expect.known_limitation}`);
        lines.push('');
      }
      continue;
    }

    // Group by severity
    const grouped: Record<string, Finding[]> = { BLOCK: [], WARN: [], INFO: [] };
    for (const f of result.findings) grouped[f.severity]!.push(f);

    lines.push(`vetlock output: **${result.verdict}** — ${result.findings.length} finding${result.findings.length === 1 ? '' : 's'}, ${result.durationMs}ms.`);
    lines.push('');

    for (const sev of ['BLOCK', 'WARN', 'INFO'] as const) {
      if (grouped[sev].length === 0) continue;
      lines.push(`**${sev} (${grouped[sev].length})**`);
      for (const f of grouped[sev]) {
        const ev = f.evidence[0]!;
        lines.push(`- \`${f.detector}\` — ${f.message}`);
        lines.push(`  - _\`${ev.file}:${ev.line}\`_: \`${escapeMd(ev.snippet).slice(0, 160)}\``);
      }
      lines.push('');
    }

    if (manifest.expect.known_limitation) {
      lines.push(`> **Known limitation:** ${manifest.expect.known_limitation}`);
      lines.push('');
    }
  }

  lines.push('## Design invariants (each a named test)');
  lines.push('');
  lines.push('- **NEVER-EXECUTE canary** — the analyzer never runs any code from analyzed packages. Test: `packages/core/test/never-execute-canary.test.ts`.');
  lines.push('- **Closure completeness** — every changed node analyzed, no default depth limit. Test: `packages/core/test/engine.test.ts`.');
  lines.push('- **New-node full-scan** — added transitive node analyzed absolutely (event-stream 2018 case). Test: `packages/core/test/engine.test.ts`.');
  lines.push('- **Provenance correctness** — shortest paths root → node. Test: `packages/core/test/lockfile.test.ts`.');
  lines.push('- **Diff-framing** — capabilities in both versions never fire; only deltas escalate. Test: `packages/detectors/test/detectors.test.ts`.');
  lines.push('- **Determinism** — same inputs → byte-identical findings JSON. Test: `packages/core/test/engine.test.ts`.');
  lines.push('- **Integrity tripwire** — same version + different hash → BLOCK unconditionally. Test: `packages/core/test/engine.test.ts`.');
  lines.push('- **Fail-soft parse** — unparseable source → WARN, never crash. Test: `packages/core/test/capabilities.test.ts`.');
  lines.push('- **Safe extract** — zip-slip, symlinks, tarbombs rejected. Test: `packages/core/test/extract.test.ts`.');
  lines.push('- **Corpus defanged** — no fixture contains a live-exfil pattern. Test: `packages/cli/test/corpus-replay.test.ts`.');
  lines.push('');

  lines.push('## Reproducing');
  lines.push('');
  lines.push('```bash');
  lines.push('git clone https://github.com/OJ-Uday/vetlock.git');
  lines.push('cd vetlock');
  lines.push('pnpm install');
  lines.push('pnpm build');
  lines.push('pnpm test                                            # runs the whole matrix, ~96 tests');
  lines.push('node packages/cli/dist/corpus/build-all.js           # regenerates every attack fixture');
  lines.push('node packages/cli/dist/corpus/generate-detections.js # regenerates this document');
  lines.push('```');
  lines.push('');
  lines.push(`_Generated by \`packages/cli/src/corpus/generate-detections.ts\` — do not edit by hand._`);
  lines.push('');

  fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
  fs.writeFileSync(OUTPUT, lines.join('\n'));
  console.log(`wrote ${OUTPUT}`);
  console.log(`  ${entries.length} attacks documented; ${totalCatches} caught, ${honestMisses} honest miss(es)`);
}

function escapeMd(s: string): string {
  return s.replace(/`/g, '\\`');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
