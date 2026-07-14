#!/usr/bin/env node
/**
 * generate-capability-map-doc.js — regenerate docs/CAPABILITY-MAP.md from
 * packages/detectors/src/capability-map.json. Ships as an npm script:
 *
 *   pnpm corpus:capmap
 *
 * A separate test (capability-map-generated.test.ts) verifies the committed
 * doc is byte-identical to a fresh regeneration — commits that touch the
 * JSON source without regenerating the doc will fail CI.
 */

'use strict';

const { readFileSync, writeFileSync } = require('node:fs');
const path = require('node:path');

const HERE = __dirname;
const REPO_ROOT = path.resolve(HERE, '..', '..', '..', '..');
const SRC = path.join(REPO_ROOT, 'packages', 'detectors', 'src', 'capability-map.json');
const OUT = path.join(REPO_ROOT, 'docs', 'CAPABILITY-MAP.md');

const map = JSON.parse(readFileSync(SRC, 'utf8'));

const byClass = new Map();
for (const e of map.entries) {
  if (!byClass.has(e.class)) byClass.set(e.class, []);
  byClass.get(e.class).push(e);
}

const lines = [];
lines.push('# CAPABILITY-MAP');
lines.push('');
lines.push(`**Version:** ${map.version} · **Source of truth:** \`packages/detectors/src/capability-map.json\` · **This doc is auto-generated** — do not edit by hand; run \`pnpm corpus:capmap\` after editing the JSON.`);
lines.push('');
lines.push('> The machine-readable enumeration of every capability *class* vetlock claims to cover, plus each class\'s sinks (runtime primitives) and entry-points (attack surfaces). ADR 0011 (completeness doctrine) is the governing law. Coverage is CI-enforced: any entry with a missing detector, missing test, or missing corpus ref (unless flagged `soft_warn_no_corpus`) fails `capability-map-coverage.test`.');
lines.push('');

// Summary table
lines.push('## Summary');
lines.push('');
const softWarn = map.entries.filter((e) => e.soft_warn_no_corpus).length;
const withCorpus = map.entries.filter((e) => e.corpus_refs.length > 0).length;
lines.push(`- **Total enumerated primitives:** ${map.entries.length}`);
lines.push(`- **With corpus fixture(s):** ${withCorpus} (${Math.round((withCorpus / map.entries.length) * 100)}%)`);
lines.push(`- **Soft-warn (no corpus yet):** ${softWarn}`);
lines.push('');
lines.push('| Class | Sink count | Entry-point count | Total |');
lines.push('|---|---:|---:|---:|');
for (const [cls, entries] of [...byClass.entries()].sort()) {
  const sinks = entries.filter((e) => e.kind === 'sink').length;
  const eps = entries.filter((e) => e.kind === 'entry-point').length;
  lines.push(`| \`${cls}\` | ${sinks} | ${eps} | ${entries.length} |`);
}
lines.push('');

// Per-class detail
for (const [cls, entries] of [...byClass.entries()].sort()) {
  lines.push(`## \`${cls}\``);
  lines.push('');
  lines.push('| ID | Kind | Detector(s) | Corpus | Chokepoint |');
  lines.push('|---|---|---|---|---|');
  for (const e of entries.sort((a, b) => a.id.localeCompare(b.id))) {
    const corpus = e.corpus_refs.length > 0
      ? e.corpus_refs.map((r) => `\`${r}\``).join(', ')
      : (e.soft_warn_no_corpus ? '_(soft-warn)_' : '**none**');
    const detectors = e.detectors.map((d) => `\`${d}\``).join(', ');
    const chokepoint = e.chokepoint ? `\`${e.chokepoint}\`` : '—';
    lines.push(`| \`${e.id}\` | ${e.kind} | ${detectors} | ${corpus} | ${chokepoint} |`);
  }
  lines.push('');
  // Notes for entries with them
  const withNotes = entries.filter((e) => e.notes);
  if (withNotes.length > 0) {
    lines.push('**Notes:**');
    for (const e of withNotes.sort((a, b) => a.id.localeCompare(b.id))) {
      lines.push(`- \`${e.id}\`: ${e.notes}`);
    }
    lines.push('');
  }
}

lines.push('---');
lines.push('');
lines.push('## How to extend this map');
lines.push('');
lines.push('1. Identify the capability CLASS the new attack shape belongs to (or propose a new class if truly novel — see ADR 0011).');
lines.push('2. Add an entry to `packages/detectors/src/capability-map.json` with:');
lines.push('   - `class`, `kind`, `id` (stable identifier)');
lines.push('   - `aliases[]` (syntactic variations)');
lines.push('   - `detectors[]` (detector IDs that fire on this)');
lines.push('   - `tests[]` (test file paths with regression coverage)');
lines.push('   - `corpus_refs[]` (`corpus/<id>` names) OR `soft_warn_no_corpus: true`');
lines.push('   - Optional: `chokepoint` (single dataflow convergence that catches novel syntax for free)');
lines.push('3. Run `pnpm corpus:capmap` to regenerate this doc.');
lines.push('4. Run `pnpm test` — the coverage gate will pass or point at the specific gap.');
lines.push('');
lines.push('_Adding a signature without touching the map is now a review-visible mistake._');
lines.push('');

writeFileSync(OUT, lines.join('\n'));
console.log(`wrote ${path.relative(REPO_ROOT, OUT)} (${map.entries.length} entries across ${byClass.size} classes)`);
