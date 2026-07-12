#!/usr/bin/env node
/**
 * build-redteam-report.mjs — deterministic report builder from salvaged
 * red-team output. No AI section-writers; pure template. The one thing an
 * agent will still do is add the prose sections (exec summary, cross-cutting
 * themes, priority recommendations, methodology retrospective) via a small
 * final stitching call driven from claude-code, not from here.
 *
 * Inputs (all on disk):
 *   redteam-salvage/all-exploits.json          — 48 original findings
 *   redteam-salvage/bucket-{L,F,S,C,D,N}.json  — same, bucketed
 *   redteam-salvage/stage2/verifications.json  — 45 verifier verdicts
 *   redteam-salvage/stage2/merges-all.json     — merge decisions per agent
 *
 * Output:
 *   redteam-salvage/stage2/body.md             — templated per-exploit report body
 *   redteam-salvage/stage2/context.json        — compact summary for the stitcher
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

const SALVAGE = '/Users/L122472/personal/vetlock/docs/redteam-salvage';
const STAGE2 = `${SALVAGE}/stage2`;

const allExploits = JSON.parse(fs.readFileSync(`${SALVAGE}/all-exploits.json`, 'utf8'));
const exploitsById = new Map(allExploits.map(e => [e.id, e]));

const verifications = JSON.parse(fs.readFileSync(`${STAGE2}/verifications.json`, 'utf8'));
const verifById = new Map(verifications.map(v => [v.id, v]));

const mergesAll = JSON.parse(fs.readFileSync(`${STAGE2}/merges-all.json`, 'utf8'));
const allDropIds = new Set(mergesAll.flatMap(m => m.merges || []).flatMap(m => m.drop_ids || []));
const allMergeDecisions = mergesAll.flatMap(m => m.merges || []);

// Priority order for output
const priorityOrder = { confirmed: 0, plausible: 1, partial: 2, refuted: 3 };

// Filter: only entries that survived dedup AND have a verification
const survivors = [];
for (const [id, exp] of exploitsById) {
  if (allDropIds.has(id)) continue;
  const verif = verifById.get(id);
  if (!verif) continue; // no verifier ran on this one
  survivors.push({ exploit: exp, verification: verif });
}

survivors.sort((a, b) => {
  const av = priorityOrder[a.verification.verdict] ?? 4;
  const bv = priorityOrder[b.verification.verdict] ?? 4;
  if (av !== bv) return av - bv;
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const asev = sevOrder[a.exploit.severity_if_confirmed] ?? 4;
  const bsev = sevOrder[b.exploit.severity_if_confirmed] ?? 4;
  if (asev !== bsev) return asev - bsev;
  return a.exploit.id.localeCompare(b.exploit.id);
});

const byVerdict = { confirmed: [], plausible: [], partial: [], refuted: [] };
for (const s of survivors) {
  const v = s.verification.verdict;
  if (byVerdict[v]) byVerdict[v].push(s);
}

const stats = {
  totalProposed: allExploits.length,
  dropped: allDropIds.size,
  verified: survivors.length,
  confirmed: byVerdict.confirmed.length,
  plausible: byVerdict.plausible.length,
  partial: byVerdict.partial.length,
  refuted: byVerdict.refuted.length,
};

// ---- render one exploit as a Markdown block ----
const VERDICT_EMOJI = {
  confirmed: '🚫',
  plausible: '⚠️',
  partial: '🟡',
  refuted: '✅',
};

function md(entry) {
  const e = entry.exploit;
  const v = entry.verification;
  const emoji = VERDICT_EMOJI[v.verdict] ?? '❓';
  const parts = [];
  parts.push(`### ${e.id} — ${e.title}`);
  parts.push('');
  parts.push(`${emoji} **${v.verdict.toUpperCase()}** · **severity: ${e.severity_if_confirmed}** · confidence: ${e.confidence ?? 'unspecified'} · attacker effort: ${e.attacker_effort ?? 'unspecified'} · fix effort: ${e.fix_effort ?? 'unspecified'}`);
  parts.push('');
  if (e.class) parts.push(`**Class:** ${e.class}`);
  parts.push('');
  parts.push(`**Description.** ${e.description ?? '(no description)'}`);
  parts.push('');
  if (e.fixture_code && e.fixture_code.length > 0) {
    parts.push(`**Fixture:**`);
    parts.push('');
    parts.push('```js');
    parts.push(e.fixture_code);
    parts.push('```');
    parts.push('');
  }
  if (e.detectors_bypassed && e.detectors_bypassed.length > 0) {
    parts.push(`**Detectors bypassed:** \`${e.detectors_bypassed.join('`, `')}\``);
    parts.push('');
  }
  parts.push(`**Verifier's finding (${v.verdict}).** ${v.reasoning}`);
  parts.push('');
  if (v.concrete_test) {
    parts.push(`**Concrete test:** ${v.concrete_test}`);
    parts.push('');
  }
  if (v.refutation && v.verdict !== 'confirmed') {
    parts.push(`**Refutation:** ${v.refutation}`);
    parts.push('');
  }
  if (e.suggested_fix) {
    parts.push(`**Suggested fix.** ${e.suggested_fix}`);
    parts.push('');
  }
  parts.push('---');
  parts.push('');
  return parts.join('\n');
}

// ---- Build the body ----
const body = [];

body.push('## Confirmed exploits\n');
if (byVerdict.confirmed.length === 0) body.push('_(none — surprising given the number of proposals)_\n');
for (const entry of byVerdict.confirmed) body.push(md(entry));

body.push('\n## Plausible exploits (needing manual verification)\n');
if (byVerdict.plausible.length === 0) body.push('_(none)_\n');
for (const entry of byVerdict.plausible) body.push(md(entry));

body.push('\n## Partial successes (less severe than claimed, still worth fixing)\n');
if (byVerdict.partial.length === 0) body.push('_(none)_\n');
for (const entry of byVerdict.partial) body.push(md(entry));

// Refuted — compact table only
body.push('\n## Refuted (compact table)\n');
if (byVerdict.refuted.length === 0) {
  body.push('_(none — the adversarial verifier confirmed almost everything)_\n');
} else {
  body.push('| ID | Title | Refutation |');
  body.push('|---|---|---|');
  for (const entry of byVerdict.refuted) {
    const e = entry.exploit;
    const v = entry.verification;
    const reason = (v.refutation || v.reasoning || '').replace(/\|/g, '\\|').replace(/\n/g, ' ').slice(0, 240);
    body.push(`| ${e.id} | ${e.title} | ${reason} |`);
  }
  body.push('');
}

// Merge audit trail
if (allMergeDecisions.length > 0) {
  body.push('\n## Dedup audit trail\n');
  body.push('_These merge decisions were made programmatically during consolidation._\n');
  body.push('| Kept ID | Dropped IDs | Rationale |');
  body.push('|---|---|---|');
  for (const m of allMergeDecisions) {
    const drops = (m.drop_ids || []).join(', ');
    const rat = (m.rationale || '').replace(/\|/g, '\\|').replace(/\n/g, ' ').slice(0, 200);
    body.push(`| ${m.keep_id} | ${drops} | ${rat} |`);
  }
  body.push('');
}

fs.writeFileSync(`${STAGE2}/body.md`, body.join('\n'));

// ---- Build compact context for the stitcher ----
const context = {
  stats,
  verdictCounts: {
    confirmed: byVerdict.confirmed.length,
    plausible: byVerdict.plausible.length,
    partial: byVerdict.partial.length,
    refuted: byVerdict.refuted.length,
  },
  // Compact per-exploit summary — id + title + verdict + severity + one-line reasoning
  summaryTable: survivors.map(s => ({
    id: s.exploit.id,
    title: s.exploit.title,
    severity: s.exploit.severity_if_confirmed,
    verdict: s.verification.verdict,
    class: s.exploit.class,
    detectors_bypassed_count: (s.exploit.detectors_bypassed || []).length,
    reasoning_summary: (s.verification.reasoning || '').slice(0, 200),
  })),
  confirmedTitles: byVerdict.confirmed.map(s => ({
    id: s.exploit.id,
    title: s.exploit.title,
    severity: s.exploit.severity_if_confirmed,
    class: s.exploit.class,
  })),
  bodyLen: body.join('\n').length,
};

fs.writeFileSync(`${STAGE2}/context.json`, JSON.stringify(context, null, 2));

console.log('=== Report body built ===');
console.log(`Body: ${body.join('\n').length} bytes → ${STAGE2}/body.md`);
console.log(`Context: ${JSON.stringify(context).length} bytes → ${STAGE2}/context.json`);
console.log('');
console.log('Stats:');
console.log(JSON.stringify(stats, null, 2));
