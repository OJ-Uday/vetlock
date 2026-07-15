/**
 * TTY renderer — pretty terminal output, grouped by severity, with provenance
 * chains rendered as `a → b → c`.
 */

import pc from 'picocolors';
import type { Finding, Severity, RunResult } from '@vetlock/core';

const SEVERITY_LABEL: Record<Severity | 'CLEAN', string> = {
  BLOCK: pc.red(pc.bold('BLOCK')),
  WARN: pc.yellow(pc.bold('WARN')),
  INFO: pc.cyan('INFO'),
  CLEAN: pc.green('CLEAN'),
};

export function renderTTY(result: RunResult, opts: { showClean?: boolean } = {}): string {
  const lines: string[] = [];

  // Header
  lines.push('');
  lines.push(pc.bold('vetlock diff summary'));
  lines.push(
    `  ${SEVERITY_LABEL[result.verdict]} · ${result.findings.length} finding${
      result.findings.length === 1 ? '' : 's'
    } · ${result.changes.length} changed package${result.changes.length === 1 ? '' : 's'} · ${result.durationMs}ms`,
  );
  lines.push('');

  if (result.findings.length === 0) {
    if (opts.showClean || result.changes.length === 0) {
      lines.push(pc.green('  No behavioral changes detected in this update.'));
    } else {
      lines.push(pc.green('  All changes are non-behavioral.'));
    }
    return lines.join('\n');
  }

  // Group findings by severity, then by package.
  const groups: Record<Severity, Finding[]> = { BLOCK: [], WARN: [], INFO: [] };
  for (const f of result.findings) groups[f.severity].push(f);

  for (const sev of ['BLOCK', 'WARN', 'INFO'] as const) {
    const findings = groups[sev];
    if (findings.length === 0) continue;
    lines.push('');
    lines.push(`${SEVERITY_LABEL[sev]}  ${findings.length}`);
    // Sub-group by package
    const byPkg = new Map<string, Finding[]>();
    for (const f of findings) {
      (byPkg.get(f.package) ?? byPkg.set(f.package, []).get(f.package)!).push(f);
    }
    for (const [pkg, fs] of byPkg) {
      const first = fs[0]!;
      const versionLabel =
        first.from && first.to
          ? `${first.from} → ${first.to}`
          : first.to ?? first.from ?? '';
      lines.push(`  ${pc.bold(pkg)} ${pc.dim(versionLabel)}`);
      if (first.provenance.length > 0) {
        for (const path of first.provenance.slice(0, 3)) {
          lines.push(`    ${pc.dim('via:')} ${path.join(' → ')}`);
        }
        if (first.provenance.length > 3) {
          const remaining = first.provenance.length - 3;
          lines.push(`    ${pc.dim(`… +${remaining} more ${remaining === 1 ? 'path' : 'paths'}`)}`);
        }
      }
      for (const f of fs) {
        lines.push(`    · ${pc.bold(f.detector)} — ${f.message}`);
        for (const ev of f.evidence.slice(0, 2)) {
          lines.push(
            `      ${pc.dim(`${ev.file}:${ev.line}`)}  ${pc.italic(ev.snippet)}`,
          );
        }
        if (f.evidence.length > 2) {
          lines.push(`      ${pc.dim(`… +${f.evidence.length - 2} more evidence`)}`);
        }
      }
    }
  }

  // Direct-dep rollup
  const direct = Object.entries(result.rollupByDirect).filter(
    ([, r]) => r.maxSeverity !== 'CLEAN',
  );
  if (direct.length > 0) {
    lines.push('');
    lines.push(pc.dim('Impact by direct dependency:'));
    for (const [name, r] of direct.sort(([a], [b]) => a.localeCompare(b))) {
      lines.push(
        `  ${name}: ${SEVERITY_LABEL[r.maxSeverity]} (${r.count} finding${
          r.count === 1 ? '' : 's'
        } in subtree)`,
      );
    }
  }

  if (result.errors.length > 0) {
    lines.push('');
    lines.push(pc.dim(`(${result.errors.length} package(s) failed to analyze — see --json for details)`));
  }

  lines.push('');
  return lines.join('\n');
}
