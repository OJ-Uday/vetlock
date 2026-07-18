#!/usr/bin/env node
/*
 * Vetlock's self-dogfood gate is deliberately narrower than Vetlock's normal
 * verdict.  The normal verdict is an analyst signal: it must be conservative
 * and can therefore block a legitimate upgrade for review.  This policy is an
 * automated merge gate, so it only fails on a complete install-time credential
 * theft chain (or when the analysis itself cannot be trusted).
 *
 * Policy v1.0.0
 *   1. malformed/incomplete analysis or reported analysis errors: fail closed
 *   2. one package adds/changes preinstall, install, or postinstall AND reads a
 *      named credential secret: fail
 *   3. the same package also introducing a new endpoint is reported as the
 *      stronger collection-and-exfiltration chain
 *
 * Findings outside that chain are never suppressed: this script prints every
 * finding so that a human can still review Vetlock's full conservative result.
 */
'use strict';

const fs = require('node:fs');

const POLICY_VERSION = '1.0.0';
const AUTOMATIC_INSTALL_HOOK = /Lifecycle script\s+"(?:preinstall|install|postinstall)"\s+(?:was added|body changed)/i;
const SENSITIVE_SECRET = /\b(?:NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|AWS_SECRET(?:_ACCESS_KEY)?|AWS_ACCESS_KEY_ID|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS)\b/i;

function textOf(finding) {
  return [
    finding.message,
    ...(Array.isArray(finding.evidence)
      ? finding.evidence.flatMap((evidence) => [evidence?.snippet, evidence?.file])
      : []),
  ]
    .filter((value) => typeof value === 'string')
    .join('\n');
}

function isAutomaticInstallHook(finding) {
  return (
    (finding.detector === 'install.script-added' || finding.detector === 'install.script-changed') &&
    AUTOMATIC_INSTALL_HOOK.test(textOf(finding))
  );
}

function readsNamedSecret(finding) {
  return finding.detector === 'env.token-harvest' && SENSITIVE_SECRET.test(textOf(finding));
}

function addsEndpoint(finding) {
  return finding.detector === 'net.new-endpoint';
}

function validateAnalysis(analysis) {
  if (!analysis || typeof analysis !== 'object') return 'the JSON root is not an object';
  if (!Number.isInteger(analysis.schemaVersion)) return 'schemaVersion is missing';
  if (!Array.isArray(analysis.findings)) return 'findings is missing or not an array';
  if (!Array.isArray(analysis.errors)) return 'errors is missing or not an array';
  return null;
}

function evaluate(analysis) {
  const invalid = validateAnalysis(analysis);
  if (invalid) {
    return { ok: false, violations: [{ kind: 'analysis-invalid', detail: invalid }] };
  }

  const violations = [];
  if (analysis.errors.length > 0) {
    violations.push({
      kind: 'analysis-error',
      detail: `${analysis.errors.length} analyzer error(s) reported`,
    });
  }

  /** @type {Map<string, {hooks: object[], secrets: object[], endpoints: object[]}>} */
  const byPackage = new Map();
  for (const finding of analysis.findings) {
    if (!finding || typeof finding !== 'object' || typeof finding.package !== 'string') continue;
    if (!byPackage.has(finding.package)) {
      byPackage.set(finding.package, { hooks: [], secrets: [], endpoints: [] });
    }
    const signals = byPackage.get(finding.package);
    if (isAutomaticInstallHook(finding)) signals.hooks.push(finding);
    if (readsNamedSecret(finding)) signals.secrets.push(finding);
    if (addsEndpoint(finding)) signals.endpoints.push(finding);
  }

  for (const [packageName, signals] of byPackage) {
    if (signals.hooks.length === 0 || signals.secrets.length === 0) continue;
    violations.push({
      kind: signals.endpoints.length > 0 ? 'install-time-secret-exfiltration' : 'install-time-secret-harvest',
      package: packageName,
      detail: signals.endpoints.length > 0
        ? 'automatic install hook, named credential access, and a new network endpoint'
        : 'automatic install hook and named credential access',
    });
  }

  return { ok: violations.length === 0, violations };
}

function render(analysis, result) {
  const counts = new Map();
  for (const finding of Array.isArray(analysis?.findings) ? analysis.findings : []) {
    const severity = finding?.severity || 'UNKNOWN';
    counts.set(severity, (counts.get(severity) || 0) + 1);
  }
  const countText = [...counts.entries()].map(([severity, count]) => `${severity}=${count}`).join(', ') || 'none';
  const lines = [
    `Vetlock dogfood policy v${POLICY_VERSION}`,
    `Analysis: verdict=${analysis?.verdict || 'UNKNOWN'} risk=${analysis?.riskScore ?? 'UNKNOWN'} findings=${Array.isArray(analysis?.findings) ? analysis.findings.length : 'UNKNOWN'} (${countText}) errors=${Array.isArray(analysis?.errors) ? analysis.errors.length : 'UNKNOWN'}`,
    '',
    'All Vetlock findings (not suppressed by merge policy):',
  ];
  for (const finding of Array.isArray(analysis?.findings) ? analysis.findings : []) {
    lines.push(`- [${finding?.severity || 'UNKNOWN'}] ${finding?.package || '<unknown>'} / ${finding?.detector || '<unknown>'}: ${finding?.message || '<no message>'}`);
  }
  if (!Array.isArray(analysis?.findings) || analysis.findings.length === 0) lines.push('- none');

  lines.push('', result.ok ? 'Gate: PASS — no versioned high-confidence install-time credential-theft chain.' : 'Gate: FAIL — policy violation(s):');
  for (const violation of result.violations) {
    lines.push(`- ${violation.kind}${violation.package ? ` (${violation.package})` : ''}: ${violation.detail}`);
  }
  return lines.join('\n');
}

function main(argv) {
  const input = argv[2];
  if (!input) {
    console.error('Usage: node scripts/vetlock-dogfood-policy.cjs <vetlock-result.json>');
    return 64;
  }

  let analysis;
  try {
    analysis = JSON.parse(fs.readFileSync(input, 'utf8').replace(/^\uFEFF/, ''));
  } catch (error) {
    console.error(`Vetlock dogfood policy v${POLICY_VERSION}: unable to read analysis JSON: ${error.message}`);
    return 1;
  }

  const result = evaluate(analysis);
  console.log(render(analysis, result));
  return result.ok ? 0 : 1;
}

if (require.main === module) process.exitCode = main(process.argv);

module.exports = {
  POLICY_VERSION,
  evaluate,
  isAutomaticInstallHook,
  readsNamedSecret,
  render,
};
