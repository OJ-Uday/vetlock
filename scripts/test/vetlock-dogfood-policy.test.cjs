'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { evaluate, POLICY_VERSION } = require('../vetlock-dogfood-policy.cjs');

function analysis(findings = [], errors = []) {
  return { schemaVersion: 2, verdict: 'BLOCK', riskScore: 10, findings, errors };
}

function finding(packageName, detector, message, severity = 'BLOCK') {
  return { package: packageName, detector, message, severity, evidence: [] };
}

test('policy is versioned', () => {
  assert.match(POLICY_VERSION, /^\d+\.\d+\.\d+$/);
});

test('does not turn broad development-tooling findings into an automatic merge failure', () => {
  const result = evaluate(analysis([
    finding('tsup', 'env.token-harvest', 'Package started reading sensitive env: USER'),
    finding('tinyexec', 'install.script-added', 'Lifecycle script "prepare" was added.', 'INFO'),
    finding('tinyexec', 'env.token-harvest', 'Package started reading sensitive env: whole-object process.env enumeration'),
    finding('esbuild', 'bin.new-native-artifact', 'New native binary artifact shipped in tarball: esbuild.exe'),
  ]));
  assert.equal(result.ok, true);
  assert.deepEqual(result.violations, []);
});

test('fails an install-time named-token harvest with a new endpoint', () => {
  const result = evaluate(analysis([
    finding('evil-release', 'install.script-added', 'Lifecycle script "postinstall" was added.'),
    finding('evil-release', 'env.token-harvest', 'Package started reading sensitive env: NPM_TOKEN'),
    finding('evil-release', 'net.new-endpoint', 'New outbound endpoint: https://collector.invalid/v1'),
  ]));
  assert.equal(result.ok, false);
  assert.deepEqual(result.violations, [{
    kind: 'install-time-secret-exfiltration',
    package: 'evil-release',
    detail: 'automatic install hook, named credential access, and a new network endpoint',
  }]);
});

test('fails an install-time named-token harvest even before an endpoint is recognized', () => {
  const result = evaluate(analysis([
    finding('evil-release', 'install.script-changed', 'Lifecycle script "preinstall" body changed.'),
    finding('evil-release', 'env.token-harvest', 'Package started reading sensitive env: GITHUB_TOKEN'),
  ]));
  assert.equal(result.ok, false);
  assert.equal(result.violations[0].kind, 'install-time-secret-harvest');
});

test('fails closed when analysis reports errors or does not have the expected schema', () => {
  assert.equal(evaluate(analysis([], [{ message: 'tarball fetch failed' }])).ok, false);
  assert.equal(evaluate({ findings: [], errors: [] }).ok, false);
});
