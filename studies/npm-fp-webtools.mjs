import { promises as fs } from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import tar from '/Users/L122472/telemeteryXsage/copilot-worktrees/vetlock/oj-uday-improved-barnacle/node_modules/.pnpm/tar@6.2.1/node_modules/tar/index.js';
import {
  runDiff,
  VETLOCK_VERSION,
} from '/Users/L122472/telemeteryXsage/copilot-worktrees/vetlock/oj-uday-improved-barnacle/packages/core/dist/index.js';
import { runAll } from '/Users/L122472/telemeteryXsage/copilot-worktrees/vetlock/oj-uday-improved-barnacle/packages/detectors/dist/index.js';

const ROOT = '/Users/L122472/telemeteryXsage/copilot-worktrees/vetlock/oj-uday-improved-barnacle';
const OUTPUT_PATH = path.join(ROOT, 'studies', 'npm-fp-batch-webtools.json');
const WORK_ROOT = path.join(ROOT, 'studies', '.npm-fp-webtools-work');
const OLD_VERSION = '1.0.0';
const NEW_VERSION = '2.0.0';

const PACKAGE_NAMES = [
  'express',
  'fastify',
  'koa',
  'hapi',
  'commander',
  'yargs',
  'minimist',
  'eslint',
  'mocha',
  'jest',
  'dotenv',
  'glob',
  'minimatch',
  'uuid',
  'sharp',
];

const PACKAGE_GROUPS = {
  express: 'prepare-script-change',
  fastify: 'prepare-script-change',
  koa: 'prepare-script-change',
  hapi: 'prepare-script-change',
  commander: 'prepare-script-change',
  yargs: 'prepare-script-change',
  minimist: 'prepare-script-change',
  eslint: 'static-local-require',
  mocha: 'prepare-script-change',
  jest: 'prepare-script-change',
  dotenv: 'existing-fs-read',
  glob: 'utility-clean',
  minimatch: 'utility-clean',
  uuid: 'uuid-prepare-script',
  sharp: 'native-binary-recompiled',
};

async function main() {
  await fs.rm(WORK_ROOT, { recursive: true, force: true });
  await fs.mkdir(WORK_ROOT, { recursive: true });
  try {
    const results = [];
    for (const packageName of PACKAGE_NAMES) {
      const bumpCase = await analyzeCase(packageName, 'bump', buildBumpScenario(packageName));
      const prepareCase = await analyzeCase(packageName, 'prepare-added', buildPrepareScenario(packageName));
      results.push({
        package: packageName,
        group: PACKAGE_GROUPS[packageName],
        scenarios: [bumpCase, prepareCase],
      });
    }

    const flatCases = results.flatMap((entry) => entry.scenarios);
    const report = {
      batch: 'WEB TOOLS',
      description: 'npm false-positive study for web tools that warned in the real v0.5.0 run plus related packages',
      version: '1',
      ecosystem: 'npm',
      vetlockVersion: VETLOCK_VERSION,
      ranAt: new Date().toISOString(),
      totalPackages: results.length,
      totalCases: flatCases.length,
      scenarioKinds: ['bump', 'prepare-added'],
      summary: summarizeCases(flatCases),
      scenarioSummary: {
        bump: summarizeCases(flatCases.filter((entry) => entry.scenario === 'bump')),
        'prepare-added': summarizeCases(flatCases.filter((entry) => entry.scenario === 'prepare-added')),
      },
      results,
    };

    await fs.writeFile(OUTPUT_PATH, JSON.stringify(report, null, 2));
  } finally {
    await fs.rm(WORK_ROOT, { recursive: true, force: true });
  }
}

function summarizeCases(cases) {
  const summary = {
    totalCases: cases.length,
    BLOCK: 0,
    WARN: 0,
    INFO: 0,
    CLEAN: 0,
    ERROR: 0,
    detectorHits: {},
    expectedMatches: 0,
    expectedMismatches: 0,
    documentedFalsePositives: 0,
    documentedTrueWarns: 0,
  };
  for (const entry of cases) {
    summary[entry.verdict] += 1;
    if (entry.matchesExpectation) summary.expectedMatches += 1;
    else summary.expectedMismatches += 1;
    if (entry.falsePositive) summary.documentedFalsePositives += 1;
    if (entry.trueWarn) summary.documentedTrueWarns += 1;
    for (const finding of entry.findings) {
      summary.detectorHits[finding.detector] = (summary.detectorHits[finding.detector] ?? 0) + 1;
    }
  }
  return summary;
}

async function analyzeCase(packageName, scenarioName, scenario) {
  const caseDir = path.join(WORK_ROOT, `${sanitize(packageName)}-${scenarioName}`);
  await fs.mkdir(caseDir, { recursive: true });

  const oldTarball = await makeTarball(path.join(caseDir, 'before'), {
    'package.json': JSON.stringify(scenario.oldManifest, null, 2),
    ...scenario.oldFiles,
  });
  const newTarball = await makeTarball(path.join(caseDir, 'after'), {
    'package.json': JSON.stringify(scenario.newManifest, null, 2),
    ...scenario.newFiles,
  });

  const beforeLock = makeLockfile(packageName, OLD_VERSION, oldTarball.integrity, oldTarball.path);
  const afterLock = makeLockfile(packageName, NEW_VERSION, newTarball.integrity, newTarball.path);
  const fetchOverride = async (ref) => {
    if (ref.resolved?.startsWith('file://')) {
      return new URL(ref.resolved).pathname;
    }
    throw new Error(`Expected file:// resolved tarball for ${ref.name}@${ref.version}`);
  };

  const diff = await runDiff(beforeLock, afterLock, {
    runDetectors: (pair) => runAll(pair),
    fetchOverride,
    concurrency: 2,
    timeoutMs: 120_000,
  });

  return {
    package: packageName,
    scenario: scenarioName,
    group: scenario.group,
    oldVersion: OLD_VERSION,
    newVersion: NEW_VERSION,
    verdict: diff.verdict,
    findingCount: diff.findings.length,
    detectors: [...new Set(diff.findings.map((finding) => finding.detector))],
    expectedVerdict: scenario.expectedVerdict,
    expectedDetectors: scenario.expectedDetectors,
    matchesExpectation: matchesExpectation(diff, scenario),
    falsePositive: scenario.falsePositive,
    trueWarn: scenario.trueWarn,
    expectationNotes: scenario.expectationNotes,
    findings: diff.findings.map((finding) => ({
      severity: finding.severity,
      detector: finding.detector,
      category: finding.category,
      message: finding.message,
      evidence: finding.evidence?.[0] ?? null,
    })),
  };
}

function matchesExpectation(diff, scenario) {
  if (diff.verdict !== scenario.expectedVerdict) return false;
  const actual = new Set(diff.findings.map((finding) => finding.detector));
  return scenario.expectedDetectors.every((detector) => actual.has(detector))
    && (scenario.expectedDetectors.length > 0 || diff.findings.length === 0);
}

function buildBumpScenario(packageName) {
  switch (packageName) {
    case 'dotenv':
      return {
        group: 'existing-fs-read',
        expectedVerdict: 'CLEAN',
        expectedDetectors: [],
        falsePositive: false,
        trueWarn: false,
        expectationNotes: [
          'fs.readFileSync(.env) exists in both versions, so fs.new-hotpath-read should not fire.',
        ],
        oldManifest: {
          name: packageName,
          version: OLD_VERSION,
          main: 'lib/main.js',
        },
        newManifest: {
          name: packageName,
          version: NEW_VERSION,
          main: 'lib/main.js',
        },
        oldFiles: { 'lib/main.js': dotenvSource() },
        newFiles: { 'lib/main.js': dotenvSource() },
      };
    case 'eslint':
      return {
        group: 'static-local-require',
        expectedVerdict: 'CLEAN',
        expectedDetectors: [],
        falsePositive: false,
        trueWarn: false,
        expectationNotes: [
          "A new static local require('./flat-config/config-loader') should not count as dynamic loading.",
        ],
        oldManifest: {
          name: packageName,
          version: OLD_VERSION,
          main: 'lib/linter.js',
        },
        newManifest: {
          name: packageName,
          version: NEW_VERSION,
          main: 'lib/linter.js',
        },
        oldFiles: {
          'lib/linter.js': "const rule = require('./rule');\nmodule.exports = class Linter { verify(code) { return []; } };\n",
          'lib/rule.js': 'module.exports = {};\n',
        },
        newFiles: {
          'lib/linter.js': "const rule = require('./rule');\nconst { loadConfigFile } = require('./flat-config/config-loader');\nmodule.exports = class Linter { verify(code) { return []; } verify2(code) { return []; } };\n",
          'lib/rule.js': 'module.exports = {};\n',
          'lib/flat-config/config-loader.js': 'exports.loadConfigFile = () => ({ extends: [] });\n',
        },
      };
    case 'sharp':
      return {
        group: 'native-binary-recompiled',
        expectedVerdict: 'BLOCK',
        expectedDetectors: ['bin.new-native-artifact'],
        falsePositive: true,
        trueWarn: false,
        expectationNotes: [
          'The detector keys native artifacts by path+sha256, so a recompiled .node at the same path still looks like a new artifact.',
        ],
        oldManifest: {
          name: packageName,
          version: OLD_VERSION,
          main: 'index.js',
        },
        newManifest: {
          name: packageName,
          version: NEW_VERSION,
          main: 'index.js',
        },
        oldFiles: {
          'index.js': "module.exports = { resize() { return 'ok'; } };\n",
          'build/Release/sharp.node': Buffer.from('sharp-native-binary-before-v1'),
        },
        newFiles: {
          'index.js': "module.exports = { resize() { return 'ok'; } };\n",
          'build/Release/sharp.node': Buffer.from('sharp-native-binary-after-v2'),
        },
      };
    case 'glob':
    case 'minimatch':
      return utilityScenario(packageName);
    default:
      return genericCleanScenario(packageName);
  }
}

function buildPrepareScenario(packageName) {
  const prepareCommand = packageName === 'uuid' ? 'rollup -c' : 'npm run compile';
  const baseScenario = packageName === 'dotenv'
    ? {
        oldManifest: { name: packageName, version: OLD_VERSION, main: 'lib/main.js', scripts: { test: 'mocha --recursive' } },
        newManifest: { name: packageName, version: NEW_VERSION, main: 'lib/main.js', scripts: { test: 'mocha --recursive', prepare: prepareCommand } },
        oldFiles: { 'lib/main.js': dotenvSource() },
        newFiles: { 'lib/main.js': dotenvSource() },
      }
    : packageName === 'eslint'
      ? {
          oldManifest: { name: packageName, version: OLD_VERSION, main: 'lib/linter.js', scripts: { test: 'mocha --recursive' } },
          newManifest: { name: packageName, version: NEW_VERSION, main: 'lib/linter.js', scripts: { test: 'mocha --recursive', prepare: prepareCommand } },
          oldFiles: {
            'lib/linter.js': "const rule = require('./rule');\nmodule.exports = class Linter { verify(code) { return []; } };\n",
            'lib/rule.js': 'module.exports = {};\n',
          },
          newFiles: {
            'lib/linter.js': "const rule = require('./rule');\nmodule.exports = class Linter { verify(code) { return []; } };\n",
            'lib/rule.js': 'module.exports = {};\n',
          },
        }
      : packageName === 'sharp'
        ? {
            oldManifest: { name: packageName, version: OLD_VERSION, main: 'index.js', scripts: { test: 'mocha --recursive' } },
            newManifest: { name: packageName, version: NEW_VERSION, main: 'index.js', scripts: { test: 'mocha --recursive', prepare: prepareCommand } },
            oldFiles: {
              'index.js': "module.exports = { resize() { return 'ok'; } };\n",
              'build/Release/sharp.node': Buffer.from('sharp-native-binary-constant'),
            },
            newFiles: {
              'index.js': "module.exports = { resize() { return 'ok'; } };\n",
              'build/Release/sharp.node': Buffer.from('sharp-native-binary-constant'),
            },
          }
        : packageName === 'glob' || packageName === 'minimatch'
          ? {
              oldManifest: { name: packageName, version: OLD_VERSION, main: 'index.js', scripts: { test: 'mocha --recursive' } },
              newManifest: { name: packageName, version: NEW_VERSION, main: 'index.js', scripts: { test: 'mocha --recursive', prepare: prepareCommand } },
              oldFiles: { 'index.js': utilitySource(packageName) },
              newFiles: { 'index.js': utilitySource(packageName) },
            }
          : {
              oldManifest: { name: packageName, version: OLD_VERSION, main: 'index.js', scripts: { test: 'mocha --recursive' } },
              newManifest: { name: packageName, version: NEW_VERSION, main: 'index.js', scripts: { test: 'mocha --recursive', prepare: prepareCommand } },
              oldFiles: { 'index.js': genericSource(packageName, 'before') },
              newFiles: { 'index.js': genericSource(packageName, 'before') },
            };

  return {
    group: packageName === 'uuid' ? 'uuid-prepare-script' : 'prepare-script-change',
    expectedVerdict: 'WARN',
    expectedDetectors: ['install.script-added'],
    falsePositive: false,
    trueWarn: true,
    expectationNotes: [
      'prepare is tracked in INSTALL detector PUBLISH_TIER, so adding it should yield install.script-added at WARN.',
      'This is a true WARN, but it documents one of the known noise sources the study wants to keep rare.',
    ],
    ...baseScenario,
  };
}

function genericCleanScenario(packageName) {
  return {
    group: 'prepare-script-change',
    expectedVerdict: 'CLEAN',
    expectedDetectors: [],
    falsePositive: false,
    trueWarn: false,
    expectationNotes: [
      'Baseline benign bump: same package shape with a small pure-JS feature/refactor and no new detector-relevant capability.',
    ],
    oldManifest: {
      name: packageName,
      version: OLD_VERSION,
      main: 'index.js',
    },
    newManifest: {
      name: packageName,
      version: NEW_VERSION,
      main: 'index.js',
    },
    oldFiles: { 'index.js': genericSource(packageName, 'before') },
    newFiles: { 'index.js': genericSource(packageName, 'after') },
  };
}

function utilityScenario(packageName) {
  return {
    group: 'utility-clean',
    expectedVerdict: 'CLEAN',
    expectedDetectors: [],
    falsePositive: false,
    trueWarn: false,
    expectationNotes: [
      'Small utility keeps the same fs/path imports in both versions, so the bump should stay CLEAN.',
    ],
    oldManifest: {
      name: packageName,
      version: OLD_VERSION,
      main: 'index.js',
    },
    newManifest: {
      name: packageName,
      version: NEW_VERSION,
      main: 'index.js',
    },
    oldFiles: { 'index.js': utilitySource(packageName) },
    newFiles: { 'index.js': utilitySource(packageName) },
  };
}

function genericSource(packageName, versionTag) {
  const helperName = sanitize(packageName);
  if (versionTag === 'before') {
    return `'use strict';\nfunction ${helperName}Helper(value) { return String(value).trim(); }\nmodule.exports = {\n  normalize(value) { return ${helperName}Helper(value); },\n};\n`;
  }
  return `'use strict';\nfunction ${helperName}Helper(value) { return String(value).trim(); }\nfunction joinParts(parts) { return parts.filter(Boolean).join('/'); }\nmodule.exports = {\n  normalize(value) { return ${helperName}Helper(value); },\n  format(parts) { return joinParts(parts.map(${helperName}Helper)); },\n};\n`;
}

function utilitySource(packageName) {
  return `const path = require('path');\nconst fs = require('fs');\nmodule.exports = function ${sanitize(packageName)}(pattern, opts) {\n  void path;\n  void fs;\n  void pattern;\n  void opts;\n  return [];\n};\n`;
}

function dotenvSource() {
  return `const fs = require('fs');\nconst path = require('path');\nfunction config(options = {}) {\n  const dotenvPath = path.resolve(process.cwd(), options.path || '.env');\n  const encoding = options.encoding || 'utf8';\n  try {\n    const parsed = fs.readFileSync(dotenvPath, { encoding });\n    return { parsed };\n  } catch (e) {\n    return { error: e };\n  }\n}\nmodule.exports = { config };\n`;
}

function makeLockfile(packageName, version, integrity, tarballPath) {
  return JSON.stringify({
    name: 'webtools-study-app',
    version: '1.0.0',
    lockfileVersion: 3,
    packages: {
      '': {
        name: 'webtools-study-app',
        version: '1.0.0',
        dependencies: {
          [packageName]: `^${version}`,
        },
      },
      [`node_modules/${packageName}`]: {
        name: packageName,
        version,
        integrity,
        resolved: `file://${tarballPath}`,
      },
    },
  }, null, 2);
}

async function makeTarball(dir, files) {
  const stage = path.join(dir, `.stage-${crypto.randomUUID()}`);
  const pkgDir = path.join(stage, 'package');
  await fs.mkdir(pkgDir, { recursive: true });
  for (const [name, content] of Object.entries(files)) {
    const filePath = path.join(pkgDir, name);
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    if (Buffer.isBuffer(content)) await fs.writeFile(filePath, content);
    else await fs.writeFile(filePath, content, 'utf8');
  }
  await fs.mkdir(dir, { recursive: true });
  const tarballPath = path.join(dir, 'package.tgz');
  await tar.c({ gzip: true, file: tarballPath, cwd: stage, portable: true }, ['package']);
  const buf = await fs.readFile(tarballPath);
  const hash = crypto.createHash('sha512').update(buf).digest('base64');
  await fs.rm(stage, { recursive: true, force: true });
  return { path: tarballPath, integrity: `sha512-${hash}` };
}

function sanitize(value) {
  return value.replace(/[^a-z0-9]+/gi, '-');
}

await main();
