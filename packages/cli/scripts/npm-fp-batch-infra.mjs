#!/usr/bin/env node
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import * as tar from 'tar';
import {
  runDiff,
  VETLOCK_VERSION,
  SENSITIVE_ENV_KEYS,
} from '@vetlock/core';
import { runAll } from '@vetlock/detectors';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const OUTPUT_FILE = path.join(REPO_ROOT, 'studies', 'npm-fp-batch-infra.json');
const SCRATCH_ROOT = path.join(REPO_ROOT, 'studies', '.scratch', 'npm-fp-batch-infra');
const SENSITIVE_ENV_SET = new Set(SENSITIVE_ENV_KEYS);
const FOCUS_DETECTORS = ['env.token-harvest', 'net.new-endpoint'];

const PACKAGE_SPECS = [
  {
    packageName: 'aws-sdk',
    category: 'cloud-sdk',
    concernProfile: {
      stableEnvReads: [
        'AWS_ACCESS_KEY_ID',
        'AWS_SECRET_ACCESS_KEY',
        'AWS_SESSION_TOKEN',
        'AWS_DEFAULT_REGION',
      ],
      stableUrlLiterals: [],
      stableConnectionStrings: [],
      stableLoggingConfig: false,
      stableConfigSchema: false,
    },
    files: {
      'index.js': `
const AWS_ACCESS_KEY = process.env.AWS_ACCESS_KEY_ID;
const AWS_SECRET = process.env.AWS_SECRET_ACCESS_KEY;
const AWS_SESSION = process.env.AWS_SESSION_TOKEN;
const AWS_REGION = process.env.AWS_DEFAULT_REGION || 'us-east-1';
module.exports = { AWS_ACCESS_KEY, AWS_SECRET, AWS_SESSION, AWS_REGION };
`,
    },
  },
  {
    packageName: '@aws-sdk/client-s3',
    category: 'cloud-sdk',
    concernProfile: {
      stableEnvReads: [
        'AWS_ACCESS_KEY_ID',
        'AWS_SECRET_ACCESS_KEY',
        'AWS_SESSION_TOKEN',
        'AWS_DEFAULT_REGION',
      ],
      stableUrlLiterals: [],
      stableConnectionStrings: [],
      stableLoggingConfig: false,
      stableConfigSchema: false,
    },
    files: {
      'index.js': `
const AWS_ACCESS_KEY = process.env.AWS_ACCESS_KEY_ID;
const AWS_SECRET = process.env.AWS_SECRET_ACCESS_KEY;
const AWS_SESSION = process.env.AWS_SESSION_TOKEN;
const AWS_REGION = process.env.AWS_DEFAULT_REGION || 'us-east-1';
exports.s3Config = { AWS_ACCESS_KEY, AWS_SECRET, AWS_SESSION, AWS_REGION };
`,
    },
  },
  {
    packageName: '@azure/identity',
    category: 'cloud-sdk',
    concernProfile: {
      stableEnvReads: ['AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_TENANT_ID'],
      stableUrlLiterals: [],
      stableConnectionStrings: [],
      stableLoggingConfig: false,
      stableConfigSchema: false,
    },
    files: {
      'index.js': `
const tenantId = process.env.AZURE_TENANT_ID;
const clientId = process.env.AZURE_CLIENT_ID;
const clientSecret = process.env.AZURE_CLIENT_SECRET;
module.exports = { tenantId, clientId, clientSecret };
`,
    },
  },
  {
    packageName: 'firebase',
    category: 'cloud-sdk',
    concernProfile: {
      stableEnvReads: [],
      stableUrlLiterals: [
        'https://firebaseio.com',
        'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword',
      ],
      stableConnectionStrings: [],
      stableLoggingConfig: false,
      stableConfigSchema: false,
    },
    files: {
      'index.js': `
const FIREBASE_URL = 'https://firebaseio.com';
const AUTH_URL = 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword';
module.exports = { FIREBASE_URL, AUTH_URL };
`,
    },
  },
  {
    packageName: 'mongoose',
    category: 'database-client',
    concernProfile: {
      stableEnvReads: ['MONGODB_URI'],
      stableUrlLiterals: [],
      stableConnectionStrings: ['mongodb://localhost:27017/app'],
      stableLoggingConfig: false,
      stableConfigSchema: false,
    },
    files: {
      'index.js': `
const MONGO_URL = process.env.MONGODB_URI || 'mongodb://localhost:27017/app';
module.exports = { MONGO_URL };
`,
    },
  },
  {
    packageName: 'redis',
    category: 'database-client',
    concernProfile: {
      stableEnvReads: ['REDIS_URL'],
      stableUrlLiterals: [],
      stableConnectionStrings: ['redis://localhost:6379'],
      stableLoggingConfig: false,
      stableConfigSchema: false,
    },
    files: {
      'index.js': `
const DEFAULT_URL = 'redis://localhost:6379';
const REDIS_URL = process.env.REDIS_URL || DEFAULT_URL;
module.exports = { DEFAULT_URL, REDIS_URL };
`,
    },
  },
  {
    packageName: 'mysql2',
    category: 'database-client',
    concernProfile: {
      stableEnvReads: ['DATABASE_URL'],
      stableUrlLiterals: [],
      stableConnectionStrings: ['mysql://root:root@localhost:3306/app'],
      stableLoggingConfig: false,
      stableConfigSchema: false,
    },
    files: {
      'index.js': `
const DATABASE_URL = process.env.DATABASE_URL || 'mysql://root:root@localhost:3306/app';
module.exports = { DATABASE_URL };
`,
    },
  },
  {
    packageName: 'pg',
    category: 'database-client',
    concernProfile: {
      stableEnvReads: ['POSTGRES_URL'],
      stableUrlLiterals: [],
      stableConnectionStrings: ['postgres://localhost:5432/app'],
      stableLoggingConfig: false,
      stableConfigSchema: false,
    },
    files: {
      'index.js': `
const POSTGRES_URL = process.env.POSTGRES_URL || 'postgres://localhost:5432/app';
module.exports = { POSTGRES_URL };
`,
    },
  },
  {
    packageName: 'nodemailer',
    category: 'mailer',
    concernProfile: {
      stableEnvReads: ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS'],
      stableUrlLiterals: [],
      stableConnectionStrings: [],
      stableLoggingConfig: false,
      stableConfigSchema: false,
    },
    files: {
      'index.js': `
const transport = {
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || '587', 10),
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
};
module.exports = { transport };
`,
    },
  },
  {
    packageName: 'node-cron',
    category: 'process-infra',
    concernProfile: {
      stableEnvReads: [],
      stableUrlLiterals: [],
      stableConnectionStrings: [],
      stableLoggingConfig: false,
      stableConfigSchema: false,
      stableScheduleConfig: true,
    },
    files: {
      'index.js': `
const JOB = '0 */6 * * *';
function register(task) {
  return { expression: JOB, task };
}
module.exports = { JOB, register };
`,
    },
  },
  {
    packageName: 'pm2',
    category: 'process-infra',
    concernProfile: {
      stableEnvReads: [],
      stableUrlLiterals: [],
      stableConnectionStrings: [],
      stableLoggingConfig: false,
      stableConfigSchema: false,
      stableProcessManagerConfig: true,
    },
    files: {
      'index.js': `
module.exports = {
  apps: [
    {
      name: 'worker',
      script: 'server.js',
      instances: 2,
      watch: false,
    },
  ],
};
`,
    },
  },
  {
    packageName: 'winston',
    category: 'logging',
    concernProfile: {
      stableEnvReads: [],
      stableUrlLiterals: [],
      stableConnectionStrings: [],
      stableLoggingConfig: true,
      stableConfigSchema: false,
    },
    files: {
      'index.js': `
module.exports = {
  level: 'info',
  format: 'json',
  defaultMeta: { service: 'app' },
};
`,
    },
  },
  {
    packageName: 'pino',
    category: 'logging',
    concernProfile: {
      stableEnvReads: [],
      stableUrlLiterals: [],
      stableConnectionStrings: [],
      stableLoggingConfig: true,
      stableConfigSchema: false,
    },
    files: {
      'index.js': `
module.exports = {
  level: 'debug',
  name: 'app',
  redact: ['req.headers.authorization'],
};
`,
    },
  },
  {
    packageName: 'bunyan',
    category: 'logging',
    concernProfile: {
      stableEnvReads: [],
      stableUrlLiterals: [],
      stableConnectionStrings: [],
      stableLoggingConfig: true,
      stableConfigSchema: false,
    },
    files: {
      'index.js': `
module.exports = {
  name: 'app',
  level: 'info',
  serializers: ['req', 'res'],
};
`,
    },
  },
  {
    packageName: 'morgan',
    category: 'logging',
    concernProfile: {
      stableEnvReads: [],
      stableUrlLiterals: [],
      stableConnectionStrings: [],
      stableLoggingConfig: true,
      stableConfigSchema: false,
    },
    files: {
      'index.js': `
module.exports = {
  format: 'combined',
  immediate: false,
  stream: 'stdout',
};
`,
    },
  },
  {
    packageName: 'config',
    category: 'config-framework',
    concernProfile: {
      stableEnvReads: ['NODE_ENV', 'PORT'],
      stableUrlLiterals: [],
      stableConnectionStrings: [],
      stableLoggingConfig: false,
      stableConfigSchema: true,
    },
    files: {
      'index.js': `
module.exports = {
  env: process.env.NODE_ENV || 'development',
  port: process.env.PORT || '3000',
};
`,
    },
  },
  {
    packageName: 'convict',
    category: 'config-framework',
    concernProfile: {
      stableEnvReads: ['NODE_ENV', 'PORT'],
      stableUrlLiterals: [],
      stableConnectionStrings: [],
      stableLoggingConfig: false,
      stableConfigSchema: true,
    },
    files: {
      'index.js': `
module.exports = {
  env: {
    doc: 'Application environment',
    default: 'development',
    env: 'NODE_ENV',
  },
  port: {
    doc: 'HTTP port',
    default: 3000,
    env: 'PORT',
  },
};
`,
    },
  },
  {
    packageName: 'cosmiconfig',
    category: 'config-framework',
    concernProfile: {
      stableEnvReads: ['NODE_ENV'],
      stableUrlLiterals: [],
      stableConnectionStrings: [],
      stableLoggingConfig: false,
      stableConfigSchema: true,
    },
    files: {
      'index.js': `
const loaders = {
  js: true,
  json: true,
  yaml: true,
};
const mode = process.env.NODE_ENV || 'development';
module.exports = { loaders, mode };
`,
    },
  },
];

const ENV_KEY_PROBES = [
  {
    envKey: 'AWS_ACCESS_KEY_ID',
    packageName: 'probe-aws-access-key-id',
    category: 'aws-env',
    expectedTrigger: true,
    newCode: `module.exports = process.env.AWS_ACCESS_KEY_ID;\n`,
  },
  {
    envKey: 'AWS_SECRET_ACCESS_KEY',
    packageName: 'probe-aws-secret-access-key',
    category: 'aws-env',
    expectedTrigger: true,
    newCode: `module.exports = process.env.AWS_SECRET_ACCESS_KEY;\n`,
  },
  {
    envKey: 'AWS_SESSION_TOKEN',
    packageName: 'probe-aws-session-token',
    category: 'aws-env',
    expectedTrigger: true,
    newCode: `module.exports = process.env.AWS_SESSION_TOKEN;\n`,
  },
  {
    envKey: 'AWS_DEFAULT_REGION',
    packageName: 'probe-aws-default-region',
    category: 'aws-env',
    expectedTrigger: true,
    newCode: `module.exports = process.env.AWS_DEFAULT_REGION || 'us-east-1';\n`,
  },
  {
    envKey: 'MONGODB_URI',
    packageName: 'probe-mongodb-uri',
    category: 'connection-string-env',
    expectedTrigger: false,
    newCode: `module.exports = process.env.MONGODB_URI || 'mongodb://localhost:27017/app';\n`,
  },
  {
    envKey: 'SMTP_HOST',
    packageName: 'probe-smtp-host',
    category: 'smtp-env',
    expectedTrigger: false,
    newCode: `module.exports = process.env.SMTP_HOST;\n`,
  },
  {
    envKey: 'SMTP_PORT',
    packageName: 'probe-smtp-port',
    category: 'smtp-env',
    expectedTrigger: false,
    newCode: `module.exports = parseInt(process.env.SMTP_PORT || '587', 10);\n`,
  },
  {
    envKey: 'SMTP_USER',
    packageName: 'probe-smtp-user',
    category: 'smtp-env',
    expectedTrigger: false,
    newCode: `module.exports = process.env.SMTP_USER;\n`,
  },
  {
    envKey: 'SMTP_PASS',
    packageName: 'probe-smtp-pass',
    category: 'smtp-env',
    expectedTrigger: false,
    newCode: `module.exports = process.env.SMTP_PASS;\n`,
  },
];

function sanitize(value) {
  return value.replace(/[^A-Za-z0-9._-]/g, '_');
}

function packageManifest(name, version) {
  return {
    name,
    version,
    main: 'index.js',
    license: 'MIT',
    description: `Synthetic npm false-positive study fixture for ${name}`,
  };
}

async function makeTarball(destDir, packageName, version, files) {
  fs.mkdirSync(destDir, { recursive: true });
  fs.mkdirSync(SCRATCH_ROOT, { recursive: true });
  const stage = fs.mkdtempSync(path.join(SCRATCH_ROOT, '.stage-'));
  const pkgDir = path.join(stage, 'package');
  fs.mkdirSync(pkgDir, { recursive: true });
  const contents = {
    'package.json': JSON.stringify(packageManifest(packageName, version), null, 2),
    'README.md': `# ${packageName} ${version}\n\nSynthetic infra/config FP study fixture.\n`,
    ...files,
  };
  for (const [name, content] of Object.entries(contents)) {
    const filePath = path.join(pkgDir, name);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
  }
  const tarballPath = path.join(destDir, `${sanitize(packageName)}-${version}.tgz`);
  await tar.c({ gzip: true, file: tarballPath, cwd: stage, portable: true }, ['package']);
  const buf = fs.readFileSync(tarballPath);
  const integrity = `sha512-${createHash('sha512').update(buf).digest('base64')}`;
  fs.rmSync(stage, { recursive: true, force: true });
  return { path: tarballPath, integrity };
}

async function analyzePackageBump(spec) {
  const versionDir = path.join(SCRATCH_ROOT, sanitize(spec.packageName));
  const oldVersion = '1.0.0';
  const newVersion = '1.0.1';
  const oldTgz = await makeTarball(path.join(versionDir, oldVersion), spec.packageName, oldVersion, spec.files);
  const newTgz = await makeTarball(path.join(versionDir, newVersion), spec.packageName, newVersion, spec.files);
  const artifactByVersion = new Map([
    [oldVersion, oldTgz.path],
    [newVersion, newTgz.path],
  ]);
  const lockBefore = JSON.stringify({
    name: 'npm-fp-study-app',
    version: '1.0.0',
    lockfileVersion: 3,
    packages: {
      '': { name: 'npm-fp-study-app', version: '1.0.0', dependencies: { [spec.packageName]: `^${oldVersion}` } },
      [`node_modules/${spec.packageName}`]: {
        name: spec.packageName,
        version: oldVersion,
        integrity: oldTgz.integrity,
        resolved: '',
      },
    },
  });
  const lockAfter = JSON.stringify({
    name: 'npm-fp-study-app',
    version: '1.0.0',
    lockfileVersion: 3,
    packages: {
      '': { name: 'npm-fp-study-app', version: '1.0.0', dependencies: { [spec.packageName]: `^${newVersion}` } },
      [`node_modules/${spec.packageName}`]: {
        name: spec.packageName,
        version: newVersion,
        integrity: newTgz.integrity,
        resolved: '',
      },
    },
  });
  const result = await runDiff(lockBefore, lockAfter, {
    runDetectors: (pair) => runAll(pair),
    timeoutMs: 60_000,
    fetchOverride: async (ref) => artifactByVersion.get(ref.version) ?? newTgz.path,
  });
  const focusDetectorHits = Object.fromEntries(
    FOCUS_DETECTORS.map((detector) => [
      detector,
      result.findings.filter((finding) => finding.detector === detector).length,
    ]),
  );
  return {
    packageName: spec.packageName,
    oldVersion,
    newVersion,
    category: spec.category,
    artifactKind: 'tarball',
    verdict: result.verdict,
    findings: result.findings.length,
    detectors: [...new Set(result.findings.map((finding) => finding.detector))],
    focusDetectorHits,
    concernProfile: spec.concernProfile,
    findingsDetail: result.findings.map((finding) => ({
      severity: finding.severity,
      detector: finding.detector,
      message: finding.message,
    })),
  };
}

async function analyzeEnvProbe(probe) {
  const versionDir = path.join(SCRATCH_ROOT, 'env-probes', sanitize(probe.packageName));
  const oldVersion = '1.0.0';
  const newVersion = '1.0.1';
  const oldTgz = await makeTarball(path.join(versionDir, oldVersion), probe.packageName, oldVersion, {
    'index.js': 'module.exports = null;\n',
  });
  const newTgz = await makeTarball(path.join(versionDir, newVersion), probe.packageName, newVersion, {
    'index.js': probe.newCode,
  });
  const artifactByVersion = new Map([
    [oldVersion, oldTgz.path],
    [newVersion, newTgz.path],
  ]);
  const lockBefore = JSON.stringify({
    name: 'npm-fp-study-app',
    version: '1.0.0',
    lockfileVersion: 3,
    packages: {
      '': { name: 'npm-fp-study-app', version: '1.0.0', dependencies: { [probe.packageName]: `^${oldVersion}` } },
      [`node_modules/${probe.packageName}`]: {
        name: probe.packageName,
        version: oldVersion,
        integrity: oldTgz.integrity,
        resolved: '',
      },
    },
  });
  const lockAfter = JSON.stringify({
    name: 'npm-fp-study-app',
    version: '1.0.0',
    lockfileVersion: 3,
    packages: {
      '': { name: 'npm-fp-study-app', version: '1.0.0', dependencies: { [probe.packageName]: `^${newVersion}` } },
      [`node_modules/${probe.packageName}`]: {
        name: probe.packageName,
        version: newVersion,
        integrity: newTgz.integrity,
        resolved: '',
      },
    },
  });
  const result = await runDiff(lockBefore, lockAfter, {
    runDetectors: (pair) => runAll(pair),
    timeoutMs: 60_000,
    fetchOverride: async (ref) => artifactByVersion.get(ref.version) ?? newTgz.path,
  });
  const envFindings = result.findings.filter((finding) => finding.detector === 'env.token-harvest');
  return {
    envKey: probe.envKey,
    category: probe.category,
    expectedTrigger: probe.expectedTrigger,
    listedInSensitiveEnvKeys: SENSITIVE_ENV_SET.has(probe.envKey),
    actualTrigger: envFindings.length > 0,
    actualVerdict: result.verdict,
    detectors: [...new Set(result.findings.map((finding) => finding.detector))],
    findingMessages: result.findings.map((finding) => finding.message),
  };
}

function buildCategorySummary(rows) {
  const summary = {};
  for (const row of rows) {
    if (!summary[row.category]) {
      summary[row.category] = { total: 0, clean: 0, findings: 0 };
    }
    summary[row.category].total += 1;
    if (row.verdict === 'CLEAN') summary[row.category].clean += 1;
    summary[row.category].findings += row.findings;
  }
  return summary;
}

async function main() {
  fs.rmSync(SCRATCH_ROOT, { recursive: true, force: true });
  fs.mkdirSync(path.dirname(OUTPUT_FILE), { recursive: true });

  const rows = [];
  for (const spec of PACKAGE_SPECS) {
    rows.push(await analyzePackageBump(spec));
  }

  const envKeyCalibration = [];
  for (const probe of ENV_KEY_PROBES) {
    envKeyCalibration.push(await analyzeEnvProbe(probe));
  }

  const succeeded = rows.filter((row) => row.verdict !== 'ERROR').length;
  const failed = rows.length - succeeded;
  const totalFindings = rows.reduce((sum, row) => sum + row.findings, 0);
  const detectorHits = new Map();
  const severityCounts = { BLOCK: 0, WARN: 0, INFO: 0, CLEAN: 0, ERROR: 0 };
  for (const row of rows) {
    severityCounts[row.verdict] = (severityCounts[row.verdict] ?? 0) + 1;
    for (const detector of row.detectors) {
      detectorHits.set(detector, (detectorHits.get(detector) ?? 0) + 1);
    }
  }
  const perDetectorFpRate = Object.fromEntries(
    [...detectorHits.entries()].map(([detector, hits]) => [
      detector,
      { hits, ratePerBump: succeeded > 0 ? hits / succeeded : 0 },
    ]),
  );
  const focusSummary = Object.fromEntries(
    FOCUS_DETECTORS.map((detector) => [
      detector,
      {
        hits: rows.reduce((sum, row) => sum + (row.focusDetectorHits[detector] ?? 0), 0),
        packagesWithHits: rows.filter((row) => (row.focusDetectorHits[detector] ?? 0) > 0).map((row) => row.packageName),
      },
    ]),
  );
  const concernSummary = {
    stableAwsEnvPackages: rows.filter((row) => row.concernProfile.stableEnvReads?.some((key) => key.startsWith('AWS_'))).map((row) => row.packageName),
    stableCloudCredentialPackages: rows.filter((row) => row.concernProfile.stableEnvReads?.some((key) => key.startsWith('AZURE_'))).map((row) => row.packageName),
    stableConnectionStringPackages: rows.filter((row) => (row.concernProfile.stableConnectionStrings?.length ?? 0) > 0).map((row) => row.packageName),
    stableMailerEnvPackages: rows.filter((row) => row.concernProfile.stableEnvReads?.some((key) => key.startsWith('SMTP_'))).map((row) => row.packageName),
    stableLoggingPackages: rows.filter((row) => row.concernProfile.stableLoggingConfig).map((row) => row.packageName),
    stableConfigPackages: rows.filter((row) => row.concernProfile.stableConfigSchema).map((row) => row.packageName),
    packagesWithAnyFindings: rows.filter((row) => row.findings > 0).map((row) => row.packageName),
  };
  const falsePositiveCategories = {
    'delta-miss': {
      description: 'Capability existed in both before and after artifacts but detector still fired on the bump.',
      count: rows.filter((row) => row.findings > 0).length,
      items: rows.filter((row) => row.findings > 0).map((row) => ({ packageName: row.packageName, detectors: row.detectors })),
    },
    'sensitive-key-too-broad': {
      description: 'An env key that should be benign still triggered env.token-harvest in calibration.',
      count: envKeyCalibration.filter((entry) => !entry.expectedTrigger && entry.actualTrigger).length,
      items: envKeyCalibration.filter((entry) => !entry.expectedTrigger && entry.actualTrigger).map((entry) => entry.envKey),
    },
  };
  const report = {
    study: 'npm-fp-batch-infra',
    batch: 'CONFIG/INFRA',
    theme: 'cloud-sdk-database-logging-config',
    ecosystem: 'npm',
    version: '1',
    vetlockVersion: VETLOCK_VERSION,
    ranAt: new Date().toISOString(),
    methodology: {
      source: 'synthetic local npm tarballs via package-lock v3 diff',
      networkAccess: 'disabled; artifacts generated in workspace scratch and analyzed via fetchOverride',
      packageCount: PACKAGE_SPECS.length,
      versionTemplate: '1.0.0 -> 1.0.1',
      focus: [
        'stable AWS/Azure env reads on bumps',
        'stable firebase URL literals in config-value/literal contexts',
        'stable database connection string patterns',
        'stable nodemailer SMTP env config',
        'logging/config packages remaining clean on routine bumps',
      ],
    },
    totalBumps: rows.length,
    bumpsSucceeded: succeeded,
    bumpsFailed: failed,
    totalFindings,
    findingsPerBump: succeeded > 0 ? totalFindings / succeeded : 0,
    perDetectorFpRate,
    perSeverity: severityCounts,
    categorySummary: buildCategorySummary(rows),
    falsePositiveRate: succeeded > 0 ? rows.filter((row) => row.verdict !== 'CLEAN').length / succeeded : 0,
    falsePositiveCategories,
    focusSummary,
    concernSummary,
    envKeyCalibration,
    keyFindings: {
      allExpectedCleanBumpsStayedClean: rows.every((row) => row.verdict === 'CLEAN'),
      awsStableEnvBumpsStayedClean: rows.filter((row) => row.concernProfile.stableEnvReads?.some((key) => key.startsWith('AWS_'))).every((row) => row.verdict === 'CLEAN'),
      firebaseUrlBumpStayedClean: rows.find((row) => row.packageName === 'firebase')?.verdict === 'CLEAN',
      mongodbUriTriggersEnvTokenHarvest: envKeyCalibration.find((entry) => entry.envKey === 'MONGODB_URI')?.actualTrigger ?? null,
      smtpPassTriggersEnvTokenHarvest: envKeyCalibration.find((entry) => entry.envKey === 'SMTP_PASS')?.actualTrigger ?? null,
      awsDefaultRegionTriggersEnvTokenHarvest: envKeyCalibration.find((entry) => entry.envKey === 'AWS_DEFAULT_REGION')?.actualTrigger ?? null,
      loggingBumpsStayedClean: rows.filter((row) => row.category === 'logging').every((row) => row.verdict === 'CLEAN'),
      packagesWithAnyFindings: rows.filter((row) => row.findings > 0).map((row) => row.packageName),
    },
    worstOffenders: [...rows]
      .sort((a, b) => b.findings - a.findings || a.packageName.localeCompare(b.packageName))
      .slice(0, 10)
      .map((row) => ({ packageName: row.packageName, findings: row.findings, detectors: row.detectors })),
    rows,
  };

  fs.writeFileSync(OUTPUT_FILE, `${JSON.stringify(report, null, 2)}\n`);
  fs.rmSync(SCRATCH_ROOT, { recursive: true, force: true });
  console.log(`wrote ${path.relative(REPO_ROOT, OUTPUT_FILE)}`);
}

main().catch((error) => {
  fs.rmSync(SCRATCH_ROOT, { recursive: true, force: true });
  console.error(error);
  process.exit(1);
});
