/**
 * INSTALL self-publish-shape — install-hook + child_process + package.json write.
 *
 * Test contract:
 *  - All three signals co-occur in pair.new → fires.
 *  - Missing any one leg → does NOT fire.
 *  - Adding an install-tier hook that wasn't there before → BLOCK.
 *  - Install hook was already there → WARN.
 *  - Stable package (identical shape in pair.old + pair.new) → does NOT fire.
 *
 * Ports from guarddog:threat-runtime-self-propagation, per §4 row 10.
 */

import { describe, it, expect } from 'vitest';
import {
  selfPublishShapeDetector,
  selfPublishShape,
} from '../src/install-self-publish-shape.js';
import { mkSnap, mkFile } from './helpers.js';

describe('install.self-publish-shape — worm mechanic', () => {
  it('emits BLOCK for a NEW package with all three signals', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'evil-worm',
        version: '1.0.0',
        manifest: {
          name: 'evil-worm',
          version: '1.0.0',
          scripts: { postinstall: 'node ./boot.js' },
        },
        files: [
          mkFile({
            path: 'boot.js',
            execModules: ['child_process'],
          }),
          mkFile({
            path: 'republish.js',
            fsWriteTargets: ['package.json'],
          }),
        ],
      }),
    };
    const findings = selfPublishShapeDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.detector).toBe('install.self-publish-shape');
    expect(findings[0]!.severity).toBe('BLOCK');
    expect(findings[0]!.confidence).toBe('high');
    expect(findings[0]!.message).toMatch(/postinstall/);
    expect(findings[0]!.message).toMatch(/child_process|exec-in/);
  });

  it('emits WARN when upgrade adds the shape but hook was already there', () => {
    const before = mkSnap({
      name: 'my-package',
      version: '1.0.0',
      manifest: {
        name: 'my-package',
        version: '1.0.0',
        scripts: { postinstall: 'echo hi' },
      },
      files: [], // no exec + no package.json writes → no shape yet
    });
    const after = mkSnap({
      name: 'my-package',
      version: '1.0.1',
      manifest: {
        name: 'my-package',
        version: '1.0.1',
        scripts: { postinstall: 'node ./boot.js' },
      },
      files: [
        mkFile({ path: 'boot.js', execModules: ['child_process'] }),
        mkFile({ path: 'republish.js', fsWriteTargets: ['package.json'] }),
      ],
    });
    const findings = selfPublishShapeDetector.run({ old: before, new: after }, { direction: 'changed' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('WARN');
    expect(findings[0]!.confidence).toBe('medium');
  });

  it('does NOT fire when missing the install-tier hook', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'code-only',
        version: '1.0.0',
        manifest: { name: 'code-only', version: '1.0.0' },
        files: [
          mkFile({ path: 'a.js', execModules: ['child_process'] }),
          mkFile({ path: 'b.js', fsWriteTargets: ['package.json'] }),
        ],
      }),
    };
    expect(selfPublishShapeDetector.run(pair, { direction: 'added' })).toHaveLength(0);
  });

  it('does NOT fire when missing child_process', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'legit-package',
        version: '1.0.0',
        manifest: {
          name: 'legit-package',
          version: '1.0.0',
          scripts: { postinstall: 'node ./setup.js' },
        },
        files: [mkFile({ path: 'setup.js', fsWriteTargets: ['package.json'] })],
      }),
    };
    expect(selfPublishShapeDetector.run(pair, { direction: 'added' })).toHaveLength(0);
  });

  it('does NOT fire when missing the package.json write', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'legit-package',
        version: '1.0.0',
        manifest: {
          name: 'legit-package',
          version: '1.0.0',
          scripts: { postinstall: 'node ./setup.js' },
        },
        files: [mkFile({ path: 'setup.js', execModules: ['child_process'] })],
      }),
    };
    expect(selfPublishShapeDetector.run(pair, { direction: 'added' })).toHaveLength(0);
  });

  it('does NOT fire when the shape is stable across versions', () => {
    // Same install hook name + same package.json write target — nothing new.
    const files = [
      mkFile({ path: 'boot.js', execModules: ['child_process'] }),
      mkFile({ path: 'republish.js', fsWriteTargets: ['package.json'] }),
    ];
    const manifest = {
      name: 'stable-worm-shape',
      version: '',
      scripts: { postinstall: 'node ./boot.js' },
    };
    const pair = {
      old: mkSnap({ name: 'stable-worm-shape', version: '1.0.0', manifest: { ...manifest, version: '1.0.0' }, files }),
      new: mkSnap({ name: 'stable-worm-shape', version: '1.0.1', manifest: { ...manifest, version: '1.0.1' }, files }),
    };
    expect(selfPublishShapeDetector.run(pair, { direction: 'changed' })).toHaveLength(0);
  });

  it('matches nested package.json writes (e.g. under a bundled subdir)', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'nested-worm',
        version: '1.0.0',
        manifest: {
          name: 'nested-worm',
          version: '1.0.0',
          scripts: { install: 'node ./boot.js' },
        },
        files: [
          mkFile({ path: 'boot.js', execModules: ['child_process'] }),
          mkFile({ path: 'republish.js', fsWriteTargets: ['nested/package.json'] }),
        ],
      }),
    };
    const findings = selfPublishShapeDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('BLOCK');
  });

  it('selfPublishShape helper returns triple for a real shape', () => {
    const snap = mkSnap({
      name: 'worm',
      version: '1.0.0',
      manifest: {
        name: 'worm',
        version: '1.0.0',
        scripts: { preinstall: 'node ./hop.js' },
      },
      files: [
        mkFile({ path: 'hop.js', execModules: ['child_process'] }),
        mkFile({ path: 'meta.js', fsWriteTargets: ['package.json'] }),
      ],
    });
    const shape = selfPublishShape(snap);
    expect(shape).not.toBeNull();
    expect(shape!.install).toBe('preinstall');
    expect(shape!.exec).toBe('hop.js');
    expect(shape!.write.target).toBe('package.json');
  });
});
