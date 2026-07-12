import { describe, it, expect } from 'vitest';
import { parseLockfile } from '../src/lockfile.js';
import { computeChangeset } from '../src/changeset.js';

function mkLock(root: { name: string; version: string; deps?: Record<string, string> }, entries: Record<string, { version: string; integrity?: string; deps?: Record<string, string> }>) {
  const packages: Record<string, unknown> = {
    '': { name: root.name, version: root.version, dependencies: root.deps ?? {} },
  };
  for (const [key, val] of Object.entries(entries)) {
    const idx = key.lastIndexOf('node_modules/');
    const derivedName = idx === -1 ? key : key.slice(idx + 'node_modules/'.length);
    packages[key] = {
      name: derivedName,
      version: val.version,
      integrity: val.integrity ?? `sha512-${val.version}=`,
      dependencies: val.deps ?? {},
    };
  }
  return { name: root.name, version: root.version, lockfileVersion: 3, packages };
}

describe('computeChangeset', () => {
  it('flags an added transitive package (event-stream regression case)', () => {
    // Old: root → a@1
    // New: root → a@1 → flatmap-stream@0.1.1
    // The event-stream 2018 attack: a legitimate top-level dep didn't upgrade
    // its own version, but a new transitive was published under it that had NEVER been present.
    const oldG = parseLockfile(mkLock({ name: 'root', version: '1.0.0', deps: { a: '^1' } }, {
      'node_modules/a': { version: '1.0.0' },
    }));
    const newG = parseLockfile(mkLock({ name: 'root', version: '1.0.0', deps: { a: '^1' } }, {
      'node_modules/a': { version: '1.0.0', deps: { 'flatmap-stream': '^0.1' } },
      'node_modules/flatmap-stream': { version: '0.1.1' },
    }));
    const changes = computeChangeset(oldG, newG);
    // 'flatmap-stream' must appear as added.
    const added = changes.find((c) => c.name === 'flatmap-stream' && c.kind === 'added');
    expect(added).toBeDefined();
    expect(added?.newVersion).toBe('0.1.1');
    expect(added?.nodeKeyNew).toBe('node_modules/flatmap-stream');
  });

  it('flags an upgraded package', () => {
    const oldG = parseLockfile(mkLock({ name: 'root', version: '1.0.0', deps: { foo: '^1' } }, {
      'node_modules/foo': { version: '1.0.0' },
    }));
    const newG = parseLockfile(mkLock({ name: 'root', version: '1.0.0', deps: { foo: '^1' } }, {
      'node_modules/foo': { version: '1.0.1' },
    }));
    const changes = computeChangeset(oldG, newG);
    expect(changes).toHaveLength(1);
    expect(changes[0]).toMatchObject({ name: 'foo', kind: 'upgraded', oldVersion: '1.0.0', newVersion: '1.0.1' });
  });

  it('flags integrity-changed with same version', () => {
    const oldG = parseLockfile(mkLock({ name: 'root', version: '1.0.0', deps: { foo: '^1' } }, {
      'node_modules/foo': { version: '1.0.0', integrity: 'sha512-original=' },
    }));
    const newG = parseLockfile(mkLock({ name: 'root', version: '1.0.0', deps: { foo: '^1' } }, {
      'node_modules/foo': { version: '1.0.0', integrity: 'sha512-tampered=' },
    }));
    const changes = computeChangeset(oldG, newG);
    const intg = changes.find((c) => c.kind === 'integrity-changed');
    expect(intg).toBeDefined();
    expect(intg?.oldIntegrity).toBe('sha512-original=');
    expect(intg?.newIntegrity).toBe('sha512-tampered=');
  });

  it('emits deterministic order', () => {
    const oldG = parseLockfile(mkLock({ name: 'root', version: '1.0.0', deps: { a: '^1', b: '^1' } }, {
      'node_modules/a': { version: '1.0.0' },
      'node_modules/b': { version: '1.0.0' },
    }));
    const newG = parseLockfile(mkLock({ name: 'root', version: '1.0.0', deps: { a: '^1', b: '^1', c: '^1' } }, {
      'node_modules/a': { version: '1.0.1' },
      'node_modules/b': { version: '1.0.0' },
      'node_modules/c': { version: '1.0.0' },
    }));
    const changes1 = computeChangeset(oldG, newG);
    const changes2 = computeChangeset(oldG, newG);
    expect(JSON.stringify(changes1)).toBe(JSON.stringify(changes2));
  });

  it('flags removed packages', () => {
    const oldG = parseLockfile(mkLock({ name: 'root', version: '1.0.0', deps: { foo: '^1' } }, {
      'node_modules/foo': { version: '1.0.0' },
    }));
    const newG = parseLockfile(mkLock({ name: 'root', version: '1.0.0', deps: {} }, {}));
    const changes = computeChangeset(oldG, newG);
    expect(changes.some((c) => c.name === 'foo' && c.kind === 'removed')).toBe(true);
  });
});
