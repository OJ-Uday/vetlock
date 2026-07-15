import { describe, it, expect } from 'vitest';
import {
  parseLockfile,
  shortestPaths,
  UnsupportedLockfileError,
} from '../src/lockfile.js';

/** Build a lockfile fixture as a plain object. */
function lock(root: { name: string; version: string; deps?: Record<string, string> }, entries: Record<string, {
  version: string;
  integrity?: string;
  deps?: Record<string, string>;
  resolved?: string;
}>) {
  const packages: Record<string, unknown> = {
    '': { name: root.name, version: root.version, dependencies: root.deps ?? {} },
  };
  for (const [key, val] of Object.entries(entries)) {
    // Derive package name from lockfile key: last 'node_modules/X' segment → X
    const idx = key.lastIndexOf('node_modules/');
    const derivedName = idx === -1 ? key : key.slice(idx + 'node_modules/'.length);
    packages[key] = {
      name: derivedName,
      version: val.version,
      integrity: val.integrity ?? `sha512-${val.version}=`,
      resolved: val.resolved ?? `https://registry/${val.version}.tgz`,
      dependencies: val.deps ?? {},
    };
  }
  return { name: root.name, version: root.version, lockfileVersion: 3, packages };
}

describe('parseLockfile', () => {
  it('rejects lockfileVersion 1', () => {
    expect(() =>
      parseLockfile({ lockfileVersion: 1, packages: {} }),
    ).toThrow(UnsupportedLockfileError);
  });

  it('rejects missing packages map', () => {
    expect(() =>
      parseLockfile({ lockfileVersion: 3 }),
    ).toThrow(UnsupportedLockfileError);
  });

  it('parses a simple root + one direct dep', () => {
    const g = parseLockfile(
      lock({ name: 'root', version: '1.0.0', deps: { foo: '^1.0.0' } }, {
        'node_modules/foo': { version: '1.2.3' },
      }),
    );
    expect(g.rootName).toBe('root');
    expect(g.nodes.size).toBe(2); // root + foo
    const foo = g.nodes.get('node_modules/foo')!;
    expect(foo.name).toBe('foo');
    expect(foo.version).toBe('1.2.3');
    // Root should have foo as a child
    const root = g.nodes.get('')!;
    expect(root.dependencies).toContain('node_modules/foo');
  });

  it('resolves transitive deps via ancestor walk', () => {
    // root → a@1 → b@1  (b is hoisted to top-level node_modules)
    const g = parseLockfile(
      lock({ name: 'root', version: '1.0.0', deps: { a: '^1' } }, {
        'node_modules/a': { version: '1.0.0', deps: { b: '^1' } },
        'node_modules/b': { version: '1.0.0' },
      }),
    );
    const a = g.nodes.get('node_modules/a')!;
    expect(a.dependencies).toContain('node_modules/b');
  });

  it('resolves nested-level deps too', () => {
    // b appears BOTH at top-level (b@1) AND nested under a (b@2). a should resolve to nested one.
    const g = parseLockfile(
      lock({ name: 'root', version: '1.0.0', deps: { a: '^1' } }, {
        'node_modules/a': { version: '1.0.0', deps: { b: '^2' } },
        'node_modules/a/node_modules/b': { version: '2.0.0' },
        'node_modules/b': { version: '1.0.0' },
      }),
    );
    const a = g.nodes.get('node_modules/a')!;
    expect(a.dependencies).toContain('node_modules/a/node_modules/b');
  });
});

describe('shortestPaths (provenance)', () => {
  it('finds root → direct dep', () => {
    const g = parseLockfile(
      lock({ name: 'root', version: '1.0.0', deps: { foo: '^1' } }, {
        'node_modules/foo': { version: '1.0.0' },
      }),
    );
    const paths = shortestPaths(g, 'node_modules/foo');
    expect(paths).toHaveLength(1);
    expect(paths[0]).toEqual(['root', 'foo']);
  });

  it('finds root → a → b for a transitive dep', () => {
    const g = parseLockfile(
      lock({ name: 'root', version: '1.0.0', deps: { a: '^1' } }, {
        'node_modules/a': { version: '1.0.0', deps: { b: '^1' } },
        'node_modules/b': { version: '1.0.0' },
      }),
    );
    const paths = shortestPaths(g, 'node_modules/b');
    expect(paths).toHaveLength(1);
    expect(paths[0]).toEqual(['root', 'a', 'b']);
  });


  it('handles a circular dependency without looping forever', () => {
    const g = parseLockfile(
      lock({ name: 'root', version: '1.0.0', deps: { a: '^1' } }, {
        'node_modules/a': { version: '1.0.0', deps: { b: '^1' } },
        'node_modules/b': { version: '1.0.0', deps: { a: '^1' } },
      }),
    );

    expect(g.nodes.get('node_modules/b')!.dependencies).toContain('node_modules/a');
    expect(shortestPaths(g, 'node_modules/b')).toEqual([['root', 'a', 'b']]);
  });

  it('returns both shortest paths for a diamond dependency graph', () => {
    const g = parseLockfile(
      lock({ name: 'root', version: '1.0.0', deps: { a: '^1', b: '^1' } }, {
        'node_modules/a': { version: '1.0.0', deps: { c: '^1' } },
        'node_modules/b': { version: '1.0.0', deps: { c: '^1' } },
        'node_modules/c': { version: '1.0.0' },
      }),
    );

    const paths = shortestPaths(g, 'node_modules/c');
    expect(paths).toHaveLength(2);
    expect(paths).toEqual([
      ['root', 'a', 'c'],
      ['root', 'b', 'c'],
    ]);
  });

  it('handles a 10-level deep dependency chain', () => {
    const entries: Record<string, { version: string; deps?: Record<string, string> }> = {};
    const names = ['a','b','c','d','e','f','g','h','i','j'];
    for (let index = 0; index < names.length; index += 1) {
      const name = names[index]!;
      const next = names[index + 1];
      entries[`node_modules/${name}`] = {
        version: '1.0.0',
        deps: next ? { [next]: '^1' } : undefined,
      };
    }

    const g = parseLockfile(lock({ name: 'root', version: '1.0.0', deps: { a: '^1' } }, entries));
    expect(shortestPaths(g, 'node_modules/j')).toEqual([['root', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j']]);
  });

  it('finds a deep chain', () => {
    // root → a → b → c → d  (5 levels)
    const g = parseLockfile(
      lock({ name: 'root', version: '1.0.0', deps: { a: '^1' } }, {
        'node_modules/a': { version: '1.0.0', deps: { b: '^1' } },
        'node_modules/b': { version: '1.0.0', deps: { c: '^1' } },
        'node_modules/c': { version: '1.0.0', deps: { d: '^1' } },
        'node_modules/d': { version: '1.0.0' },
      }),
    );
    const paths = shortestPaths(g, 'node_modules/d');
    expect(paths).toHaveLength(1);
    expect(paths[0]).toEqual(['root', 'a', 'b', 'c', 'd']);
  });
});
