/**
 * Regression tests for red-team confirmed exploits L1, L2, L3, L5, L8, L10.
 * @security-critical
 *
 * These six exploits share a root cause: the AST visitors in capabilities.ts
 * match specific literal AST shapes only. Trivially-equivalent forms slip
 * past. The fix in this worktree teaches the analyzer to bind at the VALUE
 * level for the specific shapes we know attackers use.
 *
 * Reference: docs/REDTEAM-2026-07-12.md sections L1, L2, L3, L5, L8, L10.
 */

import { describe, it, expect } from 'vitest';
import { extractCapabilities } from '../src/capabilities.js';

function cap(source: string) {
  return extractCapabilities('test.js', source, 'sha256-fake', source.length);
}

describe('REDTEAM L1: destructured process.env should register envAccesses', () => {
  it('fires on `const { NPM_TOKEN } = process.env`', () => {
    const c = cap(`const { NPM_TOKEN } = process.env;`);
    expect(c.envAccesses.length).toBeGreaterThanOrEqual(1);
    const keys = c.envAccesses.flatMap((a) => a.keys ?? []);
    expect(keys).toContain('NPM_TOKEN');
  });

  it('fires on multi-key destructuring — records EACH sensitive key', () => {
    const c = cap(
      `const { NPM_TOKEN, GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY } = process.env;`,
    );
    const keys = c.envAccesses.flatMap((a) => a.keys ?? []);
    expect(keys).toContain('NPM_TOKEN');
    expect(keys).toContain('GITHUB_TOKEN');
    expect(keys).toContain('AWS_SECRET_ACCESS_KEY');
  });

  it('fires on `const { NPM_TOKEN: t } = process.env` (renamed destructure)', () => {
    const c = cap(`const { NPM_TOKEN: t } = process.env;`);
    const keys = c.envAccesses.flatMap((a) => a.keys ?? []);
    expect(keys).toContain('NPM_TOKEN');
  });

  it('fires on nested destructure through alias: `const env = process.env; const { NPM_TOKEN } = env`', () => {
    const c = cap(
      `const env = process.env; const { NPM_TOKEN } = env;`,
    );
    const keys = c.envAccesses.flatMap((a) => a.keys ?? []);
    expect(keys).toContain('NPM_TOKEN');
  });
});

describe('REDTEAM L2: whole-object process.env enumeration variants', () => {
  it('fires on spread: `const s = {...process.env}`', () => {
    const c = cap(`const s = {...process.env};`);
    // Whole-object enumeration → keys === null OR a wildcard marker
    const whole = c.envAccesses.filter((a) => a.keys === null);
    expect(whole.length).toBeGreaterThanOrEqual(1);
  });

  it('fires on `for (const k in process.env) {}`', () => {
    const c = cap(`for (const k in process.env) {}`);
    const whole = c.envAccesses.filter((a) => a.keys === null);
    expect(whole.length).toBeGreaterThanOrEqual(1);
  });

  it('fires on `Reflect.ownKeys(process.env)`', () => {
    const c = cap(`const keys = Reflect.ownKeys(process.env);`);
    const whole = c.envAccesses.filter((a) => a.keys === null);
    expect(whole.length).toBeGreaterThanOrEqual(1);
  });

  it('fires on `Object.assign({}, process.env)` (existing baseline should still work)', () => {
    const c = cap(`const x = Object.assign({}, process.env);`);
    const whole = c.envAccesses.filter((a) => a.keys === null);
    expect(whole.length).toBeGreaterThanOrEqual(1);
  });

  it('fires on rest destructure: `const { ...rest } = process.env`', () => {
    const c = cap(`const { ...rest } = process.env;`);
    const whole = c.envAccesses.filter((a) => a.keys === null);
    expect(whole.length).toBeGreaterThanOrEqual(1);
  });
});

describe('REDTEAM L3: require-like callees other than bare `require(...)`', () => {
  it('records child_process on `require.call(null, "child_process")`', () => {
    const c = cap(`const cp = require.call(null, 'child_process');`);
    expect(c.execModules).toContain('child_process');
  });

  it('records child_process on `require.apply(null, ["child_process"])`', () => {
    const c = cap(`const cp = require.apply(null, ['child_process']);`);
    expect(c.execModules).toContain('child_process');
  });

  it('records child_process on `process.mainModule.require("child_process")`', () => {
    const c = cap(`const cp = process.mainModule.require('child_process');`);
    expect(c.execModules).toContain('child_process');
  });

  it('records http on `Module._load("http")` (module.constructor._load pattern)', () => {
    const c = cap(`const h = module.constructor._load('http');`);
    expect(c.networkModules).toContain('http');
  });
});

describe('REDTEAM L5: Reflect-based process.env access', () => {
  it('records NPM_TOKEN on `Reflect.get(process.env, "NPM_TOKEN")`', () => {
    const c = cap(`const t = Reflect.get(process.env, 'NPM_TOKEN');`);
    const keys = c.envAccesses.flatMap((a) => a.keys ?? []);
    expect(keys).toContain('NPM_TOKEN');
  });

  it('records via `Reflect.get(process, "env").NPM_TOKEN` (two-step)', () => {
    const c = cap(
      `const env = Reflect.get(process, 'env'); const t = env.NPM_TOKEN;`,
    );
    const keys = c.envAccesses.flatMap((a) => a.keys ?? []);
    expect(keys).toContain('NPM_TOKEN');
  });
});

describe('REDTEAM L8: computed property alias for process.env', () => {
  it('resolves `const env = process["env"]; env.NPM_TOKEN`', () => {
    const c = cap(`const env = process["env"]; const t = env.NPM_TOKEN;`);
    const keys = c.envAccesses.flatMap((a) => a.keys ?? []);
    expect(keys).toContain('NPM_TOKEN');
  });

  it('resolves via fold: `const env = process["e" + "nv"]; env.NPM_TOKEN`', () => {
    const c = cap(`const env = process["e" + "nv"]; const t = env.NPM_TOKEN;`);
    const keys = c.envAccesses.flatMap((a) => a.keys ?? []);
    expect(keys).toContain('NPM_TOKEN');
  });
});

describe('REDTEAM L10: eval-wrapped require', () => {
  it('records exec.new-module on `eval("require(\'child_process\')")`', () => {
    const c = cap(`const cp = eval("require('child_process')");`);
    expect(c.execModules).toContain('child_process');
  });

  it('records net.new-module on `new Function("return require(\'https\')")()`', () => {
    const c = cap(
      `const h = new Function("return require('https')")();`,
    );
    expect(c.networkModules).toContain('https');
  });

  it('resolves the eval arg through fold: `eval("requ" + "ire(\'child_process\')")`', () => {
    const c = cap(
      `const cp = eval("requ" + "ire('child_process')");`,
    );
    expect(c.execModules).toContain('child_process');
  });

  it('still records the eval as a dynamic-code site (parallel signal preserved)', () => {
    const c = cap(`const cp = eval("require('child_process')");`);
    expect(c.dynamicCode.some((d) => d.kind === 'eval')).toBe(true);
  });
});
