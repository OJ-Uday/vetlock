import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const packageJson = JSON.parse(
  readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8'),
) as {
  name: string;
  bin: Record<string, string>;
  publishConfig: Record<string, unknown>;
};

describe('published CLI package metadata', () => {
  it('publishes under the maintainer scope while retaining the vetlock command', () => {
    expect(packageJson.name).toBe('@oj-uday/vetlock');
    expect(packageJson.bin).toEqual({ vetlock: './dist/cli.js' });
    expect(packageJson.publishConfig).toMatchObject({ access: 'public', provenance: true });
  });
});
