import { describe, it, expect } from 'vitest';
import { extractCapabilities } from '@vetlock/core';

function cap(source: string) {
  return extractCapabilities('fixture.js', source, 'sha256-fixture', source.length);
}

describe('encoding regression coverage', () => {
  it('records an obfuscation signal for atob(rot13(...)) decoder chains', () => {
    const source = `
      function rot13(input) {
        return input.replace(/[A-Za-z]/g, (char) => {
          const base = char >= 'a' ? 97 : 65;
          return String.fromCharCode(((char.charCodeAt(0) - base + 13) % 26) + base);
        });
      }
      const decoded = atob(rot13('nUE0pQbiL2I4LJAjL2R4LJ91oTImL29goJ5='));
      console.log(decoded);
    `;

    const capabilities = cap(source);
    expect(capabilities.dynamicCode.some((entry) => entry.kind === 'char-arithmetic-decoder')).toBe(true);
  });

  it('normalizes unicode escape sequences into URL literals', () => {
    const capabilities = cap('const target = "\u0068\u0074\u0074\u0070://unicode.example.invalid/path";');
    expect(capabilities.urlLiterals).toContain('http://unicode.example.invalid/path');
  });

  it('normalizes hex escape sequences into URL literals', () => {
    const capabilities = cap('const target = "\x68\x74\x74\x70://hex.example.invalid/path";');
    expect(capabilities.urlLiterals).toContain('http://hex.example.invalid/path');
  });
});
