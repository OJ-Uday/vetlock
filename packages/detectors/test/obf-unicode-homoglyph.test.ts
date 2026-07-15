import { describe, it, expect } from 'vitest';
import { validateFinding } from '@vetlock/core';
import { obfUnicodeHomoglyphDetector, firstHomoglyphSample } from '../src/obf-unicode-homoglyph.js';
import { mkSnap, mkFile } from './helpers.js';

describe('obf.unicode-homoglyph-boundary (port from guarddog:threat-runtime-obfuscation-unicode)', () => {
  it('POS: fires on URL literal with Cyrillic small a adjacent to ASCII (paypаl.com)', () => {
    // `paypаl.com` — `а` here is U+0430 CYRILLIC SMALL LETTER A.
    const homoglyphFile = mkFile({
      path: 'lib/redirect.js',
      urlLiterals: ['https://paypаl.com/checkout'],
    });
    const pair = {
      old: null,
      new: mkSnap({ name: 'sketchy-pkg', version: '1.0.0', files: [homoglyphFile] }),
    };
    const findings = obfUnicodeHomoglyphDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.detector).toBe('obf.unicode-homoglyph-boundary');
    expect(f.category).toBe('OBF');
    expect(f.severity).toBe('WARN');
    expect(f.evidence[0]!.file).toBe('lib/redirect.js');
    expect(validateFinding(f)).toBeNull();
  });

  it('POS: fires on Greek omicron inside an identifier snippet', () => {
    // `gοogle` where `ο` is U+03BF GREEK SMALL LETTER OMICRON.
    const file = mkFile({
      path: 'src/api.js',
      dynamicCode: [
        {
          line: 5,
          kind: 'new-function',
          snippet: 'const url = "https://gοogle-api.example.com/token"; new Function(payload);',
        },
      ],
    });
    const pair = {
      old: null,
      new: mkSnap({ name: 'sketchy-pkg', version: '1.0.0', files: [file] }),
    };
    const findings = obfUnicodeHomoglyphDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('WARN');
  });

  it('NEG: clean ASCII-only content does not fire', () => {
    const file = mkFile({
      path: 'lib/normal.js',
      urlLiterals: ['https://example.com/api'],
      dynamicCode: [{ line: 1, kind: 'eval', snippet: 'eval("2+2")' }],
    });
    const pair = {
      old: null,
      new: mkSnap({ name: 'legit-pkg', version: '1.0.0', files: [file] }),
    };
    expect(obfUnicodeHomoglyphDetector.run(pair, { direction: 'added' })).toEqual([]);
  });

  it('NEG: content that is entirely non-ASCII does not fire (no boundary)', () => {
    // A whole-Japanese comment or Chinese error message should NOT trip the
    // detector — it has no ASCII↔non-ASCII adjacency within the sample.
    const file = mkFile({
      path: 'lib/i18n.js',
      dynamicCode: [{ line: 1, kind: 'eval', snippet: 'const msg = "エラーが発生しました";' }],
    });
    const pair = {
      old: null,
      new: mkSnap({ name: 'i18n-pkg', version: '1.0.0', files: [file] }),
    };
    // The snippet has ASCII (`const msg = "`) adjacent to the first Japanese char.
    // Japanese is NOT in our confusable set (only Cyrillic/Greek/Cherokee/Math)
    // so no boundary should trigger.
    expect(obfUnicodeHomoglyphDetector.run(pair, { direction: 'added' })).toEqual([]);
  });

  it('NEG: does not fire on JSON files (path filter)', () => {
    const file = mkFile({
      path: 'data.json',
      urlLiterals: ['https://paypаl.com/api'], // Cyrillic а
    });
    const pair = {
      old: null,
      new: mkSnap({ name: 'data-pkg', version: '1.0.0', files: [file] }),
    };
    expect(obfUnicodeHomoglyphDetector.run(pair, { direction: 'added' })).toEqual([]);
  });

  it('DIFF-SAFE: does not fire when the SAME homoglyph was already in pair.old', () => {
    const oldFile = mkFile({
      path: 'lib/redirect.js',
      urlLiterals: ['https://paypаl.com/checkout'], // Cyrillic а — already there
    });
    const newFile = mkFile({
      path: 'lib/redirect.js',
      urlLiterals: ['https://paypаl.com/checkout'], // still there
    });
    const pair = {
      old: mkSnap({ name: 'foo', version: '1.0.0', files: [oldFile] }),
      new: mkSnap({ name: 'foo', version: '1.0.1', files: [newFile] }),
    };
    expect(obfUnicodeHomoglyphDetector.run(pair, { direction: 'changed' })).toEqual([]);
  });

  it('DIFF: fires when a homoglyph appears in an existing file that was clean before', () => {
    const oldFile = mkFile({
      path: 'lib/redirect.js',
      urlLiterals: ['https://paypal.com/checkout'], // pure ASCII
    });
    const newFile = mkFile({
      path: 'lib/redirect.js',
      urlLiterals: ['https://paypаl.com/checkout'], // Cyrillic а introduced
    });
    const pair = {
      old: mkSnap({ name: 'foo', version: '1.0.0', files: [oldFile] }),
      new: mkSnap({ name: 'foo', version: '1.0.1', files: [newFile] }),
    };
    const findings = obfUnicodeHomoglyphDetector.run(pair, { direction: 'changed' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.direction).toBe('changed');
    expect(findings[0]!.from).toBe('1.0.0');
  });

  it('helper: firstHomoglyphSample returns the offending sample', () => {
    const f = mkFile({
      path: 'a.js',
      urlLiterals: ['https://benign.com', 'https://paypаl.com'], // second has Cyrillic а
    });
    const sample = firstHomoglyphSample(f);
    expect(sample).toContain('paypаl.com');
  });
});
