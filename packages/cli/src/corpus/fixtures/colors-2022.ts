/**
 * colors 1.4.44-liberty-2 (Jan 2022) — T4 protestware / maintainer sabotage.
 *
 * Marak Squires, maintainer of colors + faker, deliberately released
 * corrupted versions of his own packages ("Liberty Liberty Liberty" printed
 * in ASCII + infinite loops) as protest.
 *
 * THE HARD CASE. This is exactly the attack shape vetlock cannot catch
 * reliably: no new capabilities. colors already wrote to stdout, already used
 * setInterval, already contained ASCII art strings. The malice is logic —
 * a `while(true) console.log(...)` — using functions it always had.
 *
 * We publish this as an HONEST MISS. Mitigations exist (OBF entropy jump,
 * unusually long ASCII string literals) but they're weak. Publishing the
 * miss is worth more than pretending we catch it.
 */

import type { FixtureSpec } from '../fixture-spec.js';

const CLEAN_INDEX = `// colors 1.4.0 — real behavior stubbed.
'use strict';
function red(s) { return '\\u001b[31m' + s + '\\u001b[0m'; }
function green(s) { return '\\u001b[32m' + s + '\\u001b[0m'; }
module.exports = { red: red, green: green };
`;

// The infamous liberty payload. Uses only capabilities colors already had:
// console.log + a loop. Defanged: the loop is behind if(false).
const MAL_INDEX = `'use strict';
function red(s) { return '\\u001b[31m' + s + '\\u001b[0m'; }
function green(s) { return '\\u001b[32m' + s + '\\u001b[0m'; }
if (false) {
  while (true) {
    console.log('LIBERTY LIBERTY LIBERTY');
    console.log('   __  _  _         _   _         _____ ');
    console.log('  |  |[_][_]       [_] [_]       [_____]');
    console.log('  |  |[_][_]       [_] [_]        [___] ');
    console.log('  |__|              _   _          _|_  ');
  }
}
module.exports = { red: red, green: green };
`;

export const spec: FixtureSpec = {
  id: 'colors-2022',
  title: 'colors 1.4.44-liberty-2 (Jan 2022)',
  year: 2022,
  threatClass: 'T4 protestware / maintainer sabotage',
  summary:
    'Maintainer intentionally published a version of colors that printed "LIBERTY LIBERTY LIBERTY" in an infinite console.log loop, breaking every downstream that used colors for CLI output. Similar sabotage in faker.',
  provenance: 'RECONSTRUCTED',
  topology: 'direct',
  clean: {
    name: 'colors',
    version: '1.4.0',
    manifest: {
      name: 'colors',
      version: '1.4.0',
      main: 'index.js',
      license: 'MIT',
      maintainers: [{ email: 'marak@example' }],
    },
    files: { 'index.js': CLEAN_INDEX },
  },
  malicious: {
    name: 'colors',
    version: '1.4.44',
    manifest: {
      name: 'colors',
      version: '1.4.44',
      main: 'index.js',
      license: 'MIT',
      maintainers: [{ email: 'marak@example' }], // same maintainer — this is the point
    },
    files: { 'index.js': MAL_INDEX },
  },
  expect: {
    // NO mustFire — we honestly admit vetlock cannot catch this.
    // Optional: the OBF detector MIGHT fire on the ASCII-art string entropy shift.
    mustFire: [],
    verdict: 'CLEAN',     // <-- vetlock will say CLEAN. That's the honest answer.
    known_limitation:
      'Protestware / logic sabotage using ONLY capabilities the package already had. No new network, no new install script, no new fs write, no obfuscation. vetlock is designed as a behavioral DIFFER — this is why we publish this attack as a MISS. Manual code review is still the only line of defense here.',
  },
};
