import { defineConfig } from 'tsup';

// Bundles the CLI into a single self-contained dist/cli.js (CJS) and
// dist/index.js (CJS) so the published `vetlock` package has NO dependency
// on the private, unpublishable workspace packages @vetlock/core and
// @vetlock/detectors — their source is inlined at build time.
//
// Everything else (commander, ora, tar, zod, @babel/*, pacote, semver,
// ssri, js-yaml, @yarnpkg/*, @webassemblyjs/*, damerau-levenshtein, and all
// transitive deps pulled in by those) stays external and resolves normally
// from node_modules at install time — see package.json `dependencies`.
export default defineConfig({
  entry: {
    cli: 'src/cli.ts',
    index: 'src/index.ts',
  },
  // The package keeps "type": "module" (dev/typecheck/corpus scripts under
  // src/ rely on plain `tsc -p .` producing ESM .js — see the root `build`
  // script, and several corpus scripts use import.meta.url, which tsc
  // rejects for a CJS-inferred program). Bundling to ESM keeps dist/cli.js
  // and dist/index.js consistent with that "type": "module" — Node will
  // parse them as ESM, `import.meta.url` works natively, and the bin path
  // stays exactly ./dist/cli.js as it was before bundling.
  format: ['esm'],
  platform: 'node',
  target: 'node20',
  // Inline the private workspace packages; everything in node_modules
  // (real third-party npm packages) stays external and is resolved by the
  // installer at install time, not bundled into our tarball.
  noExternal: ['@vetlock/core', '@vetlock/detectors'],
  // dts: type declarations are still produced by `tsc -p .` in the plain
  // `build` script (dist/*.d.ts); tsup's own dts generation is skipped here
  // to avoid fighting the existing tsc-driven .d.ts output.
  dts: false,
  sourcemap: true,
  clean: true,
  // tsup auto-detects and preserves the source file's own shebang
  // (#!/usr/bin/env node) on entries that have one — no banner needed.
  splitting: false,
  shims: true,
});
