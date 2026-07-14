/**
 * code-location — move the payload to a different location in the package layout
 * WITHOUT changing its semantics. If the scanner only looks at `index.js`, or only
 * looks at JavaScript files, or only looks at the package's declared `main`, the
 * capability class is location-incomplete.
 *
 * The two transforms shipped here:
 *
 *   • intoLifecycleScript — wrap the payload as the string body of a
 *     `postinstall` script in a package.json. When npm installs the package, the
 *     script runs. A scanner that only reads `.js`/`.ts` files and never inspects
 *     `package.json.scripts.postinstall` misses this class of exploit.
 *
 *   • intoNestedFile — emit a directive header that moves the payload from
 *     `index.js` into `lib/util.js`. The payload content is unchanged. A scanner
 *     that only reads the entry point (`main`) never sees the file.
 *
 * The `transform(source, seed) => string` return value is:
 *   • for intoLifecycleScript — a serialized package.json fragment (JSON string)
 *     whose `scripts.postinstall` invokes `node -e <source>`.
 *   • for intoNestedFile — a multi-file marker: the source verbatim, prefixed
 *     with `// FILE: lib/util.js`. The completeness driver that consumes the
 *     output knows to unpack this marker into the scanner's file layout.
 *
 * Both transforms preserve the payload's semantics char-for-char inside the
 * wrapper — nothing about the payload's meaning changes.
 */

import type { CompletenessTransform } from './types.js';

export const intoLifecycleScript: CompletenessTransform = {
  id: 'into-lifecycle-script',
  family: 'code-location',
  targetClass: 'code-execution',
  description:
    'Move the payload from a source file into package.json scripts.postinstall. Class is code-execution regardless of where the string body lives.',
  transform(source, _seed): string {
    // Use JSON.stringify to embed the source safely inside `node -e "<source>"`.
    // Escapes control chars, backslashes, and quotes per JSON spec — no hand-rolled
    // escaping and no defanging surprises for downstream readers.
    const pkg = {
      name: 'defanged-fixture',
      version: '0.0.0',
      scripts: {
        postinstall: `node -e ${JSON.stringify(source)}`,
      },
    };
    return JSON.stringify(pkg, null, 2);
  },
};

/**
 * The multi-file marker recognised by the completeness driver. Lines that match
 * `// FILE: <relpath>` on their own start a new file's content; everything after
 * (until the next marker or EOF) is that file's body.
 *
 * Exported so the driver's un-packer can share the exact prefix.
 */
export const NESTED_FILE_MARKER_PREFIX = '// FILE: ';

export const intoNestedFile: CompletenessTransform = {
  id: 'into-nested-file',
  family: 'code-location',
  targetClass: 'code-execution',
  description:
    'Move the payload from index.js into lib/util.js. Content unchanged; only the file path changes. Scanners that only read the declared main entrypoint miss it.',
  transform(source, _seed): string {
    // Emit a marker followed by the payload verbatim. Ensure trailing newline so
    // consumers with `split("\n")` boundaries don't glue the next marker onto the
    // payload.
    const trimmed = source.endsWith('\n') ? source : `${source}\n`;
    return `${NESTED_FILE_MARKER_PREFIX}lib/util.js\n${trimmed}`;
  },
};
