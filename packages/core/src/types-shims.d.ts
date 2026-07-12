/**
 * Local type declarations for @yarnpkg/lockfile, which ships without types.
 * We only use `parse`; the classic yarn.lock format is stable.
 *
 * The package is CJS-only, so we consume it via a default import:
 *   `import yarnLockfile from '@yarnpkg/lockfile';`
 *   `const { parse } = yarnLockfile;`
 */
declare module '@yarnpkg/lockfile' {
  export interface ParseSuccess {
    type: 'success';
    object: Record<
      string,
      {
        version?: string;
        resolved?: string;
        integrity?: string;
        dependencies?: Record<string, string>;
        optionalDependencies?: Record<string, string>;
      }
    >;
  }
  export interface ParseFailure {
    type: 'merge' | 'conflict' | 'error';
    object: Record<string, unknown>;
  }
  export function parse(text: string): ParseSuccess | ParseFailure;
  export function stringify(object: unknown): string;
  const _default: {
    parse: typeof parse;
    stringify: typeof stringify;
  };
  export default _default;
}

/**
 * @webassemblyjs/wasm-parser also ships without types. We only use `decode`,
 * whose returned AST we walk defensively. The shape isn't fully typed here —
 * downstream code handles the AST via `unknown` and narrows.
 */
declare module '@webassemblyjs/wasm-parser' {
  export function decode(buf: Buffer | Uint8Array | ArrayBuffer, opts?: unknown): unknown;
}
