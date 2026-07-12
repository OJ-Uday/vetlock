/**
 * WASM binary import extraction.
 *
 * Uses @webassemblyjs/wasm-parser (the reference parser used by webpack).
 * Extracts import descriptors — `(module, name, kind)` — from a WASM binary.
 *
 * WHY we care: a package can ship a legitimate .wasm binary today, then push
 * an update whose new .wasm imports `env.eval`, `wasi_snapshot_preview1.fd_write`,
 * or an attacker-controlled JS glue module. Without parsing the binary we're
 * blind to what changed inside it — only whether the file hash changed.
 *
 * Per security principle (docs/SECURITY-DECISIONS.md): we do NOT execute the
 * WASM. We parse its static structure — same guarantee as the AST layer for JS.
 */

import { decode } from '@webassemblyjs/wasm-parser';

export interface WasmImport {
  module: string;
  name: string;
  kind: 'func' | 'table' | 'memory' | 'global' | 'unknown';
}

export interface WasmSummary {
  imports: WasmImport[];
  /** Bytes size — used by the BIN detector to gate expensive parsing. */
  bytes: number;
  /** True iff parsing succeeded. False → the file wasn't a valid WASM binary. */
  parsed: boolean;
  parseError?: string;
}

/**
 * WASM magic bytes: '\0asm' (0x00 0x61 0x73 0x6d).
 */
export function isWasmBinary(buf: Buffer): boolean {
  if (buf.length < 8) return false;
  return (
    buf[0] === 0x00 &&
    buf[1] === 0x61 &&
    buf[2] === 0x73 &&
    buf[3] === 0x6d
  );
}

/**
 * Parse a WASM binary and return its import list. On any failure returns
 * a summary with `parsed: false` — we do NOT throw, we fail-soft. A pathological
 * or corrupt WASM binary is itself signal (surfaced via the analyzer's
 * `parseError` path) — but never a runtime crash.
 */
export function summarizeWasm(buf: Buffer): WasmSummary {
  const summary: WasmSummary = {
    imports: [],
    bytes: buf.length,
    parsed: false,
  };
  if (!isWasmBinary(buf)) {
    summary.parseError = 'not a WASM binary (magic bytes missing)';
    return summary;
  }
  // Cap what we hand to the parser: some malicious WASM binaries are gigabytes
  // of one section repeated. 20 MiB is generous for any legitimate npm-shipped
  // WASM (usual sizes: 50 KB — 5 MB for even large libraries).
  if (buf.length > 20 * 1024 * 1024) {
    summary.parseError = `WASM binary too large to parse safely (${buf.length} bytes)`;
    return summary;
  }
  try {
    // Pass an ArrayBuffer slice to the parser. The parser's options object
    // exists but we pass defaults — we only need Import section info.
    const ast = decode(buf);
    const imports: WasmImport[] = [];
    walkForImports(ast, imports);
    summary.imports = imports;
    summary.parsed = true;
  } catch (err) {
    summary.parseError = err instanceof Error ? err.message.slice(0, 240) : String(err);
  }
  return summary;
}

// Recursive walk — the @webassemblyjs AST puts imports in a program.body's
// module.fields array with type 'ModuleImport'. We walk defensively because
// the AST shape has version-to-version variance.
function walkForImports(node: unknown, out: WasmImport[]): void {
  if (!node || typeof node !== 'object') return;
  const anyNode = node as { type?: string; module?: string; name?: string; descr?: { type?: string }; body?: unknown[]; fields?: unknown[] };
  if (anyNode.type === 'ModuleImport' && typeof anyNode.module === 'string' && typeof anyNode.name === 'string') {
    out.push({
      module: anyNode.module,
      name: anyNode.name,
      kind: kindOf(anyNode.descr?.type),
    });
  }
  if (Array.isArray(anyNode.body)) for (const c of anyNode.body) walkForImports(c, out);
  if (Array.isArray(anyNode.fields)) for (const c of anyNode.fields) walkForImports(c, out);
}

function kindOf(descrType?: string): WasmImport['kind'] {
  switch (descrType) {
    case 'FuncImportDescr': return 'func';
    case 'TableImportDescr': return 'table';
    case 'MemoryImportDescr': return 'memory';
    case 'GlobalImportDescr': return 'global';
    default: return 'unknown';
  }
}
