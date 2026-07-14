/**
 * Python-source capability extractor (P4c — ADR 0009 EcosystemAdapter).
 *
 * Reads Python source text and returns a `FileCapabilities` shape identical
 * to what the JS side produces. Detectors are ecosystem-agnostic — they
 * consume the `FileCapabilities` output, so the same NET/EXEC/ENV/FS/CODE/
 * OBF detectors that already run on npm work for PyPI without modification.
 *
 * NEVER executes any Python code (ADR 0005). We use TEXT-based extraction:
 *   - Regex sweeps for imports, function calls, string literals
 *   - Line-based cursor tracking so `Evidence.line` is meaningful
 *   - Light lexical de-Pythonisation (triple-quoted-string awareness so
 *     regexes don't false-match inside docstrings)
 *
 * A real Python AST would be better, but adding a JS-Python parser is out
 * of scope for P4c and would carry its own supply-chain risk. Every design
 * choice here favours SAFETY (fewer false negatives on the classes we've
 * enumerated) over completeness (some obscure Python syntax will slip past —
 * documented in the CAPABILITY-MAP as soft-warn where it applies).
 */

import * as crypto from 'node:crypto';
import type {
  FileCapabilities,
  EnvAccess,
  DynamicCodeSite,
  SuspiciousLiteral,
} from './finding.js';
import { shannonEntropy } from './capabilities.js';

/**
 * Python module names that indicate network egress. Mirrors NETWORK_MODULES
 * from capabilities.ts but for the Python stdlib + PyPI ecosystem.
 */
const PY_NETWORK_MODULES = new Set([
  // stdlib
  'urllib', 'urllib.request', 'urllib.parse', 'urllib.error',
  'http', 'http.client', 'http.server',
  'socket', 'socketserver', 'ssl',
  'ftplib', 'smtplib', 'poplib', 'imaplib', 'telnetlib', 'nntplib',
  'asyncio', 'asyncio.streams',
  // DNS-based covert exfil channel
  'socket.gethostbyname', 'socket.getaddrinfo',
  // ubiquitous PyPI HTTP libs
  'requests', 'httpx', 'aiohttp', 'urllib3', 'httplib2',
  // websockets / low-level
  'websocket', 'websockets', 'ws4py',
  // remote-execution shells that also carry network transports
  'paramiko', 'fabric', 'pexpect',
]);

/**
 * Python modules that constitute code-execution / process-launch primitives.
 */
const PY_EXEC_MODULES = new Set([
  'subprocess', 'os.system', 'os.popen', 'os.spawn', 'os.exec',
  'popen2', 'commands',
  'multiprocessing', 'threading',
  'ctypes', 'cffi',
  'pty', 'shlex',
  // Import machinery (equivalent of Node's Module._load)
  'importlib', 'importlib.util', 'importlib.machinery',
  'imp',   // legacy but still importable
  // Python-specific eval-ish
  'code', 'codeop', 'ast',    // ast.parse+compile is a dynamic-code pipeline
]);

const PY_FS_MODULES = new Set([
  'os', 'os.path', 'shutil', 'pathlib', 'io', 'tempfile',
  'glob', 'fnmatch', 'stat',
]);

/**
 * Sensitive environment variables the Python-side ENV detector cares about.
 * Kept separate from the JS SENSITIVE_ENV_KEYS because a Python payload
 * frequently targets a DIFFERENT set (Django SECRET_KEY, PYPI_TOKEN,
 * TWINE_PASSWORD, etc.) that has no npm-side analog.
 */
const PY_SENSITIVE_ENV_KEYS: readonly string[] = [
  // PyPI / pip credentials
  'PYPI_TOKEN', 'PYPI_API_TOKEN', 'PYPI_USERNAME', 'PYPI_PASSWORD',
  'TWINE_PASSWORD', 'TWINE_USERNAME', 'TWINE_REPOSITORY',
  // Common Python framework secrets
  'DJANGO_SECRET_KEY', 'FLASK_SECRET_KEY', 'SECRET_KEY',
  // Reuse the cross-language ones — they're just as sensitive to Python payloads
  'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
  'GITHUB_TOKEN', 'GH_TOKEN', 'GH_PAT',
  'OPENAI_API_KEY', 'ANTHROPIC_API_KEY',
  'STRIPE_SECRET_KEY', 'STRIPE_API_KEY',
  'NPM_TOKEN',   // yes, malicious Python has stolen NPM_TOKEN — cross-tooling harvest
  'HEROKU_API_KEY', 'NETLIFY_AUTH_TOKEN', 'VERCEL_TOKEN',
  'CLOUDFLARE_API_TOKEN', 'DIGITALOCEAN_TOKEN',
  'DATABASE_URL', 'MONGO_URL', 'REDIS_URL', 'POSTGRES_URL',
  'DOCKER_PASSWORD', 'DOCKER_AUTH_CONFIG',
  'SLACK_TOKEN', 'DISCORD_TOKEN', 'DISCORD_WEBHOOK',
  'JWT_SECRET', 'AUTH_SECRET', 'SESSION_SECRET',
  // Wallet / crypto
  'MNEMONIC', 'PRIVATE_KEY', 'WALLET_PRIVATE_KEY', 'SEED_PHRASE',
  // Host fingerprint
  'HOME', 'USER', 'USERNAME',
];
const PY_SENSITIVE_SET = new Set(PY_SENSITIVE_ENV_KEYS);
void PY_SENSITIVE_SET; // Retained for future direct-lookup detector; env access recording is class-based.

const URL_REGEX = /\b(https?:\/\/[^\s'"`<>]+|(?:[a-z0-9-]+\.){1,}(?:com|net|org|io|dev|co|app|xyz|ru|cn|tk|ml|ga|cf|invalid|top|pw|zip|click|info|us|biz|mobi|icu|host|online|club|cloud|site|work|stream|party|science|today|link|fit|men|rest|space|store|shop|tech|world|life|guru|pro|name|example|test|localhost))\b/gi;

/** Which file extensions we treat as Python source for capability extraction. */
export function isPythonSource(rel: string): boolean {
  // .py, .pyi (stubs — still text), .pyx (cython source — sometimes shipped as .py-shaped text)
  return /\.(py|pyi|pyx)$/i.test(rel);
}

/**
 * Extract Python-file capabilities from source text.
 *
 * Called by the pypi adapter's analyzer path for each `.py` file in the
 * extracted artifact (wheel or sdist). Runs entirely on TEXT — no
 * `pyparser`, no `py_ast`, no execution. Best-effort by design: certain
 * exotic idioms (dynamically constructed import names, `__import__` with
 * fully-computed strings) are recorded as `dynamic-code` sites so
 * downstream analysis knows the file has an unresolved code-execution
 * primitive, even when the actual imported module is opaque to us.
 */
export function extractPythonCapabilities(
  filePath: string,
  text: string,
  sha256Hex: string,
  bytes: number,
): FileCapabilities {
  const base: FileCapabilities = {
    path: filePath,
    bytes,
    sha256: sha256Hex,
    entropy: shannonEntropy(text),
    minified: false, // Python isn't minified in the JS sense; we use different signals below
    networkModules: [],
    execModules: [],
    fsModules: [],
    urlLiterals: [],
    encodedUrls: [],
    envAccesses: [],
    dynamicCode: [],
    fsWriteTargets: [],
    fsReadTargets: [],
    suspiciousLiterals: [],
  };

  // Skip totally empty / whitespace-only files
  if (text.trim().length === 0) return base;

  // Mask out triple-quoted strings and single-line strings so subsequent
  // regexes don't fire inside docstrings. We keep line numbers stable by
  // replacing chars with spaces (preserving \n).
  const stripped = maskPythonStrings(text);

  const netMods = new Set<string>();
  const execMods = new Set<string>();
  const fsMods = new Set<string>();
  const urls = new Set<string>();
  const envAccesses: EnvAccess[] = [];
  const dynamicCode: DynamicCodeSite[] = [];
  const fsWriteTargets = new Set<string>();
  const fsReadTargets = new Set<string>();
  const suspiciousLiterals: SuspiciousLiteral[] = [];

  const lines = stripped.split('\n');
  const rawLines = text.split('\n');

  // 1) Imports.  `import X`, `import X as Y`, `from X import Y`, `from X.Y import Z`.
  //    ALSO: `importlib.import_module("X")` — dynamic import (record as dynamic-code).
  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx]!;
    // Import statement
    const impMatch = line.match(/^\s*(?:import|from)\s+([A-Za-z_][\w.]*)/);
    if (impMatch) {
      const mod = impMatch[1]!;
      trackPyModule(mod, netMods, execMods, fsMods);
      // Also track submodule shape: `from urllib import request` → urllib.request is exercised
      const fromForm = line.match(/^\s*from\s+([A-Za-z_][\w.]*)\s+import\s+(.+)$/);
      if (fromForm) {
        const parent = fromForm[1]!;
        for (const name of fromForm[2]!.split(',')) {
          const clean = name.trim().split(/\s+as\s+/)[0]!.trim();
          if (clean && clean !== '*') {
            trackPyModule(`${parent}.${clean}`, netMods, execMods, fsMods);
          }
        }
      }
    }

    // Dynamic import primitives — `__import__`, `importlib.import_module`
    if (/\b__import__\s*\(/.test(line) || /\bimportlib(?:\.util)?\.import_module\s*\(/.test(line)) {
      dynamicCode.push({
        line: idx + 1,
        kind: 'dynamic-require',
        snippet: rawLines[idx]!.slice(0, 240).trim(),
      });
      execMods.add('importlib'); // record the module category too
    }

    // `exec(...)`, `eval(...)`, `compile(..., "<string>", "exec")`
    //  - Python top-level builtins that execute arbitrary strings.
    if (/\bexec\s*\(/.test(line)) {
      dynamicCode.push({
        line: idx + 1,
        kind: 'eval',
        snippet: rawLines[idx]!.slice(0, 240).trim(),
      });
    }
    if (/\beval\s*\(/.test(line)) {
      dynamicCode.push({
        line: idx + 1,
        kind: 'eval',
        snippet: rawLines[idx]!.slice(0, 240).trim(),
      });
    }
    if (/\bcompile\s*\(/.test(line)) {
      // Only fires when the third argument is 'exec' — signals eval-of-string.
      // Needs raw line to see the string literal.
      if (/\bcompile\s*\([\s\S]*?['"]exec['"]/.test(rawLines[idx]!)) {
        dynamicCode.push({
          line: idx + 1,
          kind: 'new-function',
          snippet: rawLines[idx]!.slice(0, 240).trim(),
        });
      }
    }

    // marshal.loads() — Python's pickled-bytecode loader; equivalent of `new Function(codeBytes)`.
    // Used by attackers to hide payload as compiled .pyc bytes.
    if (/\bmarshal\.loads?\s*\(/.test(line)) {
      dynamicCode.push({
        line: idx + 1,
        kind: 'new-function',
        snippet: rawLines[idx]!.slice(0, 240).trim(),
      });
      execMods.add('marshal');
    }

    // subprocess.* — treat as exec.new-module
    if (/\bsubprocess\.(?:run|call|Popen|check_output|check_call)\b/.test(line)) {
      execMods.add('subprocess');
    }
    // os.system / os.popen / os.exec* / os.spawn*
    if (/\bos\.(?:system|popen|exec[lv][ep]?|spawn[lv][ep]?)\b/.test(line)) {
      execMods.add('os.system');
    }

    // ENV access — os.environ[X] or os.environ.get(X)
    //
    // NOTE: these patterns need the STRING KEY inside the brackets, which
    // maskPythonStrings has replaced with spaces in `line`. So we scan the
    // RAW line for env-access. This is safe here — the outer shape
    // (`os.environ`, `os.getenv`) is not itself a string, so if it appears
    // outside a comment or a docstring it IS an env access. Any occurrence
    // inside a triple-quoted docstring is stripped from `line` — for
    // safety, we gate on the masked line ALSO containing `os.environ` /
    // `os.getenv` (identifier form survives masking) so we don't fire on
    // literals like `msg = "os.environ['KEY']"`.
    const rawLine = rawLines[idx]!;
    const hasEnvironInCode = /\bos\.environ\b/.test(line);
    const hasGetenvInCode = /\bos\.getenv\b/.test(line);
    if (hasEnvironInCode) {
      for (const m of rawLine.matchAll(/\bos\.environ\.get\s*\(\s*['"]([A-Z_][A-Z0-9_]*)['"]/g)) {
        envAccesses.push({
          line: idx + 1,
          keys: [m[1]!],
          snippet: rawLine.slice(0, 240).trim(),
        });
      }
      // Direct subscript: os.environ['KEY'] or os.environ["KEY"]
      for (const m of rawLine.matchAll(/\bos\.environ\s*\[\s*['"]([A-Z_][A-Z0-9_]*)['"]/g)) {
        envAccesses.push({
          line: idx + 1,
          keys: [m[1]!],
          snippet: rawLine.slice(0, 240).trim(),
        });
      }
      // Whole-object enumeration: os.environ (iteration or unpacking)
      //   - for k in os.environ:
      //   - for k, v in os.environ.items():
      //   - dict(os.environ)
      //   - list(os.environ)
      //   - {**os.environ}
      if (
        /\bfor\s+\w+(?:\s*,\s*\w+)?\s+in\s+os\.environ\b/.test(line) ||
        /\bdict\s*\(\s*os\.environ\b/.test(line) ||
        /\blist\s*\(\s*os\.environ\b/.test(line) ||
        /\{\s*\*\*\s*os\.environ\b/.test(line) ||
        /\bos\.environ\.(?:items|keys|values)\s*\(/.test(line)
      ) {
        envAccesses.push({
          line: idx + 1,
          keys: null,
          snippet: rawLine.slice(0, 240).trim(),
        });
      }
    }
    if (hasGetenvInCode) {
      // getenv shorthand: os.getenv('X') / os.getenv("X", default)
      for (const m of rawLine.matchAll(/\bos\.getenv\s*\(\s*['"]([A-Z_][A-Z0-9_]*)['"]/g)) {
        envAccesses.push({
          line: idx + 1,
          keys: [m[1]!],
          snippet: rawLine.slice(0, 240).trim(),
        });
      }
    }

    // FS writes — open(path, 'w'|'a'|'wb'|'ab'|'x'|'w+') / pathlib write_*, shutil.copy
    // Same string-content-inside-quotes situation as env access above — need raw
    // line for the path. Gate on masked line containing the outer identifier so a
    // string literal `msg = "open('/etc/passwd')"` doesn't fire.
    if (/\bopen\s*\(/.test(line)) {
      for (const m of rawLine.matchAll(/\bopen\s*\(\s*['"]([^'"]+)['"]\s*,\s*['"]([warxb+]{1,3})['"]/g)) {
        const target = m[1]!;
        const mode = m[2]!;
        if (/[waxWAX+]/.test(mode)) {
          fsWriteTargets.add(target);
        } else {
          fsReadTargets.add(target);
        }
      }
      // open(path)  — default mode is 'r' (read).
      // Only match `open('...')` with a SINGLE argument (no comma). We scan the
      // raw arg list up to the closing paren and skip any occurrence that has
      // a `,` between the string and `)`.
      for (const m of rawLine.matchAll(/\bopen\s*\(\s*['"]([^'"]+)['"]\s*\)/g)) {
        fsReadTargets.add(m[1]!);
      }
    }
    if (/\bPath\s*\(/.test(line)) {
      // pathlib: Path('...').write_text / write_bytes / read_text / read_bytes
      for (const m of rawLine.matchAll(/\bPath\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\.\s*(write_text|write_bytes|read_text|read_bytes)/g)) {
        const target = m[1]!;
        const op = m[2]!;
        if (op.startsWith('write')) fsWriteTargets.add(target);
        else fsReadTargets.add(target);
      }
    }
    if (/\bshutil\./.test(line)) {
      // shutil.copy(src, dst) — record dst as write target
      for (const m of rawLine.matchAll(/\bshutil\.(?:copy|copyfile|move)\s*\(\s*['"][^'"]+['"]\s*,\s*['"]([^'"]+)['"]/g)) {
        fsWriteTargets.add(m[1]!);
      }
    }
    if (/\bos\.(?:remove|unlink|rmdir)\b/.test(line)) {
      // os.remove / os.unlink / os.rmdir
      for (const m of rawLine.matchAll(/\bos\.(?:remove|unlink|rmdir)\s*\(\s*['"]([^'"]+)['"]/g)) {
        fsWriteTargets.add(m[1]!);
      }
    }

    // URL literals — from RAW line (not stripped) so we catch URLs inside strings.
    // Skip pure docstring lines by re-checking the stripped mask has SOMETHING on this line.
    if (line.trim().length > 0) {
      for (const m of rawLines[idx]!.matchAll(URL_REGEX)) {
        urls.add(m[0]);
      }
    }
  }

  // 2) High-entropy / suspicious literals (obfuscation candidates).
  //    We walk the RAW text for long string literals (both single-line and
  //    multi-line) and record the ones with entropy > 4.5 bits/byte.
  for (const lit of extractPythonStringLiterals(text)) {
    if (lit.value.length >= 200) {
      const h = shannonEntropy(lit.value);
      if (h > 4.5) {
        suspiciousLiterals.push({
          line: lit.line,
          length: lit.value.length,
          entropy: h,
          preview: lit.value.slice(0, 40),
        });
      }
    }
    // Encoded URL probe — base64.b64decode / hex-encoded / bytes.fromhex
    // We include these as URLs when the decoded content contains a URL.
    if (lit.value.length >= 24 && lit.value.length <= 4096) {
      const dec = tryDecodePyUrl(lit.value);
      if (dec) {
        urls.add(dec);
      }
    }
  }

  // 3) base64 + exec obfuscation shape.
  //    Attackers do:  exec(base64.b64decode("....").decode())
  //    or             exec(base64.b64decode("....."))
  //    We already recorded `exec(...)` above. Add a specific dynamic-code
  //    signature for the *combination* of "text also contains b64decode AND
  //    also contains exec". Fires per-file, not per-line — the two calls
  //    don't have to be on the same line.
  if (/\bbase64\.b64decode\s*\(/.test(text) && /\bexec\s*\(/.test(text)) {
    dynamicCode.push({
      line: 1,
      kind: 'char-arithmetic-decoder',
      snippet: 'file uses base64.b64decode + exec — encoded-payload shape',
    });
  }

  // 4) __import__ with a computed string  →  dynamic-require
  //    Also chr() joined string  →  per-char decoder (equivalent to char-arithmetic-decoder in JS)
  if (/(?:''\.join|"".join)\s*\(\s*\[?\s*chr\s*\(/.test(text)) {
    dynamicCode.push({
      line: 1,
      kind: 'char-arithmetic-decoder',
      snippet: 'file uses chr() join — per-char decoder shape',
    });
  }

  return {
    ...base,
    networkModules: [...netMods].sort(),
    execModules: [...execMods].sort(),
    fsModules: [...fsMods].sort(),
    urlLiterals: [...urls].sort(),
    envAccesses,
    dynamicCode,
    fsWriteTargets: [...fsWriteTargets].sort(),
    fsReadTargets: [...fsReadTargets].sort(),
    suspiciousLiterals,
  };
}

/**
 * Analyse `setup.py` — a common Python install-hook entry point. Return an
 * object suitable for merging into a package snapshot's manifest so the
 * existing INSTALL detector fires when a hostile setup.py appears.
 *
 * We look for:
 *   - Top-level side-effect calls (os.system(...), subprocess.*(...), download()...
 *     etc. outside of `if __name__ == "__main__":` guards)
 *   - `cmdclass={'install': CustomInstaller}` with a class overriding `run(self)`
 *     that has side effects
 *   - `entry_points={'console_scripts': [...]}`
 *
 * The returned `scripts` field ports the hostile parts into the SAME shape
 * the JS install detector expects (postinstall/preinstall/install keys).
 * That lets Python packages share the existing detector code without
 * inventing a new detector.
 */
export interface PythonInstallHooks {
  /** Freeform scripts to merge into `manifest.scripts` for install detector consumption. */
  scripts: Record<string, string>;
  /** Extra evidence rows (file/line/snippet) — passed to the finding's evidence list. */
  evidence: Array<{ file: string; line: number; snippet: string }>;
}

export function analyzeSetupPy(setupPyText: string): PythonInstallHooks {
  const hooks: PythonInstallHooks = { scripts: {}, evidence: [] };
  if (!setupPyText || setupPyText.trim().length === 0) return hooks;

  const stripped = maskPythonStrings(setupPyText);
  const lines = stripped.split('\n');
  const rawLines = setupPyText.split('\n');

  // Look for top-level side-effect calls. A "top level" line here is one with
  // no leading whitespace (Python indents everything inside functions/classes).
  const dangerousPatterns: Array<{ pattern: RegExp; label: string }> = [
    { pattern: /\bos\.system\s*\(/, label: 'os.system' },
    { pattern: /\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\(/, label: 'subprocess.exec' },
    { pattern: /\bos\.popen\s*\(/, label: 'os.popen' },
    { pattern: /\burllib\.request\.urlopen\s*\(/, label: 'urllib.urlopen' },
    { pattern: /\brequests\.(?:get|post|put)\s*\(/, label: 'requests.http' },
    { pattern: /\bhttpx\.(?:get|post|put)\s*\(/, label: 'httpx.http' },
    { pattern: /\bsocket\.socket\s*\(/, label: 'socket.socket' },
    { pattern: /\bexec\s*\(/, label: 'exec' },
    { pattern: /\beval\s*\(/, label: 'eval' },
  ];

  const sideEffects: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    // Only flag top-level lines (no leading indent) — a function body's exec
    // is only invoked if someone calls it, but a top-level exec runs at import.
    if (/^[ \t]/.test(line)) continue;
    for (const { pattern, label } of dangerousPatterns) {
      if (pattern.test(line)) {
        sideEffects.push(`${label}: ${rawLines[i]!.trim().slice(0, 200)}`);
        hooks.evidence.push({
          file: 'setup.py',
          line: i + 1,
          snippet: rawLines[i]!.slice(0, 240).trim(),
        });
      }
    }
  }

  if (sideEffects.length > 0) {
    // Feed into the SAME `install.script-added` finding that npm postinstall
    // generates.  We use the 'install' key (the closest semantic equivalent
    // to setup.py — pip runs setup.py at install time).
    hooks.scripts.install = `[setup.py side-effects] ${sideEffects.join(' ; ').slice(0, 400)}`;
  }

  // cmdclass=... with custom installer — declaring one is itself a signal
  // even if we can't tell what it does. Record it.
  if (/\bcmdclass\s*=/.test(stripped)) {
    if (!hooks.scripts.install) {
      hooks.scripts.install = '[setup.py] custom cmdclass= override (install lifecycle hijack)';
    } else {
      hooks.scripts.install += ' [+cmdclass override]';
    }
    hooks.evidence.push({
      file: 'setup.py',
      line: findFirstLineMatching(stripped, /\bcmdclass\s*=/),
      snippet: 'cmdclass= override present — install lifecycle hijack',
    });
  }

  // console_scripts entry points — the bin/ equivalent for Python.
  // We record but do NOT auto-flag; the install detector reads scripts, not
  // entry_points, so this stays as a side-channel record.
  return hooks;
}

/**
 * Analyse pyproject.toml — Python's package.json equivalent. Extract entry
 * points and script hooks so the install/bin detectors can see them.
 */
export interface PyprojectHooks {
  entryPoints: Array<{ name: string; target: string }>;
  scripts: Record<string, string>;
}

export function analyzePyproject(pyprojectText: string): PyprojectHooks {
  const hooks: PyprojectHooks = { entryPoints: [], scripts: {} };
  if (!pyprojectText) return hooks;

  // We don't need a full TOML parse here — regex sweeps for the specific
  // fields we care about are enough.  A dedicated capability-pypi.test.ts
  // pins these shapes.
  //
  //  [project.scripts]
  //  my-tool = "mymod:main"
  //
  //  [project.entry-points."console_scripts"]
  //  other = "mod:fn"
  //
  //  [tool.poetry.scripts]
  //  cli = "pkg.cli:main"
  const scriptSectionRe = /\[(?:project\.scripts|tool\.poetry\.scripts|project\.entry-points\."[^"]+")\]/;
  const sections = pyprojectText.split(/(?=^\[)/m);
  for (const sec of sections) {
    if (!scriptSectionRe.test(sec.split('\n')[0] ?? '')) continue;
    for (const line of sec.split('\n')) {
      const m = line.match(/^\s*([A-Za-z_][\w-]*)\s*=\s*['"]([^'"]+)['"]/);
      if (m) {
        hooks.entryPoints.push({ name: m[1]!, target: m[2]! });
      }
    }
  }
  return hooks;
}

// ---------- Helpers ---------------------------------------------------------

function trackPyModule(
  mod: string,
  netMods: Set<string>,
  execMods: Set<string>,
  fsMods: Set<string>,
): void {
  const root = mod.split('.')[0]!;
  if (PY_NETWORK_MODULES.has(mod) || PY_NETWORK_MODULES.has(root)) {
    netMods.add(mod);
  }
  if (PY_EXEC_MODULES.has(mod) || PY_EXEC_MODULES.has(root)) {
    execMods.add(mod);
  }
  if (PY_FS_MODULES.has(mod) || PY_FS_MODULES.has(root)) {
    fsMods.add(mod);
  }
}

/**
 * Replace the contents of Python string literals (single, double, triple)
 * with spaces so the caller's regexes don't false-match on URLs / keywords
 * inside docstrings. Preserves line numbers by keeping \n intact.
 *
 * This is a small state-machine walk — a real Python tokenizer would be
 * ideal, but for the finite subset of string shapes we care about this is
 * sound and simple.
 */
function maskPythonStrings(text: string): string {
  const out: string[] = [];
  let i = 0;
  while (i < text.length) {
    // Check for triple-quote
    if (text.startsWith('"""', i) || text.startsWith("'''", i)) {
      const q = text.slice(i, i + 3);
      const end = text.indexOf(q, i + 3);
      if (end === -1) {
        // Unterminated — mask to end of file (preserving newlines)
        for (let j = i; j < text.length; j++) {
          out.push(text[j] === '\n' ? '\n' : ' ');
        }
        break;
      }
      // Emit spaces (or newlines) for the entire triple-quoted range including delimiters
      for (let j = i; j < end + 3; j++) {
        out.push(text[j] === '\n' ? '\n' : ' ');
      }
      i = end + 3;
      continue;
    }
    // Single/double quote — mask until matching close (or EOL — Python single-line strings can't cross \n)
    if (text[i] === '"' || text[i] === "'") {
      const q = text[i]!;
      let j = i + 1;
      while (j < text.length && text[j] !== q && text[j] !== '\n') {
        if (text[j] === '\\' && j + 1 < text.length) { j += 2; continue; }
        j++;
      }
      // Emit spaces for the entire span [i, j]
      for (let k = i; k <= j; k++) {
        out.push(text[k] === '\n' ? '\n' : ' ');
      }
      i = j + 1;
      continue;
    }
    // Comment — line comment, mask till EOL
    if (text[i] === '#') {
      while (i < text.length && text[i] !== '\n') { out.push(' '); i++; }
      continue;
    }
    out.push(text[i]!);
    i++;
  }
  return out.join('');
}

/** Extract string literals with their line numbers. */
interface PyLiteral { value: string; line: number; }
function extractPythonStringLiterals(text: string): PyLiteral[] {
  const out: PyLiteral[] = [];
  let i = 0;
  let line = 1;
  while (i < text.length) {
    const c = text[i]!;
    if (c === '\n') { line++; i++; continue; }
    // Skip comments
    if (c === '#') {
      while (i < text.length && text[i] !== '\n') i++;
      continue;
    }
    // Triple-quoted
    if (text.startsWith('"""', i) || text.startsWith("'''", i)) {
      const q = text.slice(i, i + 3);
      const startLine = line;
      const end = text.indexOf(q, i + 3);
      if (end === -1) break;
      const body = text.slice(i + 3, end);
      out.push({ value: body, line: startLine });
      // Advance line counter
      for (let j = i; j < end + 3; j++) if (text[j] === '\n') line++;
      i = end + 3;
      continue;
    }
    // Single or double quote
    if (c === '"' || c === "'") {
      const q = c;
      const startLine = line;
      let j = i + 1;
      let body = '';
      while (j < text.length && text[j] !== q && text[j] !== '\n') {
        if (text[j] === '\\' && j + 1 < text.length) {
          body += text[j + 1];
          j += 2;
          continue;
        }
        body += text[j]!;
        j++;
      }
      out.push({ value: body, line: startLine });
      if (j < text.length && text[j] === '\n') line++;
      i = j + 1;
      continue;
    }
    i++;
  }
  return out;
}

/** Try to decode base64 or hex content as text containing a URL. */
function tryDecodePyUrl(literal: string): string | null {
  const isBase64 = /^[A-Za-z0-9+/=_-]+$/.test(literal) && literal.length % 4 <= 1;
  const isHex = /^[0-9a-fA-F]+$/.test(literal) && literal.length % 2 === 0;
  const attempt = (enc: BufferEncoding): string | null => {
    try {
      const dec = Buffer.from(literal, enc).toString('utf8');
      let printable = 0;
      for (let i = 0; i < dec.length; i++) {
        const cc = dec.charCodeAt(i);
        if ((cc >= 32 && cc < 127) || cc === 9 || cc === 10 || cc === 13) printable++;
      }
      if (printable / dec.length < 0.9) return null;
      const m = URL_REGEX.exec(dec);
      URL_REGEX.lastIndex = 0;
      return m ? m[0]! : null;
    } catch {
      return null;
    }
  };
  if (isBase64) {
    const url = attempt('base64');
    if (url) return url;
  }
  if (isHex) {
    const url = attempt('hex');
    if (url) return url;
  }
  return null;
}

function findFirstLineMatching(text: string, re: RegExp): number {
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i]!)) return i + 1;
  }
  return 1;
}

/** Utility: sha256 hex of a buffer. Re-exported for adapter callers. */
export function sha256HexOf(buf: Buffer): string {
  return crypto.createHash('sha256').update(buf).digest('hex');
}
