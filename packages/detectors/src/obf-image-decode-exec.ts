/**
 * OBF image-decode-exec — new image asset that is read, decoded, then handed
 * to a dynamic-code sink (eval / new Function / vm.*).
 *
 * Port from guarddog:threat-runtime-obfuscation-steganography — audit §4 row 9.
 *
 * Attacker shape: hide a JS payload inside a PNG/JPG/GIF/BMP, ship the image
 * as a regular asset in `assets/logo.png`, then at runtime:
 *
 *   const data = fs.readFileSync('./assets/logo.png');
 *   const code = Buffer.from(data.slice(...LSB-decode...)).toString('utf8');
 *   new Function(code)();          // or eval(code), vm.runInThisContext(code)
 *
 * Static byte-level scanners see a valid image. AST scanners see a
 * fs.readFileSync + a new Function — nothing links the two. This detector
 * connects them: a NEW image asset in `pair.new` (or a CHANGED one) whose
 * path shows up as an fs-read target AND lives in a package that has a
 * dynamic-code sink in ANY file.
 *
 * Signal is co-occurrence — the image alone is not a signal, the sink alone
 * is not a signal, both together on a diff-tier addition is one.
 *
 * FP guardrails:
 *   - Only fires when the read path literally references an image file (by
 *     extension) — reading a `.mjs` isn't image steganography.
 *   - Requires the sink to be in the SAME snapshot version (co-occurrence),
 *     which the diff-mode filter already enforces because we only look at
 *     pair.new.files.
 *   - Requires the image path to be a genuine ADD or CHANGE — a package that
 *     always had `logo.png` and always had a `new Function` is either legit
 *     or already flagged by other detectors.
 *
 * NEVER-EXECUTE (ADR 0005): reads only PackageSnapshot data already produced
 * by the core analyzer.
 */

import type { Detector, Finding, PackageSnapshot, SnapshotPair, FileCapabilities } from '@vetlock/core';

const IMAGE_EXTENSIONS = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.tiff', '.ico'];

function isImagePath(p: string): boolean {
  const lower = p.toLowerCase();
  return IMAGE_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

function collectImageReadTargets(files: FileCapabilities[]): Map<string, FileCapabilities[]> {
  // Map from image path to the files that read it (via fsReadTargets literal-arg).
  const readers = new Map<string, FileCapabilities[]>();
  for (const f of files) {
    for (const target of f.fsReadTargets ?? []) {
      if (!isImagePath(target)) continue;
      const arr = readers.get(target) ?? [];
      arr.push(f);
      readers.set(target, arr);
    }
  }
  return readers;
}

function packageHasDynamicSink(snap: PackageSnapshot): FileCapabilities | null {
  for (const f of snap.files) {
    if ((f.dynamicCode ?? []).some((s) => s.kind === 'eval' || s.kind === 'new-function' || s.kind === 'vm')) {
      return f;
    }
  }
  return null;
}

function newImageAssets(pair: SnapshotPair): string[] {
  const newImages = (pair.new?.files ?? []).filter((f) => isImagePath(f.path)).map((f) => f.path);
  if (!pair.old) return newImages;
  const oldByPath = new Map(pair.old.files.map((f) => [f.path, f]));
  const out: string[] = [];
  for (const nf of pair.new!.files) {
    if (!isImagePath(nf.path)) continue;
    const of = oldByPath.get(nf.path);
    if (!of || of.sha256 !== nf.sha256) out.push(nf.path);
  }
  return out;
}

export const imageDecodeExecDetector: Detector = {
  id: 'obf-image-decode-exec',
  category: 'OBF',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    // Sink co-occurrence: package must ship a dynamic-code primitive.
    const sinkFile = packageHasDynamicSink(pair.new);
    if (!sinkFile) return [];
    // Image assets: must be NEW / CHANGED in this version.
    const newImgs = new Set(newImageAssets(pair));
    if (newImgs.size === 0) return [];
    // Reader co-occurrence: SOME file in pair.new must fsReadTarget the image path.
    const readers = collectImageReadTargets(pair.new.files);
    const hits: Array<{ imagePath: string; readerPath: string }> = [];
    for (const imgPath of newImgs) {
      // Try exact match first, then match by basename (a file that reads
      // "logo.png" while the tarball path is "assets/logo.png" is a real
      // hit — literal args aren't always path-qualified).
      const exact = readers.get(imgPath);
      if (exact && exact.length > 0) {
        hits.push({ imagePath: imgPath, readerPath: exact[0]!.path });
        continue;
      }
      const bare = imgPath.split('/').pop()!;
      for (const [key, arr] of readers) {
        if (arr.length === 0) continue;
        if (key === bare || key.endsWith('/' + bare)) {
          hits.push({ imagePath: imgPath, readerPath: arr[0]!.path });
          break;
        }
      }
    }
    if (hits.length === 0) return [];
    const isAdd = pair.old === null;
    return hits.map(({ imagePath, readerPath }) => ({
      detector: 'obf.image-decode-exec',
      category: 'OBF',
      package: pair.new!.name,
      from: pair.old?.version ?? null,
      to: pair.new!.version,
      direction: isAdd ? ('added' as const) : ('changed' as const),
      severity: 'WARN' as const, // runAll escalation covers co-occurrence with NET/INSTALL/etc.
      confidence: 'medium' as const,
      message:
        `Package ships a new/changed image asset "${imagePath}" that is read via fs at "${readerPath}", ` +
        `and the same version ships a dynamic-code sink at "${sinkFile.path}". ` +
        'Image steganography shape (read image bytes → decode → eval). ' +
        'Ported from guarddog:threat-runtime-obfuscation-steganography.',
      evidence: [
        {
          file: readerPath,
          line: 1,
          snippet: `fsRead("${imagePath}") + dynamic-code sink in ${sinkFile.path}`.slice(0, 240),
        },
      ],
      provenance: [],
    }));
  },
};
