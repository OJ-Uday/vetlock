/**
 * clipboard-normalization — rewrite one clipboard-utility spelling to its POSIX
 * sibling. The clipboard class (packet §3.5) covers commands that read/write the
 * host clipboard, a documented staging surface for credential and secret exfil.
 * Two POSIX-shell utilities dominate the family:
 *
 *   • pbcopy / pbpaste   (macOS-native)
 *   • xclip / xsel       (Linux-common; both accept stdin via pipe)
 *
 * A scanner that keys on `pbcopy` but doesn't recognise `xclip` (or vice versa)
 * has a coverage gap along the exact axis this class describes — the SAME shell-
 * pipeline shape, targeting a DIFFERENT utility name, is still clipboard access.
 *
 * The transform shipped here — `execClipboardCall` — takes a string that contains
 * a defanged pipeline (e.g. `echo secret | pbcopy`) and rewrites the trailing
 * utility name to the sibling. `pbcopy` → `xclip -selection clipboard`, or if
 * the input already has xclip, it flips back to `pbcopy`. The pipeline SHAPE
 * and payload are preserved char-for-char up to the utility name.
 *
 * IMPORTANT — defang-clean invariants:
 *   • The SHELL COMMAND text stored in the input must use `echo <target>` as its
 *     data source. `echo` is on the defang guard's allow-list; a real payload
 *     command (e.g. `pbpaste` reading actual clipboard contents) would trip the
 *     guard. The transform preserves the source's shape, so if the caller keeps
 *     the input defang-clean, the output is defang-clean too.
 *   • The transform does NOT invent new command bodies; it only rewrites the
 *     tail utility name. Whatever was `echo <marker>` upstream stays that shape.
 *
 * Implementation: a targeted regex swap. This is not an AST transform because
 * shell command strings are typically STRING LITERALS or bare non-JS text, not
 * program-node contexts an AST rewriter would traverse. The regex matches the
 * whole POSIX-command word (with any inline flags) at the tail of a `|` pipeline.
 * If nothing matches, the transform is a no-op.
 */

import type { CompletenessTransform } from './types.js';

/** Match `| pbcopy` (with optional whitespace and no arguments). Preserves the
 *  leading pipe so the pipeline shape stays intact after replacement. */
const PBCOPY_RE = /(\|\s*)pbcopy\b/g;
/** Match `| xclip [-selection X]` — allow the common `-selection clipboard` flag
 *  chunk so we swap the WHOLE tail (not just the utility name and leave `-selection`
 *  orphaned). Note: this greedy chunk is bounded to a single line by `[^\r\n|;]*`. */
const XCLIP_RE = /(\|\s*)xclip(?:\s+-selection\s+\w+)?\b/g;

/** Canonical replacements. Kept as constants so the two ends of the swap are
 *  visible next to each other. */
const XCLIP_TAIL = 'xclip -selection clipboard';
const PBCOPY_TAIL = 'pbcopy';

export const execClipboardCall: CompletenessTransform = {
  id: 'exec-clipboard-call',
  family: 'sink-family-widening',
  targetClass: 'clipboard',
  description:
    'Rewrite a defanged shell clipboard pipeline (`echo <marker> | pbcopy`) to the sibling POSIX form (`echo <marker> | xclip -selection clipboard`), or vice versa. Same capability class, different utility.',
  transform(source, _seed): string {
    // Prefer pbcopy → xclip. If only xclip is present, flip the other way.
    if (PBCOPY_RE.test(source)) {
      PBCOPY_RE.lastIndex = 0;
      return source.replace(PBCOPY_RE, `$1${XCLIP_TAIL}`);
    }
    PBCOPY_RE.lastIndex = 0;
    if (XCLIP_RE.test(source)) {
      XCLIP_RE.lastIndex = 0;
      return source.replace(XCLIP_RE, `$1${PBCOPY_TAIL}`);
    }
    XCLIP_RE.lastIndex = 0;
    return source;
  },
};
