/**
 * python-install-hook-relocation — completeness-vector transform for the
 * `python-install-hook` class (STARTUP §3.5 sinks: `setup-py-cmdclass`,
 * `pyproject-entry-points`).
 *
 * The class covers install-time execution hooks in Python packaging: the
 * classic `setup.py cmdclass={"install": CustomInstall}` pattern (executes on
 * `pip install <pkg>`) and the newer `pyproject.toml` `[project.entry-points]`
 * mechanism. Both fire at install time — same class, two documented file
 * locations.
 *
 * The transform shipped here — `pySetupPyToPyproject` — is the Python analog
 * of the JS `preinstallToPostinstall` transform: MOVE the install hook to the
 * other documented location, unchanged in intent. Given a `setup.py` string
 * containing `setup(..., cmdclass={...})`, emit a `pyproject.toml` file body
 * with an equivalent `[project.entry-points]` section. The command name is
 * captured; the executed target is unchanged.
 *
 * The `family` is `code-location` (mirrors persistence-relocation.ts) because
 * the transform moves the payload from ONE source file (setup.py) to ANOTHER
 * (pyproject.toml). Content — the install-hook itself — is preserved; only
 * the file the scanner reads to find it changes.
 *
 * Output shape:
 *   Input `setup.py` with `cmdclass={"install": CustomInstall}` →
 *   Output is a multi-file marker payload similar to intoNestedFile:
 *     `# FILE: pyproject.toml\n[project.entry-points."distutils.commands"]\ninstall = "package_name:CustomInstall"\n`
 *
 * The marker prefix `# FILE: ` mirrors `intoNestedFile`'s `// FILE: ` — a
 * comment appropriate to the target language.
 *
 * ENGINE ROUTING NOTE — routed to `NO_ENGINE_DETECTOR_YET`. The assurance
 * runner has no Python scenario; and even when it does, install-hook detection
 * runs against a whole-package artifact (via `analyzeTarball`-style flow), not
 * against a single file. This transform pins the class's completeness surface
 * for the future wave that wires that flow.
 */

import type { CompletenessTransform } from './types.js';

/** Prefix for Python-style nested-file markers. Mirrors NESTED_FILE_MARKER_PREFIX. */
export const PY_NESTED_FILE_MARKER_PREFIX = '# FILE: ';

/** Extract a cmdclass entry `"NAME": ClassRef` from a setup.py source, if present. */
function findCmdclassEntry(source: string): { hook: string; target: string } | null {
  // Very rough — match `cmdclass={"install": SomeClass}` or with single quotes.
  // Real setup.py can be dynamic; that's out of scope for a completeness-vector
  // transform (we widen shapes we CAN transform; anything else is a no-op).
  const m = source.match(/cmdclass\s*=\s*\{\s*(['"])([A-Za-z_][A-Za-z0-9_]*)\1\s*:\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}/);
  if (!m) return null;
  return { hook: m[2], target: m[3] };
}

export const pySetupPyToPyproject: CompletenessTransform = {
  id: 'py-setup-py-to-pyproject',
  family: 'code-location',
  targetClass: 'python-install-hook',
  description:
    "Move a Python install hook from setup.py's cmdclass to pyproject.toml's [project.entry-points]. Same class (install-time execution), different location — completeness probe for the python-install-hook class.",
  transform(source, _seed): string {
    const entry = findCmdclassEntry(source);
    if (!entry) return source;
    // Emit a multi-file marker: original setup.py verbatim + a new pyproject.toml
    // fragment. Downstream unpackers that grok the marker prefix land each file
    // in place.
    const trimmed = source.endsWith('\n') ? source : `${source}\n`;
    const pyprojectBody =
      `[project.entry-points."distutils.commands"]\n` +
      `${entry.hook} = "package_name:${entry.target}"\n`;
    return (
      `${trimmed}` +
      `${PY_NESTED_FILE_MARKER_PREFIX}pyproject.toml\n${pyprojectBody}`
    );
  },
};
