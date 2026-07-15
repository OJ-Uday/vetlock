/**
 * MITRE ATT&CK Enterprise technique tags per detector id.
 *
 * Source: https://attack.mitre.org/matrices/enterprise/
 *
 * Rules:
 *   - Every detector-emitted finding SHOULD carry 1-3 techniques.
 *   - Technique IDs match /^T\d{4}(\.\d{3})?$/ (parent tactics or sub-techniques).
 *   - Prefer sub-techniques (T1059.007 JavaScript) over parents (T1059) when
 *     the mapping is precise. Fall back to the parent when the sub-technique
 *     lookup would be misleading.
 *   - Conservative: use at most 3 techniques. When no ATT&CK technique is a good
 *     fit, entry can be an empty array (rare — we lean toward citing).
 *
 * Consumers:
 *   - `tagFinding(f)` in this module attaches `mitre` in-place and returns f.
 *   - detector.ts files call this once per emitted Finding.
 *   - The finding-schema validator (validateFinding in @vetlock/core) accepts
 *     `mitre` as optional; findings without it are still valid.
 */

// Technique reference (Enterprise matrix):
//   T1059         Command and Scripting Interpreter  (parent)
//   T1059.006     Python
//   T1059.007     JavaScript
//   T1195         Supply Chain Compromise            (parent)
//   T1195.002     Compromise Software Supply Chain
//   T1552         Unsecured Credentials              (parent)
//   T1552.001     Credentials In Files
//   T1552.005     Cloud Instance Metadata API
//   T1078         Valid Accounts
//   T1027         Obfuscated Files or Information
//   T1140         Deobfuscate/Decode Files or Information
//   T1573         Encrypted Channel
//   T1071         Application Layer Protocol
//   T1071.001     Web Protocols
//   T1041         Exfiltration Over C2 Channel
//   T1567         Exfiltration Over Web Service
//   T1005         Data from Local System
//   T1074         Data Staged
//   T1105         Ingress Tool Transfer
//   T1547         Boot or Logon Autostart Execution
//   T1554         Compromise Client Software Binary
//   T1587.001     Develop Capabilities: Malware
//   T1608         Stage Capabilities
//   T1608.001     Upload Malware
//   T1583.001     Acquire Infrastructure: Domains
//   T1036         Masquerading
//   T1036.005     Match Legitimate Name or Location
//   T1499         Endpoint Denial of Service
//   T1055         Process Injection

export const MITRE_TAGS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  // ============ INSTALL — supply-chain compromise via lifecycle scripts.
  // A published package with a preinstall/install/postinstall script that
  // reaches beyond build tooling is the canonical supply-chain-compromise
  // technique. Attacker executes JS interpreter at install time.
  'install.script-added': ['T1195.002', 'T1059.007'],
  'install.script-changed': ['T1195.002', 'T1059.007'],
  'install.bundled-lifecycle': ['T1195.002', 'T1059.007'],

  // ============ META — maintainer takeover / account compromise.
  'meta.maintainer-change': ['T1078', 'T1195.002'],

  // ============ NET — new outbound calls / exfil endpoints.
  // A newly-imported network module or new URL literal is the exfil-channel
  // side of the kill chain (T1041 C2, T1071.001 web protocols); T1567 covers
  // web-service exfil (pastebins, transfer.sh, discord webhooks).
  'net.new-module': ['T1071.001', 'T1041'],
  'net.new-endpoint': ['T1071.001', 'T1041', 'T1567'],
  'net.encoded-endpoint': ['T1027', 'T1140', 'T1573'],

  // ============ EXEC — child_process / new interpreter capability.
  'exec.new-module': ['T1059.007', 'T1059'],

  // ============ FS — file-system reach.
  // Writes to hot autoload paths → autostart / persistence (T1547).
  'fs.new-hotpath-write': ['T1547', 'T1554'],
  // Reads of secret-shaped files → credentials-in-files (T1552.001)
  // plus metadata endpoint reads (T1552.005 for IMDS-style).
  'fs.new-hotpath-read': ['T1552.001', 'T1005'],

  // ============ ENV — env-var harvesting for secrets.
  // Enumerating process.env is credentials-in-files by another surface, and
  // when combined with a subsequent NET call is data-staging (T1074) into an
  // exfil pipeline.
  'env.token-harvest': ['T1552.001', 'T1074'],

  // ============ CODE — dynamic sinks (eval, new Function, VM contexts).
  // Dynamic code execution and downloaded-payload execution.
  'code.dynamic-loading-added': ['T1059.007', 'T1140', 'T1105'],

  // ============ OBF — obfuscated / high-entropy new file, entropy jump.
  'obf.entropy-jump': ['T1027', 'T1140'],
  'obf.new-obfuscated-file': ['T1027', 'T1140'],

  // ============ BIN — new native binary artifact.
  // Native artifacts extend compromise of a legit software binary to code
  // that vetlock cannot statically inspect; also masquerading if named
  // like a legit component.
  'bin.new-native-artifact': ['T1554', 'T1027'],

  // ============ WASM — suspicious WASM imports / unparseable.
  'wasm.suspicious-import': ['T1027', 'T1055'],
  'wasm.unparseable': ['T1027'],

  // ============ DEPS — dependency-graph attacks: typosquat, aliasing,
  //                    workspace shadowing, first-version cluster.
  'deps.new-direct-dep': ['T1195.002'],
  'deps.typosquat-candidate': ['T1036.005', 'T1195.002', 'T1583.001'],
  'deps.first-version-cluster': ['T1195.002', 'T1608.001'],
  'deps.bundled-dependency-added': ['T1195.002', 'T1027'],
  'deps.workspace-shadowing': ['T1036.005', 'T1195.002'],
  'deps.aliased-name': ['T1036.005', 'T1195.002'],
  'deps.non-registry-source': ['T1195.002'],
  'deps.local-source': ['T1195.002'],

  // ============ INTEG — integrity tripwire.
  // Same version, different tarball hash — a registry-side or in-flight
  // tamper: compromise a legit binary already trusted in a lockfile.
  'integrity.hash-mismatch': ['T1554', 'T1195.002'],

  // ============ META engine-emitted / config-trust.
  // analysis.failed: an analyzer that could not process the artifact IS the
  // signal — an attacker who ships a malformed artifact to evade content
  // scanning is masquerading a legit-looking package as safe. No exfil/exec
  // technique fires yet — this is a defense-evasion posture.
  'analysis.failed': ['T1027'],
  'config.in-diff-untrusted': ['T1195.002'],
});

/**
 * Return the MITRE ATT&CK technique ID list for a detector id, or `[]` if
 * unmapped. Callers apply this to a Finding's `mitre` field. Frozen — mutations
 * are silently ignored.
 */
export function mitreTagsFor(detectorId: string): readonly string[] {
  return MITRE_TAGS[detectorId] ?? [];
}
