/**
 * @vetlock/assurance CAPABILITY-MAP — packet §3.5.
 *
 * The machine-readable enumeration of capability classes, sinks, and entry-points that
 * the completeness doctrine requires the engine to cover. Consumed by the P2 coverage
 * gate (packet §5 P2 done-gate: "coverage gate at 100% enumerated").
 *
 * Standalone assurance-side artifact until STARTUP §3.5 ships
 * `packages/detectors/src/capability-map.json`. When STARTUP lands its map, the loader
 * automatically prefers it. See ./README.md for the handoff plan.
 */

export type {
  CapabilityMap,
  CapabilityClass,
  CapabilityClassId,
  Sink,
  EntryPoint,
  EntryPoints,
  PerClassCoverage,
  CoverageReport,
} from './types.js';

export { loadCapabilityMap, CAPABILITY_CLASS_IDS, _resetStartupHandoffWarning } from './loader.js';

export { CoverageGate, type EntryPointAxis } from './coverage-gate.js';
