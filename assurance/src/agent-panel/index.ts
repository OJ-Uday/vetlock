/**
 * @vetlock/assurance adversarial-agent panel (packet §5 P4).
 *
 * Public surface: the driver, the stub agent, the mock capability map, and the shared
 * types. The CLI is invoked directly (via cli.ts) and doesn't need to be re-exported.
 */

export { runPanel } from './panel.js';
export { stubAgent } from './stub-agent.js';
export { loadCapabilityMap } from './capability-map.js';
export type {
  CapabilityMap,
  CapabilityMapEntry,
  EvasionAgent,
  EvasionHypothesis,
  EvasionRun,
  PanelOptions,
  PanelReport,
  RejectedHypothesis,
} from './types.js';
