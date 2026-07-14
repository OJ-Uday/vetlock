/**
 * @vetlock/assurance runner — bounded, sandboxed engine execution (ADR-0003).
 */

export { runBounded } from './runner.js';
export type {
  Scenario,
  SyntheticScenario,
  EngineScenario,
  AnalyzeFn,
  RunControl,
} from './types.js';
