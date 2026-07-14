/**
 * @vetlock/assurance robustness generators (packet §5 P1, §2.1 threat families).
 *
 * Each generator is a pure function from a seed to a hostile lockfile-shaped input. The
 * robustness driver (in tests) wires them through the bounded runner and asserts the
 * oracle set. Every gap → corpus regression (packet rule #6).
 */

export type {
  LockfileFormat,
  LockfileInput,
  RobustnessGenerator,
} from './types.js';

export { deepNestedYaml, type DeepNestedYamlParams } from './deep-nested-yaml.js';
