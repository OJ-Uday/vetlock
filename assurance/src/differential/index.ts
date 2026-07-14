/**
 * @vetlock/assurance differential adapters (packet §2.2 modality 3, §4 ledger metric).
 *
 * Public scanners (npm audit, osv-scanner, …) run the same lockfile inputs and produce
 * findings. The DifferentialLedger classifies every delta so the harness never silently
 * ignores a competitor hit. Barrel wiring lives in `../index.ts` (Wave 2 owns that).
 */

export type {
  DifferentialScanner,
  ScannerFinding,
  Delta,
  DeltaClass,
  LedgerFile,
} from './types.js';

export { DifferentialLedger } from './ledger.js';
export { NpmAuditScanner } from './npm-audit.js';
export { OsvScanner } from './osv-scanner.js';
