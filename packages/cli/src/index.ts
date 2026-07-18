// Keep this in sync with packages/cli/package.json and the CLI's core version.
// The public package must not expose a declaration that imports the private
// workspace package that is intentionally inlined into the release bundle.
export const VETLOCK_VERSION = '0.8.0';
export { renderTTY } from './tty.js';
export { renderJSON, JSON_SCHEMA_VERSION } from './json.js';
export { renderOSIF } from './osif.js';
export { renderSARIF } from './sarif.js';
export { renderMarkdown } from './md.js';
