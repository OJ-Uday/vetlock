/**
 * @vetlock/assurance — public entry.
 *
 * P0 exports the shared oracle set, the bounded engine runner, and the report generator.
 * See docs/adr/ for design decisions and the mission packet
 * (`~/personal/packets/PACKET-VETLOCK-ASSURANCE.md`) for the wider mission.
 */
export * from './oracles/index.js';
export * from './runner/index.js';
export * from './report/index.js';
