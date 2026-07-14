import { defineConfig } from 'vitest/config';

// Assurance harness must be more robust than what it tests. Configure vitest so oracle
// self-tests (which deliberately trigger hangs, crashes, and heap-cap trips) don't destabilize
// the runner itself.
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    testTimeout: 30_000,
    hookTimeout: 10_000,
    // One fork PER FILE (singleFork: false is the default), so a test file that provokes a
    // native abort in a child worker (rare, but the whole point of the harness is that it
    // CAN and we need to survive) only kills its own fork. Vitest reruns nothing in a
    // crashed fork's queue — the file just fails, cleanly, without taking others with it.
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: false,
      },
    },
  },
});
