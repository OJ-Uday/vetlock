import { defineConfig } from 'vitest/config';

// Assurance harness must be more robust than what it tests. Configure vitest so oracle
// self-tests (which deliberately trigger hangs, crashes, and heap-cap trips) don't destabilize
// the runner itself.
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    testTimeout: 30_000,
    hookTimeout: 10_000,
    // Sequential by default. Per-test resource caps must not be confounded by co-runners
    // fighting over cores or heap. Individual suites may opt into concurrency where safe.
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: true,
      },
    },
  },
});
