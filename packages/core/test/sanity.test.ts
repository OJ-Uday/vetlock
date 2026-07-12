import { describe, it, expect } from 'vitest';
import { VETLOCK_VERSION } from '../src/index.js';

describe('scaffold sanity', () => {
  it('exports a version constant', () => {
    expect(typeof VETLOCK_VERSION).toBe('string');
  });
});
