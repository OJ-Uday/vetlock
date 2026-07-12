import { describe, it, expect } from 'vitest';
import { DETECTORS_REGISTRY } from '../src/index.js';

describe('scaffold sanity', () => {
  it('exports the registry placeholder', () => {
    expect(DETECTORS_REGISTRY).toBe('placeholder');
  });
});
