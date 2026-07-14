/**
 * claude-agent tests. **No real API calls.**
 *
 * Every test constructs `createClaudeAgent({ client: … })` with a hand-rolled
 * `ClaudeMessageClient` stub. The stubs exercise the four failure modes and one
 * happy-path round-trip:
 *
 *   1. Happy path — a well-formed JSON array is parsed into EvasionHypothesis[] and every
 *      fixture passes the defang guard.
 *   2. Missing ANTHROPIC_API_KEY — the factory throws before any API call happens.
 *   3. Malformed JSON — parse error is surfaced with the raw preview in the message.
 *   4. Non-array top-level JSON — a specific "expected array" error.
 *   5. Missing/invalid fields on a hypothesis — a specific "missing … technique/…" error.
 *   6. Dirty fixture — defang scan rejects the batch with a clear "not following the
 *      defang constraint" error and does NOT return partial results.
 *   7. Response with no text content block — a specific "no text content" error.
 *
 * The mock is a plain object literal, not vi.mock — no module patching, no timing games.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createClaudeAgent } from '../../src/agent-panel/claude-agent.js';
import { scanForDefangViolations } from '../../src/defang/index.js';
import type {
  ClaudeMessageClient,
  ClaudeMessageCreateParams,
  ClaudeMessageResponse,
} from '../../src/agent-panel/claude-agent.js';
import type { CapabilityMapEntry } from '../../src/agent-panel/index.js';

/** A single CAPABILITY-MAP entry we use across the suite. */
const ENTRY: CapabilityMapEntry = {
  class: 'code-execution',
  sinkId: 'child_process.exec',
  kind: 'sink',
  description: 'Direct shell invocation via child_process.exec / execSync.',
};

/** Build a mock client whose messages.create returns the given text. */
function stubClient(text: string): ClaudeMessageClient & { readonly calls: ClaudeMessageCreateParams[] } {
  const calls: ClaudeMessageCreateParams[] = [];
  const client: ClaudeMessageClient = {
    messages: {
      async create(params: ClaudeMessageCreateParams): Promise<ClaudeMessageResponse> {
        calls.push(params);
        return { content: [{ type: 'text', text }] };
      },
    },
  };
  return Object.assign(client, { calls });
}

/** Build a mock client with a caller-supplied response object (for edge cases). */
function stubClientRaw(response: ClaudeMessageResponse): ClaudeMessageClient {
  return {
    messages: {
      async create(): Promise<ClaudeMessageResponse> {
        return response;
      },
    },
  };
}

// A defang-clean pnpm-lock.yaml fixture. Uses only reserved-domain endpoints — mirrors the
// stub-agent shape so we know it passes scanForDefangViolations without hitting the guard.
const CLEAN_FIXTURE = [
  `lockfileVersion: '6.0'`,
  `settings:`,
  `  autoInstallPeers: true`,
  `packages:`,
  `  /evade-code-execution@0.1.0:`,
  `    resolution:`,
  `      integrity: sha512-AAAA`,
  `      tarball: https://packages.invalid/evade-code-execution/-/evade-code-execution-0.1.0.tgz`,
  `    description: 'proposes to evade child_process.exec by splitting the identifier'`,
  ``,
].join('\n');

const SECOND_CLEAN_FIXTURE = [
  `lockfileVersion: '6.0'`,
  `settings:`,
  `  autoInstallPeers: true`,
  `packages:`,
  `  /nested-code-execution@0.2.0:`,
  `    resolution:`,
  `      integrity: sha512-BBBB`,
  `      tarball: https://packages.test/nested-code-execution/-/nested-code-execution-0.2.0.tgz`,
  `    description: 'moves child_process.exec into a nested script hook — echo hello only'`,
  ``,
].join('\n');

// A DIRTY fixture — contains a real-looking network host that the defang guard flags.
const DIRTY_FIXTURE = [
  `lockfileVersion: '6.0'`,
  `packages:`,
  `  /leak: 'https://attacker.com/exfil'`,
  ``,
].join('\n');

describe('createClaudeAgent — factory guards', () => {
  const savedKey = process.env.ANTHROPIC_API_KEY;
  beforeEach(() => {
    delete process.env.ANTHROPIC_API_KEY;
  });
  afterEach(() => {
    if (savedKey !== undefined) process.env.ANTHROPIC_API_KEY = savedKey;
    else delete process.env.ANTHROPIC_API_KEY;
  });

  it('throws a clear error when ANTHROPIC_API_KEY is absent and no client is injected', () => {
    expect(() => createClaudeAgent()).toThrow(/ANTHROPIC_API_KEY/);
  });

  it("mentions the env var name and how to set it", () => {
    // The error message should be actionable — name the env var and how to invoke.
    let msg = '';
    try {
      createClaudeAgent();
    } catch (err) {
      msg = err instanceof Error ? err.message : String(err);
    }
    expect(msg).toContain('ANTHROPIC_API_KEY');
    expect(msg).toContain('--agent=claude');
  });

  it('accepts an injected client and skips the env-var check', () => {
    // With a client injected, no env var is needed.
    const client = stubClient('[]');
    expect(() => createClaudeAgent({ client })).not.toThrow();
  });

  it('accepts an explicit apiKey without touching process.env', () => {
    expect(() => createClaudeAgent({ apiKey: 'sk-test-not-used-in-this-test' })).not.toThrow();
  });
});

describe('createClaudeAgent.propose — happy path', () => {
  it('parses a well-formed JSON response into EvasionHypothesis[] that pass the defang guard', async () => {
    // A well-formed model response with two hypotheses.
    const modelResponse = JSON.stringify([
      {
        technique: 'identifier-split-and-concat',
        generatedFixture: CLEAN_FIXTURE,
        rationale: 'Split the sink identifier across two literals concatenated at runtime.',
      },
      {
        technique: 'nested-manifest-relocation',
        generatedFixture: SECOND_CLEAN_FIXTURE,
        rationale: "Move the invocation into a nested package.json 'scripts' entry.",
      },
    ]);
    const client = stubClient(modelResponse);
    const agent = createClaudeAgent({ client });

    expect(agent.id).toBe('claude');

    const hypotheses = await agent.propose(ENTRY, 42, 5);

    // Two hypotheses, each with the expected shape.
    expect(hypotheses).toHaveLength(2);
    for (const [i, h] of hypotheses.entries()) {
      expect(h.targetClass).toBe('code-execution');
      expect(h.targetSink).toBe('child_process.exec');
      expect(h.proposedBy).toBe('claude');
      expect(h.id).toBe(`claude-child_process.exec-${i}-s42`);
      expect(typeof h.technique).toBe('string');
      expect(typeof h.generatedFixture).toBe('string');
      expect(typeof h.rationale).toBe('string');
    }

    // The defang guarantee — every fixture the agent returns is clean. This is the
    // "round-trip synthetic model response into EvasionHypothesis[] that pass the defang
    // guard" the task asks us to verify.
    for (const h of hypotheses) {
      const scan = scanForDefangViolations(h.generatedFixture);
      expect(scan.clean).toBe(true);
    }
  });

  it('honours the `max` cap when the model returns more', async () => {
    // Three-element response but max=2 → only the first two returned.
    const modelResponse = JSON.stringify([
      { technique: 'a', generatedFixture: CLEAN_FIXTURE, rationale: 'r1' },
      { technique: 'b', generatedFixture: SECOND_CLEAN_FIXTURE, rationale: 'r2' },
      { technique: 'c', generatedFixture: CLEAN_FIXTURE, rationale: 'r3' },
    ]);
    const agent = createClaudeAgent({ client: stubClient(modelResponse) });
    const hs = await agent.propose(ENTRY, 42, 2);
    expect(hs).toHaveLength(2);
    expect(hs[0].technique).toBe('a');
    expect(hs[1].technique).toBe('b');
  });

  it('returns [] when max=0 without calling the API', async () => {
    const client = stubClient('this should not be parsed');
    const agent = createClaudeAgent({ client });
    const hs = await agent.propose(ENTRY, 42, 0);
    expect(hs).toHaveLength(0);
    expect(client.calls).toHaveLength(0); // no API call made
  });

  it('strips markdown code fences the model may wrap around the JSON', async () => {
    const jsonBody = JSON.stringify([
      { technique: 'fenced', generatedFixture: CLEAN_FIXTURE, rationale: 'r' },
    ]);
    const fenced = `\`\`\`json\n${jsonBody}\n\`\`\``;
    const agent = createClaudeAgent({ client: stubClient(fenced) });
    const hs = await agent.propose(ENTRY, 7, 5);
    expect(hs).toHaveLength(1);
    expect(hs[0].technique).toBe('fenced');
  });

  it('passes the configured model + system prompt + user prompt through to the client', async () => {
    const client = stubClient('[]');
    const agent = createClaudeAgent({ client, model: 'claude-haiku-4-5-20251001', temperature: 0 });
    await agent.propose(ENTRY, 42, 3);

    expect(client.calls).toHaveLength(1);
    const params = client.calls[0];
    expect(params.model).toBe('claude-haiku-4-5-20251001');
    expect(params.temperature).toBe(0);
    expect(params.system).toContain('DEFANGED-ONLY');
    expect(params.messages).toHaveLength(1);
    expect(params.messages[0].role).toBe('user');
    expect(params.messages[0].content).toContain('code-execution');
    expect(params.messages[0].content).toContain('child_process.exec');
  });

  it("defaults to model 'claude-haiku-4-5-20251001' when not overridden", async () => {
    const client = stubClient('[]');
    const agent = createClaudeAgent({ client });
    await agent.propose(ENTRY, 42, 3);
    expect(client.calls[0].model).toBe('claude-haiku-4-5-20251001');
  });
});

describe('createClaudeAgent.propose — malformed responses', () => {
  it('throws when the JSON does not parse', async () => {
    const agent = createClaudeAgent({ client: stubClient('this is not JSON at all') });
    await expect(agent.propose(ENTRY, 42, 3)).rejects.toThrow(/not valid JSON/);
  });

  it('throws when the top-level JSON is an object, not an array', async () => {
    const agent = createClaudeAgent({ client: stubClient('{"hypotheses": []}') });
    await expect(agent.propose(ENTRY, 42, 3)).rejects.toThrow(/expected top-level JSON array/);
  });

  it('throws when the top-level JSON is null', async () => {
    const agent = createClaudeAgent({ client: stubClient('null') });
    await expect(agent.propose(ENTRY, 42, 3)).rejects.toThrow(/expected top-level JSON array/);
  });

  it('throws when a hypothesis is missing "technique"', async () => {
    const body = JSON.stringify([
      { generatedFixture: CLEAN_FIXTURE, rationale: 'r' }, // no technique
    ]);
    const agent = createClaudeAgent({ client: stubClient(body) });
    await expect(agent.propose(ENTRY, 42, 3)).rejects.toThrow(/technique/);
  });

  it('throws when a hypothesis is missing "generatedFixture"', async () => {
    const body = JSON.stringify([{ technique: 't', rationale: 'r' }]);
    const agent = createClaudeAgent({ client: stubClient(body) });
    await expect(agent.propose(ENTRY, 42, 3)).rejects.toThrow(/generatedFixture/);
  });

  it('throws when a hypothesis is missing "rationale"', async () => {
    const body = JSON.stringify([{ technique: 't', generatedFixture: CLEAN_FIXTURE }]);
    const agent = createClaudeAgent({ client: stubClient(body) });
    await expect(agent.propose(ENTRY, 42, 3)).rejects.toThrow(/rationale/);
  });

  it('throws when a hypothesis is not an object', async () => {
    const body = JSON.stringify(['not an object', 42, null]);
    const agent = createClaudeAgent({ client: stubClient(body) });
    await expect(agent.propose(ENTRY, 42, 3)).rejects.toThrow(/not an object/);
  });

  it('throws when the response contains no text content block', async () => {
    // A response whose only content block is a non-text type (e.g. tool_use).
    const client = stubClientRaw({ content: [{ type: 'tool_use' }] });
    const agent = createClaudeAgent({ client });
    await expect(agent.propose(ENTRY, 42, 3)).rejects.toThrow(/no text content/);
  });

  it('throws when the response has empty content array', async () => {
    const client = stubClientRaw({ content: [] });
    const agent = createClaudeAgent({ client });
    await expect(agent.propose(ENTRY, 42, 3)).rejects.toThrow(/no text content/);
  });
});

describe('createClaudeAgent.propose — defang enforcement (packet rule #2)', () => {
  it('rejects the whole batch when any fixture is defang-dirty', async () => {
    // Sanity: the fixture actually IS dirty (this pins the test's assumption to the guard).
    expect(scanForDefangViolations(DIRTY_FIXTURE).clean).toBe(false);

    const body = JSON.stringify([
      { technique: 'dirty', generatedFixture: DIRTY_FIXTURE, rationale: 'oops' },
    ]);
    const agent = createClaudeAgent({ client: stubClient(body) });
    await expect(agent.propose(ENTRY, 42, 3)).rejects.toThrow(/defang-DIRTY/);
  });

  it("names the number of violations and does not silently return partial results", async () => {
    // First hypothesis is clean, second is dirty → whole batch fails, nothing returned.
    const body = JSON.stringify([
      { technique: 'clean', generatedFixture: CLEAN_FIXTURE, rationale: 'ok' },
      { technique: 'dirty', generatedFixture: DIRTY_FIXTURE, rationale: 'oops' },
    ]);
    const agent = createClaudeAgent({ client: stubClient(body) });
    await expect(agent.propose(ENTRY, 42, 3)).rejects.toThrow(/violation/);
  });
});
