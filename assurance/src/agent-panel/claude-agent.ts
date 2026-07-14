/**
 * Claude evasion agent (PACKET-VETLOCK-ASSURANCE §5 P4, scheduled tier).
 *
 * Companion to `stubAgent`. Where the stub returns hardcoded hypotheses so CI can exercise
 * the whole propose → defang → run → oracle pipeline without an LLM, this agent asks a
 * cheap Anthropic model to brainstorm novel evasion hypotheses per capability class.
 *
 * NOT FOR CI. The panel driver in scheduled tier (assurance-scheduled.yml) may opt in via
 * an explicit ANTHROPIC_API_KEY secret; nothing in this file hits the API when the key is
 * absent. Every test in `claude-agent.test.ts` mocks the client — the real API is never
 * touched by the test suite.
 *
 * DESIGN NOTES
 *   - Dependency-injected client. The factory accepts an optional `client` matching a
 *     minimal interface that the real `@anthropic-ai/sdk` client satisfies (structural). If
 *     no client is passed, we construct `new Anthropic({ apiKey })` from ANTHROPIC_API_KEY.
 *     Tests inject a stub; production reads the env var. The real API surface is a superset
 *     of `ClaudeMessageClient`, so the cast at the SDK boundary is safe.
 *   - Model default: `claude-haiku-4-5-20251001`. Cheap, plenty capable for evasion-hypothesis
 *     brainstorming. The panel is scheduled tier — cost matters. Override via `opts.model`.
 *   - The agent enforces packet rule #2 at the source: every fixture the model returns is
 *     scanned by `scanForDefangViolations`. A dirty fixture aborts the batch with a clear
 *     error — the panel's own scan is defense in depth. If the model can't follow the
 *     defang constraint on ANY hypothesis for the class, the whole batch is suspect and
 *     the scheduled job should surface that loudly (a triage signal, not silent failure).
 *   - Response format: we ask the model for a JSON array of
 *     `{technique, generatedFixture, rationale}` objects. Markdown code fences from the
 *     model (```json ... ```) are stripped before parsing.
 *   - No streaming, no tool use — a single messages.create() per capability entry. Determinism
 *     is best-effort (`temperature: 0` in the request); we don't rely on it for correctness.
 *     The defang guard + JSON schema check catch anything the model gets wrong.
 */

import Anthropic from '@anthropic-ai/sdk';
import { scanForDefangViolations } from '../defang/index.js';
import type { CapabilityMapEntry, EvasionAgent, EvasionHypothesis } from './types.js';

/**
 * Minimal structural interface for the Anthropic Messages API. The real
 * `@anthropic-ai/sdk` client satisfies this (its return type is a superset of what we
 * read). Keeping the surface minimal lets tests pass in a hand-rolled stub without the
 * SDK's whole type footprint.
 */
export interface ClaudeMessageClient {
  readonly messages: {
    create(params: ClaudeMessageCreateParams): Promise<ClaudeMessageResponse>;
  };
}

/** Params we send. The real SDK type has many more optional knobs — we use only these. */
export interface ClaudeMessageCreateParams {
  readonly model: string;
  readonly max_tokens: number;
  readonly system?: string;
  readonly temperature?: number;
  readonly messages: readonly {
    readonly role: 'user' | 'assistant';
    readonly content: string;
  }[];
}

/** Response shape we read. The real Message has more fields (id, usage, stop_reason, …). */
export interface ClaudeMessageResponse {
  readonly content: readonly {
    readonly type: string;
    readonly text?: string;
  }[];
}

/** Factory options. */
export interface CreateClaudeAgentOptions {
  /**
   * Injected client. Tests pass a stub; production omits this and the factory constructs a
   * real `Anthropic()` from `opts.apiKey` (or `process.env.ANTHROPIC_API_KEY`).
   */
  readonly client?: ClaudeMessageClient;
  /** Model id. Default: `claude-haiku-4-5-20251001` — cheap, sufficient for brainstorming. */
  readonly model?: string;
  /** API key override. Defaults to `process.env.ANTHROPIC_API_KEY`. */
  readonly apiKey?: string;
  /** Max output tokens per request. Default 4096 — enough for ~5 hypotheses with rationale. */
  readonly maxTokens?: number;
  /** Sampling temperature. Default 0 (deterministic-ish; still not byte-stable, but tighter). */
  readonly temperature?: number;
}

const DEFAULT_MODEL = 'claude-haiku-4-5-20251001';
const DEFAULT_MAX_TOKENS = 4096;
const DEFAULT_TEMPERATURE = 0;

const SYSTEM_PROMPT = [
  'You are an evasion-hypothesis brainstormer for a vetlock static-analysis harness — a red-team',
  'that helps the detector find its blind spots. Your job: propose transformations that would',
  'let a hostile package invoke a target sink WITHOUT the detector catching it.',
  '',
  'ABSOLUTE CONSTRAINT — DEFANGED-ONLY (packet rule #2, non-negotiable):',
  '  - No real network hosts. Use only: *.invalid, *.test, *.example, *.localhost,',
  '    example.com, example.org, example.net, 127.0.0.1, 0.0.0.0, ::1.',
  '  - No runnable shell payloads. If a fixture must NAME a command, use only echo, printf,',
  '    true, false, or `:` — never curl/wget/nc/bash -c with a real body.',
  '  - No large base64 or hex blobs paired with a decode-and-run call (atob, Buffer.from,',
  '    eval, new Function). If you need to represent an obfuscated payload, describe it in',
  '    an inert marker field (e.g. a description string), do not embed a runnable blob.',
  '  - No credential paths (~/.ssh/id_rsa, ~/.aws/credentials, .npmrc, .env, etc) paired',
  '    with a network endpoint — that is the exfil shape, forbidden.',
  '',
  'FIXTURES: emit pnpm-lock.yaml-shaped YAML (lockfileVersion, settings, packages) that',
  'names the target sink in an inert-marker field (a description string, a peerDependencies',
  'entry). The point is to describe the technique, not to execute it. A downstream defang',
  'scanner will reject any fixture that violates the rules above — if that happens, the',
  'entire batch is rejected and the run is wasted.',
  '',
  'OUTPUT FORMAT: a single JSON array. Each element is an object with EXACTLY these keys:',
  '  {',
  '    "technique": "<short kebab-case label — e.g. identifier-split-and-concat>",',
  '    "generatedFixture": "<multi-line pnpm-lock.yaml fixture as a string>",',
  '    "rationale": "<one or two sentences on why this evades the current detector>"',
  '  }',
  'No prose outside the JSON. No markdown code fences (I will parse the array directly).',
  'If unsure, produce fewer high-quality hypotheses over more low-quality ones.',
].join('\n');

/** Build the per-class user prompt. */
function buildUserPrompt(entry: CapabilityMapEntry, seed: number, max: number): string {
  return [
    `Target capability class: ${entry.class}`,
    `Enumerated sink: ${entry.sinkId} (kind=${entry.kind})`,
    `Sink description: ${entry.description}`,
    ``,
    `Propose up to ${max} evasion hypotheses. Seed: ${seed} (for your own randomness, if any).`,
    `Return only the JSON array — no prose, no code fences.`,
  ].join('\n');
}

/**
 * Extract the first text content block. The real Message has an array where each block has
 * `type: 'text' | 'tool_use' | ...`. We only asked for text, so the first text block is our
 * answer. Missing or non-text response is a hard error — we can't proceed without a body.
 */
function extractText(response: ClaudeMessageResponse): string {
  const textBlock = response.content.find(
    (b): b is { type: string; text: string } =>
      b.type === 'text' && typeof b.text === 'string' && b.text.length > 0,
  );
  if (!textBlock) {
    throw new Error(
      'claude-agent: response contained no text content block. Model may have returned an ' +
        'empty response or only non-text blocks (tool_use, image, etc).',
    );
  }
  return textBlock.text;
}

/**
 * Strip markdown code fences if the model wrapped its JSON. Models sometimes ignore the
 * "no fences" instruction; being lenient here saves a whole retry loop.
 */
function stripCodeFences(text: string): string {
  const trimmed = text.trim();
  const fenceMatch = trimmed.match(/^```(?:json)?\s*\n([\s\S]*?)\n```\s*$/);
  return fenceMatch ? fenceMatch[1] : trimmed;
}

/** Parse the model's JSON response into an unknown value; throw with the raw prefix on failure. */
function parseJson(text: string): unknown {
  const cleaned = stripCodeFences(text);
  try {
    return JSON.parse(cleaned);
  } catch (err) {
    const preview = cleaned.slice(0, 200);
    throw new Error(
      `claude-agent: response was not valid JSON — ${
        err instanceof Error ? err.message : String(err)
      }. Preview: ${preview}${cleaned.length > 200 ? '…' : ''}`,
    );
  }
}

/** Shape-check one array element. */
function assertRawHypothesis(x: unknown, i: number): {
  technique: string;
  generatedFixture: string;
  rationale: string;
} {
  if (typeof x !== 'object' || x === null) {
    throw new Error(
      `claude-agent: hypothesis at index ${i} is not an object (got ${typeof x})`,
    );
  }
  const obj = x as Record<string, unknown>;
  const technique = obj.technique;
  const generatedFixture = obj.generatedFixture;
  const rationale = obj.rationale;
  if (typeof technique !== 'string' || technique.length === 0) {
    throw new Error(
      `claude-agent: hypothesis at index ${i} is missing/invalid "technique" (must be non-empty string)`,
    );
  }
  if (typeof generatedFixture !== 'string' || generatedFixture.length === 0) {
    throw new Error(
      `claude-agent: hypothesis at index ${i} is missing/invalid "generatedFixture" (must be non-empty string)`,
    );
  }
  if (typeof rationale !== 'string' || rationale.length === 0) {
    throw new Error(
      `claude-agent: hypothesis at index ${i} is missing/invalid "rationale" (must be non-empty string)`,
    );
  }
  return { technique, generatedFixture, rationale };
}

/**
 * Resolve the client, or construct one from ANTHROPIC_API_KEY. If no key is available and
 * no client was injected, throw with a clear message naming the env var. This is what makes
 * `--agent=claude` fail loudly in an unconfigured environment (CI, someone's laptop without
 * the key) instead of silently making network calls or hanging.
 */
function resolveClient(opts: CreateClaudeAgentOptions): ClaudeMessageClient {
  if (opts.client) return opts.client;
  const apiKey = opts.apiKey ?? process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error(
      'claude-agent: ANTHROPIC_API_KEY environment variable is not set. Set it before ' +
        'running the panel with --agent=claude, e.g. ' +
        '`ANTHROPIC_API_KEY=sk-… node dist/agent-panel/cli.js --agent=claude`. ' +
        'The stub agent is the CI default — never run --agent=claude in CI without an ' +
        'explicit opt-in secret.',
    );
  }
  // The real Anthropic client is a structural superset of ClaudeMessageClient. Cast at the
  // boundary; internal code sees only the minimal interface.
  return new Anthropic({ apiKey }) as unknown as ClaudeMessageClient;
}

/**
 * Build a Claude-backed EvasionAgent.
 *
 * Errors thrown by `propose(...)`:
 *   - ANTHROPIC_API_KEY missing (at factory time, unless `client` injected)
 *   - Model returned no text content
 *   - Model returned invalid JSON (parse error, or non-array top level)
 *   - Hypothesis missing/invalid technique/generatedFixture/rationale
 *   - Fixture flunked the defang guard (packet rule #2)
 */
export function createClaudeAgent(opts: CreateClaudeAgentOptions = {}): EvasionAgent {
  const client = resolveClient(opts);
  const model = opts.model ?? DEFAULT_MODEL;
  const maxTokens = opts.maxTokens ?? DEFAULT_MAX_TOKENS;
  const temperature = opts.temperature ?? DEFAULT_TEMPERATURE;

  return {
    id: 'claude',
    async propose(
      entry: CapabilityMapEntry,
      seed: number,
      max: number,
    ): Promise<readonly EvasionHypothesis[]> {
      if (max <= 0) return [];

      const response = await client.messages.create({
        model,
        max_tokens: maxTokens,
        temperature,
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: buildUserPrompt(entry, seed, max) }],
      });

      const text = extractText(response);
      const parsed = parseJson(text);
      if (!Array.isArray(parsed)) {
        throw new Error(
          `claude-agent: expected top-level JSON array of hypotheses; got ${
            parsed === null ? 'null' : typeof parsed
          }`,
        );
      }

      const hypotheses: EvasionHypothesis[] = [];
      const limit = Math.min(parsed.length, max);
      for (let i = 0; i < limit; i++) {
        const raw = assertRawHypothesis(parsed[i], i);
        const scan = scanForDefangViolations(raw.generatedFixture);
        if (!scan.clean) {
          const sample = scan.violations
            .slice(0, 3)
            .map((v) => `${v.category}:"${v.match.slice(0, 40)}"`)
            .join(', ');
          throw new Error(
            `claude-agent: hypothesis at index ${i} produced a defang-DIRTY fixture — ` +
              `${scan.violations.length} violation(s): ${sample}. ` +
              `The whole batch is rejected; the model is not following the defang constraint. ` +
              `Investigate before retrying — do not silently discard.`,
          );
        }
        hypotheses.push({
          id: `claude-${entry.sinkId}-${i}-s${seed}`,
          targetClass: entry.class,
          targetSink: entry.sinkId,
          technique: raw.technique,
          generatedFixture: raw.generatedFixture,
          proposedBy: 'claude',
          rationale: raw.rationale,
        });
      }
      return hypotheses;
    },
  };
}
