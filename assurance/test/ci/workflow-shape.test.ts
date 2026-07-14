/**
 * workflow-shape.test.ts — structural + safety checks over the assurance CI wiring.
 *
 * This test doesn't try to *run* the workflows (that's GitHub Actions' job). It parses
 * them as YAML and asserts the shape we depend on:
 *
 *   1. `assurance-pr.yml` is a PR-tier gate (fires on pull_request) that actually runs
 *      `pnpm test` on @vetlock/assurance.
 *   2. `assurance-scheduled.yml` is a cron-scheduled workflow with a valid cron string.
 *   3. Neither workflow contains destructive shell (`rm -rf`, `curl | sh`, etc.). A
 *      compromised workflow would be an obvious way to attack the repo — this test is
 *      the first line of defence.
 *   4. The root README carries the assurance badge with the correct workflow slug.
 *
 * Every assertion is written so a regression names the exact contract violated. When
 * this test fails, someone changed the release-gate wiring — either intentionally
 * (update this test) or accidentally (revert).
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as yaml from 'js-yaml';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '..', '..', '..');
const WORKFLOWS_DIR = resolve(REPO_ROOT, '.github', 'workflows');
const PR_WORKFLOW = resolve(WORKFLOWS_DIR, 'assurance-pr.yml');
const SCHEDULED_WORKFLOW = resolve(WORKFLOWS_DIR, 'assurance-scheduled.yml');
const ROOT_README = resolve(REPO_ROOT, 'README.md');

// ---- helpers --------------------------------------------------------------------------

interface WorkflowStep {
  readonly name?: string;
  readonly run?: string;
  readonly uses?: string;
  readonly with?: Record<string, unknown>;
}

interface WorkflowJob {
  readonly steps?: readonly WorkflowStep[];
  readonly [k: string]: unknown;
}

interface ParsedWorkflow {
  readonly name?: string;
  // GitHub's `on` key is parsed by js-yaml as either a string, array, or object.
  readonly on?: unknown;
  readonly jobs?: Record<string, WorkflowJob>;
}

function loadWorkflow(path: string): ParsedWorkflow {
  const text = readFileSync(path, 'utf-8');
  const doc = yaml.load(text) as ParsedWorkflow;
  expect(doc, `${path} must parse as a non-null YAML object`).toBeTruthy();
  return doc;
}

function allSteps(doc: ParsedWorkflow): readonly WorkflowStep[] {
  const jobs = doc.jobs ?? {};
  const collected: WorkflowStep[] = [];
  for (const job of Object.values(jobs)) {
    for (const step of job.steps ?? []) collected.push(step);
  }
  return collected;
}

function allRunCommands(doc: ParsedWorkflow): readonly string[] {
  return allSteps(doc)
    .map((s) => s.run)
    .filter((r): r is string => typeof r === 'string');
}

/** js-yaml normalizes the workflow `on:` shorthand into several possible shapes.
 *  This helper returns the trigger *keys* regardless of which shape appears. */
function triggerKeys(on: unknown): readonly string[] {
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.filter((x): x is string => typeof x === 'string');
  if (on !== null && typeof on === 'object') return Object.keys(on as Record<string, unknown>);
  return [];
}

/** Extract the `on.pull_request` sub-config as an object (or null if missing). */
function pullRequestConfig(on: unknown): Record<string, unknown> | null {
  if (on !== null && typeof on === 'object' && !Array.isArray(on)) {
    const pr = (on as Record<string, unknown>).pull_request;
    if (pr && typeof pr === 'object' && !Array.isArray(pr)) return pr as Record<string, unknown>;
  }
  return null;
}

/** Extract `on.schedule` as an array of cron entries. */
function scheduleConfig(on: unknown): readonly Record<string, unknown>[] {
  if (on !== null && typeof on === 'object' && !Array.isArray(on)) {
    const sched = (on as Record<string, unknown>).schedule;
    if (Array.isArray(sched)) return sched as Record<string, unknown>[];
  }
  return [];
}

// A minimal cron sanity check. GitHub uses standard 5-field crontab syntax.
// We accept digits, `*`, `,`, `-`, `/`, and whitespace — anything else is suspicious.
const CRON_5FIELDS_RE = /^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$/;
const CRON_ALLOWED_CHAR_RE = /^[\d*,\-/]+$/;

function isPlausibleCron(expr: string): boolean {
  const m = CRON_5FIELDS_RE.exec(expr);
  if (!m) return false;
  return m.slice(1).every((f) => CRON_ALLOWED_CHAR_RE.test(f));
}

// Suspicious shell patterns. Each pattern is a real footgun that has no place in a
// blocking CI workflow. If a future step legitimately needs one, the test will alert
// the reviewer — that's the point.
const SUSPICIOUS_PATTERNS: readonly { readonly pattern: RegExp; readonly label: string }[] = [
  { pattern: /\brm\s+-rf\b/, label: 'rm -rf' },
  { pattern: /:\(\)\s*\{/, label: 'fork bomb' },
  { pattern: /\bcurl\b[^\n|]*\|\s*(bash|sh)\b/, label: 'curl | sh' },
  { pattern: /\bwget\b[^\n|]*\|\s*(bash|sh)\b/, label: 'wget | sh' },
  { pattern: /\beval\s+["'`]?\$/, label: 'eval $VAR' },
  { pattern: /\bnc\s+-l\b/, label: 'netcat listener' },
  { pattern: /\bmkfs\b/, label: 'mkfs' },
];

// ---- assurance-pr.yml ----------------------------------------------------------------

describe('assurance-pr.yml — blocking PR gate', () => {
  const doc = loadWorkflow(PR_WORKFLOW);

  it('has a human-readable workflow name', () => {
    expect(doc.name, 'top-level `name:` is required').toBeTruthy();
  });

  it('triggers on pull_request', () => {
    const triggers = triggerKeys(doc.on);
    expect(triggers).toContain('pull_request');
    const pr = pullRequestConfig(doc.on);
    // Either explicit path filters or a full `pull_request:` config is fine. What we
    // reject is *no* pull_request trigger (which would make this workflow non-blocking).
    expect(pr, 'pull_request must be configured, not just referenced').not.toBeNull();
  });

  it('has at least one job with concrete steps', () => {
    const jobs = doc.jobs ?? {};
    expect(Object.keys(jobs).length).toBeGreaterThan(0);
    for (const [id, job] of Object.entries(jobs)) {
      expect(job.steps, `job "${id}" must have steps`).toBeTruthy();
      expect((job.steps ?? []).length, `job "${id}" must have >= 1 step`).toBeGreaterThan(0);
    }
  });

  it('includes a step that runs the assurance test suite (pnpm test)', () => {
    const runs = allRunCommands(doc);
    const hasTest = runs.some(
      (cmd) =>
        /pnpm\b/.test(cmd) &&
        /\btest\b/.test(cmd) &&
        // Guard against a stray `pnpm test` in some other package; the PR gate
        // targets @vetlock/assurance specifically.
        (/@vetlock\/assurance/.test(cmd) || /--filter\s+assurance/.test(cmd)),
    );
    expect(hasTest, 'expected a `pnpm --filter @vetlock/assurance test` step').toBe(true);
  });

  it('includes a step that regenerates ASSURANCE.md', () => {
    const runs = allRunCommands(doc);
    expect(runs.some((cmd) => /assurance:report/.test(cmd))).toBe(true);
  });

  it('has no suspicious shell commands', () => {
    const runs = allRunCommands(doc);
    for (const cmd of runs) {
      for (const { pattern, label } of SUSPICIOUS_PATTERNS) {
        expect(pattern.test(cmd), `Disallowed pattern "${label}" in step run:\n${cmd}`).toBe(false);
      }
    }
  });
});

// ---- assurance-scheduled.yml ---------------------------------------------------------

describe('assurance-scheduled.yml — nightly discovery tier', () => {
  const doc = loadWorkflow(SCHEDULED_WORKFLOW);

  it('has a human-readable workflow name', () => {
    expect(doc.name).toBeTruthy();
  });

  it('triggers on schedule with at least one cron entry', () => {
    const triggers = triggerKeys(doc.on);
    expect(triggers).toContain('schedule');
    const schedule = scheduleConfig(doc.on);
    expect(schedule.length).toBeGreaterThan(0);
    for (const entry of schedule) {
      const cron = entry.cron;
      expect(typeof cron, 'each schedule entry needs a cron string').toBe('string');
      expect(
        isPlausibleCron(cron as string),
        `cron expression must be a valid 5-field crontab; got "${cron}"`,
      ).toBe(true);
    }
  });

  it('also allows manual dispatch (workflow_dispatch)', () => {
    // A scheduled tier that can't be manually re-run is a scheduled tier no one runs.
    expect(triggerKeys(doc.on)).toContain('workflow_dispatch');
  });

  it('runs the assurance test suite', () => {
    const runs = allRunCommands(doc);
    const hasTest = runs.some(
      (cmd) =>
        /pnpm\b/.test(cmd) &&
        /\btest\b/.test(cmd) &&
        (/@vetlock\/assurance/.test(cmd) || /--filter\s+assurance/.test(cmd)),
    );
    expect(hasTest).toBe(true);
  });

  it('has no suspicious shell commands', () => {
    const runs = allRunCommands(doc);
    for (const cmd of runs) {
      for (const { pattern, label } of SUSPICIOUS_PATTERNS) {
        expect(pattern.test(cmd), `Disallowed pattern "${label}" in step run:\n${cmd}`).toBe(false);
      }
    }
  });
});

// ---- README badge --------------------------------------------------------------------

describe('root README assurance badge', () => {
  const readme = readFileSync(ROOT_README, 'utf-8');

  it('links the assurance-pr workflow badge', () => {
    // shields.io / GitHub Actions badge URL syntax. We check for the exact workflow
    // slug so a rename of the yml file will trip this test.
    const BADGE_RE =
      /!\[Assurance\]\(https:\/\/github\.com\/[\w-]+\/vetlock\/actions\/workflows\/assurance-pr\.yml\/badge\.svg\)/;
    expect(BADGE_RE.test(readme), 'assurance-pr badge missing or wrong URL').toBe(true);
  });

  it('links ASSURANCE.md from the "standing adversary" section', () => {
    // The README section names the trust artifact; the link must resolve.
    expect(readme).toMatch(/standing adversary/i);
    expect(readme).toMatch(/assurance\/report\/ASSURANCE\.md/);
  });
});
