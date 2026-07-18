#!/usr/bin/env node
/** Vetlock MCP stdio server. Protocol messages go to stdout; diagnostics never do. */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { fileURLToPath } from 'node:url';
import * as path from 'node:path';
import { z } from 'zod';
import type { Finding } from '@vetlock/core';
import {
  analyzeLockfileChange,
  analyzePackageInstall,
  canonicalJson,
  createReceipt,
  evaluatePolicy,
  explainFinding,
  normalizedPolicy,
  sha256,
  verifyReceipt,
  type AdmissionReceipt,
  type Policy,
} from './admission.js';

const severity = z.enum(['BLOCK', 'WARN', 'INFO']);
const finding = z.object({
  detector: z.string(), category: z.string(), package: z.string(), from: z.string().nullable(), to: z.string().nullable(),
  direction: z.string(), severity, confidence: z.string(), message: z.string(),
  evidence: z.array(z.object({ file: z.string(), line: z.number(), snippet: z.string() })),
  provenance: z.array(z.array(z.string())), mitre: z.array(z.string()).optional(),
});
const policy = z.object({ reviewSeverities: z.array(z.enum(['WARN', 'INFO'])).optional(), blockSeverities: z.array(severity).optional(), failClosed: z.boolean().optional() }).strict();

function json(value: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(value, null, 2) }], structuredContent: value as Record<string, unknown> };
}

function failure(error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  return { content: [{ type: 'text' as const, text: JSON.stringify({ error: message }, null, 2) }], isError: true };
}

export function createVetlockMcpServer(): McpServer {
  const server = new McpServer({ name: 'vetlock-admission', version: '0.8.0' }, { capabilities: { logging: {} } });

  server.registerTool('analyze_lockfile_change', {
    title: 'Analyze lockfile change',
    description: 'Statically analyze two absolute lockfile paths. Fetches/analyzes package bytes but never executes package code or a package manager.',
    inputSchema: { beforePath: z.string().min(1), afterPath: z.string().min(1) },
  }, async ({ beforePath, afterPath }) => {
    try { return json(await analyzeLockfileChange(beforePath, afterPath)); } catch (error) { return failure(error); }
  });

  server.registerTool('analyze_package_install', {
    title: 'Analyze package before installation',
    description: 'Scan an npm package spec before installation. This never invokes npm, pnpm, yarn, or package code.',
    inputSchema: { packageSpec: z.string().min(1), projectDirectory: z.string().min(1), registry: z.string().url().optional() },
  }, async ({ packageSpec, projectDirectory, registry }) => {
    try { return json(await analyzePackageInstall(packageSpec, projectDirectory, registry)); } catch (error) { return failure(error); }
  });

  server.registerTool('evaluate_policy', {
    title: 'Evaluate admission policy',
    description: 'Turn Vetlock findings into allow, review, or block. Advisory only: enforcement remains vetlock add/guard.',
    inputSchema: { findings: z.array(finding), policy: policy.optional() },
  }, async ({ findings, policy: requestedPolicy }) => json(evaluatePolicy(findings as unknown as Finding[], requestedPolicy as Policy | undefined)));

  server.registerTool('issue_admission_receipt', {
    title: 'Issue unsigned admission receipt',
    description: 'Create a deterministic integrity receipt bound to package, artifact, project, policy, findings and decision. It is explicitly unsigned and does not authenticate an issuer.',
    inputSchema: {
      package: z.string().min(1), packageVersion: z.string().min(1), artifactSha256: z.string().regex(/^[a-f0-9]{64}$/i), projectHash: z.string().regex(/^[a-f0-9]{64}$/i),
      findings: z.array(finding), policy: policy.optional(), issuedAt: z.string().datetime().optional(),
    },
  }, async ({ package: packageName, packageVersion, artifactSha256, projectHash, findings, policy: requestedPolicy, issuedAt }) => {
    const typedFindings = findings as unknown as Finding[];
    const outcome = evaluatePolicy(typedFindings, requestedPolicy as Policy | undefined);
    const resolvedPolicy = normalizedPolicy(requestedPolicy as Policy | undefined);
    return json(createReceipt({
      package: packageName, packageVersion, artifactSha256: artifactSha256.toLowerCase(), projectHash: projectHash.toLowerCase(),
      policyHash: sha256(canonicalJson(resolvedPolicy)), findingsHash: sha256(canonicalJson(typedFindings)), decision: outcome.decision,
      issuedAt: issuedAt ?? new Date().toISOString(),
    }));
  });

  server.registerTool('verify_admission_receipt', {
    title: 'Verify unsigned admission receipt integrity',
    description: 'Verify deterministic receipt integrity only. Unsigned receipts never prove authorization or issuer identity.',
    inputSchema: { receipt: z.object({
      version: z.literal(1), kind: z.literal('vetlock-admission-receipt'), integrity: z.literal('sha256-deterministic-unsigned'),
      package: z.string(), packageVersion: z.string(), artifactSha256: z.string(), projectHash: z.string(), policyHash: z.string(), findingsHash: z.string(),
      decision: z.enum(['allow', 'review', 'block']), issuedAt: z.string(), receiptHash: z.string(), authenticity: z.literal('not-signed'),
    }) },
  }, async ({ receipt }) => json(verifyReceipt(receipt as AdmissionReceipt)));

  server.registerTool('explain_finding', {
    title: 'Explain a Vetlock finding',
    description: 'Filter an analysis result to the evidence for a detector and optionally one package.',
    inputSchema: { findings: z.array(finding), detector: z.string().min(1), package: z.string().min(1).optional() },
  }, async ({ findings, detector, package: packageName }) => json({ findings: explainFinding(findings as unknown as Finding[], detector, packageName) }));

  return server;
}

async function main(): Promise<void> {
  const server = createVetlockMcpServer();
  await server.connect(new StdioServerTransport());
}

if (process.argv[1] && path.resolve(fileURLToPath(import.meta.url)) === path.resolve(process.argv[1])) {
  main().catch((error) => { process.stderr.write(`vetlock-mcp: ${error instanceof Error ? error.stack ?? error.message : String(error)}\n`); process.exitCode = 1; });
}
