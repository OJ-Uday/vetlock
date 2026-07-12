/**
 * Regression tests for red-team confirmed exploit S3.
 * @security-critical
 *
 * S3 — Substring match on trust store lets attacker@github.com.evil.example
 *      pass as GitHub. Fix: exact-domain-or-subdomain match for `@domain`
 *      anchors, exact-email match for full-email anchors, exact-local-part
 *      match for bare-username anchors.
 */

import { describe, it, expect } from 'vitest';
import { isTrustedPublisher } from '../src/publishers.js';

describe('REDTEAM S3: publisher trust exact-match (no substring bypass)', () => {
  // === Domain-anchor tests ===
  it('accepts an email whose domain exactly matches a @domain anchor', () => {
    expect(isTrustedPublisher('foo@github.com', ['@github.com'])).toBe(true);
  });

  it('accepts a subdomain of a @domain anchor', () => {
    expect(isTrustedPublisher('foo@app.github.com', ['@github.com'])).toBe(true);
  });

  it('REJECTS the S3 fixture: attacker@github.com.evil.example', () => {
    expect(isTrustedPublisher('attacker@github.com.evil.example', ['@github.com'])).toBe(false);
  });

  it('REJECTS a similar-shape suffix confusion: foo@notgithub.com', () => {
    expect(isTrustedPublisher('foo@notgithub.com', ['@github.com'])).toBe(false);
  });

  it('REJECTS a domain-anchor lookalike with prepended text', () => {
    expect(isTrustedPublisher('foo@evilgithub.com', ['@github.com'])).toBe(false);
  });

  // === Bare-username tests ===
  it('accepts email whose local part is the username anchor', () => {
    expect(isTrustedPublisher('sindresorhus@example.com', ['sindresorhus'])).toBe(true);
  });

  it('REJECTS username-substring: sindresorhus-fake@example.com', () => {
    expect(isTrustedPublisher('sindresorhus-fake@example.com', ['sindresorhus'])).toBe(false);
  });

  it('REJECTS prepended-text lookalike: notsindresorhus@example.com', () => {
    expect(isTrustedPublisher('notsindresorhus@example.com', ['sindresorhus'])).toBe(false);
  });

  it('REJECTS the S3 solana fixture where an attacker email contains the trust anchor as substring', () => {
    // If trust anchor is `@solana.com`, attacker@solana.com.evil.example must fail.
    expect(isTrustedPublisher('attacker@solana.com.evil.example', ['@solana.com'])).toBe(false);
  });

  // === Full-email-anchor tests ===
  it('accepts an exact full-email anchor', () => {
    expect(isTrustedPublisher('specific@known.com', ['specific@known.com'])).toBe(true);
  });

  it('REJECTS a different full email when trust anchor is a full email', () => {
    expect(isTrustedPublisher('other@known.com', ['specific@known.com'])).toBe(false);
  });

  // === Arrow / meta.maintainer-change snippet shape ===
  it('checks only the NEW side of an arrow-separated snippet', () => {
    const snippet = 'maintainers: [attacker@evil.example] → [sindresorhus@example.com]';
    expect(isTrustedPublisher(snippet, ['sindresorhus'])).toBe(true);
  });

  it('rejects when the NEW side has an untrusted email even if the OLD side was trusted', () => {
    const snippet = 'maintainers: [sindresorhus@example.com] → [attacker@evil.example]';
    expect(isTrustedPublisher(snippet, ['sindresorhus'])).toBe(false);
  });

  it('rejects when the NEW side has multiple emails and any one is untrusted', () => {
    const snippet = 'maintainers: [foo@github.com] → [foo@github.com, attacker@evil.example]';
    expect(isTrustedPublisher(snippet, ['@github.com'])).toBe(false);
  });

  it('accepts when NEW side has multiple emails all trusted (rotation within team)', () => {
    const snippet = 'maintainers: [foo@github.com] → [foo@github.com, bar@github.com]';
    expect(isTrustedPublisher(snippet, ['@github.com'])).toBe(true);
  });

  // === Defense-in-depth: reject short anchors ===
  it('ignores anchors shorter than 3 chars (defense-in-depth against D3-shape configs)', () => {
    expect(isTrustedPublisher('foo@example.com', [''])).toBe(false);
    expect(isTrustedPublisher('foo@example.com', ['a'])).toBe(false);
    expect(isTrustedPublisher('foo@example.com', ['@a'])).toBe(false);
  });

  it('returns false on an empty trust list', () => {
    expect(isTrustedPublisher('foo@github.com', [])).toBe(false);
  });

  it('returns false when the snippet has no email addresses', () => {
    expect(isTrustedPublisher('nothing to see here', ['@github.com'])).toBe(false);
  });
});
