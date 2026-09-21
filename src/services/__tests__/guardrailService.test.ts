import {
  evaluateToolPolicy,
  isGuardrailsEnabled,
  normalizeGuardrailsConfig,
  scanValue,
} from '../guardrailService.js';
import { GuardrailFilterConfig } from '../../types/index.js';

describe('guardrailService', () => {
  describe('isGuardrailsEnabled', () => {
    test('returns false when config is missing or not explicitly enabled', () => {
      expect(isGuardrailsEnabled(undefined)).toBe(false);
      expect(isGuardrailsEnabled({})).toBe(false);
      expect(isGuardrailsEnabled({ enabled: false })).toBe(false);
    });

    test('returns true only when enabled is true', () => {
      expect(isGuardrailsEnabled({ enabled: true })).toBe(true);
    });
  });

  describe('evaluateToolPolicy', () => {
    test('allows everything when no policy is configured', () => {
      expect(evaluateToolPolicy('server-tool').allowed).toBe(true);
      expect(evaluateToolPolicy('server-tool', {}).allowed).toBe(true);
    });

    test('deny takes precedence over allow', () => {
      const result = evaluateToolPolicy('fs-delete', {
        allow: ['fs-*'],
        deny: ['fs-delete'],
      });
      expect(result.allowed).toBe(false);
      expect(result.rule).toBe('fs-delete');
    });

    test('supports wildcard deny rules', () => {
      expect(evaluateToolPolicy('shell-exec', { deny: ['shell-*'] }).allowed).toBe(false);
      expect(evaluateToolPolicy('fs-read', { deny: ['shell-*'] }).allowed).toBe(true);
    });

    test('non-empty allowlist blocks tools that do not match', () => {
      const result = evaluateToolPolicy('shell-exec', { allow: ['fs-*'] });
      expect(result.allowed).toBe(false);
      expect(result.rule).toBe('not-in-allowlist');
      expect(evaluateToolPolicy('fs-read', { allow: ['fs-*'] }).allowed).toBe(true);
    });
  });

  describe('scanValue', () => {
    test('returns input untouched when the filter is inactive', () => {
      const value = { a: 'test@example.com' };
      expect(scanValue(value, undefined)).toEqual({ blocked: false, value, matches: [] });
      expect(scanValue(value, { enabled: false, pii: ['email'] }).value).toBe(value);
    });

    test('redacts built-in PII in nested strings by default', () => {
      const filter: GuardrailFilterConfig = { pii: ['email'] };
      const result = scanValue({ note: 'reach me at test@example.com now' }, filter);
      expect(result.blocked).toBe(false);
      expect((result.value as any).note).toBe('reach me at [REDACTED] now');
      expect(result.matches).toEqual([{ rule: 'pii:email', action: 'redact', count: 1 }]);
    });

    test('redacts across arrays and honors custom redaction text', () => {
      const filter: GuardrailFilterConfig = { pii: ['email'], redactionText: '***' };
      const result = scanValue(['a@b.co', { deep: ['c@d.co'] }], filter);
      expect(result.value).toEqual(['***', { deep: ['***'] }]);
      expect(result.matches[0].count).toBe(2);
    });

    test('blocks when a matched rule uses the block action', () => {
      const filter: GuardrailFilterConfig = { keywords: ['topsecret'], action: 'block' };
      const result = scanValue({ q: 'this is TopSecret data' }, filter);
      expect(result.blocked).toBe(true);
      expect(result.blockedRule).toBe('keyword:topsecret');
      // Value is left unchanged on a block (caller rejects the call entirely).
      expect(result.value).toEqual({ q: 'this is TopSecret data' });
    });

    test('applies custom regex patterns with per-rule action', () => {
      const filter: GuardrailFilterConfig = {
        patterns: [{ name: 'api-key', pattern: 'sk-[a-z0-9]+', action: 'redact' }],
      };
      const result = scanValue('key sk-abc123 end', filter);
      expect(result.value).toBe('key [REDACTED] end');
      expect(result.matches[0].rule).toBe('pattern:api-key');
    });

    test('ignores invalid custom regex instead of throwing', () => {
      const filter: GuardrailFilterConfig = {
        patterns: [{ pattern: '(' }],
        pii: ['email'],
      };
      const result = scanValue('x@y.co', filter);
      expect(result.value).toBe('[REDACTED]');
    });

    test('returns the original reference when nothing matches', () => {
      const value = { safe: 'nothing here' };
      const result = scanValue(value, { pii: ['email'] });
      expect(result.value).toBe(value);
      expect(result.matches).toEqual([]);
    });
  });

  describe('normalizeGuardrailsConfig', () => {
    test('coerces enabled to a strict boolean and drops unknown fields', () => {
      const result = normalizeGuardrailsConfig({ enabled: 'yes', bogus: 1 });
      expect(result).toEqual({ enabled: false });
      expect(normalizeGuardrailsConfig({ enabled: true }).enabled).toBe(true);
    });

    test('normalizes policy and filters, filtering invalid entries', () => {
      const result = normalizeGuardrailsConfig({
        enabled: true,
        policy: { allow: ['fs-*', 42], deny: ['shell-*'] },
        input: {
          pii: ['email', 'not-a-detector'],
          keywords: ['secret', 7],
          patterns: [
            { name: 'k', pattern: 'sk-\\w+', action: 'block' },
            { name: 'invalid' },
          ],
          action: 'block',
        },
        output: { enabled: false },
      });

      expect(result.policy).toEqual({ allow: ['fs-*'], deny: ['shell-*'] });
      expect(result.input).toEqual({
        enabled: true,
        pii: ['email'],
        keywords: ['secret'],
        patterns: [{ name: 'k', pattern: 'sk-\\w+', action: 'block' }],
        action: 'block',
        redactionText: '[REDACTED]',
      });
      expect(result.output).toEqual({
        enabled: false,
        pii: [],
        keywords: [],
        patterns: [],
        action: 'redact',
        redactionText: '[REDACTED]',
      });
    });

    test('omits policy/filters that are absent', () => {
      expect(normalizeGuardrailsConfig({ enabled: true })).toEqual({ enabled: true });
    });
  });
});
