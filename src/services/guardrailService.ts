import {
  GuardrailAction,
  GuardrailFilterConfig,
  GuardrailPattern,
  GuardrailPolicyConfig,
  GuardrailsConfig,
} from '../types/index.js';

// Detector keys exposed to the dashboard and accepted from config.
export const SUPPORTED_PII_DETECTORS = ['email', 'phone', 'credit-card', 'ssn', 'ip'] as const;

// Built-in PII detectors. Kept intentionally conservative to limit false
// positives; deployments needing stricter matching can add custom `patterns`.
const PII_DETECTORS: Record<string, RegExp> = {
  email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  // International-ish phone numbers: optional +, 7-15 digits with common separators.
  phone: /(?<!\d)(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{1,4}\)[\s.-]?)?\d{3}[\s.-]?\d{3,4}[\s.-]?\d{0,4}(?!\d)/g,
  'credit-card': /\b(?:\d[ -]*?){13,16}\b/g,
  ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
  ip: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
};

const DEFAULT_REDACTION = '[REDACTED]';

export interface GuardrailMatch {
  rule: string; // Label of the rule that matched
  action: GuardrailAction; // Action taken (or that would be taken) for the match
  count: number; // Number of matched occurrences
}

export interface GuardrailScanResult {
  blocked: boolean; // True when at least one matched rule requires blocking
  blockedRule?: string; // Label of the first blocking rule
  value: unknown; // The (possibly redacted) value; unchanged when no redactions applied
  matches: GuardrailMatch[]; // All matched rules for logging
}

export interface GuardrailPolicyResult {
  allowed: boolean;
  rule?: string; // The deny rule that blocked the call, when denied
}

export const isGuardrailsEnabled = (config?: GuardrailsConfig): config is GuardrailsConfig =>
  !!config && config.enabled === true;

const toStringArray = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];

const toAction = (value: unknown, fallback: GuardrailAction): GuardrailAction =>
  value === 'block' || value === 'redact' ? value : fallback;

const normalizePattern = (input: any): GuardrailPattern | undefined => {
  if (!input || typeof input !== 'object' || typeof input.pattern !== 'string' || !input.pattern) {
    return undefined;
  }
  const pattern: GuardrailPattern = { pattern: input.pattern };
  if (typeof input.name === 'string' && input.name) pattern.name = input.name;
  if (typeof input.flags === 'string') pattern.flags = input.flags;
  if (input.action === 'block' || input.action === 'redact') pattern.action = input.action;
  if (typeof input.replacement === 'string') pattern.replacement = input.replacement;
  return pattern;
};

const normalizeFilter = (input: any): GuardrailFilterConfig | undefined => {
  if (!input || typeof input !== 'object') return undefined;
  return {
    enabled: input.enabled !== false,
    pii: toStringArray(input.pii).filter((d) =>
      (SUPPORTED_PII_DETECTORS as readonly string[]).includes(d),
    ),
    keywords: toStringArray(input.keywords),
    patterns: Array.isArray(input.patterns)
      ? input.patterns
          .map(normalizePattern)
          .filter((p: GuardrailPattern | undefined): p is GuardrailPattern => !!p)
      : [],
    action: toAction(input.action, 'redact'),
    redactionText: typeof input.redactionText === 'string' ? input.redactionText : '[REDACTED]',
  };
};

/**
 * Coerce an untrusted request body into a well-formed GuardrailsConfig, dropping
 * unknown fields and invalid entries so only safe, expected shapes are persisted.
 */
export const normalizeGuardrailsConfig = (input: any): GuardrailsConfig => {
  const config: GuardrailsConfig = { enabled: input?.enabled === true };

  if (input?.policy && typeof input.policy === 'object') {
    config.policy = {
      allow: toStringArray(input.policy.allow),
      deny: toStringArray(input.policy.deny),
    };
  }

  const inputFilter = normalizeFilter(input?.input);
  if (inputFilter) config.input = inputFilter;

  const outputFilter = normalizeFilter(input?.output);
  if (outputFilter) config.output = outputFilter;

  return config;
};

const isFilterActive = (filter?: GuardrailFilterConfig): filter is GuardrailFilterConfig =>
  !!filter && filter.enabled !== false;

// Convert a policy pattern (exact name or '*' wildcard) into an anchored RegExp.
const wildcardToRegExp = (pattern: string): RegExp => {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`);
};

const matchesAny = (name: string, patterns?: string[]): string | undefined => {
  if (!patterns || patterns.length === 0) return undefined;
  for (const pattern of patterns) {
    if (wildcardToRegExp(pattern).test(name)) return pattern;
  }
  return undefined;
};

/**
 * Evaluate the tool allow/deny policy for an effective tool name.
 * Deny always wins; when `allow` is non-empty a tool must match it to pass.
 */
export const evaluateToolPolicy = (
  toolName: string,
  policy?: GuardrailPolicyConfig,
): GuardrailPolicyResult => {
  if (!policy) return { allowed: true };

  const denied = matchesAny(toolName, policy.deny);
  if (denied) return { allowed: false, rule: denied };

  if (policy.allow && policy.allow.length > 0) {
    const allowed = matchesAny(toolName, policy.allow);
    if (!allowed) return { allowed: false, rule: 'not-in-allowlist' };
  }

  return { allowed: true };
};

interface CompiledRule {
  label: string;
  regex: RegExp;
  action: GuardrailAction;
  replacement: string;
}

const buildKeywordRegex = (keyword: string): RegExp =>
  new RegExp(keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');

// Compile a filter config into a flat list of executable rules.
const compileRules = (filter: GuardrailFilterConfig): CompiledRule[] => {
  const defaultAction: GuardrailAction = filter.action ?? 'redact';
  const defaultReplacement = filter.redactionText ?? DEFAULT_REDACTION;
  const rules: CompiledRule[] = [];

  for (const detector of filter.pii ?? []) {
    const regex = PII_DETECTORS[detector];
    if (!regex) continue;
    rules.push({
      label: `pii:${detector}`,
      regex: new RegExp(regex.source, regex.flags),
      action: defaultAction,
      replacement: defaultReplacement,
    });
  }

  for (const keyword of filter.keywords ?? []) {
    if (!keyword) continue;
    rules.push({
      label: `keyword:${keyword}`,
      regex: buildKeywordRegex(keyword),
      action: defaultAction,
      replacement: defaultReplacement,
    });
  }

  for (const pattern of filter.patterns ?? []) {
    if (!pattern?.pattern) continue;
    let regex: RegExp;
    try {
      regex = new RegExp(pattern.pattern, pattern.flags ?? 'gi');
    } catch {
      // Skip invalid custom patterns rather than failing every tool call.
      continue;
    }
    rules.push({
      label: pattern.name ? `pattern:${pattern.name}` : `pattern:${pattern.pattern}`,
      regex,
      action: pattern.action ?? defaultAction,
      replacement: pattern.replacement ?? defaultReplacement,
    });
  }

  return rules;
};

interface ScanState {
  rules: CompiledRule[];
  matches: Map<string, GuardrailMatch>;
  blockedRule?: string;
}

const recordMatch = (state: ScanState, rule: CompiledRule, count: number): void => {
  const existing = state.matches.get(rule.label);
  if (existing) {
    existing.count += count;
  } else {
    state.matches.set(rule.label, { rule: rule.label, action: rule.action, count });
  }
  if (rule.action === 'block' && !state.blockedRule) {
    state.blockedRule = rule.label;
  }
};

const scanString = (input: string, state: ScanState): string => {
  let output = input;
  for (const rule of state.rules) {
    // Reset lastIndex; regexes may carry the global flag and be reused.
    rule.regex.lastIndex = 0;
    const matched = input.match(rule.regex);
    if (!matched || matched.length === 0) continue;
    recordMatch(state, rule, matched.length);
    if (rule.action === 'redact') {
      rule.regex.lastIndex = 0;
      output = output.replace(rule.regex, rule.replacement);
    }
  }
  return output;
};

const scanNode = (node: unknown, state: ScanState): unknown => {
  if (typeof node === 'string') return scanString(node, state);
  if (Array.isArray(node)) return node.map((item) => scanNode(item, state));
  if (node && typeof node === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      result[key] = scanNode(value, state);
    }
    return result;
  }
  return node;
};

/**
 * Recursively scan an arbitrary value (tool arguments or a tool result) against
 * a guardrail filter, redacting matched substrings and flagging blocking rules.
 * Returns the original reference untouched when nothing matched.
 */
export const scanValue = (value: unknown, filter?: GuardrailFilterConfig): GuardrailScanResult => {
  if (!isFilterActive(filter) || value === undefined || value === null) {
    return { blocked: false, value, matches: [] };
  }

  const rules = compileRules(filter);
  if (rules.length === 0) {
    return { blocked: false, value, matches: [] };
  }

  const state: ScanState = { rules, matches: new Map() };
  const scanned = scanNode(value, state);
  const matches = [...state.matches.values()];

  return {
    blocked: !!state.blockedRule,
    blockedRule: state.blockedRule,
    // Preserve the original reference when no redaction changed anything.
    value: matches.some((m) => m.action === 'redact') ? scanned : value,
    matches,
  };
};
