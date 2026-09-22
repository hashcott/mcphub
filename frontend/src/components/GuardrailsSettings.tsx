import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ShieldCheck, Plus, Trash2 } from 'lucide-react';
import { Switch } from '@/components/ui/ToggleGroup';
import { useSettingsData } from '@/hooks/useSettingsData';
import type {
  GuardrailAction,
  GuardrailFilterConfig,
  GuardrailPattern,
  GuardrailsConfig,
} from '@/types';

const PII_OPTIONS = ['email', 'phone', 'credit-card', 'ssn', 'ip'] as const;

const inputClass =
  'mt-1 block w-full py-2 px-3 border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm form-input';
const selectClass = inputClass + ' form-select';

const linesToArray = (text: string): string[] =>
  text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

const arrayToLines = (arr?: string[]): string => (arr ?? []).join('\n');

const defaultFilter = (): GuardrailFilterConfig => ({
  enabled: true,
  pii: [],
  keywords: [],
  patterns: [],
  action: 'redact',
  redactionText: '[REDACTED]',
});

interface FilterEditorProps {
  title: string;
  description: string;
  filter: GuardrailFilterConfig;
  onChange: (next: GuardrailFilterConfig) => void;
  disabled?: boolean;
}

const FilterEditor: React.FC<FilterEditorProps> = ({
  title,
  description,
  filter,
  onChange,
  disabled,
}) => {
  const { t } = useTranslation();
  const patterns = filter.patterns ?? [];

  const togglePii = (detector: string, checked: boolean) => {
    const current = new Set(filter.pii ?? []);
    if (checked) current.add(detector);
    else current.delete(detector);
    onChange({ ...filter, pii: [...current] });
  };

  const updatePattern = (index: number, patch: Partial<GuardrailPattern>) => {
    const next = patterns.map((p, i) => (i === index ? { ...p, ...patch } : p));
    onChange({ ...filter, patterns: next });
  };

  const addPattern = () => {
    onChange({ ...filter, patterns: [...patterns, { pattern: '', action: 'redact' }] });
  };

  const removePattern = (index: number) => {
    onChange({ ...filter, patterns: patterns.filter((_, i) => i !== index) });
  };

  return (
    <div
      className="space-y-3 rounded-md p-4"
      style={{ border: '1px solid var(--hub-line)', background: 'var(--hub-bg-2)' }}
    >
      <div className="flex items-center justify-between">
        <div>
          <h3 className="font-medium" style={{ color: 'var(--hub-ink)', fontSize: 13 }}>
            {title}
          </h3>
          <p style={{ fontSize: 12, color: 'var(--hub-ink-3)' }}>{description}</p>
        </div>
        <Switch
          disabled={disabled}
          checked={filter.enabled !== false}
          onCheckedChange={(checked) => onChange({ ...filter, enabled: checked })}
        />
      </div>

      {filter.enabled !== false && (
        <>
          <div>
            <label className="text-xs font-medium" style={{ color: 'var(--hub-ink-2)' }}>
              {t('settings.guardrailsPii') || 'PII detectors'}
            </label>
            <div className="mt-2 flex flex-wrap gap-3">
              {PII_OPTIONS.map((detector) => (
                <label
                  key={detector}
                  className="flex items-center gap-1.5 text-sm"
                  style={{ color: 'var(--hub-ink-2)' }}
                >
                  <input
                    type="checkbox"
                    disabled={disabled}
                    checked={(filter.pii ?? []).includes(detector)}
                    onChange={(e) => togglePii(detector, e.target.checked)}
                  />
                  {detector}
                </label>
              ))}
            </div>
          </div>

          <div>
            <label className="text-xs font-medium" style={{ color: 'var(--hub-ink-2)' }}>
              {t('settings.guardrailsKeywords') || 'Keywords (one per line)'}
            </label>
            <textarea
              rows={3}
              disabled={disabled}
              value={arrayToLines(filter.keywords)}
              onChange={(e) => onChange({ ...filter, keywords: linesToArray(e.target.value) })}
              className={inputClass}
              placeholder="internal-only&#10;confidential"
            />
          </div>

          <div>
            <div className="flex items-center justify-between">
              <label className="text-xs font-medium" style={{ color: 'var(--hub-ink-2)' }}>
                {t('settings.guardrailsPatterns') || 'Custom regex patterns'}
              </label>
              <button
                type="button"
                disabled={disabled}
                onClick={addPattern}
                className="flex items-center gap-1 text-xs text-blue-600 hover:text-blue-700"
              >
                <Plus size={13} /> {t('settings.guardrailsAddPattern') || 'Add pattern'}
              </button>
            </div>
            <div className="mt-2 space-y-2">
              {patterns.map((pattern, index) => (
                <div key={index} className="flex flex-wrap items-center gap-2">
                  <input
                    type="text"
                    disabled={disabled}
                    value={pattern.name ?? ''}
                    onChange={(e) => updatePattern(index, { name: e.target.value })}
                    className={inputClass + ' flex-1 min-w-[120px]'}
                    placeholder={t('settings.guardrailsPatternName') || 'name'}
                  />
                  <input
                    type="text"
                    disabled={disabled}
                    value={pattern.pattern}
                    onChange={(e) => updatePattern(index, { pattern: e.target.value })}
                    className={inputClass + ' flex-[2] min-w-[160px] font-mono'}
                    placeholder={t('settings.guardrailsPatternRegex') || 'regex, e.g. sk-[a-z0-9]+'}
                  />
                  <select
                    disabled={disabled}
                    value={pattern.action ?? 'redact'}
                    onChange={(e) =>
                      updatePattern(index, { action: e.target.value as GuardrailAction })
                    }
                    className={selectClass + ' w-28'}
                  >
                    <option value="redact">{t('settings.guardrailsActionRedact') || 'Redact'}</option>
                    <option value="block">{t('settings.guardrailsActionBlock') || 'Block'}</option>
                  </select>
                  <button
                    type="button"
                    disabled={disabled}
                    onClick={() => removePattern(index)}
                    className="text-red-500 hover:text-red-600"
                    aria-label={t('common.delete') || 'Delete'}
                  >
                    <Trash2 size={15} />
                  </button>
                </div>
              ))}
            </div>
          </div>

          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <label className="text-xs font-medium" style={{ color: 'var(--hub-ink-2)' }}>
                {t('settings.guardrailsDefaultAction') || 'Default action (PII / keywords)'}
              </label>
              <select
                disabled={disabled}
                value={filter.action ?? 'redact'}
                onChange={(e) => onChange({ ...filter, action: e.target.value as GuardrailAction })}
                className={selectClass}
              >
                <option value="redact">{t('settings.guardrailsActionRedact') || 'Redact'}</option>
                <option value="block">{t('settings.guardrailsActionBlock') || 'Block'}</option>
              </select>
            </div>
            <div>
              <label className="text-xs font-medium" style={{ color: 'var(--hub-ink-2)' }}>
                {t('settings.guardrailsRedactionText') || 'Redaction text'}
              </label>
              <input
                type="text"
                disabled={disabled}
                value={filter.redactionText ?? ''}
                onChange={(e) => onChange({ ...filter, redactionText: e.target.value })}
                className={inputClass}
                placeholder="[REDACTED]"
              />
            </div>
          </div>
        </>
      )}
    </div>
  );
};

const GuardrailsSettings: React.FC = () => {
  const { t } = useTranslation();
  const { guardrailsConfig, updateGuardrailsConfig, loading } = useSettingsData();
  const [expanded, setExpanded] = useState(false);
  const [draft, setDraft] = useState<GuardrailsConfig>(guardrailsConfig);

  useEffect(() => {
    setDraft(guardrailsConfig);
  }, [guardrailsConfig]);

  const enabled = draft.enabled === true;

  const handleSave = async () => {
    await updateGuardrailsConfig(draft);
  };

  return (
    <div className="hub-card mb-6 overflow-hidden">
      <div
        className="flex justify-between items-center cursor-pointer transition-colors hover:bg-[var(--hub-surface-hover)] px-6 py-3"
        onClick={() => setExpanded((v) => !v)}
      >
        <div className="flex items-center gap-2.5">
          <ShieldCheck size={15} className="text-[var(--hub-ink-2)]" />
          <h2 className="font-medium text-[var(--hub-ink)]">
            {t('settings.guardrailsTitle') || 'Guardrails'}
          </h2>
          <span className="hub-status ml-2" data-state={enabled ? 'on' : 'off'}>
            <span
              className="hub-dot"
              style={{
                background: enabled ? 'var(--hub-ok)' : 'var(--hub-ink-3)',
                boxShadow: enabled ? '0 0 0 3px oklch(0.66 0.15 145 / 0.15)' : 'none',
              }}
            />
            <span
              style={{
                color: enabled ? 'oklch(0.4 0.13 145)' : 'var(--hub-ink-3)',
                fontSize: 12,
              }}
            >
              {enabled ? t('common.active') : t('common.inactive')}
            </span>
          </span>
        </div>
        <span className="text-[var(--hub-ink-3)]">{expanded ? '−' : '+'}</span>
      </div>

      {expanded && (
        <div className="px-6 py-5 border-t border-[var(--hub-line-2)] space-y-4">
          <div
            className="flex items-center justify-between rounded-md p-3"
            style={{ border: '1px solid var(--hub-line)', background: 'var(--hub-bg-2)' }}
          >
            <div>
              <h3 className="font-medium" style={{ color: 'var(--hub-ink)', fontSize: 13 }}>
                {t('settings.guardrailsEnable') || 'Enable guardrails'}
              </h3>
              <p style={{ fontSize: 12, color: 'var(--hub-ink-3)' }}>
                {t('settings.guardrailsDescription') ||
                  'Apply global safety controls to every MCP tool call. Changes apply to the next tool call.'}
              </p>
            </div>
            <Switch
              disabled={loading}
              checked={enabled}
              onCheckedChange={(checked) => setDraft({ ...draft, enabled: checked })}
            />
          </div>

          {/* Tool allow/deny policy */}
          <div
            className="space-y-3 rounded-md p-4"
            style={{ border: '1px solid var(--hub-line)', background: 'var(--hub-bg-2)' }}
          >
            <div>
              <h3 className="font-medium" style={{ color: 'var(--hub-ink)', fontSize: 13 }}>
                {t('settings.guardrailsPolicyTitle') || 'Tool policy'}
              </h3>
              <p style={{ fontSize: 12, color: 'var(--hub-ink-3)' }}>
                {t('settings.guardrailsPolicyDescription') ||
                  'Match the effective tool name (e.g. server-tool). Use * as a wildcard. Deny takes precedence.'}
              </p>
            </div>
            <div className="grid gap-3 md:grid-cols-2">
              <div>
                <label className="text-xs font-medium" style={{ color: 'var(--hub-ink-2)' }}>
                  {t('settings.guardrailsAllow') || 'Allow (one per line, empty = all)'}
                </label>
                <textarea
                  rows={3}
                  disabled={loading}
                  value={arrayToLines(draft.policy?.allow)}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      policy: { ...draft.policy, allow: linesToArray(e.target.value) },
                    })
                  }
                  className={inputClass + ' font-mono'}
                  placeholder="fs-*&#10;github-*"
                />
              </div>
              <div>
                <label className="text-xs font-medium" style={{ color: 'var(--hub-ink-2)' }}>
                  {t('settings.guardrailsDeny') || 'Deny (one per line)'}
                </label>
                <textarea
                  rows={3}
                  disabled={loading}
                  value={arrayToLines(draft.policy?.deny)}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      policy: { ...draft.policy, deny: linesToArray(e.target.value) },
                    })
                  }
                  className={inputClass + ' font-mono'}
                  placeholder="shell-*&#10;fs-delete"
                />
              </div>
            </div>
          </div>

          <FilterEditor
            title={t('settings.guardrailsInputTitle') || 'Input filter'}
            description={
              t('settings.guardrailsInputDescription') ||
              'Scan tool-call arguments before they reach the upstream server.'
            }
            filter={draft.input ?? defaultFilter()}
            onChange={(next) => setDraft({ ...draft, input: next })}
            disabled={loading}
          />

          <FilterEditor
            title={t('settings.guardrailsOutputTitle') || 'Output filter'}
            description={
              t('settings.guardrailsOutputDescription') ||
              'Scan tool-call results before they are returned to the client.'
            }
            filter={draft.output ?? defaultFilter()}
            onChange={(next) => setDraft({ ...draft, output: next })}
            disabled={loading}
          />

          <div className="flex justify-end pt-1">
            <button
              type="button"
              disabled={loading}
              onClick={handleSave}
              className="hub-btn primary"
            >
              {t('common.save')}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default GuardrailsSettings;
