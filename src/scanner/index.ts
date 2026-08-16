/**
 * 扫描引擎统一入口。
 */
import type { AuditReport, Finding, SafetyRule, ScanOptions } from '../types.js';
import { discoverFiles } from './files.js';
import { runRules } from './engine.js';
import { buildProfile } from './profile.js';
import { renderMarkdown, toSummary } from './report.js';
import { resolveAllowlist, applyAllowlist } from '../allowlist/index.js';

export { discoverFiles } from './files.js';
export { runRules } from './engine.js';
export { buildProfile } from './profile.js';
export { renderMarkdown, toSummary } from './report.js';
export { defaultAllowlist } from '../allowlist/index.js';

export const RULE_SET_VERSION = '0.1.0';

export async function scan(options: ScanOptions, rules: SafetyRule[]): Promise<AuditReport> {
  const started = Date.now();
  const files = await discoverFiles(options.root, {
    maxFiles: options.maxFiles,
    maxFileBytes: options.maxFileBytes,
  });
  const activeRules = options.ruleIds && options.ruleIds.length > 0
    ? rules.filter((r) => options.ruleIds!.includes(r.id))
    : rules;
  let findings: Finding[] = runRules(files, activeRules);

  const profile = buildProfile(files, [] as never[]);

  // 白名单：跳过/降级已知误报
  const allowlist = resolveAllowlist(options);
  const applied = applyAllowlist(findings, allowlist, options.sourceLabel, profile.outboundHosts);
  findings = applied.findings;
  const suppressions = applied.suppressions;

  const hasReview = findings.some((f) => f.severity === 'review');
  const risk: AuditReport['risk'] = hasReview ? 'review' : 'ok';

  return {
    source: options.sourceLabel,
    ruleSetVersion: RULE_SET_VERSION,
    risk,
    filesScanned: files.length,
    findingsCount: findings.length,
    findings,
    profile,
    ...(suppressions.length > 0 ? { suppressions } : {}),
    writesPerformed: false,
    durationMs: Date.now() - started,
    scannedAt: new Date().toISOString(),
  };
}
