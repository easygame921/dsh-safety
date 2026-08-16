/**
 * dsh-safety 公共入口。
 */
export { scan, renderMarkdown, toSummary, RULE_SET_VERSION } from './scanner/index.js';
export { v1Rules } from './rules/index.js';
export { createServer } from './mcp/server.js';
export { parseSource, resolveSource, prepareSource } from './resolve/source.js';
export type {
  AuditReport, AuditSummary, Finding, Evidence, PermissionProfile,
  SafetyRule, Severity, ThreatId, ScanOptions, RuleId,
} from './types.js';
