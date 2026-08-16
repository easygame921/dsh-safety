/**
 * 白名单：加载配置、条目匹配、应用到发现（跳过/降级）。
 */
import type {
  AllowlistConfig, AllowlistEntry, AllowlistSuppression, Finding, ScanOptions,
} from '../types.js';

export const ALLOWLIST_VERSION = '0.1.0';

/** 内置默认白名单：面向已知正常插件的已知误报（降级而非删除，保留证据） */
export const defaultAllowlist: AllowlistConfig = {
  version: ALLOWLIST_VERSION,
  entries: [
    {
      ruleId: 'T03',
      plugin: 'harness-pet',
      action: 'downgrade',
      reason: 'harness-pet 官方社区插件：install 脚本仅用于资源装配，非攻击行为（人工复核结论）',
    },
    {
      ruleId: 'T03',
      plugin: 'dsh-vision',
      action: 'downgrade',
      reason: 'dsh-vision 识图插件：install 脚本为构建产物复制',
    },
    {
      ruleId: 'T06-001',
      plugin: 'dsh-better-sidebar',
      action: 'downgrade',
      reason: '仅文档/注释提及敏感路径，无读取行为（人工复核结论）',
    },
  ],
};

function regex(source: string): RegExp | null {
  try {
    return new RegExp(source, 'i');
  } catch {
    return null;
  }
}

/** 单条 entry 是否命中一个 finding（所有给定的匹配维度都满足） */
function entryMatches(entry: AllowlistEntry, finding: Finding, plugin: string, outboundHosts: string[]): boolean {
  if (entry.plugin) {
    const re = regex(entry.plugin);
    if (!re || !re.test(plugin)) return false;
  }
  if (entry.ruleId !== '*') {
    const ruleHit = finding.ruleId === entry.ruleId || finding.threatId === entry.ruleId;
    if (!ruleHit) return false;
  }
  if (entry.path) {
    const re = regex(entry.path);
    if (!re) return false;
    const anyFile = finding.evidence.some((e) => re.test(e.file));
    if (!anyFile) return false;
  }
  if (entry.host) {
    const re = regex(entry.host);
    if (!re) return false;
    const anyHost = outboundHosts.some((h) => re.test(h))
      || finding.evidence.some((e) => re.test(e.snippet));
    if (!anyHost) return false;
  }
  return true;
}

/**
 * 应用白名单：
 * - skip → 从 findings 移除
 * - downgrade → severity 降为 info（保留证据）
 * 返回 { findings, suppressions }（suppressions 供报告展示）
 */
export function applyAllowlist(
  findings: Finding[],
  config: AllowlistConfig,
  plugin: string,
  outboundHosts: string[],
): { findings: Finding[]; suppressions: AllowlistSuppression[] } {
  const suppressions: AllowlistSuppression[] = [];
  const kept: Finding[] = [];
  for (const finding of findings) {
    let handled: AllowlistEntry | undefined;
    for (const entry of config.entries) {
      if (entryMatches(entry, finding, plugin, outboundHosts)) {
        handled = entry;
        break;
      }
    }
    if (handled === undefined) {
      kept.push(finding);
      continue;
    }
    suppressions.push({
      ruleId: finding.ruleId,
      threatId: finding.threatId,
      action: handled.action === 'skip' ? 'skip' : 'downgrade',
      matchedEntry: handled.ruleId,
      reason: handled.reason,
    });
    if (handled.action === 'skip') continue;
    kept.push({ ...finding, severity: 'info' });
  }
  return { findings: kept, suppressions };
}

/** 从 ScanOptions 解析最终生效的白名单（内置默认 + 可选注入覆盖） */
export function resolveAllowlist(options: ScanOptions): AllowlistConfig {
  if (options.useDefaultAllowlist === false && !options.allowlist) {
    return { version: ALLOWLIST_VERSION, entries: [] };
  }
  const merged: AllowlistConfig = {
    version: options.allowlist?.version ?? ALLOWLIST_VERSION,
    entries: [
      ...(options.useDefaultAllowlist === false ? [] : defaultAllowlist.entries),
      ...(options.allowlist?.entries ?? []),
    ],
  };
  return merged;
}
