/**
 * manifest 级文件检查：package.json 安装脚本、cordis.patch.yml 禁用安全插件。
 */
import yaml from 'js-yaml';
import type { Evidence } from '../types.js';

const SECURITY_PLUGIN_IDS = new Set([
  'approval', 'sandbox', 'permission', 'bash-sandbox', 'pwsh-sandbox',
  'fs-observation-policy', 'dsh-fs-sandbox', 'dsh-user-approval',
  'dsh-permission-presets', 'dsh-sandbox-local', 'dsh-sandbox-policy',
  'dsh-bash-sandbox', 'dsh-pwsh-sandbox', 'dsh-fs-observation-policy',
]);

/** package.json 的 preinstall/postinstall/prepare 脚本检查 */
export function pkgInstallScripts(content: string, relPath: string): Evidence[] {
  if (!relPath.endsWith('package.json')) return [];
  let pkg: unknown;
  try {
    pkg = JSON.parse(content);
  } catch {
    return [];
  }
  const scripts = (pkg as { scripts?: Record<string, string> })?.scripts;
  if (!scripts) return [];
  const out: Evidence[] = [];
  for (const [name, cmd] of Object.entries(scripts)) {
    if (name === 'preinstall' || name === 'postinstall' || name === 'prepare') {
      out.push({
        file: relPath,
        line: 0,
        pattern: `install-script:${name}`,
        snippet: `${name}: ${String(cmd).slice(0, 180)}`,
      });
    }
  }
  return out;
}

/** cordis.patch.yml / bundle patch：递归查找 disabled 安全插件条目 */
export function patchDisablesSecurity(content: string, relPath: string): Evidence[] {
  if (!/\.(ya?ml|json)$/i.test(relPath)) return [];
  let data: unknown;
  try {
    data = yaml.load(content);
  } catch {
    return [];
  }
  const out: Evidence[] = [];
  const lines = content.split('\n');

  function findLineFor(idOrName: string, hintLine: number): number {
    if (hintLine > 0) return hintLine;
    const idx = lines.findIndex((l) => l.includes(idOrName));
    return idx >= 0 ? idx + 1 : 0;
  }

  function walk(node: unknown, hintLine = 0): void {
    if (Array.isArray(node)) {
      for (const item of node) {
        if (item && typeof item === 'object') {
          const rec = item as Record<string, unknown>;
          const disabled = rec.disabled === true;
          const id = typeof rec.id === 'string' ? rec.id : '';
          const name = typeof rec.name === 'string' ? rec.name : '';
          if (disabled && (SECURITY_PLUGIN_IDS.has(id) || SECURITY_PLUGIN_IDS.has(name))) {
            out.push({
              file: relPath,
              line: findLineFor(id || name, hintLine),
              pattern: `patch-disables-security:${id || name}`,
              snippet: `disabled security plugin: ${id || name}`,
            });
          }
          walk(rec.insert, hintLine);
          walk(rec.config, hintLine);
        }
      }
      return;
    }
    if (node && typeof node === 'object') {
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        if (k === 'insert') walk(v, 0);
        else if (v && typeof v === 'object') walk(v, 0);
      }
    }
  }

  walk(data);
  return out;
}

// ── 依赖链审计（T14）──────────────────────────────────────────────────────

/** 已知被投毒/恶意的 npm 包名单（真实供应链事件，2021-2025 汇总） */
const KNOWN_MALICIOUS_PACKAGES = new Set([
  'event-stream', // 2018 被投毒（flatmap-stream 后门，Bitcoin 窃取）
  'flatmap-stream', // event-stream 事件的后门载荷
  'ua-parser-js', // 2021 被投毒（cryptominer，非官方版本 0.7.29/0.8.0）
  'rc', // 2021 被投毒（非官方 1.2.9）
  'coa', // 2021 被投毒（非官方 2.0.3/2.1.1/3.0.1）
  'is-promise', // 2021 被投毒（非官方 2.2.2）
  'node-ipc', // 2022 peacenotwar 抗议性恶意（删文件）
  'colors', // 2022 faker.js/colors 抗议性破坏
  'faker.js', // 同上
  'crypto-js', // 2023 被投毒（非官方 4.2.0，窃取密钥）
  'eslint-scope', // 2018 被投毒（凭据窃取）
  'babel-mixin', // 恶意后门
  'sequelize', // 2019 非官方版本投毒（凭据窃取）
  'user-agent-parser', // ua-parser-js 的 typosquat 变体
  'ua-parser-js-pro', // 假冒变体
  // 注：lodahs/loadsh/axois/exprees 等 typosquat 由通用检测（长度相同+距离1）覆盖，
  // 不硬编码——名单只收录"事件实证"的投毒包
]);

/** 高价值知名包名（typosquatting 相似度基准） */
const HIGH_VALUE_PACKAGES = [
  'lodash', 'express', 'axios', 'node-fetch', 'request', 'debug', 'mime',
  'uuid', 'chalk', 'yaml', 'js-yaml', 'dotenv', 'ws', 'zod', 'commander',
  'typescript', 'tsx', 'vite', 'webpack', 'eslint', 'prettier', 'semver',
  'deepseek-harness', 'dsh-safety', 'dsh-plugin-audit', 'harness-pet', 'dsh-vision',
  'dsh-market', 'dsh-better-sidebar', 'dsh-super-injector', 'dsh-mcp-client',
];

/** Optimal String Alignment 距离（Damerau-Levenshtein 的 OSA 变体：相邻字符交换计 1 次编辑） */
function osaDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (Math.abs(m - n) > 1) return 3; // 长度差>1 直接跳过
  const d: number[][] = Array.from({ length: m + 1 }, () => Array<number>(n + 1).fill(0));
  for (let i = 0; i <= m; i++) d[i]![0] = i;
  for (let j = 0; j <= n; j++) d[0]![j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i]![j] = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      // 相邻字符交换（typosquat 常用：lodahs/lodash、axois/axios）
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i]![j] = Math.min(d[i]![j]!, d[i - 2]![j - 2]! + 1);
      }
    }
  }
  return d[m]![n]!;
}

/** 解析依赖声明并输出 T14 证据（typosquat / 可疑协议 / 已知恶意包） */
export function pkgDepsAudit(content: string, relPath: string): Evidence[] {
  if (!relPath.endsWith('package.json')) return [];
  let pkg: unknown;
  try {
    pkg = JSON.parse(content);
  } catch {
    return [];
  }
  const out: Evidence[] = [];
  const deps: Record<string, string> = {};
  for (const section of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    const d = (pkg as Record<string, Record<string, string> | undefined>)?.[section];
    if (d) Object.assign(deps, d);
  }
  const depNames = Object.keys(deps);
  const seen = new Set<string>();

  for (const name of depNames) {
    const range = deps[name] ?? '';
    // 1) 已知恶意包名单（精确匹配 + 去掉 scope 后匹配）
    const bare = name.startsWith('@') ? name.split('/')[1] ?? name : name;
    const hitKnown = KNOWN_MALICIOUS_PACKAGES.has(name) || KNOWN_MALICIOUS_PACKAGES.has(bare);
    if (hitKnown && !seen.has(name)) {
      seen.add(name);
      out.push({
        file: relPath,
        line: 0,
        pattern: 'dep-known-malicious',
        snippet: `依赖命中已知恶意/被投毒包名单: ${name}`,
      });
    }
    // 2) 可疑协议：file: / git+ / http://（非 https）
    if (/^(file:|git(\+|:)|http:\/\/)/.test(range)) {
      out.push({
        file: relPath,
        line: 0,
        pattern: 'dep-suspicious-protocol',
        snippet: `依赖 ${name} 使用可疑来源协议: ${range.slice(0, 80)}`,
      });
    }
    // 3) typosquatting：与高价值知名包**长度相同且 OSA 距离 =1**（单字符替换或相邻交换，
    //    如 lodahs/lodash、axois/axios）；距离 2 的短词（clsx/tsx、vitest/vite）为合法包，
    //    不再误报
    const key = `typo:${bare}`;
    if (!seen.has(key) && !KNOWN_MALICIOUS_PACKAGES.has(name) && !KNOWN_MALICIOUS_PACKAGES.has(bare)) {
      for (const known of HIGH_VALUE_PACKAGES) {
        if (bare === known) break;
        if (bare.length === known.length && osaDistance(bare, known) === 1) {
          seen.add(key);
          out.push({
            file: relPath,
            line: 0,
            pattern: 'dep-typosquat',
            snippet: `依赖 ${name} 与知名包 ${known} 仅 1 次编辑差异（单字符替换/相邻交换，长度相同）——疑似 typosquatting`,
          });
          break;
        }
      }
    }
  }
  return out;
}

/** 通配版本依赖检查（* / latest）——提示级：DSH 官方 @deepseek-ai/* 包用 * 是生态标准 */
export function pkgDepWideRange(content: string, relPath: string): Evidence[] {
  if (!relPath.endsWith('package.json')) return [];
  let pkg: unknown;
  try {
    pkg = JSON.parse(content);
  } catch {
    return [];
  }
  const deps: Record<string, string> = {};
  for (const section of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    const d = (pkg as Record<string, Record<string, string> | undefined>)?.[section];
    if (d) Object.assign(deps, d);
  }
  const out: Evidence[] = [];
  for (const [name, range] of Object.entries(deps)) {
    if (/^(\*|latest)$/.test(String(range).trim())) {
      out.push({
        file: relPath,
        line: 0,
        pattern: 'dep-wide-range',
        snippet: `依赖 ${name} 版本为通配（* / latest）——供应链投毒常见载体；DSH 官方 @deepseek-ai/* 包属标准做法`,
      });
    }
  }
  return out;
}
