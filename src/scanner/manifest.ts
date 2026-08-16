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
