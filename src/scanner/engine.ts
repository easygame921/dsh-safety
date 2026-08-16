/**
 * 规则执行引擎：对文件集跑规则，聚合证据产出 Finding。
 */
import type { Evidence, Finding, SafetyRule } from '../types.js';
import type { ScannedFile } from './files.js';
import { matchPattern, matchPath } from './matchers.js';
import { patchDisablesSecurity, pkgInstallScripts } from './manifest.js';
import { runAstChecks } from './ast.js';

function globToRe(glob: string): RegExp {
  // 逐字符转换：** -> .* ；* -> [^/]* ；{a,b} -> (a|b) ；其余正则特殊字符转义
  let re = '';
  let i = 0;
  const n = glob.length;
  while (i < n) {
    const ch = glob[i]!;
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        re += '.*';
        i += 2;
      } else {
        re += '[^/]*';
        i += 1;
      }
      continue;
    }
    if (ch === '{') {
      const end = glob.indexOf('}', i);
      if (end !== -1) {
        const members = glob.slice(i + 1, end)
          .split(',')
          .map((m) => m.replace(/[.+^$()|[\]\\]/g, '\\$&'))
          .join('|');
        re += '(' + members + ')';
        i = end + 1;
        continue;
      }
    }
    if ('.+^$()|[]\\'.includes(ch)) re += '\\' + ch;
    else re += ch;
    i += 1;
  }
  // "**/x" 也要匹配根目录下的 x（re 以 '.*/' 开头，去掉它）
  let full = '^' + re + '$';
  if (glob.startsWith('**/')) full = '^(?:.*/)?' + re.slice(3) + '$';
  return new RegExp(full);
}

function fileMatchesGlobs(relPath: string, globs?: string[]): boolean {
  if (!globs || globs.length === 0) return true;
  for (const g of globs) {
    try {
      if (globToRe(g).test(relPath)) return true;
    } catch {
      // 忽略非法 glob
    }
  }
  return false;
}

/** 组合规则（combinators）在同一文件内检查 */
function runCombinators(file: ScannedFile, rule: SafetyRule): Evidence[] {
  if (!rule.combinators || rule.combinators.length === 0) return [];
  const out: Evidence[] = [];
  for (const combo of rule.combinators) {
    let hit = false;
    let detail = '';
    if (combo.allOf && combo.allOf.length > 0) {
      hit = combo.allOf.every((p) => {
        try {
          return new RegExp(p).test(file.content);
        } catch {
          return false;
        }
      });
      detail = combo.allOf.join(' && ');
    } else if (combo.anyOf && combo.anyOf.length > 0) {
      hit = combo.anyOf.some((p) => {
        try {
          return new RegExp(p).test(file.content);
        } catch {
          return false;
        }
      });
      detail = combo.anyOf.join(' || ');
    }
    if (hit) {
      out.push({
        file: file.relPath,
        line: 0,
        pattern: `combinator:${combo.name}`,
        snippet: `组合命中: ${detail}`,
      });
    }
  }
  return out;
}

/** 对单个文件执行单条规则，返回该文件上的证据（空 = 未命中） */
function runRuleOnFile(file: ScannedFile, rule: SafetyRule): Evidence[] {
  const ev: Evidence[] = [];
  for (const p of rule.patterns ?? []) {
    ev.push(...matchPattern(file.content, p, file.relPath));
  }
  if (rule.pathPatterns && matchPath(file.relPath, rule.pathPatterns)) {
    ev.push({ file: file.relPath, line: 0, pattern: rule.pathPatterns.join('|'), snippet: '路径匹配' });
  }
  for (const check of rule.fileChecks ?? []) {
    if (check === 'pkg-install-scripts') ev.push(...pkgInstallScripts(file.content, file.relPath));
    if (check === 'patch-disables-security') ev.push(...patchDisablesSecurity(file.content, file.relPath));
  }
  if (rule.astChecks && rule.astChecks.length > 0) {
    ev.push(...runAstChecks(file.content, file.relPath, rule.astChecks));
  }
  ev.push(...runCombinators(file, rule));
  return ev;
}

export function runRules(files: ScannedFile[], rules: SafetyRule[]): Finding[] {
  const findings: Finding[] = [];
  for (const rule of rules) {
    for (const file of files) {
      if (!fileMatchesGlobs(file.relPath, rule.fileGlobs)) continue;
      const evidence = runRuleOnFile(file, rule);
      if (evidence.length > 0) {
        findings.push({
          ruleId: rule.id,
          threatId: rule.threatId,
          severity: rule.severity,
          title: rule.title,
          description: rule.description,
          evidence,
          combinatorName: evidence.find((e) => e.pattern.startsWith('combinator:'))?.pattern.replace('combinator:', ''),
        });
      }
    }
  }
  return findings;
}
