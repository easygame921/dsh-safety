/**
 * 规则执行引擎：对文件集跑规则，聚合证据产出 Finding。
 */
import type { Evidence, Finding, SafetyRule } from '../types.js';
import type { ScannedFile } from './files.js';
import { matchPattern, matchPath, isCommentLine } from './matchers.js';
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

/**
 * 组合规则（combinators）在同一文件内检查。
 * 邻近语义：allOf 的多个子特征必须出现在**相近的字符窗口**内（默认 ±2000 字符，
 * 约 40 行源码）才算组合——"同一函数/语句块的关联行为"；全文件散落共存
 * （如查市场 fetch + 读配置 readFile）不算组合。字符窗口同时覆盖压缩产物（单行大文件）。
 * anyOf 保持"任一出现即命中"。
 * 注释/纯文本行不参与组合匹配（注释里描述危险模式 ≠ 真实行为）。
 */
const COMBO_PROXIMITY_CHARS = 2000;

/** 把注释/纯文本行替换为等长空格（保留偏移），返回净化文本 */
function stripCommentLines(file: ScannedFile): string {
  const lines = file.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l === undefined) continue;
    if (isCommentLine(l)) lines[i] = ' '.repeat(l.length);
  }
  return lines.join('\n');
}

function runCombinators(file: ScannedFile, rule: SafetyRule): Evidence[] {
  if (!rule.combinators || rule.combinators.length === 0) return [];
  const out: Evidence[] = [];
  const clean = stripCommentLines(file);
  /** 子特征正则命中的字符偏移（可重叠搜索） */
  const hitOffsets = (p: string): number[] => {
    try {
      const re = new RegExp(p, 'g');
      const res: number[] = [];
      let m: RegExpExecArray | null;
      while ((m = re.exec(clean)) !== null) {
        res.push(m.index);
        if (m.index === re.lastIndex) re.lastIndex++;
      }
      return res;
    } catch {
      return [];
    }
  };
  for (const combo of rule.combinators) {
    if (combo.allOf && combo.allOf.length > 0) {
      const allHits = combo.allOf.map(hitOffsets);
      if (allHits.some((h) => h.length === 0)) continue; // 有子特征未命中
      // 邻近窗口：以第一个子特征的每个命中偏移为中心，其余子特征须在 ±Δ 内有命中
      let matchedOffset = -1;
      for (const off of allHits[0]!) {
        const inWindow = allHits.slice(1).every((h) => h.some((o) => Math.abs(o - off) <= COMBO_PROXIMITY_CHARS));
        if (inWindow) {
          matchedOffset = off;
          break;
        }
      }
      if (matchedOffset < 0) continue;
      const line = clean.slice(0, matchedOffset).split('\n').length;
      out.push({
        file: file.relPath,
        line,
        pattern: `combinator:${combo.name}`,
        snippet: `组合命中（±${COMBO_PROXIMITY_CHARS} 字符内）: ${combo.allOf.join(' && ')}`,
      });
    } else if (combo.anyOf && combo.anyOf.length > 0) {
      const anyHits = combo.anyOf.map(hitOffsets);
      if (anyHits.some((h) => h.length > 0)) {
        const firstOff = anyHits.find((h) => h.length > 0)![0]!;
        const line = clean.slice(0, firstOff).split('\n').length;
        out.push({
          file: file.relPath,
          line,
          pattern: `combinator:${combo.name}`,
          snippet: `组合命中（anyOf）: ${combo.anyOf.join(' || ')}`,
        });
      }
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
