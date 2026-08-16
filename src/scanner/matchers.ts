/**
 * 匹配器：正则逐行定位 + snippet 脱敏；路径正则匹配。
 * 代码规则默认跳过注释/纯文本行（注释里描述危险模式 ≠ 真实行为）。
 */
import type { Evidence } from '../types.js';

/** 把行内 16+ 字符的连续 base64/hex 串替换为 <redacted>，并截断到 200 字符 */
export function redactSnippet(line: string, maxLen = 200): string {
  let out = line.replace(/[A-Za-z0-9+/]{16,}={0,2}/g, '<redacted>');
  out = out.replace(/[0-9a-fA-F]{32,}/g, '<redacted>');
  if (out.length > maxLen) out = out.slice(0, maxLen) + '…';
  return out;
}

/**
 * 判断一行是否为"注释/纯文本"行（命中不应作为代码行为证据）：
 * - 整行注释：以 //、/*、*（JSDoc）、#、-- 开头
 * - 行尾注释：危险模式只出现在 // 之后（行首代码为空）
 * 仅适用于代码文件（调用方限定 js/ts 等）；md/yml 等由 excludeDocs/角色规则处理。
 */
export function isCommentLine(line: string): boolean {
  const t = line.trimStart();
  if (!t) return true; // 空行
  if (t.startsWith('//') || t.startsWith('/*') || t.startsWith('*') || t.startsWith('#') || t.startsWith('--')) return true;
  return false;
}

/** 对文件内容逐行跑正则，产出行号证据；默认跳过注释/纯文本行 */
export function matchPattern(content: string, pattern: string, file: string, skipComments = true): Evidence[] {
  const re = new RegExp(pattern);
  const lines = content.split('\n');
  const out: Evidence[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === undefined) continue;
    if (skipComments && isCommentLine(line)) continue;
    if (re.test(line)) {
      out.push({ file, line: i + 1, pattern, snippet: redactSnippet(line.trim()) });
    }
  }
  return out;
}

/** 路径正则匹配（任一命中即 true） */
export function matchPath(relPath: string, pathPatterns: string[]): boolean {
  for (const p of pathPatterns) {
    try {
      if (new RegExp(p).test(relPath)) return true;
    } catch {
      // 非法正则忽略
    }
  }
  return false;
}
