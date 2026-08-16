/**
 * 匹配器：正则逐行定位 + snippet 脱敏；路径正则匹配。
 */
import type { Evidence } from '../types.js';

/** 把行内 16+ 字符的连续 base64/hex 串替换为 <redacted>，并截断到 200 字符 */
export function redactSnippet(line: string, maxLen = 200): string {
  let out = line.replace(/[A-Za-z0-9+/]{16,}={0,2}/g, '<redacted>');
  out = out.replace(/[0-9a-fA-F]{32,}/g, '<redacted>');
  if (out.length > maxLen) out = out.slice(0, maxLen) + '…';
  return out;
}

/** 对文件内容逐行跑正则，产出行号证据 */
export function matchPattern(content: string, pattern: string, file: string): Evidence[] {
  const re = new RegExp(pattern);
  const lines = content.split('\n');
  const out: Evidence[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === undefined) continue;
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
