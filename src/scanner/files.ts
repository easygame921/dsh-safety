/**
 * 文件发现：递归遍历插件目录，只读、限量、排除依赖与构建目录。
 */
import { promises as fs } from 'node:fs';
import { join, relative, extname } from 'node:path';

export interface ScannedFile {
  /** 绝对路径 */
  path: string;
  /** 相对插件根的路径（报告用） */
  relPath: string;
  content: string;
  size: number;
}

const EXCLUDE_DIRS = new Set(['node_modules', '.git', 'dist', '.dsh-safety-cache']);
const INCLUDE_EXT = new Set(['.js', '.ts', '.mjs', '.cjs', '.json', '.yml', '.yaml', '.md', '.ps1', '.sh', '.jsx', '.tsx']);

export interface DiscoverOptions {
  maxFiles?: number;
  maxFileBytes?: number;
}

export async function discoverFiles(root: string, opts: DiscoverOptions = {}): Promise<ScannedFile[]> {
  const maxFiles = opts.maxFiles ?? 400;
  const maxBytes = opts.maxFileBytes ?? 256 * 1024;
  const out: ScannedFile[] = [];
  let skipped = 0;

  async function walk(dir: string): Promise<void> {
    if (out.length >= maxFiles) return;
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (out.length >= maxFiles) return;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (EXCLUDE_DIRS.has(entry.name)) continue;
        await walk(full);
        continue;
      }
      if (!entry.isFile()) continue;
      const ext = extname(entry.name).toLowerCase();
      if (!INCLUDE_EXT.has(ext)) continue;
      let stat;
      try {
        stat = await fs.stat(full);
      } catch {
        continue;
      }
      if (stat.size > maxBytes) {
        skipped += 1;
        continue;
      }
      if (stat.size > maxFiles * maxBytes) continue; // 防御性
      let content: string;
      try {
        const buf = await fs.readFile(full);
        if (buf.includes(0)) continue; // 二进制
        content = buf.toString('utf8');
      } catch {
        continue;
      }
      out.push({ path: full, relPath: relative(root, full).replaceAll('\\', '/'), content, size: stat.size });
    }
  }

  await walk(root);
  void skipped;
  return out;
}
