/**
 * 批量审计：读 samples.json，对每个样本做远程审计（临时目录、审计后清理、不持久下载）。
 * 用法：node scripts/batch-audit.mjs <start> <end>
 * 结果写入 results/batch-<start>-<end>.json
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan, v1Rules, prepareSource } from '../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const samples = JSON.parse(readFileSync(join(root, 'samples.json'), 'utf8'));
const outDir = join(root, 'results');
mkdirSync(outDir, { recursive: true });

const start = Number(process.argv[2] ?? 0);
const end = Number(process.argv[3] ?? 1e9);

const flat = [];
for (const cat of samples.categories) {
  for (const s of cat.samples) flat.push({ ...s, category: cat.name });
}
const slice = flat.slice(start, end);
const results = [];

for (const item of slice) {
  // local: 前缀 → 本地路径（parseSource 不识别，脚本预处理）
  const source = item.source.startsWith('local:') ? item.source.slice('local:'.length) : item.source;
  const started = Date.now();
  try {
    const { root: pluginRoot, workDir, cleanup } = await prepareSource(source);
    try {
      const report = await scan({ root: pluginRoot, sourceLabel: item.name }, v1Rules);
      results.push({
        name: item.name,
        category: item.category,
        source: item.source,
        risk: report.risk,
        filesScanned: report.filesScanned,
        findingsCount: report.findingsCount,
        review: report.findings
          .filter((f) => f.severity === 'review')
          .map((f) => `${f.threatId} ${f.title}`),
        notice: report.findings
          .filter((f) => f.severity === 'notice' || f.severity === 'info')
          .map((f) => f.threatId),
        suppressions: (report.suppressions ?? []).map((s) => s.ruleId),
        durationMs: Date.now() - started,
      });
      console.log(`[ok] ${item.name} (${item.category}): risk=${report.risk} findings=${report.findingsCount}`);
    } finally {
      await cleanup();
    }
  } catch (err) {
    results.push({
      name: item.name,
      category: item.category,
      source: item.source,
      error: err instanceof Error ? err.message : String(err),
      durationMs: Date.now() - started,
    });
    console.log(`[ERR] ${item.name}: ${err instanceof Error ? err.message : String(err)}`);
  }
}

writeFileSync(join(outDir, `batch-${start}-${end}.json`), JSON.stringify(results, null, 2), 'utf8');
console.log(`batch ${start}-${end} done: ${results.length} samples -> results/batch-${start}-${end}.json`);
