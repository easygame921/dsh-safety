/**
 * 真实恶意样本检测率测试：fixtures/malicious-real/ 全库扫描 → 抓取率量化。
 *
 * 指标定义（README 与报告中一致）：
 *  - 样本抓取率 = 至少命中 1 个"预期威胁"且为 review 级发现的样本数 / 总样本数
 *    （恶意插件被拦下的比例——安装前会看到 review 告警）
 *  - 威胁覆盖率 = 预期 threatId 中至少产生一条 review 级发现的占比
 *    （攻击面被看到的比例，细粒度）
 *  - 误报对照：benign/ 两个样本应 0 review
 *
 * 用法：npm run build && node scripts/detection-rate.mjs [--report _checkpoints/xxx.md]
 */
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scan, v1Rules } from '../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const corpus = join(root, 'fixtures', 'malicious-real');

const manifest = JSON.parse(readFileSync(join(corpus, 'manifest.json'), 'utf8'));

/** 扫描一个样本目录，返回报告 */
async function audit(dir) {
  return scan(
    { root: join(corpus, dir), sourceLabel: dir, excludeTests: false, excludeDocs: false, useDefaultAllowlist: false },
    v1Rules,
  );
}

/** review 级命中的 threatId 集合 */
function reviewThreats(report) {
  return new Set(report.findings.filter((f) => f.severity === 'review').map((f) => f.threatId));
}

const rows = [];
for (const s of manifest.samples) {
  const report = await audit(s.dir);
  const hit = reviewThreats(report);
  const expected = new Set(s.expected);
  const missed = [...expected].filter((t) => !hit.has(t));
  const caught = missed.length === 0; // 全部预期威胁都命中 review
  const anyCaught = [...expected].some((t) => hit.has(t));
  rows.push({
    dir: s.dir,
    label: s.label,
    expected: s.expected.join(','),
    hit: [...hit].sort().join(',') || '—',
    missed: missed.join(',') || '—',
    caught,
    anyCaught,
    risk: report.risk,
    findings: report.findingsCount,
    files: report.filesScanned,
  });
}

const total = rows.length;
const sampleCaught = rows.filter((r) => r.anyCaught).length; // 至少抓到 1 个预期威胁(review)
const fullyCaught = rows.filter((r) => r.caught).length; // 全部预期威胁都命中
const expectedTotal = rows.reduce((n, r) => n + r.expected.split(',').filter(Boolean).length, 0);
const threatHitCount = rows.reduce(
  (n, r) => n + r.expected.split(',').filter(Boolean).filter((t) => r.hit.split(',').includes(t)).length,
  0,
);

// 误报对照（benign 应 0 review）
const benignDirs = readdirSync(join(root, 'fixtures', 'benign')).filter((d) => !d.startsWith('.'));
let benignReviews = 0;
const benignRows = [];
for (const d of benignDirs) {
  const r = await scan(
    { root: join(root, 'fixtures', 'benign', d), sourceLabel: d, excludeTests: false, excludeDocs: false, useDefaultAllowlist: false },
    v1Rules,
  );
  const reviews = r.findings.filter((f) => f.severity === 'review');
  benignReviews += reviews.length;
  benignRows.push({ dir: d, reviews: reviews.length, risk: r.risk });
}

// 本地真实插件对照（已人工复核为良性；存在则扫，不存在跳过——CI 等无本机路径的环境）
const localPlugins = [
  { dir: 'C:/Users/gojo/.dsh/profiles/web/node_modules/dsh-better-sidebar', label: 'dsh-better-sidebar' },
  { dir: 'C:/Users/gojo/.dsh/profiles/web/node_modules/zat-dsh-engine', label: 'zat-dsh-engine' },
  { dir: 'C:/Users/gojo/.dsh/profiles/web/node_modules/@dsh-external/dsh-vision', label: 'dsh-vision' },
  { dir: 'C:/Users/gojo/.dsh/profiles/web/node_modules/@dsh-external/dsh-super-injector', label: 'dsh-super-injector' },
  { dir: 'C:/Users/gojo/.dsh/profiles/web/node_modules/harness-pet', label: 'harness-pet' },
];
const { access } = await import('node:fs/promises');
const localRows = [];
for (const p of localPlugins) {
  let exists = true;
  try { await access(p.dir); } catch { exists = false; }
  if (!exists) continue;
  const r = await scan({ root: p.dir, sourceLabel: p.label }, v1Rules);
  const reviews = r.findings.filter((f) => f.severity === 'review');
  localRows.push({ dir: p.label, reviews: reviews.length, threats: [...new Set(reviews.map((f) => f.threatId))].join(',') || '—', risk: r.risk });
}

const sampleRate = ((sampleCaught / total) * 100).toFixed(1);
const fullRate = ((fullyCaught / total) * 100).toFixed(1);
const threatRate = ((threatHitCount / expectedTotal) * 100).toFixed(1);

const lines = [];
lines.push('# dsh-safety 真实恶意样本检测率报告');
lines.push('');
lines.push(`> 生成时间：${new Date().toISOString()}`);
lines.push(`> 规则库：v${v1Rules.length ? '' : ''}${manifest.version} manifest / ${readFileSync(join(root, 'package.json'), 'utf8').match(/"version": "([^"]+)"/)?.[1]} package`);
lines.push(`> 样本：${total} 个仿真恶意插件（fixtures/malicious-real/），攻击技法提炼自真实供应链攻击事件`);
lines.push('');
lines.push('## 总览');
lines.push('');
lines.push(`| 指标 | 数值 | 目标 |`);
lines.push(`| --- | --- | --- |`);
lines.push(`| **样本抓取率**（≥1 预期威胁命中 review） | **${sampleRate}%**（${sampleCaught}/${total}） | ≥90% |`);
lines.push(`| 全威胁命中率（全部预期威胁都命中） | ${fullRate}%（${fullyCaught}/${total}） | — |`);
lines.push(`| **威胁覆盖率**（预期 threatId 产生 review） | **${threatRate}%**（${threatHitCount}/${expectedTotal}） | ≥80% |`);
lines.push(`| 良性样本误报（benign/ 共 ${benignDirs.length} 个） | ${benignReviews} 条 review | 0 |`);
lines.push('');
lines.push('## 样本明细');
lines.push('');
lines.push('| 样本 | 预期威胁 | review 命中 | 漏报 | 判定 |');
lines.push('| --- | --- | --- | --- | --- |');
for (const r of rows) {
  const verdict = r.caught ? '✅ 全中' : r.anyCaught ? '⚠️ 部分' : '❌ 漏报';
  lines.push(`| ${r.dir} | ${r.expected} | ${r.hit} | ${r.missed} | ${verdict} |`);
}
lines.push('');
lines.push('## 良性对照');
lines.push('');
lines.push('| 样本 | review 数 | 风险 |');
lines.push('| --- | --- | --- |');
for (const b of benignRows) lines.push(`| ${b.dir} | ${b.reviews} | ${b.risk} |`);
lines.push('');
if (localRows.length > 0) {
  lines.push('## 本地真实插件对照（已人工复核良性）');
  lines.push('');
  lines.push('| 插件 | review 数 | 威胁 | 风险 |');
  lines.push('| --- | --- | --- | --- |');
  for (const b of localRows) lines.push(`| ${b.dir} | ${b.reviews} | ${b.threats} | ${b.risk} |`);
  const localReview = localRows.reduce((n, r) => n + r.reviews, 0);
  lines.push('');
  lines.push(`本地真实插件误报合计：**${localReview} 条 review**（剩余多为能力面合理项，如 prepare 脚本/git 凭据助手）`);
  lines.push('');
}
lines.push('## 判定标准');
lines.push('');
lines.push('- 抓取 = 预期威胁至少产生一条 **review 级**发现（安装前会告警）');
lines.push('- 样本抓取率衡量"恶意插件被拦下的概率"；威胁覆盖率衡量"攻击面被看到的完整度"');
lines.push('- 误报对照：良性插件不应产生 review 级告警；本地真实插件对照监控能力面噪音');

const text = lines.join('\n');
console.log(text);
console.log('');

const reportIdx = process.argv.indexOf('--report');
if (reportIdx !== -1 && process.argv[reportIdx + 1]) {
  writeFileSync(join(root, process.argv[reportIdx + 1]), text + '\n', 'utf8');
  console.log(`报告已写入：${process.argv[reportIdx + 1]}`);
}
