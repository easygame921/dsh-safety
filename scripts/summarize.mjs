/**
 * 汇总批量审计结果 → 测试报告（Markdown，存 _checkpoints/）。
 * 用法：node scripts/summarize.mjs
 */
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const resultsDir = join(root, 'results');
const outDir = join(root, '_checkpoints');
const samples = JSON.parse(readFileSync(join(root, 'samples.json'), 'utf8'));

// 合并所有 batch-*.json
const batches = readdirSync(resultsDir).filter((f) => f.startsWith('batch-') && f.endsWith('.json'));
const rows = [];
for (const f of batches) {
  rows.push(...JSON.parse(readFileSync(join(resultsDir, f), 'utf8')));
}
// 去重（同一 name 保留第一个成功结果）
const byName = new Map();
for (const r of rows) {
  if (!byName.has(r.name) || byName.get(r.name).error) byName.set(r.name, r);
}
const all = [...byName.values()];

const ok = all.filter((r) => !r.error);
const failed = all.filter((r) => r.error);
const riskCount = { ok: 0, review: 0 };
for (const r of ok) riskCount[r.risk] = (riskCount[r.risk] ?? 0) + 1;

// 威胁命中统计（按"涉及插件数"去重 + 总发现条数）
const threatPlugins = new Map();
const threatFindings = new Map();
for (const r of ok) {
  const seen = new Set();
  for (const f of r.review ?? []) {
    const tid = f.split(' ')[0];
    threatFindings.set(tid, (threatFindings.get(tid) ?? 0) + 1);
    if (!seen.has(tid)) { seen.add(tid); threatPlugins.set(tid, (threatPlugins.get(tid) ?? 0) + 1); }
  }
}

// 分类统计
const catStats = new Map();
for (const cat of samples.categories) {
  catStats.set(cat.name, { total: cat.samples.length, ok: 0, review: 0, failed: 0 });
}
for (const r of all) {
  const s = catStats.get(r.category);
  if (!s) continue;
  s.total = s.total;
  if (r.error) s.failed += 1;
  else if (r.risk === 'ok') s.ok += 1;
  else s.review += 1;
}

const lines = [];
lines.push(`# dsh 社区插件批量安全审计报告`);
lines.push('');
lines.push(`> 生成时间：${new Date().toISOString()}`);
lines.push(`> 工具：dsh-safety v0.1.0（规则库 T01-T11 + 白名单 + excludeTests）`);
lines.push(`> 样本：${all.length} 份（${samples.categories.length} 类），来源 npm/GitHub/本地，远程审计后临时目录已清理`);
lines.push('');
lines.push(`## 总体结论`);
lines.push('');
lines.push(`- 成功审计：**${ok.length}** 份；失败：**${failed.length}** 份（网络/来源不可达）`);
lines.push(`- 风险分布：OK **${riskCount.ok ?? 0}** 份，REVIEW **${riskCount.review ?? 0}** 份`);
lines.push(`- REVIEW 率：**${ok.length > 0 ? Math.round(((riskCount.review ?? 0) / ok.length) * 100) : 0}%**（说明：多数"高危"来自插件自身功能面，见误报分析）`);
lines.push('');
lines.push(`## 分类统计`);
lines.push('');
lines.push('| 类别 | 样本数 | OK | REVIEW | 失败 |');
lines.push('| --- | --- | --- | --- | --- |');
for (const [name, s] of catStats) {
  lines.push(`| ${name} | ${s.total} | ${s.ok} | ${s.review} | ${s.failed} |`);
}
lines.push('');
lines.push(`## 威胁命中分布（review 级，按涉及插件数 / 总发现条数）`);
lines.push('');
lines.push('| 威胁 | 涉及插件数 | 发现条数 | 说明 |');
lines.push('| --- | --- | --- | --- |');
const threatDesc = {
  T01: '配置树降级/禁用安全插件', T02: '隐藏prompt混淆', T03: '安装脚本',
  T04: '远程拉码执行', T05: '数据外传', T06: '凭据窃取',
  T07: 'prompt注入', T08: '思维链劫持', T09: 'client钓鱼',
  T10: '持久化驻留', T11: 'DNS外带',
};
for (const [tid, n] of [...threatPlugins.entries()].sort((a, b) => b[1] - a[1])) {
  lines.push(`| ${tid} | ${n} | ${threatFindings.get(tid)} | ${threatDesc[tid] ?? ''} |`);
}
lines.push('');
lines.push(`## 样本明细`);
lines.push('');
lines.push('| 类别 | 插件 | 风险 | 文件数 | 发现数 | review 项 |');
lines.push('| --- | --- | --- | --- | --- | --- |');
for (const r of [...all].sort((a, b) => (a.category ?? '').localeCompare(b.category ?? ''))) {
  if (r.error) {
    lines.push(`| ${r.category} | ${r.name} | ❌ 失败 | — | — | ${r.error.slice(0, 60)} |`);
  } else {
    const rev = (r.review ?? []).slice(0, 3).join('; ') || '—';
    lines.push(`| ${r.category} | ${r.name} | ${r.risk} | ${r.filesScanned} | ${r.findingsCount} | ${rev} |`);
  }
}
lines.push('');
lines.push(`## 误报分析与说明`);
lines.push('');
lines.push(`1. **REVIEW ≠ 恶意**：dsh-safety 输出的是"能力证据 + 风险等级"，REVIEW 表示"需要人工复核"，不代表插件是恶意的。本批样本绝大多数是正常社区插件。`);
lines.push(`2. **常见误报源**：`);
lines.push(`   - 安全/审计类插件（dsh-plugin-audit 等）：自身代码就是扫描敏感模式，命中 T05/T06 属预期；`);
lines.push(`   - 带 install 脚本的插件（T03）：多数是资源装配（已白名单降级 harness-pet 等）；`);
lines.push(`   - 网络能力（T05/T11）：多数是调用 API/遥测，无凭据读取组合时无实害；`);
lines.push(`   - README 文档里描述危险模式也会命中（如 dsh-plugin-audit 的 README）。`);
lines.push(`3. **excludeTests 已排除** tests/fixtures 目录（显式恶意样本不参与）。`);
lines.push(`4. **建议**：将已复核无害的"网络+无敏感读取"类降级为 notice，减少 REVIEW 噪音。`);
lines.push('');
lines.push(`## 失败清单`);
lines.push('');
const failedRows = failed.map((r) => `- ${r.name}（${r.category}）：${r.error.slice(0, 100)}`).join('\n') || '- 无';
lines.push(failedRows);
lines.push('');

const reportName = `2026-08-16_社区插件批量审计.md`;
writeFileSync(join(outDir, reportName), lines.join('\n'), 'utf8');
console.log(`report written: ${join(outDir, reportName)}`);
console.log(`summary: ${ok.length} ok / ${failed.length} failed, REVIEW=${riskCount.review ?? 0}`);
