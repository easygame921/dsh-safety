/**
 * 真实插件 cross-validation 抽样验证：对 6 个 npm REVIEW 样本跑 静态+动态+交叉，
 * 输出逐威胁结论，人工判断"证实/未证实"判定是否合理（找误证实/漏证实）。
 * 用法：node scripts/validate-cross.mjs
 */
import { scan, v1Rules, prepareSource } from '../dist/index.js';
import { runDynamic } from '../dist/dynamic/index.js';
import { crossValidate } from '../dist/cross/index.js';

const targets = [
  ['dsh-codex-connect', 'npm:dsh-codex-connect'],
  ['linxin666-dsh-ssh', 'npm:@linxin666/dsh-ssh'],
  ['dsh-pocket', 'npm:dsh-pocket'],
  ['dsh-market', 'npm:dshmarket'],
  ['rongyi7-dsh-stats', 'npm:@rongyi7/dsh-stats'],
  ['dsh-plug-manager', 'npm:dsh-plug-manager'],
  ['harness-pet', 'C:/Users/gojo/.dsh/profiles/web/node_modules/harness-pet'],
  ['dsh-vision', 'C:/Users/gojo/.dsh/profiles/web/node_modules/@dsh-external/dsh-vision'],
];

for (const [name, src] of targets) {
  const isLocal = src.startsWith('C:') || src.startsWith('D:') || src.startsWith('/');
  try {
    const { root, cleanup } = await prepareSource(src);
    try {
      const report = await scan({ root, sourceLabel: name }, v1Rules);
      const reviewThreats = [...new Set(report.findings.filter((f) => f.severity === 'review').map((f) => f.threatId))];
      console.log(`=== ${name} | risk=${report.risk} | review=[${reviewThreats.join(',')}]`);
      if (report.risk !== 'review') {
        console.log('  (非 REVIEW，跳过动态)');
        continue;
      }
      const dyn = await runDynamic(root, { timeoutMs: 25000, installDeps: !isLocal });
      console.log(`  dynamic: ${dyn.status} | surfaces=[${dyn.riskSurfaces.join(',')}]`);
      console.log(`  traces: ${dyn.traces.slice(0, 12).map((t) => t.type + (t.path ? ':' + String(t.path).slice(-30) : t.url ? ':' + String(t.url).slice(0, 40) : t.cmd ? ':cmd' : '')).join(' | ')}`);
      const cv = crossValidate(report, dyn);
      for (const v of cv.verdicts) {
        console.log(`    ${v.threatId} → ${v.verdict} | ${v.reason.slice(0, 70)}`);
      }
      if (cv.dynamicAddsFindings) console.log(`    ⚠️ 额外: ${cv.additions.join('; ')}`);
    } finally {
      await cleanup();
    }
  } catch (e) {
    console.log(`=== ${name} | ERR ${String(e.message).slice(0, 100)}`);
  }
}
