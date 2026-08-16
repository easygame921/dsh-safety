// 验证依赖安装 + mock 迭代：对一批真实插件跑动态，统计加载成功率
import { prepareSource } from '../dist/index.js';
import { runDynamic } from '../dist/dynamic/index.js';

const samples = [
  'npm:dsh-better-edit',
  'npm:dsh-cost-log',
  'npm:dsh-speak',
  'npm:dsh-ergonomics',
  'npm:dsh-mini-tui',
  'npm:dsh-plug-manager',
];

let completed = 0;
for (const src of samples) {
  try {
    const { root, cleanup } = await prepareSource(src);
    try {
      const r = await runDynamic(root, { timeoutMs: 20000, installDeps: true });
      const surfaces = r.riskSurfaces.length > 0 ? r.riskSurfaces.join(',') : '—';
      console.log(`${r.status.padEnd(12)} ${src.padEnd(26)} surfaces=${surfaces} errs=${r.errors.length}`);
      if (r.status === 'completed') completed += 1;
    } finally {
      await cleanup();
    }
  } catch (e) {
    console.log(`${'ERR'.padEnd(12)} ${src.padEnd(26)} ${String(e).slice(0, 80)}`);
  }
}
console.log(`\ncompleted: ${completed}/${samples.length}`);
