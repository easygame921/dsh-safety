/**
 * 动态沙箱模块统一入口。
 */
import type { DynamicReport } from './runner.js';
export { runDynamic } from './runner.js';
export type { DynamicReport, DynamicTrace } from './runner.js';

/** 轨迹 → 大白话摘要（与静态报告合并展示用） */
export function renderDynamicSummary(report: DynamicReport): string {
  const lines: string[] = [];
  lines.push('## 🏃 动态沙箱行为轨迹');
  lines.push('');
  lines.push(`**状态**：${report.status === 'completed' ? '完成' : report.status}（耗时 ${report.durationMs}ms）`);
  if (report.entry) lines.push(`入口：\`${report.entry}\``);
  if (report.registeredTools && report.registeredTools.length > 0) {
    lines.push(`注册工具：${report.registeredTools.join('、')}`);
  }
  if (report.eventsTriggered && report.eventsTriggered.length > 0) {
    lines.push(`触发事件：${report.eventsTriggered.join('、')}`);
  }
  lines.push('');
  if (report.riskSurfaces && report.riskSurfaces.length > 0) {
    lines.push(`**风险面**：${report.riskSurfaces.map((s) => '`' + s + '`').join('、')}`);
    lines.push('');
  }
  if (report.traces && report.traces.length > 0) {
    lines.push('**调用轨迹**：');
    lines.push('');
    for (const t of report.traces.slice(0, 30)) {
      switch (t.type) {
        case 'network':
          lines.push(`- 🌐 网络请求：${t.method} ${t.url}${t.bodyBytes ? `（body ${t.bodyBytes}B）` : ''}`);
          break;
        case 'command':
          lines.push(`- 💻 命令调用：\`${t.cmd}\``);
          break;
        case 'fs-read':
          lines.push(`- 📖 读取文件：\`${t.path}\``);
          break;
        case 'fs-write':
          lines.push(`- ✍️ 写入文件：\`${t.path}\``);
          break;
        case 'eval':
          lines.push(`- ⚡ eval/Function：\`${t.snippet}\``);
          break;
        case 'env':
          lines.push(`- 🔑 读取环境变量：${t.key}`);
          break;
        case 'timer':
          lines.push(`- ⏱️ 定时器：${t.kind}（延迟 ${t.delay}ms，已加速立即执行）`);
          break;
        case 'tool':
          lines.push(`- 🛠️ 工具调用模拟：${t.name}`);
          break;
        default:
          lines.push(`- ${t.type}: ${JSON.stringify(t).slice(0, 120)}`);
      }
    }
    lines.push('');
  } else if (report.status === 'completed') {
    lines.push('无敏感调用轨迹（干净）。');
  }
  if (report.errors && report.errors.length > 0) {
    lines.push('**错误/注意**：');
    for (const e of report.errors.slice(0, 5)) lines.push(`- ${e}`);
    lines.push('');
  }
  lines.push('> 沙箱约束：网络不真实外发、命令不执行、eval 不执行、文件读写隔离、超时强杀。轨迹为插件代码在模拟环境中的调用意图。');
  return lines.join('\n');
}
