/**
 * 报告生成：Markdown 权限画像卡 + JSON 摘要。
 */
import type { AuditReport, AuditSummary } from '../types.js';

export function toSummary(report: AuditReport): AuditSummary {
  return {
    source: report.source,
    risk: report.risk,
    filesScanned: report.filesScanned,
    findingsCount: report.findingsCount,
    findings: report.findings,
    writesPerformed: false,
    ruleSetVersion: report.ruleSetVersion,
  };
}

function markdownTable(headers: string[], rows: string[][]): string {
  const h = `| ${headers.join(' | ')} |`;
  const sep = `| ${headers.map(() => '---').join(' | ')} |`;
  const body = rows.map((r) => `| ${r.join(' | ')} |`).join('\n');
  return `${h}\n${sep}\n${body}`;
}

export function renderMarkdown(report: AuditReport): string {
  const riskLabel = report.risk === 'danger' ? 'DANGER' : report.risk === 'review' ? 'REVIEW' : 'OK';
  const lines: string[] = [];
  lines.push(`## 插件安全审计：${report.source}`);
  lines.push('');
  lines.push(`**风险：${riskLabel}** — ${report.risk === 'ok' ? '未发现高危项' : '建议人工复核后再安装'}`);
  lines.push('');
  lines.push(`> 扫描 ${report.filesScanned} 个文件，发现 ${report.findingsCount} 条（规则库 ${report.ruleSetVersion}，只读审计 writesPerformed=false，耗时 ${report.durationMs}ms）`);
  lines.push('');
  lines.push('### 权限画像');
  lines.push('');
  const p = report.profile;
  lines.push(markdownTable(
    ['能力面', '观察值'],
    [
      ['文件系统读取', p.filesystemRead ? '**是**' : '否'],
      ['文件系统写入', p.filesystemWrite ? '**是**' : '否'],
      ['子进程执行', p.childProcesses ? '**是**' : '否'],
      ['网络', p.network ? '**是**' : '否'],
      ['外联主机', p.outboundHosts.length > 0 ? p.outboundHosts.join(', ') : '—'],
      ['环境变量', p.envVariables.join(', ') || '—'],
      ['疑似凭据环境变量', p.credentialLookingEnv.join(', ') || '—'],
      ['凭据路径引用', p.credentialPaths.join(', ') || '—'],
      ['动态代码执行', p.dynamicCodeExecution ? '**是**' : '否'],
      ['注入服务', p.injectedServices.join(', ') || '—'],
      ['依赖', p.declaredDependencies.join(', ') || '—'],
      ['bundle patch', p.bundlePatch ? '**是**' : '否'],
      ['安装脚本', p.installScripts.join('; ') || '—'],
    ],
  ));
  lines.push('');
  lines.push('### 发现');
  lines.push('');
  if (report.findings.length === 0) {
    lines.push('无。');
  } else {
    const rows = report.findings.map((f) => {
      const locs = f.evidence.map((e) => `${e.file}${e.line > 0 ? ':' + e.line : ''}`).join(', ');
      const detail = f.evidence[0]?.snippet ?? '';
      return [f.severity === 'review' ? `**${f.severity}**` : f.severity, f.threatId, f.title, locs, detail];
    });
    lines.push(markdownTable(['严重度', '威胁', '标题', '位置', '证据片段'], rows));
    lines.push('');
    for (const f of report.findings) {
      lines.push(`- **${f.threatId} ${f.title}**（${f.severity}）— ${f.description}`);
      for (const e of f.evidence.slice(0, 5)) {
        lines.push(`  - \`${e.file}${e.line > 0 ? ':' + e.line : ''}\` ${e.snippet}`);
      }
    }
  }
  lines.push('');
  lines.push('> 审计是辅助，不是裁决——请基于证据自行判断。');
  return lines.join('\n');
}
