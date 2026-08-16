/**
 * 报告生成：Markdown 权限画像卡 + 大白话总结 + JSON 摘要。
 */
import type { AuditReport, AuditSummary, ThreatId } from '../types.js';

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

/** 威胁编号 → 大白话解释（普通用户可懂） */
const THREAT_PLAIN: Record<ThreatId, string> = {
  T01: '装完后可能会偷偷关掉你的安全保护（审批/沙箱），然后为所欲为',
  T02: '代码里藏着看不见的指令或加密内容，可能想骗过 AI 或检查',
  T03: '安装的时候会自动执行一段脚本命令（最常见的手脚）',
  T04: '运行时会从网上下载代码再执行——装的时候看不出来，防不胜防',
  T05: '可能把你的数据（包括文件内容）偷偷发给外部服务器',
  T06: '可能读取你的密钥/密码/配置文件（比如 .credentials.yaml、.ssh）',
  T07: '可能往对话里塞指令，偷偷影响 AI 的回答',
  T08: '可能偷看你的思考过程（思维链）或完整对话记录',
  T09: '可能伪造弹窗骗你点"允许"，或偷听键盘、读剪贴板',
  T10: '可能修改开机自启/启动脚本——卸载了它还能继续跑',
  T11: '可能用域名解析做隐蔽通道，偷偷往外传数据',
  T12: '在不同环境下表现不同，可能只在真实用户机器上才使坏',
  T13: '来源信誉存疑（包名像冒牌货/仓库可疑）',
  T14: '它的依赖里有可疑包（供应链投毒）',
};

/** 权限画像 → 大白话（它"能干什么"） */
function plainAbilities(report: AuditReport): string[] {
  const p = report.profile;
  const out: string[] = [];
  if (p.filesystemRead) out.push('读取你电脑上的文件');
  if (p.filesystemWrite) out.push('往你电脑上写文件');
  if (p.childProcesses) out.push('执行系统命令');
  if (p.network) out.push(`联网（访问 ${p.outboundHosts.slice(0, 5).join('、') || '外部服务器'}）`);
  if (p.dynamicCodeExecution) out.push('动态执行代码');
  if (p.credentialPaths.length > 0) out.push('涉及敏感文件（密钥/配置）');
  if (p.injectedServices.length > 0) out.push('访问内部服务');
  if (p.installScripts.length > 0) out.push('安装时执行脚本');
  if (p.bundlePatch) out.push('带配置补丁（可改装配）');
  return out;
}

/**
 * 大白话总结：普通用户能直接看懂的审计结论。
 * 机制约定（docs/AUTOTRIGGER.md）：每次输出报告后必须附带本总结。
 */
export function renderPlainSummary(report: AuditReport): string {
  const lines: string[] = [];
  const riskText = report.risk === 'ok' ? '✅ 没发现明显危险' : '⚠️ 建议谨慎，有值得注意的地方';
  const verdict = report.risk === 'ok'
    ? '可以安装，但记得从可信来源装'
    : '先别急着装——把下面几条看完，确认没问题再决定';
  lines.push('## 🗣️ 大白话总结');
  lines.push('');
  lines.push(`**结论**：${verdict}`);
  lines.push('');
  lines.push(`这个插件${report.profile.filesystemRead || report.profile.filesystemWrite || report.profile.network || report.profile.childProcesses ? '**有这些能力**：' : '比较单纯，没做什么敏感操作。'}`);
  const abilities = plainAbilities(report);
  if (abilities.length > 0) {
    for (const a of abilities) lines.push(`- ${a}`);
  }
  lines.push('');
  if (report.findings.length === 0) {
    lines.push('没有触发任何风险规则。');
  } else {
    lines.push(`发现了 ${report.findingsCount} 条记录（${report.risk === 'ok' ? '都是低级别提醒' : '其中包含需要认真看的'}），用大白话讲：`);
    lines.push('');
    for (const f of report.findings) {
      const threat = THREAT_PLAIN[f.threatId] ?? f.threatId;
      const locs = f.evidence.slice(0, 2).map((e) => `\`${e.file}${e.line > 0 ? ':' + e.line : ''}\``).join('、');
      lines.push(`- **${f.title}**（${f.severity === 'review' ? '⚠️ 重点' : 'ℹ️ 提醒'}）：${threat}${locs ? ` — 位置：${locs}` : ''}`);
    }
  }
  lines.push('');
  if (report.suppressions && report.suppressions.length > 0) {
    lines.push(`另有 ${report.suppressions.length} 条已按白名单放行（人工确认过没问题）：${report.suppressions.map((s) => s.ruleId).join('、')}。`);
  }
  lines.push('');
  lines.push('> 详细证据（文件、行号、代码片段）见上方完整报告；拿不准就搜一下这个插件的口碑再装。');
  return lines.join('\n');
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
  if (report.suppressions && report.suppressions.length > 0) {
    lines.push('### 白名单抑制');
    lines.push('');
    for (const s of report.suppressions) {
      lines.push(`- ${s.ruleId}（${s.threatId}）→ ${s.action === 'skip' ? '跳过' : '降级为 info'}：${s.reason ?? ''}`);
    }
    lines.push('');
  }
  lines.push('> 审计是辅助，不是裁决——请基于证据自行判断。');
  return lines.join('\n');
}
