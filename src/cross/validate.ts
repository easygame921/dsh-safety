/**
 * 动态 ↔ 静态 cross-validation：把静态发现的威胁与动态轨迹交叉印证。
 *
 * 动机：静态 REVIEW 不等于恶意（可能是功能面噪音）；动态给了"运行时到底做了什么"。
 * 合并结论三态：
 *  - confirmed（动态证实）：静态说 T06 读凭据，动态真的 fs-read 了敏感路径
 *  - unconfirmed（未证实）：静态说 T06，动态没触发相关行为（可能功能面噪音/未触发到）
 *  - contradicted（证伪）：静态 notice 级能力，动态却出现更严重行为（升级信号）
 *
 * 威胁 → 动态证据映射（每条 review 规则判定它需要什么动态证据才算"证实"）。
 */
import type { AuditReport, Finding, ThreatId } from '../types.js';
import type { DynamicReport, DynamicTrace } from '../dynamic/index.js';

export interface ThreatVerdict {
  threatId: ThreatId;
  severity: 'review' | 'notice';
  /** 静态命中数（该威胁的 review 发现数） */
  staticFindings: number;
  /** 交叉结论 */
  verdict: 'confirmed' | 'unconfirmed' | 'contradicted' | 'no-dynamic' | 'load-failed';
  /** 支撑证据说明 */
  reason: string;
  /** 命中的动态轨迹（抽样） */
  matchingTraces: DynamicTrace[];
}

export interface CrossValidationResult {
  hasDynamic: boolean;
  verdicts: ThreatVerdict[];
  /** 全局结论：动态证实了至少一个静态风险？ */
  dynamicConfirmsRisk: boolean;
  /** 动态暴露了静态没发现的行为？ */
  dynamicAddsFindings: boolean;
  /** 动态额外发现的描述列表（静态未标 review 的行为） */
  additions: string[];
  /** 大白话一句话总结 */
  plain: string;
}

const SENSITIVE_RE = /\.credentials\.ya?ml|id_rsa|id_ed25519|\.ssh|\.npmrc|\.codex|\.aws[/\\]credentials|\.netrc|(?<![\w.])[.]env\b|\.dsh[/\\]sessions/i;

/** 一条动态轨迹是否"敏感读取" */
function isSensitiveRead(t: DynamicTrace): boolean {
  return t.type === 'fs-read' && typeof t.path === 'string' && SENSITIVE_RE.test(t.path);
}
/** 动态轨迹里是否存在某种类型的调用 */
function hasTrace(ts: DynamicTrace[], type: string, pred?: (t: DynamicTrace) => boolean): boolean {
  return ts.some((t) => t.type === type && (!pred || pred(t)));
}

interface EvidenceRequirement {
  threatId: ThreatId;
  /** 需要满足的动态证据（任一满足即证实） */
  anyOf: string[];
  /** 描述（大白话） */
  describe: string;
}

const REQUIREMENTS: EvidenceRequirement[] = [
  {
    threatId: 'T01',
    anyOf: ['patch-disables-security'],
    describe: '启动时禁用安全插件（patch 层面行为）',
  },
  {
    threatId: 'T02',
    anyOf: ['eval', 'load-failed-obfuscated'],
    describe: 'eval/Function 执行编码载荷',
  },
  {
    threatId: 'T03',
    anyOf: ['install-script'],
    describe: '安装脚本（安装期攻击，动态不执行安装钩子——维持 unconfirmed 属预期）',
  },
  {
    threatId: 'T04',
    anyOf: ['network-then-eval', 'eval'],
    describe: '远程拉码后执行（fetch + eval 数据流）',
  },
  {
    threatId: 'T05',
    anyOf: ['network-exfil', 'sensitive-read-then-network'],
    describe: '敏感数据外传（网络 + 敏感读取组合）',
  },
  {
    threatId: 'T06',
    anyOf: ['sensitive-read'],
    describe: '读取凭据/敏感路径内容',
  },
  {
    threatId: 'T07',
    anyOf: ['prompt-inject'],
    describe: '注入指令文本（提示词层面，动态难直接触发——维持 unconfirmed 属预期）',
  },
  {
    threatId: 'T08',
    anyOf: ['sensitive-read-sessions'],
    describe: '读取会话日志/思维链',
  },
  {
    threatId: 'T09',
    anyOf: ['client-eval', 'eval'],
    describe: 'client 端钓鱼（client 不在沙箱范围——维持 unconfirmed 属预期）',
  },
  {
    threatId: 'T10',
    anyOf: ['fs-write-persistence', 'command'],
    describe: '持久化驻留（写 rc/计划任务/自启）',
  },
  {
    threatId: 'T11',
    anyOf: ['dns-tunnel', 'network'],
    describe: 'DNS 外带（dns.resolve + 敏感读取）',
  },
  {
    threatId: 'T14',
    anyOf: ['dep-poison'],
    describe: '依赖链投毒（依赖声明层面，动态不安装依赖——维持 unconfirmed 属预期）',
  },
];

/** 判断动态轨迹是否满足某条证据要求（anyOf 语义） */
function evidenceMet(requirement: EvidenceRequirement, traces: DynamicTrace[]): boolean {
  for (const ev of requirement.anyOf) {
    switch (ev) {
      case 'eval':
        if (hasTrace(traces, 'eval')) return true;
        break;
      case 'sensitive-read':
        if (hasTrace(traces, 'fs-read', isSensitiveRead)) return true;
        break;
      case 'sensitive-read-sessions':
        if (hasTrace(traces, 'fs-read', (t) => typeof t.path === 'string' && /\.dsh[/\\]sessions|[/\\]sessions[/\\]/i.test(t.path))) return true;
        break;
      case 'sensitive-read-then-network': {
        const srIdx = traces.findIndex(isSensitiveRead);
        const netIdx = traces.findIndex((t) => t.type === 'network');
        if (srIdx >= 0 && netIdx > srIdx) return true;
        break;
      }
      case 'network-exfil': {
        const net = traces.some((t) => t.type === 'network');
        const sr = traces.some(isSensitiveRead);
        const cmd = traces.some((t) => t.type === 'command');
        if (net && (sr || cmd)) return true;
        break;
      }
      case 'network-then-eval': {
        const netIdx = traces.findIndex((t) => t.type === 'network');
        const evalIdx = traces.findIndex((t) => t.type === 'eval');
        if (netIdx >= 0 && evalIdx > netIdx) return true;
        break;
      }
      case 'command':
        if (hasTrace(traces, 'command')) return true;
        break;
      case 'fs-write-persistence':
        if (hasTrace(traces, 'fs-write', (t) => typeof t.path === 'string' && /\.bashrc|\.zshrc|\.profile|schtasks|autostart|systemd/i.test(t.path))) return true;
        break;
      case 'network':
        if (hasTrace(traces, 'network')) return true;
        break;
      case 'dns-tunnel':
        if (hasTrace(traces, 'network') && hasTrace(traces, 'fs-read', isSensitiveRead)) return true;
        break;
      case 'dep-poison':
      case 'install-script':
      case 'patch-disables-security':
      case 'prompt-inject':
      case 'client-eval':
      case 'load-failed-obfuscated':
        // 安装期/声明期/prompt/client 层面的行为动态沙箱（host 端、不装依赖、不跑 client）观察不到——
        // 无法证实也不证伪，维持 unconfirmed（预期），不因"动态干净"误判为安全
        return false;
    }
  }
  return false;
}

/** 静态 threatId 集合（review 级） */
function staticReviewThreats(report: AuditReport): Map<ThreatId, Finding[]> {
  const m = new Map<ThreatId, Finding[]>();
  for (const f of report.findings) {
    if (f.severity !== 'review') continue;
    const arr = m.get(f.threatId) ?? [];
    arr.push(f);
    m.set(f.threatId, arr);
  }
  return m;
}

/** 动态暴露但静态没标 review 的威胁（升级信号） */
function dynamicAdditions(traces: DynamicTrace[]): string[] {
  const out: string[] = [];
  if (hasTrace(traces, 'eval')) out.push('动态执行 eval/Function（静态未标 review）');
  if (hasTrace(traces, 'fs-read', isSensitiveRead)) out.push('动态读取敏感路径（静态未标 review）');
  if (hasTrace(traces, 'command')) out.push('动态调用子进程命令（静态未标 review）');
  if (hasTrace(traces, 'timer') && hasTrace(traces, 'fs-read', isSensitiveRead)) out.push('延迟触发敏感读取（反静态检测手法）');
  return out;
}

/**
 * 交叉验证：静态报告 × 动态轨迹 → 逐威胁结论。
 * @param dynamic 可空（未跑动态时 verdict=no-dynamic）
 */
export function crossValidate(report: AuditReport, dynamic?: DynamicReport): CrossValidationResult {
  const traces = dynamic?.traces ?? [];
  // 区分：真没跑动态（no-dynamic）vs 动态跑了但加载失败（load-failed——无法验证，不等于安全）
  const ranDynamic = !!dynamic && dynamic.status !== 'spawn-failed';
  const loaded = !!dynamic && dynamic.status === 'completed';
  const hasDynamic = loaded;
  const staticThreats = staticReviewThreats(report);
  const verdicts: ThreatVerdict[] = [];

  for (const [threatId, findings] of staticThreats) {
    const req = REQUIREMENTS.find((r) => r.threatId === threatId);
    if (!ranDynamic || !req) {
      verdicts.push({
        threatId,
        severity: 'review',
        staticFindings: findings.length,
        verdict: 'no-dynamic',
        reason: !req ? '无动态证据映射（规则未定义）' : '未运行动态沙箱',
        matchingTraces: [],
      });
      continue;
    }
    if (!loaded) {
      verdicts.push({
        threatId,
        severity: 'review',
        staticFindings: findings.length,
        verdict: 'load-failed',
        reason: `动态沙箱加载失败（${dynamic?.status}）——无法交叉验证，不因"无动态证据"降低风险`,
        matchingTraces: [],
      });
      continue;
    }
    const met = evidenceMet(req, traces);
    const matching = traces.filter((t) => {
      return t.type === 'eval' || t.type === 'network' || t.type === 'command' || t.type === 'fs-read' || t.type === 'timer' || t.type === 'fs-write';
    });
    verdicts.push({
      threatId,
      severity: 'review',
      staticFindings: findings.length,
      verdict: met ? 'confirmed' : 'unconfirmed',
      reason: met
        ? `动态证实：${req.describe}`
        : `动态未证实：${req.describe}（未观察到相关调用；可能是功能面噪音，或行为未触发到）`,
      matchingTraces: matching.slice(0, 5),
    });
  }

  const dynamicConfirmsRisk = verdicts.some((v) => v.verdict === 'confirmed');
  const additions = ranDynamic ? dynamicAdditions(traces) : [];
  const dynamicAddsFindings = additions.length > 0;
  const confirmedThreats = verdicts.filter((v) => v.verdict === 'confirmed').map((v) => v.threatId);

  const confirmed = confirmedThreats.length;
  const unconfirmed = verdicts.filter((v) => v.verdict === 'unconfirmed').length;
  const loadFailed = verdicts.filter((v) => v.verdict === 'load-failed').length;
  let plain: string;
  if (!ranDynamic) {
    plain = `静态发现 ${verdicts.length} 项 review 风险，未运行动态沙箱——如需动态佐证请用 dynamic 选项。`;
  } else if (loadFailed > 0 && confirmed === 0) {
    plain = `静态风险（${verdicts.map((v) => v.threatId).join('、')}）的动态沙箱加载失败（${loadFailed} 项无法验证）——不能因"无动态证据"降低风险，建议人工复核。`;
  } else if (confirmed > 0 && additions.length > 0) {
    plain = `动态沙箱证实了 ${confirmed} 项静态风险（${confirmedThreats.join('、')}），并额外发现 ${additions.length} 项静态未标的行为——建议优先复核。`;
  } else if (confirmed > 0) {
    plain = `动态沙箱证实了 ${confirmed} 项静态风险：${confirmedThreats.join('、')}——这些是实打实的运行时行为，建议人工复核后再安装。`;
  } else if (unconfirmed > 0 && additions.length > 0) {
    plain = `静态风险均未获动态证实，但动态额外发现 ${additions.length} 项静态未标的行为（${additions[0]}）——值得人工查看。`;
  } else {
    plain = `静态风险（${verdicts.map((v) => v.threatId).join('、')}）在动态沙箱中未观察到对应行为——可能是功能面噪音（静态误报）或行为未触发到；建议结合代码人工复核。`;
  }

  return {
    hasDynamic,
    verdicts,
    dynamicConfirmsRisk,
    dynamicAddsFindings,
    additions,
    plain,
  };
}

/** cross-validation 结果的 Markdown 渲染 */
export function renderCrossValidation(cv: CrossValidationResult): string {
  const lines: string[] = [];
  lines.push('## 🔀 静态 × 动态交叉验证');
  lines.push('');
  if (!cv.hasDynamic) {
    lines.push('未运行动态沙箱，无交叉结论。');
    return lines.join('\n');
  }
  lines.push(`**结论**：${cv.plain}`);
  lines.push('');
  lines.push('| 威胁 | 静态 | 动态结论 | 说明 |');
  lines.push('| --- | --- | --- | --- |');
  for (const v of cv.verdicts) {
    const badge = v.verdict === 'confirmed' ? '✅ 证实' : v.verdict === 'unconfirmed' ? '⚠️ 未证实' : v.verdict === 'load-failed' ? '🚫 加载失败' : '—';
    lines.push(`| ${v.threatId} | ${v.staticFindings} 条 review | ${badge} | ${v.reason} |`);
  }
  if (cv.dynamicAddsFindings && cv.additions.length > 0) {
    lines.push('');
    lines.push('**动态额外发现（静态未标 review）**：');
    for (const a of cv.additions) lines.push(`- ⚠️ ${a}`);
    lines.push('');
  }
  return lines.join('\n');
}
