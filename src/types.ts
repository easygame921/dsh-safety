/**
 * dsh-safety 核心类型定义 —— 规则/引擎/报告的统一契约。
 * 任何模块不得偏离本文件定义的结构（防漂移）。
 */

/** 威胁编号（对应 DESIGN.md §2.2） */
export type ThreatId =
  | 'T01' // 配置树降级 / 安全组件禁用
  | 'T02' // 隐藏 prompt / 反静态检测混淆
  | 'T03' // 安装生命周期攻击
  | 'T04' // 运行时远程拉码执行
  | 'T05' // 脚本外传（数据外带）
  | 'T06' // 凭据与个人信息窃取
  | 'T07' // prompt 注入
  | 'T08' // 思维链/会话劫持
  | 'T09' // client 端钓鱼
  | 'T10' // 持久化驻留
  | 'T11' // DNS 外带
  | 'T12' // 双面代码
  | 'T13' // 供应链信誉
  | 'T14'; // 依赖链投毒

/** 发现严重度：review=必须人工复核；notice=注意；info=信息 */
export type Severity = 'review' | 'notice' | 'info';

/** 规则 ID：如 T01-001 */
export type RuleId = string;

/**
 * 一条安全规则。匹配方式是"文件内容正则 + 路径正则 + 文件级检查"的任意组合，
 * 全部命中才产出发现（AND 语义）；组合规则（T04/T05/T10 等跨表面威胁）用 combinators。
 */
export interface SafetyRule {
  id: RuleId;
  /** 关联威胁编号 */
  threatId: ThreatId;
  severity: Severity;
  /** 中文标题（报告用） */
  title: string;
  /** 中文说明：威胁是什么、为什么危险 */
  description: string;
  /** 限定文件 glob（默认 src/**\/*.{js,ts,json,yml,yaml,mjs,cjs}；空 = 全量） */
  fileGlobs?: string[];
  /** 文件内容正则（RegExp source，不携带 /g 状态；匹配到即定位行号） */
  patterns?: string[];
  /** 路径名正则（匹配文件路径，如 .credentials.yaml） */
  pathPatterns?: string[];
  /** 文件级检查：解析 manifest/patch 后调用的断言（见 scanner/manifest.ts） */
  fileChecks?: FileCheckId[];
  /** 组合规则：多个"子发现"在**同一文件**内都出现才算命中（用于外带/窃取等跨表面威胁） */
  combinators?: CombinatorRule[];
  /** 误报控制说明（报告展示 + 维护者参考） */
  falsePositiveNotes?: string;
}

/** 文件级检查 id（引擎内置实现） */
export type FileCheckId =
  | 'pkg-install-scripts' // package.json scripts.preinstall/postinstall/prepare
  | 'patch-disables-security'; // cordis.patch.yml / 内嵌 patch：disabled 安全插件

/** 组合规则：一组子特征在**同一文件**内共存才命中 */
export interface CombinatorRule {
  /** 组合名（用于定位解释） */
  name: string;
  /** 所有子特征正则，全部出现在同一文件内容中即命中 */
  allOf?: string[];
  /** 任一子特征出现即命中（互斥使用） */
  anyOf?: string[];
}

/** 一条证据（发现的最小单元） */
export interface Evidence {
  /** 相对路径 */
  file: string;
  /** 行号（1-based，未知为 0） */
  line: number;
  /** 命中的规则特征说明 */
  pattern: string;
  /** 命中片段（脱敏后，最长 200 字符） */
  snippet: string;
}

/** 一条发现（可能聚合多条证据） */
export interface Finding {
  ruleId: RuleId;
  threatId: ThreatId;
  severity: Severity;
  title: string;
  description: string;
  /** 证据列表（可能跨文件） */
  evidence: Evidence[];
  /** 组合规则的命中解释（如有） */
  combinatorName?: string;
}

/** 权限画像（DESIGN.md 报告卡的核心表） */
export interface PermissionProfile {
  filesystemRead: boolean;
  filesystemWrite: boolean;
  childProcesses: boolean;
  network: boolean;
  /** 提取到的外联主机（去重） */
  outboundHosts: string[];
  envVariables: string[];
  credentialLookingEnv: string[];
  credentialPaths: string[];
  dynamicCodeExecution: boolean;
  injectedServices: string[];
  declaredDependencies: string[];
  bundlePatch: boolean;
  installScripts: string[];
}

/** 完整审计报告 */
export interface AuditReport {
  /** 插件标识（包名/仓库/路径） */
  source: string;
  /** 规则库版本（如 '0.1.0'） */
  ruleSetVersion: string;
  risk: 'ok' | 'review' | 'danger';
  filesScanned: number;
  findingsCount: number;
  findings: Finding[];
  profile: PermissionProfile;
  /** 白名单抑制/降级记录（如有） */
  suppressions?: AllowlistSuppression[];
  /** 只读契约：审计绝不写被审计对象 */
  writesPerformed: false;
  /** 扫描耗时 ms */
  durationMs: number;
  scannedAt: string;
}

/** 扫描引擎的输入 */
export interface ScanOptions {
  /** 插件源目录（已解析到本地路径） */
  root: string;
  /** 显示用插件标识 */
  sourceLabel: string;
  /** 规则子集过滤（空 = 全部） */
  ruleIds?: RuleId[];
  /** 最大文件数（默认 400） */
  maxFiles?: number;
  /** 单文件最大字节（默认 256KB） */
  maxFileBytes?: number;
  /** 白名单配置（注入；缺省用内置默认白名单） */
  allowlist?: AllowlistConfig;
  /** 是否加载内置默认白名单（默认 true） */
  useDefaultAllowlist?: boolean;
  /** 是否排除测试/夹具目录（tests/spec/fixtures 等，默认 true——那里常含显式恶意样本，非插件真实行为） */
  excludeTests?: boolean;
  /** 是否排除文档文件（*.md/*.mdx，默认 true——README 常描述危险模式导致误报） */
  excludeDocs?: boolean;
}

// ── 白名单（Allowlist）────────────────────────────────────────────────────

/**
 * 白名单条目：命中则跳过或降级对应规则产出，用于抑制"正常插件也会触发"的
 * 已知误报。匹配维度：插件名 / 文件路径 / 外联主机，与 规则id/威胁编号 组合。
 */
export interface AllowlistEntry {
  /** 规则 id（如 T03-001）或威胁编号（如 T03）或 '*'（全部） */
  ruleId: string;
  /** 插件名/来源匹配（正则 source，大小写不敏感；缺省 = 任意插件） */
  plugin?: string;
  /** 文件相对路径匹配（正则 source；作用于发现的 evidence.file） */
  path?: string;
  /** 外联主机匹配（正则 source；作用于证据片段/外联主机表） */
  host?: string;
  /** 命中行为：skip=移除发现；downgrade=降级为 info（默认 downgrade） */
  action?: 'skip' | 'downgrade';
  /** 中文理由（报告展示） */
  reason?: string;
}

/** 白名单配置 */
export interface AllowlistConfig {
  version: string;
  entries: AllowlistEntry[];
}

/** 被白名单抑制/降级的记录（报告展示） */
export interface AllowlistSuppression {
  ruleId: RuleId;
  threatId: ThreatId;
  action: 'skip' | 'downgrade';
  matchedEntry: string;
  reason?: string;
}

/** MCP 工具返回的 JSON 摘要（DESIGN.md §4） */
export interface AuditSummary {
  source: string;
  risk: AuditReport['risk'];
  filesScanned: number;
  findingsCount: number;
  findings: Finding[];
  writesPerformed: false;
  ruleSetVersion: string;
}
