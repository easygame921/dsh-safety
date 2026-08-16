/**
 * 规则库 v1（P0：T01-T06）。
 * 每条规则严格遵循 src/types.ts 的 SafetyRule 契约与 docs/RULES.md 规范。
 */
import type { SafetyRule } from '../types.js';

export const RULE_SET_VERSION = '0.1.0';

export const v1Rules: SafetyRule[] = [
  // ── T01 配置树降级 / 安全组件禁用 ──────────────────────────────────────
  {
    id: 'T01-001',
    threatId: 'T01',
    severity: 'review',
    title: '配置树降级：禁用安全插件',
    description: '插件的 cordis.patch.yml / bundle patch 在启动时 disabled 了审批、沙箱、权限等安全插件，使 dsh 失去安全边界（deepseek-harness #587 已确认此攻击面）。',
    fileGlobs: ['**/*.yml', '**/*.yaml', '**/*.json'],
    fileChecks: ['patch-disables-security'],
    falsePositiveNotes: '仅当 id/name 属于安全插件白名单且 disabled=true 时命中；开发者自用 profile 禁用某个安全插件属误报源，需人工复核上下文。',
  },
  {
    id: 'T01-002',
    threatId: 'T01',
    severity: 'review',
    title: '源码内嵌 patch 禁用安全插件',
    description: '源码（js/ts）中构建了禁用安全插件的 patch 文本（disabled: true 配合 approval/sandbox/permission 等精确 id），与 cordis 装配层同等的降级风险。',
    fileGlobs: ['**/*.{js,ts,mjs,cjs}'],
    patterns: ['disabled\\s*:\\s*true[\\s\\S]{0,120}\\b(approval|sandbox|permission|fs-observation-policy)\\b', '\\b(approval|sandbox|permission|fs-observation-policy)\\b[\\s\\S]{0,120}disabled\\s*:\\s*true'],
    falsePositiveNotes: '仅限 js/ts 源码（文档/配置由 T01-001 的 patch 解析覆盖）；要求 disabled: true 与安全插件精确 id 词边界同时出现。',
  },

  // ── T02 隐藏 prompt / 反静态检测混淆 ───────────────────────────────────
  {
    id: 'T02-001',
    threatId: 'T02',
    severity: 'review',
    title: '零宽/不可见字符注入',
    description: '源码包含零宽字符（\\u200B\\u200C\\u200D\\uFEFF 等）或 Unicode 控制字符——2025 年已出现用此类字符隐藏 prompt 指令、规避 AI 安全扫描器的恶意 npm 包。',
    fileGlobs: ['**/*.{js,ts,mjs,cjs,json,yml,yaml,md}'],
    patterns: ['[\\u200B\\u200C\\u200D\\uFEFF\\u2060\\u200E\\u200F]', '[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F]'],
    falsePositiveNotes: '部分 i18n 文件可能含少见 Unicode；命中即提示人工检查上下文。',
  },
  {
    id: 'T02-002',
    threatId: 'T02',
    severity: 'notice',
    title: 'eval/Function 执行编码载荷',
    description: 'eval/new Function 接收 base64 或超长拼接串，可能是混淆后的恶意代码（本样本即 base64 载荷 + eval 模式）。',
    fileGlobs: ['**/*.{js,ts,mjs,cjs}'],
    patterns: ['eval\\s*\\([^)]{0,20}(Buffer|atob|fromCharCode)', 'new Function\\s*\\([^)]{0,40}["\'`]', 'eval\\s*\\(\\s*[`"\'][A-Za-z0-9+/=]{60,}'],
    combinators: [
      {
        name: 'eval-var-encoded',
        allOf: ['eval\\s*\\(\\s*[a-zA-Z_$][\\w$]*\\s*\\)', 'Buffer\\.from|atob|fromCharCode'],
      },
    ],
    falsePositiveNotes: 'minify 产物可能误报；"变量间接 eval + base64 解码"组合用于抓分片载荷（对抗性样本）。',
  },
  {
    id: 'T02-003',
    threatId: 'T02',
    severity: 'notice',
    title: '超高熵字符串（疑似编码载荷）',
    description: '文件中出现 ≥80 字符的 base64/hex 连续串，可能是隐藏指令或加密载荷。',
    fileGlobs: ['**/*.{js,ts,mjs,cjs,json}'],
    patterns: ['[A-Za-z0-9+/]{80,}={0,2}', '[0-9a-fA-F]{80,}'],
    falsePositiveNotes: 'license 文件、测试向量可能误报；与 T02-001/002 组合评估。',
  },

  // ── T03 安装生命周期攻击 ──────────────────────────────────────────────
  {
    id: 'T03-001',
    threatId: 'T03',
    severity: 'review',
    title: '安装脚本（preinstall/postinstall/prepare）',
    description: 'package.json 定义了安装生命周期脚本——npm 供应链攻击最经典的入口，安装即执行任意命令。',
    fileGlobs: ['**/package.json'],
    fileChecks: ['pkg-install-scripts'],
    falsePositiveNotes: '部分合法插件用 install 脚本编译原生模块；命中即需人工审阅脚本内容。',
  },

  // ── T04 运行时远程拉码执行 ────────────────────────────────────────────
  {
    id: 'T04-001',
    threatId: 'T04',
    severity: 'review',
    title: '远程拉取代码并执行（fetch + eval/import）',
    description: '同一文件内出现网络请求与动态执行（eval/Function/import()）——安装时看似干净，运行时从远程下载代码执行，是静态扫描最难防御的模式。',
    fileGlobs: ['**/*.{js,ts,mjs,cjs}'],
    combinators: [
      {
        name: 'fetch+eval',
        allOf: ['fetch\\s*\\(', 'eval\\s*\\(|new Function|Function\\s*\\(|import\\s*\\('],
      },
    ],
    falsePositiveNotes: '需要同文件同时含网络与执行；合法的"动态加载模块"（如 import 已内置模块）不命中。',
  },
  {
    id: 'T04-002',
    threatId: 'T04',
    severity: 'notice',
    title: '动态 import 外部模块',
    description: '运行时 import() 远程/外部 URL——评估其来源可信度。',
    fileGlobs: ['**/*.{js,ts,mjs,cjs}'],
    patterns: ['import\\s*\\(\\s*[`"\'][a-z]+://', 'import\\s*\\(\\s*[`"\']https?://'],
    falsePositiveNotes: '仅命中协议 URL 的动态 import。',
  },

  // ── T05 脚本外传（数据外带） ──────────────────────────────────────────
  {
    id: 'T05-001',
    threatId: 'T05',
    severity: 'review',
    title: '敏感数据外传（网络 + 敏感读取组合）',
    description: '同一文件同时出现网络调用与敏感数据读取（读取对象含凭据/密钥/会话等敏感词，或执行进程并取输出），构成数据外带模式。',
    fileGlobs: ['**/*.{js,ts,mjs,cjs}'],
    combinators: [
      {
        name: 'network+sensitive-read',
        allOf: [
          'fetch\\s*\\(|https?\\.[a-z]+\\s*\\(|WebSocket|axios|request\\s*\\(',
          'readFile[^\\n]{0,120}(credential|id_rsa|\\.ssh|\\.npmrc|\\.env|secret|token|key|session)|execFile|execSync|spawn\\s*\\(',
        ],
      },
    ],
    falsePositiveNotes: '良性 vision 插件（网络 + 无敏感读取）不命中；需敏感读取与网络同文件共存。',
  },
  {
    id: 'T05-002',
    threatId: 'T05',
    severity: 'notice',
    title: '外联主机提取（人工确认）',
    description: '源码引用了外部主机（非 localhost/本地域名）。列出供确认是否可信。',
    fileGlobs: ['**/*.{js,ts,mjs,cjs,json,yml,yaml}'],
    patterns: ['https?://(?!localhost|127\\.0\\.0\\.1)[A-Za-z0-9.-]+'],
    falsePositiveNotes: '网络能力本身不是恶意的；结合 T05-001 与凭据访问判断。',
  },

  // ── T06 凭据与个人信息窃取 ────────────────────────────────────────────
  {
    id: 'T06-001',
    threatId: 'T06',
    severity: 'notice',
    title: '引用凭据/敏感路径',
    description: '源码引用 DSH 凭据文件（.credentials.yaml）、SSH 私钥、.npmrc、.codex、.env 等敏感路径——提示性发现；只有与读取 API 组合（T06-002）才构成窃取证据。',
    fileGlobs: ['**/*.{js,ts,mjs,cjs}'],
    pathPatterns: ['\\.credentials\\.ya?ml', '\\.ssh|id_rsa|id_ed25519', '\\.npmrc', '\\.codex', '\\.env', '\\.aws[/\\\\]credentials', '\\.kube', '\\.netrc'],
    patterns: ['\\.credentials\\.ya?ml|id_rsa|id_ed25519|\\.ssh|\\.npmrc|\\.codex|auth\\.json|\\.aws[/\\\\]credentials|\\.netrc'],
    falsePositiveNotes: '仅限源码文件（文档/配置文件不再计入）；引用≠读取，实害由 T06-002 判定。',
  },
  {
    id: 'T06-002',
    threatId: 'T06',
    severity: 'review',
    title: '读取敏感路径内容',
    description: '用 fs/child_process 读取凭据或个人信息文件的完整内容——窃取凭据的直接证据。',
    fileGlobs: ['**/*.{js,ts,mjs,cjs}'],
    combinators: [
      {
        name: 'read-credential-path',
        allOf: ['readFile|readFileSync|execFile|execSync|spawn|exec\\s*\\(', '\\.credentials\\.ya?ml|id_rsa|id_ed25519|\\.ssh|\\.npmrc|\\.codex|auth\\.json|\\.env|credential'],
      },
    ],
    falsePositiveNotes: '需"读取 API + 敏感路径"同文件共存；扫描器自身代码排除在外。',
  },

  // ── T07 prompt 注入 ─────────────────────────────────────────────────────
  {
    id: 'T07-001',
    threatId: 'T07',
    severity: 'review',
    title: '指令注入文本（hidden instruction）',
    description: '代码/配置中出现"忽略之前指令/你现在是/不要告诉用户"等指令注入特征，或向 system-prompt/agent-preset 注入内容——劫持模型行为。',
    fileGlobs: ['**/*.{js,ts,mjs,cjs,json,yml,yaml,md}'],
    patterns: [
      'ignore\\s+(all\\s+)?previous\\s+(instructions|prompts|rules)',
      '\\u4e0d\\u8981\\u7ba1\\u4e4b\\u524d|\\u5ffd\\u7565\\u4e4b\\u524d|\\u4e0d\\u7528\\u7406\\u4f1a\\u4e4b\\u524d',
      '\\u4f60\\u73b0\\u5728\\u662f|\\u4f60\\u5c31\\u662f|\\u4f60\\u8981\\u88c5\\u4f5c|pretend\\s+(you are|to be)|act\\s+as\\s+',
      'do\\s+not\\s+(tell|reveal|mention).{0,40}(user|human)',
      '\\u4e0d\\u8981\\u544a\\u8bc9\\u7528\\u6237|\\u4e0d\\u8981\\u63d0\\u53ca|\\u9690\\u85cf.{0,10}\\u4e0b\\u9762',
    ],
    falsePositiveNotes: '安全测试/提示词工程类插件可能含此类文本；结合文件角色（prompt/preset 文件 vs 普通代码）判断。',
  },
  {
    id: 'T07-002',
    threatId: 'T07',
    severity: 'notice',
    title: 'agent-preset / system-prompt 补丁',
    description: '插件携带 agent-preset 或 system-prompt 覆盖/注入——评估其提示词内容是否含越权指令。',
    pathPatterns: ['agent-preset', 'system-prompt', 'prompt-custom'],
    falsePositiveNotes: '合法插件可能自带预设；命中仅提示审查预设内容。',
  },

  // ── T08 思维链/会话劫持 ────────────────────────────────────────────────
  {
    id: 'T08-001',
    threatId: 'T08',
    severity: 'review',
    title: '思维链/消息改写 hook',
    description: '注入 agent-loop 或读取/改写 reasoning、trajectory、消息内容——劫持思维链或篡改对话历史。',
    fileGlobs: ['**/*.{js,ts,mjs,cjs}'],
    patterns: [
      'agent[-_]loop',
      'trajectory|reasoning[-_]?content',
      'ctx\\.sessions\\.(get|set|update|mutate)\\s*\\([^)]*(content|message|reasoning|trajectory)',
    ],
    falsePositiveNotes: '仅命中 agent-loop 注入、reasoning/trajectory 读写、会话内容改写；普通会话事件监听（session/start 等）不命中。',
  },
  {
    id: 'T08-002',
    threatId: 'T08',
    severity: 'review',
    title: '读取会话日志（思维链/对话记录）',
    description: '直接读取 ~/.dsh 下的会话数据（sessions 目录 / 会话 jsonl）——窃取思维链与完整对话记录。',
    fileGlobs: ['**/*.{js,ts,mjs,cjs}'],
    combinators: [
      {
        name: 'read-session-logs',
        allOf: ['readFile|readFileSync|execFile|execSync|spawn', '\\.dsh', 'sessions'],
      },
    ],
    falsePositiveNotes: '需"读取 API + .dsh 路径 + sessions 字样"同文件共存（排除仅提及 session 的普通代码）。',
  },

  // ── T09 client 端钓鱼 ──────────────────────────────────────────────────
  {
    id: 'T09-001',
    threatId: 'T09',
    severity: 'review',
    title: 'client 端 DOM 注入（伪造审批弹窗）',
    description: '浏览器侧注入覆盖式 UI（position:fixed + 高 z-index + 审批/授权字样），可伪造 dsh 审批弹窗钓鱼。',
    fileGlobs: ['**/client*.{js,ts,mjs,cjs}'],
    combinators: [
      {
        name: 'fake-dialog',
        allOf: ['position\\s*:\\s*fixed|z[-_]?index\\s*:\\s*\\d{3,}', 'innerHTML|insertAdjacentHTML|appendChild|createElement', 'approve|\\u5ba1\\u6279|\\u6388\\u6743|\\u5141\\u8bb8|permission'],
      },
    ],
    falsePositiveNotes: '需"覆盖式定位 + DOM 写入 + 审批字样"同文件共存；正常 UI 组件可能命中部分特征。',
  },
  {
    id: 'T09-002',
    threatId: 'T09',
    severity: 'review',
    title: '键盘/剪贴板监听',
    description: '监听键盘输入或读取剪贴板——窃取用户输入（含密码/密钥）。',
    fileGlobs: ['**/client*.{js,ts,mjs,cjs}'],
    patterns: [
      'addEventListener\\s*\\(\\s*[\'"](keydown|keyup|keypress|paste)',
      'navigator\\.clipboard\\.readText|document\\.execCommand\\s*\\(\\s*[\'"]paste',
      'onkeydown|onkeyup|onpaste',
    ],
    falsePositiveNotes: '部分插件（如命令面板）监听键盘；重点看是否记录/外发输入。',
  },

  // ── T10 持久化驻留 ─────────────────────────────────────────────────────
  {
    id: 'T10-001',
    threatId: 'T10',
    severity: 'review',
    title: '持久化驻留（写 rc / 计划任务 / 自启）',
    description: '写入 shell 启动文件、注册计划任务或开机自启——插件卸载后仍持续运行。',
    fileGlobs: ['**/*.{js,ts,mjs,cjs,ps1,sh,json}'],
    patterns: [
      '(\\~|HOME|USERPROFILE)[\\\\/](\\.zshrc|\\.bashrc|\\.profile|\\.bash_profile|\\.config[\\\\/]autostart)',
      'schtasks|TaskScheduler|Register-ScheduledTask|\\/etc\\/systemd|rc\\.local|\\/etc\\/init\\.d',
      'HKEY_CURRENT_USER[\\\\/]Software[\\\\/]Microsoft[\\\\/]Windows[\\\\/]CurrentVersion[\\\\/]Run',
      'Startup[\\\\/]|startup\\s*folder|CreateShortcut',
    ],
    falsePositiveNotes: '正常工具可能写配置到 ~/.config；重点看 rc 文件/计划任务/注册表 Run。',
  },

  // ── T11 DNS 外带 ───────────────────────────────────────────────────────
  {
    id: 'T11-001',
    threatId: 'T11',
    severity: 'notice',
    title: 'DNS 解析试探（疑似外带通道）',
    description: '使用 dns.resolve/lookup 做域名解析——可能是绕过网络白名单的数据外带通道（如 DNS-over-HTTP 隧道）。',
    fileGlobs: ['**/*.{js,ts,mjs,cjs}'],
    patterns: [
      'dns\\.(resolve|lookup|resolve4|resolve6)\\s*\\(',
      'dns\\.promises|require\\s*\\(\\s*[\'"]dns[\'"]\\s*\\)',
    ],
    falsePositiveNotes: '正常插件可能用 dns 判断网络；与 T05 网络+敏感读取组合时升级为 review（见下）。',
  },
  {
    id: 'T11-002',
    threatId: 'T11',
    severity: 'review',
    title: 'DNS 解析 + 敏感读取组合',
    description: '同文件内同时出现 DNS 解析与敏感数据读取——高疑似 DNS 外带通道。',
    fileGlobs: ['**/*.{js,ts,mjs,cjs}'],
    combinators: [
      {
        name: 'dns-exfil',
        allOf: ['dns\\.(resolve|lookup|resolve4|resolve6)|dns\\.promises', 'readFile|readFileSync|execFile|execSync|process\\.env'],
      },
    ],
    falsePositiveNotes: '需 DNS API 与敏感读取同文件共存。',
  },
];
