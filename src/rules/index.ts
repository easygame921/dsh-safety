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
    title: '内嵌 patch 文本禁用安全插件',
    description: '源码中内嵌了禁用安全插件的 patch 文本（如 disabled: true 配合 approval/sandbox/permission），与 cordis 装配层同等的降级风险。',
    patterns: ['disabled\\s*:\\s*true\\s*[\\s\\S]{0,120}(approval|sandbox|permission)', 'approval|sandbox|permission.{0,120}disabled\\s*:\\s*true'],
    falsePositiveNotes: '需要 disabled 与安全插件 id 同时出现；隔离的注释/文档不命中（无 disabled: true 结构）。',
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
    falsePositiveNotes: 'minify 产物可能误报；结合 T02-003 熵检测交叉判断。',
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
    description: '同一文件同时出现网络调用与敏感数据读取（fs 读文件 / child_process 输出 / 凭据路径），构成数据外带模式。',
    fileGlobs: ['**/*.{js,ts,mjs,cjs}'],
    combinators: [
      {
        name: 'network+sensitive-read',
        allOf: [
          'fetch\\s*\\(|https?\\.[a-z]+\\s*\\(|WebSocket|axios|request\\s*\\(',
          'readFile|readFileSync|execFile|execSync|spawn|exec\\s*\\(',
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
    severity: 'review',
    title: '引用凭据/敏感路径',
    description: '代码引用 DSH 凭据文件（.credentials.yaml）、SSH 私钥、.npmrc、.codex、.env 等敏感路径——可能窃取用户密钥与个人信息。',
    pathPatterns: ['\\.credentials\\.ya?ml', '\\.ssh|id_rsa|id_ed25519', '\\.npmrc', '\\.codex', '\\.env', '\\.aws[/\\\\]credentials', '\\.kube', '\\.netrc'],
    patterns: ['\\.credentials\\.ya?ml|id_rsa|id_ed25519|\\.ssh|\\.npmrc|\\.codex|auth\\.json|\\.aws[/\\\\]credentials|\\.netrc'],
    falsePositiveNotes: '文档/注释中提到这些路径不算读取；与 fs 读取 API 组合时风险更高（T06-002）。',
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
];
