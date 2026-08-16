# dsh-safety — 设计文档（Design Doc）

> 状态：**草案 v0.1**（2026-08-16）
> 本文件是 dsh-safety 的唯一权威设计来源。任何实现偏离本文件，必须先更新本文件（ADR 记录），防止漂移。

---

## 1. 项目定位（Problem Statement）

**一句话**：dsh-safety 是一个 **MCP 服务器**，对社区开源的 **DeepSeek Harness（DSH）插件**做安装前安全审计——输入插件来源（npm 包名 / GitHub 仓库 / 本地插件目录），输出结构化安全报告（风险等级 + 证据），并支持在 `dsh plugin add` 之前作为安全闸门。

**明确不做**：
- 不做通用仓库/项目安全审计（这是 [dsh-code-security](https://github.com/ihuajiu/dsh-code-security) 的定位）。
- 不做运行时拦截（这是 [dsh-plugin-audit](https://github.com/jkrandom-sudo/dsh-plugin-audit) 哨兵、[dsh-guardian](https://github.com/lonelymoon87/dsh-guardian) 的定位）；dsh-safety 聚焦**安装前静态审计**，可输出结果给其他守护组件消费。
- 不做评分/信誉裁决，只出**证据 + 风险等级**，由用户决策。

**与现有项目的差异化**：
| 项目 | 形态 | 差异 |
|---|---|---|
| [dsh-plugin-audit](https://github.com/jkrandom-sudo/dsh-plugin-audit) | dsh 插件（进程内） | dsh-safety 是 **MCP（独立进程）**，信任隔离；且补上 prompt 注入 / 思维链劫持 / 配置树降级等 dsh 特有检测点 |
| [dsh-code-security](https://github.com/ihuajiu/dsh-code-security) | 会话预设 + 扫描工具 | 针对任意项目；dsh-safety 针对 **dsh 插件包** |
| [dsh-skill-pack-security](https://github.com/PerryLink/dsh-skill-pack-security) | agent skills（LLM 驱动） | dsh-safety 是**确定性规则引擎** + 可选 LLM 复核，不依赖 LLM 判断力 |

## 2. 威胁模型（Threat Model）

### 2.1 攻击者能力假设
- 攻击者能发布看似正常的 dsh 插件（npm 包 / GitHub 仓库 / 私有市场），诱导用户安装。
- DSH 插件 = **进程内任意代码执行**（Node host 侧）+ **浏览器 client 侧**，安装后自动获得：
  - 完整 config-tree 写权限（官方 [#587](https://github.com/deepseek-ai/deepseek-harness/discussions/587)：boot 时即可禁用 approval/sandbox/permission 等安全插件）；
  - 读写 `~/.dsh`（`.credentials.yaml`、会话日志/思维链、profiles 配置）；
  - 执行任意 shell 命令、发起任意网络请求；
  - client 侧可访问浏览器存储（localStorage）、DOM、伪造 UI（钓鱼审批弹窗）。

### 2.2 威胁清单（规则库来源，按优先级）

#### P0 — v1 必做（高危）
| ID | 威胁 | 检测策略（静态特征） |
|---|---|---|
| T01 | **配置树降级 / 安全组件禁用**：patch 里 `disabled: true` 掉 approval/sandbox/permission/bash-sandbox/pwsh-sandbox/fs-observation-policy 等 | 解析 cordis.patch.yml + bundle 内嵌 patch，白名单比对安全插件 id |
| T02 | **隐藏 prompt / 反静态检测混淆**：零宽字符、Unicode 控制字符、超高熵字符串、多层 base64/hex/加密、混淆压缩单行 | 熵检测、不可见字符扫描、编码特征识别、`eval`/`new Function` 目标不可读 |
| T03 | **安装生命周期攻击**：`preinstall`/`postinstall`/`prepare` 脚本（npm 供应链经典入口） | 读取 package.json scripts，逐条特征扫描 |
| T04 | **运行时远程拉码执行**：安装时干净、运行时 fetch + eval / dynamic import 远程 | 静态标记"动态下载执行"（fetch/request + eval/import/Function 组合）并强制 REVIEW |
| T05 | **脚本外传（数据外带）**：将文件/凭据/会话数据发往外部主机 | 网络调用 + 读取敏感路径/进程输出的组合；外联域名提取 |
| T06 | **凭据与个人信息窃取**：读 `~/.dsh/.credentials.yaml`、`.ssh`、`.npmrc`、`.codex`、浏览器数据、localStorage | 敏感路径引用匹配 + 读取 API 组合 |

#### P1 — v1.5
| ID | 威胁 | 检测策略 |
|---|---|---|
| T07 | **prompt 注入**：向 system-prompt/agent-preset/用户可见文本注入指令；hidden prompt | 扫描 system-prompt 补丁、agent-preset 文件、prompt-custom 类 hook；指令型文本特征（"ignore previous instructions" 等 + 混淆变体） |
| T08 | **思维链/会话劫持**：hook agent-loop、读写 reasoning/trajectory 事件、静默读 `~/.dsh/sessions/*.jsonl` | 扫描 hook 注入点（agent-loop、session 事件监听、compaction/trajectory 相关）+ 会话文件读取 |
| T09 | **client 端钓鱼**：注入 DOM 伪造 dsh 审批弹窗、键盘/剪贴板读取 | 扫 client.js 的 DOM 注入、`beforeunload`/剪贴板/`addEventListener('keydown')` 特征 |
| T10 | **持久化驻留**：写 shell rc 文件、注册计划任务、写 profile 配置自启 | rc 路径引用 + 写 API 组合 |
| T11 | **DNS 外带**：域名解析试探绕过网络白名单 | 网络调用到裸域名/IP、`dns.resolve` 特征（标记 REVIEW） |

#### P2 — 后期
| ID | 威胁 | 检测策略 |
|---|---|---|
| T12 | **双面代码（bifurcation）**：检测到 CI/沙箱/非交互时隐藏恶意行为 | 环境检测特征（`process.env.CI`、`isTTY`、沙箱 marker）分支标记 |
| T13 | **供应链信誉**：typosquatting 包名、仓库年龄/star/作者异常、npm 完整性 hash 校验 | 接入 GitHub/npm API 元数据 + 名称相似度 |
| T14 | **依赖链投毒**：依赖包本身可疑（install 脚本、低信誉） | npm audit / OSV 接口 + 递归浅扫依赖 manifest |

### 2.3 豁免与假阳性控制
- 本地 Ollama/localhost 网络目标默认不告警（`localhost`/`127.0.0.1`/`*.local` 白名单）。
- `allowedHosts` 可配置（默认：github.com、api.github.com、raw.githubusercontent.com、registry.npmjs.org、`*.deepseek.com`）。
- 所有发现分 `review`（必须人工复核）/ `notice`（注意）/ `info`（信息）三级。

## 3. 架构设计（Architecture）

```
┌─────────────────────────────────────────────────────────────┐
│  DSH host (任何 profile)                                     │
│  会话 agent ──调用──▶ mcp__safety__audit_plugin 等工具       │
└──────────────┬──────────────────────────────────────────────┘
               │ stdio / MCP 协议
┌──────────────▼──────────────────────────────────────────────┐
│  dsh-safety (独立 MCP 服务器进程 = 信任隔离)                 │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ 来源解析器    │→│ 下载/缓存器   │→│ 插件解包器         │  │
│  │ npm/GitHub/  │  │ (只读、限大)  │  │ (去除 node_modules)│  │
│  │ 本地目录      │  └──────────────┘  └───────────────────┘  │
│  └──────────────┘                                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 静态扫描引擎                                            │   │
│  │  · 文件发现（上限 400 文件 / 256KB 每个）                │   │
│  │  · 规则引擎（P0..P2 规则表，确定性匹配 + 证据定位）      │   │
│  │  · patch/manifest 解析（cordis.patch.yml、package.json）│   │
│  │  · 混淆检测（熵 / Unicode / 编码特征）                   │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 报告生成（Markdown 权限画像卡 + JSON 结构化输出）        │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 3.1 设计原则
1. **信任隔离**：MCP 独立进程；扫描器自身不加载被审计插件的任何代码（纯文本/AST 解析）。
2. **只读契约**：扫描对源文件只读；下载到独立缓存目录；报告必须携带 `writesPerformed: false`。
3. **无遥测**：除"下载用户指定的插件源"外零网络；报告中的域名仅提取不联系。
4. **证据驱动**：每条发现带 文件:行号 + 代码片段，绝不只给结论。
5. **不裁决**：输出风险等级与证据，安装与否由用户决定。

## 4. 协议（MCP Tools）

| 工具 | 输入 | 输出 |
|---|---|---|
| `audit_plugin` | `source`: npm 包名 / `github:owner/repo` / `git@...` / 本地绝对路径；可选 `format`（markdown/json） | 审计报告（Markdown 卡片 + JSON 摘要 `{risk, findings[], writesPerformed}`） |
| `audit_url` | `url`: 插件仓库/包页 URL | 同 `audit_plugin` |
| `list_rules` | — | 规则库版本与启用规则清单 |
| `get_rule` | `ruleId` | 单条规则定义（检测策略 + 误报控制） |

## 5. 规则库 v1 清单（落地范围）

- P0：T01–T06（六条，见 2.2）
- 规则形式：`{ id, threatId, severity, fileGlobs, patterns[], combinators[], evidence, falsePositiveNotes }`
- 每条规则独立可开关、可扩展；规则文件与引擎解耦（JSON/YAML 规则表）。

## 6. 技术栈

- Node.js ≥ 22（LTS），TypeScript（严格模式）
- MCP SDK：`@modelcontextprotocol/sdk`（stdio transport）
- 解析：JSON/YAML（cordis.patch.yml、package.json）、AST（esprima/acorn 轻量静态分析）
- 下载：npm registry tarball（`npm pack` 或 registry API）+ GitHub codeload；限大、超时、校验和
- 依赖审计接口（P2）：npm audit 输出 / OSV API

## 7. 里程碑（Roadmap）

| 阶段 | 内容 | 验收 |
|---|---|---|
| M0 规则库 v1 | 规则表（T01–T06）落地 + 单元测试夹具（良性/恶意插件样例） | 恶意夹具全命中、良性零误报（目标） |
| M1 扫描引擎 | 文件发现 + 规则执行 + 证据收集 + 报告生成 | CLI 可对本地目录出报告 |
| M2 MCP 服务器 | 四个 MCP 工具 + npm/GitHub 下载解析 | DSH 会话可调用并拿到结构化报告 |
| M3 加固 | 混淆检测增强、P1 规则、缓存与限流 | P1 规则上线 |
| M4 开源 | README/文档/贡献指南、CI（lint+test）、发布 npm + GitHub Release | 可被社区安装使用 |

## 8. 安全设计自审（扫描器自身）
- 下载内容限制大小（默认 50MB）与文件数（400），防 zip bomb / 路径穿越（解包白名单校验）。
- 不执行被审计插件任何代码、不安装其依赖。
- 报告中的凭据/密钥值脱敏（只留路径与访问模式）。
- 规则与引擎升级有版本号，报告携带规则版本供追溯。

## 9. 开源规划
- 许可证：**Apache-2.0**（与 DSH 生态主流一致，兼容商用；最终以用户确认为准）。
- 仓库结构：`src/{rules,scanner,reporter,mcp,resolve}`、`fixtures/{benign,malicious}`、`docs/`。
- 发布：npm（`dsh-safety`）+ GitHub Release（含 tgz）。

## 10. 开放问题（待决策）
- Q1：是否增加 `--gate` 模式（与 `dsh plugin add` 集成做强制闸门）——需要官方 CLI hook 支持情况。
- Q2：规则匹配用纯正则还是 AST 增强（v1 先正则+AST 轻量，重混淆样本走熵/编码特征）。
- Q3：报告语言（中/英双语 i18n）。
