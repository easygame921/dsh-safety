# dsh-safety

<p align="center">
  <img src="assets/logo.svg" alt="dsh-safety logo" width="160"/>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="license"/></a>
  <a href="https://github.com/easygame921/dsh-safety/actions"><img src="https://img.shields.io/github/actions/workflow/status/easygame921/dsh-safety/ci.yml" alt="CI"/></a>
  <a href="https://github.com/easygame921/dsh-safety/releases"><img src="https://img.shields.io/github/v/tag/easygame921/dsh-safety" alt="version"/></a>
</p>

对社区开源的 **DeepSeek Harness（DSH）插件**做安装前安全审计的 MCP 服务器。

> ✅ 状态：**M0-M3 已完成**（规则库 v1 + 轻量 AST + 扫描引擎 + MCP + 动态沙箱），详见 [DESIGN.md](./DESIGN.md)

## 能做什么

输入插件来源（npm 包名 / GitHub 仓库 / 本地插件目录），输出结构化安全报告：

### 静态（正则 + 轻量 AST）
| 威胁 | 说明 |
|---|---|
| T01 配置树降级 | patch 禁用 approval/sandbox/permission 等安全插件 |
| T02 隐藏 prompt 混淆 | 零宽字符注入、编码载荷、变量间接 eval（AST 溯源） |
| T03 安装脚本 | preinstall/postinstall/prepare 生命周期攻击 |
| T04 远程拉码执行 | fetch + eval/import 组合 |
| T05 脚本外传 | 网络 + 敏感读取组合，外联主机提取 |
| T06 凭据窃取 | .credentials.yaml / .ssh / .npmrc / .env 引用与读取（AST 常量折叠对抗拼接绕过） |
| T07-T11 | prompt 注入 / 思维链劫持 / client 钓鱼 / 持久化驻留 / DNS 外带 |
| T14 | 依赖链投毒：已知恶意包名单（event-stream 等真实事件）、typosquatting（lodahs/axois 类）、registry 篡改、通配版本 |

AST 增强：`eval` 变量溯源（base64 解码来源）、敏感路径常量折叠（拆片拼接对抗）、
**数据流外传**（`readFile → 变量 → fetch` 多行拆分对抗）、**凭据读取精确判定**
（读取实参折叠后即敏感路径）、排除类型声明与文档文件、注释/纯文本行不参与代码规则。

### 动态（受限沙箱试运行）
在**受限子进程**中试运行插件 host 端，记录**真实行为轨迹**：
- 读取了哪些文件（敏感路径标记，HOME 重定向隔离，**不碰真实文件系统**）
- 联网目标（网络黑洞，不真实外发）
- 命令调用 / eval（记录不执行）
- 超时强杀（20s）、V8 堆限制（内存炸弹遏制）

隔离为**本地方案**（Node 权限模型 + 插桩，**不依赖 Docker**）；Docker 容器模式代码
就绪为可选增强。真实插件动态加载率 5/6。

## 快速开始

```bash
# 安装依赖并构建
npm install && npm run build

# 静态审计（本地 / npm / GitHub）
node dist/cli.js audit "npm:some-dsh-plugin"

# 动态沙箱试运行（远程来源自动装依赖 --ignore-scripts）
node dist/cli.js dynamic "npm:some-dsh-plugin"

# MCP 服务器模式（stdio）
node dist/cli.js serve
```

## 自动触发（配合 DSH 会话）

用户在会话中表达「想装/想试社区 dsh 插件」时，agent 自动：
1. 静态审计（`dynamicOnReview: true`）→ 风险为 REVIEW 时自动附加动态沙箱
2. 对话流输出：完整报告 + 动态轨迹（如有）+ 大白话总结
3. 需要时保存文件报告到桌面

## 检测率（真实恶意样本）

> 仿真恶意样本库：**12 个**攻击技法提炼自真实供应链攻击事件的完整 DSH 插件
> （凭据窃取+外传 / 供应链 stage2 / 零宽字符投毒 / DNS 隧道 / 持久化后门 / client 钓鱼 /
> 多层编码混淆 / 延迟+拆串对抗 / 密钥嗅探 / 双面代码 / **依赖链投毒 / registry 篡改**），
> 全部带伪装业务逻辑与反检测手法。
> 样本与 ground truth 见 [fixtures/malicious-real/](./fixtures/malicious-real/)。

| 指标 | 数值 | 目标 |
| --- | --- | --- |
| **样本抓取率**（≥1 预期威胁命中 review） | **100%**（12/12） | ≥90% |
| 全威胁命中率（全部预期威胁命中） | 100%（12/12） | — |
| **威胁覆盖率**（预期 threatId 产生 review） | **100%**（21/21） | ≥80% |
| 良性样本误报（benign/ 对照） | 0 条 review | 0 |
| 本地真实插件误报（5 个已知良性） | 1 条 review（能力面合理项） | ≤3/插件 |

本轮测试驱动的规则增强（真实对抗手法）：
- T02：零宽字符**转义文本形态**（`\u200b`）识别——攻击者用转义规避字符集检测
- T02：AST `eval` 溯源扩展到 `new Function(变量)` 间接执行
- T05：AST **数据流外传**检查——`readFile(敏感路径) → 变量 → fetch` 跨行拆分
- T10：`homedir()`/`os.homedir()` + 写 API 拼启动文件形态识别
- T06：AST **凭据读取精确判定**（读取实参折叠后即敏感路径）
- T14：**依赖链投毒**——已知恶意包名单 / typosquatting / registry 篡改 / 通配版本

复现：`npm run build && node scripts/detection-rate.mjs`
回归门槛：`node --test test/detection-rate.test.mjs`

## 测试

```bash
npm test   # 27 项：T01-T11 恶意样本命中、良性零误报、AST 对抗样本、动态沙箱验收、检测率门槛、契约校验
node scripts/mcp-smoke.mjs   # MCP 工具注册冒烟测试
```

## 为什么是 MCP

独立进程 = 信任隔离：扫描器不运行在被审计插件的信任域内，恶意插件无法干扰审计自身；审计对源文件**只读**（`writesPerformed: false` 契约），下载物落临时目录自动清理；动态沙箱为**独立受限子进程**（权限模型 + 插桩 + 超时/内存限制）。

## 文档

- [设计文档 DESIGN.md](./DESIGN.md) — 权威设计来源（威胁模型、架构、协议、路线图）
- [动态沙箱设计 docs/DYNAMIC-SANDBOX.md](./docs/DYNAMIC-SANDBOX.md) — 隔离方案（本地方案为主）、验收标准
- [自动触发规范 docs/AUTOTRIGGER.md](./docs/AUTOTRIGGER.md)
- [规则编写指南 docs/RULES.md](./docs/RULES.md)
- [MCP 装配到 DSH docs/MCP-INTEGRATION.md](./docs/MCP-INTEGRATION.md)
- [白名单指南 docs/ALLOWLIST.md](./docs/ALLOWLIST.md)

## 许可

Apache-2.0（待正式发布时确认）
