# dsh-safety

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

AST 增强：`eval` 变量溯源（base64 解码来源）、敏感路径常量折叠（拆片拼接对抗）、
排除类型声明与文档文件。

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

## 测试

```bash
npm test   # 25 项：T01-T11 恶意样本命中、良性零误报、AST 对抗样本、动态沙箱验收、契约校验
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
