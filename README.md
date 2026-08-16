# dsh-safety

对社区开源的 **DeepSeek Harness（DSH）插件**做安装前安全审计的 MCP 服务器。

> ✅ 状态：**M0-M2 已完成**（规则库 v1 + 扫描引擎 + MCP 服务器），详见 [DESIGN.md](./DESIGN.md)

## 能做什么

输入插件来源（npm 包名 / GitHub 仓库 / 本地插件目录），输出结构化安全报告：

| 威胁 | 说明 |
|---|---|
| T01 配置树降级 | patch 禁用 approval/sandbox/permission 等安全插件 |
| T02 隐藏 prompt 混淆 | 零宽字符注入、编码载荷、超高熵串 |
| T03 安装脚本 | preinstall/postinstall/prepare 生命周期攻击 |
| T04 远程拉码执行 | fetch + eval/import 组合 |
| T05 脚本外传 | 网络 + 敏感读取组合，外联主机提取 |
| T06 凭据窃取 | .credentials.yaml / .ssh / .npmrc / .env 引用与读取 |

## 快速开始

```bash
# 安装依赖并构建
npm install && npm run build

# 审计本地插件目录
node dist/cli.js audit "C:\path\to\some-dsh-plugin"

# 审计 npm 包
node dist/cli.js audit "npm:some-dsh-plugin"

# 审计 GitHub 仓库
node dist/cli.js audit "github:owner/repo"

# MCP 服务器模式（stdio）
node dist/cli.js serve
```

## 测试

```bash
npm test   # 9 项：T01-T06 恶意样本全命中、良性样本零误报、契约校验
node scripts/mcp-smoke.mjs   # MCP 4 工具注册冒烟测试
```

## 为什么是 MCP

独立进程 = 信任隔离：扫描器不运行在被审计插件的信任域内，恶意插件无法干扰审计自身；审计对源文件**只读**（`writesPerformed: false` 契约），下载物落临时目录自动清理。

## 文档

- [设计文档 DESIGN.md](./DESIGN.md) — 权威设计来源（威胁模型 P0-P2、架构、协议、路线图）
- [规则编写指南 docs/RULES.md](./docs/RULES.md)
- [MCP 装配到 DSH docs/MCP-INTEGRATION.md](./docs/MCP-INTEGRATION.md)

## 许可

Apache-2.0（待正式发布时确认）
