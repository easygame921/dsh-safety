# dsh-safety

对社区开源的 **DeepSeek Harness（DSH）插件**做安装前安全审计的 MCP 服务器。

> ⚠️ 状态：**设计阶段（v0.1）** — 详见 [DESIGN.md](./DESIGN.md)

## 做什么

输入插件来源（npm 包名 / GitHub 仓库 / 本地插件目录），输出结构化安全报告：
- 配置树降级 / 安全组件被禁用
- 隐藏 prompt / 混淆规避
- 安装脚本 / 远程拉码执行
- 脚本外传 / 凭据与个人信息窃取
- prompt 注入 / 思维链劫持（v1.5）

## 为什么是 MCP

独立进程 = 信任隔离：扫描器不运行在被审计插件的信任域内，恶意插件无法干扰审计自身。

## 快速开始（规划）

```bash
# M2 之后可用
npx dsh-safety audit npm:some-dsh-plugin
```

## 文档

- [设计文档 DESIGN.md](./DESIGN.md) — 权威设计来源，防漂移

## 许可

Apache-2.0（待定，见 DESIGN.md §9）
