# MCP 装配到 DSH（Integration Guide）

dsh-safety 是标准 MCP 服务器（stdio），可被任何 DSH profile 的会话调用，
方式与 mcp-vision 完全相同（走 `@deepseek-ai/dsh-mcp-client`）。

## 方式一：patch 装配（推荐）

在 profile 的 `cordis.patch.yml` 追加：

```yaml
- insert:
    - id: dsh-safety
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: safety
        transport: stdio
        command: node
        args: ['D:\学习\个人demo\dsh-plug\dsh-safety\dist\cli.js', 'serve']
        env:
          DSH_SAFETY_WORKDIR: 'D:\学习\个人demo\dsh-plug\dsh-safety\.work'
        toolCallTimeoutMs: 120000
```

> `D:\...` 路径按实际安装位置替换；发布为 npm 包后可用
> `args: ['dsh-safety', 'serve']`（需全局安装）。

## 方式二：npx 直跑（无装配，临时验证）

```bash
npx --yes dsh-safety serve
```

配合任意 MCP 客户端（含 Claude Code / Codex / 其他 Harness profile）使用。

## 验证

重启 profile 后，会话里应出现 4 个工具：

| 工具 | 作用 |
|---|---|
| `mcp__safety__audit_plugin` | 审计 npm 包 / GitHub 仓库 / 本地插件目录 |
| `mcp__safety__audit_url` | 从 URL 审计 |
| `mcp__safety__list_rules` | 列出规则库 |
| `mcp__safety__get_rule` | 查看单条规则 |

## 安全注意

- MCP 服务器进程 = **独立信任域**：恶意插件无法干扰审计器自身。
- 服务器只读被审计对象；下载的插件源码落在 `DSH_SAFETY_WORKDIR`（临时），
  结束自动清理。
- 不建议把审计器本身装成 dsh 插件（信任自举问题）。
