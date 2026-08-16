# 白名单配置指南（Allowlist Guide）

白名单用于抑制"正常插件也会触发"的已知误报——**默认是降级（downgrade）而非删除**，
保留证据但不再拉高风险等级。审计是辅助，白名单是人工复核结论的固化。

## 默认白名单（内置）

| 插件 | 规则 | 行为 | 理由 |
|---|---|---|---|
| harness-pet | T03 | downgrade | install 脚本仅资源装配（人工复核结论） |
| dsh-vision | T03 | downgrade | install 脚本为构建产物复制 |
| dsh-better-sidebar | T06-001 | downgrade | 仅文档提及敏感路径，无读取 |

内置默认白名单通过 `useDefaultAllowlist: false` 关闭，或注入自定义配置追加。

## 自定义白名单（注入）

MCP 工具 / CLI 支持注入 `AllowlistConfig`：

```json
{
  "version": "0.2.0",
  "entries": [
    {
      "ruleId": "T03",                 // 规则 id / 威胁编号 / "*"
      "plugin": "my-plugin",           // 插件名正则（大小写不敏感）
      "path": "scripts\\/.*\\.js",     // 可选：文件相对路径正则
      "host": "api\\.trusted\\.com",   // 可选：外联主机正则
      "action": "downgrade",           // skip=移除 | downgrade=降级 info（默认）
      "reason": "这是正常行为，因为……"
    }
  ]
}
```

匹配语义：所有给定维度都满足才命中（AND）；`ruleId: '*'` 匹配该插件的全部规则。

## 报告展示

被抑制的规则出现在报告的「白名单抑制」段，例如：

```
- T03-001（T03）→ 降级为 info：harness-pet 官方社区插件：install 脚本仅用于资源装配……
```

## 新增白名单的原则

1. **先复核，后白名单**：必须实际人工审查过该插件对应行为，确认无害，再固化。
2. **优先 downgrade，慎用 skip**：降级保留证据可追溯；skip 会完全隐藏。
3. **收窄匹配**：尽量带 `plugin` + `path`/`host`，避免误伤同类插件。
4. **理由必填**：写明人工复核结论，供后续维护者追溯。
