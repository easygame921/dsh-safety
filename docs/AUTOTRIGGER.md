# 自动触发规范（Auto-trigger Guide）

dsh-safety 的目标使用方式：**用户一旦表达"想装/想试某个社区 dsh 插件"，审计自动发生，
报告进对话流；用户要求时再落盘文件报告。**

## 触发条件（agent 应识别）

用户在会话中表达以下意图之一（中英文均可）：
- 安装 / 下载 / 添加 / 尝试 / 体验 / 评测 / 看看某个 dsh 插件
- 给出插件来源：npm 包名、`github:owner/repo`、GitHub 仓库 URL、npm 包页 URL、本地插件目录

示例：
> "帮我装一个 xxx 插件" / "这个 github:foo/bar 插件怎么样" / "npm 上有个 dsh-plugin 想试试"

## 自动动作（agent 行为约定）

1. **先审计，后安装**：调用 `mcp__safety__audit_plugin`（或 `audit_url`）完成扫描，
   **不得**在审计完成前执行 `dsh plugin add` / 安装操作。
2. **对话流输出 = 完整报告 + 大白话总结**：MCP 返回两个文本块（完整 Markdown 报告 +
   🗣️ 大白话总结）。agent 应向用户展示**两者**——报告面向能看懂的人，大白话保证
   普通用户也懂。展示顺序：先完整报告要点，再大白话总结（或按用户偏好只给一个）。
3. **文件报告（按需）**：当用户要求"输出文件/保存报告"时，用文件写入工具把完整
   Markdown 报告保存到用户指定路径（默认桌面 `dsh-safety-report-<插件名>.md`），
   并在对话流给出路径。
4. **风险提示**：REVIEW 级发现时明确提示用户人工复核，**不代替用户做安装决定**。

## 输出格式约定（对话流摘要模板）

```
🔍 dsh-safety 审计：<插件名> → 风险 <OK|REVIEW>
- 扫描 N 个文件，M 条发现
- ⚠ review：T0x <标题> @ file:line
- ℹ info/notice：...
- 白名单抑制：<若适用>
结论：<建议>
```

## 装配方式

把本规范的指令追加到 agent 指令文件（如 `~/.dsh/AGENTS.md`）或作为 agent-preset
内容，使会话内 agent 自动遵守。见仓库 `assets/agent-presets/dsh-safety/`。
