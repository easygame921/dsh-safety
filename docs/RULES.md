# 规则编写指南（Rules Guide）

> dsh-safety 的规则表是审计的"知识库"。新增规则必须遵循本指南，
> 并通过 fixtures 验证（恶意样本命中、良性样本不误报）。

## 规则结构

规则是 `SafetyRule`（`src/types.ts`），核心字段：

```ts
{
  id: 'T01-002',            // 威胁编号-序号
  threatId: 'T01',          // 对应威胁模型（DESIGN.md §2.2）
  severity: 'review',       // review | notice | info
  title: '中文标题',
  description: '威胁与危害说明（中文）',
  fileGlobs: ['**/*.js'],   // 限定文件类型；缺省=全量
  patterns: ['正则'],       // 文件内容正则（RegExp source，不带 /g）
  pathPatterns: ['正则'],   // 路径名正则
  fileChecks: ['patch-disables-security'],  // 内置文件级检查
  combinators: [            // 同文件组合规则
    { name: 'fetch+eval', allOf: ['fetch\\s*\\(', 'eval\\s*\\('] }
  ],
  falsePositiveNotes: '误报控制说明',
}
```

## 匹配语义

- **同一条规则**：patterns / pathPatterns / fileChecks 是 **OR** 关系（任一命中即发现）；
  文件过滤（fileGlobs）先执行。
- **combinators**：`allOf` 全部出现或 `anyOf` 任一出现 → 命中（AND/OR 组合）。
  用于跨表面威胁（如 T04 远程拉码 = 网络 + 执行）。
- **evidence**：每条命中产出 文件:行号 + 脱敏片段（16+ 字符 base64/hex 自动脱敏）。

## 严重度约定

| severity | 含义 | 示例 |
|---|---|---|
| review | 必须人工复核后再安装 | 禁用安全插件、窃取凭据、远程拉码 |
| notice | 注意，通常无害但值得了解 | 网络调用（白名单外）、动态执行 |
| info | 信息性 | env 变量使用、服务注入 |

## 新增规则流程（必须）

1. 在 DESIGN.md 威胁模型登记（或作为现有威胁的扩展规则）。
2. 写规则 → `src/rules/`。
3. 加 fixtures：
   - `fixtures/malicious/<name>/` —— 命中样本（必须被命中）；
   - 若规则有误报风险，在良性夹具或新良性夹具中加对照样本（不得误报）。
4. 在 `test/audit.test.mjs` 加断言（按 threatId 断言）。
5. `npm run build && npm test` 全绿；git 提交（规则 + 夹具 + 测试一起）。

## 反规避注意

- 攻击者会用零宽字符、base64、压缩混淆规避静态扫描（T02）。
- 网络域名提取要排除 localhost/127.0.0.1/*.local 与配置白名单。
- 组合规则（combinators）优先于单特征规则（防误报）。
