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

## 组合规则邻近语义（2026-08 起）

`combinators.allOf` 的子特征必须在**同一文件 ±2000 字符窗口**内共存才算命中——
"同一函数/语句块的关联行为"。全文件散落共存（如查市场 fetch + 读配置 readFile）
不算组合。字符窗口对压缩产物（单行大文件）同样有效。动机：64% → 34.8% 误报率压制
的核心机制之一（跨模块无关能力不再误判为攻击组合）。

## 注释排除

代码规则（patterns / combinators）默认跳过注释/纯文本行（`//`、`/*`、`*`、`#`、`--` 开头）。
注释里描述危险模式 ≠ 真实行为（真实插件 README/注释大量描述安全警告导致误报）。

## T14 依赖链投毒（新增，2026-08）

| 规则 | severity | 检查 | 说明 |
|---|---|---|---|
| T14-001 | review | `pkg-deps-audit` | 已知恶意包名单（event-stream、ua-parser-js 投毒版、node-ipc、crypto-js 等真实事件）；typosquatting（与高价值知名包**长度相同且编辑距离=1**，如 lodahs/lodash、axois/axios）；可疑来源协议（file:/git+/http://） |
| T14-002 | review | `.npmrc` patterns | registry 指向非 https 或非官方源（registry 篡改） |
| T14-003 | notice | `pkg-dep-wide-range` | 通配版本（* / latest）依赖——DSH 官方 @deepseek-ai/* 包用通配是生态标准，仅提示 |

typosquat 判定要点：**长度相同 + 编辑距离 1**（单字符差异）。短词 2 字符差异
（clsx/tsx、vitest/vite、@codemirror/commands vs commander）为合法包，不得误报
（本地真实插件实测驱动）。dotfile（.npmrc/.lock）由 files.ts 按完整文件名匹配
（`extname('.npmrc')` 返回空串，需特殊处理）。
