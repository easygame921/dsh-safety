/**
 * 动态沙箱：受限子进程入口（sandbox.mjs 由 runner 以
 * `node --experimental-permission` 启动）。
 *
 * 安全约束（docs/DYNAMIC-SANDBOX.md §3）：
 * - Node permission model：fs 只允许插件目录与沙箱工作目录；禁网络/子进程/worker
 * - 本文件再补：eval/Function patch（记录不执行）、fetch patch（记录+拒绝）、
 *   process.env 访问记录（注入假 HOME/USERPROFILE）
 * - 输出：单行 JSON 轨迹到 stdout
 */
const pluginRoot = process.argv[2];
const sandboxWorkDir = process.argv[3];
if (!pluginRoot || !sandboxWorkDir) {
  process.stderr.write('usage: sandbox.mjs <pluginRoot> <sandboxWorkDir>\n');
  process.exit(2);
}

const traces = [];
const errors = [];
const log = (t) => traces.push(t);

// 插件代码常有不 await 的 async 调用（如 `const x = fetch(...)` 忘了 await）——
// unhandled rejection 默认会崩沙箱；捕获为错误轨迹，不影响观察其余行为。
process.on('unhandledRejection', (reason) => {
  pushError(reason instanceof Error ? reason : new Error(String(reason)));
});

/** 从错误信息提取行为轨迹（ESM 导入的 fs/cp 无法插桩，错误即证据） */
function classifyError(msg) {
  const enoent = msg.match(/ENOENT[^\n]*?open '([^']+)'/);
  if (enoent) return { type: 'fs-read', path: enoent[1], note: '尝试读取（已被沙箱隔离）' };
  // Node 24 权限模型拒绝：--allow-fs-read 报 "Access to this API has been restricted"，无路径
  // ——无法区分读写；记 fs 轨迹（generic），结合上下文判断
  if (msg.includes('restricted') || msg.includes('--allow-fs')) return { type: 'fs', note: 'fs 访问被沙箱拒绝' };
  if (msg.includes('--allow-child-process')) return { type: 'command', note: 'child_process 调用被沙箱拒绝' };
  if (msg.includes('network blocked')) return { type: 'network', note: '网络请求被沙箱拒绝' };
  return null;
}
function pushError(e) {
  const msg = String((e && e.message) ?? e).slice(0, 300);
  errors.push(msg);
  const cls = classifyError(msg);
  if (cls) log(cls);
}

// ── 1. eval / Function：记录，不执行 ─────────────────────────────────────
const realEval = globalThis.eval;
// @ts-expect-error 运行时 patch
globalThis.eval = function patchedEval(...args) {
  log({ type: 'eval', snippet: String(args[0] ?? '').slice(0, 200) });
  return undefined;
};
// new Function：记录，返回 noop（不执行载荷）
const realFunction = globalThis.Function;
// @ts-expect-error 运行时 patch
globalThis.Function = new Proxy(realFunction, {
  apply(_t, _thisArg, args) {
    const body = args.length > 0 ? String(args[args.length - 1] ?? '') : '';
    log({ type: 'eval', snippet: body.slice(0, 200) });
    return function noop() { /* 沙箱：不执行 */ };
  },
  construct(_t, args) {
    const body = args.length > 0 ? String(args[args.length - 1] ?? '') : '';
    log({ type: 'eval', snippet: body.slice(0, 200) });
    return function noop() { /* 沙箱：不执行 */ };
  },
});

// ── 2. fetch / WebSocket：记录目标，拒绝（不真实外发） ───────────────────
// @ts-expect-error 运行时 patch
globalThis.fetch = async (...args) => {
  const url = String(args[0] ?? '');
  const method = (args[1] && args[1].method) || 'GET';
  let bodyBytes = 0;
  if (args[1] && args[1].body) {
    try { bodyBytes = String(args[1].body).length; } catch { bodyBytes = -1; }
  }
  log({ type: 'network', method, url, bodyBytes });
  throw new Error('sandbox: network blocked');
};

// ── 3. process.env：记录访问（过滤内部噪声，去重），注入假 HOME ─────────
const envBacking = { ...process.env };
envBacking.HOME = sandboxWorkDir;
envBacking.USERPROFILE = sandboxWorkDir;
envBacking.DSH_HOME = sandboxWorkDir;
const envLog = new Set();
const ENV_INTEREST_RE = /HOME|USERPROFILE|DSH|TOKEN|KEY|SECRET|PASSWORD|API|CREDENTIAL/i;
// @ts-expect-error 运行时替换
process.env = new Proxy(envBacking, {
  get(t, k) {
    if (typeof k === 'string' && ENV_INTEREST_RE.test(k) && !envLog.has(k)) {
      envLog.add(k);
      log({ type: 'env', key: k });
    }
    return t[k];
  },
  set(t, k, v) {
    t[k] = v;
    return true;
  },
});

// ── 3.5 时间加速：setTimeout/setInterval/setImmediate 立即触发（记录原始延迟）──
// 动机：延迟触发型恶意行为（setTimeout 5s 后读凭据）在观察窗口内必然漏；
// 沙箱内不真实等待——回调立即执行，危险动作仍被 fs/net/cp 拦截，只是时机提前。
const realSetTimeout = globalThis.setTimeout;
const realSetInterval = globalThis.setInterval;
const realSetImmediate = globalThis.setImmediate;
const realClearTimeout = globalThis.clearTimeout;
const realClearInterval = globalThis.clearInterval;
// @ts-expect-error 运行时 patch
globalThis.setTimeout = function patchedSetTimeout(fn, delay, ...rest) {
  log({ type: 'timer', kind: 'setTimeout', delay: Number(delay) || 0 });
  if (typeof fn !== 'function') return realSetTimeout(fn, delay, ...rest);
  // 立即执行（捕获错误，不中断沙箱）；返回假 timer id 便于 clear
  try { fn(...rest); } catch (e) { pushError(e); }
  return { __sandboxTimer: true };
};
// @ts-expect-error 运行时 patch
globalThis.setInterval = function patchedSetInterval(fn, delay, ...rest) {
  log({ type: 'timer', kind: 'setInterval', delay: Number(delay) || 0 });
  if (typeof fn !== 'function') return realSetInterval(fn, delay, ...rest);
  // 立即执行一次（不循环——沙箱内循环会耗尽窗口）
  try { fn(...rest); } catch (e) { pushError(e); }
  return { __sandboxTimer: true };
};
// @ts-expect-error 运行时 patch
globalThis.setImmediate = function patchedSetImmediate(fn, ...rest) {
  log({ type: 'timer', kind: 'setImmediate', delay: 0 });
  if (typeof fn !== 'function') return realSetImmediate(fn, ...rest);
  try { fn(...rest); } catch (e) { pushError(e); }
  return { __sandboxTimer: true };
};
globalThis.clearTimeout = (id) => { if (id && id.__sandboxTimer) return; realClearTimeout(id); };
globalThis.clearInterval = (id) => { if (id && id.__sandboxTimer) return; realClearInterval(id); };

// ── 3.6 fs / child_process 插桩（ESM 命名导入共享 CJS 模块对象，patch 生效）──
// 动机：权限模型拒绝错误不带路径，轨迹粒度粗；patch 后能记录**精确路径/命令**。
// 读 API：记录路径，返回空 Buffer（不真实读）；写 API：记录后丢弃；
// child_process：记录命令，返回模拟空输出。权限模型仍作内核级兜底。
import { createRequire } from 'node:module';
const __req = createRequire(import.meta.url);
const realFs = __req('node:fs');
const realCp = __req('node:child_process');

/** 归一化路径用于白名单判断（file:// URL 剥前缀、正斜杠、去前导斜杠） */
const allowRootSlash = String(pluginRoot).replaceAll('\\', '/');
function normPath(p) {
  let s = String(p ?? '');
  if (s.startsWith('file://')) s = decodeURIComponent(s.slice('file://'.length));
  return s.replaceAll('\\', '/').replace(/^\/+/, '');
}
function isInsidePluginRoot(p) {
  return normPath(p).startsWith(allowRootSlash.replace(/^\/+/, ''));
}

function recordFsRead(p, extra = {}) {
  const path = String(p ?? '');
  log({ type: 'fs-read', path, ...extra });
  return Buffer.alloc(0); // 空内容（不真实读）
}
function recordFsWrite(p, extra = {}) {
  const path = String(p ?? '');
  log({ type: 'fs-write', path, ...extra });
  return undefined;
}

// 保存原始实现（插件目录内读取——ESM loader/入口探测——走真实路径）
const _readFile = realFs.readFile;
const _readFileSync = realFs.readFileSync;

// readFile / readFileSync / createReadStream
// 路径敏感：插件根内（loader 读源码/探测）走真实；根外（插件运行时读系统文件）记录+空
realFs.readFile = async function (p, ...rest) {
  if (isInsidePluginRoot(p)) return _readFile.call(realFs, p, ...rest);
  const last = rest.length > 0 && typeof rest[rest.length - 1] === 'function' ? rest.pop() : null;
  const cb = last;
  const opts = rest[0] ?? {};
  const enc = typeof opts === 'string' ? opts : (opts && opts.encoding) || 'utf8';
  const buf = recordFsRead(p);
  if (cb) { queueMicrotask(() => cb(null, enc && enc !== 'buffer' ? buf.toString(enc) : buf)); return; }
  return enc && enc !== 'buffer' ? buf.toString(enc) : buf;
};
realFs.readFileSync = function (p, ...rest) {
  if (isInsidePluginRoot(p)) return _readFileSync.call(realFs, p, ...rest);
  return recordFsRead(p);
};
realFs.createReadStream = (p, ...rest) => {
  recordFsRead(p);
  // 返回最小可读流（立即 end，不真实读）
  const { Readable } = __req('node:stream');
  const s = new Readable({ read() { this.push(null); } });
  return s;
};
// writeFile / writeFileSync / appendFile / mkdir / rm / unlink / copyFile
realFs.writeFile = (p, ...rest) => { const cb = typeof rest[rest.length - 1] === 'function' ? rest.pop() : null; recordFsWrite(p); if (cb) queueMicrotask(() => cb(null)); return Promise.resolve(); };
realFs.writeFileSync = (p, ...rest) => recordFsWrite(p);
realFs.appendFile = (p, ...rest) => { const cb = typeof rest[rest.length - 1] === 'function' ? rest.pop() : null; recordFsWrite(p); if (cb) queueMicrotask(() => cb(null)); return Promise.resolve(); };
realFs.appendFileSync = (p, ...rest) => recordFsWrite(p);
realFs.mkdir = (p, ...rest) => { const cb = typeof rest[rest.length - 1] === 'function' ? rest.pop() : null; recordFsWrite(p, { op: 'mkdir' }); if (cb) queueMicrotask(() => cb(null)); return Promise.resolve(); };
realFs.mkdirSync = (p, ...rest) => recordFsWrite(p, { op: 'mkdir' });
realFs.rm = (p, ...rest) => { const cb = typeof rest[rest.length - 1] === 'function' ? rest.pop() : null; recordFsWrite(p, { op: 'rm' }); if (cb) queueMicrotask(() => cb(null)); return Promise.resolve(); };
realFs.rmSync = (p, ...rest) => recordFsWrite(p, { op: 'rm' });
realFs.unlink = (p, ...rest) => { const cb = typeof rest[rest.length - 1] === 'function' ? rest.pop() : null; recordFsWrite(p, { op: 'unlink' }); if (cb) queueMicrotask(() => cb(null)); return Promise.resolve(); };
realFs.unlinkSync = (p, ...rest) => recordFsWrite(p, { op: 'unlink' });
realFs.copyFile = (src, dst, ...rest) => { const cb = typeof rest[rest.length - 1] === 'function' ? rest.pop() : null; recordFsRead(src); recordFsWrite(dst, { op: 'copyFile' }); if (cb) queueMicrotask(() => cb(null)); return Promise.resolve(); };
realFs.copyFileSync = (src, dst, ...rest) => { recordFsRead(src); recordFsWrite(dst, { op: 'copyFile' }); };
// readdir / stat / existsSync：记录路径（信息性）
realFs.readdir = (p, ...rest) => { const cb = typeof rest[rest.length - 1] === 'function' ? rest.pop() : null; log({ type: 'fs-read', path: String(p ?? ''), op: 'readdir' }); if (cb) queueMicrotask(() => cb(null, [])); return Promise.resolve([]); };
realFs.readdirSync = (p, ...rest) => { log({ type: 'fs-read', path: String(p ?? ''), op: 'readdir' }); return []; };
realFs.stat = (p, ...rest) => { const cb = typeof rest[rest.length - 1] === 'function' ? rest.pop() : null; log({ type: 'fs-read', path: String(p ?? ''), op: 'stat' }); const fake = { isFile: () => true, isDirectory: () => false, size: 0 }; if (cb) queueMicrotask(() => cb(null, fake)); return Promise.resolve(fake); };
realFs.statSync = (p, ...rest) => { log({ type: 'fs-read', path: String(p ?? ''), op: 'stat' }); return { isFile: () => true, isDirectory: () => false, size: 0 }; };
realFs.existsSync = (p, ...rest) => { log({ type: 'fs-read', path: String(p ?? ''), op: 'exists' }); return true; }; // 返回 true 让逻辑继续（真实读取仍被拦）

// child_process：记录命令，返回模拟空输出（不执行）
function recordCommand(cmd) { log({ type: 'command', cmd: String(cmd ?? '').slice(0, 200) }); }
function fakeCpResult(enc) { return enc ? '' : Buffer.alloc(0); }
realCp.exec = (cmd, ...rest) => { const cb = typeof rest[rest.length - 1] === 'function' ? rest.pop() : null; recordCommand(cmd); if (cb) queueMicrotask(() => cb(null, '', '')); return { on() {}, stdout: { on() {}, pipe() {} }, stderr: { on() {}, pipe() {} } }; };
realCp.execSync = (cmd, ...rest) => { recordCommand(cmd); return fakeCpResult(rest[0] && rest[0].encoding); };
realCp.execFile = (file, ...rest) => { const args = Array.isArray(rest[0]) ? rest[0] : []; const cb = typeof rest[rest.length - 1] === 'function' ? rest.pop() : null; recordCommand(file + ' ' + args.join(' ')); if (cb) queueMicrotask(() => cb(null, '', '')); return { on() {}, stdout: { on() {}, pipe() {} }, stderr: { on() {}, pipe() {} } }; };
realCp.execFileSync = (file, ...rest) => { const args = Array.isArray(rest[0]) ? rest[0] : []; recordCommand(file + ' ' + args.join(' ')); return fakeCpResult(rest.find((x) => x && x.encoding)); };
realCp.spawn = (file, ...rest) => { const args = Array.isArray(rest[0]) ? rest[0] : []; recordCommand(file + ' ' + args.join(' ')); const { EventEmitter } = __req('node:events'); const child = new EventEmitter(); child.pid = -1; child.stdout = { on() {}, pipe() {} }; child.stderr = { on() {}, pipe() {} }; child.stdin = { write() {}, end() {} }; child.kill = () => true; queueMicrotask(() => child.emit('close', 0, null)); return child; };
realCp.spawnSync = (file, ...rest) => { const args = Array.isArray(rest[0]) ? rest[0] : []; recordCommand(file + ' ' + args.join(' ')); return { status: 0, signal: null, output: [], stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), pid: -1, error: null }; };

// ── 4. 最小 ctx mock ─────────────────────────────────────────────────────
const handlers = new Map();
const registeredTools = [];
const toolHandlers = new Map();
const logs = [];

/** 可链式调用的 noop 对象：任何属性/调用都返回自身（未知 ctx 表面不崩） */
function chainable(label) {
  const fn = function () {};
  return new Proxy(fn, {
    get(t, prop) {
      if (prop === Symbol.toPrimitive) return () => 0;
      if (prop === 'then' || prop === 'catch' || prop === 'finally') return undefined; // 避免被当 Promise
      return chainable(`${label}.${String(prop)}`);
    },
    apply() { return chainable(label); },
    construct() { return chainable(label); },
  });
}

const mockCtxBase = {
  session: { id: 'sandbox-session' },
  on(event, cb) {
    if (!handlers.has(event)) handlers.set(event, []);
    handlers.get(event).push(cb);
  },
  once(event, cb) { this.on(event, cb); },
  off() {},
  emit() {},
  // DSH 工具注册三种形态：
  //  ctx.tool('name', handler)          —— 直接带 handler
  //  ctx.tool('name').register(handler) —— 链式带 name
  //  ctx.tool().register('name', fn)    —— 无参 tool() + register(name, fn)
  tool(name, handler) {
    if (typeof name === 'function') { handler = name; name = undefined; }
    if (name !== undefined) registeredTools.push(String(name));
    return {
      register(fnOrName, maybeFn) {
        const n = typeof fnOrName === 'string' ? fnOrName : String(name ?? 'anonymous');
        const h = typeof fnOrName === 'function' ? fnOrName : maybeFn;
        if (n !== 'anonymous' && !registeredTools.includes(n)) registeredTools.push(n);
        if (typeof h === 'function') toolHandlers.set(n, h);
        return this;
      },
      handler(fnOrName, maybeFn) {
        const n = typeof fnOrName === 'string' ? fnOrName : String(name ?? 'anonymous');
        const h = typeof fnOrName === 'function' ? fnOrName : maybeFn;
        if (typeof h === 'function') toolHandlers.set(n, h);
        return this;
      },
      schema() { return this; },
      usage() { return this; },
      option() { return this; },
      action(fnOrName, maybeFn) {
        const n = typeof fnOrName === 'string' ? fnOrName : String(name ?? 'anonymous');
        const h = typeof fnOrName === 'function' ? fnOrName : maybeFn;
        if (typeof h === 'function') toolHandlers.set(n, h);
        return this;
      },
    };
  },
  // DSH 常见生命周期/装配 API（真实样本暴露的常用表面）
  effect(fn) { try { fn(); } catch (e) { pushError(e); } return { dispose() {} }; },
  inject() { return {}; },
  deploy() {},
  model: { on() {} },
  logger: {
    info: (...a) => logs.push(['info', ...a]),
    warn: (...a) => logs.push(['warn', ...a]),
    error: (...a) => logs.push(['error', ...a]),
  },
  settings: { get: () => ({}), describe: () => [] },
  sessions: { get: () => ({ push() {}, content: [] }), getCurrent: () => null },
  config: { get: () => undefined },
  workspace: { get cwd() { return sandboxWorkDir; } },
  // cordis 服务获取：返回 chainable（未知服务不崩）
  get: () => chainable('ctx.get'),
  inject: () => chainable('ctx.inject'),
  // ── 常见服务表面（dsh 生态插件常用，安全空实现，不抛错）──
  model: {
    on() {},
    listModels: async () => [],
    resolveModelInfo: async () => ({ inputModalities: ['text'], id: 'sandbox-model' }),
    chat: async () => ({ content: '' }),
  },
  agent: { on() {}, start() {}, steer() {}, followup() {}, fork() {}, getCurrent: () => null, initiator: { on() {} } },
  approval: { ask: async () => ({ outcome: 'deny', reason: 'sandbox' }) },
  permission: { on() {} },
  permissionPresets: { on() {} },
  storage: {
    get: () => undefined,
    domain: () => ({ get: async () => undefined, set: async () => {}, on: () => {} }),
  },
  terminal: { on() {}, start: async () => ({}), send: async () => {} },
  shell: { on() {}, execute: async () => ({ stdout: '', code: 0 }) },
  workflows: { on() {}, run: async () => ({}) },
  compaction: { on() {} },
  subagent: { on() {}, start: async () => ({}) },
  attachment: { on() {}, saveImage: async () => ({ attachmentId: 'sandbox' }) },
  credentials: { get: async () => undefined, list: async () => [] },
  telemetry: { on() {} },
  scope: { on() {} },
  invariants: { on() {} },
  sdk: { on() {} },
  plugins: { on() {} },
  heartbeat: { on() {} },
};

// 顶层兜底：未知 ctx 属性返回 chainable（链式调用不崩，行为记录为未知表面）
const mockCtx = new Proxy(mockCtxBase, {
  get(t, prop) {
    if (prop in t) return t[prop];
    return chainable(`ctx.${String(prop)}`);
  },
});

// ── 5. 加载插件入口 ──────────────────────────────────────────────────────
async function loadPlugin() {
  const { pathToFileURL } = await import('node:url');
  const candidates = ['src/index.js', 'lib/index.js', 'index.js'];
  let entry = null;
  for (const c of candidates) {
    const p = `${pluginRoot}/${c}`;
    try {
      const { readFile } = await import('node:fs/promises');
      await readFile(p, 'utf8'); // fs.access 在权限模型下被禁止，改用 readFile 探测
      entry = p;
      break;
    } catch (e) {
      errors.push(`entry-probe ${c}: ${String((e && e.message) ?? e).slice(0, 120)}`);
    }
  }
  if (!entry) {
    // 读 package.json main
    try {
      const { readFileSync } = await import('node:fs');
      const pkg = JSON.parse(readFileSync(`${pluginRoot}/package.json`, 'utf8'));
      if (pkg.main) entry = `${pluginRoot}/${pkg.main}`;
    } catch { /* 忽略 */ }
  }
  if (!entry) throw new Error('no plugin entry found (src/index.js / lib/index.js / package.json main)');
  const mod = await import(pathToFileURL(entry).href);
  const apply = mod.apply ?? (mod.default && mod.default.apply);
  if (typeof apply !== 'function') throw new Error(`entry ${entry} has no apply(ctx)`);
  return { entry, apply };
}

// ── 6. 运行 + 触发事件 + 工具调用模拟 + 输出 ────────────────────────────
let status = 'completed';
let applyError = null;
/** mock 工具入参（常见形态，触发 handler 执行夹带行为） */
const mockToolArgs = { input: { text: 'sandbox-test', file: 'test.txt', path: 'test.txt', url: 'https://example.com/test' } };
(async () => {
  try {
    const { entry, apply } = await loadPlugin();
    log({ type: 'load', entry });
    apply(mockCtx);
    // 触发确定性事件（每类一次），传 mock 消息对象
    const events = [
      ['session/start', { session: mockCtx.session }],
      ['agent/turn/start', { session: mockCtx.session, message: { role: 'user', content: 'hello' } }],
      ['message/create', { session: mockCtx.session, message: { role: 'user', content: 'hello' } }],
      ['agent/tool/call', { session: mockCtx.session, name: 'sandbox-tool', args: mockToolArgs.input }],
      ['session/end', { session: mockCtx.session }],
    ];
    for (const [ev, payload] of events) {
      const cbs = handlers.get(ev) ?? [];
      if (cbs.length === 0) continue;
      log({ type: 'event', event: ev, handlers: cbs.length });
      for (const cb of cbs) {
        try { await cb(payload); } catch (e) { pushError(e); }
      }
    }
    // 工具调用模拟：逐个调用已注册工具 handler（夹带行为常藏在 handler 里）
    for (const [name, fn] of toolHandlers) {
      log({ type: 'tool', name, called: true });
      try { await fn(mockToolArgs.input, { session: mockCtx.session }); } catch (e) { pushError(e); }
    }
    // 给异步行为一小段时间（timer 已加速，窗口主要等微任务/IO 回调）
    await new Promise((r) => realSetTimeout(r, 2000));
  } catch (e) {
    status = 'load-failed';
    applyError = String((e && e.message) ?? e).slice(0, 300);
  }
  const out = {
    status,
    pluginRoot,
    traces,
    errors,
    registeredTools,
    loggerLogs: logs.length,
    applyError,
  };
  process.stdout.write(JSON.stringify(out) + '\n');
  process.exit(0);
})();
