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

/** 从错误信息提取行为轨迹（ESM 导入的 fs/cp 无法插桩，错误即证据） */
function classifyError(msg) {
  const enoent = msg.match(/ENOENT[^\n]*?open '([^']+)'/);
  if (enoent) return { type: 'fs-read', path: enoent[1], note: '尝试读取（已被沙箱隔离）' };
  if (msg.includes('--allow-child-process')) return { type: 'command', note: 'child_process 调用被沙箱拒绝' };
  if (msg.includes('--allow-fs')) return { type: 'fs', note: 'fs 访问被沙箱拒绝' };
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

// ── 4. 最小 ctx mock ─────────────────────────────────────────────────────
const handlers = new Map();
const registeredTools = [];
const logs = [];
const mockCtx = {
  session: { id: 'sandbox-session' },
  on(event, cb) {
    if (!handlers.has(event)) handlers.set(event, []);
    handlers.get(event).push(cb);
  },
  once(event, cb) { this.on(event, cb); },
  off() {},
  emit() {},
  tool(name) {
    registeredTools.push(String(name));
    // DSH tool API 返回链式对象（register/schema 等）
    return { register() {}, schema() { return this; }, handler() { return this; }, usage() { return this; } };
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

// ── 6. 运行 + 触发事件 + 输出 ────────────────────────────────────────────
let status = 'completed';
let applyError = null;
(async () => {
  try {
    const { entry, apply } = await loadPlugin();
    log({ type: 'load', entry });
    apply(mockCtx);
    // 触发确定性事件（每类一次）
    const events = ['session/start', 'agent/turn/start', 'session/end'];
    for (const ev of events) {
      const cbs = handlers.get(ev) ?? [];
      if (cbs.length === 0) continue;
      log({ type: 'event', event: ev, handlers: cbs.length });
      for (const cb of cbs) {
        try { await cb({ session: mockCtx.session }); } catch (e) { pushError(e); }
      }
    }
    // 给异步行为一小段时间
    await new Promise((r) => setTimeout(r, 800));
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
