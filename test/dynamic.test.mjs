/**
 * 动态沙箱 MVP 测试（验收标准固化，docs/DYNAMIC-SANDBOX.md §7）。
 * 运行：npm run build && node --test
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runDynamic } from '../dist/dynamic/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, '..', 'fixtures');

test('dynamic: malicious exfil fixture triggers fs-read-sensitive surface', async () => {
  const r = await runDynamic(join(fixtures, 'malicious', 'exfil'), { timeoutMs: 15000, installDeps: false });
  assert.equal(r.status, 'completed', `status: ${r.status} ${r.errors.join('; ')}`);
  assert.ok(r.riskSurfaces.includes('fs-read-sensitive'), `surfaces: ${r.riskSurfaces.join(',')}`);
  assert.ok(
    r.traces.some((t) => t.type === 'fs-read' && String(t.path).includes('.credentials')),
    'must attempt reading credentials path (isolated)',
  );
});

test('dynamic: benign ok-plugin runs clean', async () => {
  const r = await runDynamic(join(fixtures, 'benign', 'ok-plugin'), { timeoutMs: 15000, installDeps: false });
  assert.equal(r.status, 'completed', `status: ${r.status} ${r.errors.join('; ')}`);
  assert.ok(!r.riskSurfaces.includes('fs-read-sensitive'), 'benign must not read sensitive paths');
  assert.ok(!r.riskSurfaces.includes('network'), 'benign must not touch network');
  assert.ok(r.registeredTools.includes('hello'), 'tool registration captured');
});

test('dynamic: unknown/loadable plugin reports status without crashing runner', async () => {
  // 不存在目录 → spawn-failed 或 crashed，主进程不崩
  const r = await runDynamic(join(fixtures, 'malicious', 'does-not-exist'), { timeoutMs: 10000, installDeps: false });
  assert.ok(['crashed', 'spawn-failed', 'load-failed'].includes(r.status), `status: ${r.status}`);
  assert.ok(r.durationMs >= 0);
});

// ---------------------------------------------------------------- 打磨后新增（2026-08-16 二轮）
test('dynamic: delayed-exfil (setTimeout 5s) caught via timer acceleration', async () => {
  // 延迟触发型恶意：setTimeout 5s 后读凭据外传——timer 加速后立即暴露
  const r = await runDynamic(join(fixtures, 'malicious-real', 'delayed-exfil'), { timeoutMs: 12000, installDeps: false });
  assert.equal(r.status, 'completed', `status: ${r.status} ${r.errors.join('; ')}`);
  assert.ok(r.traces.some((t) => t.type === 'timer'), 'must record timer');
  assert.ok(r.riskSurfaces.includes('fs-read-sensitive'), `surfaces: ${r.riskSurfaces.join(',')}`);
  assert.ok(r.riskSurfaces.includes('network-exfil-risk'), 'delayed exfil must be caught');
  assert.ok(r.riskSurfaces.includes('deferred-trigger'), 'deferred-trigger surface expected');
});

test('dynamic: persistence-rat unhandled-rejection tolerated, command+eval captured', async () => {
  // 插件内 `const code = await_fetch_rat()`（忘 await）→ unhandled rejection 不崩沙箱
  const r = await runDynamic(join(fixtures, 'malicious-real', 'persistence-rat'), { timeoutMs: 12000, installDeps: false });
  assert.equal(r.status, 'completed', `status: ${r.status} ${r.errors.join('; ')}`);
  assert.ok(r.riskSurfaces.includes('command'), `command expected, got ${r.riskSurfaces.join(',')}`);
  assert.ok(r.riskSurfaces.includes('eval'), `eval expected, got ${r.riskSurfaces.join(',')}`);
});

test('dynamic: session-thief session-log read flags fs-read-sensitive', async () => {
  const r = await runDynamic(join(fixtures, 'malicious-real', 'session-thief'), { timeoutMs: 12000, installDeps: false });
  assert.equal(r.status, 'completed', `status: ${r.status} ${r.errors.join('; ')}`);
  assert.ok(r.riskSurfaces.includes('fs-read-sensitive'), `surfaces: ${r.riskSurfaces.join(',')}`);
});

test('dynamic: api-key-sniffer .env read + exfil captured', async () => {
  const r = await runDynamic(join(fixtures, 'malicious-real', 'api-key-sniffer'), { timeoutMs: 12000, installDeps: false });
  assert.equal(r.status, 'completed', `status: ${r.status} ${r.errors.join('; ')}`);
  assert.ok(r.riskSurfaces.includes('fs-read-sensitive'), `surfaces: ${r.riskSurfaces.join(',')}`);
  assert.ok(r.riskSurfaces.includes('network-exfil-risk'), 'exfil risk expected');
});

test('dynamic: tool handler invoked (registered tool body executes in sandbox)', async () => {
  // benign-lookalike 注册 greet 工具；工具 handler 被调用模拟（不崩）
  const r = await runDynamic(join(fixtures, 'malicious-real', 'benign-lookalike'), { timeoutMs: 12000, installDeps: false });
  assert.equal(r.status, 'completed', `status: ${r.status} ${r.errors.join('; ')}`);
  assert.ok(r.registeredTools.includes('greet'), 'tool registered');
  assert.ok(r.traces.some((t) => t.type === 'tool' && t.name === 'greet'), 'tool call simulated');
});
