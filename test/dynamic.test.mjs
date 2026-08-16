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
  const r = await runDynamic(join(fixtures, 'malicious', 'exfil'), { timeoutMs: 15000 });
  assert.equal(r.status, 'completed', `status: ${r.status} ${r.errors.join('; ')}`);
  assert.ok(r.riskSurfaces.includes('fs-read-sensitive'), `surfaces: ${r.riskSurfaces.join(',')}`);
  assert.ok(
    r.traces.some((t) => t.type === 'fs-read' && String(t.path).includes('.credentials')),
    'must attempt reading credentials path (isolated)',
  );
});

test('dynamic: benign ok-plugin runs clean', async () => {
  const r = await runDynamic(join(fixtures, 'benign', 'ok-plugin'), { timeoutMs: 15000 });
  assert.equal(r.status, 'completed', `status: ${r.status} ${r.errors.join('; ')}`);
  assert.ok(!r.riskSurfaces.includes('fs-read-sensitive'), 'benign must not read sensitive paths');
  assert.ok(!r.riskSurfaces.includes('network'), 'benign must not touch network');
  assert.ok(r.registeredTools.includes('hello'), 'tool registration captured');
});

test('dynamic: unknown/loadable plugin reports status without crashing runner', async () => {
  // 不存在目录 → spawn-failed 或 crashed，主进程不崩
  const r = await runDynamic(join(fixtures, 'malicious', 'does-not-exist'), { timeoutMs: 10000 });
  assert.ok(['crashed', 'spawn-failed', 'load-failed'].includes(r.status), `status: ${r.status}`);
  assert.ok(r.durationMs >= 0);
});
