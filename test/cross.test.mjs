/**
 * 动态 ↔ 静态 cross-validation 测试。
 * 场景：恶意样本（静态 review + 动态证实）、良性（静态 ok + 动态干净）、
 * 纯静态威胁（T03/T07/T14 类——动态观察不到，维持 unconfirmed 不误判为安全）。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scan, v1Rules } from '../dist/index.js';
import { runDynamic } from '../dist/dynamic/index.js';
import { crossValidate } from '../dist/cross/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, '..', 'fixtures');

test('cross: malicious exfil — static T05/T06 confirmed by dynamic', async () => {
  const root = join(fixtures, 'malicious', 'exfil');
  const report = await scan({ root, sourceLabel: 'exfil', excludeTests: false }, v1Rules);
  const dynamic = await runDynamic(root, { timeoutMs: 15000, installDeps: false });
  const cv = crossValidate(report, dynamic);
  assert.equal(cv.hasDynamic, true);
  assert.ok(cv.dynamicConfirmsRisk, 'exfil must be dynamically confirmed');
  const t06 = cv.verdicts.find((v) => v.threatId === 'T06');
  assert.ok(t06 && t06.verdict === 'confirmed', `T06 verdict: ${t06?.verdict}`);
  const t05 = cv.verdicts.find((v) => v.threatId === 'T05');
  assert.ok(t05 && t05.verdict === 'confirmed', `T05 verdict: ${t05?.verdict}`);
});

test('cross: benign ok-plugin — no dynamic confirmation, no false alarm', async () => {
  const root = join(fixtures, 'benign', 'ok-plugin');
  const report = await scan({ root, sourceLabel: 'ok', excludeTests: false }, v1Rules);
  const dynamic = await runDynamic(root, { timeoutMs: 15000, installDeps: false });
  const cv = crossValidate(report, dynamic);
  assert.equal(cv.hasDynamic, true);
  assert.ok(!cv.dynamicConfirmsRisk, 'benign must not be dynamically confirmed as risk');
});

test('cross: no-dynamic — verdicts report no-dynamic without crashing', async () => {
  const root = join(fixtures, 'malicious', 'exfil');
  const report = await scan({ root, sourceLabel: 'exfil', excludeTests: false }, v1Rules);
  const cv = crossValidate(report, undefined);
  assert.equal(cv.hasDynamic, false);
  assert.ok(cv.verdicts.length > 0);
  assert.ok(cv.verdicts.every((v) => v.verdict === 'no-dynamic'));
});

test('cross: load-failed dynamic is NOT treated as safe (load-failed verdict)', async () => {
  // 动态跑了但加载失败（如依赖不齐/apply 依赖真实环境）——必须标 load-failed，
  // 绝不能因"没动态证据"降级为安全
  const root = join(fixtures, 'malicious', 'install-script'); // 无 host 入口 → load-failed
  const report = await scan({ root, sourceLabel: 'install-script', excludeTests: false }, v1Rules);
  const dynamic = await runDynamic(root, { timeoutMs: 15000, installDeps: false });
  const cv = crossValidate(report, dynamic);
  assert.equal(cv.hasDynamic, false, 'load-failed must not count as dynamic evidence');
  assert.ok(cv.verdicts.some((v) => v.verdict === 'load-failed'), 'load-failed verdict expected');
  assert.ok(!cv.plain.includes('未观察到对应行为'), 'must not claim clean when load failed');
});

test('cross: install-script-only threat (T03) stays unconfirmed/load-failed, not contradicted', async () => {
  // T03 安装脚本：动态沙箱不执行安装钩子 → 观察不到是预期；不得因"动态干净"降级为安全。
  // 该夹具无 host 端入口（只有 package.json + scripts），动态可能 load-failed——同样不得降级。
  const root = join(fixtures, 'malicious', 'install-script');
  const report = await scan({ root, sourceLabel: 'install-script', excludeTests: false }, v1Rules);
  const dynamic = await runDynamic(root, { timeoutMs: 15000, installDeps: false });
  const cv = crossValidate(report, dynamic);
  const t03 = cv.verdicts.find((v) => v.threatId === 'T03');
  // T03 可能是 review（install script 是 review 规则）
  if (t03) {
    assert.ok(['unconfirmed', 'load-failed', 'no-dynamic'].includes(t03.verdict), `T03 must not be claimed safe, got ${t03.verdict}`);
  }
});
