/**
 * dsh-safety 端到端测试：对 fixtures 跑真实扫描。
 * 运行：npm run build && node --test test/
 * 断言策略：按 threatId 断言（不绑定具体规则 ID，规则库演进不破坏测试）。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scan } from '../dist/index.js';
import { v1Rules } from '../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, '..', 'fixtures');

/** 扫描一个夹具目录，返回报告 */
async function auditFixture(name) {
  const root = join(fixtures, name);
  return scan({ root, sourceLabel: name }, v1Rules);
}

/** 报告中的 threatId 集合 */
function threatIds(report) {
  return new Set(report.findings.map((f) => f.threatId));
}

// ---------------------------------------------------------------- malicious
test('T01 disable-security: patch-disables-security fires', async () => {
  const r = await auditFixture('malicious/disable-security');
  assert.ok(threatIds(r).has('T01'), `expected T01 finding, got: ${[...threatIds(r)]}`);
  assert.ok(r.findings.some((f) => f.severity === 'review'));
});

test('T02 hidden-prompt: zero-width / encoded eval detected', async () => {
  const r = await auditFixture('malicious/hidden-prompt');
  assert.ok(threatIds(r).has('T02'), `expected T02 finding, got: ${[...threatIds(r)]}`);
});

test('T03 install-script: preinstall/postinstall flagged', async () => {
  const r = await auditFixture('malicious/install-script');
  assert.ok(threatIds(r).has('T03'), `expected T03 finding, got: ${[...threatIds(r)]}`);
  const f = r.findings.find((x) => x.threatId === 'T03');
  assert.ok(f && f.evidence.length >= 2, 'install scripts should each carry evidence');
});

test('T04 remote-code: fetch+eval combinator fires', async () => {
  const r = await auditFixture('malicious/remote-code');
  assert.ok(threatIds(r).has('T04'), `expected T04 finding, got: ${[...threatIds(r)]}`);
});

test('T05 exfil: network + sensitive read combinator fires', async () => {
  const r = await auditFixture('malicious/exfil');
  assert.ok(threatIds(r).has('T05'), `expected T05 finding, got: ${[...threatIds(r)]}`);
});

test('T06 credential-steal: credential paths flagged', async () => {
  const r = await auditFixture('malicious/credential-steal');
  assert.ok(threatIds(r).has('T06'), `expected T06 finding, got: ${[...threatIds(r)]}`);
});

// ---------------------------------------------------------------- benign
test('benign ok-plugin: zero review findings', async () => {
  const r = await auditFixture('benign/ok-plugin');
  assert.equal(r.findings.filter((f) => f.severity === 'review').length, 0,
    `ok-plugin must have no review findings: ${JSON.stringify(r.findings)}`);
});

test('benign vision-helper: network without exfil is not review', async () => {
  const r = await auditFixture('benign/vision-helper');
  const review = r.findings.filter((f) => f.severity === 'review');
  assert.equal(review.length, 0, `vision-helper must have no review findings: ${JSON.stringify(review)}`);
  // 但网络能力应被记录在权限画像里
  assert.equal(r.profile.network, true);
  assert.ok(r.profile.outboundHosts.includes('api.vision.example.com'));
});

// ---------------------------------------------------------------- contract
test('contract: audit report is read-only and well-formed', async () => {
  const r = await auditFixture('benign/ok-plugin');
  assert.equal(r.writesPerformed, false);
  assert.equal(typeof r.filesScanned, 'number');
  assert.ok(r.filesScanned >= 1);
  assert.ok(r.ruleSetVersion.length > 0);
  assert.ok(typeof r.durationMs === 'number');
  assert.ok(typeof r.scannedAt === 'string');
});
