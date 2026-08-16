/**
 * 真实恶意样本检测率回归测试：fixtures/malicious-real/ 抓取率门槛。
 * 门槛：样本抓取率 ≥90%、威胁覆盖率 ≥80%、良性样本 0 误报。
 * 运行：npm run build && node --test test/
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scan, v1Rules } from '../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const corpus = join(root, 'fixtures', 'malicious-real');
const manifest = JSON.parse(readFileSync(join(corpus, 'manifest.json'), 'utf8'));

function reviewThreats(report) {
  return new Set(report.findings.filter((f) => f.severity === 'review').map((f) => f.threatId));
}

test('detection-rate: sample catch rate >= 90% and threat coverage >= 80%', async () => {
  let sampleCaught = 0;
  let fullyCaught = 0;
  let expectedTotal = 0;
  let threatHit = 0;
  const detail = [];
  for (const s of manifest.samples) {
    const report = await scan(
      { root: join(corpus, s.dir), sourceLabel: s.dir, excludeTests: false, excludeDocs: false, useDefaultAllowlist: false },
      v1Rules,
    );
    const hit = reviewThreats(report);
    const missed = s.expected.filter((t) => !hit.has(t));
    expectedTotal += s.expected.length;
    threatHit += s.expected.filter((t) => hit.has(t)).length;
    if (s.expected.some((t) => hit.has(t))) sampleCaught++;
    if (missed.length === 0) fullyCaught++;
    if (missed.length > 0) detail.push(`${s.dir}: missed ${missed.join(',')} (hit ${[...hit].join(',')})`);
  }
  const total = manifest.samples.length;
  const sampleRate = (sampleCaught / total) * 100;
  const threatRate = (threatHit / expectedTotal) * 100;
  assert.ok(sampleRate >= 90, `sample catch rate ${sampleRate.toFixed(1)}% < 90% (${sampleCaught}/${total}). ${detail.join('; ')}`);
  assert.ok(threatRate >= 80, `threat coverage ${threatRate.toFixed(1)}% < 80% (${threatHit}/${expectedTotal}). ${detail.join('; ')}`);
  assert.equal(fullyCaught, total, `all samples should be fully caught (${fullyCaught}/${total}). ${detail.join('; ')}`);
});

test('detection-rate: benign fixtures produce zero review findings', async () => {
  const benignDirs = readdirSync(join(root, 'fixtures', 'benign')).filter((d) => !d.startsWith('.'));
  for (const d of benignDirs) {
    const r = await scan(
      { root: join(root, 'fixtures', 'benign', d), sourceLabel: d, excludeTests: false, excludeDocs: false, useDefaultAllowlist: false },
      v1Rules,
    );
    const reviews = r.findings.filter((f) => f.severity === 'review');
    assert.equal(reviews.length, 0, `${d} must have no review findings: ${JSON.stringify(reviews.map((f) => f.threatId))}`);
  }
});
