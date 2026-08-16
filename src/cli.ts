/**
 * CLI 入口：dsh-safety audit <source> | serve | --version | --help
 */
import { scan, renderMarkdown, renderPlainSummary } from './scanner/index.js';
import { v1Rules } from './rules/index.js';
import { prepareSource, parseSource } from './resolve/source.js';
import { createServer } from './mcp/server.js';
import { runDynamic, renderDynamicSummary } from './dynamic/index.js';
import { crossValidate, renderCrossValidation } from './cross/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

const VERSION = '0.1.0';

function help(): string {
  return [
    'dsh-safety — DSH 插件安全审计',
    '',
    '用法:',
    '  dsh-safety audit <source>               审计插件（npm 包名 / github:owner/repo / 本地路径）',
    '  dsh-safety audit <source> --dynamic     审计 + 动态沙箱 + 交叉验证',
    '  dsh-safety dynamic <source>             仅运行动态沙箱（输出轨迹）',
    '  dsh-safety serve                        以 MCP stdio 服务器模式运行',
    '  dsh-safety --version                    输出版本',
    '  dsh-safety --help                       显示帮助',
  ].join('\n');
}

async function cmdAudit(source: string, dynamic = false): Promise<number> {
  const { root, workDir, cleanup } = await prepareSource(source);
  try {
    const report = await scan({ root, sourceLabel: source }, v1Rules);
    process.stdout.write(renderMarkdown(report) + '\n');
    if (dynamic) {
      const spec = parseSource(source);
      const dyn = await runDynamic(root, { installDeps: spec.kind !== 'local' });
      const cv = crossValidate(report, dyn);
      process.stdout.write('\n---\n\n' + renderCrossValidation(cv) + '\n');
      process.stdout.write('\n---\n\n' + renderDynamicSummary(dyn) + '\n');
    }
    process.stdout.write('\n---\n\n' + renderPlainSummary(report) + '\n');
    return report.risk === 'ok' ? 0 : 1;
  } finally {
    await cleanup();
  }
}

async function cmdServe(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // 保持运行直到 stdin 关闭
  await new Promise<void>((resolve) => {
    process.stdin.on('end', () => resolve());
    process.stdin.resume();
  });
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') {
    process.stdout.write(help() + '\n');
    return;
  }
  if (argv[0] === '--version' || argv[0] === '-V') {
    process.stdout.write(VERSION + '\n');
    return;
  }
  if (argv[0] === 'serve') {
    await cmdServe();
    return;
  }
  if (argv[0] === 'audit') {
    const source = argv[1];
    if (!source) {
      process.stderr.write('缺少插件来源参数\n');
      process.exitCode = 2;
      return;
    }
    try {
      // audit <source> [--dynamic]：--dynamic 附带动态沙箱 + 交叉验证
      const wantDynamic = argv.includes('--dynamic');
      process.exitCode = await cmdAudit(source, wantDynamic);
    } catch (err) {
      process.stderr.write(`审计失败: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 1;
    }
    return;
  }
  if (argv[0] === 'dynamic') {
    const source = argv[1];
    if (!source) {
      process.stderr.write('缺少插件来源参数\n');
      process.exitCode = 2;
      return;
    }
    try {
      const { root, workDir, cleanup } = await prepareSource(source);
      try {
        // 远程来源（npm/github）才装依赖到临时目录；本地源码不装（避免污染用户插件目录）
        const spec = parseSource(source);
        const report = await runDynamic(root, { installDeps: spec.kind !== 'local' });
        process.stdout.write(renderDynamicSummary(report) + '\n');
        process.stdout.write('\n--- 原始轨迹 ---\n' + JSON.stringify(report.traces, null, 2) + '\n');
      } finally {
        await cleanup();
      }
    } catch (err) {
      process.stderr.write(`动态运行失败: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 1;
    }
    return;
  }
  process.stderr.write(`未知命令: ${argv[0]}\n`);
  process.exitCode = 2;
}

void main();
