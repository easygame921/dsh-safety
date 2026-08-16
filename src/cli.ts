/**
 * CLI 入口：dsh-safety audit <source> | serve | --version | --help
 */
import { scan, renderMarkdown } from './scanner/index.js';
import { v1Rules } from './rules/index.js';
import { prepareSource } from './resolve/source.js';
import { createServer } from './mcp/server.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

const VERSION = '0.1.0';

function help(): string {
  return [
    'dsh-safety — DSH 插件安全审计',
    '',
    '用法:',
    '  dsh-safety audit <source>    审计插件（npm 包名 / github:owner/repo / 本地路径）',
    '  dsh-safety serve             以 MCP stdio 服务器模式运行',
    '  dsh-safety --version         输出版本',
    '  dsh-safety --help            显示帮助',
  ].join('\n');
}

async function cmdAudit(source: string): Promise<number> {
  const { root, workDir, cleanup } = await prepareSource(source);
  try {
    const report = await scan({ root, sourceLabel: source }, v1Rules);
    process.stdout.write(renderMarkdown(report) + '\n');
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
      process.exitCode = await cmdAudit(source);
    } catch (err) {
      process.stderr.write(`审计失败: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 1;
    }
    return;
  }
  process.stderr.write(`未知命令: ${argv[0]}\n`);
  process.exitCode = 2;
}

void main();
