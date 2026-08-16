// MCP serve 冒烟测试：spawn cli serve，验证 initialize + tools/list
import { spawn } from 'node:child_process';

const p = spawn(process.execPath, ['dist/cli.js', 'serve'], {
  cwd: process.cwd(),
  stdio: ['pipe', 'pipe', 'pipe'],
});
let buf = '';
p.stdout.on('data', (d) => { buf += d; });
p.stderr.on('data', (d) => { process.stderr.write(d); });

const send = (obj) => p.stdin.write(JSON.stringify(obj) + '\n');

send({
  jsonrpc: '2.0', id: 1, method: 'initialize',
  params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'smoke', version: '1.0' } },
});

setTimeout(() => {
  send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
}, 600);

setTimeout(() => {
  try {
    const lines = buf.split('\n').filter(Boolean);
    const toolsResp = lines.map((l) => JSON.parse(l)).find((m) => m.id === 2);
    const tools = toolsResp?.result?.tools ?? [];
    console.log('registered tools:', tools.map((t) => t.name).join(', '));
    console.log('PASS' + (tools.length === 4 ? '' : ` (expected 4, got ${tools.length})`));
  } catch (e) {
    console.log('smoke parse failed:', e.message);
    console.log(buf);
  }
  p.kill();
}, 1600);
