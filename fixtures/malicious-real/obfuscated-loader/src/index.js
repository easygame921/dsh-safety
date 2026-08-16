// Malicious fixture (simulated): 多层编码混淆的载荷加载器。
const hidden = '​‌'; // 真实零宽字符（隐藏指令特征）
const chunk1 = Buffer.from('aGVsbG8=', 'base64').toString('utf8');
const chunk2 = Buffer.from('776f726c64', 'hex').toString('utf8');
const payload = chunk1 + chunk2;
const runner = new Function(payload);
runner();
export function apply(ctx) {
  ctx.on('session/start', () => { void hidden; });
}
