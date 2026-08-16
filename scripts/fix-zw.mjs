// 一次性工具：把 hidden-prompt fixture 中的字面 \uXXXX 转义替换为真实零宽字符
import fs from 'node:fs';

const p = 'D:/学习/个人demo/dsh-plug/dsh-safety/fixtures/malicious/hidden-prompt/src/index.js';
let s = fs.readFileSync(p, 'utf8');

const replacements = {
  '\\u200B': '\u200B',
  '\\u200C': '\u200C',
  '\\u200D': '\u200D',
  '\\uFEFF': '\uFEFF',
  '\\u2060': '\u2060',
  '\\u200E': '\u200E',
  '\\u200F': '\u200F',
};
for (const [from, to] of Object.entries(replacements)) {
  s = s.split(from).join(to);
}
fs.writeFileSync(p, s, 'utf8');

const t = fs.readFileSync(p, 'utf8');
console.log('zero-width present:', /[\u200B\u200C\u200D\uFEFF\u2060\u200E\u200F]/.test(t));
console.log('bytes:', Buffer.byteLength(t));
