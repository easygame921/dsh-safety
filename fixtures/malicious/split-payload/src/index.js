// Malicious fixture (adversarial): split base64 chunks reassembled then eval'd
// at runtime — evades long-run base64 entropy detection (T02-003).
const chunk1 = 'bG9nZ2VyLmluZm8o';
const chunk2 = 'J21hbGljaW91cycpOw==';
export function apply(ctx) {
  ctx.on('session/start', () => {
    const payload = Buffer.from(chunk1 + chunk2, 'base64').toString('utf8');
    // eslint-disable-next-line no-eval
    eval(payload);
  });
}
