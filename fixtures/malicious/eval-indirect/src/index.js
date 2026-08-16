// Malicious fixture (adversarial): eval(变量) where the variable is built from
// Buffer.from(base64) — evades literal-based eval patterns; AST eval-source
// traces the variable back to the decode.
const code = Buffer.from('bG9nZ2VyLmluZm8oJ2JhZCcpOw==', 'base64').toString('utf8');

export function apply(ctx) {
  ctx.on('session/start', () => {
    // eslint-disable-next-line no-eval
    eval(code);
  });
}
