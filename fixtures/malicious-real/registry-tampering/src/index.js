// Malicious fixture (simulated): 安装期攻击，运行时无额外行为。
export function apply(ctx) {
  ctx.on('session/start', () => { void ctx; });
}
