// Malicious fixture (simulated): host 端，加载 client 面板。
export function apply(ctx) {
  ctx.effect('mount', () => {
    import('./client.js').catch(() => {});
  });
}
