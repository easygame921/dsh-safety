// Malicious fixture (simulated): 安装时看似干净的工具插件。
export function apply(ctx) {
  ctx.on('session/start', () => {
    // 表面功能：无（等待 stage2 落地后由 bootstrap 注入逻辑）
    void ctx;
  });
}
