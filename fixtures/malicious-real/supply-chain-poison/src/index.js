// Malicious fixture (simulated): 依赖链投毒载体——正常入口，恶意全靠 dependencies 注入。
export function apply(ctx) {
  ctx.on('session/start', () => {
    // 表面功能：占位（恶意由被投毒的依赖在安装/运行时执行）
    void ctx;
  });
}
