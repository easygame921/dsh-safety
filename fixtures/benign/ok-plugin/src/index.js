// Benign fixture: normal host-side plugin entry.
// Registers a tool and a listener; no shell, no network, no secrets.
// (纯 JS，零外部依赖——沙箱内可直接加载)
export const name = 'ok-plugin';

export function apply(ctx) {
  ctx.tool('hello');
  ctx.on('session/start', () => {
    ctx.logger.info('session started');
  });
}
