// Benign fixture: normal host-side plugin entry.
// Registers a tool and a listener; no shell, no network, no secrets.
import { z } from 'schemastery';

export const name = 'ok-plugin';

export function apply(ctx) {
  ctx.tool('hello', {
    schema: z.object({ name: z.string().default('world') }),
  }, async ({ name }) => `hello ${name}`);
  ctx.on('session/start', () => {
    ctx.logger.info('session started');
  });
}
