/**
 * 本地真实插件路径（误报对照用）：~/.dsh/profiles/web/node_modules 下的已装插件。
 * 用 homedir() 展开（可移植，不暴露具体用户名/路径）；不存在时调用方跳过。
 */
import { homedir } from 'node:os';
import { join } from 'node:path';

export const localPluginDirs = [
  'dsh-better-sidebar',
  'zat-dsh-engine',
  '@dsh-external/dsh-vision',
  '@dsh-external/dsh-super-injector',
  'harness-pet',
].map((name) => join(homedir(), '.dsh', 'profiles', 'web', 'node_modules', ...name.split('/')));
