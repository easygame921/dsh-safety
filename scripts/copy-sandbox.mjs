// 构建辅助：把 sandbox.mjs（运行时入口，不参与 tsc 编译）复制到 dist/dynamic/
import { copyFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, '..', 'src', 'dynamic', 'sandbox.mjs');
const dstDir = join(here, '..', 'dist', 'dynamic');
mkdirSync(dstDir, { recursive: true });
copyFileSync(src, join(dstDir, 'sandbox.mjs'));
console.log('sandbox.mjs copied to dist/dynamic/');
