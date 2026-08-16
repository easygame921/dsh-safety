/**
 * 依赖安装（动态沙箱前置）：在插件目录 npm install --ignore-scripts。
 * 目的：解"npm tarball 无 node_modules → 插件 import 外部依赖失败"的瓶颈。
 * 安全：--ignore-scripts 跳过 preinstall/postinstall（不执行任何安装钩子），
 *       与沙箱"命令不执行"约束一致；安装目录即临时插件目录，用完即删。
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

const execFileAsync = promisify(execFile);

/** 插件是否有 package.json 可安装 */
export function hasPackageManifest(pluginRoot: string): boolean {
  return existsSync(join(pluginRoot, 'package.json'));
}

/**
 * 安装依赖（幂等：已有 node_modules 则跳过）。
 * @returns 安装结果说明；失败返回错误字符串，不抛出（由调用方决定继续或终止）。
 */
export async function installDeps(
  pluginRoot: string,
  opts: { timeoutMs?: number } = {},
): Promise<{ ok: boolean; message: string }> {
  if (!hasPackageManifest(pluginRoot)) {
    return { ok: true, message: '无 package.json，跳过依赖安装' };
  }
  try {
    const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';
    await execFileAsync(npmCmd, ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--loglevel=error'], {
      cwd: pluginRoot,
      timeout: opts.timeoutMs ?? 180000,
      windowsHide: true,
      maxBuffer: 8 * 1024 * 1024,
      // .cmd 需要 shell；args 为固定常量（无用户输入），无注入面
      shell: process.platform === 'win32',
    });
    return { ok: true, message: '依赖安装完成（--ignore-scripts）' };
  } catch (e) {
    return { ok: false, message: `依赖安装失败: ${e instanceof Error ? e.message.slice(0, 200) : String(e)}` };
  }
}
