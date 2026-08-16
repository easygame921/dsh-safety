/**
 * 来源解析：把插件来源（npm / GitHub / 本地路径）解析为本地源码目录。
 * 安全契约：不安装依赖、不执行插件代码；下载物只落在 workDir。
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';

const execFileAsync = promisify(execFile);

export type SourceSpec = { kind: 'npm' | 'github' | 'local'; value: string };

const NPM_NAME_RE = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i;
const GITHUB_REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

export function parseSource(input: string): SourceSpec {
  const s = input.trim();
  if (s.startsWith('npm:')) return { kind: 'npm', value: s.slice(4) };
  if (s.startsWith('github:')) return { kind: 'github', value: s.slice(7) };
  if (s.startsWith('git@') || s.startsWith('https://github.com/') || s.startsWith('git+')) {
    return { kind: 'github', value: s };
  }
  if (NPM_NAME_RE.test(s)) return { kind: 'npm', value: s };
  if (GITHUB_REPO_RE.test(s)) return { kind: 'github', value: s };
  return { kind: 'local', value: s };
}

export function makeWorkDir(prefix = 'dsh-safety'): Promise<string> {
  return fs.mkdtemp(join(tmpdir(), `${prefix}-`));
}

async function run(cmd: string, args: string[], cwd: string, timeoutMs = 120000): Promise<void> {
  await execFileAsync(cmd, args, { cwd, timeout: timeoutMs, windowsHide: true, maxBuffer: 16 * 1024 * 1024 });
}

/** 找出解压/克隆结果中的"插件根目录"（npm 包常见 package/ 前缀单目录） */
async function findRoot(dir: string): Promise<string> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const dirs = entries.filter((e) => e.isDirectory()).map((e) => e.name);
  const first = dirs[0];
  if (first && first === 'package') {
    const sub = join(dir, first);
    // 仅当子目录含 package.json 或明显是包根时进入
    try {
      await fs.access(join(sub, 'package.json'));
      return sub;
    } catch {
      return dir;
    }
  }
  return dir;
}

export async function resolveSource(spec: SourceSpec, workDir: string): Promise<string> {
  if (spec.kind === 'local') {
    let st;
    try {
      st = await fs.stat(spec.value);
    } catch {
      throw new Error(`本地插件路径不存在: ${spec.value}`);
    }
    if (!st.isDirectory()) throw new Error(`本地插件路径不是目录: ${spec.value}`);
    return spec.value;
  }

  if (spec.kind === 'npm') {
    // 安全直连 registry API：不 spawn npm（避免 shell/注入），下载 tarball 后 tar 解压
    const name = spec.value;
    const registryUrl = `https://registry.npmjs.org/${encodeURIComponent(name)}`;
    const metaRes = await fetch(registryUrl, { signal: AbortSignal.timeout(60000) });
    if (!metaRes.ok) throw new Error(`npm registry 查询失败: HTTP ${metaRes.status} (${name})`);
    const meta = await metaRes.json() as {
      'dist-tags'?: Record<string, string>;
      versions?: Record<string, { dist?: { tarball?: string } }>;
      dist?: { tarball?: string };
    };
    const latestTag = meta?.['dist-tags']?.latest;
    const tarballUrl = meta?.dist?.tarball
      ?? (latestTag && meta?.versions?.[latestTag]?.dist?.tarball)
      ?? (meta?.versions && Object.values(meta.versions)[0]?.dist?.tarball);
    if (typeof tarballUrl !== 'string') throw new Error(`npm 包无 tarball: ${name}`);
    const tgzRes = await fetch(tarballUrl, { signal: AbortSignal.timeout(120000) });
    if (!tgzRes.ok) throw new Error(`tarball 下载失败: HTTP ${tgzRes.status}`);
    const tgzPath = join(workDir, 'pkg.tgz');
    await fs.writeFile(tgzPath, Buffer.from(await tgzRes.arrayBuffer()));
    const target = join(workDir, 'npm-extract');
    await fs.mkdir(target, { recursive: true });
    await run('tar', ['-xzf', tgzPath, '-C', target], workDir);
    return findRoot(target);
  }

  // github
  const repoName = spec.value.split('/').pop()?.replace(/\.git$/, '') ?? 'repo';
  const target = join(workDir, repoName);
  const url = spec.value.startsWith('http') || spec.value.startsWith('git@')
    ? spec.value
    : `https://github.com/${spec.value}.git`;
  await run('git', ['clone', '--depth', '1', url, target], workDir);
  return target;
}

/** 一键：解析来源 → 建 workDir → 拉取 → 返回 { root, workDir, cleanup } */
export async function prepareSource(input: string): Promise<{ root: string; workDir: string; cleanup: () => Promise<void> }> {
  const spec = parseSource(input);
  const workDir = await makeWorkDir();
  const root = await resolveSource(spec, workDir);
  return {
    root,
    workDir,
    cleanup: async () => {
      try {
        await fs.rm(workDir, { recursive: true, force: true });
      } catch {
        // 忽略清理失败
      }
    },
  };
}

export { randomBytes };
