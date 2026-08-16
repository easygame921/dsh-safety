/**
 * 容器沙箱 runner（可选后端）：docker run --network none + 只读挂载 + 资源限制。
 * 依赖 Docker daemon；daemon 不可用时返回 spawn-failed 并明确提示（不静默降级为本地沙箱，
 * 由调用方决定是否回退）。当前环境 daemon 不可用（docker-desktop WSL 启动失败），
 * 代码就绪待环境——见 docs/DYNAMIC-SANDBOX.md「容器化」。
 */
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { DynamicReport } from './runner.js';
import { riskSurfacesOf } from './runner.js';

const execFileAsync = promisify(execFile);
const IMAGE = 'dsh-safety-sandbox';

export interface DockerRunOptions {
  timeoutMs?: number;
  /** 是否允许自动构建镜像（默认 true） */
  buildImage?: boolean;
}

export async function dockerAvailable(): Promise<boolean> {
  try {
    await execFileAsync('docker', ['info', '--format', '{{.ServerVersion}}'], { timeout: 8000, windowsHide: true });
    return true;
  } catch {
    return false;
  }
}

export async function runDynamicDocker(
  pluginRoot: string,
  opts: DockerRunOptions = {},
): Promise<DynamicReport> {
  const started = Date.now();
  const timeoutMs = opts.timeoutMs ?? 25000;
  const sandboxWorkDir = await mkdtemp(join(tmpdir(), 'dsh-safety-dock-'));
  const base: DynamicReport = {
    plugin: pluginRoot,
    status: 'spawn-failed',
    durationMs: 0,
    traces: [],
    eventsTriggered: [],
    registeredTools: [],
    errors: [],
    riskSurfaces: [],
  };

  try {
    if (!(await dockerAvailable())) {
      return {
        ...base,
        status: 'spawn-failed',
        durationMs: Date.now() - started,
        errors: ['Docker daemon 不可用（容器沙箱需要 Docker Desktop/WSL 运行中）——请先启动 Docker 再试，或使用本地沙箱'],
      };
    }
    if (opts.buildImage !== false) {
      try {
        await execFileAsync('docker', ['build', '-t', IMAGE, '.'], {
          cwd: join(import.meta.dirname, '..', '..'),
          timeout: 180000,
          windowsHide: true,
        });
      } catch (e) {
        return { ...base, status: 'spawn-failed', errors: [`镜像构建失败: ${e instanceof Error ? e.message.slice(0, 200) : String(e)}`] };
      }
    }

    const pluginAbs = await realpath(pluginRoot);
    const workAbs = await realpath(sandboxWorkDir);
    const args = [
      'run', '--rm',
      '--network', 'none',
      '-v', `${pluginAbs}:/sandbox/plugin:ro`,
      '-v', `${workAbs}:/sandbox/work`,
      '-m', '512m', '--memory-swap', '512m', '--cpus', '1',
      '--read-only',
      IMAGE,
    ];
    const child = spawn('docker', args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });

    const result = await new Promise<DynamicReport>((resolve) => {
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        resolve({ ...base, status: 'timed-out', durationMs: Date.now() - started, errors: ['容器沙箱超时，已强杀'] });
      }, timeoutMs);
      child.on('error', (e) => {
        clearTimeout(timer);
        resolve({ ...base, status: 'spawn-failed', errors: [e.message] });
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        const durationMs = Date.now() - started;
        const lines = stdout.trim().split('\n');
        const last = lines[lines.length - 1] ?? '';
        let parsed: Record<string, unknown> | null = null;
        if (last.startsWith('{')) {
          try { parsed = JSON.parse(last); } catch { /* crashed */ }
        }
        if (parsed) {
          const traces = (parsed.traces as DynamicReport['traces']) ?? [];
          const events = traces.filter((t) => t.type === 'event').map((t) => String(t.event ?? ''));
          const loaded = traces.find((t) => t.type === 'load');
          resolve({
            ...base,
            status: (parsed.status as DynamicReport['status']) ?? 'completed',
            durationMs,
            entry: loaded ? String(loaded.entry ?? '') : undefined,
            traces,
            eventsTriggered: events,
            registeredTools: (parsed.registeredTools as string[]) ?? [],
            errors: [...((parsed.errors as string[]) ?? []), ...(parsed.applyError ? [String(parsed.applyError)] : [])],
            riskSurfaces: riskSurfacesOf(traces),
            note: code !== 0 ? `容器退出码 ${code}；stderr: ${stderr.slice(0, 200)}` : undefined,
          });
        } else {
          resolve({ ...base, status: 'crashed', durationMs, errors: [stderr.slice(0, 400) || `容器退出码 ${code}`] });
        }
      });
    });

    await rm(sandboxWorkDir, { recursive: true, force: true }).catch(() => {});
    return result;
  } catch (e) {
    await rm(sandboxWorkDir, { recursive: true, force: true }).catch(() => {});
    return { ...base, status: 'spawn-failed', errors: [e instanceof Error ? e.message : String(e)] };
  }
}
