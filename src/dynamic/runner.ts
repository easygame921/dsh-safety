/**
 * 动态沙箱 runner：以受限子进程运行插件 host 端代码，收集行为轨迹。
 * 安全约束见 docs/DYNAMIC-SANDBOX.md；子进程用 Node permission model
 * （fs 白名单、禁网络/子进程/worker）+ sandbox.mjs 内补 eval/fetch/env 插桩。
 */
import { spawn } from 'node:child_process';
import { mkdtemp, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { installDeps } from './deps.js';

export interface DynamicTrace {
  type: 'network' | 'command' | 'fs-read' | 'fs-write' | 'eval' | 'env' | 'event' | 'load';
  [k: string]: unknown;
}

export interface DynamicReport {
  plugin: string;
  status: 'completed' | 'timed-out' | 'crashed' | 'load-failed' | 'spawn-failed';
  durationMs: number;
  entry?: string;
  traces: DynamicTrace[];
  eventsTriggered: string[];
  registeredTools: string[];
  errors: string[];
  /** 汇总的风险面 */
  riskSurfaces: string[];
  note?: string;
}

const here = dirname(fileURLToPath(import.meta.url));
/** 沙箱入口脚本（源文件，MVP 开发模式直接引用） */
const SANDBOX_MJS = join(here, '..', 'dynamic', 'sandbox.mjs');
const DEFAULT_TIMEOUT_MS = 20000;

export { riskSurfacesOf };

/** 敏感路径正则（风险面判定） */
const SENSITIVE_RE = /\.credentials\.ya?ml|id_rsa|id_ed25519|\.ssh|\.npmrc|\.codex|\.aws[/\\]credentials|\.netrc|(?<![\\w.])[.]env\b/i;

function riskSurfacesOf(traces: DynamicTrace[]): string[] {
  const surfaces = new Set<string>();
  const hasSensitiveRead = traces.some(
    (t) => t.type === 'fs-read' && typeof t.path === 'string' && SENSITIVE_RE.test(t.path),
  );
  const hasNetwork = traces.some((t) => t.type === 'network');
  const hasCommand = traces.some((t) => t.type === 'command');
  const hasEval = traces.some((t) => t.type === 'eval');
  if (hasSensitiveRead) surfaces.add('fs-read-sensitive');
  if (hasNetwork) surfaces.add('network');
  if (hasNetwork && (hasSensitiveRead || hasCommand)) surfaces.add('network-exfil-risk');
  if (hasCommand) surfaces.add('command');
  if (hasEval) surfaces.add('eval');
  return [...surfaces];
}

export async function runDynamic(
  pluginRoot: string,
  opts: { timeoutMs?: number; installDeps?: boolean } = {},
): Promise<DynamicReport> {
  const started = Date.now();
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const sandboxWorkDir = await mkdtemp(join(tmpdir(), 'dsh-safety-dyn-'));
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
  // 前置：装依赖（--ignore-scripts 安全），失败不阻断（无依赖插件也能跑）
  if (opts.installDeps !== false) {
    const inst = await installDeps(pluginRoot, { timeoutMs: timeoutMs + 60000 });
    if (!inst.ok) base.errors.push(inst.message);
  }

  try {
    const slash = (p: string) => p.replaceAll('\\', '/'); // Node 24 权限模型用正斜杠匹配
    const allowRoot = slash(await realpath(pluginRoot));
    const allowSandbox = slash(await realpath(sandboxWorkDir));
    // 每个允许路径一个独立 flag（逗号分隔不被 Node 支持）
    const args = [
      '--permission',
      `--allow-fs-read=${allowRoot}`,
      `--allow-fs-read=${allowSandbox}`,
      `--allow-fs-read=${slash(dirname(SANDBOX_MJS))}`,
      `--allow-fs-write=${allowSandbox}`,
      SANDBOX_MJS,
      allowRoot,
      allowSandbox,
    ];
    const child = spawn(process.execPath, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });

    const result = await new Promise<DynamicReport>((resolve) => {
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        resolve({ ...base, status: 'timed-out', durationMs: Date.now() - started, errors: ['沙箱超时，已强杀'] });
      }, timeoutMs);
      child.on('error', (e) => {
        clearTimeout(timer);
        resolve({ ...base, status: 'spawn-failed', durationMs: Date.now() - started, errors: [e.message] });
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        const durationMs = Date.now() - started;
        // stdout 最后一行是轨迹 JSON
        const lines = stdout.trim().split('\n');
        const last = lines[lines.length - 1] ?? '';
        let parsed: Record<string, unknown> | null = null;
        if (last.startsWith('{')) {
          try { parsed = JSON.parse(last); } catch { /* 解析失败走 crashed */ }
        }
        if (parsed) {
          const traces = (parsed.traces as DynamicTrace[]) ?? [];
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
            note: code !== 0 ? `子进程退出码 ${code}；stderr: ${stderr.slice(0, 200)}` : undefined,
          });
        } else {
          resolve({
            ...base,
            status: 'crashed',
            durationMs,
            errors: [stderr.slice(0, 400) || `非零退出码 ${code}`],
          });
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
