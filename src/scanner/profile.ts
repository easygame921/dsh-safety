/**
 * 权限画像：从文件内容特征推断插件的能力面。
 */
import type { PermissionProfile } from '../types.js';
import type { ScannedFile } from './files.js';

const LOCAL_HOSTS = /localhost|127\.0\.0\.1|::1|\.local$/i;

function extractHosts(content: string): string[] {
  const hosts = new Set<string>();
  const re = /https?:\/\/([A-Za-z0-9.-]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    const host = m[1];
    if (host && !LOCAL_HOSTS.test(host)) hosts.add(host.toLowerCase());
  }
  // 双引号/单引号里的 host 形式（fetch('//host/x') 等）
  const re2 = /['"](?:https?:)?\/\/?([A-Za-z0-9.-]+)['"]/g;
  while ((m = re2.exec(content)) !== null) {
    const host = m[1];
    if (host && !LOCAL_HOSTS.test(host)) hosts.add(host.toLowerCase());
  }
  return [...hosts].sort();
}

function extractEnvVars(content: string): string[] {
  const vars = new Set<string>();
  const re = /process\.env\.([A-Z0-9_]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) if (m[1]) vars.add(m[1]);
  // 也抓 getenv 形式
  const re2 = /(?:getenv|env)\s*\(\s*['"]([A-Z0-9_]+)['"]/g;
  while ((m = re2.exec(content)) !== null) if (m[1]) vars.add(m[1]);
  return [...vars].sort();
}

const CRED_PATH_RE = /\.credentials\.yaml|\.ssh|\.npmrc|\.codex|id_rsa|id_ed25519|\.aws\/credentials|\.env\b|\.kube|\.netrc|keychain/i;

export function buildProfile(files: ScannedFile[], _findings: never[]): PermissionProfile {
  const all = files.map((f) => f.content).join('\n');
  const injectedServices = [...new Set([...all.matchAll(/ctx\.([A-Za-z0-9_]+)/g)].map((m) => m[1]).filter((v): v is string => v !== undefined))]
    .filter((v) => !['on', 'logger', 'tool', 'error', 'once', 'off', 'emit', 'get', 'set', 'config', 'deploy'].includes(v))
    .sort();
  const profile: PermissionProfile = {
    filesystemRead: /fs\.(readFile|open|readFileSync|createReadStream)|\breadFile(Sync)?\s*\(|\bcreateReadStream\s*\(|node:fs/.test(all),
    filesystemWrite: /fs\.(writeFile|appendFile|mkdir|rm|unlink|rename|writeFileSync|createWriteStream|copyFile)|\bwriteFile(Sync)?\s*\(|\bappendFile(Sync)?\s*\(|\bcreateWriteStream\s*\(/.test(all),
    childProcesses: /child_process|spawn\(|exec\(|execFile|execSync|spawnSync|\.exec\(/i.test(all),
    network: /fetch\s*\(|https?\.(get|request)|WebSocket|axios|got\(|request\(|node:net|net\.connect|dns\.resolve/i.test(all),
    outboundHosts: extractHosts(all),
    envVariables: extractEnvVars(all),
    credentialLookingEnv: extractEnvVars(all).filter((v) => /TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL/i.test(v)),
    credentialPaths: files.filter((f) => CRED_PATH_RE.test(f.content)).map((f) => f.relPath),
    dynamicCodeExecution: /eval\s*\(|new Function|Function\s*\(|import\s*\(\s*['"`]|child_process.*-e\b/i.test(all),
    injectedServices,
    declaredDependencies: [],
    bundlePatch: files.some((f) => /cordis\.patch\.ya?ml|\.dsh-plugin\b/.test(f.relPath) || /patch.*(yml|yaml)/i.test(f.relPath)),
    installScripts: [],
  };
  // declaredDependencies / installScripts 从 package.json 提取
  for (const f of files) {
    if (!f.relPath.endsWith('package.json')) continue;
    try {
      const pkg = JSON.parse(f.content) as { dependencies?: Record<string, string>; scripts?: Record<string, string> };
      if (pkg.dependencies) profile.declaredDependencies = Object.keys(pkg.dependencies);
      if (pkg.scripts) profile.installScripts = Object.entries(pkg.scripts)
        .filter(([n]) => n === 'preinstall' || n === 'postinstall' || n === 'prepare')
        .map(([n, c]) => `${n}: ${c}`);
    } catch {
      // 忽略
    }
  }
  return profile;
}
