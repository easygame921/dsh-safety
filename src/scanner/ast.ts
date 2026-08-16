/**
 * 轻量 AST 增强（acorn）：在正则匹配之外做语义检查，针对对抗性绕过。
 * 1) eval-source：eval(变量) 且变量初始化来自 base64 解码（Buffer.from/atob/fromCharCode）——
 *    精确抓"分片/间接载荷"，避免同文件恰好有 Buffer 的误报。
 * 2) folded-sensitive-path：变量拼接/模板字面量折叠后含敏感路径（对抗拼接绕过——
 *    敏感词被拆成字面量分片，正则看不到完整串）。
 */
import { parse } from 'acorn';
import type { AstCheckId, Evidence } from '../types.js';

export interface AstResult {
  folded: string;
  evalSources: string[];
}

const SENSITIVE_PATH_RE = /\.credentials\.ya?ml|id_rsa|id_ed25519|\.ssh|\.npmrc|\.codex|auth\.json|\.env|credential/i;

type Node = Record<string, unknown>;

/** 解析 JS 源码为 AST；失败返回 null（调用方回退正则路径） */
function parseAst(content: string): ReturnType<typeof parse> | null {
  for (const sourceType of ['module', 'script'] as const) {
    try {
      return parse(content, { ecmaVersion: 'latest', sourceType, locations: true });
    } catch {
      // 继续尝试
    }
  }
  return null;
}

/** 递归遍历（白名单键集，避免遍历 acorn 内部环） */
const CHILD_KEYS = ['body', 'declarations', 'consequent', 'alternate', 'arguments', 'expression', 'init', 'callee', 'left', 'right', 'elements', 'properties', 'value', 'object', 'property', 'argument', 'quasis', 'expressions', 'declaration'];
function walk(node: unknown, visit: (n: Node) => void): void {
  if (node === null || typeof node !== 'object') return;
  visit(node as Node);
  const n = node as Node;
  for (const key of CHILD_KEYS) {
    const child = n[key];
    if (Array.isArray(child)) for (const c of child) walk(c, visit);
    else if (child && typeof child === 'object') walk(child, visit);
  }
}

/** 把表达式折叠为字符串字面量；不可折叠返回 undefined */
function literalString(node: Node | undefined, bindings: Map<string, string>): string | undefined {
  if (!node) return undefined;
  switch (node.type) {
    case 'Literal': {
      const v = node.value as string | number | boolean | null;
      return typeof v === 'string' ? v : undefined;
    }
    case 'TemplateLiteral': {
      // 仅当无插值时折叠（有 ${} 交给二元/标识符路径处理可折叠部分）
      const quasis = (node.quasis as Array<{ value?: { cooked?: string } }>) ?? [];
      const expressions = (node.expressions as Node[]) ?? [];
      if (expressions.length === 0) {
        return quasis.map((q) => q.value?.cooked ?? '').join('');
      }
      let out = '';
      for (let i = 0; i < quasis.length; i++) {
        out += quasis[i]?.value?.cooked ?? '';
        const expr = expressions[i];
        if (expr) {
          const v = literalString(expr, bindings);
          if (v === undefined) return undefined;
          out += v;
        }
      }
      return out;
    }
    case 'BinaryExpression': {
      if (node.operator !== '+') return undefined;
      const l = literalString(node.left as Node, bindings);
      const r = literalString(node.right as Node, bindings);
      return l !== undefined && r !== undefined ? l + r : undefined;
    }
    case 'Identifier': {
      return typeof node.name === 'string' ? bindings.get(node.name) : undefined;
    }
    default:
      return undefined;
  }
}

/** 是否为 base64 解码表达式（Buffer.from(...) / atob(...) / fromCharCode，支持 .toString() 链） */
function isDecodedExpr(node: Node | undefined): boolean {
  let cur: Node | undefined = node;
  while (cur) {
    if (cur.type === 'CallExpression') {
      const callee = cur.callee as Node | undefined;
      if (!callee) return false;
      if (callee.type === 'Identifier' && (callee.name === 'atob' || callee.name === 'fromCharCode')) return true;
      if (callee.type === 'MemberExpression') {
        const prop = callee.property as Node | undefined;
        const obj = callee.object as Node | undefined;
        if (prop?.name === 'from' && obj?.type === 'Identifier' && obj.name === 'Buffer') return true;
        // Buffer.from(...).toString(...) 链：沿 object 继续
        cur = obj;
        continue;
      }
      return false;
    }
    return false;
  }
  return false;
}

/** 收集绑定 + 解码变量集合 + 折叠后含敏感路径的变量/拼接表达式 */
function collectBindings(ast: ReturnType<typeof parse>): {
  bindings: Map<string, string>;
  decoded: Set<string>;
  sensitiveFolded: Map<string, string>;
  sensitiveExprs: string[];
} {
  const bindings = new Map<string, string>();
  const decoded = new Set<string>();
  const sensitiveFolded = new Map<string, string>();
  const sensitiveExprs: string[] = [];
  walk(ast, (n) => {
    if (n.type === 'VariableDeclaration') {
      for (const decl of (n.declarations as Array<Node>) ?? []) {
        const id = decl.id as Node | undefined;
        const init = decl.init as Node | undefined;
        if (!id || !init) continue;
        if (id.type !== 'Identifier' || typeof id.name !== 'string') continue;
        const value = literalString(init, bindings);
        if (value !== undefined) {
          bindings.set(id.name, value);
          if (SENSITIVE_PATH_RE.test(value)) sensitiveFolded.set(id.name, value);
        }
        if (isDecodedExpr(init)) decoded.add(id.name);
      }
      return;
    }
    // 拼接/模板表达式折叠后含敏感路径（敏感词被拆到多个字面量）
    if (n.type === 'BinaryExpression' && n.operator === '+') {
      const value = literalString(n, bindings);
      if (value !== undefined && SENSITIVE_PATH_RE.test(value) && !sensitiveExprs.includes(value)) {
        sensitiveExprs.push(value);
      }
    }
  });
  return { bindings, decoded, sensitiveFolded, sensitiveExprs };
}

/** 检查 eval/new Function 实参：直接解码表达式 或 变量（绑定值含敏感串 / 来自解码） */
function findEvalSources(ast: ReturnType<typeof parse>, bindings: Map<string, string>, decoded: Set<string>): string[] {
  const out: string[] = [];
  const visit = (n: Node) => {
    let arg: Node | undefined;
    let kind = '';
    if (n.type === 'CallExpression') {
      const callee = n.callee as Node | undefined;
      if (callee?.type !== 'Identifier' || callee.name !== 'eval') return;
      arg = (n.arguments as Array<Node>)?.[0];
      kind = 'eval';
    } else if (n.type === 'NewExpression' || (n.type === 'CallExpression' && (n.callee as Node | undefined)?.type === 'Identifier' && (n.callee as Node | undefined)?.name === 'Function')) {
      const callee = n.callee as Node | undefined;
      if (callee?.type !== 'Identifier' || callee.name !== 'Function') return;
      arg = (n.arguments as Array<Node>)?.[0];
      kind = 'new Function';
    } else {
      return;
    }
    if (!arg) return;
    if (arg.type === 'Identifier' && typeof arg.name === 'string') {
      if (decoded.has(arg.name)) out.push(`${kind}(${arg.name}) ← base64 解码载荷`);
      else if (bindings.has(arg.name)) out.push(`${kind}(${arg.name}) ← 变量间接执行`);
    } else if (isDecodedExpr(arg)) {
      out.push(`${kind}(解码表达式)`);
    }
  };
  walk(ast, visit);
  return out;
}

/** 折叠 path.join/resolve(...) 调用：收集全部可折叠实参（不可折叠的忽略），拼接测试敏感路径 */
function foldPathCall(node: Node | undefined, bindings: Map<string, string>): string | undefined {
  if (!node || node.type !== 'CallExpression') return undefined;
  const callee = node.callee as Node | undefined;
  const name =
    callee?.type === 'Identifier'
      ? callee.name
      : callee?.type === 'MemberExpression'
        ? (callee.property as Node | undefined)?.name
        : undefined;
  if (name !== 'join' && name !== 'resolve') return undefined;
  const args = (node.arguments as Array<Node>) ?? [];
  const parts: string[] = [];
  for (const a of args) {
    const v = literalString(a, bindings);
    if (v !== undefined) parts.push(v);
  }
  if (parts.length === 0) return undefined;
  return parts.join('/');
}

/**
 * 解析一个"可能含敏感路径"的表达式为字符串：
 * 字面量 → 变量回查 init → path.join/resolve 折叠（宽容：只拼可折叠片段）。
 */
function resolvePathExpr(
  node: Node | undefined,
  bindings: Map<string, string>,
  varInits: Map<string, Node>,
): string | undefined {
  if (!node) return undefined;
  const direct = literalString(node, bindings);
  if (direct !== undefined) return direct;
  if (node.type === 'Identifier' && typeof node.name === 'string') {
    const init = varInits.get(node.name);
    if (init) return resolvePathExpr(init, bindings, varInits);
  }
  if (node.type === 'CallExpression') return foldPathCall(node, bindings);
  return undefined;
}

/**
 * 数据流外传检查（对抗"readFile → 变量 → fetch"的多行拆分）：
 * 1) 收集赋值自"敏感路径读取"的变量（readFileSync(敏感路径)/execSync 取输出等）；
 * 2) 若该变量出现在 fetch 的实参（body 等）中 → 敏感数据流入网络，构成外传证据。
 */
function findExfilFlows(ast: ReturnType<typeof parse>, bindings: Map<string, string>): string[] {
  const varInits = new Map<string, Node>();
  walk(ast, (n) => {
    if (n.type !== 'VariableDeclaration') return;
    for (const decl of (n.declarations as Array<Node>) ?? []) {
      const id = decl.id as Node | undefined;
      if (id?.type === 'Identifier' && typeof id.name === 'string' && decl.init) {
        varInits.set(id.name, decl.init as Node);
      }
    }
  });
  const sensitiveReadVars = new Set<string>();
  walk(ast, (n) => {
    if (n.type !== 'VariableDeclaration') return;
    for (const decl of (n.declarations as Array<Node>) ?? []) {
      const id = decl.id as Node | undefined;
      const init = decl.init as Node | undefined;
      if (id?.type !== 'Identifier' || typeof id.name !== 'string' || !init) continue;
      if (init.type !== 'CallExpression') continue;
      const callee = init.callee as Node | undefined;
      const name: string | undefined =
        callee?.type === 'Identifier'
          ? String(callee.name ?? '')
          : callee?.type === 'MemberExpression'
            ? String((callee.property as Node | undefined)?.name ?? '')
            : undefined;
      if (!name) continue;
      const readLike = ['readFileSync', 'readFile', 'readdirSync', 'execFileSync', 'execSync', 'spawnSync', 'spawn'].includes(name);
      if (!readLike) continue;
      const arg0 = (init.arguments as Array<Node>)?.[0];
      const folded = resolvePathExpr(arg0, bindings, varInits);
      if (folded && SENSITIVE_PATH_RE.test(folded)) sensitiveReadVars.add(id.name);
    }
  });
  if (sensitiveReadVars.size === 0) return [];
  const out: string[] = [];
  walk(ast, (n) => {
    if (n.type !== 'CallExpression') return;
    const callee = n.callee as Node | undefined;
    if (callee?.type !== 'Identifier' || callee.name !== 'fetch') return;
    const args = (n.arguments as Array<Node>) ?? [];
    const usedNames = new Set<string>();
    for (const a of args) {
      if (a.type === 'Identifier' && typeof a.name === 'string') usedNames.add(a.name);
      if (a.type === 'ObjectExpression') {
        for (const p of (a.properties as Array<Node>) ?? []) {
          const v = (p as { value?: Node }).value;
          const vname = v?.type === 'Identifier' ? String(v.name ?? '') : '';
          if (vname) usedNames.add(vname);
        }
      }
    }
    for (const v of sensitiveReadVars) {
      if (usedNames.has(v)) out.push(`readFile(敏感路径) → ${v} → fetch 外传`);
    }
  });
  return out;
}

/**
 * 对文件执行 AST 级检查。
 * @returns 命中的证据（pattern 说明检查类型）
 */
export function runAstChecks(content: string, file: string, checks: AstCheckId[]): Evidence[] {
  const ast = parseAst(content);
  if (!ast) return [];
  const { bindings, decoded, sensitiveFolded, sensitiveExprs } = collectBindings(ast);
  const out: Evidence[] = [];

  if (checks.includes('eval-source')) {
    for (const s of findEvalSources(ast, bindings, decoded)) {
      out.push({ file, line: 0, pattern: 'ast:eval-source', snippet: s });
    }
  }
  if (checks.includes('folded-sensitive-path')) {
    const hasRead = /readFile|readFileSync|execFile|execSync|spawn|exec\s*\(/.test(content);
    // 变量折叠后为敏感路径且被读取调用引用
    for (const [name, value] of sensitiveFolded) {
      if (new RegExp(`readFile|readFileSync|execFile|execSync|spawn|exec\\s*\\([^\\n]{0,80}\\b${name}\\b`).test(content)) {
        out.push({
          file,
          line: 0,
          pattern: 'ast:folded-sensitive-path',
          snippet: `${name} = ${value}（敏感路径由变量拼接，被读取调用引用）`,
        });
      }
    }
    // 拼接表达式折叠后为敏感路径（敏感词拆片）且文件存在读取调用
    if (sensitiveExprs.length > 0 && hasRead) {
      for (const value of sensitiveExprs) {
        out.push({
          file,
          line: 0,
          pattern: 'ast:folded-sensitive-path',
          snippet: `拼接表达式折叠后为敏感路径：${value}（敏感词被拆片，与读取调用共存）`,
        });
      }
    }
  }
  if (checks.includes('exfil-flow')) {
    for (const s of findExfilFlows(ast, bindings)) {
      out.push({ file, line: 0, pattern: 'ast:exfil-flow', snippet: s });
    }
  }
  return out;
}
