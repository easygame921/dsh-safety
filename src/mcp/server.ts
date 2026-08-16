/**
 * MCP 服务器：注册 audit_plugin / audit_url / list_rules / get_rule 四个工具。
 * audit_plugin / audit_url 支持 dynamic 选项（动态沙箱并入，输出静态+动态合并报告）。
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AuditReport } from '../types.js';
import { scan, renderMarkdown, renderPlainSummary } from '../scanner/index.js';
import { v1Rules } from '../rules/index.js';
import { prepareSource } from '../resolve/source.js';
import { runDynamic, renderDynamicSummary } from '../dynamic/index.js';
import type { DynamicReport } from '../dynamic/index.js';
import { crossValidate, renderCrossValidation } from '../cross/index.js';

export function createServer(): McpServer {
  const server = new McpServer({
    name: 'dsh-safety',
    version: '0.1.0',
  });

  interface AuditResult {
    report: AuditReport;
    dynamic?: DynamicReport;
  }

  interface AuditOptions {
    ruleIds?: string[];
    dynamic?: boolean;
    /** 风险为 review 时自动附带动态沙箱（避免每次等待依赖安装，REVIEW 场景动态佐证） */
    dynamicOnReview?: boolean;
  }

  async function doAudit(source: string, opts: AuditOptions = {}): Promise<AuditResult> {
    const { root, workDir, cleanup } = await prepareSource(source);
    try {
      const rules = opts.ruleIds && opts.ruleIds.length > 0
        ? v1Rules.filter((r) => opts.ruleIds!.includes(r.id))
        : v1Rules;
      const report = await scan({ root, sourceLabel: source }, rules);
      const wantDynamic = opts.dynamic === true || (opts.dynamicOnReview === true && report.risk === 'review');
      const dynamicReport = wantDynamic ? await runDynamic(root, { timeoutMs: 25000 }) : undefined;
      return { report, dynamic: dynamicReport };
    } finally {
      await cleanup();
    }
  }

  /** 输出 = 完整报告 + 交叉验证（有动态时）+ 动态轨迹 + 大白话总结 */
  function auditContent(result: AuditResult): { type: 'text'; text: string }[] {
    const blocks = [
      { type: 'text' as const, text: renderMarkdown(result.report) },
    ];
    if (result.dynamic) {
      const cv = crossValidate(result.report, result.dynamic);
      blocks.push({ type: 'text' as const, text: renderCrossValidation(cv) });
      blocks.push({ type: 'text' as const, text: renderDynamicSummary(result.dynamic) });
    }
    blocks.push({ type: 'text' as const, text: renderPlainSummary(result.report) });
    return blocks;
  }

  server.registerTool(
    'audit_plugin',
    {
      description: '审计一个 DSH 插件来源（npm 包名 / github:owner/repo / 本地目录路径），返回完整报告 + 大白话总结；dynamic=true 强制动态，dynamicOnReview=true 在风险为 review 时自动动态。',
      inputSchema: {
        source: z.string().describe('npm 包名、github:owner/repo 或本地绝对路径'),
        ruleIds: z.array(z.string()).optional().describe('可选：只跑指定规则 id'),
        dynamic: z.boolean().optional().describe('可选：true 时在受限沙箱中试运行插件 host 端，输出动态行为轨迹'),
        dynamicOnReview: z.boolean().optional().describe('可选：true 时仅在静态风险为 review 时自动附加动态沙箱'),
      },
    },
    async ({ source, ruleIds, dynamic, dynamicOnReview }) => ({
      content: auditContent(await doAudit(source, { ruleIds, dynamic, dynamicOnReview })),
    }),
  );

  server.registerTool(
    'audit_url',
    {
      description: '从插件 URL（GitHub 仓库页 / npm 包页）审计 DSH 插件，返回 Markdown 安全报告；dynamic=true 强制动态，dynamicOnReview=true 在 review 时自动动态。',
      inputSchema: {
        url: z.string().describe('GitHub 仓库 URL 或 npm 包页 URL'),
        ruleIds: z.array(z.string()).optional(),
        dynamic: z.boolean().optional(),
        dynamicOnReview: z.boolean().optional(),
      },
    },
    async ({ url, ruleIds, dynamic, dynamicOnReview }) => {
      let source: string;
      const gh = url.match(/github\.com\/([^/]+\/[^/]+)/);
      if (gh && gh[1]) {
        source = 'github:' + gh[1].replace(/\.git$/, '');
      } else {
        const npm = url.match(/npmjs\.com\/package\/(.+)/);
        source = npm && npm[1] ? 'npm:' + npm[1] : url;
      }
      return { content: auditContent(await doAudit(source, { ruleIds, dynamic, dynamicOnReview })) };
    },
  );

  server.registerTool(
    'list_rules',
    {
      description: '列出规则库 v1 的全部规则（id / 威胁编号 / 严重度 / 标题）。',
      inputSchema: {},
    },
    async () => ({
      content: [{
        type: 'text',
        text: v1Rules.map((r) => `${r.id}\t${r.threatId}\t${r.severity}\t${r.title}`).join('\n'),
      }],
    }),
  );

  server.registerTool(
    'get_rule',
    {
      description: '查看单条规则的完整定义（含正则与误报控制）。',
      inputSchema: {
        ruleId: z.string().describe('规则 id，如 T01-001'),
      },
    },
    async ({ ruleId }) => {
      const rule = v1Rules.find((r) => r.id === ruleId);
      if (!rule) return { content: [{ type: 'text', text: `未找到规则 ${ruleId}` }], isError: true };
      return { content: [{ type: 'text', text: JSON.stringify(rule, null, 2) }] };
    },
  );

  return server;
}
