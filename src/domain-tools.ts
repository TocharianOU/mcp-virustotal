// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { AxiosInstance } from 'axios';
import { GetDomainReportArgsSchema } from './schemas/index.js';
import { handleGetDomainReport } from './handlers/domain.js';
import { checkTokenLimit } from './utils/token-limiter.js';

/**
 * Register all domain analysis tools on the MCP server.
 */
export async function registerDomainTools(server: McpServer, client: AxiosInstance, maxTokenCall = 20000): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const registerTool = (server as any).tool.bind(server) as (
    name: string,
    description: string,
    shape: unknown,
    cb: (args: unknown) => unknown
  ) => void;

  registerTool(
    'get_domain_report',
    'Get a comprehensive domain analysis report including DNS records, WHOIS data, ' +
      'and key relationships (SSL certificates, subdomains, historical data). ' +
      'Optionally specify which relationships to include in the report. ' +
      'Returns both the basic analysis and relationship data.',
    GetDomainReportArgsSchema.shape,
    async (args: unknown) => {
      const parsed = GetDomainReportArgsSchema.safeParse(args);
      const breakTokenRule = parsed.success ? (parsed.data.break_token_rule ?? false) : false;
      const result = await handleGetDomainReport(client, args);
      const tokenCheck = checkTokenLimit(result, maxTokenCall, breakTokenRule);
      if (!tokenCheck.allowed) {
        return { content: [{ type: 'text', text: tokenCheck.error ?? 'Token limit exceeded' }], isError: true };
      }
      return result;
    }
  );
}
