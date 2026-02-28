// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { AxiosInstance } from 'axios';
import { GetIpReportArgsSchema, GetIpRelationshipArgsSchema } from './schemas/index.js';
import { handleGetIpReport, handleGetIpRelationship } from './handlers/ip.js';
import { checkTokenLimit } from './utils/token-limiter.js';

/**
 * Register all IP address analysis tools on the MCP server.
 */
export async function registerIpTools(server: McpServer, client: AxiosInstance, maxTokenCall = 20000): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const registerTool = (server as any).tool.bind(server) as (
    name: string,
    description: string,
    shape: unknown,
    cb: (args: unknown) => unknown
  ) => void;

  registerTool(
    'get_ip_report',
    'Get a comprehensive IP address analysis report including geolocation, reputation data, ' +
      'and key relationships (communicating files, historical certificates/WHOIS, resolutions). ' +
      'Returns both the basic analysis and automatically fetched relationship data.',
    GetIpReportArgsSchema.shape,
    async (args: unknown) => {
      const parsed = GetIpReportArgsSchema.safeParse(args);
      const breakTokenRule = parsed.success ? (parsed.data.break_token_rule ?? false) : false;
      const result = await handleGetIpReport(client, args);
      const tokenCheck = checkTokenLimit(result, maxTokenCall, breakTokenRule);
      if (!tokenCheck.allowed) {
        return { content: [{ type: 'text', text: tokenCheck.error ?? 'Token limit exceeded' }], isError: true };
      }
      return result;
    }
  );

  registerTool(
    'get_ip_relationship',
    'Query a specific relationship type for an IP address with pagination support. ' +
      'Choose from 12 relationship types including communicating files, historical SSL certificates, ' +
      'WHOIS records, resolutions, and threat actors. ' +
      'Useful for detailed investigation of specific relationship types.',
    GetIpRelationshipArgsSchema.shape,
    (args: unknown) => handleGetIpRelationship(client, args)
  );
}
