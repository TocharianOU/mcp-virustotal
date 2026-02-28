// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { AxiosInstance } from 'axios';
import { GetFileReportArgsSchema, GetFileRelationshipArgsSchema } from './schemas/index.js';
import { handleGetFileReport, handleGetFileRelationship } from './handlers/file.js';
import { checkTokenLimit } from './utils/token-limiter.js';

/**
 * Register all file analysis tools on the MCP server.
 */
export async function registerFileTools(server: McpServer, client: AxiosInstance, maxTokenCall = 20000): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const registerTool = (server as any).tool.bind(server) as (
    name: string,
    description: string,
    shape: unknown,
    cb: (args: unknown) => unknown
  ) => void;

  registerTool(
    'get_file_report',
    'Get a comprehensive file analysis report using its hash (MD5/SHA-1/SHA-256). ' +
      'Includes detection results, file properties, and key relationships ' +
      '(behaviors, dropped files, network connections, embedded content, threat actors). ' +
      'Returns both the basic analysis and automatically fetched relationship data.',
    GetFileReportArgsSchema.shape,
    async (args: unknown) => {
      const parsed = GetFileReportArgsSchema.safeParse(args);
      const breakTokenRule = parsed.success ? (parsed.data.break_token_rule ?? false) : false;
      const result = await handleGetFileReport(client, args);
      const tokenCheck = checkTokenLimit(result, maxTokenCall, breakTokenRule);
      if (!tokenCheck.allowed) {
        return { content: [{ type: 'text', text: tokenCheck.error ?? 'Token limit exceeded' }], isError: true };
      }
      return result;
    }
  );

  registerTool(
    'get_file_relationship',
    'Query a specific relationship type for a file with pagination support. ' +
      'Choose from 41 relationship types including behaviors, network connections, dropped files, ' +
      'embedded content, execution chains, and threat actors. ' +
      'Useful for detailed investigation of specific relationship types.',
    GetFileRelationshipArgsSchema.shape,
    (args: unknown) => handleGetFileRelationship(client, args)
  );
}
