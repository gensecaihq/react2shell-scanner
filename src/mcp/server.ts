#!/usr/bin/env node

/**
 * MCP (Model Context Protocol) Server for react2shell-guard
 * Allows AI assistants to scan for CVE-2025-55182 vulnerabilities
 */

import { createInterface } from 'node:readline';
import { scan, scanSbom } from '../core/scanner.js';

// MCP Protocol Types
interface MCPRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: Record<string, unknown>;
}

interface MCPResponse {
  jsonrpc: '2.0';
  id: string | number;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

interface MCPToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
}

// Server info
const SERVER_INFO = {
  name: 'react2shell-guard',
  version: '1.0.4',
  description: 'Security scanner for CVE-2025-55182 - React Server Components RCE vulnerability',
};

// Available tools
const TOOLS: MCPToolDefinition[] = [
  {
    name: 'scan_repo',
    description: 'Scan a repository or directory for CVE-2025-55182 vulnerabilities in React Server Components',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Path to the repository or directory to scan',
        },
        ignorePaths: {
          type: 'array',
          items: { type: 'string' },
          description: 'Paths to ignore during scanning',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'scan_sbom',
    description: 'Scan a CycloneDX SBOM file for CVE-2025-55182 vulnerabilities',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Path to the CycloneDX SBOM JSON file',
        },
      },
      required: ['path'],
    },
  },
];

// Handle MCP requests
function handleRequest(request: MCPRequest): MCPResponse {
  const { id, method, params } = request;

  try {
    switch (method) {
      case 'initialize':
        return {
          jsonrpc: '2.0',
          id,
          result: {
            protocolVersion: '2024-11-05',
            serverInfo: SERVER_INFO,
            capabilities: {
              tools: {},
            },
          },
        };

      case 'tools/list':
        return {
          jsonrpc: '2.0',
          id,
          result: {
            tools: TOOLS,
          },
        };

      case 'tools/call': {
        const toolName = params?.name as string;
        const toolArgs = params?.arguments as Record<string, unknown>;

        if (toolName === 'scan_repo') {
          const path = toolArgs?.path as string;
          const ignorePaths = toolArgs?.ignorePaths as string[] | undefined;

          if (!path) {
            return {
              jsonrpc: '2.0',
              id,
              error: {
                code: -32602,
                message: 'Invalid params: path is required',
              },
            };
          }

          const result = scan({ path, ignorePaths });
          return {
            jsonrpc: '2.0',
            id,
            result: {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(result, null, 2),
                },
              ],
            },
          };
        }

        if (toolName === 'scan_sbom') {
          const path = toolArgs?.path as string;

          if (!path) {
            return {
              jsonrpc: '2.0',
              id,
              error: {
                code: -32602,
                message: 'Invalid params: path is required',
              },
            };
          }

          const result = scanSbom({ sbomPath: path });
          return {
            jsonrpc: '2.0',
            id,
            result: {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(result, null, 2),
                },
              ],
            },
          };
        }

        return {
          jsonrpc: '2.0',
          id,
          error: {
            code: -32601,
            message: `Unknown tool: ${toolName}`,
          },
        };
      }

      case 'notifications/initialized':
        // Notification, no response needed
        return { jsonrpc: '2.0', id, result: null };

      default:
        return {
          jsonrpc: '2.0',
          id,
          error: {
            code: -32601,
            message: `Method not found: ${method}`,
          },
        };
    }
  } catch (error) {
    return {
      jsonrpc: '2.0',
      id,
      error: {
        code: -32603,
        message: error instanceof Error ? error.message : 'Internal error',
      },
    };
  }
}

// Main server loop
function startServer(): void {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false,
  });

  rl.on('line', (line) => {
    try {
      const request = JSON.parse(line) as MCPRequest;
      const response = handleRequest(request);

      // Only send response if it's not a notification
      if (response.result !== null || response.error) {
        console.log(JSON.stringify(response));
      }
    } catch (error) {
      const errorResponse: MCPResponse = {
        jsonrpc: '2.0',
        id: 0,
        error: {
          code: -32700,
          message: 'Parse error',
        },
      };
      console.log(JSON.stringify(errorResponse));
    }
  });

  rl.on('close', () => {
    process.exit(0);
  });
}

// Export for CLI integration
export { startServer };

// Auto-start if run directly
const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  startServer();
}
