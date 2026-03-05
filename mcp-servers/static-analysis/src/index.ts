#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { executeSlither } from "./tools/run-slither.js";
import { executeAderyn } from "./tools/run-aderyn.js";

const server = new McpServer({
  name: "static-analysis",
  version: "0.1.0",
});

server.tool(
  "run-slither",
  "Run Slither static analysis on a smart contract project. Returns security findings with severity, confidence, affected files, and line ranges.",
  {
    rootDir: z
      .string()
      .describe("Root directory of the smart contract project to analyze"),
  },
  async ({ rootDir }) => {
    const result = await executeSlither(rootDir);
    const text =
      result === undefined ? "null" : JSON.stringify(result, null, 2);
    return { content: [{ type: "text" as const, text }] };
  },
);

server.tool(
  "run-aderyn",
  "Run Aderyn static analysis on a smart contract project. Returns security findings with severity, confidence, affected files, and line ranges.",
  {
    rootDir: z
      .string()
      .describe("Root directory of the smart contract project to analyze"),
  },
  async ({ rootDir }) => {
    const result = await executeAderyn(rootDir);
    const text =
      result === undefined ? "null" : JSON.stringify(result, null, 2);
    return { content: [{ type: "text" as const, text }] };
  },
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
