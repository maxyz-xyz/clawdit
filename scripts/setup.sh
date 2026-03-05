#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Installing MCP server dependencies..."

echo "  -> solodit server"
cd "$ROOT_DIR/mcp-servers/solodit"
npm install
npm run build

echo "  -> static-analysis server"
cd "$ROOT_DIR/mcp-servers/static-analysis"
npm install
npm run build

echo ""
echo "Checking for external tools..."

if command -v uvx &>/dev/null; then
  echo "  uvx: $(uvx --version 2>&1 | head -1) (used to run slither-analyzer)"
else
  echo "  uvx: NOT FOUND — install with: brew install uv"
fi

if command -v aderyn &>/dev/null; then
  echo "  aderyn: $(aderyn --version 2>&1 | head -1)"
else
  echo "  aderyn: NOT FOUND — install with: cargo install aderyn"
fi

echo ""
echo "Setup complete."
