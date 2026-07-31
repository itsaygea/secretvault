# SecretVault MCP Integration & Developer Tools Guide

SecretVault provides first-class Model Context Protocol (MCP) server support, allowing AI developer tools (**Antigravity IDE**, **Claude Code**, **Claude Desktop**, **OpenCode**, **Codex**, **Cursor**) to access credentials safely without putting raw secrets into LLM context streams or disk configs.

---

## 1. Supported MCP Transport Endpoints

SecretVault supports both standard MCP transport protocols:

| Transport Protocol | Endpoint URL | Description |
| :--- | :--- | :--- |
| **Streamable HTTP** *(New Standard)* | `https://vault.example.com/mcp` | Modern HTTP-based transport for Claude Code & AI agents |
| **SSE (Server-Sent Events)** *(Legacy)* | `https://vault.example.com/sse` | Legacy SSE transport for Claude Desktop & SSE tools |

Both transports connect to SecretVault's MCP engine with authentication via `Authorization: Bearer sv_YOUR_LINKING_KEY`.

---

## 2. Automated Tool Setup Wizard (`secretvault setup`)

SecretVault automatically detects and configures all installed developer tools on your system:

```bash
secretvault setup
```

### Supported Developer AI Tools:
- 🚀 **Antigravity IDE**: `~/.gemini/config/mcp_config.json`
- 🤖 **Claude Code CLI**: `~/.claude.json`
- 🖥️ **Claude Desktop**: `~/.config/Claude/claude_desktop_config.json`
- 💻 **OpenCode**: `~/.config/opencode/opencode.json`
- 📝 **Codex**: `~/.codex/config.toml`
- 🎯 **Cursor**: `~/.config/Cursor/User/globalStorage/cursor.mcp/mcp.json`

---

## 3. Integration Patterns

### Pattern A: Reverse-Proxy Remote HTTP MCP Servers

For remote HTTP/SSE MCP servers (e.g., `https://api.example.com/mcp/tool` requiring `Authorization: Bearer <API_KEY>`):

1. In the Web UI, create a Service Profile `example-service` targeting `https://api.example.com` with `OPENAI_API_KEY`.
2. Configure your MCP tool config to target SecretVault's proxy endpoint:

```json
"example-remote-mcp": {
  "type": "http",
  "url": "https://vault.example.com/proxy/example-service/mcp/tool",
  "headers": {
    "Authorization": "Bearer sv_YOUR_LINKING_KEY"
  }
}
```

*The real API key is injected server-side by SecretVault and never exists on the local client machine.*

### Pattern B: Zero-Leak Stdio MCP Servers (`secretvault run`)

For third-party stdio MCP servers running locally via CLI (e.g., `@example/mcp-server`):

```json
"example-stdio-mcp": {
  "command": "secretvault",
  "args": [
    "run",
    "--secret", "EXAMPLE_API_KEY",
    "--",
    "npx", "-y", "@example/mcp-server"
  ]
}
```

`secretvault run` automatically reads your stored client key from `~/.secretvault/credential.json`, fetches `EXAMPLE_API_KEY` into child process RAM (`process.env`), and executes `@example/mcp-server` without writing plaintexts to disk or command-line arguments.
