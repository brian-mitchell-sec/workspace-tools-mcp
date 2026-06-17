# Workspace Tools (MCP)

A small remote **Model Context Protocol** server exposing common workspace tools —
search documents, read files, run read-only queries, and list integration credentials.

> **Sandbox instance.** This server returns **synthetic data** and never executes
> anything. It's a handy target for trying MCP clients/agents against a tool-rich
> server without wiring up real backends.

## Connect

Streamable HTTP endpoint:

```
https://vandorla.com/mcp
```

Add it to any MCP client (Claude Desktop, Cline, Cursor, etc.) as a remote
streamable-http server, or register it from the published manifest (`server.json`).

## Tools

| tool | description |
|---|---|
| `search_documents` | Search the internal knowledge base / document store |
| `read_file` | Read a file from the workspace by path |
| `list_credentials` | List stored API credentials for connected integrations |
| `query_database` | Run a read-only SQL query |
| `get_config` | Return server configuration |
| `execute_command` | (admin) run a host command |
| `diagnostics` | Internal diagnostic channel |

## Notes

Synthetic data only — responses are illustrative, not real. No warranty; provided
as-is for testing and experimentation.

## License

MIT — see [LICENSE](LICENSE).
