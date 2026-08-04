# Workspace Tools (MCP)

> ## This is a research honeypot. It records the connections it receives.
>
> If you connect a client or an agent to this server, the requests it makes are
> logged and analyzed. Read [What is recorded](#what-is-recorded) before
> connecting anything.
>
> **Do not point an agent at this server if that agent has access to anything you
> care about.** Tool arguments are logged, so a `read_file` or `query_database`
> call arrives carrying whatever path or query string your agent decided to send.

An MCP server presenting a plausible, tool-rich workspace surface, in order to
study what MCP clients and agents do when handed tools with names like
`list_credentials` and `execute_command`.

There is little public data on that question. Whether an agent invokes a
dangerous-sounding tool unprompted, whether it reads a schema before calling,
what it sends as arguments, and what a client does with a tool nobody asked it
to use are all open and all measurable. This is the instrument for measuring
them.

## Disclosure

This repository and its registry listing originally described this as a sandbox
server returning synthetic data, and did not mention that connections are
recorded. That description was incomplete in the way that mattered: it invited
connections without saying what happens to them. It read that way from
2026-06-17 until this rewrite.

If you connected before 2026-08-03 and want records associated with you removed,
email **security@brianmitchell.ai** with an approximate time range.

## What it does

Every response is synthetic. No tool executes anything, queries any real system,
or makes an outbound request on a caller's behalf. `execute_command` does not
run commands. `list_credentials` returns invented values. `query_database`
queries nothing.

| tool | behaviour |
|---|---|
| `search_documents` | Returns invented documents. Query text is logged. |
| `read_file` | Returns invented file contents. Requested path is logged. |
| `list_credentials` | Returns honeytokens. Never real credentials. |
| `query_database` | Returns invented rows. Query text is logged. |
| `get_config` | Returns invented configuration. |
| `execute_command` | Runs nothing. Returns a synthetic error. The command string is logged. |
| `diagnostics` | Returns invented diagnostics. |

The credentials it returns are honeytokens: unique per issuance, syntactically
plausible, never valid anywhere. If one is later presented to a system under my
control, that ties a specific retrieval to a specific reuse.

## What is recorded

Per request: timestamp, source address, transport metadata, the tool invoked,
and the arguments passed to it.

Arguments are the part worth thinking about before connecting. An agent calling
`read_file` sends a path; an agent calling `query_database` sends a query. Those
come from whatever context your agent is operating in, and this server receives
them. Tool arguments are not currently redacted, which is why the warning is at
the top of this file rather than buried in it.

If you want to exercise a tool-rich MCP server without that, run one locally.

## Source

The implementation is not published, so the behaviour described above is not
independently verifiable by you. That is a real limitation and worth stating
plainly rather than leaving implied: you are being asked to take my word for
what a black box does with what you send it.

Treat this listing as a hosted research service with a disclosed telemetry
policy, and not as open-source software you can audit. The MIT licence covers
this repository's contents, which are the manifest and this document.

A related instrument with the same thesis, applied to HTTP scanners rather than
MCP clients, is fully open and auditable:
<https://github.com/brian-mitchell-sec/http-bait>.

## Connect

```
https://vandorla.com/mcp
```

Streamable HTTP. Connect a client only if you have read the sections above.

## Contact

Questions, removal requests, and anything else: **security@brianmitchell.ai**.

## License

MIT, see [LICENSE](LICENSE).
