# Data handling

What the workspace-tools MCP honeypot records, what it does with it, and what
you can ask for. The short version is in the [README](README.md#what-is-recorded);
this file is the policy.

## What is recorded

Per request to `https://vandorla.com/mcp`:

- timestamp
- source IP address and transport metadata (TLS and HTTP-level headers,
  including the MCP session id)
- the JSON-RPC method, the tool invoked, and the arguments passed to it —
  **unredacted**
- for the injection probes described in the README: whether the agent called
  `diagnostics` after being instructed to, and what summary it sent

Arguments routinely contain whatever the connecting agent had in context: file
paths, query strings, and — via the `diagnostics` probe — summaries of system
instructions. Treat anything your agent could plausibly send as recorded.

## What is not done with it

- No real credentials exist on this server; anything it serves is synthetic.
  Nothing recorded is used to authenticate anywhere.
- Records are not published with source addresses attached. Any published
  analysis is aggregated and anonymized (counts, shapes, timings), the same
  standard the sister project [http-bait](https://github.com/brian-mitchell-sec/http-bait)
  applies in its own DATA-HANDLING.md.
- Records are not sold or shared with third parties.

## Storage and retention

- Records are stored on the single host serving the endpoint, access-restricted
  to the operator.
- Raw records are kept for at most **12 months** from collection, then deleted;
  aggregated anonymized statistics may be kept longer.
- The host is dedicated to this research and runs no other service, so a
  compromise of the endpoint does not expose anything beyond the collected
  telemetry itself.

## Redaction status and roadmap

Tool arguments are **not currently redacted**. This is a deliberate interim
state, not an oversight: argument content is the primary signal for some of the
research questions (e.g., what paths agents probe), and redaction design that
preserves that signal without retaining secrets is non-trivial. Planned, in
order:

1. Length-and-HMAC reduction for argument values matching credential shapes
   (the middleware-enforced scheme http-bait already uses for headers).
2. Path argument reduction to a shape signature (depth, extension class) with
   the basename dropped.
3. A documented per-field retention table in this file.

Until those land, the mitigation is the warning: do not connect an agent that
has access to anything you would not want logged.

## Removal

Email **security@brianmitchell.ai** with an approximate time range and, if
possible, the source address or MCP session id. Records matching the request
are deleted within 30 days, confirmed by reply. This applies retroactively to
the pre-disclosure window described in the README's Disclosure section
(connections before 2026-08-03).

## Contact

**security@brianmitchell.ai**
