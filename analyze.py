"""
Summarize MCP honeypot activity, with per-session timing/cadence and IP classification.

Usage:
  python mcp/analyze.py mcp_data/logs/mcp_events.jsonl            # offline (reverse-DNS + cloud heuristic)
  python mcp/analyze.py mcp_data/logs/mcp_events.jsonl --enrich   # + ASN/geo/hosting/proxy via ip-api.com

--enrich makes a live call to ip-api.com (sends the observed IPs to a 3rd party); off by default.
Self-test connections (clientInfo name 'selftest-*') are excluded.
"""
import json
import os
import socket
import sys
from collections import Counter, defaultdict
from datetime import datetime
from urllib.parse import parse_qs

socket.setdefaulttimeout(2.0)


def _option(name):
    for i, arg in enumerate(sys.argv[1:]):
        if arg == name and i + 2 <= len(sys.argv[1:]):
            return sys.argv[1:][i + 1]
        if arg.startswith(name + "="):
            return arg.split("=", 1)[1]
    return None


SINCE_RAW = _option("--since")
SINCE = datetime.fromisoformat(SINCE_RAW) if SINCE_RAW else None
_skip_values = {SINCE_RAW} if SINCE_RAW else set()
PATH = next((a for a in sys.argv[1:] if not a.startswith("-") and a not in _skip_values),
            "mcp_data/logs/mcp_events.jsonl")
ENRICH = "--enrich" in sys.argv

CLOUD = {  # reverse-DNS substring -> provider class
    "amazonaws": "AWS", "google": "GCP", "googleusercontent": "GCP", "azure": "Azure",
    "microsoft": "Azure", "digitalocean": "DigitalOcean", "hetzner": "Hetzner",
    "ovh": "OVH", "linode": "Linode", "akamai": "Akamai/Linode", "scaleway": "Scaleway",
    "vultr": "Vultr", "oracle": "Oracle", "cloudflare": "Cloudflare", "fastly": "Fastly",
}


def classify_ip(ip):
    if not ip:
        return ("", "unknown")
    ip = ip.split(",")[0].strip()  # XFF may be a list
    try:
        ptr = socket.gethostbyaddr(ip)[0].lower()
    except Exception:
        return (ip, "no-ptr")  # no reverse DNS — common for scanners/cloud
    for sub, name in CLOUD.items():
        if sub in ptr:
            return (ip, f"cloud:{name}")
    return (ip, f"other:{ptr.split('.')[-2] if '.' in ptr else ptr}")


def enrich(ips):
    """ip-api.com batch: returns {ip: 'AS.. org | country | hosting/proxy flags'}."""
    import urllib.request
    out = {}
    ips = [i.split(",")[0].strip() for i in ips if i]
    for i in range(0, len(ips), 95):
        batch = [{"query": q, "fields": "query,as,org,country,hosting,proxy,mobile"} for q in ips[i:i + 95]]
        try:
            req = urllib.request.Request("http://ip-api.com/batch",
                                         data=json.dumps(batch).encode(),
                                         headers={"Content-Type": "application/json"})
            for r in json.load(urllib.request.urlopen(req, timeout=10)):
                flags = ",".join(f for f in ("hosting", "proxy", "mobile") if r.get(f))
                out[r.get("query")] = f"{r.get('as','')} | {r.get('country','')}{' | '+flags if flags else ''}"
        except Exception as e:
            print(f"  (enrich failed: {e})", file=sys.stderr)
            break
    return out


def parse_ts(r):
    try:
        return datetime.fromisoformat(r["ts"])
    except Exception:
        return None


def cadence(gaps, n):
    if n <= 1:
        return "single-shot"
    if not gaps:
        return "?"
    g = sorted(gaps)[len(gaps) // 2]  # median
    if g < 0.3:
        return "scanner-burst"
    if g <= 20:
        return "llm-paced"
    return "slow/interactive"


# Substrings that identify an MCP-ecosystem indexer/crawler/scorer (not an agent runtime).
CRAWLER_TOKENS = (
    "crawler", "scanner", "scan", "prober", "probe", "registry", "marketplace",
    "scoring", "score", "graph", "census", "enricher", "enrich", "proctor",
    "stats", "extractor", "research", "audit", "index", "directory", "catalog", "monitor",
    "censys",
    "glama", "mcpup", "pulsemcp", "prsm", "rugpull", "aisec", "odel", "acton",
    "tiza", "dominion", "agent-tools", "central", "skill-extractor",
)
# Substrings of real client/agent RUNTIMES — connecting because a user/agent uses the tools.
RUNTIME_TOKENS = (
    "claude", "anthropic", "cursor", "cline", "continue", "windsurf", "copilot",
    "openai", "gpt", "langchain", "llamaindex", "vscode", "zed", "goose",
    "librechat", "5ire", "witsy", "fast-agent", "fastagent", "autogen", "crewai",
)


def classify_client(name, ua, called_tools, high_confidence=False):
    """Classify conservatively: a tool call is engagement, not proof of an LLM.

    Known audit/indexer products routinely call tools. Only cross-turn evidence that
    requires consuming a prior response (currently a valid admin-key chain) earns the
    high-confidence label.
    """
    n = f"{name or ''} {ua or ''}".lower()
    if any(t in n for t in CRAWLER_TOKENS):
        return (("crawler-tooling" if called_tools else "crawler/indexer"),
                "ecosystem-infra identity" + (" made tool call(s)" if called_tools else ""))
    if high_confidence:
        return ("high-confidence-agent", "completed response-dependent cross-turn chain")
    if any(t in n for t in RUNTIME_TOKENS):
        return (("candidate-engaged" if called_tools else "candidate-agent"),
                "runtime identity" + (" made tool call(s)" if called_tools else ""))
    if called_tools:
        return ("ambiguous-engaged", "unknown identity made tool call(s)")
    return ("ambiguous", "generic/unknown name, init+list only")


def _load_rows(path):
    rows = []
    bad = 0
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    bad += 1  # one corrupted line (e.g. a crash mid-write) shouldn't abort the run
    if bad:
        print(f"  (skipped {bad} malformed JSONL line(s) in {path})", file=sys.stderr)
    return rows


def main():
    rows = _load_rows(PATH)
    if SINCE:
        rows = [r for r in rows if (parse_ts(r) and parse_ts(r) >= SINCE)]

    # Exclude only the self-test identity and its sessions. Filtering its whole source
    # IP would silently discard unrelated users behind the same NAT.
    selftest_sessions = {
        r.get("mcp_session") for r in rows
        if (str((r.get("client_info") or {}).get("name", "")).startswith("selftest")
            or str(r.get("ua", "")).startswith("selftest")) and r.get("mcp_session")
    }
    selftest_req_ids = {
        r.get("req_id") for r in rows
        if str((r.get("client_info") or {}).get("name", "")).startswith("selftest")
        or str(r.get("ua", "")).startswith("selftest")
        if r.get("req_id")
    }
    rows = [
        r for r in rows
        if r.get("mcp_session") not in selftest_sessions
        and r.get("req_id") not in selftest_req_ids
        and not str((r.get("client_info") or {}).get("name", "")).startswith("selftest")
        and not str(r.get("ua", "")).startswith("selftest")
    ]

    # The initialize request has no session header; the server assigns it in the
    # response. Join req_id -> response Mcp-Session-Id so initialize and later calls
    # land in one session. Legacy SSE carries session_id in /messages query strings.
    response_sessions = {
        r.get("req_id"): r.get("mcp_session")
        for r in rows if r.get("event") == "response" and r.get("req_id") and r.get("mcp_session")
    }

    def session_of(r):
        if r.get("mcp_session"):
            return r["mcp_session"]
        if response_sessions.get(r.get("req_id")):
            return response_sessions[r["req_id"]]
        if r.get("path", "").startswith("/messages"):
            return (parse_qs(r.get("query", "")).get("session_id") or [""])[0]
        return ""

    # group by session (mcp_session, else ip+ua)
    sess = defaultdict(list)
    for r in rows:
        if r.get("event") != "request":
            continue
        key = session_of(r) or f"{r.get('ip')}|{r.get('ua')}"
        sess[key].append(r)

    high_conf_sessions = {
        r.get("session") for r in rows
        if r.get("event") in {"admin_exec_attempt", "admin_status_attempt"}
        and r.get("chain") == "completed" and r.get("session")
    }

    clients, ja4s, tools, ipset = Counter(), Counter(), Counter(), Counter()
    inj = [r for r in rows if r.get("event") == "injection_complied"]
    execs = [r.get("command", "") for r in rows if r.get("event") == "exec_attempt"]
    issued = {r.get("token"): r for r in rows if r.get("event") == "canary_issued" and r.get("token")}
    canaries = [r for r in rows if r.get("event") == "canary_triggered"]
    sess_rows = []
    for key, evs in sess.items():
        evs.sort(key=lambda r: r.get("ts", ""))
        ts = [d for d in (parse_ts(r) for r in evs) if d is not None]
        gaps = [(ts[i + 1] - ts[i]).total_seconds() for i in range(len(ts) - 1)] if len(ts) > 1 else []
        ini = next((r for r in evs if r.get("jsonrpc_method") == "initialize"), evs[0])
        ci = ini.get("client_info") or {}
        ip = ini.get("ip", "")
        for r in evs:
            if r.get("jsonrpc_method") == "tools/call":
                tools[r.get("tool", "?")] += 1
        clients[f"{ci.get('name','?')} {ci.get('version','')}"] += 1
        if ini.get("ja4"):
            ja4s[ini["ja4"]] += 1
        ipset[ip] += 1
        dur = (ts[-1] - ts[0]).total_seconds() if len(ts) > 1 else 0.0
        did_init = any(r.get("jsonrpc_method") == "initialize" for r in evs)
        sess_rows.append({"key": key, "ip": ip, "ua": ini.get("ua", ""), "ja4": ini.get("ja4", ""),
                          "client": f"{ci.get('name','?')}/{ci.get('version','')}", "init": did_init,
                          "n": len(evs), "dur": dur, "cadence": cadence(gaps, len(ts)),
                          "tools": [r.get("tool") for r in evs if r.get("jsonrpc_method") == "tools/call"]})

    window = f"; since {SINCE_RAW}" if SINCE_RAW else ""
    print(f"=== MCP honeypot activity ({len(rows)} events, {len(sess)} sessions; self-tests excluded{window}) ===")
    print(f"distinct IPs: {len(ipset)} | distinct JA4: {len(ja4s)}")

    # A/B by hostname (registered vs unlisted control). Host = SNI, else Host header.
    def host_of(r):
        return (r.get("tls") or {}).get("sni") or (r.get("headers") or {}).get("host", "") or "?"
    hosts = defaultdict(lambda: {"events": 0, "ips": set(), "inits": 0, "calls": 0, "mcp_posts": 0})
    for r in rows:
        if r.get("event") != "request":
            continue
        h = hosts[host_of(r)]
        h["events"] += 1
        h["ips"].add(r.get("ip"))
        if r.get("path") == "/mcp":
            h["mcp_posts"] += 1
        if r.get("jsonrpc_method") == "initialize":
            h["inits"] += 1
        if r.get("jsonrpc_method") == "tools/call":
            h["calls"] += 1
    print("\nA/B by hostname (registered vs unlisted control):")
    print(f"   {'host':<28} {'events':>6} {'IPs':>4} {'/mcp hits':>9} {'MCP init':>8} {'tool calls':>10}")
    for host, h in sorted(hosts.items(), key=lambda kv: -kv[1]["events"]):
        print(f"   {host:<28} {h['events']:>6} {len(h['ips']):>4} {h['mcp_posts']:>9} {h['inits']:>8} {h['calls']:>10}")
    control = hosts.get(os.environ.get("MCP_CONTROL_HOST", "console.honeypot.example.com"))
    if control and control["inits"]:
        print(f"   ALERT: unlisted control completed {control['inits']} MCP initialize handshake(s)")

    methods = Counter(r.get("jsonrpc_method") for r in rows
                      if r.get("event") == "request" and r.get("jsonrpc_method"))
    print("\nJSON-RPC surface activity:")
    for method, n in methods.most_common():
        print(f"   {n:>5}  {method}")

    funnels = defaultdict(Counter)
    for r in rows:
        if r.get("event") != "request":
            continue
        source = (parse_qs(r.get("query", "")).get("src") or ["(none)"])[0]
        funnels[source]["http"] += 1
        method = r.get("jsonrpc_method")
        if method == "initialize":
            funnels[source]["init"] += 1
        elif method == "tools/list":
            funnels[source]["list"] += 1
        elif method == "tools/call":
            funnels[source]["call"] += 1
        elif method in {"prompts/get", "resources/read"}:
            funnels[source]["content_read"] += 1
    print("\ndiscovery-source funnel:")
    print(f"   {'src':<22} {'HTTP':>6} {'init':>6} {'list':>6} {'call':>6} {'content':>8}")
    for source, counts in sorted(funnels.items(), key=lambda kv: -kv[1]["http"]):
        print(f"   {source[:22]:<22} {counts['http']:>6} {counts['init']:>6} "
              f"{counts['list']:>6} {counts['call']:>6} {counts['content_read']:>8}")
    # Crawler vs candidate-agent classification. Only sessions that actually completed an
    # MCP `initialize` are real MCP clients; the rest are HTTP-level probes (GET /mcp, path
    # scans) with no handshake — counted separately so they don't dilute the client picture.
    cls_counter = Counter()
    cls_clients = defaultdict(Counter)
    http_only = 0
    for s in sess_rows:
        if not s["init"]:
            http_only += 1
            continue
        klass, _ = classify_client(s["client"].split("/")[0], s["ua"], s["tools"],
                                   s["key"] in high_conf_sessions)
        cls_counter[klass] += 1
        cls_clients[klass][s["client"].split("/")[0]] += 1
    order = ["high-confidence-agent", "candidate-engaged", "ambiguous-engaged",
             "crawler-tooling", "candidate-agent", "ambiguous", "crawler/indexer"]
    print("\nMCP client classification (handshaked sessions only):")
    for k in sorted(cls_counter, key=lambda k: (order.index(k) if k in order else 9)):
        names = ", ".join(f"{c}×{n}" for c, n in cls_clients[k].most_common(6))
        print(f"   {cls_counter[k]:>4}  {k:<16} {names}")
    print(f"   (+ {http_only} HTTP-only probe sessions with no MCP initialize)")

    print("\nclient identities (initialize clientInfo):")
    for c, n in clients.most_common():
        print(f"   {n:>4}  {c}")
    print("\nJA4 fingerprints:")
    for j, n in ja4s.most_common():
        print(f"   {n:>4}  {j}")
    print("\ntool calls:", dict(tools))
    print(f"injection-complied: {len(inj)} | exec_attempts: {len(execs)} | canary triggers: {len(canaries)}")
    for r in inj[:5]:
        print("   inj→", r.get("report", "")[:100])
    if execs:
        print("   exec→", execs[:5])
    for trigger in canaries[:10]:
        origin = issued.get(trigger.get("token")) or {}
        print("   canary→",
              f"method={trigger.get('method', 'GET')} token={trigger.get('token')} "
              f"issued_tool={origin.get('tool', '?')} issued_session={origin.get('session', '?')}")

    epochs = Counter(str(r.get("instrument_version", "legacy")) for r in rows)
    print("\ninstrument epochs:")
    for version, n in epochs.most_common():
        print(f"   {n:>6}  {version}")

    # IP classification
    print("\nIP classification:")
    ipinfo = {ip: classify_ip(ip) for ip in ipset}
    geo = enrich(list(ipset)) if ENRICH else {}
    for ip, n in ipset.most_common():
        _, cls = ipinfo[ip]
        q = ip.split(",")[0].strip()
        extra = f"  [{geo[q]}]" if geo.get(q) else ""
        print(f"   {n:>4}  {ip:<20} {cls}{extra}")

    # per-session cadence (agent vs scanner discrimination)
    print("\nper-session cadence:")
    print(f"   {'ip':<18} {'client':<22} {'n':>3} {'dur(s)':>7} {'cadence':<15} tools")
    for r in sorted(sess_rows, key=lambda r: -r["n"]):
        print(f"   {r['ip']:<18} {r['client']:<22} {r['n']:>3} {r['dur']:>7.1f} {r['cadence']:<15} {r['tools']}")

    identity_over_time(rows)


# --------------------------------------------------------------------------- #
# Identity-over-time: the unit that separates "a scanner sweep" from "a real adopted
# tool being used over time" is not the session, it's the identity across the whole
# window. A genuinely adopted integration looks like: one persistent identity (IP),
# active across MULTIPLE CALENDAR DAYS spanning real elapsed time (not a burst),
# calling tools with VARYING, non-templated arguments (not the same 3 empty-arg
# calls replayed). A scanner/indexer is usually the opposite: one-shot or same-day
# bursts, identical or empty args every time. This aggregates across sessions per
# identity to surface that pattern; it does not replace the per-session view above.
# --------------------------------------------------------------------------- #
def identity_over_time(rows):
    by_ip = defaultdict(list)
    for r in rows:
        if r.get("event") != "request":
            continue
        by_ip[r.get("ip", "")].append(r)

    print("\nidentity-over-time (aggregated across sessions per IP; the slow-burn-adoption signature):")
    print(f"   {'ip':<18} {'client(s)':<26} {'days-active':>11} {'span(d)':>8} {'calls':>6} {'distinct-args':>13}  flag")
    candidates = []
    for ip, evs in by_ip.items():
        if not ip:
            continue
        days = set()
        first = last = None
        clients = Counter()
        calls = [r for r in evs if r.get("jsonrpc_method") == "tools/call"]
        arg_sigs = set()
        for r in evs:
            d = parse_ts(r)
            if d is None:
                continue
            days.add(d.date())
            first = d if first is None or d < first else first
            last = d if last is None or d > last else last
            ci = r.get("client_info") or {}
            if ci.get("name"):
                clients[ci["name"]] += 1
        for c in calls:
            arg_sigs.add(json.dumps(c.get("arguments") or {}, sort_keys=True))
        span = (last - first).total_seconds() / 86400 if (first and last) else 0.0
        if len(days) < 2 and not calls:
            continue  # skip single-touch non-callers; not interesting for this view
        flag = ""
        if len(days) >= 3 and span >= 2.0 and len(arg_sigs) >= 2:
            flag = "<-- slow-burn adoption signature (recheck this one)"
            candidates.append(ip)
        cnames = ", ".join(f"{c}" for c, _ in clients.most_common(2)) or "?"
        print(f"   {ip:<18} {cnames:<26} {len(days):>11} {span:>8.1f} {len(calls):>6} {len(arg_sigs):>13}  {flag}")
    if not candidates:
        print("   (no identity shows the multi-day, varying-argument adoption signature in this window)")


if __name__ == "__main__":
    main()
