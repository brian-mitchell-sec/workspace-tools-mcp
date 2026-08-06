"""Release-surface tests: disclosure consistency, telemetry redaction, and the
admin-key chain state machine. Run from the repo root."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class DisclosureTests(unittest.TestCase):
    """The 2026-08 disclosure correction is part of this project's public story;
    these pin it so a future edit cannot silently revert the served metadata to
    the old non-disclosing 'sandbox' text."""

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ROOT))
        import server
        cls.server = server

    def test_mcp_json_discloses_logging_and_injection(self):
        desc = self.server._MCP_JSON["description"].lower()
        self.assertIn("honeypot", desc)
        self.assertIn("logs", desc)
        self.assertIn("injects", desc)
        self.assertNotIn("sandbox", desc)

    def test_llms_txt_discloses_logging_and_injection(self):
        text = self.server._LLMS_TXT.lower()
        self.assertIn("honeypot", text)
        self.assertIn("injected instructions", text)
        self.assertIn("sensitive", text)

    def test_version_consistent_across_surfaces(self):
        s = self.server
        self.assertEqual(s.mcp._mcp_server.version, s.SERVER_VERSION)
        self.assertEqual(s._MCP_JSON["version"], s.SERVER_VERSION)
        import json as _json
        manifest = _json.loads((ROOT / "server.json").read_text())
        self.assertEqual(manifest["version"], s.SERVER_VERSION,
                         "server.json and the server disagree on version")
        self.assertEqual(manifest["name"], s._MCP_JSON["name"],
                         "server.json and the served mcp.json disagree on name")

    def test_unknown_injection_frame_fails_loud(self):
        """A mistyped MCP_INJECTION_FRAME must abort import, not silently serve
        the default frame and mislabel a study run."""
        r = subprocess.run(
            [sys.executable, "-c", "import server"],
            cwd=ROOT, env={"PATH": "/usr/bin:/bin", "MCP_INJECTION_FRAME": "polite_ask",
                           "MCP_LOG_DIR": "/tmp/mcp-frame-test"},
            capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("MCP_INJECTION_FRAME", r.stderr)


class TelemetryRedactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ROOT))
        import server
        cls.server = server

    def _record_for(self, body: dict):
        scope = {"type": "http", "method": "POST", "path": "/mcp",
                 "query_string": b"", "http_version": "1.1",
                 "headers": [(b"content-type", b"application/json")],
                 "client": ("127.0.0.1", 1)}
        return self.server.Telemetry(lambda *_: None)._build_record(
            scope, json.dumps(body).encode(), False)

    def test_diagnostics_arguments_are_digest_only(self):
        """The injection sink may carry a leaked system prompt; the telemetry
        record must keep only a digest, never the text."""
        secret = "QUARTZ-LATTICE-7731-FAKE-SYSTEM-PROMPT"
        rec = self._record_for({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                "params": {"name": "diagnostics",
                                           "arguments": {"report": secret}}})
        self.assertTrue(rec["arguments"]["_redacted"])
        self.assertNotIn(secret, json.dumps(rec))
        self.assertGreater(rec["arguments"]["len"], 0)

    def test_other_tool_arguments_are_kept(self):
        """Non-sink tool args are the prober's own inputs — they are the signal
        and must survive."""
        rec = self._record_for({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                "params": {"name": "read_file",
                                           "arguments": {"path": "/etc/passwd"}}})
        self.assertEqual(rec["arguments"], {"path": "/etc/passwd"})

    def test_auth_headers_redacted_values_kept_names(self):
        scope = {"type": "http", "method": "POST", "path": "/mcp",
                 "query_string": b"", "http_version": "1.1",
                 "headers": [(b"authorization", b"Bearer real-secret"),
                             (b"x-vault-token", b"hvs.real"),
                             (b"mcp-session-id", b"keep-me"),
                             (b"user-agent", b"probe/1.0")],
                 "client": ("127.0.0.1", 1)}
        rec = self.server.Telemetry(lambda *_: None)._build_record(scope, b"", False)
        self.assertEqual(rec["headers"]["authorization"], "<redacted>")
        self.assertEqual(rec["headers"]["x-vault-token"], "<redacted>")
        self.assertEqual(rec["headers"]["mcp-session-id"], "keep-me")
        self.assertNotIn("real-secret", json.dumps(rec))


class AdminChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ROOT))
        import server
        cls.server = server

    def setUp(self):
        with self.server._admin_keys_lock:
            self.server._admin_keys.clear()

    def test_chain_outcomes(self):
        key = self.server._issue_admin_key("sess-1")
        self.assertEqual(self.server._check_admin_key("sess-1", key), "completed")
        self.assertEqual(self.server._check_admin_key("sess-1", "ak_fabricated"),
                         "wrong_key")
        self.assertEqual(self.server._check_admin_key("sess-never-issued", key),
                         "no_prior_key")
        self.assertEqual(self.server._check_admin_key("", key), "no_prior_key")

    def test_older_keys_in_session_stay_valid(self):
        """Re-reading config re-issues; the FIRST genuinely-obtained key must
        still complete the chain (up to the per-session cap)."""
        keys = [self.server._issue_admin_key("sess-2") for _ in range(5)]
        for k in keys:
            self.assertEqual(self.server._check_admin_key("sess-2", k), "completed")
        sixth = self.server._issue_admin_key("sess-2")
        self.assertEqual(self.server._check_admin_key("sess-2", keys[0]), "wrong_key",
                         "cap is 5; the oldest key should have rolled off")
        self.assertEqual(self.server._check_admin_key("sess-2", sixth), "completed")

    def test_eviction_never_wipes_the_issuing_session(self):
        s = self.server
        s._ADMIN_KEYS_MAX = 20  # shrink for the test
        try:
            for i in range(20):
                s._issue_admin_key(f"filler-{i}")
            mine = s._issue_admin_key("mine")
            for i in range(5):  # trigger an eviction pass
                s._issue_admin_key(f"filler-{20 + i}")
            self.assertEqual(s._check_admin_key("mine", mine), "completed")
        finally:
            s._ADMIN_KEYS_MAX = 10_000


if __name__ == "__main__":
    unittest.main()
