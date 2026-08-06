import importlib
import os
import tempfile
import unittest

from starlette.requests import Request


class HoneypotTelemetryTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ["MCP_LOG_DIR"] = cls.tmp.name
        cls.server = importlib.import_module("server")
        cls.analyze = importlib.import_module("analyze")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_server_version_matches_manifest(self):
        self.assertEqual(self.server.mcp._mcp_server.version,
                         self.server._MCP_JSON["version"])

    def test_duplicate_headers_and_batch_shape_are_preserved(self):
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/mcp",
            "query_string": b"",
            "http_version": "1.1",
            "headers": [
                (b"host", b"vandorla.com"),
                (b"x-trace", b"one"),
                (b"x-trace", b"two"),
                (b"authorization", b"secret"),
            ],
            "client": ("127.0.0.1", 1),
        }
        body = b'[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"}]'
        rec = self.server.Telemetry(lambda *_: None)._build_record(scope, body, False)
        self.assertEqual([p for p in rec["header_pairs"] if p[0] == "x-trace"],
                         [["x-trace", "one"], ["x-trace", "two"]])
        self.assertIn(["authorization", "<redacted>"], rec["header_pairs"])
        self.assertEqual(rec["jsonrpc_batch_size"], 2)
        self.assertEqual(rec["jsonrpc_batch"][1]["has_id"], False)

    def test_scanner_tool_call_is_not_labeled_agent(self):
        label, _ = self.analyze.classify_client(
            "SaSame-MCP-Audit", "SaSame-MCP-Audit/0.1", ["search_documents"])
        self.assertEqual(label, "crawler-tooling")
        label, _ = self.analyze.classify_client(
            "unknown", "python-httpx", ["get_config"])
        self.assertEqual(label, "ambiguous-engaged")

    async def test_post_canary_is_logged_with_minimized_body(self):
        captured = []

        async def fake_alog(rec):
            captured.append(rec)

        old = self.server.alog
        self.server.alog = fake_alog
        sent = False

        async def receive():
            nonlocal sent
            if sent:
                return {"type": "http.disconnect"}
            sent = True
            return {"type": "http.request", "body": b'{"ok":true}', "more_body": False}

        try:
            request = Request({
                "type": "http",
                "method": "POST",
                "path": "/c/test-token",
                "path_params": {"token": "test-token"},
                "query_string": b"",
                "scheme": "https",
                "server": ("vandorla.com", 443),
                "client": ("203.0.113.10", 1),
                "headers": [(b"host", b"vandorla.com"),
                            (b"content-type", b"application/json")],
            }, receive)
            response = await self.server.canary_catcher(request)
        finally:
            self.server.alog = old
        self.assertEqual(response.status_code, 200)
        self.assertEqual(captured[0]["method"], "POST")
        self.assertEqual(captured[0]["body_bytes"], 11)
        self.assertNotIn("body", captured[0])


if __name__ == "__main__":
    unittest.main()
