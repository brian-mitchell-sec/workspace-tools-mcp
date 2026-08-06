"""Pytest bootstrap: repo root on sys.path, telemetry into a temp dir.

MCP_LOG_DIR must be set BEFORE server.py is imported (the log directory is
created at import time), so it happens here in conftest rather than in any
test's setUp.
"""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("MCP_LOG_DIR", tempfile.mkdtemp(prefix="mcp-honeypot-test-"))
