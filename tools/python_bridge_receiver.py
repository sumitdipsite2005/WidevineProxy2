#!/usr/bin/env python3
"""Local receiver for the WidevineProxy2 Python bridge.

Listens only on 127.0.0.1:8765 and accepts JSON POSTs at
/widevineproxy2. The current extension bridge sends sanitized capture
metadata only.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

HOST = "127.0.0.1"
PORT = 8765
PATH = "/widevineproxy2"
MAX_BODY_BYTES = 1_000_000


class BridgeHandler(BaseHTTPRequestHandler):
    server_version = "WVP2PythonBridge/1.0"

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if self.path != PATH:
            self._send_json(404, {"ok": False, "error": "not found"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"ok": False, "error": "invalid content length"})
            return

        if content_length <= 0 or content_length > MAX_BODY_BYTES:
            self._send_json(413, {"ok": False, "error": "invalid body size"})
            return

        raw = self.rfile.read(content_length)

        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"ok": False, "error": "invalid JSON"})
            return

        if not isinstance(payload, dict):
            self._send_json(400, {"ok": False, "error": "JSON object required"})
            return

        print("\n[WidevineProxy2] Capture received")
        print(json.dumps(payload, indent=2, ensure_ascii=False))

        self._send_json(200, {"ok": True})

    def log_message(self, format: str, *args: Any) -> None:
        # Keep normal request logging compact while preserving useful errors.
        print(f"[HTTP] {format % args}")


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), BridgeHandler)
    print(f"WidevineProxy2 Python bridge listening on http://{HOST}:{PORT}{PATH}")
    print("Press Ctrl+C to stop.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping bridge receiver.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
