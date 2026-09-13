#!/usr/bin/env python3
"""Local receiver for the WidevineProxy2 Python bridge.

Listens only on 127.0.0.1:8765.

POST /widevineproxy2
    Accepts the sanitized capture metadata sent by the extension.

GET /widevineproxy2/latest
    Returns the most recent sanitized capture so another local Python
    process, such as a recorder, can consume it.
"""

from __future__ import annotations

import copy
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

HOST = "127.0.0.1"
PORT = 8765
POST_PATH = "/widevineproxy2"
LATEST_PATH = "/widevineproxy2/latest"
MAX_BODY_BYTES = 1_000_000

_latest_capture: dict[str, Any] | None = None
_latest_lock = threading.Lock()


def choose_preferred_manifest(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Choose the HLS master when present, otherwise the first manifest."""
    manifests = payload.get("manifests")
    if not isinstance(manifests, list):
        return None

    valid = [item for item in manifests if isinstance(item, dict)]
    if not valid:
        return None

    for item in valid:
        if item.get("type") == "HLS_MASTER":
            return copy.deepcopy(item)

    return copy.deepcopy(valid[0])


def store_latest_capture(payload: dict[str, Any]) -> dict[str, Any]:
    """Store a defensive copy and add a safe derived manifest selection."""
    global _latest_capture

    record = copy.deepcopy(payload)
    record["preferred_manifest"] = choose_preferred_manifest(record)

    with _latest_lock:
        _latest_capture = record

    return record


def get_latest_capture() -> dict[str, Any] | None:
    with _latest_lock:
        return copy.deepcopy(_latest_capture)


class BridgeHandler(BaseHTTPRequestHandler):
    server_version = "WVP2PythonBridge/1.1"

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path != LATEST_PATH:
            self._send_json(404, {"ok": False, "error": "not found"})
            return

        latest = get_latest_capture()
        if latest is None:
            self._send_json(404, {"ok": False, "error": "no capture yet"})
            return

        self._send_json(200, latest)

    def do_POST(self) -> None:
        if self.path != POST_PATH:
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

        stored = store_latest_capture(payload)

        print("\n[WidevineProxy2] Capture received")
        print(json.dumps(stored, indent=2, ensure_ascii=False))

        self._send_json(200, {"ok": True})

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[HTTP] {format % args}")


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), BridgeHandler)
    print(f"WidevineProxy2 Python bridge listening on http://{HOST}:{PORT}{POST_PATH}")
    print(f"Latest capture available at http://{HOST}:{PORT}{LATEST_PATH}")
    print("Press Ctrl+C to stop.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping bridge receiver.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
