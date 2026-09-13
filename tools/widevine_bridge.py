#!/usr/bin/env python3
"""Local job-aware bridge between WidevineProxy2 and recorder processes.

The bridge listens only on 127.0.0.1:8765 and carries sanitized capture
metadata. It does not transport content keys, PSSH contents, or auth headers.

API:
    GET    /health
    POST   /jobs
    GET    /jobs/<job_id>
    DELETE /jobs/<job_id>
    GET    /attach/<job_id>
    POST   /jobs/<job_id>/attached
    GET    /jobs/<job_id>/latest
    POST   /widevineproxy2
    GET    /widevineproxy2/latest   (debug convenience)
"""

from __future__ import annotations

import copy
import html
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote, urlparse

HOST = "127.0.0.1"
PORT = 8765
CAPTURE_PATH = "/widevineproxy2"
LATEST_PATH = "/widevineproxy2/latest"
HEALTH_PATH = "/health"
JOBS_PATH = "/jobs"
MAX_BODY_BYTES = 1_000_000

_JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_JOB_PATH_RE = re.compile(r"^/jobs/([^/]+)$")
_JOB_LATEST_PATH_RE = re.compile(r"^/jobs/([^/]+)/latest$")
_JOB_ATTACHED_PATH_RE = re.compile(r"^/jobs/([^/]+)/attached$")
_ATTACH_PATH_RE = re.compile(r"^/attach/([^/]+)$")

_state_lock = threading.RLock()
_jobs: dict[str, dict[str, Any]] = {}
_latest_capture: dict[str, Any] | None = None


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def normalize_job_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not _JOB_ID_RE.fullmatch(value):
        return None
    return value


def path_job_id(match: re.Match[str] | None) -> str | None:
    if match is None:
        return None
    try:
        value = unquote(match.group(1))
    except Exception:
        return None
    return normalize_job_id(value)


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


def public_job(job: dict[str, Any]) -> dict[str, Any]:
    return {
        "job_id": job["job_id"],
        "created_at": job["created_at"],
        "attached": job["attached"],
        "tab_id": job["tab_id"],
        "capture_count": job["capture_count"],
        "latest_capture_timestamp": job["latest_capture_timestamp"],
    }


def register_job(job_id: str) -> tuple[dict[str, Any], bool]:
    """Register a job idempotently. Returns (job, created)."""
    with _state_lock:
        existing = _jobs.get(job_id)
        if existing is not None:
            return copy.deepcopy(public_job(existing)), False

        job = {
            "job_id": job_id,
            "created_at": now_ms(),
            "attached": False,
            "tab_id": None,
            "capture_count": 0,
            "latest_capture_timestamp": None,
            "latest_capture": None,
        }
        _jobs[job_id] = job
        return copy.deepcopy(public_job(job)), True


def get_job(job_id: str) -> dict[str, Any] | None:
    with _state_lock:
        job = _jobs.get(job_id)
        return copy.deepcopy(public_job(job)) if job is not None else None


def mark_job_attached(job_id: str, tab_id: int) -> dict[str, Any] | None:
    with _state_lock:
        job = _jobs.get(job_id)
        if job is None:
            return None
        job["attached"] = True
        job["tab_id"] = tab_id
        return copy.deepcopy(public_job(job))


def delete_job(job_id: str) -> bool:
    with _state_lock:
        return _jobs.pop(job_id, None) is not None


def capture_timestamp(record: dict[str, Any]) -> float:
    value = record.get("timestamp")
    return float(value) if isinstance(value, (int, float)) else float(now_ms())


def store_capture(payload: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    """Store sanitized capture metadata globally and, when correlated, by job."""
    global _latest_capture

    record = copy.deepcopy(payload)
    record["preferred_manifest"] = choose_preferred_manifest(record)
    job_id = normalize_job_id(record.get("job_id"))

    with _state_lock:
        _latest_capture = copy.deepcopy(record)

        if record.get("job_id") is not None and job_id is None:
            return record, "invalid job_id"

        if job_id is None:
            return record, None

        job = _jobs.get(job_id)
        if job is None:
            return record, "unknown job_id"

        current = job["latest_capture"]
        if current is None or capture_timestamp(record) >= capture_timestamp(current):
            job["latest_capture"] = copy.deepcopy(record)
            job["latest_capture_timestamp"] = record.get("timestamp")

        job["capture_count"] += 1

    return record, None


def get_latest_capture() -> dict[str, Any] | None:
    with _state_lock:
        return copy.deepcopy(_latest_capture)


def get_job_latest_capture(job_id: str) -> dict[str, Any] | None:
    with _state_lock:
        job = _jobs.get(job_id)
        if job is None or job["latest_capture"] is None:
            return None
        return copy.deepcopy(job["latest_capture"])


class BridgeHandler(BaseHTTPRequestHandler):
    server_version = "WidevineBridge/2.0"

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status: int, body_text: str) -> None:
        body = body_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_object(self) -> dict[str, Any] | None:
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"ok": False, "error": "invalid content length"})
            return None

        if content_length <= 0 or content_length > MAX_BODY_BYTES:
            self._send_json(413, {"ok": False, "error": "invalid body size"})
            return None

        raw = self.rfile.read(content_length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"ok": False, "error": "invalid JSON"})
            return None

        if not isinstance(payload, dict):
            self._send_json(400, {"ok": False, "error": "JSON object required"})
            return None

        return payload

    def do_GET(self) -> None:
        path = urlparse(self.path).path

        if path == HEALTH_PATH:
            with _state_lock:
                job_count = len(_jobs)
            self._send_json(200, {
                "ok": True,
                "service": "widevine_bridge",
                "version": 2,
                "job_count": job_count,
            })
            return

        if path == LATEST_PATH:
            latest = get_latest_capture()
            if latest is None:
                self._send_json(404, {"ok": False, "error": "no capture yet"})
            else:
                self._send_json(200, latest)
            return

        job_id = path_job_id(_JOB_LATEST_PATH_RE.fullmatch(path))
        if job_id is not None:
            if get_job(job_id) is None:
                self._send_json(404, {"ok": False, "error": "unknown job_id"})
                return
            latest = get_job_latest_capture(job_id)
            if latest is None:
                self._send_json(404, {"ok": False, "error": "no capture for job yet"})
            else:
                self._send_json(200, latest)
            return

        job_id = path_job_id(_JOB_PATH_RE.fullmatch(path))
        if job_id is not None:
            job = get_job(job_id)
            if job is None:
                self._send_json(404, {"ok": False, "error": "unknown job_id"})
            else:
                self._send_json(200, {"ok": True, "job": job})
            return

        job_id = path_job_id(_ATTACH_PATH_RE.fullmatch(path))
        if job_id is not None:
            if get_job(job_id) is None:
                self._send_json(404, {"ok": False, "error": "unknown job_id"})
                return

            safe_job_id = html.escape(job_id)
            self._send_html(200, f"""<!doctype html>
<html>
<head><meta charset=\"utf-8\"><title>Widevine Bridge</title></head>
<body data-widevine-bridge-job=\"{safe_job_id}\">
Associating recorder job {safe_job_id} with this browser tab.
</body>
</html>""")
            return

        self._send_json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path

        if path == JOBS_PATH:
            payload = self._read_json_object()
            if payload is None:
                return
            job_id = normalize_job_id(payload.get("job_id"))
            if job_id is None:
                self._send_json(400, {"ok": False, "error": "valid job_id required"})
                return
            job, created = register_job(job_id)
            self._send_json(201 if created else 200, {"ok": True, "created": created, "job": job})
            return

        job_id = path_job_id(_JOB_ATTACHED_PATH_RE.fullmatch(path))
        if job_id is not None:
            payload = self._read_json_object()
            if payload is None:
                return
            tab_id = payload.get("tab_id")
            if not isinstance(tab_id, int) or tab_id < 0:
                self._send_json(400, {"ok": False, "error": "valid tab_id required"})
                return
            job = mark_job_attached(job_id, tab_id)
            if job is None:
                self._send_json(404, {"ok": False, "error": "unknown job_id"})
            else:
                self._send_json(200, {"ok": True, "job": job})
            return

        if path == CAPTURE_PATH:
            payload = self._read_json_object()
            if payload is None:
                return

            stored, correlation_error = store_capture(payload)
            print("\n[WidevineProxy2] Capture received")
            print(json.dumps(stored, indent=2, ensure_ascii=False))

            if correlation_error is not None:
                self._send_json(409, {"ok": False, "error": correlation_error})
            else:
                self._send_json(200, {
                    "ok": True,
                    "correlated": normalize_job_id(stored.get("job_id")) is not None,
                })
            return

        self._send_json(404, {"ok": False, "error": "not found"})

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        job_id = path_job_id(_JOB_PATH_RE.fullmatch(path))
        if job_id is None:
            self._send_json(404, {"ok": False, "error": "not found"})
            return

        if not delete_job(job_id):
            self._send_json(404, {"ok": False, "error": "unknown job_id"})
            return

        self._send_json(200, {"ok": True, "job_id": job_id})

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[HTTP] {format % args}")


class BridgeServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    server = BridgeServer((HOST, PORT), BridgeHandler)
    print(f"Widevine Bridge listening on http://{HOST}:{PORT}")
    print(f"Health: http://{HOST}:{PORT}{HEALTH_PATH}")
    print(f"Debug latest capture: http://{HOST}:{PORT}{LATEST_PATH}")
    print("Press Ctrl+C to stop.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Widevine Bridge.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
