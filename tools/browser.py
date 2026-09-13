#!/usr/bin/env python3
"""Standalone Chrome automation test for the Widevine Bridge.

This tool does not contain recorder logic. It proves the browser side of the
job-correlation flow independently:

1. Verify widevine_bridge.py is alive.
2. Register a unique job ID.
3. Launch Chrome with a chosen persistent profile.
4. Load /attach/<job_id> and wait for positive attachment confirmation.
5. Navigate the same tab to the requested page URL.
6. Wait for the latest sanitized capture belonging to that job.
7. Print the capture and clean up the bridge job.

The bridge payload is intentionally metadata-only; this tool does not request
or transport content keys, PSSH contents, cookies, or authentication headers.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

BRIDGE_BASE_URL = "http://127.0.0.1:8765"
DEFAULT_TIMEOUT_SECONDS = 90.0
POLL_INTERVAL_SECONDS = 0.25


def default_chrome_user_data_dir() -> Path:
    system = platform.system()
    if system == "Windows":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            raise RuntimeError("LOCALAPPDATA is not available")
        return Path(local_app_data) / "Google" / "Chrome" / "User Data"
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / "Google" / "Chrome"
    return Path.home() / ".config" / "google-chrome"


def list_chrome_profiles(user_data_dir: Path) -> int:
    """List Chrome profile directory names without exposing account emails."""
    local_state_path = user_data_dir / "Local State"
    if not local_state_path.exists():
        print(f"Chrome Local State not found: {local_state_path}")
        return 1

    try:
        state = json.loads(local_state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Could not read Chrome Local State: {exc}")
        return 1

    info_cache = state.get("profile", {}).get("info_cache", {})
    if not isinstance(info_cache, dict) or not info_cache:
        print("No Chrome profiles found.")
        return 1

    print("Chrome profiles:")
    for directory, info in info_cache.items():
        name = info.get("name") if isinstance(info, dict) else None
        if not isinstance(name, str) or not name.strip():
            name = "(unnamed)"
        print(f"  {directory}: {name}")
    return 0


def bridge_request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    timeout: float = 5.0,
) -> tuple[int, dict[str, Any] | None]:
    body = None
    headers: dict[str, str] = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = Request(
        f"{BRIDGE_BASE_URL}{path}",
        data=body,
        headers=headers,
        method=method,
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read()
            parsed = json.loads(raw.decode("utf-8")) if raw else None
            return response.status, parsed
    except HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed = None
        return exc.code, parsed
    except URLError as exc:
        raise RuntimeError(f"Widevine Bridge is unavailable: {exc.reason}") from exc


def ensure_bridge() -> None:
    status, payload = bridge_request("GET", "/health")
    if status != 200 or not payload or payload.get("ok") is not True:
        raise RuntimeError("Widevine Bridge health check failed")


def register_job(job_id: str) -> None:
    status, payload = bridge_request("POST", "/jobs", {"job_id": job_id})
    if status not in (200, 201) or not payload or payload.get("ok") is not True:
        raise RuntimeError(f"Could not register bridge job {job_id!r}: {payload}")


def delete_job(job_id: str) -> None:
    try:
        bridge_request("DELETE", f"/jobs/{quote(job_id, safe='')}")
    except RuntimeError:
        pass


def wait_until_attached(job_id: str, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    path = f"/jobs/{quote(job_id, safe='')}"

    while time.monotonic() < deadline:
        status, payload = bridge_request("GET", path)
        if status == 200 and payload:
            job = payload.get("job")
            if isinstance(job, dict) and job.get("attached") is True:
                return job
        time.sleep(POLL_INTERVAL_SECONDS)

    raise TimeoutError(f"Timed out waiting for browser tab to attach to job {job_id}")


def wait_for_capture(job_id: str, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    path = f"/jobs/{quote(job_id, safe='')}/latest"

    while time.monotonic() < deadline:
        status, payload = bridge_request("GET", path)
        if status == 200 and isinstance(payload, dict):
            return payload
        if status not in (404,):
            raise RuntimeError(f"Bridge returned HTTP {status} while waiting for capture: {payload}")
        time.sleep(POLL_INTERVAL_SECONDS)

    raise TimeoutError(f"Timed out waiting for a capture for job {job_id}")


def import_selenium():
    try:
        from selenium import webdriver
        from selenium.common.exceptions import SessionNotCreatedException, WebDriverException
        from selenium.webdriver.chrome.options import Options
    except ImportError as exc:
        raise RuntimeError(
            "Selenium is required for browser automation. Install it with: "
            "python -m pip install selenium"
        ) from exc

    return webdriver, Options, SessionNotCreatedException, WebDriverException


def launch_chrome(
    user_data_dir: Path,
    profile_directory: str,
    chrome_binary: str | None,
):
    webdriver, Options, SessionNotCreatedException, WebDriverException = import_selenium()

    options = Options()
    options.page_load_strategy = "eager"
    options.add_argument(f"--user-data-dir={user_data_dir}")
    options.add_argument(f"--profile-directory={profile_directory}")
    options.add_argument("--no-first-run")
    options.add_argument("--no-default-browser-check")

    if chrome_binary:
        options.binary_location = chrome_binary

    try:
        return webdriver.Chrome(options=options)
    except SessionNotCreatedException as exc:
        raise RuntimeError(
            "Chrome could not start with that profile. Close every Chrome window using "
            "the same Chrome user-data directory, then try again."
        ) from exc
    except WebDriverException as exc:
        raise RuntimeError(f"Chrome automation failed to start: {exc}") from exc


def run_capture(args: argparse.Namespace) -> int:
    user_data_dir = Path(args.user_data_dir).expanduser().resolve()
    if not user_data_dir.exists():
        raise RuntimeError(f"Chrome user-data directory does not exist: {user_data_dir}")

    ensure_bridge()

    job_id = args.job_id or f"browser-{uuid.uuid4()}"
    register_job(job_id)

    driver = None
    try:
        print(f"Job: {job_id}")
        print(f"Chrome profile: {args.profile_directory}")

        driver = launch_chrome(
            user_data_dir=user_data_dir,
            profile_directory=args.profile_directory,
            chrome_binary=args.chrome_binary,
        )
        driver.set_page_load_timeout(args.page_load_timeout)

        attach_url = f"{BRIDGE_BASE_URL}/attach/{quote(job_id, safe='')}"
        print("Attaching browser tab to job...")
        driver.get(attach_url)
        job = wait_until_attached(job_id, args.attach_timeout)
        print(f"Attached tab: {job.get('tab_id')}")

        print("Opening target page...")
        driver.get(args.url)

        print("Waiting for matching sanitized capture...")
        capture = wait_for_capture(job_id, args.capture_timeout)
        print("\nCapture received for this job:")
        print(json.dumps(capture, indent=2, ensure_ascii=False))
        return 0
    finally:
        delete_job(job_id)
        if driver is not None and not args.keep_open:
            try:
                driver.quit()
            except Exception:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Standalone Widevine Bridge browser automation test")
    parser.add_argument("--url", help="Authorized target page URL to open")
    parser.add_argument(
        "--user-data-dir",
        default=str(default_chrome_user_data_dir()),
        help="Chrome user-data directory",
    )
    parser.add_argument(
        "--profile-directory",
        default="Default",
        help='Chrome profile directory, for example "Default" or "Profile 2"',
    )
    parser.add_argument("--chrome-binary", help="Optional path to chrome.exe / Chrome binary")
    parser.add_argument("--job-id", help="Optional explicit bridge job ID")
    parser.add_argument("--attach-timeout", type=float, default=15.0)
    parser.add_argument("--capture-timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--page-load-timeout", type=float, default=30.0)
    parser.add_argument("--keep-open", action="store_true", help="Leave Chrome open after the test")
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List Chrome profile directory names, then exit",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    user_data_dir = Path(args.user_data_dir).expanduser().resolve()
    if args.list_profiles:
        return list_chrome_profiles(user_data_dir)

    if not args.url:
        parser.error("--url is required unless --list-profiles is used")

    try:
        return run_capture(args)
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
