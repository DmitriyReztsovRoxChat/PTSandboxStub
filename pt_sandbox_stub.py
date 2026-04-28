#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import socket
import sys
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

LISTEN_HOST_DEFAULT = "0.0.0.0"
PORT_DEFAULT = 8090
UPLOAD_PATH = "/api/v1/storage/uploadScanFile"
SCAN_PATH = "/api/v1/analysis/createScanTask"

VERDICT_STEMS = frozenset({"SKIP", "PASS", "FAIL", "ERROR"})

# PT-style verdicts used by Webim wm_files_security.PTSandbox
VERDICT_CLEAN = "CLEAN"
VERDICT_UNWANTED = "UNWANTED"
VERDICT_DANGEROUS = "DANGEROUS"
VERDICT_UNKNOWN_FOR_ERROR = "UNKNOWN"  # not handled by client -> ERROR

SCAN_STATE_FULL = "FULL"

_file_uri_registry: set[str] = set()
_file_uri_lock = threading.Lock()
_allowed_ext: frozenset[str] | None = None


def _load_allowed_extensions() -> frozenset[str]:
    global _allowed_ext
    if _allowed_ext is not None:
        return _allowed_ext
    json_path = Path(__file__).resolve().parent / "allowed_upload_extensions.json"
    if not json_path.is_file():
        raise FileNotFoundError(f"Missing allowlist: {json_path}")
    data = json.loads(json_path.read_text(encoding="utf-8"))
    _allowed_ext = frozenset(str(x).lower() for x in data)
    return _allowed_ext


def _split_stem_ext(file_name: str) -> tuple[str, str]:
    if "." not in file_name:
        return file_name, ""
    stem, ext = file_name.rsplit(".", 1)
    return stem, ext.lower()


def _scenario_from_file_name(file_name: str | None) -> str:
    """
    Returns one of: PASS, FAIL, ERROR, SKIP (SKIP treated like PASS at HTTP level).
    Default PASS when stem does not exactly match or extension not allowed.
    """
    if not file_name:
        return "PASS"
    stem, ext = _split_stem_ext(file_name)
    allowed = _load_allowed_extensions()
    if ext not in allowed:
        return "PASS"
    if stem not in VERDICT_STEMS:
        return "PASS"
    return stem


def _new_file_uri() -> str:
    slug = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H")
    u1 = str(uuid.uuid4())
    u2 = str(uuid.uuid4())
    return f"sfm-files:///{slug}/{u1}/{u2}"


def _json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


def _assert_port_available(host: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
    except OSError as e:
        if getattr(e, "errno", None) in (98, 48) or "Address already in use" in str(e):
            logging.error("Порт %s:%s уже занят. Освободите порт или укажите --port.", host, port)
            sys.exit(1)
        raise
    finally:
        sock.close()


class PTSandboxStubHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        logging.info("%s - %s", self.address_string(), fmt % args)

    def _send(self, code: int, body: bytes, content_type: str = "application/json; charset=utf-8") -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code: int, obj: dict) -> None:
        payload = _json_bytes(obj)
        self._send(code, payload)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def do_POST(self) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        upload_p = UPLOAD_PATH.rstrip("/")
        scan_p = SCAN_PATH.rstrip("/")
        if path == upload_p:
            self._handle_upload()
        elif path == scan_p:
            self._handle_scan()
        else:
            self._send_json(
                404,
                {
                    "data": {},
                    "errors": [{"type": "HTTPNotFound", "message": f"Unknown path {path}"}],
                },
            )

    def _handle_upload(self) -> None:
        # Length required for octet-stream body
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length) if length else b""

        uri = _new_file_uri()
        with _file_uri_lock:
            _file_uri_registry.add(uri)

        body = {
            "data": {"file_uri": uri, "ttl": 3600},
            "errors": [],
        }
        logging.info("uploadScanFile -> 200 file_uri issued")
        self._send_json(200, body)

    def _handle_scan(self) -> None:
        payload = self._read_json_body()
        file_uri = payload.get("file_uri")
        file_name = payload.get("file_name")

        with _file_uri_lock:
            known = file_uri in _file_uri_registry if file_uri else False

        if not file_uri or not known:
            logging.warning("createScanTask -> 404 unknown or missing file_uri")
            self._send_json(
                404,
                {
                    "data": {},
                    "errors": [
                        {
                            "type": "HTTPNotFound",
                            "message": f'File "{file_uri}" not found',
                        }
                    ],
                },
            )
            return

        scenario = _scenario_from_file_name(file_name if isinstance(file_name, str) else None)
        # HTTP-level: SKIP имитируем как успешный CLEAN (см. модульный docstring).
        if scenario == "ERROR":
            result = {
                "scan_state": SCAN_STATE_FULL,
                "verdict": VERDICT_UNKNOWN_FOR_ERROR,
                "threat": "STUB",
                "errors": [],
            }
            logging.info("createScanTask -> 200 scenario=ERROR (unknown verdict)")
            self._send_json(200, {"data": {"result": result}, "errors": []})
            return

        if scenario == "FAIL":
            verdict = VERDICT_DANGEROUS
            threat = "VIRUS"
        else:
            verdict = VERDICT_CLEAN
            threat = "NONE"

        result = {
            "scan_state": SCAN_STATE_FULL,
            "verdict": verdict,
            "threat": threat,
            "errors": [],
        }
        logging.info("createScanTask -> 200 scenario=%s verdict=%s", scenario, verdict)
        self._send_json(200, {"data": {"result": result}, "errors": []})

    def do_GET(self) -> None:
        self.send_error(405, "Method Not Allowed")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PT Sandbox API stub for Webim (port 8090 by default).",
        epilog=(
            "Allowlist: allowed_upload_extensions.json рядом с этим скриптом. "
            "Обновление: python3 tools/pt_sandbox_mock/regenerate_allowed_extensions.py"
        ),
    )
    parser.add_argument("--host", default=LISTEN_HOST_DEFAULT, help="Bind address (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=PORT_DEFAULT, help="TCP port (default 8090)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    _load_allowed_extensions()
    _assert_port_available(args.host, args.port)

    server = ThreadingHTTPServer((args.host, args.port), PTSandboxStubHandler)
    server.daemon_threads = True
    logging.info("PT Sandbox stub listening on http://%s:%s", args.host, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
