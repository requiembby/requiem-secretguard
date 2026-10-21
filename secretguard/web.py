"""Localhost-only dashboard server. No dependencies, external calls or telemetry.

The browser's folder picker uploads text only to the *local* Python process on
127.0.0.1. This module never writes these contents to disk.
"""
from __future__ import annotations

import argparse
import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from urllib.parse import urlsplit

from .scanner import scan_documents

MAX_BODY_BYTES = 12_000_000
MAX_FILES = 1000
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
ROUTES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}


def demo_report() -> dict:
    return scan_documents([
        {"path": ".env", "content": "APP_MODE=dev\nSTRIPE_SECRET=sk_live_" + "D" * 24 + "\n"},
        {"path": "config.py", "content": "GITHUB_TOKEN = 'ghp_" + "S" * 36 + "'\n"},
        {"path": "README.md", "content": "# Safe demo: invented patterns, no actual credentials\n"},
    ], target="Synthetic demo (no real keys)")


class LocalHandler(BaseHTTPRequestHandler):
    server_version = "SecretGuard/0.3"
    sys_version = ""

    def log_message(self, format, *args):  # no paths, body, tokens, or client details in logs
        pass

    def _headers(self, status: int, kind: str, length: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", CSP)
        self.end_headers()

    def _send(self, status: int, content: bytes, kind: str) -> None:
        self._headers(status, kind, len(content))
        self.wfile.write(content)

    def _json(self, status: int, data: dict) -> None:
        self._send(status, json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _host_ok(self) -> bool:
        host = self.headers.get("Host", "")
        return host in (f"127.0.0.1:{self.server.server_port}",
                        f"localhost:{self.server.server_port}")

    def do_GET(self) -> None:
        if not self._host_ok():
            self._json(403, {"error": "Unrecognized host"})
            return
        route = urlsplit(self.path).path
        # Local test fixture: invented patterns for validating the extension.
        # Deliberately constructed at runtime so scanning this repository does
        # not mistake these harmless demonstration strings for real leaks.
        if route == "/extension-demo":
            html = ("<!doctype html><html lang='en'><meta charset='utf-8'>"
                    "<title>SecretGuard Extension Demo</title>"
                    "<link rel='stylesheet' href='/style.css'>"
                    "<main class='content'><section class='intro'>"
                    "<div class='eyebrow'>REQUIEM / SAFE TEST</div>"
                    "<h1>SecretGuard <span>Extension Demo.</span></h1>"
                    "<p>This page includes two synthetic, invalid credential patterns "
                    "in a same-origin JavaScript file. Nothing here is a real key.</p>"
                    "</section><section class='scan-panel'><h2>How to test</h2>"
                    "<p>Click the Chrome extension, confirm authorization and run the scan. "
                    "Expected: a critical Stripe pattern and a high GitHub pattern.</p>"
                    "<a href='/'>Back to dashboard</a></section></main>"
                    "<script src='/extension-demo.js'></script></html>")
            self._send(200, html.encode('utf-8'), 'text/html; charset=utf-8')
            return
        if route == "/extension-demo.js":
            javascript = ("const syntheticExample = {stripe: 'sk_live_" + "D" * 24
                          + "', github: 'ghp_" + "S" * 36
                          + "'}; // Fake values for safe, local extension testing\n")
            self._send(200, javascript.encode('utf-8'), 'application/javascript; charset=utf-8')
            return
        asset = ROUTES.get(route)
        if asset is None:
            self._json(404, {"error": "Not found"})
            return
        filename, mime = asset
        body = files("secretguard").joinpath("webui", filename).read_bytes()
        self._send(200, body, mime)

    def do_POST(self) -> None:
        if not self._host_ok():
            self._json(403, {"error": "Unrecognized host"})
            return
        host = self.headers.get("Host", "")
        origin = self.headers.get("Origin", "")
        if origin not in (f"http://{host}",) or self.headers.get("X-SecretGuard-Request") != "local-ui":
            self._json(403, {"error": "Only requests from the local dashboard are allowed"})
            return
        route = urlsplit(self.path).path
        if route not in ("/api/scan", "/api/demo"):
            self._json(404, {"error": "Not found"})
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0].lower() != "application/json":
            self._json(415, {"error": "JSON required"})
            return
        try:
            body_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            body_length = 0
        if not 0 < body_length <= MAX_BODY_BYTES:
            self._json(413, {"error": "Request too large or empty (maximum 12 MB)"})
            return
        try:
            request = json.loads(self.rfile.read(body_length))
            if not isinstance(request, dict):
                raise ValueError("Expected JSON object")
            if route == "/api/demo":
                result = demo_report()
            else:
                documents = request.get("files")
                if not isinstance(documents, list) or not documents:
                    raise ValueError("Select a folder containing files")
                if len(documents) > MAX_FILES:
                    raise ValueError(f"Select fewer than {MAX_FILES + 1} files")
                result = scan_documents(documents, target=request.get("folder", "Browser-selected folder"),
                                        max_files=MAX_FILES)
            self._json(200, result)
        except (ValueError, UnicodeError, TypeError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)[:300]})


def create_server(port: int = 8765) -> ThreadingHTTPServer:
    if not 0 <= port <= 65535:
        raise ValueError("Port must be 0-65535")
    server = ThreadingHTTPServer(("127.0.0.1", port), LocalHandler)
    server.daemon_threads = True
    return server


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Local REQUIEM SecretGuard dashboard")
    parser.add_argument("--port", type=int, default=8765, help="Localhost port (default 8765)")
    parser.add_argument("--no-browser", action="store_true", help="Don't open the browser automatically")
    args = parser.parse_args(argv)
    try:
        with create_server(args.port) as server:
            url = f"http://127.0.0.1:{server.server_port}/"
            print("REQUIEM SecretGuard v0.3 · LOCAL WEB UI")
            print("Dashboard:", url)
            print("No cloud connection. Keep this terminal open; Ctrl+C to stop.")
            if not args.no_browser:
                threading.Timer(0.6, webbrowser.open, [url]).start()
            try:
                server.serve_forever(poll_interval=0.2)
            except KeyboardInterrupt:
                print("\nSecretGuard stopped.")
    except OSError as exc:
        print(f"Cannot start local dashboard: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
