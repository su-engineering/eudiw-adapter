# Copyright 2026 su-engineering. Licensed under the Apache License, Version 2.0.
"""A minimal relying-party backend for eudiw-adapter, standard library only (Python 3.10 or later).

    POST /verifications                 start a session; returns the launch URI and URLs for the browser
    GET  /verifications/{id}/status     {"status": ...} for the <eudiw-request> component
    POST /verifications/{id}/result     fetch the verified claims once (a real app acts on them server-side)
    POST /webhooks/eudiw                signed session notifications from the adapter

The browser only ever sees a random local id. The adapter's client credentials, session id and result stay here.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG = {
    "port": int(os.environ.get("PORT", "3001")),
    # Loopback by default. On Linux, Docker reaches the host only on a non-loopback address (examples/README.md).
    "host": os.environ.get("HOST", "127.0.0.1"),
    "adapter_url": os.environ.get("ADAPTER_URL", "http://localhost:8080").rstrip("/"),
    "token_url": os.environ.get("TOKEN_URL", "http://localhost:8081/realms/demo/protocol/openid-connect/token"),
    "client_id": os.environ.get("CLIENT_ID", "demo-portal"),
    "client_secret": os.environ.get("CLIENT_SECRET", "demo-only-secret"),
    "policy_id": os.environ.get("POLICY_ID", "age-over-18"),
    # What the policy asks for, in the user's words, shown by the component.
    "request_label": os.environ.get("REQUEST_LABEL", "over 18"),
    # whsec_ secrets: the current one, and during a rotation also the previous one.
    "webhook_secrets": [s for s in (os.environ.get("WEBHOOK_SECRET"), os.environ.get("WEBHOOK_PREVIOUS_SECRET")) if s],
}
STATIC = {
    "/": (HERE.parent / "shared" / "index.html", "text/html; charset=utf-8"),
    "/eudiw/eudiw-request.js": (HERE.parent.parent / "clients" / "web" / "eudiw-request.js", "text/javascript"),
    "/eudiw/vendor/qrcode.mjs": (HERE.parent.parent / "clients" / "web" / "vendor" / "qrcode.mjs", "text/javascript"),
}
for _font in ("jetbrains-mono-latin-wght-normal.woff2", "jetbrains-mono-latin-ext-wght-normal.woff2"):
    STATIC[f"/eudiw/fonts/{_font}"] = (HERE.parent.parent / "clients" / "web" / "fonts" / _font, "font/woff2")
LOCAL_PATH = re.compile(r"^/verifications/([A-Za-z0-9_-]{43})/(status|result)$")


class WebhookError(Exception):
    pass


def verify_webhook(raw_body: bytes, headers, secrets_: list, now: float | None = None, tolerance: int = 300) -> dict:
    """Standard Webhooks verification over the raw body. Returns the parsed event, or raises WebhookError."""
    msg_id = headers.get("webhook-id")
    timestamp = headers.get("webhook-timestamp")
    signatures = headers.get("webhook-signature")
    if not msg_id or not timestamp or not signatures or not timestamp.isdigit():
        raise WebhookError("missing webhook headers")
    if abs((time.time() if now is None else now) - int(timestamp)) > tolerance:
        raise WebhookError("webhook timestamp outside tolerance")
    content = f"{msg_id}.{timestamp}.".encode() + raw_body
    expected = [
        hmac.new(base64.b64decode(s.removeprefix("whsec_")), content, hashlib.sha256).digest() for s in secrets_
    ]
    for entry in signatures.split(" "):
        version, _, value = entry.partition(",")
        if version != "v1" or not value:
            continue
        try:
            given = base64.b64decode(value, validate=True)
        except ValueError:
            continue
        if any(hmac.compare_digest(e, given) for e in expected):
            return json.loads(raw_body)
    raise WebhookError("no valid webhook signature")


_token = {"value": None, "expires_at": 0.0}
_token_lock = threading.Lock()


def access_token(trace=None) -> str:
    with _token_lock:
        if _token["value"] and _token["expires_at"] > time.time() + 30:
            return _token["value"]
        if trace:
            trace("backend", "POST token endpoint", "client_credentials")
        data = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": CONFIG["client_id"],
            "client_secret": CONFIG["client_secret"],
        }).encode()
        with urllib.request.urlopen(urllib.request.Request(CONFIG["token_url"], data=data), timeout=10) as r:
            body = json.load(r)
        _token["value"] = body["access_token"]
        _token["expires_at"] = time.time() + body.get("expires_in", 60)
        return _token["value"]


def adapter(method: str, path: str, body: dict | None = None, idempotency_key: str | None = None, trace=None):
    headers = {"Authorization": f"Bearer {access_token(trace)}", "Accept": "application/json"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    request = urllib.request.Request(CONFIG["adapter_url"] + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=15) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, None


# Local id (random, given to the browser) -> {adapter session id, status, trace}. Use your database in a real
# application. The trace records what this backend did, so the example page can show it; it never holds claims.
sessions: dict[str, dict] = {}


def tracer(events: list):
    def add(actor: str, event: str, detail: str = ""):
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int(time.time() * 1000) % 1000:03d}Z"
        events.append({"at": stamp, "actor": actor, "event": event, "detail": detail})
    return add


class Handler(BaseHTTPRequestHandler):
    def send(self, status: int, body, content_type: str = "application/json"):
        payload = json.dumps(body).encode() if content_type == "application/json" else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path in STATIC:
            file, content_type = STATIC[path]
            return self.send(200, file.read_bytes(), content_type)
        match = LOCAL_PATH.match(path)
        if match and match.group(2) == "status" and match.group(1) in sessions:
            session = sessions[match.group(1)]
            status, body = adapter("GET", f"/v1/verification-sessions/{session['id']}")
            if status != 200:
                return self.send(404, {})
            if body["status"] != session["status"]:
                session["status"] = body["status"]
                reason = f" ({body['reason']})" if body.get("reason") else ""
                tracer(session["trace"])("backend", "GET /v1/verification-sessions/{id}", body["status"] + reason)
            return self.send(200, {"status": session["status"], "expires_at": body["expires_at"],
                                   "trace": session["trace"]})
        self.send(404, {"error": "not_found"})

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        if length > 64 * 1024:
            return self.send(413, {"error": "too_large"})
        raw = self.rfile.read(length)
        if path == "/verifications":
            events: list = []
            trace = tracer(events)
            trace("browser", "POST /verifications")
            status, body = adapter(
                "POST",
                "/v1/verification-sessions",
                {"policy_id": CONFIG["policy_id"], "mode": "cross_device"},
                str(uuid.uuid4()),
                trace,
            )
            trace("backend", "POST /v1/verification-sessions", f"{status} {(body or {}).get('status', '')}".strip())
            if status != 201:
                return self.send(502, {"error": "could_not_start"})
            local = secrets.token_urlsafe(32)
            sessions[local] = {"id": body["id"], "status": body["status"], "trace": events}
            return self.send(201, {
                "launch_uri": body["wallet_launch"]["launch_uri"],
                "expires_at": body["expires_at"],
                "request_label": CONFIG["request_label"],
                "status_url": f"/verifications/{local}/status",
                "result_url": f"/verifications/{local}/result",
                "trace": events,
            })
        match = LOCAL_PATH.match(path)
        if match and match.group(2) == "result" and match.group(1) in sessions:
            session = sessions.pop(match.group(1))
            status, body = adapter("GET", f"/v1/verification-sessions/{session['id']}/result")
            tracer(session["trace"])("backend", "GET /v1/verification-sessions/{id}/result", str(status))
            if status != 200:
                return self.send(404, {})
            return self.send(200, {"claims": body["claims"], "trace": session["trace"]})
        if path == "/webhooks/eudiw":
            headers = {k.lower(): v for k, v in self.headers.items()}
            try:
                event = verify_webhook(raw, headers, CONFIG["webhook_secrets"])
            except (WebhookError, ValueError, KeyError, TypeError):
                return self.send(401, {"error": "invalid_signature"})
            # {type, timestamp, data: {id, status, policy_id, reason?, client_reference?}}, never claims.
            data = event["data"]
            print(f"webhook: session {data['id']} is {data['status']}", flush=True)
            # A real application would update its own record here. The example adds it to the session's trace.
            for session in list(sessions.values()):
                if session["id"] == data["id"]:
                    tracer(session["trace"])("adapter", "POST /webhooks/eudiw", f"{data['status']} · signature valid")
            self.send_response(204)
            self.end_headers()
            return None
        self.send(404, {"error": "not_found"})

    def log_message(self, format, *args):  # keep request URLs, which carry local ids, out of the log
        pass


if __name__ == "__main__":
    print(f"example backend on http://localhost:{CONFIG['port']}", flush=True)
    ThreadingHTTPServer((CONFIG["host"], CONFIG["port"]), Handler).serve_forever()
