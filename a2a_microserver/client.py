"""A2A microserver: outbound SSE client for the Agent Authority relay.

Message pipe only. Receives messages via SSE, re-verifies sender
signatures, stores them locally for the bot, posts replies back.
"""

import http.client
import http.server
import json
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from a2a_microserver.crypto import (
    CONNECT_PROFILE,
    SEND_PROFILE,
    RegistryClient,
    sign_headers,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

LOCAL_PORT = int(os.environ.get("A2A_LOCAL_PORT", "8421"))
RELAY_ORIGIN = os.environ.get("A2A_RELAY_ORIGIN", "https://a2a.agentauthority.org")
REGISTRY_ORIGIN = os.environ.get("AA_REGISTRY_ORIGIN", "https://agentauthority.org")
AGENT_ID = os.environ.get("A2A_AGENT_ID", "")
AGENT_ADDRESS = os.environ.get("A2A_AGENT_ADDRESS", "")
KEY_FILE = os.environ.get("A2A_KEY_FILE", os.path.expanduser("~/.a2a-direct/agent.key"))
RECONNECT_DELAY = int(os.environ.get("A2A_RECONNECT_DELAY", "5"))

agent_key = None
registry_client: RegistryClient = None  # type: ignore[assignment]

pending_messages: dict[str, dict] = {}
pending_lock = threading.Lock()


def load_key(path):
    if os.stat(path).st_mode & 0o077:
        sys.exit(f"Key {path} is group/other readable — run: chmod 600 {path}")
    with open(path, "rb") as f:
        raw = f.read()
    if len(raw) == 32:
        return Ed25519PrivateKey.from_private_bytes(raw)
    return serialization.load_pem_private_key(raw, password=None)


def post_reply(task_id, text):
    reply_url = f"{RELAY_ORIGIN}/{AGENT_ADDRESS}/reply"
    body = json.dumps(
        {"task_id": task_id, "message": {"role": "agent", "parts": [{"kind": "text", "text": text}]}}
    ).encode()
    hdrs = sign_headers(agent_key, AGENT_ID, reply_url, body, profile=SEND_PROFILE)
    hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(reply_url, data=body, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            print(f"reply posted: {json.loads(r.read())}", file=sys.stderr)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        print(f"reply post failed: {e}", file=sys.stderr)


def send_ack(task_id, status, reason=None):
    ack_url = f"{RELAY_ORIGIN}/{AGENT_ADDRESS}/ack"
    payload = {"task_id": task_id, "status": status}
    if reason:
        payload["reason"] = reason
    body = json.dumps(payload).encode()
    hdrs = sign_headers(agent_key, AGENT_ID, ack_url, body, profile=SEND_PROFILE)
    hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(ack_url, data=body, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10):
            print(f"ack sent: {status} task {task_id[:8]}", file=sys.stderr)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        print(f"ack failed: {e}", file=sys.stderr)


def handle_sse_event(event):
    task_id = event.get("task_id", "")
    sender = event.get("sender_agent_id", "")

    raw_body = event.get("body")
    sender_headers = event.get("sender_headers", {})
    if raw_body and sender_headers:
        recipient_url = f"{RELAY_ORIGIN}/{AGENT_ADDRESS}/"
        ok, _code, msg, _aid = registry_client.verify_sender(
            raw_body.encode() if isinstance(raw_body, str) else raw_body,
            sender_headers,
            recipient_url,
            profile=SEND_PROFILE,
            skip_replay=True,
        )
        if not ok:
            print(f"re-verify failed for {sender} on task {task_id}: {msg}", file=sys.stderr)
            send_ack(task_id, "rejected", reason=msg)
            return

    try:
        rpc = json.loads(raw_body) if raw_body else {}
        message = rpc.get("params", {}).get("message", {})
    except (json.JSONDecodeError, AttributeError):
        message = {}

    with pending_lock:
        pending_messages[task_id] = {"task_id": task_id, "sender": sender, "message": message}
    print(f"message verified and stored: {sender} task {task_id[:8]}", file=sys.stderr)
    send_ack(task_id, "accepted")


def sse_connect():
    connect_url = f"{RELAY_ORIGIN}/{AGENT_ADDRESS}/connect"
    hdrs = sign_headers(agent_key, AGENT_ID, connect_url, profile=CONNECT_PROFILE)

    parsed = urllib.parse.urlparse(connect_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path

    if parsed.scheme == "https":
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=300)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=300)

    try:
        conn.request("GET", path, headers=hdrs)
        resp = conn.getresponse()
        if resp.status != 200:
            body = resp.read().decode()[:200]
            print(f"connect rejected: {resp.status} {body}", file=sys.stderr)
            return

        print("connected to relay", file=sys.stderr)
        while True:
            line = resp.readline()
            if not line:
                break
            line = line.decode().strip()
            if line.startswith("data: "):
                try:
                    event = json.loads(line[6:])
                    threading.Thread(target=handle_sse_event, args=(event,), daemon=True).start()
                except json.JSONDecodeError:
                    pass
    finally:
        conn.close()


def sse_loop():
    while True:
        try:
            sse_connect()
        except (OSError, http.client.HTTPException) as e:
            print(f"sse disconnected: {e}", file=sys.stderr)
        print(f"reconnecting in {RECONNECT_DELAY}s", file=sys.stderr)
        time.sleep(RECONNECT_DELAY)


class LocalHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[local {self.log_date_time_string()}] {fmt % args}", file=sys.stderr)

    def do_GET(self):
        if self.path == "/tasks/pending":
            with pending_lock:
                ids = list(pending_messages.keys())
            return self._json({"tasks": ids})

        if self.path.startswith("/tasks/") and not self.path.endswith("/reply"):
            task_id = self.path.split("/")[2]
            with pending_lock:
                msg = pending_messages.get(task_id)
            if not msg:
                return self._json({"error": "not found"}, 404)
            return self._json(msg)

        self.send_error(404)

    def do_POST(self):
        if not (self.path.startswith("/tasks/") and self.path.endswith("/reply")):
            self.send_error(404)
            return
        task_id = self.path.split("/")[2]
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            reply = json.loads(body)
        except json.JSONDecodeError:
            return self._json({"error": "bad json"}, 400)

        text = reply.get("text", "")
        with pending_lock:
            pending_messages.pop(task_id, None)
        threading.Thread(target=post_reply, args=(task_id, text), daemon=True).start()
        self._json({"ok": True, "task_id": task_id})

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    global agent_key, registry_client

    for var in ("A2A_AGENT_ID", "A2A_AGENT_ADDRESS"):
        if not os.environ.get(var):
            sys.exit(f"Set {var}")

    agent_key = load_key(KEY_FILE)
    registry_client = RegistryClient(REGISTRY_ORIGIN)

    local_srv = http.server.HTTPServer(("127.0.0.1", LOCAL_PORT), LocalHandler)
    threading.Thread(target=local_srv.serve_forever, daemon=True).start()
    print(f"Local on 127.0.0.1:{LOCAL_PORT}", file=sys.stderr)
    print(f"Relay: {RELAY_ORIGIN}/{AGENT_ADDRESS}/connect", file=sys.stderr)

    try:
        sse_loop()
    except KeyboardInterrupt:
        print("\nbye", file=sys.stderr)
        local_srv.shutdown()
