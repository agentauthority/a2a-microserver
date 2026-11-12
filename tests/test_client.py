"""Tests for the microserver client: local server and SSE event handling."""

import http.server
import json
import os
import stat
import tempfile
import threading
import time
import unittest
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a2a_microserver import client
from a2a_microserver.crypto import SEND_PROFILE, RegistryClient, b64url_encode, sign_headers


# ---- Fake registry ----

SENDER_KEY = Ed25519PrivateKey.generate()
SENDER_PUBKEY = b64url_encode(SENDER_KEY.public_key().public_bytes_raw())
SENDER_ID = "sender-001"
AGENT_KEY = Ed25519PrivateKey.generate()
AGENT_ID = "agent-001"
AGENT_ADDRESS = "@testowner/testagent"


class FakeRegistry(RegistryClient):
    def __init__(self):
        super().__init__("https://fake")
        self._agents = {
            SENDER_ID: (
                SENDER_PUBKEY,
                {"registration": "active", "authority": "valid", "verified": True, "disputed": False},
            ),
        }

    def agent_status(self, agent_id):
        if agent_id not in self._agents:
            raise LookupError(agent_id)
        return self._agents[agent_id]


# ---- Tests ----


class TestLoadKey(unittest.TestCase):
    def test_raw_32_bytes(self):
        key = Ed25519PrivateKey.generate()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(key.private_bytes_raw())
            path = f.name
        os.chmod(path, 0o600)
        try:
            loaded = client.load_key(path)
            assert loaded.private_bytes_raw() == key.private_bytes_raw()
        finally:
            os.unlink(path)

    def test_rejects_world_readable(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"x" * 32)
            path = f.name
        os.chmod(path, 0o644)
        try:
            with self.assertRaises(SystemExit):
                client.load_key(path)
        finally:
            os.unlink(path)


class TestHandleSSEEvent(unittest.TestCase):
    def setUp(self):
        client.registry_client = FakeRegistry()
        client.agent_key = AGENT_KEY
        client.AGENT_ID = AGENT_ID
        client.AGENT_ADDRESS = AGENT_ADDRESS
        client.RELAY_ORIGIN = "http://localhost:9999"
        with client.pending_lock:
            client.pending_messages.clear()

    def test_verified_message_stored(self):
        url = f"{client.RELAY_ORIGIN}/{AGENT_ADDRESS}/"
        rpc_body = json.dumps(
            {"jsonrpc": "2.0", "method": "SendMessage", "params": {"message": {"role": "user", "parts": [{"kind": "text", "text": "hello"}]}}}
        )
        hdrs = sign_headers(SENDER_KEY, SENDER_ID, url, rpc_body.encode())
        event = {
            "task_id": "task-abc",
            "sender_agent_id": SENDER_ID,
            "body": rpc_body,
            "sender_headers": hdrs,
        }
        # send_ack will fail (no relay running) but that's fine — we test storage
        client.handle_sse_event(event)
        with client.pending_lock:
            assert "task-abc" in client.pending_messages
            msg = client.pending_messages["task-abc"]
        assert msg["message"]["role"] == "user"

    def test_bad_signature_rejected(self):
        url = f"{client.RELAY_ORIGIN}/{AGENT_ADDRESS}/"
        rpc_body = json.dumps({"jsonrpc": "2.0", "method": "SendMessage", "params": {"message": {}}})
        wrong_key = Ed25519PrivateKey.generate()
        hdrs = sign_headers(wrong_key, SENDER_ID, url, rpc_body.encode())
        event = {
            "task_id": "task-bad",
            "sender_agent_id": SENDER_ID,
            "body": rpc_body,
            "sender_headers": hdrs,
        }
        client.handle_sse_event(event)
        with client.pending_lock:
            assert "task-bad" not in client.pending_messages


class TestLocalServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        client.agent_key = AGENT_KEY
        client.AGENT_ID = AGENT_ID
        client.AGENT_ADDRESS = AGENT_ADDRESS
        client.RELAY_ORIGIN = "http://localhost:9999"
        with client.pending_lock:
            client.pending_messages.clear()
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), client.LocalHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        with client.pending_lock:
            client.pending_messages.clear()

    def _get(self, path):
        url = f"http://127.0.0.1:{self.port}{path}"
        with urllib.request.urlopen(url, timeout=2) as r:
            return json.loads(r.read())

    def _post(self, path, body):
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=2) as r:
            return json.loads(r.read())

    def test_pending_empty(self):
        assert self._get("/tasks/pending") == {"tasks": []}

    def test_pending_with_task(self):
        with client.pending_lock:
            client.pending_messages["t1"] = {"task_id": "t1", "sender": "s", "message": {}}
        result = self._get("/tasks/pending")
        assert "t1" in result["tasks"]

    def test_get_task(self):
        with client.pending_lock:
            client.pending_messages["t2"] = {"task_id": "t2", "sender": "s", "message": {"text": "hi"}}
        result = self._get("/tasks/t2")
        assert result["task_id"] == "t2"

    def test_get_missing_task(self):
        try:
            self._get("/tasks/nonexistent")
            assert False, "should have raised"
        except urllib.error.HTTPError as e:
            assert e.code == 404

    def test_post_reply_removes_task(self):
        with client.pending_lock:
            client.pending_messages["t3"] = {"task_id": "t3", "sender": "s", "message": {}}
        result = self._post("/tasks/t3/reply", {"text": "done"})
        assert result["ok"]
        time.sleep(0.1)
        with client.pending_lock:
            assert "t3" not in client.pending_messages
