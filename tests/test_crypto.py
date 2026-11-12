"""Tests for crypto: signing, verification, canonical encoding."""

import json
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a2a_microserver.crypto import (
    SEND_PROFILE,
    RegistryClient,
    b64url_decode,
    b64url_encode,
    canonical,
    sign_headers,
)


class TestCanonical(unittest.TestCase):
    def test_deterministic_key_order(self):
        assert canonical({"b": 1, "a": 2}) == b'{"a":2,"b":1}'

    def test_no_spaces(self):
        assert b" " not in canonical({"x": [1, 2, 3]})


class TestBase64Url(unittest.TestCase):
    def test_roundtrip(self):
        data = b"\xff\x00\xab"
        assert b64url_decode(b64url_encode(data)) == data


class TestSignHeaders(unittest.TestCase):
    def test_all_headers_present(self):
        key = Ed25519PrivateKey.generate()
        hdrs = sign_headers(key, "agent-1", "https://example.com/target", b"body")
        for h in ("X-AA-Agent-Id", "X-AA-Timestamp", "X-AA-Nonce", "X-AA-Signature"):
            assert h in hdrs

    def test_body_optional(self):
        key = Ed25519PrivateKey.generate()
        hdrs = sign_headers(key, "agent-1", "https://example.com/target")
        assert "X-AA-Signature" in hdrs


SENDER_KEY = Ed25519PrivateKey.generate()
SENDER_PUBKEY = b64url_encode(SENDER_KEY.public_key().public_bytes_raw())
SENDER_ID = "test-sender"


class FakeRegistry(RegistryClient):
    def __init__(self, agents=None):
        super().__init__("https://fake")
        self._agents = agents or {}

    def agent_status(self, agent_id):
        if agent_id not in self._agents:
            raise LookupError(agent_id)
        return self._agents[agent_id]


def active_status():
    return {"registration": "active", "authority": "valid", "verified": True, "disputed": False}


class TestVerifySender(unittest.TestCase):
    def setUp(self):
        self.reg = FakeRegistry({SENDER_ID: (SENDER_PUBKEY, active_status())})
        self.url = "https://relay.example.com/@owner/agent/"

    def test_valid_signature(self):
        body = b'{"test": true}'
        hdrs = sign_headers(SENDER_KEY, SENDER_ID, self.url, body)
        ok, code, msg, aid = self.reg.verify_sender(body, hdrs, self.url, skip_replay=True)
        assert ok
        assert aid == SENDER_ID

    def test_missing_headers(self):
        ok, code, msg, aid = self.reg.verify_sender(b"body", {}, self.url, skip_replay=True)
        assert not ok
        assert code == -32010

    def test_wrong_key(self):
        wrong = Ed25519PrivateKey.generate()
        body = b"hello"
        hdrs = sign_headers(wrong, SENDER_ID, self.url, body)
        ok, code, msg, aid = self.reg.verify_sender(body, hdrs, self.url, skip_replay=True)
        assert not ok
        assert code == -32014

    def test_unknown_agent(self):
        body = b"hello"
        hdrs = sign_headers(SENDER_KEY, "unknown-agent", self.url, body)
        ok, code, msg, aid = self.reg.verify_sender(body, hdrs, self.url, skip_replay=True)
        assert not ok
        assert code == -32013

    def test_inactive_agent(self):
        inactive = {"registration": "revoked", "authority": "valid", "verified": True, "disputed": False}
        reg = FakeRegistry({SENDER_ID: (SENDER_PUBKEY, inactive)})
        body = b"hello"
        hdrs = sign_headers(SENDER_KEY, SENDER_ID, self.url, body)
        ok, code, msg, aid = reg.verify_sender(body, hdrs, self.url, skip_replay=True)
        assert not ok
        assert code == -32013
