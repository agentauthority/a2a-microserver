"""Crypto helpers: Ed25519 signing, verification, and registry client."""

import base64
import hashlib
import json
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SEND_PROFILE = "aor-a2a-send-v1"
CONNECT_PROFILE = "aor-a2a-connect-v1"
SIGNATURE_WINDOW_MS = 5 * 60 * 1000
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")

SIG_MISSING = -32010
SIG_TIMESTAMP = -32011
SIG_REPLAY = -32012
SIG_AGENT = -32013
SIG_BAD = -32014
SIG_REGISTRY = -32015


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64url_decode(s):
    return base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_", validate=True)


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def sign_headers(key, agent_id, recipient_url, body=None, *, profile=SEND_PROFILE):
    timestamp = int(time.time() * 1000)
    nonce = secrets.token_hex(16)
    payload = {
        "profile": profile,
        "agent_id": agent_id,
        "recipient": recipient_url.rstrip("/"),
        "timestamp": timestamp,
        "nonce": nonce,
    }
    if body is not None:
        payload["body_digest"] = sha256_hex(body)
    return {
        "X-AA-Agent-Id": agent_id,
        "X-AA-Timestamp": str(timestamp),
        "X-AA-Nonce": nonce,
        "X-AA-Signature": b64url_encode(key.sign(canonical(payload))),
    }


class RegistryClient:
    """Cached lookups against the AA public registry."""

    def __init__(self, origin, *, trust_key_ttl=300, status_ttl=60):
        self.origin = origin
        self._trust_key = None
        self._trust_key_expires = 0.0
        self._trust_key_ttl = trust_key_ttl
        self._status_cache = {}
        self._status_ttl = status_ttl
        self._seen_nonces = {}

    def trust_key(self):
        now = time.monotonic()
        if self._trust_key and now < self._trust_key_expires:
            return self._trust_key
        url = f"{self.origin}/api/public/trust-key"
        with urllib.request.urlopen(urllib.request.Request(url), timeout=5) as r:
            self._trust_key = json.loads(r.read())["public_key"]
        self._trust_key_expires = now + self._trust_key_ttl
        return self._trust_key

    def _verify_envelope(self, envelope):
        key = self.trust_key()
        if not isinstance(envelope, dict) or set(envelope) != {"profile", "payload", "signature"}:
            raise ValueError("bad envelope")
        if envelope["profile"] != "aor-ed25519-json-v1":
            raise ValueError("bad envelope profile")
        Ed25519PublicKey.from_public_bytes(b64url_decode(key)).verify(
            b64url_decode(envelope["signature"]), canonical(envelope["payload"])
        )
        return envelope["payload"]

    def agent_status(self, agent_id):
        now = time.monotonic()
        cached = self._status_cache.get(agent_id)
        if cached and now < cached["expires"]:
            return cached["public_key"], cached["status"]

        nonce = secrets.token_hex(16)
        safe_id = urllib.parse.quote(agent_id, safe="")
        url = f"{self.origin}/api/public/agents/{safe_id}?nonce={nonce}"
        try:
            with urllib.request.urlopen(urllib.request.Request(url), timeout=5) as r:
                envelope = json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise LookupError(agent_id) from None
            raise

        p = self._verify_envelope(envelope)
        if p.get("profile") != "aor-status-v1" or p.get("agent_id") != agent_id or p.get("nonce") != nonce:
            raise ValueError("bad status")

        current = next(a for a in p["history"] if a["id"] == p["current_acceptance"])
        status = {
            "registration": p["registration"],
            "authority": p["authority"],
            "verified": p["verified"],
            "disputed": p["disputed"],
        }
        self._status_cache[agent_id] = {
            "public_key": current["public_key"],
            "status": status,
            "expires": now + self._status_ttl,
        }
        return current["public_key"], status

    def _prune_nonces(self):
        now_ms = int(time.time() * 1000)
        for k in [k for k, v in self._seen_nonces.items() if v <= now_ms]:
            del self._seen_nonces[k]

    def verify_sender(self, body_bytes, headers, recipient_url, *, profile=SEND_PROFILE, skip_replay=False):
        """Verify X-AA-* signature. Returns (ok, code, msg, agent_id)."""
        h = {k.lower(): v for k, v in (headers.items() if hasattr(headers, "items") else [])}
        agent_id = h.get("x-aa-agent-id", "").strip()
        ts_str = h.get("x-aa-timestamp", "").strip()
        nonce = h.get("x-aa-nonce", "").strip()
        sig = h.get("x-aa-signature", "").strip()

        if not all([agent_id, ts_str, nonce, sig]):
            return False, SIG_MISSING, "Missing X-AA-* headers", None

        try:
            timestamp = int(ts_str)
        except ValueError:
            return False, SIG_TIMESTAMP, "Invalid timestamp", None

        if not skip_replay:
            now_ms = int(time.time() * 1000)
            if abs(now_ms - timestamp) > SIGNATURE_WINDOW_MS:
                return False, SIG_TIMESTAMP, "Timestamp outside window", None
            if not NONCE_RE.match(nonce):
                return False, SIG_MISSING, "Invalid nonce", None
            self._prune_nonces()
            if nonce in self._seen_nonces:
                return False, SIG_REPLAY, "Nonce already used", None

        try:
            public_key, status = self.agent_status(agent_id)
        except LookupError:
            print(f"sig: unknown agent {agent_id}", file=sys.stderr)
            return False, SIG_AGENT, "Unknown agent", None
        except (urllib.error.URLError, OSError, ValueError, KeyError):
            print(f"sig: registry unavailable for {agent_id}", file=sys.stderr)
            return False, SIG_REGISTRY, "Registry unavailable", None

        if (
            status["registration"] != "active"
            or status["authority"] != "valid"
            or not status["verified"]
            or status["disputed"]
        ):
            print(f"sig: inactive agent {agent_id}", file=sys.stderr)
            return False, SIG_AGENT, "Agent not active", None

        payload = {
            "profile": profile,
            "agent_id": agent_id,
            "recipient": recipient_url.rstrip("/"),
            "timestamp": timestamp,
            "nonce": nonce,
        }
        if body_bytes is not None:
            payload["body_digest"] = sha256_hex(body_bytes)

        try:
            Ed25519PublicKey.from_public_bytes(b64url_decode(public_key)).verify(b64url_decode(sig), canonical(payload))
        except (ValueError, TypeError, InvalidSignature):
            print(f"sig: bad signature from {agent_id}", file=sys.stderr)
            return False, SIG_BAD, "Signature failed", None

        if not skip_replay:
            self._seen_nonces[nonce] = timestamp + SIGNATURE_WINDOW_MS
        return True, 0, None, agent_id
