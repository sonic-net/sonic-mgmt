"""Unit tests for the sonic-nightly-service token relay.

The tests exercise the "always-401 except authenticated /token" policy and
the dual-secret rotation behaviour. The Azure managed-identity dependency is
replaced with a fake credential so the tests run fully offline.
"""

from __future__ import annotations

import os
import time
import unittest
from unittest.mock import patch

from azure.core.exceptions import ClientAuthenticationError
from fastapi.testclient import TestClient

import app as app_module


SECRET = "primary-shared-secret-value"
NEXT_SECRET = "next-shared-secret-value"


class _FakeAccessToken:
    def __init__(self, token: str, expires_on: int) -> None:
        self.token = token
        self.expires_on = expires_on


class _FakeCredential:
    """Minimal stand-in for DefaultAzureCredential."""

    def __init__(self, token: str = "fake-aad-token", ttl: int = 3600,
                 raises: Exception | None = None) -> None:
        self._token = token
        self._ttl = ttl
        self._raises = raises
        self.calls: list[str] = []

    def get_token(self, *scopes: str) -> _FakeAccessToken:
        self.calls.append(",".join(scopes))
        if self._raises is not None:
            raise self._raises
        return _FakeAccessToken(self._token, int(time.time()) + self._ttl)


class _Base(unittest.TestCase):
    def _client(self, credential: _FakeCredential | None = None,
                env: dict[str, str] | None = None) -> TestClient:
        env = {"SHARED_SECRET": SECRET} if env is None else env
        # Ensure no leftover env vars between tests influence the result.
        with patch.dict(os.environ, env, clear=True):
            app = app_module.create_app(credential=credential or _FakeCredential())
        # The app captured the env at construction time via os.environ in
        # _load_secrets(), but _load_secrets() is called per request, so we
        # need the env to remain set for the lifetime of the request too.
        self._env_patch = patch.dict(os.environ, env, clear=True)
        self._env_patch.start()
        self.addCleanup(self._env_patch.stop)
        return TestClient(app)


class TestUnauthorizedShape(_Base):
    """Every 401 response must be byte-identical (body + key headers)."""

    def test_all_unauth_paths_are_indistinguishable(self) -> None:
        client = self._client()
        responses = [
            client.get("/"),
            client.get("/health"),
            client.get("/token"),                                  # no header
            client.get("/token", headers={"Authorization": "garbage"}),
            client.get("/token", headers={"Authorization": "Bearer wrong"}),
            client.get("/unknown/path/xyz"),
            client.post("/token"),
            client.put("/anything"),
        ]
        for resp in responses:
            self.assertEqual(resp.status_code, 401)
            self.assertEqual(resp.content, b"Unauthorized")
            self.assertEqual(resp.headers.get("www-authenticate"), "Bearer")
            self.assertEqual(
                resp.headers.get("content-type"),
                "text/plain; charset=utf-8",
            )

    def test_token_returns_401_when_no_secret_configured(self) -> None:
        # Service deployed without SHARED_SECRET should fail closed.
        client = self._client(env={})
        resp = client.get(
            "/token", headers={"Authorization": f"Bearer {SECRET}"}
        )
        self.assertEqual(resp.status_code, 401)


class TestTokenSuccess(_Base):
    def test_valid_secret_returns_token(self) -> None:
        cred = _FakeCredential(token="aad-xyz", ttl=3600)
        client = self._client(credential=cred)
        resp = client.get(
            "/token", headers={"Authorization": f"Bearer {SECRET}"}
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["access_token"], "aad-xyz")
        self.assertGreater(body["expires_on"], int(time.time()))
        # The credential must have been called for the AzDevOps audience.
        self.assertEqual(len(cred.calls), 1)
        self.assertIn("499b84ac-1321-427f-aa17-267ca6975798", cred.calls[0])

    def test_mi_failure_returns_401_not_500(self) -> None:
        cred = _FakeCredential(raises=ClientAuthenticationError("MI down"))
        client = self._client(credential=cred)
        resp = client.get(
            "/token", headers={"Authorization": f"Bearer {SECRET}"}
        )
        # 401 (not 500) so attackers cannot fingerprint the difference
        # between "got past the shared-secret check" and "didn't".
        self.assertEqual(resp.status_code, 401)


class TestDualSecretRotation(_Base):
    def test_next_secret_also_accepted(self) -> None:
        env = {"SHARED_SECRET": SECRET, "SHARED_SECRET_NEXT": NEXT_SECRET}
        client = self._client(env=env)
        for value in (SECRET, NEXT_SECRET):
            resp = client.get(
                "/token", headers={"Authorization": f"Bearer {value}"}
            )
            self.assertEqual(resp.status_code, 200, msg=f"value={value}")

    def test_neither_secret_rejects(self) -> None:
        env = {"SHARED_SECRET": SECRET, "SHARED_SECRET_NEXT": NEXT_SECRET}
        client = self._client(env=env)
        resp = client.get(
            "/token", headers={"Authorization": "Bearer something-else"}
        )
        self.assertEqual(resp.status_code, 401)


class TestBearerHeaderParsing(_Base):
    def test_case_insensitive_scheme(self) -> None:
        client = self._client()
        resp = client.get(
            "/token", headers={"Authorization": f"bearer {SECRET}"}
        )
        self.assertEqual(resp.status_code, 200)

    def test_extra_whitespace_in_token(self) -> None:
        client = self._client()
        resp = client.get(
            "/token", headers={"Authorization": f"Bearer   {SECRET}   "}
        )
        # Strip is intentional.
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
