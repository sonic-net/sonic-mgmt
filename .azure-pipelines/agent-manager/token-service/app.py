"""sonic-nightly-service — AAD access-token relay for self-hosted Azure
Pipeline agent registration.

Behaviour summary (anti-recon "always-401" policy):
  * GET /token with Authorization: Bearer <SHARED_SECRET>  -> 200 + JSON
    {"access_token": "...", "expires_on": <epoch>}
  * Any other request (wrong/missing secret, /, /health, unknown path,
    non-GET method, etc.) -> 401 with an identical body and headers.

Inbound auth: shared secret in the SHARED_SECRET env var. SHARED_SECRET_NEXT
may also be set during a rotation window; either value is accepted. The
service intentionally exposes no health endpoint to the public internet so
that uninformed scanners cannot fingerprint the service. App Service's
built-in health-check feature must NOT be enabled — it would treat the 401
as unhealthy and restart the app.

Outbound auth: managed identity via DefaultAzureCredential, requesting a
token for the Azure DevOps audience (499b84ac-1321-427f-aa17-267ca6975798).
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import sys
import time

from typing import Optional

from azure.core.exceptions import ClientAuthenticationError
from azure.identity import DefaultAzureCredential
from fastapi import FastAPI, Request
from fastapi.responses import Response


AZURE_DEVOPS_RESOURCE = "499b84ac-1321-427f-aa17-267ca6975798/.default"

# Identical 401 returned for every non-authenticated path/method/header
# combination so an attacker cannot distinguish wrong-secret from wrong-path
# from no-header by looking at the response shape.
_UNAUTHORIZED_BODY = b"Unauthorized"
_UNAUTHORIZED_HEADERS = {
    "WWW-Authenticate": "Bearer",
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "no-store",
}


logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":%(message)s}',
)
logger = logging.getLogger("sonic-nightly-service")


def _log(event: str, **fields) -> None:
    payload = {"event": event, **fields}
    # We pre-serialise the message so that the format string's %(message)s
    # always receives valid JSON, keeping the overall log line valid JSON.
    logger.info(json.dumps(payload, default=str))


def _unauthorized() -> Response:
    return Response(
        content=_UNAUTHORIZED_BODY,
        status_code=401,
        headers=_UNAUTHORIZED_HEADERS,
    )


def _load_secrets() -> list[bytes]:
    """Return the list of accepted shared-secret values as bytes.

    SHARED_SECRET is the primary value. SHARED_SECRET_NEXT, when present,
    enables a dual-secret rotation window so the App Service and all client
    hosts can be updated independently without an outage.
    """
    secrets: list[bytes] = []
    primary = os.environ.get("SHARED_SECRET", "")
    if primary:
        secrets.append(primary.encode("utf-8"))
    nxt = os.environ.get("SHARED_SECRET_NEXT", "")
    if nxt:
        secrets.append(nxt.encode("utf-8"))
    if not secrets:
        # Fail closed: nothing matches, every /token request returns 401.
        _log("no_shared_secret_configured")
    return secrets


def _bearer_from_header(auth_header: Optional[str]) -> bytes:
    """Extract the raw bearer credential bytes from the Authorization header.

    Returns b"" when the header is missing or malformed; the caller must
    still perform a constant-time compare so that this branch cannot be
    distinguished by timing from the wrong-secret branch.
    """
    if not auth_header:
        return b""
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return b""
    return parts[1].strip().encode("utf-8")


def _secret_matches(presented: bytes, accepted: list[bytes]) -> bool:
    # Always perform at least one constant-time compare so the "no header"
    # path takes a similar amount of time as the "wrong header" path.
    if not accepted:
        hmac.compare_digest(presented, b"\x00" * max(len(presented), 1))
        return False
    matched = False
    for candidate in accepted:
        if hmac.compare_digest(presented, candidate):
            matched = True
    return matched


def create_app(credential: Optional[DefaultAzureCredential] = None) -> FastAPI:
    """Build the FastAPI app. Tests inject a fake credential."""
    cred = credential if credential is not None else DefaultAzureCredential()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/token")
    def get_token(request: Request) -> Response:
        accepted = _load_secrets()
        presented = _bearer_from_header(request.headers.get("authorization"))
        if not _secret_matches(presented, accepted):
            _log(
                "auth_failed",
                path="/token",
                client=request.client.host if request.client else None,
            )
            return _unauthorized()
        try:
            token = cred.get_token(AZURE_DEVOPS_RESOURCE)
        except ClientAuthenticationError as exc:
            _log("mi_token_failed", error=str(exc))
            # Return 401 (not 500) so an attacker cannot use error codes to
            # learn that they got past the shared-secret check.
            return _unauthorized()
        except Exception as exc:  # pragma: no cover - defensive
            _log("mi_token_unexpected_error", error=repr(exc))
            return _unauthorized()
        body = json.dumps(
            {"access_token": token.token, "expires_on": int(token.expires_on)}
        ).encode("utf-8")
        _log(
            "token_issued",
            expires_on=int(token.expires_on),
            ttl=int(token.expires_on - time.time()),
        )
        return Response(
            content=body,
            status_code=200,
            media_type="application/json",
            headers={"Cache-Control": "no-store"},
        )

    # Catch-all: every other path/method returns the same 401.
    async def _catch_all(request: Request) -> Response:
        return _unauthorized()

    app.add_api_route(
        "/{full_path:path}",
        _catch_all,
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    )

    return app


app = create_app()
