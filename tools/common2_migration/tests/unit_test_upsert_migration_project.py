import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "upsert_migration_project.py"
SPEC = importlib.util.spec_from_file_location("upsert_migration_project", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class DummyResponse:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return MODULE.json.dumps(self._payload).encode("utf-8")


def test_resolve_auth_token_prefers_app_token(monkeypatch):
    monkeypatch.delenv("PROJECT_TOKEN", raising=False)
    monkeypatch.setenv("GITHUB_APP_TOKEN", "app-token")
    monkeypatch.delenv("GH_APP_TOKEN", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "base-token")

    assert MODULE.resolve_auth_token() == "app-token"


def test_resolve_auth_token_falls_back_to_project_token(monkeypatch):
    monkeypatch.setenv("PROJECT_TOKEN", "project-token")
    monkeypatch.delenv("GITHUB_APP_TOKEN", raising=False)
    monkeypatch.delenv("GH_APP_TOKEN", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "base-token")

    assert MODULE.resolve_auth_token() == "project-token"


def test_graphql_retries_when_github_returns_rate_limited_error_payload(monkeypatch):
    calls = []
    responses = [
        DummyResponse({"errors": [{"type": "RATE_LIMITED", "message": "API rate limit exceeded"}]}),
        DummyResponse({"data": {"ok": True}}),
    ]

    def fake_urlopen(req, timeout=30):
        calls.append(req)
        return responses.pop(0)

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(MODULE.time, "sleep", lambda *_args, **_kwargs: None)

    result = MODULE.graphql("token", "query { viewer { login } }", {})

    assert result == {"ok": True}
    assert len(calls) == 2
