import importlib.util
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "upsert_migration_project.py"
SPEC = importlib.util.spec_from_file_location("upsert_migration_project", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


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
