import inspect
from pathlib import Path
from types import SimpleNamespace


def test_run_session_uses_standard_ptfhost_and_minimal_session_contract():
    from tests.ranking.run import conftest

    fixture = inspect.signature(conftest.ranking_session.__wrapped__)
    assert list(fixture.parameters) == ['request', 'ptfhost']


def test_run_session_opens_and_closes_current_session(tmp_path, monkeypatch):
    from tests.ranking.run import conftest

    runtime = {}
    config = SimpleNamespace(_ranking_output=tmp_path)
    request = SimpleNamespace(config=config)
    active = {'binding_root': '/binding', 'session_id': 'a' * 32}
    events = []
    monkeypatch.setattr(conftest, '_settings', lambda ignored: runtime)
    monkeypatch.setattr(
        conftest.ptf_container, 'open_session',
        lambda *args: events.append('open') or active)
    monkeypatch.setattr(
        conftest.ptf_container, 'close_session',
        lambda *args: events.append('close'))

    fixture = conftest.ranking_session.__wrapped__(request, object())
    assert next(fixture)['session'] is active
    fixture.close()
    assert events == ['open', 'close']


def test_run_entry_is_thin_pytest_mapping():
    from tests.ranking.run import test_ranking

    source = inspect.getsource(test_ranking.test_ranking_case)
    assert 'execute(' in source


def test_run_package_keeps_only_approved_module_boundaries():
    root = Path(__file__).resolve().parents[2] / 'run'
    assert {path.name for path in root.glob('*.py')} == {
        '__init__.py',
        'conftest.py',
        'test_ranking.py',
        'run_assets.py',
        'case_executor.py',
        'ptf_protocol.py',
        'ptf_container.py',
        'ptf_runner.py',
        'artifact_collection.py',
        'remote_artifacts.py',
        'live_console.py',
    }
