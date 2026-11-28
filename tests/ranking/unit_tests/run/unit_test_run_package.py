import inspect
import json
from pathlib import Path
from types import SimpleNamespace


def test_run_assets_need_only_manifest_and_runner(tmp_path, manifest):
    from tests.ranking.run.run_assets import load_run_assets

    (tmp_path / 'cases').mkdir()
    manifest_path = tmp_path / 'cases' / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest))
    (tmp_path / 'run').mkdir()
    runner_path = tmp_path / 'run' / 'ptf_runner.py'
    runner_path.write_text('# container runner\n')

    assert load_run_assets(tmp_path) == {
        'manifest': str(manifest_path),
        'manifest_data': manifest,
        'runner_path': str(runner_path),
    }


def test_run_session_uses_standard_ptfhost_and_minimal_session_contract():
    from tests.ranking.run import conftest

    fixture = inspect.signature(conftest.ranking_session.__wrapped__)
    assert list(fixture.parameters) == ['request', 'ptfhost']


def test_run_session_opens_and_closes_current_session(tmp_path, monkeypatch):
    from tests.ranking.run import conftest

    runtime = {}
    config = SimpleNamespace(_ranking_output=tmp_path)
    request = SimpleNamespace(config=config)
    active = {'session_id': 'a' * 32}
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
