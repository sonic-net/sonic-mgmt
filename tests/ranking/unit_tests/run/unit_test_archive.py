import hashlib
import json

import pytest


def _files(path, text):
    (path / 'outcome.json').write_text('{}')
    (path / 'run.log').write_text(text)
    return {name: hashlib.sha256((path / name).read_bytes()).hexdigest()
            for name in ('outcome.json', 'run.log')}


def _result(case='sairoute.Case', status='passed'):
    return {
        'case': case,
        'status': status,
        'rc': 0 if status == 'passed' else 1,
        'duration_seconds': 0.1,
        'error_message': None,
        'metadata': {},
        'spec_results': [],
        'attr_records': [],
    }


def test_publish_groups_artifacts_by_module_and_overwrites_only_same_case(tmp_path):
    from tests.ranking.run import artifact_collection

    first = artifact_collection.create_staging(tmp_path, 'sairoute.Case', 'a' * 32)
    manifest = _files(first, 'first')
    artifact_collection.verify(first, manifest, 'sairoute.Case')
    published = artifact_collection.publish(first, 'sairoute.Case', _result())
    second = artifact_collection.create_staging(tmp_path, 'sairoute.Case', 'b' * 32)
    manifest = _files(second, 'second')
    artifact_collection.verify(second, manifest, 'sairoute.Case')
    artifact_collection.publish(second, 'sairoute.Case', _result())

    assert published == {
        'result': tmp_path / 'cases/sairoute/results/Case.json',
        'log': tmp_path / 'cases/sairoute/logs/Case.log',
        'pcap': None,
    }
    assert published['log'].read_text() == 'second'
    assert json.loads(published['result'].read_text()) == _result()
    assert not (tmp_path / 'cases/sairoute.Case').exists()


def test_publish_replaces_optional_pcap_and_removes_stale_capture(tmp_path):
    from tests.ranking.run import artifact_collection

    first = artifact_collection.create_staging(tmp_path, 'sairoute.Case', 'c' * 32)
    manifest = _files(first, 'first')
    (first / 'ptf.pcap').write_bytes(b'pcap')
    manifest['ptf.pcap'] = hashlib.sha256(b'pcap').hexdigest()
    artifact_collection.verify(first, manifest, 'sairoute.Case')
    published = artifact_collection.publish(first, 'sairoute.Case', _result())
    assert published['pcap'].read_bytes() == b'pcap'

    second = artifact_collection.create_staging(tmp_path, 'sairoute.Case', 'd' * 32)
    manifest = _files(second, 'second')
    artifact_collection.verify(second, manifest, 'sairoute.Case')
    published = artifact_collection.publish(second, 'sairoute.Case', _result())

    assert published['pcap'] is None
    assert not (tmp_path / 'cases/sairoute/pcaps/Case.pcap').exists()


def test_failed_publish_restores_the_previous_case_outputs(
        tmp_path, monkeypatch):
    from tests.ranking.run import artifact_collection

    first = artifact_collection.create_staging(
        tmp_path, 'sairoute.Case', '1' * 32)
    manifest = _files(first, 'old log')
    (first / 'ptf.pcap').write_bytes(b'old pcap')
    manifest['ptf.pcap'] = hashlib.sha256(b'old pcap').hexdigest()
    artifact_collection.verify(first, manifest, 'sairoute.Case')
    published = artifact_collection.publish(
        first, 'sairoute.Case', _result())
    old_result = published['result'].read_bytes()

    second = artifact_collection.create_staging(
        tmp_path, 'sairoute.Case', '2' * 32)
    artifact_collection.verify(
        second, _files(second, 'new log'), 'sairoute.Case')
    atomic_bytes = artifact_collection._atomic_bytes

    def fail_result(path, payload):
        if path.name == 'Case.json':
            raise OSError('injected result write failure')
        atomic_bytes(path, payload)

    monkeypatch.setattr(artifact_collection, '_atomic_bytes', fail_result)
    with pytest.raises(OSError, match='injected result write failure'):
        artifact_collection.publish(
            second, 'sairoute.Case', _result(status='failed'))

    assert published['result'].read_bytes() == old_result
    assert published['log'].read_text() == 'old log'
    assert published['pcap'].read_bytes() == b'old pcap'
    assert second.is_dir()


def test_hidden_staging_is_not_a_final_case(tmp_path):
    from tests.ranking.run import artifact_collection

    staging = artifact_collection.create_staging(tmp_path, 'sairoute.Case', 'e' * 32)
    assert staging.name.startswith('.')
    assert not (tmp_path / 'cases' / 'sairoute.Case').exists()


def test_remote_operation_distinguishes_host_from_ptf_container(monkeypatch):
    from tests.ranking.run import artifact_collection

    commands = []

    def command(host, argv, description):
        commands.append((argv, description))
        return {'stdout': '{"created": true}'}

    monkeypatch.setattr(artifact_collection.container_runtime, 'command', command)
    session = {
        'container_id': 'a' * 64,
        'root': '/tmp/ranking/session',
    }

    artifact_collection.remote_operation(
        object(), session, 'b' * 32, 'create', ptf_container=False)
    artifact_collection.remote_operation(
        object(), session, 'c' * 32, 'create', ptf_container=True)

    assert commands[0][0][0] == 'python3'
    assert commands[0][1] == 'host artifact create'
    assert commands[1][0][:3] == ['docker', 'exec', 'a' * 64]
    assert commands[1][1] == 'container artifact create'


def test_create_run_reports_container_create_and_host_rollback_failures(
        monkeypatch):
    from tests.ranking.run import artifact_collection

    calls = []

    def operation(host, session, run_id, action, value=None,
                  ptf_container=True):
        calls.append((action, ptf_container))
        if action == 'create' and ptf_container:
            raise RuntimeError('container create failed')
        if action == 'delete' and not ptf_container:
            raise RuntimeError('host rollback failed')

    monkeypatch.setattr(artifact_collection, 'remote_operation', operation)
    with pytest.raises(RuntimeError) as error:
        artifact_collection.create_run(object(), {}, 'a' * 32)

    assert 'container create failed' in str(error.value)
    assert 'host rollback failed' in str(error.value)
    assert str(error.value.__cause__) == 'container create failed'
    assert calls == [
        ('create', False), ('create', True), ('delete', False),
    ]


def test_cleanup_deletes_ptf_container_then_host(monkeypatch):
    from tests.ranking.run import artifact_collection

    targets = []
    monkeypatch.setattr(
        artifact_collection, 'remote_operation',
        lambda *args, **kwargs: targets.append(kwargs['ptf_container']))

    artifact_collection.cleanup(object(), {}, 'd' * 32)

    assert targets == [True, False]
