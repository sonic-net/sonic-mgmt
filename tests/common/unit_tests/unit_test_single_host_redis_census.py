"""Reject runtime Redis processes and listeners omitted by configuration metadata."""
import importlib.util
import json
from pathlib import Path
from unittest.mock import Mock

import pytest


@pytest.fixture
def helper():
    path = Path(__file__).resolve().parents[2] / 'redis/files/check_redis_access.py'
    spec = importlib.util.spec_from_file_location('single_host_redis_access', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def instances():
    return {'redis': {'unix_socket_path': '/run/redis/redis.sock', 'port': 0, 'container': 'database'},
            'redis_bmp': {'unix_socket_path': '/run/redis/redis_bmp.sock', 'port': 0, 'container': 'database'}}


@pytest.mark.parametrize('fault', [None, 'tcp-open', 'extra-process', 'missing-process',
                                  'duplicate-socket', 'wrong-socket', 'missing-socket', 'extra-socket'])
def test_census_reconciles_live_processes_and_listeners(helper, instances, monkeypatch, fault):
    rows = [{'pid': 101, 'sockets': ['/run/redis/redis.sock'], 'tcp_ports': []},
            {'pid': 102, 'sockets': ['/run/redis/redis_bmp.sock'], 'tcp_ports': []}]
    if fault == 'tcp-open':
        rows[0]['tcp_ports'] = [6379]
    elif fault == 'extra-process':
        rows.append({'pid': 103, 'sockets': ['/extra.sock'], 'tcp_ports': []})
    elif fault == 'missing-process':
        rows.pop()
    elif fault == 'duplicate-socket':
        rows[1]['sockets'] = rows[0]['sockets']
    elif fault == 'wrong-socket':
        rows[0]['sockets'] = ['/wrong.sock']
    elif fault == 'missing-socket':
        rows[0]['sockets'] = []
    elif fault == 'extra-socket':
        rows[0]['sockets'].append('/extra.sock')
    run = Mock(return_value=(0, json.dumps(rows).encode(), b''))
    monkeypatch.setattr(helper, 'execute', run)
    if fault:
        with pytest.raises(AssertionError):
            helper.verify_census(instances)
    else:
        assert helper.verify_census(instances) == 2
    args = run.call_args.args[0]
    assert args[:7] == ['docker', 'exec', '--user', 'redis', 'database', 'python3', '-c']


@pytest.mark.parametrize('ports,accepted', [([6400], True), ([6400, 6400], True),
                                           ([], False), ([6379], False), ([6400, 6379], False)])
def test_configured_tcp_exception_matches_actual_listeners(helper, instances, monkeypatch, ports, accepted):
    instances['redis_bmp']['port'] = 6400
    rows = [{'pid': 101, 'sockets': ['/run/redis/redis.sock'], 'tcp_ports': []},
            {'pid': 102, 'sockets': ['/run/redis/redis_bmp.sock'], 'tcp_ports': ports}]
    monkeypatch.setattr(helper, 'execute', Mock(return_value=(0, json.dumps(rows).encode(), b'')))
    assert helper.protection_scope(instances, {'/run/redis/redis.sock': {}},
                                   allow_tcp_exceptions=True,
                                   intent={'mode': 'enforce', 'tcp_exceptions': ['redis_bmp']}) == {'redis_bmp'}
    if accepted:
        assert helper.verify_census(instances) == 2
    else:
        with pytest.raises(AssertionError, match='TCP listeners'):
            helper.verify_census(instances)


def test_census_failure_cannot_be_accepted_as_no_processes(helper, instances, monkeypatch):
    monkeypatch.setattr(helper, 'execute', Mock(return_value=(1, b'', b'permission denied')))
    with pytest.raises(AssertionError, match='Could not enumerate'):
        helper.verify_census(instances)


def test_main_requires_runtime_census_before_credentials_or_access(helper, instances, monkeypatch, tmp_path):
    metadata = {'INSTANCES': {name: dict(item, hostname='127.0.0.1') for name, item in instances.items()}}
    path = tmp_path / 'database_config.json'
    path.write_text(json.dumps(metadata))
    monkeypatch.setattr(helper, 'discover_databases', lambda: ({'': metadata}, instances))
    monkeypatch.setattr(helper.os, 'geteuid', lambda: 0)
    census = Mock(side_effect=AssertionError('runtime mismatch'))
    monkeypatch.setattr(helper, 'verify_census', census)
    with pytest.raises(AssertionError, match='runtime mismatch'):
        helper.main(False)
    census.assert_called_once()
    assert {item['container'] for item in census.call_args.args[0].values()} == {'database'}
