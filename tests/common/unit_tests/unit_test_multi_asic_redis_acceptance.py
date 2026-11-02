"""Namespace discovery, CLI routing and actual listener census for Redis probes."""
import importlib.util
import json
from pathlib import Path
from unittest.mock import Mock

import pytest


@pytest.fixture
def helper():
    path = Path(__file__).resolve().parents[2] / 'redis/files/check_redis_access.py'
    spec = importlib.util.spec_from_file_location('multi_asic_redis_access', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def maps(tmp_path, monkeypatch, helper):
    config = tmp_path / 'redis/sonic-db/database_config.json'
    config.parent.mkdir(parents=True)
    asic = tmp_path / 'asic.conf'
    asic.write_text('NUM_ASIC=2\n')
    monkeypatch.setattr(helper, 'CONFIG', config)
    monkeypatch.setattr(helper, 'ASIC_CONF', asic)
    includes = [{'include': '../../redis/sonic-db/database_config.json'}]
    for number in ('', '0', '1'):
        path = tmp_path / ('redis' + number) / 'sonic-db/database_config.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        instance = {'hostname': '172.17.0.2' if number else '127.0.0.1', 'port': 0,
                    'unix_socket_path': str(path.parents[1] / 'redis.sock')}
        path.write_text(json.dumps({'INSTANCES': {'redis': instance},
                                   'DATABASES': {'APPL_DB': {'instance': 'redis', 'id': 0}}}))
        if number:
            includes.append({'namespace': 'asic' + number,
                             'include': '../../redis' + number + '/sonic-db/database_config.json'})
    (config.parent / 'database_global.json').write_text(json.dumps({'INCLUDES': includes}))
    return helper, config


def test_expected_namespaces_do_not_depend_on_policy(maps):
    helper, _ = maps
    metadata, local = helper.discover_databases()
    assert set(metadata) == {'', 'asic0', 'asic1'}
    assert set(local) == {'redis', 'asic0/redis', 'asic1/redis'}
    with pytest.raises(AssertionError, match='exactly'):
        helper.protection_scope(local, {item['unix_socket_path']: {} for name, item in local.items()
                                        if name != 'asic1/redis'})


@pytest.mark.parametrize('fault', ['missing-map', 'missing-include', 'extra-include', 'foreign-socket', 'remote'])
def test_discovery_rejects_incomplete_or_foreign_namespaces(maps, fault):
    helper, config = maps
    target = config.parents[2] / 'redis1/sonic-db/database_config.json'
    if fault == 'missing-map':
        target.unlink()
    elif fault in ('missing-include', 'extra-include'):
        path = config.parent / 'database_global.json'
        data = json.loads(path.read_text())
        if fault == 'missing-include':
            data['INCLUDES'].pop()
        else:
            data['INCLUDES'].append({'namespace': 'dpu0', 'include': 'foreign'})
        path.write_text(json.dumps(data))
    else:
        data = json.loads(target.read_text())
        if fault == 'foreign-socket':
            data['INSTANCES']['redis']['unix_socket_path'] = '/foreign/redis.sock'
        else:
            data['INSTANCES']['redis']['database_type'] = 'dpudb'
        target.write_text(json.dumps(data))
    with pytest.raises((AssertionError, OSError)):
        helper.discover_databases()


@pytest.mark.parametrize('fault', [None, 'extra-process', 'missing-process', 'tcp-open', 'wrong-socket'])
def test_actual_census_cannot_silently_omit_servers(maps, monkeypatch, fault):
    helper, _ = maps
    _, local = helper.discover_databases()
    def execute(args):
        container = args[4]
        instance = next(item for item in local.values() if item['container'] == container)
        rows = [{'pid': 101, 'sockets': [instance['unix_socket_path']], 'tcp_ports': []}]
        if container == 'database1':
            if fault == 'extra-process':
                rows.append({'pid': 102, 'sockets': ['/extra.sock'], 'tcp_ports': []})
            elif fault == 'missing-process':
                rows.clear()
            elif fault == 'tcp-open':
                rows[0]['tcp_ports'] = [6379]
            elif fault == 'wrong-socket':
                rows[0]['sockets'] = ['/wrong.sock']
        return 0, json.dumps(rows).encode(), b''
    monkeypatch.setattr(helper, 'execute', execute)
    if fault:
        with pytest.raises(AssertionError):
            helper.verify_census(local)
    else:
        assert helper.verify_census(local) == 3


def test_tcp_exceptions_apply_across_all_namespaces(maps):
    helper, _ = maps
    _, local = helper.discover_databases()
    for number in ('', '0', '1'):
        identity = 'asic' + number + '/redis_bmp' if number else 'redis_bmp'
        local[identity] = {'unix_socket_path': '/run/redis' + number + '/bmp.sock', 'port': 6400}
    selected = {item['unix_socket_path']: {} for name, item in local.items() if name.split('/')[-1] == 'redis'}
    assert helper.protection_scope(local, selected, allow_tcp_exceptions=True,
        intent={'mode': 'enforce', 'tcp_exceptions': ['redis_bmp']}) == {'redis_bmp'}


def test_write_connection_errors_are_not_permission_success(helper):
    for error in (helper.redis.exceptions.ConnectionError('unreachable'),
                  helper.redis.exceptions.ResponseError('ERR unknown command')):
        with pytest.raises((AssertionError, helper.redis.exceptions.ConnectionError)):
            helper.denied(Mock(side_effect=error))
    helper.denied(Mock(side_effect=helper.redis.exceptions.NoPermissionError('not allowed')))
    helper.denied(Mock(side_effect=helper.redis.exceptions.ResponseError('ACL failure in script: denied SET')))


def test_ordinary_process_has_only_its_private_primary_group(helper, monkeypatch):
    run = Mock(return_value=Mock(returncode=0, stdout=b'', stderr=b''))
    monkeypatch.setattr(helper.subprocess, 'run', run)
    helper.execute(['true'], ordinary=True)
    options = run.call_args.kwargs
    assert options['user'] != 0
    assert options['group'] == helper.pwd.getpwnam('nobody').pw_gid
    assert options['extra_groups'] == []


def test_named_and_raw_clis_keep_the_selected_namespace(helper, monkeypatch):
    metadata = {'DATABASES': {'APPL_DB': {'instance': 'redis', 'id': 0}}}
    process = {'value': 'value-asic1', 'protected': True, 'socket': '/var/run/redis1/redis.sock',
               'host': '172.17.0.3', 'port': 0, 'container': 'database1'}
    values = {'scratch': b'value-asic1'}
    client = Mock()
    client.get.side_effect = lambda key: values.get(key)
    calls = []
    def execute(args, data=None, ordinary=False):
        calls.append((args, ordinary))
        if args[0] == 'sonic-db-cli':
            assert args[1:3] == ['-n', 'asic1']
        assert args[0] != '/usr/bin/redis-cli', 'Host wrapper cannot reach an ASIC socket'
        if args[0] == 'docker':
            assert 'database1' in args and '/var/run/redis1/redis.sock' in args
            if data is not None:
                assert '-i' in args
        if 'HGETALL' in args:
            return 0, b'{"field":"value-asic1"}', b''
        if 'GET' in args:
            return 0, b'value-asic1\n', b''
        if args[0] == 'sonic-db-cli' and not ordinary:
            values['scratch:cli'] = b'value-asic1'
            return 0, b'OK\n', b''
        return 0, b'NOPERM not allowed\n', b''
    monkeypatch.setattr(helper, 'execute', execute)
    assert helper.cli_checks(metadata, {'redis': process}, {'redis': client},
                             'scratch', False, 'asic1') == 1
    assert any(ordinary and args[0] == 'sonic-db-cli' for args, ordinary in calls)
    assert any(args[0] == 'docker' for args, ordinary in calls)


def test_host_lookup_uses_existing_device_info_without_container_alias(maps, monkeypatch):
    import sys
    from types import SimpleNamespace
    helper, _ = maps
    path = helper.ASIC_CONF
    monkeypatch.setattr(helper, 'ASIC_CONF', None)
    lookup = Mock(return_value=str(path))
    monkeypatch.setitem(sys.modules, 'sonic_py_common',
                        SimpleNamespace(device_info=SimpleNamespace(get_asic_conf_file_path=lookup)))
    metadata, _ = helper.discover_databases()
    assert set(metadata) == {'', 'asic0', 'asic1'}
    lookup.assert_called_once_with()
