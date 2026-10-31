"""Check rendered Redis task commands without loading DUT fixtures."""

import ast
import io
import json
import logging
import os
from pathlib import Path
import shlex
import subprocess
from types import SimpleNamespace

from jinja2 import Environment, StrictUndefined
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
TASKS = ROOT / 'ansible/roles/test/tasks'


def render(template, **context):
    environment = Environment(undefined=StrictUndefined)
    environment.filters.update(quote=shlex.quote, from_json=json.loads)
    return environment.from_string(template).render(**context)


@pytest.mark.parametrize('filename', ['neighbour-mac.yml', 'neighbour-mac-noptf.yml'])
@pytest.mark.parametrize('port', [0, 6380, None])
def test_neighbour_native_hash_output_keeps_configured_endpoint(filename, port):
    tasks = yaml.safe_load((TASKS / filename).read_text())
    template = next(task['set_fact']['neighbour_asic_cli'] for task in tasks
                    if 'neighbour_asic_cli' in task.get('set_fact', {}))
    instance = {'hostname': '127.0.0.2', 'unix_socket_path': '/run/redis/socket with spaces.sock'}
    if port is not None:
        instance['port'] = port
    metadata = {'DATABASES': {'ASIC_DB': {'id': 71, 'instance': 'target'}},
                'INSTANCES': {'target': instance}}
    command = render(template, neighbour_database_metadata={'stdout': json.dumps(metadata)})
    endpoint = ['-s', instance['unix_socket_path']] if port == 0 else [
        '-h', '127.0.0.2', '-p', str(6379 if port is None else port)]
    assert shlex.split(command) == ['redis-cli'] + endpoint + ['-n', '71']


@pytest.mark.parametrize('port', [0, 6380, None])
def test_ecn_native_lua_reader_keeps_endpoint_file_and_argument(port):
    tasks = yaml.safe_load((TASKS / 'ecn_wred_worker.yml').read_text())
    template = next(task['shell'] for task in tasks if task.get('name') == 'Get WRED objects')
    instance = {'hostname': '127.0.0.2', 'unix_socket_path': '/run/redis/socket with spaces.sock'}
    if port is not None:
        instance['port'] = port
    command = render(template, ecn_asic_redis=instance, ecn_asic_db={'id': 71},
                     tmp_dir='/tmp/redis task', item='491520')
    endpoint = ['-s', instance['unix_socket_path']] if port == 0 else [
        '-h', '127.0.0.2', '-p', str(6379 if port is None else port)]
    assert shlex.split(command) == ['docker', 'exec', 'database', 'redis-cli'] + endpoint + [
        '-n', '71', '--eval', '/tmp/redis task/get_red_min.lua', ',', '491520', '|', 'grep', '491520']


@pytest.mark.parametrize('exists', ['True', '1', 'False', '0'])
def test_parallel_bgp_updates_keep_numeric_database_and_presence_formats(tmp_path, exists):
    source = ROOT / 'ansible/library/check_bgp_ipv6_routes_converged.py'
    tree = ast.parse(source.read_text())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == 'toggle_bgp_neighbors_in_parallel')
    metadata = {'DATABASES': {'CONFIG_DB': {'id': 4, 'instance': 'primary'},
                              'BMP_DB': {'id': 4, 'instance': 'secondary'}}}
    calls = []
    cli = tmp_path / 'sonic-db-cli'
    cli.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\n'
                   'if [ "$2" = EXISTS ]; then printf "%s\\n" "$EXISTS"; else echo OK; fi\n')
    cli.chmod(0o755)
    environment = dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ['PATH'],
                       CALLS=str(tmp_path / 'calls'), EXISTS=exists)

    def execute(module, command):
        calls.append(command)
        result = subprocess.run(['bash', '-c', command], env=environment,
                                capture_output=True, text=True, check=True)
        return result.stdout

    def fail(**kwargs):
        raise ValueError(kwargs['msg'])

    namespace = {'json': json, 'shlex': shlex, 'logging': logging,
                 'open': lambda path: io.StringIO(json.dumps(metadata)), '_execute_command_on_dut': execute}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
    function = namespace[function.name]
    if exists in ('True', '1'):
        function(SimpleNamespace(fail_json=fail), ['2001:db8::1'], 'down', parallelism=1, redis_db=4)
    else:
        with pytest.raises(ValueError, match='No BGP neighbor keys were toggled'):
            function(SimpleNamespace(fail_json=fail), ['2001:db8::1'], 'down', parallelism=1, redis_db=4)
    command_calls = (tmp_path / 'calls').read_text().splitlines()
    assert command_calls[0] == 'CONFIG_DB EXISTS BGP_NEIGHBOR|2001:db8::1'
    expected_updates = ['CONFIG_DB HSET BGP_NEIGHBOR|2001:db8::1 admin_status down'] if exists in ('True', '1') else []
    assert command_calls[1:] == expected_updates
    assert len(calls) == 1


def test_everflow_reads_use_the_named_application_database():
    text = (TASKS / 'everflow/logic_test/logic_test.yml').read_text()
    assert 'docker exec -i swss redis-cli' not in text
    assert text.count('sonic-db-cli APPL_DB HGET MIRROR_SESSION_TABLE:') == 5
