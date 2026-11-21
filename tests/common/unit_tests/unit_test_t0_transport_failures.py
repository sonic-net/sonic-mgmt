"""Common table dump endpoint and namespace regressions."""
import ast
import json
from pathlib import Path
import shlex
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(relative, name, namespace, owner=None):
    path = ROOT / relative
    tree = ast.parse(path.read_text())
    body = tree.body
    if owner:
        body = next(n for n in body if isinstance(n, ast.ClassDef) and n.name == owner).body
    node = next(n for n in body if isinstance(n, ast.FunctionDef) and n.name == name)
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), 'exec'), namespace)
    return namespace[name]


@pytest.mark.parametrize('database', ['APPL_DB', 'CONFIG_DB', 'CHASSIS_APP_DB', 'CHASSIS_STATE_DB'])
@pytest.mark.parametrize('use_tcp,transport', [(False, 'unix_socket'), (True, 'tcp')])
@pytest.mark.parametrize('kind', ['host', 'single-asic', 'asic3'])
def test_table_dump_preserves_endpoint_namespace_and_result(database, use_tcp, transport, kind):
    class Asic:
        pass
    host = SimpleNamespace(command=Mock(return_value={'stdout': '{"row":{"value":{"field":"value"}}}'}))
    host.sonichost = host
    selected = host
    if kind != 'host':
        selected = Asic()
        selected.namespace = 'asic3' if kind == 'asic3' else None
        selected.sonichost = host
    method = load('common/helpers/sonic_db.py', 'dump',
                  {'json': json, 'SonicAsic': Asic, 'DEFAULT_NAMESPACE': None}, 'SonicDbCli')
    assert method(SimpleNamespace(host=selected, database=database, USE_TCP=use_tcp),
                  'TABLE:') == {'row': {'value': {'field': 'value'}}}
    argv = shlex.split(host.command.call_args.args[0])
    if kind == 'asic3':
        assert argv[:5] == ['sudo', 'ip', 'netns', 'exec', 'asic3']
        argv = argv[5:]
    assert argv == ['sonic-db-dump', '-t', transport, '-n', database, '-y', '-k', '*TABLE:*']
