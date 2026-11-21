"""Check local and chassis command routing without loading testbed fixtures."""
import ast
from pathlib import Path
from unittest.mock import Mock

import pytest


class Asic:
    sonic_db_cli = 'sonic-db-cli -s -n asic1'


@pytest.mark.parametrize('asic', [False, True])
@pytest.mark.parametrize('database', ['CONFIG_DB', 'STATE_DB', 'CHASSIS_APP_DB', 'CHASSIS_STATE_DB'])
def test_shared_cli_keeps_local_namespace_and_chassis_tcp(asic, database):
    path = Path(__file__).resolve().parents[1] / 'helpers/sonic_db.py'
    tree = ast.parse(path.read_text())
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == '_run_sonic_db_cli')
    namespace = {'SonicAsic': Asic}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), 'exec'), namespace)
    host = Asic() if asic else Mock()
    host.shell = Mock(return_value={'stdout': 'value'})
    result = namespace['_run_sonic_db_cli'](host, database + ' GET key')
    prefix = 'sonic-db-cli' if database.startswith('CHASSIS_') else (
        'sonic-db-cli -s -n asic1' if asic else 'sonic-db-cli -s')
    host.shell.assert_called_once_with(prefix + ' ' + database + ' GET key', module_ignore_errors=True)
    assert result == {'stdout': 'value'}
