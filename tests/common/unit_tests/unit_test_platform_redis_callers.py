"""Check host-local Redis command compatibility without DUT fixtures."""

import ast
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize('output,down', [('admin_status\ndown', True),
                                         ("{'admin_status': 'down'}", True), ('', False), ('{}', False)])
def test_host_local_module_query_keeps_its_status_result(output, down):
    path = ROOT / 'tests/smartswitch/common/device_utils_dpu.py'
    tree = ast.parse(path.read_text())
    function = next(node for node in reversed(tree.body)
                    if isinstance(node, ast.FunctionDef) and node.name == 'is_dark_mode_enabled')
    command = []

    def execute(value):
        command.append(value)
        return {'stdout': output}
    namespace = {'module': SimpleNamespace(get_name=lambda connection, index: 'DPU0'), 'logging': logging}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), 'exec'), namespace)
    assert namespace['is_dark_mode_enabled'](SimpleNamespace(command=execute), None, 1) == down
    assert command == ['sonic-db-cli CONFIG_DB hgetall "CHASSIS_MODULE|DPU0"']
