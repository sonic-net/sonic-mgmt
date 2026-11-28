"""Check PFC watchdog setup and restoration on each ASIC's configured socket."""

import ast
import json
from pathlib import Path
from unittest.mock import Mock, call

import pytest

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize('asic_ids', [[None], [0, 1]])
@pytest.mark.parametrize('initial_status', ['disable', 'enable'])
def test_default_status_uses_each_asic_database(asic_ids, initial_status):
    path = ROOT / 'tests/generic_config_updater/test_pfcwd_status.py'
    tree = ast.parse(path.read_text())
    setup = next(node for node in tree.body
                 if isinstance(node, ast.FunctionDef) and node.name == 'set_default_pfcwd_config')
    setup.decorator_list = []
    namespace = {'json': json, 'pytest_assert': lambda ok, message: ok}
    exec(compile(ast.Module(body=[setup], type_ignores=[]), str(path), 'exec'), namespace)
    dut = Mock()
    dut.shell.return_value = {'rc': 0, 'stdout': json.dumps({
        'DEVICE_METADATA|localhost': {'value': {'default_pfcwd_status': initial_status}}})}
    dut.get_asic_ids.return_value = asic_ids
    asics = {index: Mock() for index in asic_ids}
    dut.asic_instance.side_effect = asics.__getitem__
    fixture = namespace['set_default_pfcwd_config'](dut)
    next(fixture)
    if initial_status == 'disable':
        for asic in asics.values():
            asic.run_sonic_db_cli_cmd.assert_called_once_with(
                'CONFIG_DB hset "DEVICE_METADATA|localhost" default_pfcwd_status enable',
                authenticate=True)
    with pytest.raises(StopIteration):
        next(fixture)
    for asic in asics.values():
        if initial_status == 'disable':
            assert asic.run_sonic_db_cli_cmd.call_args_list == [
                call('CONFIG_DB hset "DEVICE_METADATA|localhost" default_pfcwd_status enable',
                     authenticate=True),
                call('CONFIG_DB hset "DEVICE_METADATA|localhost" default_pfcwd_status disable',
                     authenticate=True)]
        else:
            asic.run_sonic_db_cli_cmd.assert_not_called()
        asic.command.assert_not_called()
