import importlib.util
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import pytest


@pytest.mark.parametrize('ipv4,prefix', [(True, '10.0.0.0/24'), (False, '2001:db8::/64')])
def test_lpm_prefix_insert_and_delete_restore_boundaries(ipv4, prefix):
    subnet_tree = ModuleType('SubnetTree')
    subnet_tree.SubnetTree = dict
    path = Path(__file__).resolve().parents[1] / 'cases' / 'lpm.py'
    spec = importlib.util.spec_from_file_location('ranking_case_lpm', path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict('sys.modules', {'SubnetTree': subnet_tree}):
        spec.loader.exec_module(module)
    table = module.LpmDict(ipv4=ipv4)
    original = dict(table._boundaries)
    table[prefix] = 'route'
    assert table[prefix] == 'route'
    assert table._prefix_set == {prefix}
    assert len(table._boundaries) == len(original) + 2
    del table[prefix]
    assert table._prefix_set == set()
    assert table._boundaries == original
    assert not table.contains(prefix)
