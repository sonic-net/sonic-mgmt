"""Regression tests for the vSONiC switch-to-dataplane lifecycle boundary."""

import ast
from pathlib import Path
from types import SimpleNamespace


SOURCE = (Path(__file__).resolve().parents[2] / 'cases' / 'ptf'
          / 'platform_helper' / 'brcm_sai_helper.py')


def _start_switch():
    tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
    helper = next(node for node in tree.body
                  if isinstance(node, ast.ClassDef)
                  and node.name == 'BrcmSaiHelper')
    function = next(node for node in helper.body
                    if isinstance(node, ast.FunctionDef)
                    and node.name == 'start_switch')
    module = ast.Module(body=[function], type_ignores=[])
    ast.fix_missing_locations(module)
    sleeps = []
    namespace = {
        'ROUTER_MAC': '00:00:00:00:00:00',
        'SAI_STATUS_SUCCESS': 0,
        'sai_thrift_create_switch': lambda *args, **kwargs: 42,
        'time': SimpleNamespace(sleep=sleeps.append),
    }
    exec(compile(module, str(SOURCE), 'exec'), namespace)
    return namespace['start_switch'], sleeps


def test_vsonic_runtime_can_extend_the_post_switch_dataplane_wait():
    start_switch, sleeps = _start_switch()
    helper = SimpleNamespace(
        client=object(), test_params={'vsonic_dataplane_wait_s': 20},
        status=lambda: 0,
        assertEqual=lambda actual, expected: None)

    start_switch(helper)

    assert helper.switch_id == 42
    assert sleeps == [20]


def test_non_vsonic_broadcom_keeps_the_existing_five_second_default():
    start_switch, sleeps = _start_switch()
    helper = SimpleNamespace(
        client=object(), test_params={}, status=lambda: 0,
        assertEqual=lambda actual, expected: None)

    start_switch(helper)

    assert sleeps == [5]
