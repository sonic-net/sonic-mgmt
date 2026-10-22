import ast

import pytest

from tests.ranking.run.ptf_protocol import build_request, serialize_test_params


def _parse(encoded):
    body = ast.parse('class _TestParams:\n    ' + encoded).body[0].body
    return {item.targets[0].id: ast.literal_eval(item.value)
            for item in body if isinstance(item, ast.Assign)}


def test_test_params_round_trip_as_ptf_literals():
    values = {'thrift_server': '192.0.2.1', 'enabled': True,
              'ports': [1, 2], 'none': None}
    assert _parse(serialize_test_params(values)) == values


@pytest.mark.parametrize('value', [set(), object(), float('nan'), float('inf')])
def test_test_params_reject_non_literals(value):
    with pytest.raises(ValueError):
        serialize_test_params({'value': value})


def test_generic_builder_uses_profile_supplied_command_fields():
    config = {
        'ptf_executable': '/SAI-TEST/test/ptf/ptf',
        'ptf_arguments': ['--relax'],
        'ptf_workdir': '/SAI-TEST',
        'ptf_case_dir': '/SAI-TEST/ptf',
        'collector_dir': '/tmp/results',
        'interface_args': ['--interface', '0-1@Ethernet1'],
        'test_params': {'thrift_server': '192.0.2.10'},
        'timeout_s': 60,
        'env': {'PYTHONPATH': '/configured'},
    }
    session = {
        'binding_root': '/binding',
        'container_id': 'a' * 64,
    }

    request = build_request(
        config, session, 'sairoute.multipleRoutesTest', '/tmp/ranking/run')

    assert request['argv'] == [
        '/SAI-TEST/test/ptf/ptf', '--test-dir', '/SAI-TEST/ptf',
        'sairoute.multipleRoutesTest', '--interface', '0-1@Ethernet1',
        '--relax', '--test-params', "thrift_server='192.0.2.10'",
    ]
    assert request['env']['PYTHONPATH'] == '/binding:/configured'
    assert 'topology' not in config
    assert 'rpc_port' not in config
