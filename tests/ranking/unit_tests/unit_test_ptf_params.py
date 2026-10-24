import ast

import pytest

from tests.ranking.execution_config import build_ptf_request


def parse_ptf_params(encoded):
    # PTF evaluates --test-params as a Python class body, not a JSON document.
    body = ast.parse('class _TestParams:\n    ' + encoded).body[0].body
    return {item.targets[0].id: ast.literal_eval(item.value)
            for item in body if isinstance(item, ast.Assign)}


def test_request_parameters_round_trip_through_ptf_syntax(execution_spec):
    values = {'text': "a'; other='x; \\", 'enabled': True, 'disabled': False,
              'absent': None, 'count': 3, 'ratio': 1.5}
    execution_spec['execution']['test_params'] = values
    request = build_ptf_request(execution_spec, 'env-a', 'sairoute.RouteA', 'run-a')
    encoded = request['argv'][request['argv'].index('--test-params') + 1]
    actual = parse_ptf_params(encoded)
    assert {key: actual[key] for key in values} == values
    assert actual['thrift_server'] == 'example.invalid'
    assert actual['rpc_port'] == 9092
    assert actual['config_db_json'] == '/tmp/ranking/env-a/resources/ptf-config-db.json'


@pytest.mark.parametrize('key', ['x; injected', 'x=y', 'with space', 'class',
                                 '__doc__', '__hidden', '1key'])
def test_invalid_ptf_parameter_names_rejected_before_execution(execution_spec, key):
    execution_spec['execution']['test_params'] = {key: 'value'}
    with pytest.raises(ValueError, match='parameter name'):
        build_ptf_request(execution_spec, 'env-a', 'sairoute.RouteA', 'run-a')
