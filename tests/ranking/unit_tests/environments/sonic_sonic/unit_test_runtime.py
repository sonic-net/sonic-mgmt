from pathlib import Path

import pytest
import yaml


EXAMPLE = Path(__file__).resolve().parents[3] / 'environments' / 'sonic_sonic'


def _load(path):
    from tests.ranking.environments.sonic_sonic.environment import load_config
    from tests.ranking.run.run_assets import load_run_assets

    runtime = load_run_assets(EXAMPLE.parents[1])
    runtime.update(load_config(path))
    return runtime


def test_environment_compiles_to_existing_runtime_contract_without_auth():
    runtime = _load(EXAMPLE / 'environment.yml')
    ranking = EXAMPLE.parents[1]

    assert runtime['ptf_container'] == 'saiserverv2'
    assert runtime['ptf_workdir'] == '/SAI-TEST'
    assert runtime['ptf_executable'] == '/SAI-TEST/test/ptf/ptf'
    assert runtime['ptf_case_dir'] == '/SAI-TEST/ptf'
    assert runtime['collector_dir'] == '/tmp/sai_test_results'
    assert runtime['ptf_arguments'] == ['--relax']
    assert runtime['test_params'] == {'thrift_server': '192.0.2.10'}
    assert runtime['manifest'] == str(ranking / 'cases' / 'manifest.json')
    assert runtime['runner_path'] == str(ranking / 'run' / 'ptf_runner.py')
    assert runtime['interface_args'][:2] == ['--interface', '0-1@Ethernet1']
    assert runtime['interface_args'][-2:] == ['--interface', '0-32@Ethernet32']
    assert 'auth' not in runtime
    assert 'hosts' not in runtime
    assert 'environment_identity' not in runtime
    assert 'source_identity' not in runtime
    for unused in (
            'topology', 'profile', 'rpc_host', 'rpc_port', 'binding_dir',
            'expected_connected_ports', 'ptf_root', 'ptf_argv'):
        assert unused not in runtime


def test_interface_arguments_preserve_current_split_port_order():
    runtime = _load(EXAMPLE / 'environment.yml')

    pairs = list(zip(runtime['interface_args'][::2], runtime['interface_args'][1::2]))
    assert pairs[0] == ('--interface', '0-1@Ethernet1')
    assert pairs[-1] == ('--interface', '0-32@Ethernet32')


def test_binding_contract_remains_v1_10_pdx():
    runtime = _load(EXAMPLE / 'environment.yml')

    assert runtime['binding_identity']['semantic_identity'] == {
        'SAI_MAJOR': 1, 'SAI_MINOR': 10,
        'SAI_REVISION': 2, 'SAI_API_VERSION': 11002}


@pytest.mark.parametrize('field,value', (
    ('rpc_port', 9093),
    ('arguments', []),
    ('arguments', ['--platform', 'eth']),
))
def test_runtime_compiler_defends_the_fixed_sonic_sonic_contract(field, value):
    from tests.ranking.environments.sonic_sonic.environment import compile_runtime, load_environment

    environment = load_environment(EXAMPLE / 'environment.yml')
    if field == 'rpc_port':
        environment['dut'][field] = value
    else:
        environment['ptf'][field] = value

    with pytest.raises(ValueError, match='9092|--relax'):
        compile_runtime(environment, EXAMPLE / 'environment.yml')


def test_optional_password_never_enters_compiled_runtime(tmp_path):
    values = yaml.safe_load((EXAMPLE / 'environment.yml').read_text(encoding='utf-8'))
    values['hosts']['dut']['auth'] = {'password': 'sensitive-value'}
    path = tmp_path / 'environment.yml'
    path.write_text(yaml.safe_dump(values, sort_keys=False), encoding='utf-8')

    from tests.ranking.environments.sonic_sonic.environment import compile_runtime, load_environment

    runtime = compile_runtime(load_environment(path), EXAMPLE / 'environment.yml')

    assert 'sensitive-value' not in repr(runtime)
    assert 'auth' not in repr(runtime)
