import copy
import importlib
import json

import pytest

from tests.ranking.prepare_inputs import compile_inputs
from tests.ranking.unit_tests.unit_test_prepare_inputs import (
    inputs, manifest, profile, sample_request,
)


def execution_api():
    try:
        return importlib.import_module('tests.ranking.execution_config')
    except ModuleNotFoundError as error:
        if error.name != 'tests.ranking.execution_config':
            raise
        pytest.fail('S2.1 execution_config API is not implemented')


@pytest.fixture
def prepared_request(sample_request, tmp_path):
    request = copy.deepcopy(sample_request)
    for name in ('case_source', 'header_dir', 'binding_dir', 'prebuilt_dir'):
        directory = tmp_path / name
        directory.mkdir()
    case_source = tmp_path / 'case_source'
    (case_source / 'sairoute.py').write_text(
        'class RouteA: pass\nclass RouteB: pass\n')
    (case_source / 'saivlan.py').write_text('class VlanA: pass\n')
    (case_source / 'ranking-contract.json').write_text(json.dumps({
        'schema_version': 1,
        'source_identity': request['source_identity'],
        'rpc_port': request['runtime']['rpc_port'],
        'requires_dut_credentials': False,
        'switch_owner': 'case',
        'dataplane_validation': 'after_create_switch',
    }))
    (tmp_path / 'header_dir' / 'sai.h').write_text('typedef int sai_status_t;\n')
    binding = tmp_path / 'binding_dir' / 'sai_thrift'
    binding.mkdir()
    (binding / '__init__.py').write_text('prepared = True\n')
    (tmp_path / 'prebuilt_dir' / 'attr_map.json').write_text('{}')
    adapter = tmp_path / 'adapter.py'
    adapter.write_text('prepared=True\n')
    inventory = tmp_path / 'inventory'
    inventory.write_text('[dut]\ndut-a\n[ptf]\nserver-a\n')
    request['runtime'].update(
        case_source=str(case_source), header_dir=str(tmp_path / 'header_dir'),
        adapter_path=str(adapter), inventory=str(inventory),
        start_argv=['/usr/bin/docker', 'run', '--pull=never', '--detach',
                    '--name', '{saiserver_container}', '{saiserver_image_id}'],
        stop_argv=['/usr/bin/docker', 'stop', '--time', '90',
                   '{saiserver_container_id}'],
        execution={
            'dut_host': 'dut-a', 'ptf_host': 'server-a',
            'rpc_host': 'example.invalid', 'profile_id': 'launch-a',
            'ptf_argv': ['/usr/bin/ptf'], 'test_params': {}, 'env': {},
            'binding_dir': str(tmp_path / 'binding_dir'),
            'prebuilt_dir': str(tmp_path / 'prebuilt_dir'), 'dut_files': [],
        },
    )
    return request


@pytest.fixture
def execution_spec(prepared_request, tmp_path):
    target = tmp_path / 'compiled-execution'
    compile_inputs(prepared_request, target)
    return execution_api().load_execution_inputs(target, tmp_path / 'artifacts')
