import copy
import importlib
import json

import pytest

from tests.ranking.generate_case_manifest import build_manifest
from tests.ranking.prepare_inputs import compile_inputs


@pytest.fixture
def manifest():
    return build_manifest(
        ['sairoute.RouteA', 'saivlan.VlanA', 'sairoute.RouteB'],
        {'repo': 'SAI', 'commit': 'a' * 40},
        {'sairoute': 'P0'},
    )


@pytest.fixture
def inputs():
    graph = {
        'device_conn': {'dut-a': {
            'Ethernet8': {'peerdevice': 'fanout-a', 'peerport': 'Ethernet2'},
            'Ethernet40': {'peerdevice': 'fanout-a', 'peerport': 'Ethernet19'},
        }},
        'device_vlan_map_list': {'dut-a': {0: 3007, 1: 3018}},
    }
    config_db = {'PORT': {
        'Ethernet8': {'lanes': '8,9,10,11', 'index': '3', 'speed': '400000'},
        'Ethernet40': {'lanes': '40,41,42,43', 'index': '11', 'speed': '400000'},
    }, 'DEVICE_METADATA': {'localhost': {'hostname': 'dut-a'}}}
    ptf_ports = {
        'Ethernet8': {'id': 7, 'interface': 'eth7'},
        'Ethernet40': {'id': 18, 'interface': 'eth18'},
    }
    return graph, 'dut-a', ['Ethernet40', 'Ethernet8'], config_db, ptf_ports


@pytest.fixture
def profile():
    return {
        'schema_version': 1,
        'backend': 'physical_fanout',
        'dut_id': 'dut-a', 'ptf_host_id': 'server-a', 'ptf_container': 'ptf-a',
        'inventory': 'ansible/lab', 'dut_limit': 'dut-a',
        'saiserver_container': 'saiserverv2',
        'saiserver_image': 'sha256:' + 'a' * 64,
        'start_argv': ['/usr/bin/saiserverv2.sh', 'start'],
        'stop_argv': ['/usr/bin/saiserverv2.sh', 'stop'],
        'rpc_port': 9092, 'timeout_s': 300, 'expected_connected_ports': 32,
        'ptf_root': '/tmp/ranking', 'case_source': 'tests/ranking/cases',
        'header_dir': '/SAI-TEST/inc',
        'experimental_header_dir': '/SAI-TEST/experimental',
        'adapter_path': '/usr/lib/python3/dist-packages/sai_thrift/sai_adapter.py',
        'dut_ssh': {'user': 'testuser', 'identity_file': '/test/dut_identity',
                    'known_hosts': '/test/known_hosts'},
    }


@pytest.fixture
def sample_request(profile, manifest, inputs):
    graph, dut_name, selected_ports, config_db, ptf_port_map = inputs
    runtime = dict(profile)
    runtime['expected_connected_ports'] = 2
    return {'runtime': runtime, 'manifest': manifest,
            'source_identity': manifest['source_identity'],
            'selector': {'single': 'sairoute.RouteA'},
            'graph': graph, 'dut_ports': selected_ports,
            'config_db': config_db, 'ptf_port_map': ptf_port_map}


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
    for name in ('case_source', 'header_dir', 'experimental_header_dir',
                 'binding_dir', 'prebuilt_dir'):
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
    (binding / 'sai_adapter.py').write_bytes(adapter.read_bytes())
    identity = tmp_path / 'dut_identity'
    identity.write_text('test fixture, not a private key\n')
    known_hosts = tmp_path / 'known_hosts'
    known_hosts.write_text('test fixture, not a host key\n')
    inventory = tmp_path / 'inventory'
    inventory.write_text('[dut]\ndut-a\n[ptf]\nserver-a\n')
    request['runtime'].update(
        case_source=str(case_source), header_dir=str(tmp_path / 'header_dir'),
        experimental_header_dir=str(tmp_path / 'experimental_header_dir'),
        adapter_path=str(adapter), inventory=str(inventory),
        dut_ssh={'user': 'testuser', 'identity_file': str(identity),
                 'known_hosts': str(known_hosts)},
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
