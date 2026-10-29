"""Unit tests for safe, cached testbed topology parsing."""

import importlib.util
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml


@pytest.fixture(params=list(dict.fromkeys([yaml.SafeLoader, getattr(yaml, 'CSafeLoader', yaml.SafeLoader)])))
def testbed_module(request):
    """Load the parser independently and exercise both supported safe loaders."""
    path = Path(__file__).resolve().parents[1] / 'testbed.py'
    spec = importlib.util.spec_from_file_location('testbed_under_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.SafeLoader = request.param
    return module


def make_testbeds(tmp_path, testbed_module, topology):
    """Write two synthetic testbeds that share a nested topology definition."""
    testbed_module.TestbedInfo.TOPOLOGY_FILEPATH = 'vars'
    testbed_module.TestbedInfo.NUT_TOPOLOGY_FILEPATH = 'vars'
    directory = tmp_path / 'vars'
    directory.mkdir()
    filename = '{}.yml' if topology.startswith('nut-') else 'topo_{}.yml'
    topology_file = directory / filename.format(topology)
    properties = {
        'topology': {
            'host_interfaces': ['0.0@1,1.0@2'],
            'disabled_host_interfaces': ['0.3@3'],
            'VMs': {'VM1': {'vlans': ['0.1@4', '1.1@5']}},
        },
        'configuration_properties': {'common': {'dut_asn': 65000}},
    }
    topology_file.write_text(yaml.safe_dump(properties))
    entries = []
    for name in ('testbed-a', 'testbed-b'):
        if topology.startswith('nut-'):
            entries.append({'name': name, 'topo': topology, 'tg_api_server': '192.0.2.1:443'})
        else:
            entries.append({'conf-name': name, 'topo': topology, 'dut': ['dut-a', 'dut-b']})
    catalogue = tmp_path / 'testbed.yaml'
    catalogue.write_text(yaml.safe_dump(entries))
    return catalogue, topology_file, properties


@pytest.mark.parametrize('topology', ['t0', 't0-vpp', 'nut-sample'])
def test_shared_topology_is_parsed_once_and_copied(tmp_path, testbed_module, topology):
    """Reuse parsed YAML without sharing nested properties or per-testbed maps."""
    catalogue, _, properties = make_testbeds(tmp_path, testbed_module, topology)
    with patch.object(testbed_module.yaml, 'load', wraps=yaml.load) as load:
        info = testbed_module.TestbedInfo(str(catalogue))
    assert load.call_count == 2
    assert all(call.kwargs['Loader'] is testbed_module.SafeLoader for call in load.call_args_list)
    first = info.testbed_topo['testbed-a']['topo']
    second = info.testbed_topo['testbed-b']['topo']
    assert first['properties'] == second['properties'] == properties
    first['properties']['topology']['VMs']['VM1']['vlans'].append('0.2@6')
    assert second['properties'] == properties
    if topology.startswith('nut-'):
        assert 'ptf_map' not in first
    else:
        assert first['name'] == second['name'] == 't0'
        assert first['ptf_map'] == {'0': {'0': 1, '1': 4}, '1': {'0': 2, '1': 5}}
        assert first['ptf_map_disabled'] == {'0': {'3': 3}}
        assert first['ptf_dut_intf_map'] == {'1': {'0': 0}, '2': {'1': 0}, '4': {'0': 1}, '5': {'1': 1}}
        first['ptf_map']['0']['0'] = 99
        assert second['ptf_map']['0']['0'] == 1


def test_topology_cache_does_not_outlive_construction(tmp_path, testbed_module):
    """A later construction must observe updates to the topology file."""
    catalogue, topology_file, properties = make_testbeds(tmp_path, testbed_module, 't0')
    first = testbed_module.TestbedInfo(str(catalogue))
    properties['configuration_properties']['common']['dut_asn'] = 65001
    topology_file.write_text(yaml.safe_dump(properties))
    second = testbed_module.TestbedInfo(str(catalogue))
    first_properties = first.testbed_topo['testbed-a']['topo']['properties']
    assert first_properties['configuration_properties']['common']['dut_asn'] == 65000
    assert second.testbed_topo['testbed-a']['topo']['properties'] == properties
