import importlib.util
import sys
import types
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[2] / 'ansible' / 'library' / 'nut_allocate_ip.py'


def _load_module():
    ansible = types.ModuleType('ansible')
    module_utils = types.ModuleType('ansible.module_utils')
    basic = types.ModuleType('ansible.module_utils.basic')
    debug_utils = types.ModuleType('ansible.module_utils.debug_utils')

    basic.AnsibleModule = object
    debug_utils.config_module_logging = lambda *args, **kwargs: None

    sys.modules.setdefault('ansible', ansible)
    sys.modules.setdefault('ansible.module_utils', module_utils)
    sys.modules['ansible.module_utils.basic'] = basic
    sys.modules['ansible.module_utils.debug_utils'] = debug_utils

    spec = importlib.util.spec_from_file_location('nut_allocate_ip', MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nut_allocate_ip = _load_module()
L2SnakeVlanAllocator = nut_allocate_ip.L2SnakeVlanAllocator


def test_single_dut_l2_snake_keeps_existing_behavior():
    allocator = L2SnakeVlanAllocator(
        testbed_facts={
            'topo': {'properties': {'vlan_base': 1001}},
            'duts': ['dut1'],
            'tgs': ['tg1'],
        },
        device_info={'dut1': {'Type': 'ToRRouter'}},
        device_port_links={
            'dut1': {
                'Ethernet0': {'peerdevice': 'tg1', 'peerport': 'Port1'},
                'Ethernet4': {'peerdevice': 'dut1', 'peerport': 'Ethernet8'},
                'Ethernet8': {'peerdevice': 'dut1', 'peerport': 'Ethernet4'},
                'Ethernet12': {'peerdevice': 'tg1', 'peerport': 'Port2'},
            }
        },
        device_port_vrfs={},
    )

    allocator.run()

    assert allocator.device_vlan_list['dut1'] == [1001, 1002]
    assert allocator.device_port_vlans['dut1'] == {
        'Ethernet0': {'vlanlist': [1001], 'mode': 'Access'},
        'Ethernet4': {'vlanlist': [1001], 'mode': 'Access'},
        'Ethernet8': {'vlanlist': [1002], 'mode': 'Access'},
        'Ethernet12': {'vlanlist': [1002], 'mode': 'Access'},
    }
    assert allocator.device_vlans['dut1']['chains'] == [{
        'chain_id': 0,
        'tx_port': 'Ethernet0',
        'rx_port': 'Ethernet12',
        'vlan_pairs': [
            {'vlan_id': 1001, 'ports': ['Ethernet0', 'Ethernet4']},
            {'vlan_id': 1002, 'ports': ['Ethernet8', 'Ethernet12']},
        ],
    }]


def test_multi_device_l2_snake_traces_across_inter_dut_link():
    allocator = L2SnakeVlanAllocator(
        testbed_facts={
            'topo': {'properties': {'vlan_base': 2001}},
            'duts': ['dut1', 'dut2'],
            'tgs': ['tg1'],
        },
        device_info={
            'dut1': {'Type': 'ToRRouter'},
            'dut2': {'Type': 'ToRRouter'},
        },
        device_port_links={
            'dut1': {
                'Ethernet0': {'peerdevice': 'tg1', 'peerport': 'Port1'},
                'Ethernet4': {'peerdevice': 'dut2', 'peerport': 'Ethernet0'},
            },
            'dut2': {
                'Ethernet0': {'peerdevice': 'dut1', 'peerport': 'Ethernet4'},
                'Ethernet4': {'peerdevice': 'tg1', 'peerport': 'Port2'},
            },
        },
        device_port_vrfs={},
    )

    allocator.run()

    assert allocator.device_vlan_list['dut1'] == [2001]
    assert allocator.device_vlan_list['dut2'] == [2002]
    assert allocator.device_port_vlans['dut1'] == {
        'Ethernet0': {'vlanlist': [2001], 'mode': 'Access'},
        'Ethernet4': {'vlanlist': [2001], 'mode': 'Access'},
    }
    assert allocator.device_port_vlans['dut2'] == {
        'Ethernet0': {'vlanlist': [2002], 'mode': 'Access'},
        'Ethernet4': {'vlanlist': [2002], 'mode': 'Access'},
    }
    assert allocator.device_vlans['dut1']['chains'] == [{
        'chain_id': 0,
        'tx_port': 'Ethernet0',
        'rx_port': None,
        'vlan_pairs': [
            {'vlan_id': 2001, 'ports': ['Ethernet0', 'Ethernet4']},
        ],
    }]
    assert allocator.device_vlans['dut2']['chains'] == [{
        'chain_id': 0,
        'tx_port': None,
        'rx_port': 'Ethernet4',
        'vlan_pairs': [
            {'vlan_id': 2002, 'ports': ['Ethernet0', 'Ethernet4']},
        ],
    }]
