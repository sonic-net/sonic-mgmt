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

    expected_vlan_port = {
        'Ethernet0': {'vlanlist': [1001], 'mode': 'Access'},
        'Ethernet4': {'vlanlist': [1001], 'mode': 'Access'},
        'Ethernet8': {'vlanlist': [1002], 'mode': 'Access'},
        'Ethernet12': {'vlanlist': [1002], 'mode': 'Access'},
    }
    expected_vlans = {
        'vlans': [
            {'vlan_id': 1001, 'ports': ['Ethernet0', 'Ethernet4']},
            {'vlan_id': 1002, 'ports': ['Ethernet8', 'Ethernet12']},
        ],
    }

    assert allocator.device_vlan_range['dut1'] == ['1001', '1002']
    assert allocator.device_vlan_port['dut1'] == expected_vlan_port
    assert not hasattr(allocator, 'device_port_vlans')
    assert allocator.device_vlan_list['dut1'] == [1001, 1002]
    assert allocator.device_vlans['dut1'] == expected_vlans


def _build_dual_dut_two_chain_links():
    dut1_links = {
        0: ('tg1', 'Port1'),
        4: ('dut2', 'Ethernet0'),
        8: ('dut2', 'Ethernet12'),
        12: ('dut1', 'Ethernet16'),
        16: ('dut1', 'Ethernet12'),
        20: ('dut2', 'Ethernet16'),
        24: ('dut2', 'Ethernet28'),
        28: ('dut1', 'Ethernet32'),
        32: ('dut1', 'Ethernet28'),
        36: ('dut2', 'Ethernet32'),
        40: ('dut2', 'Ethernet44'),
        44: ('dut1', 'Ethernet48'),
        48: ('dut1', 'Ethernet44'),
        52: ('dut2', 'Ethernet48'),
        56: ('dut2', 'Ethernet60'),
        60: ('tg1', 'Port2'),
        64: ('tg1', 'Port3'),
        68: ('dut2', 'Ethernet64'),
        72: ('dut2', 'Ethernet76'),
        76: ('dut1', 'Ethernet80'),
        80: ('dut1', 'Ethernet76'),
        84: ('dut2', 'Ethernet80'),
        88: ('dut2', 'Ethernet92'),
        92: ('dut1', 'Ethernet96'),
        96: ('dut1', 'Ethernet92'),
        100: ('dut2', 'Ethernet96'),
        104: ('dut2', 'Ethernet108'),
        108: ('dut1', 'Ethernet112'),
        112: ('dut1', 'Ethernet108'),
        116: ('dut2', 'Ethernet112'),
        120: ('dut2', 'Ethernet124'),
        124: ('tg1', 'Port4'),
    }
    dut2_links = {
        0: ('dut1', 'Ethernet4'),
        4: ('dut2', 'Ethernet8'),
        8: ('dut2', 'Ethernet4'),
        12: ('dut1', 'Ethernet8'),
        16: ('dut1', 'Ethernet20'),
        20: ('dut2', 'Ethernet24'),
        24: ('dut2', 'Ethernet20'),
        28: ('dut1', 'Ethernet24'),
        32: ('dut1', 'Ethernet36'),
        36: ('dut2', 'Ethernet40'),
        40: ('dut2', 'Ethernet36'),
        44: ('dut1', 'Ethernet40'),
        48: ('dut1', 'Ethernet52'),
        52: ('dut2', 'Ethernet56'),
        56: ('dut2', 'Ethernet52'),
        60: ('dut1', 'Ethernet56'),
        64: ('dut1', 'Ethernet68'),
        68: ('dut2', 'Ethernet72'),
        72: ('dut2', 'Ethernet68'),
        76: ('dut1', 'Ethernet72'),
        80: ('dut1', 'Ethernet84'),
        84: ('dut2', 'Ethernet88'),
        88: ('dut2', 'Ethernet84'),
        92: ('dut1', 'Ethernet88'),
        96: ('dut1', 'Ethernet100'),
        100: ('dut2', 'Ethernet104'),
        104: ('dut2', 'Ethernet100'),
        108: ('dut1', 'Ethernet104'),
        112: ('dut1', 'Ethernet116'),
        116: ('dut2', 'Ethernet120'),
        120: ('dut2', 'Ethernet116'),
        124: ('dut1', 'Ethernet120'),
    }

    return {
        'dut1': {
            f'Ethernet{port}': {'peerdevice': peer_device, 'peerport': peer_port}
            for port, (peer_device, peer_port) in dut1_links.items()
        },
        'dut2': {
            f'Ethernet{port}': {'peerdevice': peer_device, 'peerport': peer_port}
            for port, (peer_device, peer_port) in dut2_links.items()
        },
    }


def test_multi_device_l2_snake_supports_two_parallel_chains_with_eight_crossings_each():
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
        device_port_links=_build_dual_dut_two_chain_links(),
        device_port_vrfs={},
    )

    allocator.run()

    assert allocator.device_vlan_list['dut1'] == [
        2001, 2004, 2005, 2008, 2009, 2012, 2013, 2016,
        2017, 2020, 2021, 2024, 2025, 2028, 2029, 2032,
    ]
    assert allocator.device_vlan_list['dut2'] == [
        2002, 2003, 2006, 2007, 2010, 2011, 2014, 2015,
        2018, 2019, 2022, 2023, 2026, 2027, 2030, 2031,
    ]
    assert allocator.device_vlan_range['dut1'] == [str(vlan) for vlan in allocator.device_vlan_list['dut1']]
    assert allocator.device_vlan_range['dut2'] == [str(vlan) for vlan in allocator.device_vlan_list['dut2']]

    assert allocator.device_vlans['dut1'] == {
        'vlans': [
            {'vlan_id': 2001, 'ports': ['Ethernet0', 'Ethernet4']},
            {'vlan_id': 2004, 'ports': ['Ethernet8', 'Ethernet12']},
            {'vlan_id': 2005, 'ports': ['Ethernet16', 'Ethernet20']},
            {'vlan_id': 2008, 'ports': ['Ethernet24', 'Ethernet28']},
            {'vlan_id': 2009, 'ports': ['Ethernet32', 'Ethernet36']},
            {'vlan_id': 2012, 'ports': ['Ethernet40', 'Ethernet44']},
            {'vlan_id': 2013, 'ports': ['Ethernet48', 'Ethernet52']},
            {'vlan_id': 2016, 'ports': ['Ethernet56', 'Ethernet64']},
            {'vlan_id': 2017, 'ports': ['Ethernet60', 'Ethernet68']},
            {'vlan_id': 2020, 'ports': ['Ethernet72', 'Ethernet76']},
            {'vlan_id': 2021, 'ports': ['Ethernet80', 'Ethernet84']},
            {'vlan_id': 2024, 'ports': ['Ethernet88', 'Ethernet92']},
            {'vlan_id': 2025, 'ports': ['Ethernet96', 'Ethernet100']},
            {'vlan_id': 2028, 'ports': ['Ethernet104', 'Ethernet108']},
            {'vlan_id': 2029, 'ports': ['Ethernet112', 'Ethernet116']},
            {'vlan_id': 2032, 'ports': ['Ethernet120', 'Ethernet124']},
        ],
    }
    assert allocator.device_vlans['dut2'] == {
        'vlans': [
            {'vlan_id': 2002, 'ports': ['Ethernet0', 'Ethernet4']},
            {'vlan_id': 2003, 'ports': ['Ethernet8', 'Ethernet12']},
            {'vlan_id': 2006, 'ports': ['Ethernet16', 'Ethernet20']},
            {'vlan_id': 2007, 'ports': ['Ethernet24', 'Ethernet28']},
            {'vlan_id': 2010, 'ports': ['Ethernet32', 'Ethernet36']},
            {'vlan_id': 2011, 'ports': ['Ethernet40', 'Ethernet44']},
            {'vlan_id': 2014, 'ports': ['Ethernet48', 'Ethernet52']},
            {'vlan_id': 2015, 'ports': ['Ethernet56', 'Ethernet60']},
            {'vlan_id': 2018, 'ports': ['Ethernet64', 'Ethernet68']},
            {'vlan_id': 2019, 'ports': ['Ethernet72', 'Ethernet76']},
            {'vlan_id': 2022, 'ports': ['Ethernet80', 'Ethernet84']},
            {'vlan_id': 2023, 'ports': ['Ethernet88', 'Ethernet92']},
            {'vlan_id': 2026, 'ports': ['Ethernet96', 'Ethernet100']},
            {'vlan_id': 2027, 'ports': ['Ethernet104', 'Ethernet108']},
            {'vlan_id': 2030, 'ports': ['Ethernet112', 'Ethernet116']},
            {'vlan_id': 2031, 'ports': ['Ethernet120', 'Ethernet124']},
        ],
    }


def test_single_dut_l2_snake_traces_parallel_chains_in_lockstep():
    allocator = L2SnakeVlanAllocator(
        testbed_facts={
            'topo': {'properties': {'vlan_base': 4001}},
            'duts': ['dut1'],
            'tgs': ['tg1'],
        },
        device_info={'dut1': {'Type': 'ToRRouter'}},
        device_port_links={
            'dut1': {
                'Ethernet0': {'peerdevice': 'tg1', 'peerport': 'Port1'},
                'Ethernet4': {'peerdevice': 'tg1', 'peerport': 'Port2'},
                'Ethernet8': {'peerdevice': 'dut1', 'peerport': 'Ethernet12'},
                'Ethernet12': {'peerdevice': 'dut1', 'peerport': 'Ethernet8'},
                'Ethernet16': {'peerdevice': 'dut1', 'peerport': 'Ethernet20'},
                'Ethernet20': {'peerdevice': 'dut1', 'peerport': 'Ethernet16'},
                'Ethernet24': {'peerdevice': 'dut1', 'peerport': 'Ethernet28'},
                'Ethernet28': {'peerdevice': 'dut1', 'peerport': 'Ethernet24'},
                'Ethernet32': {'peerdevice': 'dut1', 'peerport': 'Ethernet36'},
                'Ethernet36': {'peerdevice': 'dut1', 'peerport': 'Ethernet32'},
                'Ethernet40': {'peerdevice': 'tg1', 'peerport': 'Port3'},
                'Ethernet44': {'peerdevice': 'tg1', 'peerport': 'Port4'},
            }
        },
        device_port_vrfs={},
    )

    allocator.run()

    assert allocator.device_vlans['dut1'] == {
        'vlans': [
            {'vlan_id': 4001, 'ports': ['Ethernet0', 'Ethernet8']},
            {'vlan_id': 4002, 'ports': ['Ethernet12', 'Ethernet24']},
            {'vlan_id': 4003, 'ports': ['Ethernet28', 'Ethernet40']},
            {'vlan_id': 4004, 'ports': ['Ethernet4', 'Ethernet16']},
            {'vlan_id': 4005, 'ports': ['Ethernet20', 'Ethernet32']},
            {'vlan_id': 4006, 'ports': ['Ethernet36', 'Ethernet44']},
        ],
    }


def test_multi_device_tgen_split_is_done_per_dut():
    allocator = L2SnakeVlanAllocator(
        testbed_facts={
            'topo': {'properties': {'vlan_base': 3001}},
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
                'Ethernet4': {'peerdevice': 'dut1', 'peerport': 'Ethernet8'},
                'Ethernet8': {'peerdevice': 'dut1', 'peerport': 'Ethernet4'},
                'Ethernet12': {'peerdevice': 'tg1', 'peerport': 'Port2'},
            },
            'dut2': {
                'Ethernet0': {'peerdevice': 'tg1', 'peerport': 'Port3'},
                'Ethernet4': {'peerdevice': 'dut2', 'peerport': 'Ethernet8'},
                'Ethernet8': {'peerdevice': 'dut2', 'peerport': 'Ethernet4'},
                'Ethernet12': {'peerdevice': 'tg1', 'peerport': 'Port4'},
            },
        },
        device_port_vrfs={},
    )

    allocator.run()

    assert allocator.device_vlans['dut1'] == {
        'vlans': [
            {'vlan_id': 3001, 'ports': ['Ethernet0', 'Ethernet4']},
            {'vlan_id': 3002, 'ports': ['Ethernet8', 'Ethernet12']},
        ],
    }
    assert allocator.device_vlans['dut2'] == {
        'vlans': [
            {'vlan_id': 3003, 'ports': ['Ethernet0', 'Ethernet4']},
            {'vlan_id': 3004, 'ports': ['Ethernet8', 'Ethernet12']},
        ],
    }
