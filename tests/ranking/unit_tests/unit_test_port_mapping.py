import copy

import pytest

from tests.ranking.port_mapping import (
    build_port_mapping, interface_args, ptf_config_view,
)


def test_mapping_uses_natural_position_and_selection_order(inputs):
    original = copy.deepcopy(inputs)
    mapping = build_port_mapping(*inputs)
    assert mapping == [
        {'dut_port': 'Ethernet40', 'lanes': [40, 41, 42, 43],
         'fanout_host': 'fanout-a', 'fanout_port': 'Ethernet19',
         'transport_vlan': 3018, 'ptf_port_id': 18, 'ptf_interface': 'eth18'},
        {'dut_port': 'Ethernet8', 'lanes': [8, 9, 10, 11],
         'fanout_host': 'fanout-a', 'fanout_port': 'Ethernet2',
         'transport_vlan': 3007, 'ptf_port_id': 7, 'ptf_interface': 'eth7'},
    ]
    assert interface_args(mapping) == [
        '--interface', '0-18@eth18', '--interface', '0-7@eth7',
    ]
    assert inputs == original


def test_json_vlan_keys(inputs):
    inputs[0]['device_vlan_map_list']['dut-a'] = {'0': 3007, '1': 3018}
    assert [row['transport_vlan'] for row in build_port_mapping(*inputs)] == [3018, 3007]


def test_positions_include_unselected_hwsku_ports(inputs):
    inputs[3]['PORT']['Ethernet0'] = {'lanes': '0,1,2,3', 'index': '99'}
    inputs[0]['device_vlan_map_list']['dut-a'] = {1: 3007, 2: 3018}
    mapping = build_port_mapping(*inputs)
    assert [row['transport_vlan'] for row in mapping] == [3018, 3007]


def test_view_uses_mapping_order_and_preserves_config(inputs):
    config_db = inputs[3]
    original = copy.deepcopy(config_db)
    assert list(config_db['PORT']) == ['Ethernet8', 'Ethernet40']
    mapping = build_port_mapping(*inputs)
    view = ptf_config_view(config_db, mapping)
    assert list(view['PORT']) == ['Ethernet40', 'Ethernet8']
    for port in view['PORT']:
        assert view['PORT'][port] == original['PORT'][port]
        assert view['PORT'][port] is not config_db['PORT'][port]
    assert {key: value for key, value in view.items() if key != 'PORT'} == {
        key: value for key, value in original.items() if key != 'PORT'
    }
    assert config_db == original
    assert list(config_db['PORT']) == ['Ethernet8', 'Ethernet40']


def test_view_filters_ports_and_preserves_index(inputs):
    inputs[3]['PORT']['Ethernet80'] = {'lanes': '80,81', 'index': '22'}
    original = copy.deepcopy(inputs[3])
    mapping = build_port_mapping(*inputs)
    view = ptf_config_view(inputs[3], mapping)
    assert list(view['PORT']) == ['Ethernet40', 'Ethernet8']
    assert view['PORT']['Ethernet40']['index'] == '11'
    assert view['DEVICE_METADATA'] == original['DEVICE_METADATA']
    view['PORT']['Ethernet40']['index'] = '999'
    view['DEVICE_METADATA']['localhost']['hostname'] = 'changed'
    assert inputs[3] == original


@pytest.mark.parametrize('change', [
    lambda a: a[0]['device_vlan_map_list']['dut-a'].update({1: 3007}),
    lambda a: a[0]['device_vlan_map_list']['dut-a'].pop(1),
    lambda a: a[0]['device_vlan_map_list']['dut-a'].update({1: 0}),
    lambda a: a[0]['device_vlan_map_list']['dut-a'].update({1: 4095}),
    lambda a: a[0]['device_vlan_map_list']['dut-a'].update({1: True}),
    lambda a: a[0]['device_vlan_map_list']['dut-a'].update({1: '3018'}),
    lambda a: a[0]['device_vlan_map_list']['dut-a'].update({'0': 3007}),
    lambda a: a[0]['device_conn']['dut-a']['Ethernet40'].pop('peerport'),
    lambda a: a[0]['device_conn']['dut-a']['Ethernet40'].update(peerdevice=''),
    lambda a: a[0]['device_conn']['dut-a'].pop('Ethernet40'),
    lambda a: a[0]['device_conn']['dut-a']['Ethernet40'].update(peerport='Ethernet2'),
    lambda a: a[4]['Ethernet40'].update(interface='eth7'),
    lambda a: a[4]['Ethernet40'].update(id=7),
    lambda a: a[4]['Ethernet40'].update(id=True),
    lambda a: a[4]['Ethernet40'].update(id=-1),
    lambda a: a[4]['Ethernet40'].update(id='18'),
    lambda a: a[4]['Ethernet40'].update(interface='eth18;id'),
    lambda a: a[4]['Ethernet40'].update(interface='eth18\n'),
    lambda a: a[4]['Ethernet40'].pop('interface'),
    lambda a: a[4].pop('Ethernet40'),
    lambda a: a[3]['PORT']['Ethernet40'].update(lanes=''),
    lambda a: a[3]['PORT']['Ethernet40'].update(lanes='40,'),
    lambda a: a[3]['PORT']['Ethernet40'].update(lanes='40,40'),
    lambda a: a[3]['PORT']['Ethernet40'].update(lanes='10,40'),
    lambda a: a[3]['PORT']['Ethernet40'].update(lanes='-1'),
    lambda a: a[3]['PORT']['Ethernet40'].update(lanes=True),
    lambda a: a[3]['PORT']['Ethernet40'].update(lanes=[True]),
    lambda a: a[3]['PORT'].pop('Ethernet40'),
    lambda a: a[2].append('Ethernet40'),
    lambda a: a[2].append('Unknown'),
    lambda a: a[2].clear(),
])
def test_invalid_mapping_inputs(inputs, change):
    change(inputs)
    with pytest.raises(ValueError):
        build_port_mapping(*inputs)


@pytest.mark.parametrize('position,value', [
    (0, []), (1, 'dut-a;id'), (1, None), (2, 'Ethernet8'),
    (2, [True]), (3, []), (4, []),
])
def test_invalid_argument_types(inputs, position, value):
    args = list(inputs)
    args[position] = value
    with pytest.raises(ValueError):
        build_port_mapping(*args)


def test_zero_lane_and_ptf_id_are_valid(inputs):
    inputs[3]['PORT']['Ethernet8']['lanes'] = '0,1'
    inputs[4]['Ethernet8']['id'] = 0
    mapping = build_port_mapping(*inputs)
    assert mapping[1]['lanes'] == [0, 1]
    assert interface_args(mapping)[-1] == '0-0@eth7'


@pytest.mark.parametrize('field,value', [
    ('ptf_interface', 'eth18@oops'), ('ptf_port_id', True),
    ('ptf_port_id', -1), ('ptf_interface', None),
])
def test_interface_args_revalidates_boundary(inputs, field, value):
    mapping = build_port_mapping(*inputs)
    mapping[0][field] = value
    with pytest.raises(ValueError):
        interface_args(mapping)


def test_interface_args_rejects_duplicates(inputs):
    mapping = build_port_mapping(*inputs)
    mapping.append(copy.deepcopy(mapping[0]))
    with pytest.raises(ValueError):
        interface_args(mapping)


def test_view_rejects_unknown_port(inputs):
    mapping = build_port_mapping(*inputs)
    mapping[0]['dut_port'] = 'Unknown'
    with pytest.raises(ValueError):
        ptf_config_view(inputs[3], mapping)


def _virtual_mapping(inputs):
    from tests.ranking import port_mapping

    builder = getattr(port_mapping, 'build_virtual_port_mapping', None)
    assert builder is not None, 'S2.1 virtual mapping API is not implemented'
    return builder(inputs[3], inputs[2], inputs[4])


def test_virtual_mapping_exact_order_and_detachment(inputs):
    original = copy.deepcopy(inputs)
    mapping = _virtual_mapping(inputs)
    assert mapping == [
        {'dut_port': 'Ethernet40', 'lanes': [40, 41, 42, 43],
         'ptf_port_id': 18, 'ptf_interface': 'eth18'},
        {'dut_port': 'Ethernet8', 'lanes': [8, 9, 10, 11],
         'ptf_port_id': 7, 'ptf_interface': 'eth7'},
    ]
    assert interface_args(mapping) == [
        '--interface', '0-18@eth18', '--interface', '0-7@eth7']
    assert list(ptf_config_view(inputs[3], mapping)['PORT']) == [
        'Ethernet40', 'Ethernet8']
    mapping[0]['lanes'].clear()
    assert inputs == original


@pytest.mark.parametrize('mutation', [
    lambda a: a[3].pop('PORT'),
    lambda a: a[3]['PORT']['Ethernet40'].update(lanes='8,40'),
    lambda a: a[3]['PORT']['Ethernet40'].update(lanes=[True]),
    lambda a: a[3]['PORT'].pop('Ethernet40'),
    lambda a: a[2].append('Ethernet40'),
    lambda a: a[2].clear(),
    lambda a: a[4]['Ethernet40'].update(id=7),
    lambda a: a[4]['Ethernet40'].update(interface='eth7'),
    lambda a: a[4]['Ethernet40'].update(id=True),
    lambda a: a[4].pop('Ethernet40'),
])
def test_virtual_mapping_invalid_inputs(inputs, mutation):
    mutation(inputs)
    with pytest.raises(ValueError):
        _virtual_mapping(inputs)


@pytest.mark.parametrize('mutation', [
    lambda m: m[0].update(extra=1),
    lambda m: m[0].pop('fanout_port'),
    lambda m: [m[0].pop(key) for key in (
        'fanout_host', 'fanout_port', 'transport_vlan')],
])
@pytest.mark.parametrize('consumer', [interface_args, ptf_config_view])
def test_mapping_requires_exact_homogeneous_rows(inputs, mutation, consumer):
    mapping = build_port_mapping(*inputs)
    mutation(mapping)
    with pytest.raises(ValueError):
        if consumer is ptf_config_view:
            consumer(inputs[3], mapping)
        else:
            consumer(mapping)
