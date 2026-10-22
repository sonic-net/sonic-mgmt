import copy

import pytest

from tests.ranking.environments.sonic_sonic.port_mapping import (
    build_port_mapping, interface_args, load_port_config,
)


def test_mapping_preserves_real_lanes_selection_order_and_inputs(inputs):
    original = copy.deepcopy(inputs)
    mapping = build_port_mapping(*inputs)
    assert mapping == [
        {'dut_port': 'Ethernet40', 'lanes': [40, 41, 42, 43],
         'ptf_port_id': 18, 'ptf_interface': 'eth18'},
        {'dut_port': 'Ethernet8', 'lanes': [8, 9, 10, 11],
         'ptf_port_id': 7, 'ptf_interface': 'eth7'},
    ]
    assert interface_args(mapping) == [
        '--interface', '0-18@eth18', '--interface', '0-7@eth7',
    ]
    mapping[0]['lanes'].clear()
    assert inputs == original


def test_one_three_argument_mapping_api_for_both_topologies():
    config = {'PORT': {
        'Ethernet9': {'lanes': '17,18,19,20', 'index': '9', 'speed': '400000'},
        'Ethernet5': {'lanes': '25,26,27,28', 'index': '5', 'speed': '400000'},
    }}
    ports = {'Ethernet9': {'id': 18, 'interface': 'eth18'},
             'Ethernet5': {'id': 7, 'interface': 'eth7'}}
    mapping = build_port_mapping(config, ['Ethernet5', 'Ethernet9'], ports)
    assert mapping == [
        {'dut_port': 'Ethernet5', 'lanes': [25, 26, 27, 28],
         'ptf_port_id': 7, 'ptf_interface': 'eth7'},
        {'dut_port': 'Ethernet9', 'lanes': [17, 18, 19, 20],
         'ptf_port_id': 18, 'ptf_interface': 'eth18'},
    ]


@pytest.mark.parametrize('change', [
    lambda a: a[2]['Ethernet40'].update(interface='eth7'),
    lambda a: a[2]['Ethernet40'].update(id=7),
    lambda a: a[2]['Ethernet40'].update(id=True),
    lambda a: a[2]['Ethernet40'].update(id=-1),
    lambda a: a[2]['Ethernet40'].update(id='18'),
    lambda a: a[2]['Ethernet40'].update(interface='eth18;id'),
    lambda a: a[2]['Ethernet40'].update(interface='eth18\n'),
    lambda a: a[2]['Ethernet40'].pop('interface'),
    lambda a: a[2].pop('Ethernet40'),
    lambda a: a[0].pop('PORT'),
    lambda a: a[0]['PORT']['Ethernet40'].update(lanes=''),
    lambda a: a[0]['PORT']['Ethernet40'].update(lanes='40,'),
    lambda a: a[0]['PORT']['Ethernet40'].update(lanes='40,40'),
    lambda a: a[0]['PORT']['Ethernet40'].update(lanes='10,40'),
    lambda a: a[0]['PORT']['Ethernet40'].update(lanes='-1'),
    lambda a: a[0]['PORT']['Ethernet40'].update(lanes=True),
    lambda a: a[0]['PORT']['Ethernet40'].update(lanes=[True]),
    lambda a: a[0]['PORT'].pop('Ethernet40'),
    lambda a: a[1].append('Ethernet40'),
    lambda a: a[1].append('Unknown'),
    lambda a: a[1].clear(),
])
def test_invalid_mapping_inputs(inputs, change):
    change(inputs)
    with pytest.raises(ValueError):
        build_port_mapping(*inputs)


@pytest.mark.parametrize('position,value', [
    (0, []), (0, {}), (0, {'PORT': {}}), (1, 'Ethernet8'),
    (1, [True]), (1, None), (2, []),
])
def test_invalid_argument_types(inputs, position, value):
    args = list(inputs)
    args[position] = value
    with pytest.raises(ValueError):
        build_port_mapping(*args)


def test_zero_lane_and_ptf_id_are_valid(inputs):
    inputs[0]['PORT']['Ethernet8']['lanes'] = '0,1'
    inputs[2]['Ethernet8']['id'] = 0
    mapping = build_port_mapping(*inputs)
    assert mapping[1]['lanes'] == [0, 1]
    assert interface_args(mapping)[-1] == '0-0@eth7'


@pytest.mark.parametrize('field,value', [
    ('ptf_interface', 'eth18@oops'), ('ptf_port_id', True),
    ('ptf_port_id', -1), ('ptf_interface', None), ('lanes', '40,41'),
    ('lanes', []), ('lanes', [True]), ('dut_port', 'Ethernet40;id'),
])
def test_interface_args_revalidates_boundary(inputs, field, value):
    mapping = build_port_mapping(*inputs)
    mapping[0][field] = value
    with pytest.raises(ValueError):
        interface_args(mapping)


@pytest.mark.parametrize('field,value', [
    ('dut_port', 'Ethernet40'), ('lanes', [40]),
    ('ptf_port_id', 18), ('ptf_interface', 'eth18'),
])
def test_mapping_consumers_reject_duplicates(inputs, field, value):
    mapping = build_port_mapping(*inputs)
    mapping[1][field] = value
    with pytest.raises(ValueError, match='duplicate'):
        interface_args(mapping)


@pytest.mark.parametrize('mutation', [
    lambda m: m[0].update(extra=1),
    lambda m: m[0].pop('ptf_interface'),
    lambda m: m[0].update(fanout_host='fanout-a', fanout_port='Ethernet2',
                          transport_vlan=3007),
])
def test_mapping_requires_exact_common_rows(inputs, mutation):
    mapping = build_port_mapping(*inputs)
    mutation(mapping)
    with pytest.raises(ValueError):
        interface_args(mapping)


def test_load_existing_port_config_columns(tmp_path):
    source = tmp_path / 'port_config.ini'
    source.write_text('# SONiC port config\n# name speed alias lanes index fec\n'
                      'Ethernet9 400000 etp2 17,18,19,20 9 rs\n'
                      'Ethernet5 200000 etp1 25,26 5 rs\n')
    assert load_port_config(source) == {
        'Ethernet9': {'speed': '400000', 'alias': 'etp2', 'lanes': [17, 18, 19, 20],
                     'index': '9', 'fec': 'rs'},
        'Ethernet5': {'speed': '200000', 'alias': 'etp1', 'lanes': [25, 26],
                     'index': '5', 'fec': 'rs'},
    }


@pytest.mark.parametrize('text', [
    '', '# name lanes index speed\n', 'Ethernet0 0,1 0 100000\n',
    '# name lanes index\nEthernet0 0,1 0\n',
    '# name lanes index index speed\nEthernet0 0,1 0 0 100000\n',
    '# name lanes index speed\n# name lanes index speed\nEthernet0 0 0 100000\n',
    '# name lanes index speed\nEthernet0 0,1 0\n',
    '# name lanes index speed\nEthernet0 0,1 0 100000\nEthernet0 2,3 1 100000\n',
    '# name lanes index speed\nEthernet0 0,0 0 100000\n',
    '# name lanes index speed\nEthernet0 -1 0 100000\n',
    '# name lanes index speed\nEthernet0 0 -1 100000\n',
    '# name lanes index speed\nEthernet0 0 0 0\n',
])
def test_load_port_config_rejects_invalid_input(tmp_path, text):
    source = tmp_path / 'port_config.ini'
    source.write_text(text)
    with pytest.raises(ValueError):
        load_port_config(source)
