import re
from copy import deepcopy


NAME_PATTERN = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:/-]*')
HOST_PATTERN = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]*')
INTERFACE_PATTERN = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:-]*')
DECIMAL_PATTERN = re.compile(r'[0-9]+')
MIN_VLAN = 1
MAX_VLAN = 4094
VIRTUAL_ROW_FIELDS = frozenset((
    'dut_port', 'lanes', 'ptf_port_id', 'ptf_interface',
))
PHYSICAL_ROW_FIELDS = VIRTUAL_ROW_FIELDS | frozenset((
    'fanout_host', 'fanout_port', 'transport_vlan',
))


def _object(value, description):
    if not isinstance(value, dict):
        raise ValueError('{} must be an object'.format(description))
    return value


def _name(value, description, pattern=NAME_PATTERN):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError('invalid {}: {!r}'.format(description, value))
    return value


def _nonnegative_integer(value, description):
    if type(value) is not int or value < 0:
        raise ValueError('{} must be a non-negative integer'.format(description))
    return value


def _vlan(value):
    if type(value) is not int or not MIN_VLAN <= value <= MAX_VLAN:
        raise ValueError('transport VLAN must be an integer in 1..4094')
    return value


def _lanes(value):
    if isinstance(value, str):
        parts = [part.strip() for part in value.split(',')]
        if any(not DECIMAL_PATTERN.fullmatch(part) for part in parts):
            raise ValueError('lanes must contain comma-separated non-negative integers')
        lanes = [int(part) for part in parts]
    elif isinstance(value, list):
        lanes = list(value)
    else:
        raise ValueError('lanes must be a string or integer list')
    if not lanes:
        raise ValueError('lanes must not be empty')
    for lane in lanes:
        _nonnegative_integer(lane, 'lane')
    if len(lanes) != len(set(lanes)):
        raise ValueError('duplicate lane in port')
    return lanes


def _natural_key(value):
    return tuple((1, int(part)) if part.isdigit() else (0, part.lower())
                 for part in re.split(r'([0-9]+)', value))


def _port_table(config_db):
    ports = _object(_object(config_db, 'config_db').get('PORT'), 'PORT')
    if not ports:
        raise ValueError('PORT must not be empty')
    for port, entry in ports.items():
        _name(port, 'DUT port')
        _object(entry, 'PORT entry')
    return ports


def _selected_ports(value):
    if not isinstance(value, (list, tuple)) or not value:
        raise ValueError('selected ports must be a non-empty sequence')
    for port in value:
        _name(port, 'DUT port')
    if len(value) != len(set(value)):
        raise ValueError('duplicate selected DUT port')
    return value


def _vlan_map(value):
    result = {}
    for key, vlan in _object(value, 'DUT VLAN map').items():
        if isinstance(key, str) and DECIMAL_PATTERN.fullmatch(key):
            position = int(key)
        else:
            position = _nonnegative_integer(key, 'VLAN map position')
        if position in result:
            raise ValueError('duplicate VLAN map position: {}'.format(position))
        result[position] = _vlan(vlan)
    return result


def _ptf_endpoint(value):
    value = _object(value, 'PTF port map entry')
    port_id = _nonnegative_integer(value.get('id'), 'PTF port ID')
    interface = _name(value.get('interface'), 'PTF interface', INTERFACE_PATTERN)
    return port_id, interface


def _validate_mapping(mapping):
    if not isinstance(mapping, list) or not mapping:
        raise ValueError('mapping must be a non-empty list')
    seen = {key: set() for key in (
        'dut_port', 'lane', 'fanout_endpoint', 'transport_vlan',
        'ptf_port_id', 'ptf_interface',
    )}
    fields = frozenset(_object(mapping[0], 'mapping entry'))
    if fields not in (PHYSICAL_ROW_FIELDS, VIRTUAL_ROW_FIELDS):
        raise ValueError('mapping must have exact physical or virtual row fields')
    for row in mapping:
        if frozenset(_object(row, 'mapping entry')) != fields:
            raise ValueError('mapping rows must be homogeneous with exact fields')
        port = _name(row.get('dut_port'), 'DUT port')
        if not isinstance(row.get('lanes'), list):
            raise ValueError('mapping lanes must be an integer list')
        lanes = _lanes(row['lanes'])
        port_id, interface = _ptf_endpoint({
            'id': row.get('ptf_port_id'), 'interface': row.get('ptf_interface'),
        })
        values = {
            'dut_port': [port], 'lane': lanes, 'ptf_port_id': [port_id],
            'ptf_interface': [interface],
        }
        if fields == PHYSICAL_ROW_FIELDS:
            host = _name(row['fanout_host'], 'fanout host', HOST_PATTERN)
            peer = _name(row['fanout_port'], 'fanout port')
            values['fanout_endpoint'] = [(host, peer)]
            values['transport_vlan'] = [_vlan(row['transport_vlan'])]
        for key, items in values.items():
            for item in items:
                if item in seen[key]:
                    raise ValueError('duplicate {} in mapping: {}'.format(key, item))
                seen[key].add(item)


def build_port_mapping(graph, dut_name, selected_ports,
                       config_db, ptf_port_map) -> list[dict]:
    _object(graph, 'graph')
    _name(dut_name, 'DUT name', HOST_PATTERN)
    _selected_ports(selected_ports)
    ports = _port_table(config_db)
    ptf_ports = _object(ptf_port_map, 'ptf_port_map')
    connections = _object(
        _object(graph.get('device_conn'), 'device_conn').get(dut_name),
        'DUT connections',
    )
    vlans = _vlan_map(
        _object(graph.get('device_vlan_map_list'), 'device_vlan_map_list').get(dut_name),
    )
    positions = {port: position for position, port in enumerate(
        sorted(ports, key=lambda port: (_natural_key(port), port)),
    )}
    mapping = []
    for port in selected_ports:
        if port not in ports:
            raise ValueError('missing PORT entry: {}'.format(port))
        peer = _object(connections.get(port), 'connection for {}'.format(port))
        position = positions[port]
        if position not in vlans:
            raise ValueError('missing transport VLAN for {}'.format(port))
        port_id, interface = _ptf_endpoint(ptf_ports.get(port))
        mapping.append({
            'dut_port': port,
            'lanes': _lanes(ports[port].get('lanes')),
            'fanout_host': _name(peer.get('peerdevice'), 'fanout host', HOST_PATTERN),
            'fanout_port': _name(peer.get('peerport'), 'fanout port'),
            'transport_vlan': vlans[position],
            'ptf_port_id': port_id,
            'ptf_interface': interface,
        })
    _validate_mapping(mapping)
    return mapping


def build_virtual_port_mapping(config_db, selected_ports, ptf_port_map) -> list[dict]:
    ports = _port_table(config_db)
    _selected_ports(selected_ports)
    ptf_ports = _object(ptf_port_map, 'ptf_port_map')
    mapping = []
    for port in selected_ports:
        if port not in ports:
            raise ValueError('missing PORT entry: {}'.format(port))
        port_id, interface = _ptf_endpoint(ptf_ports.get(port))
        mapping.append({
            'dut_port': port,
            'lanes': _lanes(ports[port].get('lanes')),
            'ptf_port_id': port_id,
            'ptf_interface': interface,
        })
    _validate_mapping(mapping)
    return mapping


def interface_args(mapping) -> list[str]:
    _validate_mapping(mapping)
    args = []
    for row in mapping:
        args.extend(['--interface', '0-{}@{}'.format(
            row['ptf_port_id'], row['ptf_interface'],
        )])
    return args


def ptf_config_view(config_db, mapping) -> dict:
    ports = _port_table(config_db)
    _validate_mapping(mapping)
    selected = {row['dut_port'] for row in mapping}
    unknown = selected.difference(ports)
    if unknown:
        raise ValueError('mapping contains unknown PORT entries: {}'.format(sorted(unknown)))
    view = deepcopy(config_db)
    view['PORT'] = {row['dut_port']: view['PORT'][row['dut_port']] for row in mapping}
    return view
