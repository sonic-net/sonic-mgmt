import re
from pathlib import Path


NAME_PATTERN = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:/-]*')
INTERFACE_PATTERN = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:-]*')
DECIMAL_PATTERN = re.compile(r'[0-9]+')
MAPPING_FIELDS = frozenset((
    'dut_port', 'lanes', 'ptf_port_id', 'ptf_interface',
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


def _ptf_endpoint(value):
    value = _object(value, 'PTF port map entry')
    port_id = _nonnegative_integer(value.get('id'), 'PTF port ID')
    interface = _name(value.get('interface'), 'PTF interface', INTERFACE_PATTERN)
    return port_id, interface


def _validate_mapping(mapping):
    if not isinstance(mapping, list) or not mapping:
        raise ValueError('mapping must be a non-empty list')
    seen = {key: set() for key in (
        'dut_port', 'lane', 'ptf_port_id', 'ptf_interface',
    )}
    for row in mapping:
        if frozenset(_object(row, 'mapping entry')) != MAPPING_FIELDS:
            raise ValueError('mapping must have the exact common row fields')
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
        for key, items in values.items():
            for item in items:
                if item in seen[key]:
                    raise ValueError('duplicate {} in mapping: {}'.format(key, item))
                seen[key].add(item)


def build_port_mapping(config_db, selected_ports, ptf_port_map) -> list[dict]:
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


def load_port_config(path) -> dict:
    """Read the existing port_config.ini columns without importing PTF assets."""
    header = None
    ports = {}
    for number, line in enumerate(Path(path).read_text(encoding='utf-8').splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        if line.startswith('#'):
            columns = line.lstrip('#').split()
            if columns and columns[0] == 'name':
                if header is not None or len(columns) != len(set(columns)):
                    raise ValueError('duplicate port_config.ini header')
                if not {'name', 'lanes', 'index', 'speed'}.issubset(columns):
                    raise ValueError('port_config.ini requires name, lanes, index and speed')
                header = columns
            continue
        if header is None:
            raise ValueError('port_config.ini requires a commented column header')
        values = line.split()
        if len(values) != len(header):
            raise ValueError('port_config.ini column count differs at line {}'.format(number))
        row = dict(zip(header, values))
        name = _name(row.pop('name'), 'DUT port')
        if name in ports:
            raise ValueError('duplicate port in port_config.ini: {}'.format(name))
        row['lanes'] = _lanes(row['lanes'])
        _port_integer(row['index'], 'PORT index', 0)
        _port_integer(row['speed'], 'PORT speed', 1)
        ports[name] = row
    if not ports:
        raise ValueError('port_config.ini must contain ports')
    return ports


def _port_integer(value, description, minimum):
    if isinstance(value, str) and DECIMAL_PATTERN.fullmatch(value):
        number = int(value)
    elif type(value) is int:
        number = value
    else:
        raise ValueError('{} must be an integer or numeric string'.format(description))
    if number < minimum:
        raise ValueError('{} must be at least {}'.format(description, minimum))
    return str(value)
