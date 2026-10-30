import base64
import binascii
import hashlib
import json
import re

from ansible.errors import AnsibleFilterError


MACHINE_ID_PATTERN = re.compile(r'[0-9a-f]{32}')
PORT_NAME_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*')
PORT_FIELDS = frozenset(('admin_state', 'oper_state', 'speed'))
PORT_STATES = ('up', 'down')
SYSTEMD_ACTIVE_STATES = ('active', 'reloading')
SYSTEMD_INACTIVE_STATES = ('inactive', 'failed')
SONIC_STATUS_COLUMNS = (
    ('Interface', 'name'), ('Speed', 'speed'), ('Oper', 'oper_state'), ('Admin', 'admin_state'),
)


def ranking_dut_identity(text):
    value = text.strip().lower().replace('-', '') if isinstance(text, str) else ''
    if MACHINE_ID_PATTERN.fullmatch(value) is None or len(set(value)) == 1:
        raise AnsibleFilterError('DUT identity file must hold a unique 128-bit hexadecimal identity')
    return value


def ranking_image_fingerprint(results):
    if not isinstance(results, list) or not results:
        raise AnsibleFilterError('DUT image identity requires at least one slurped file')
    digest = hashlib.sha256()
    for result in results:
        try:
            parts = (result['item'].encode('utf-8'),
                     base64.b64decode(result['content'], validate=True))
        except (KeyError, TypeError, AttributeError, binascii.Error) as error:
            raise AnsibleFilterError('invalid DUT image identity record: {}'.format(error))
        for part in parts:
            digest.update(len(part).to_bytes(8, 'big'))
            digest.update(part)
    return 'sha256:' + digest.hexdigest()


def ranking_service_states(results, strict=True):
    states = {}
    for result in results:
        name = result['item']
        properties = dict(line.partition('=')[::2] for line in result['stdout'].splitlines())
        active = properties.get('ActiveState')
        if active in SYSTEMD_ACTIVE_STATES:
            states[name] = 'active'
        elif active in SYSTEMD_INACTIVE_STATES:
            states[name] = 'absent' if properties.get('LoadState') == 'not-found' else 'inactive'
        elif strict:
            raise AnsibleFilterError(
                'service {} is in transitional state {!r}; retry once it settles'.format(name, active))
        else:
            states[name] = active
    return states


def _port(name, port):
    if not isinstance(name, str) or PORT_NAME_PATTERN.fullmatch(name) is None:
        raise ValueError('invalid port name: {!r}'.format(name))
    if not isinstance(port, dict) or set(port) != PORT_FIELDS:
        raise ValueError('port {} must declare admin_state, oper_state, and speed'.format(name))
    if port['admin_state'] not in PORT_STATES or port['oper_state'] not in PORT_STATES:
        raise ValueError('port {} admin and oper states must be up or down'.format(name))
    if not isinstance(port['speed'], str) or not port['speed']:
        raise ValueError('port {} speed must be a non-empty string'.format(name))
    return dict(port)


def _json_ports(text):
    value = json.loads(text)
    if not isinstance(value, dict) or not value:
        raise ValueError('port baseline must be a non-empty object')
    return {name: _port(name, port) for name, port in value.items()}


def _sonic_ports(text):
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if index and line.strip() and not line.strip('- '):
            break
    else:
        raise ValueError('interface status table rule is missing')
    # Column extents come from the dash rule because Type and Alias values contain spaces.
    spans = [match.span() for match in re.finditer(r'-+', lines[index])]
    spans[-1] = (spans[-1][0], None)
    titles = [lines[index - 1][start:end].strip() for start, end in spans]
    if any(titles.count(title) != 1 for title, _ in SONIC_STATUS_COLUMNS):
        raise ValueError('interface status table lacks Interface, Speed, Oper, or Admin')
    positions = {field: titles.index(title) for title, field in SONIC_STATUS_COLUMNS}
    ports = {}
    for line in lines[index + 1:]:
        if not line.strip():
            continue
        cells = [line[start:end].strip() for start, end in spans]
        record = {field: cells[position] for field, position in positions.items()}
        name = record.pop('name')
        if name in ports:
            raise ValueError('duplicate port {}'.format(name))
        ports[name] = _port(name, record)
    if not ports:
        raise ValueError('interface status table has no ports')
    return ports


def ranking_port_states(text, port_format, strict=True):
    parsers = {'json': _json_ports, 'sonic_interfaces_status': _sonic_ports}
    try:
        if port_format not in parsers or not isinstance(text, str):
            raise ValueError('unsupported port baseline output')
        return parsers[port_format](text)
    except ValueError as error:
        if strict:
            raise AnsibleFilterError('cannot parse the DUT port baseline: {}'.format(error))
        return None


class FilterModule(object):
    def filters(self):
        return {
            'ranking_dut_identity': ranking_dut_identity,
            'ranking_image_fingerprint': ranking_image_fingerprint,
            'ranking_service_states': ranking_service_states,
            'ranking_port_states': ranking_port_states,
        }
