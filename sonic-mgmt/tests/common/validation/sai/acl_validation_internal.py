import logging
import re
import tests.common.sai_validation.gnmi_client as gnmi_client

logger = logging.getLogger(__name__)


def cidr_to_netmask(cidr):
    mask = (0xffffffff << (32 - cidr)) << (32 - cidr)
    return f'{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}'


def tcp_flags_to_bitmask(flags):
    # Define the bit positions for each flag
    flag_mapping = {
        'TCP_URG': 1 << 5,  # 0b00100000
        'TCP_ACK': 1 << 4,  # 0b00010000
        'TCP_PSH': 1 << 3,  # 0b00001000
        'TCP_RST': 1 << 2,  # 0b00000100
        'TCP_SYN': 1 << 1,  # 0b00000010
        'TCP_FIN': 1 << 0   # 0b00000001
    }

    # Initialize bitmask to 0
    bitmask = 0

    # Set the corresponding bits for each flag in the list
    for flag in flags:
        if flag in flag_mapping:
            bitmask |= flag_mapping[flag]
        else:
            raise ValueError(f"Unknown TCP flag: {flag}")

    return bitmask


def to_list(value):
    """
    Extract strings from a string representation of python list
    "['a', 'b', 'c']" -> ['a', 'b', 'c']
    """
    logger.debug(f'to_list input is of type {type(value)} and value is {value}')
    pattern = r'(["\'])(.*?)(\1)'
    if value is None or value == []:
        return []
    if isinstance(value, list):
        return value
    if not isinstance(value, str):
        raise ValueError(f'Invalid input type: {type(value)}')
    result = []
    v = re.findall(pattern, value)
    for i in v:
        result.append(i[1])
    logger.debug(f'Converted {value} to list: {result}')
    return result


def fmt_asicdb_acl_value(type, v):
    """
    Convert the value to SAI format
    """
    if type is None or v is None:
        return None

    if type == 'action':
        if v == 'DROP':
            return 'SAI_PACKET_ACTION_DROP'
        if v == 'FORWARD' or v == 'ACCEPT':
            return 'SAI_PACKET_ACTION_FORWARD'
        if v == 'COPY':
            return 'SAI_PACKET_ACTION_COPY'
        if v == 'TRAP':
            return 'SAI_PACKET_ACTION_TRAP'
        if v == 'LOG':
            return 'SAI_PACKET_ACTION_LOG'
        if v == 'DENY':
            return 'SAI_PACKET_ACTION_DENY'
        if v == 'TRANSIT':
            return 'SAI_PACKET_ACTION_TRANSIT'

    if type == 'ip':
        slash_pos = v.find('/')
        ip_addr = None
        ip_mask = None
        if slash_pos != -1:
            ip_addr = v[:slash_pos]
            ip_mask = v[slash_pos+1:]
        else:
            ip_addr = v
            ip_mask = '32'
        netmask = cidr_to_netmask(int(ip_mask))
        return f'{ip_addr}&mask:{netmask}'

    if type == 'protocol':
        return f'{v}&mask:0xff'


def match_rule_to_event(rule, event):
    for key in rule:
        if key not in event or rule[key] != event.get(key):
            return False
    return True


# given a known object id (SAI_OBJECT_TYPE_ACL_ENTRY:oid:0x1234) return
# its value from gnmi_events
def find_object_value(gnmi_events: list, object_id: str):
    logger.debug(f'finding object {object_id} in gnmi events')
    for event in gnmi_events:
        value_type = event.get('value_type')
        if value_type != 'JSON_IETF':
            logger.error(f'Event value type {value_type} is not JSON_IETF')
            continue
        event_value = event.get('value')
        # event_value is a dictionary of dictionaries for which we don't
        # know the key names
        value = event_value.get(object_id)
        logger.debug(f'found value {value} for object {object_id}')
        return value


# Given a object type but not the object id, find the value from
# gnmi_events. The object type example is SAI_OBJECT_TYPE_ACL_ENTRY
# or SAI_OBJECT_TYPE_ACL_RANGE or SAI_OBJECT_TYPE_ROUTE_ENTRY etc.
def find_object_value_by_type(gnmi_events: list, object_type: str) -> dict:
    values = {}
    logger.debug(f'finding object {object_type} in gnmi events')
    for event in gnmi_events:
        value_type = event.get('value_type')
        if value_type != 'JSON_IETF':
            logger.error(f'Event value type {value_type} is not JSON_IETF')
            continue
        event_value = event.get('value')
        # event_value is a dictionary of dictionaries for which we don't
        # know the key names
        for entry, value in event_value.items():
            logger.debug(f'find_object_value_by_type: entry {entry} value {value}')
            if entry.startswith(object_type):
                values[entry] = value
    logger.debug(f'found values {values} for object type {object_type}')
    return values


def rule_in_events(sequence_id, rule, events, gnmi_connection):
    fetch_range = False
    if 'SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE' in rule:
        fetch_range = True
    for evt_key, event in events.items():
        # if the rule is a range type we need to fetch corresponding range object of the
        # event and compare the range values.
        if 'SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE' in event and fetch_range:
            range_oid = event['SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE']
            oid = None
            if isinstance(range_oid, str):
                oid = range_oid[range_oid.find('oid:'):]
                path_str = f'ASIC_DB/localhost/ASIC_STATE/SAI_OBJECT_TYPE_ACL_RANGE:{oid}'
                gnmi_path = gnmi_client.get_gnmi_path(path_str)
                range_oid_values = gnmi_client.get_request(gnmi_connection, gnmi_path)
                logger.debug(f'found range oid values {range_oid_values} for range oid {oid}')
                # rewrite evt for comparison to match the rule format for comparison
                range_oid_value = range_oid_values[0]
                event['SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE'] = (range_oid_value['SAI_ACL_RANGE_ATTR_TYPE'],
                                                                    range_oid_value['SAI_ACL_RANGE_ATTR_LIMIT'])
            else:
                logger.debug(f'Event is already in the format required {event}')
        # logger.debug(f'searching in event (from ASIC_DB): {event}')
        if match_rule_to_event(rule, event):
            logger.debug('Found event for rule. Returning True')
            return True
    return False
