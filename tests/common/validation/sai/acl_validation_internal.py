import logging
import re
import redis

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


def rule_in_events(rule, events, asic_db_connection: redis.Redis):
    logger.debug('searching for rule')
    fetch_range = False
    if 'SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE' in rule:
        fetch_range = True
    for evt_key, event in events.items():
        # Fetch event again from ASIC DB events produced during creation of
        # ACL rule does not populate all values in the event.
        # TODO: Find a way to avoid accessing db.
        evt = asic_db_connection.hgetall(evt_key)
        # if the rule is a range type we need to fetch corresponding range object of the
        # event and compare the range values.
        if 'SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE' in evt and fetch_range:
            range_oid = evt['SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE']
            oid = range_oid[range_oid.find('oid:'):]
            range = asic_db_connection.hgetall(f'ASIC_STATE:SAI_OBJECT_TYPE_ACL_RANGE:{oid}')
            # rewrite evt for comparison to match the rule format for comparison
            evt['SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE'] = (range['SAI_ACL_RANGE_ATTR_TYPE'],
                                                              range['SAI_ACL_RANGE_ATTR_LIMIT'])
        logger.debug(f'searching in event (from ASIC_DB): {evt}')
        if match_rule_to_event(rule, evt):
            logger.debug('Found event for rule. Returning True')
            return True
    logger.debug('Event for rule not found. Returning False')
    return False
