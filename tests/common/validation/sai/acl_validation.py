import logging

from tests.common.validation.sai.acl_validation_internal import fmt_asicdb_acl_value, rule_in_events
from tests.common.validation.sai.acl_validation_internal import to_list, tcp_flags_to_bitmask

logger = logging.getLogger(__name__)


def validate_acl_asicdb_entries(acl_rules, table_name, events, ip_version, gnmi_connection):
    """
    Check if all the input ACL rules from the config command have corresponding ASIC DB events/entries.
    """
    if gnmi_connection is None:
        logger.debug('gnmi_connection is None, skipping ACL validation')
        return True

    # TODO - Add support for ipv6
    if ip_version == 'ipv6':
        return True
    result = True
    logger.debug('Checking if the rules have the expected events')
    rules = acl_rules['acl']['acl-sets']['acl-set'][table_name]['acl-entries']['acl-entry']
    for _, rule in rules.items():
        logger.debug(f'Checking next rule: {rule}')
        rule_evt = {}
        action = None
        if (
            'actions' in rule
            and 'config' in rule['actions']
            and 'forwarding-action' in rule['actions']['config']
        ):
            action = fmt_asicdb_acl_value('action', rule['actions']['config']['forwarding-action'])
            rule_evt['SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION'] = action

        source_ip_address = None
        if (
            'ip' in rule
            and 'config' in rule['ip']
            and 'source-ip-address' in rule['ip']['config']
        ):
            source_ip_address = fmt_asicdb_acl_value('ip', rule['ip']['config']['source-ip-address'])
            rule_evt['SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP'] = source_ip_address

        destination_ip_address = None
        if (
            'ip' in rule
            and 'config' in rule['ip']
            and 'destination-ip-address' in rule['ip']['config']
        ):
            destination_ip_address = fmt_asicdb_acl_value('ip', rule['ip']['config']['destination-ip-address'])
            rule_evt['SAI_ACL_ENTRY_ATTR_FIELD_DST_IP'] = destination_ip_address

        source_port = None
        if (
            'transport' in rule
            and 'config' in rule['transport']
            and 'source-port' in rule['transport']['config']
        ):
            source_port = rule['transport']['config']['source-port']
            if '..' in source_port:
                range_limit = source_port.split('..')
                rule_evt['SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE'] = ("SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE",
                                                                       f'{range_limit[0]},{range_limit[1]}')
            else:
                rule_evt['SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT'] = f'{source_port}&mask:0xffff'

        destination_port = None
        if (
            'transport' in rule
            and 'config' in rule['transport']
            and 'destination-port' in rule['transport']['config']
        ):
            destination_port = rule['transport']['config']['destination-port']
            if '..' in destination_port:
                range_limit = destination_port.split('..')
                rule_evt['SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE'] = ("SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE",
                                                                       f'{range_limit[0]},{range_limit[1]}')
            else:
                rule_evt['SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT'] = f'{destination_port}&mask:0xffff'

        protocol = None
        if (
            'ip' in rule
            and 'config' in rule['ip']
            and 'protocol' in rule['ip']['config']
        ):
            protocol = rule['ip']['config']['protocol']
            rule_evt['SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL'] = f'{protocol}&mask:0xff'

        tcp_flags = None
        if (
            'transport' in rule
            and 'config' in rule['transport']
            and 'tcp-flags' in rule['transport']['config']
        ):
            tcp_flags = rule['transport']['config']['tcp-flags']
            flag_mask = tcp_flags_to_bitmask(to_list(tcp_flags))
            rule_evt['SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS'] = f'{flag_mask}&mask:{hex(flag_mask)}'

        sequence_id = None
        if (
            'config' in rule
            and 'sequence-id' in rule['config']
        ):
            sequence_id = rule['config']['sequence-id']

        logger.debug(f'rule_evt: {rule_evt}, sequence id {sequence_id}')
        if not rule_in_events(sequence_id, rule_evt, events, gnmi_connection):
            logger.debug(f'Rule event: {rule_evt} not found in events')
            result = False

    return result
