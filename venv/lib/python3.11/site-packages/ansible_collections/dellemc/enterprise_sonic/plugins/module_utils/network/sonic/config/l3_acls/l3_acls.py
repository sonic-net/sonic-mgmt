#
# -*- coding: utf-8 -*-
# Copyright 2022 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_l3_acls class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ast import literal_eval

from ansible.module_utils._text import to_text
from ansible.module_utils.common.validation import check_required_arguments
from ansible.module_utils.connection import ConnectionError
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
    remove_empties,
    validate_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    update_states
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_CONFIG_IF_NO_SUBCONFIG,
    get_new_config,
    get_formatted_config_diff
)

DELETE = 'delete'
PATCH = 'patch'
POST = 'post'

TEST_KEYS_formatted_diff = [
    {'config': {'address_family': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'acls': {'name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'rules': {'sequence_num': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
]

L4_PORT_START = 0
L4_PORT_END = 65535

protocol_number_to_name_map = {
    1: 'icmp',
    6: 'tcp',
    17: 'udp',
    58: 'icmpv6'
}
dscp_value_to_name_map = {
    0: 'default',
    8: 'cs1',
    16: 'cs2',
    24: 'cs3',
    32: 'cs4',
    40: 'cs5',
    48: 'cs6',
    56: 'cs7',
    10: 'af11',
    12: 'af12',
    14: 'af13',
    18: 'af21',
    20: 'af22',
    22: 'af23',
    26: 'af31',
    28: 'af32',
    30: 'af33',
    34: 'af41',
    36: 'af42',
    38: 'af43',
    46: 'ef',
    44: 'voice_admit'
}

# Spec value to payload value mappings
acl_type_to_payload_map = {
    'ipv4': 'ACL_IPV4',
    'ipv6': 'ACL_IPV6'
}
acl_type_to_host_mask_map = {
    'ipv4': '/32',
    'ipv6': '/128'
}
action_value_to_payload_map = {
    'permit': 'ACCEPT',
    'discard': 'DISCARD',
    'do-not-nat': 'DO_NOT_NAT',
    'deny': 'DROP',
    'transit': 'TRANSIT'
}
protocol_name_to_payload_map = {
    'icmp': 'IP_ICMP',
    'icmpv6': 58,
    'tcp': 'IP_TCP',
    'udp': 'IP_UDP'
}
protocol_number_to_payload_map = {
    2: 'IP_IGMP',
    46: 'IP_RSVP',
    47: 'IP_GRE',
    51: 'IP_AUTH',
    103: 'IP_PIM',
    115: 'IP_L2TP'
}
dscp_name_to_value_map = {v: k for k, v in dscp_value_to_name_map.items()}


class L3_acls(ConfigBase):
    """
    The sonic_l3_acls class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'l3_acls',
    ]

    acl_path = 'data/openconfig-acl:acl/acl-sets/acl-set'
    l3_acl_path = 'data/openconfig-acl:acl/acl-sets/acl-set={acl_name},{acl_type}'
    l3_acl_rule_path = 'data/openconfig-acl:acl/acl-sets/acl-set={acl_name},{acl_type}/acl-entries'
    l3_acl_remark_path = 'data/openconfig-acl:acl/acl-sets/acl-set={acl_name},{acl_type}/config/description'

    def __init__(self, module):
        super(L3_acls, self).__init__(module)

    def get_l3_acls_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        l3_acls_facts = facts['ansible_network_resources'].get('l3_acls')
        if not l3_acls_facts:
            return []
        return l3_acls_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = []

        existing_l3_acls_facts = self.get_l3_acls_facts()
        commands, requests = self.set_config(existing_l3_acls_facts)
        if commands:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._handle_failure_response(exc)

            result['changed'] = True

        changed_l3_acls_facts = self.get_l3_acls_facts()

        result['before'] = existing_l3_acls_facts
        if result['changed']:
            result['after'] = changed_l3_acls_facts

        result['commands'] = commands

        new_config = changed_l3_acls_facts
        old_config = existing_l3_acls_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_l3_acls_facts,
                                        TEST_KEYS_formatted_diff)
            self.post_process_generated_config(new_config)
            result['after(generated)'] = new_config
        if self._module._diff:
            self.sort_config(new_config)
            self.sort_config(old_config)
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)
        result['warnings'] = warnings
        return result

    def set_config(self, existing_l3_acls_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        if want:
            want = self.validate_and_normalize_config(want)
        else:
            want = []

        have = existing_l3_acls_facts
        resp = self.set_state(want, have)
        return to_list(resp)

    def set_state(self, want, have):
        """ Select the appropriate function based on the state provided

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        state = self._module.params['state']
        if state in ('merged', 'overridden', 'replaced'):
            commands, requests = self._state_merged_overridden_replaced(want, have, state)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)

        return commands, requests

    def _handle_failure_response(self, connection_error):
        log = None
        try:
            response = literal_eval(connection_error.args[0])
            error_app_tag = response['ietf-restconf:errors']['error'][0].get('error-app-tag')
        except Exception:
            pass
        else:
            if error_app_tag == 'too-many-elements':
                log = 'Exceeds maximum number of ACL / ACL Rules'
            elif error_app_tag == 'update-not-allowed':
                log = 'Creating ACLs with same name and different type not allowed'

        if log:
            response.update({u'log': log})
            self._module.fail_json(msg=to_text(response), code=connection_error.code)
        else:
            self._module.fail_json(msg=str(connection_error), code=connection_error.code)

    def _state_merged_overridden_replaced(self, want, have, state):
        """ The command generator when state is merged/overridden/replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        add_commands = []
        del_commands = []
        commands = []

        add_requests = []
        del_requests = []
        requests = []

        have_dict = self._convert_config_list_to_dict(have)
        want_dict = self._convert_config_list_to_dict(want)

        for acl_type in ('ipv4', 'ipv6'):
            acl_type_add_commands = []
            acl_type_del_commands = []

            have_acl_names = set(have_dict.get(acl_type, {}).keys())
            want_acl_names = set(want_dict.get(acl_type, {}).keys())

            if state == 'overridden':
                # Delete non-modified ACLs
                for acl_name in have_acl_names.difference(want_acl_names):
                    acl_type_del_commands.append({'name': acl_name})
                    del_requests.append(self.get_delete_l3_acl_request(acl_type, acl_name))

            # Modify existing ACLs
            for acl_name in want_acl_names.intersection(have_acl_names):
                acl_add_command = {'name': acl_name}
                acl_del_command = {'name': acl_name}
                rule_add_commands = []
                rule_del_commands = []

                have_acl = have_dict[acl_type][acl_name]
                want_acl = want_dict[acl_type][acl_name]
                if not want_acl['remark']:
                    if have_acl['remark'] and state in ('replaced', 'overridden'):
                        acl_del_command['remark'] = have_acl['remark']
                        del_requests.append(self.get_delete_l3_acl_remark_request(acl_type, acl_name))
                else:
                    if want_acl['remark'] != have_acl['remark']:
                        acl_add_command['remark'] = want_acl['remark']
                        add_requests.append(self.get_create_l3_acl_remark_request(acl_type, acl_name, want_acl['remark']))

                have_seq_nums = set(have_acl['rules'].keys())
                want_seq_nums = set(want_acl['rules'].keys())

                if state in ('replaced', 'overridden'):
                    # Delete non-modified rules
                    for seq_num in have_seq_nums.difference(want_seq_nums):
                        rule_del_commands.append({'sequence_num': seq_num})
                        del_requests.append(self.get_delete_l3_acl_rule_request(acl_type, acl_name, seq_num))

                for seq_num in want_seq_nums.intersection(have_seq_nums):
                    # Replace existing rules
                    if have_acl['rules'][seq_num] != want_acl['rules'][seq_num]:
                        if state == 'merged':
                            self._module.fail_json(
                                msg="Cannot update existing sequence {0} of {1} ACL {2} with state merged."
                                    " Please use state replaced or overridden.".format(seq_num, acl_type, acl_name)
                            )

                        rule_del_commands.append({'sequence_num': seq_num})
                        del_requests.append(self.get_delete_l3_acl_rule_request(acl_type, acl_name, seq_num))

                        rule_add_commands.append(want_acl['rules'][seq_num])
                        add_requests.append(self.get_create_l3_acl_rule_request(acl_type, acl_name, seq_num, want_acl['rules'][seq_num]))

                # Add new rules
                for seq_num in want_seq_nums.difference(have_seq_nums):
                    rule_add_commands.append(want_acl['rules'][seq_num])
                    add_requests.append(self.get_create_l3_acl_rule_request(acl_type, acl_name, seq_num, want_acl['rules'][seq_num]))

                if rule_del_commands:
                    acl_del_command['rules'] = rule_del_commands
                if rule_add_commands:
                    acl_add_command['rules'] = rule_add_commands

                if acl_del_command.get('rules') or acl_del_command.get('remark'):
                    acl_type_del_commands.append(acl_del_command)
                if acl_add_command.get('rules') or acl_add_command.get('remark'):
                    acl_type_add_commands.append(acl_add_command)

            # Add new ACLs
            for acl_name in want_acl_names.difference(have_acl_names):
                acl_add_command = {'name': acl_name}
                add_requests.append(self.get_create_l3_acl_request(acl_type, acl_name))

                want_acl = want_dict[acl_type][acl_name]
                if want_acl['remark']:
                    acl_add_command['remark'] = want_acl['remark']
                    add_requests.append(self.get_create_l3_acl_remark_request(acl_type, acl_name, want_acl['remark']))

                # Add new rules
                want_seq_nums = set(want_acl['rules'].keys())
                if want_seq_nums:
                    acl_add_command['rules'] = []
                    for seq_num in want_seq_nums:
                        acl_add_command['rules'].append(want_acl['rules'][seq_num])
                        add_requests.append(self.get_create_l3_acl_rule_request(acl_type, acl_name, seq_num, want_acl['rules'][seq_num]))

                acl_type_add_commands.append(acl_add_command)

            if acl_type_del_commands:
                del_commands.append({'address_family': acl_type, 'acls': acl_type_del_commands})

            if acl_type_add_commands:
                add_commands.append({'address_family': acl_type, 'acls': acl_type_add_commands})

        if del_commands:
            commands = update_states(del_commands, 'deleted')
            requests = del_requests

        if add_commands:
            commands.extend(update_states(add_commands, state))
            requests.extend(add_requests)

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        commands = []
        requests = []

        if not want:
            for config in have:
                if not config.get('acls'):
                    continue

                acl_type_commands = []
                acl_type = config['address_family']
                for acl in config['acls']:
                    acl_type_commands.append({'name': acl['name']})
                    requests.append(self.get_delete_l3_acl_request(acl_type, acl['name']))

                if acl_type_commands:
                    commands.append({'address_family': acl_type, 'acls': acl_type_commands})
        else:
            have_dict = self._convert_config_list_to_dict(have)
            want_dict = self._convert_config_list_to_dict(want)

            for acl_type in ('ipv4', 'ipv6'):
                acl_type_commands = []
                have_acl_names = set(have_dict.get(acl_type, {}).keys())
                want_acl_names = set(want_dict.get(acl_type, {}).keys())

                # If only the type is specified, delete all ACLs of that type
                if acl_type in want_dict and not want_acl_names:
                    for acl_name in have_acl_names:
                        acl_type_commands.append({'name': acl_name})
                        requests.append(self.get_delete_l3_acl_request(acl_type, acl_name))

                # Delete existing ACLs
                for acl_name in want_acl_names.intersection(have_acl_names):
                    have_acl = have_dict[acl_type][acl_name]
                    want_acl = want_dict[acl_type][acl_name]

                    # Delete entire ACL if only the name is specified
                    if not want_acl['remark'] and not want_acl['rules']:
                        acl_type_commands.append({'name': acl_name})
                        requests.append(self.get_delete_l3_acl_request(acl_type, acl_name))
                        continue

                    acl_del_command = {'name': acl_name}
                    rule_del_commands = []
                    have_seq_nums = set(have_acl['rules'].keys())
                    want_seq_nums = set(want_acl['rules'].keys())

                    if want_acl['remark'] and want_acl['remark'] == have_acl['remark']:
                        acl_del_command['remark'] = want_acl['remark']
                        requests.append(self.get_delete_l3_acl_remark_request(acl_type, acl_name))

                    # Delete existing rules
                    # When state is deleted, options other than sequence_num are not considered
                    for seq_num in want_seq_nums.intersection(have_seq_nums):
                        rule_del_commands.append({'sequence_num': seq_num})
                        requests.append(self.get_delete_l3_acl_rule_request(acl_type, acl_name, seq_num))

                    if rule_del_commands:
                        acl_del_command['rules'] = rule_del_commands

                    if acl_del_command.get('rules') or acl_del_command.get('remark'):
                        acl_type_commands.append(acl_del_command)

                if acl_type_commands:
                    commands.append({'address_family': acl_type, 'acls': acl_type_commands})

        commands = update_states(commands, "deleted")
        return commands, requests

    def get_create_l3_acl_request(self, acl_type, acl_name):
        """Get request to create L3 ACL with specified type and name"""
        url = self.acl_path
        payload = {
            'acl-set': [{
                'name': acl_name,
                'type': acl_type_to_payload_map[acl_type],
                'config': {
                    'name': acl_name,
                    'type': acl_type_to_payload_map[acl_type]
                }
            }]
        }

        return {'path': url, 'method': PATCH, 'data': payload}

    def get_create_l3_acl_remark_request(self, acl_type, acl_name, remark):
        """Get request to add given remark to the specified L3 ACL"""
        url = self.l3_acl_remark_path.format(acl_name=acl_name, acl_type=acl_type_to_payload_map[acl_type])
        payload = {'description': remark}
        return {'path': url, 'method': PATCH, 'data': payload}

    def get_create_l3_acl_rule_request(self, acl_type, acl_name, seq_num, rule):
        """Get request to create a rule with given sequence number
        and configuration in the specified L3 ACL
        """
        url = self.l3_acl_rule_path.format(acl_name=acl_name, acl_type=acl_type_to_payload_map[acl_type])
        payload = {
            'openconfig-acl:acl-entry': [{
                'sequence-id': seq_num,
                'config': {
                    'sequence-id': seq_num
                },
                acl_type: {
                    'config': {}
                },
                'transport': {
                    'config': {}
                },
                'actions': {
                    'config': {
                        'forwarding-action': action_value_to_payload_map[rule['action']]
                    }
                }
            }]
        }
        rule_l3_config = payload['openconfig-acl:acl-entry'][0][acl_type]['config']
        rule_l4_config = payload['openconfig-acl:acl-entry'][0]['transport']['config']

        if rule['protocol'].get('number') is not None:
            protocol = rule['protocol']['number']
            rule_l3_config['protocol'] = protocol_number_to_payload_map.get(protocol, protocol)
        else:
            protocol = rule['protocol']['name']
            if protocol not in ('ip', 'ipv6'):
                rule_l3_config['protocol'] = protocol_name_to_payload_map[protocol]

        if rule['source'].get('host'):
            rule_l3_config['source-address'] = rule['source']['host'] + acl_type_to_host_mask_map[acl_type]
        elif rule['source'].get('prefix'):
            rule_l3_config['source-address'] = rule['source']['prefix']

        src_port_number = self._convert_port_dict_to_payload_format(rule['source'].get('port_number'))
        if src_port_number:
            rule_l4_config['source-port'] = src_port_number

        if rule['destination'].get('host'):
            rule_l3_config['destination-address'] = rule['destination']['host'] + acl_type_to_host_mask_map[acl_type]
        elif rule['destination'].get('prefix'):
            rule_l3_config['destination-address'] = rule['destination']['prefix']

        dest_port_number = self._convert_port_dict_to_payload_format(rule['destination'].get('port_number'))
        if dest_port_number:
            rule_l4_config['destination-port'] = dest_port_number

        if rule.get('protocol_options'):
            if protocol in ('icmp', 'icmpv6') and rule['protocol_options'].get(protocol):
                if rule['protocol_options'][protocol].get('type') is not None:
                    rule_l4_config['icmp-type'] = rule['protocol_options'][protocol]['type']
                if rule['protocol_options'][protocol].get('code') is not None:
                    rule_l4_config['icmp-code'] = rule['protocol_options'][protocol]['code']
            elif rule['protocol_options'].get('tcp'):
                if rule['protocol_options']['tcp'].get('established'):
                    rule_l4_config['tcp-session-established'] = True
                else:
                    tcp_flag_list = []
                    for tcp_flag in rule['protocol_options']['tcp'].keys():
                        if rule['protocol_options']['tcp'][tcp_flag]:
                            tcp_flag_list.append('tcp_{0}'.format(tcp_flag).upper())

                    if tcp_flag_list:
                        rule_l4_config['tcp-flags'] = tcp_flag_list

        if rule.get('vlan_id') is not None:
            payload['openconfig-acl:acl-entry'][0]['l2'] = {
                'config': {
                    'vlanid': rule['vlan_id']
                }
            }

        if rule.get('dscp'):
            if rule['dscp'].get('value') is not None:
                rule_l3_config['dscp'] = rule['dscp']['value']
            else:
                dscp_opt = next(iter(rule['dscp']))
                if rule['dscp'][dscp_opt]:
                    rule_l3_config['dscp'] = dscp_name_to_value_map[dscp_opt]

        if rule.get('remark'):
            payload['openconfig-acl:acl-entry'][0]['config']['description'] = rule['remark']

        return {'path': url, 'method': POST, 'data': payload}

    def get_delete_l3_acl_request(self, acl_type, acl_name):
        """Get request to delete L3 ACL with specified type and name"""
        url = self.l3_acl_path.format(acl_name=acl_name, acl_type=acl_type_to_payload_map[acl_type])
        return {'path': url, 'method': DELETE}

    def get_delete_l3_acl_remark_request(self, acl_type, acl_name):
        """Get request to delete remark of the specified L3 ACL"""
        url = self.l3_acl_remark_path.format(acl_name=acl_name, acl_type=acl_type_to_payload_map[acl_type])
        return {'path': url, 'method': DELETE}

    def get_delete_l3_acl_rule_request(self, acl_type, acl_name, seq_num):
        """Get request to delete the rule with given sequence number
        in the specified L3 ACL
        """
        url = self.l3_acl_rule_path.format(acl_name=acl_name, acl_type=acl_type_to_payload_map[acl_type])
        url += '/acl-entry={0}'.format(seq_num)
        return {'path': url, 'method': DELETE}

    def validate_and_normalize_config(self, config_list):
        """Validate and normalize the given config"""
        # Remove empties and validate the config with argument spec
        updated_config_list = [remove_empties(config) for config in config_list]
        validate_config(self._module.argument_spec, {'config': updated_config_list})

        state = self._module.params['state']
        # When state is deleted, options other than sequence_num are not considered
        if state == 'deleted':
            return updated_config_list

        for config in updated_config_list:
            if not config.get('acls'):
                continue

            acl_type = config['address_family']
            for acl in config['acls']:
                if not acl.get('rules'):
                    continue

                acl_name = acl['name']
                for rule in acl['rules']:
                    seq_num = rule['sequence_num']

                    self._check_required(['action', 'source', 'destination', 'protocol'], rule, ['config', 'acls', 'rules'])
                    self._validate_and_normalize_protocol(acl_type, acl_name, rule)
                    protocol = rule['protocol']['name'] if rule['protocol'].get('name') else str(rule['protocol']['number'])

                    for endpoint in ('source', 'destination'):
                        if rule[endpoint].get('any') is False:
                            self._invalid_rule('True is the only valid value for {0} -> any'.format(endpoint), acl_type, acl_name, seq_num)
                        elif rule[endpoint].get('host'):
                            rule[endpoint]['host'] = rule[endpoint]['host'].lower()
                        elif rule[endpoint].get('prefix'):
                            rule[endpoint]['prefix'] = rule[endpoint]['prefix'].lower()

                        if rule[endpoint].get('port_number'):
                            if protocol not in ('tcp', 'udp'):
                                self._invalid_rule('{0} -> port_number is valid only for TCP or UDP protocol'.format(endpoint), acl_type, acl_name, seq_num)

                            self._validate_and_normalize_port_number(acl_type, acl_name, rule, endpoint)

                    if rule.get('protocol_options'):
                        protocol_options = next(iter(rule['protocol_options']))
                        if protocol != protocol_options:
                            self._invalid_rule('protocol_options -> {0} is not valid for protocol {1}'.format(protocol_options, protocol),
                                               acl_type, acl_name, seq_num)

                        self._normalize_protocol_options(rule)

                    self._normalize_dscp(rule)

        return updated_config_list

    def _validate_and_normalize_protocol(self, acl_type, acl_name, rule):
        protocol = rule.get('protocol')
        if protocol:
            if protocol.get('number') is not None:
                if protocol['number'] in protocol_number_to_name_map:
                    protocol['name'] = protocol_number_to_name_map[protocol.pop('number')]

            protocol_name = protocol.get('name')
            if (acl_type == 'ipv4' and protocol_name in ('ipv6', 'icmpv6')) or (acl_type == 'ipv6' and protocol_name in ('ip', 'icmp')):
                self._invalid_rule('invalid protocol {0} for {1} ACL'.format(protocol_name, acl_type), acl_type, acl_name, rule['sequence_num'])

    def _validate_and_normalize_port_number(self, acl_type, acl_name, rule, endpoint):
        port_number = rule.get(endpoint, {}).get('port_number')
        if port_number:
            # Greater than 0 is the same as less than 65535
            if port_number.get('gt') == L4_PORT_START:
                port_number['lt'] = L4_PORT_END
                del port_number['gt']
            elif rule[endpoint]['port_number'].get('range'):
                port_range = rule[endpoint]['port_number']['range']
                if port_range['begin'] >= port_range['end']:
                    self._invalid_rule('begin must be less than end in {0} -> port_number -> range'.format(endpoint), acl_type, acl_name, rule['sequence_num'])

                # Range of 0 to x is the same as less than x and
                # range of x to 65535 is the same as greater than x
                if port_range['begin'] == L4_PORT_START:
                    port_number['lt'] = port_range['end']
                    del port_number['range']
                elif port_range['end'] == L4_PORT_END:
                    port_number['gt'] = port_range['begin']
                    del port_number['range']

    def _invalid_rule(self, err_msg, acl_type, acl_name, seq_num):
        self._module.fail_json(msg='{0} ACL {1}, sequence number {2}: {3}'.format(acl_type, acl_name, seq_num, err_msg))

    def _check_required(self, required_parameters, parameters, options_context=None):
        if required_parameters:
            spec = {}
            for parameter in required_parameters:
                spec[parameter] = {'required': True}

            try:
                check_required_arguments(spec, parameters, options_context)
            except TypeError as exc:
                self._module.fail_json(msg=str(exc))

    @staticmethod
    def _normalize_protocol_options(rule):
        tcp = rule.get('protocol_options', {}).get('tcp')
        if tcp:
            # Remove protocol_options option if all tcp options are False
            if not any(list(tcp.values())):
                del rule['protocol_options']
            else:
                tcp_flag_list = list(tcp.keys())
                for tcp_flag in tcp_flag_list:
                    # Remove tcp option if its value is False
                    if not tcp[tcp_flag]:
                        del tcp[tcp_flag]

    @staticmethod
    def _normalize_dscp(rule):
        dscp = rule.get('dscp')
        if dscp:
            if dscp.get('value') is not None:
                if dscp['value'] in dscp_value_to_name_map:
                    dscp[dscp_value_to_name_map[dscp.pop('value')]] = True
            else:
                # Remove dscp option if its value is False
                if not next(iter(dscp.values())):
                    del rule['dscp']

    @staticmethod
    def _convert_config_list_to_dict(config_list):
        config_dict = {}
        for config in config_list:
            acl_type = config['address_family']
            config_dict[acl_type] = {}
            if config.get('acls'):
                for acl in config['acls']:
                    acl_name = acl['name']
                    config_dict[acl_type][acl_name] = {}
                    config_dict[acl_type][acl_name]['remark'] = acl.get('remark')
                    config_dict[acl_type][acl_name]['rules'] = {}
                    if acl.get('rules'):
                        for rule in acl['rules']:
                            config_dict[acl_type][acl_name]['rules'][rule['sequence_num']] = rule

        return config_dict

    @staticmethod
    def _convert_port_dict_to_payload_format(port_dict):
        payload = None
        if port_dict:
            if port_dict.get('eq') is not None:
                payload = port_dict['eq']
            elif port_dict.get('lt') is not None:
                payload = '{0}..{1}'.format(L4_PORT_START, port_dict['lt'])
            elif port_dict.get('gt') is not None:
                payload = '{0}..{1}'.format(port_dict['gt'], L4_PORT_END)
            elif port_dict.get('range'):
                payload = '{0}..{1}'.format(port_dict['range']['begin'], port_dict['range']['end'])

        return payload

    def sort_config(self, configs):
        # natsort provides better result.
        # The use of natsort causes sanity error due to it is not available in
        # python version currently used.
        # new_config = natsorted(new_config, key=lambda x: x['name'])
        # For time-being, use simple "sort"
        configs.sort(key=lambda x: x['address_family'])

        for conf in configs:
            acls = conf.get('acls', [])
            if acls:
                acls.sort(key=lambda x: x['name'])
                for acl in acls:
                    if acl.get('rules', []):
                        acl['rules'].sort(key=lambda x: x['sequence_num'])

    def post_process_generated_config(self, configs):
        for conf in configs[:]:
            if not conf.get('acls', []):
                configs.remove(conf)
