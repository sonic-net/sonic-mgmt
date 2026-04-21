#
# -*- coding: utf-8 -*-
# Copyright 2022 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_l2_acls class
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
    {'config': {'name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'rules': {'sequence_num': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
]

L2_ACL_TYPE = 'ACL_L2'
ETHERTYPE_FORMAT = '0x{:04x}'

ethertype_value_to_protocol_map = {
    '0x0800': 'ipv4',
    '0x0806': 'arp',
    '0x86dd': 'ipv6'
}
pcp_value_to_traffic_map = {
    0: 'be',
    1: 'bk',
    2: 'ee',
    3: 'ca',
    4: 'vi',
    5: 'vo',
    6: 'ic',
    7: 'nc'
}

# Spec value to payload value mappings
action_value_to_payload_map = {
    'permit': 'ACCEPT',
    'discard': 'DISCARD',
    'do-not-nat': 'DO_NOT_NAT',
    'deny': 'DROP',
    'transit': 'TRANSIT'
}
ethertype_protocol_to_payload_map = {
    'arp': 'ETHERTYPE_ARP',
    'ipv4': 'ETHERTYPE_IPV4',
    'ipv6': 'ETHERTYPE_IPV6'
}
ethertype_value_to_payload_map = {
    '0x8847': 'ETHERTYPE_MPLS',
    '0x88cc': 'ETHERTYPE_LLDP',
    '0x8915': 'ETHERTYPE_ROCE'
}
pcp_traffic_to_value_map = {v: k for k, v in pcp_value_to_traffic_map.items()}


class L2_acls(ConfigBase):
    """
    The sonic_l2_acls class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'l2_acls',
    ]

    acl_path = 'data/openconfig-acl:acl/acl-sets/acl-set'
    l2_acl_path = 'data/openconfig-acl:acl/acl-sets/acl-set={acl_name},ACL_L2'
    l2_acl_rule_path = 'data/openconfig-acl:acl/acl-sets/acl-set={acl_name},ACL_L2/acl-entries'
    l2_acl_remark_path = 'data/openconfig-acl:acl/acl-sets/acl-set={acl_name},ACL_L2/config/description'

    def __init__(self, module):
        super(L2_acls, self).__init__(module)

    def get_l2_acls_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        l2_acls_facts = facts['ansible_network_resources'].get('l2_acls')
        if not l2_acls_facts:
            return []
        return l2_acls_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = []

        existing_l2_acls_facts = self.get_l2_acls_facts()
        commands, requests = self.set_config(existing_l2_acls_facts)
        if commands:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._handle_failure_response(exc)

            result['changed'] = True

        changed_l2_acls_facts = self.get_l2_acls_facts()

        result['before'] = existing_l2_acls_facts
        if result['changed']:
            result['after'] = changed_l2_acls_facts

        result['commands'] = commands

        new_config = changed_l2_acls_facts
        old_config = existing_l2_acls_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_l2_acls_facts,
                                        TEST_KEYS_formatted_diff)
            result['after(generated)'] = new_config
        if self._module._diff:
            self.sort_config(new_config)
            self.sort_config(old_config)
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)
        result['warnings'] = warnings
        return result

    def set_config(self, existing_l2_acls_facts):
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

        have = existing_l2_acls_facts
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
        have_acl_names = set(have_dict.keys())
        want_acl_names = set(want_dict.keys())

        if state == 'overridden':
            # Delete non-modified ACLs
            for acl_name in have_acl_names.difference(want_acl_names):
                del_commands.append({'name': acl_name})
                del_requests.append(self.get_delete_l2_acl_request(acl_name))

        # Modify existing ACLs
        for acl_name in want_acl_names.intersection(have_acl_names):
            acl_add_command = {'name': acl_name}
            acl_del_command = {'name': acl_name}
            rule_add_commands = []
            rule_del_commands = []

            have_acl = have_dict[acl_name]
            want_acl = want_dict[acl_name]
            if not want_acl['remark']:
                if have_acl['remark'] and state in ('replaced', 'overridden'):
                    acl_del_command['remark'] = have_acl['remark']
                    del_requests.append(self.get_delete_l2_acl_remark_request(acl_name))
            else:
                if want_acl['remark'] != have_acl['remark']:
                    acl_add_command['remark'] = want_acl['remark']
                    add_requests.append(self.get_create_l2_acl_remark_request(acl_name, want_acl['remark']))

            have_seq_nums = set(have_acl['rules'].keys())
            want_seq_nums = set(want_acl['rules'].keys())

            if state in ('replaced', 'overridden'):
                # Delete non-modified rules
                for seq_num in have_seq_nums.difference(want_seq_nums):
                    rule_del_commands.append({'sequence_num': seq_num})
                    del_requests.append(self.get_delete_l2_acl_rule_request(acl_name, seq_num))

            for seq_num in want_seq_nums.intersection(have_seq_nums):
                # Replace existing rules
                if have_acl['rules'][seq_num] != want_acl['rules'][seq_num]:
                    if state == 'merged':
                        self._module.fail_json(
                            msg="Cannot update existing sequence {0} of L2 ACL {1} with state merged."
                                " Please use state replaced or overridden.".format(seq_num, acl_name)
                        )

                    rule_del_commands.append({'sequence_num': seq_num})
                    del_requests.append(self.get_delete_l2_acl_rule_request(acl_name, seq_num))

                    rule_add_commands.append(want_acl['rules'][seq_num])
                    add_requests.append(self.get_create_l2_acl_rule_request(acl_name, seq_num, want_acl['rules'][seq_num]))

            # Add new rules
            for seq_num in want_seq_nums.difference(have_seq_nums):
                rule_add_commands.append(want_acl['rules'][seq_num])
                add_requests.append(self.get_create_l2_acl_rule_request(acl_name, seq_num, want_acl['rules'][seq_num]))

            if rule_del_commands:
                acl_del_command['rules'] = rule_del_commands
            if rule_add_commands:
                acl_add_command['rules'] = rule_add_commands

            if acl_del_command.get('rules') or acl_del_command.get('remark'):
                del_commands.append(acl_del_command)
            if acl_add_command.get('rules') or acl_add_command.get('remark'):
                add_commands.append(acl_add_command)

        # Add new ACLs
        for acl_name in want_acl_names.difference(have_acl_names):
            acl_add_command = {'name': acl_name}
            add_requests.append(self.get_create_l2_acl_request(acl_name))

            want_acl = want_dict[acl_name]
            if want_acl['remark']:
                acl_add_command['remark'] = want_acl['remark']
                add_requests.append(self.get_create_l2_acl_remark_request(acl_name, want_acl['remark']))

            # Add new rules
            want_seq_nums = set(want_acl['rules'].keys())
            if want_seq_nums:
                acl_add_command['rules'] = []
                for seq_num in want_seq_nums:
                    acl_add_command['rules'].append(want_acl['rules'][seq_num])
                    add_requests.append(self.get_create_l2_acl_rule_request(acl_name, seq_num, want_acl['rules'][seq_num]))

            add_commands.append(acl_add_command)

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
            for acl in have:
                commands.append({'name': acl['name']})
                requests.append(self.get_delete_l2_acl_request(acl['name']))
        else:
            have_dict = self._convert_config_list_to_dict(have)
            want_dict = self._convert_config_list_to_dict(want)
            have_acl_names = set(have_dict.keys())
            want_acl_names = set(want_dict.keys())

            # Delete existing ACLs
            for acl_name in want_acl_names.intersection(have_acl_names):
                have_acl = have_dict[acl_name]
                want_acl = want_dict[acl_name]

                # Delete entire ACL if only the name is specified
                if not want_acl['remark'] and not want_acl['rules']:
                    commands.append({'name': acl_name})
                    requests.append(self.get_delete_l2_acl_request(acl_name))
                    continue

                acl_del_command = {'name': acl_name}
                rule_del_commands = []
                have_seq_nums = set(have_acl['rules'].keys())
                want_seq_nums = set(want_acl['rules'].keys())

                if want_acl['remark'] and want_acl['remark'] == have_acl['remark']:
                    acl_del_command['remark'] = want_acl['remark']
                    requests.append(self.get_delete_l2_acl_remark_request(acl_name))

                # Delete existing rules
                # When state is deleted, options other than sequence_num are not considered
                for seq_num in want_seq_nums.intersection(have_seq_nums):
                    rule_del_commands.append({'sequence_num': seq_num})
                    requests.append(self.get_delete_l2_acl_rule_request(acl_name, seq_num))

                if rule_del_commands:
                    acl_del_command['rules'] = rule_del_commands

                if acl_del_command.get('rules') or acl_del_command.get('remark'):
                    commands.append(acl_del_command)

        commands = update_states(commands, "deleted")
        return commands, requests

    def get_create_l2_acl_request(self, acl_name):
        """Get request to create L2 ACL with specified name"""
        url = self.acl_path
        payload = {
            'acl-set': [{
                'name': acl_name,
                'type': L2_ACL_TYPE,
                'config': {
                    'name': acl_name,
                    'type': L2_ACL_TYPE
                }
            }]
        }

        return {'path': url, 'method': PATCH, 'data': payload}

    def get_create_l2_acl_remark_request(self, acl_name, remark):
        """Get request to add given remark to the specified L2 ACL"""
        url = self.l2_acl_remark_path.format(acl_name=acl_name)
        payload = {'description': remark}
        return {'path': url, 'method': PATCH, 'data': payload}

    def get_create_l2_acl_rule_request(self, acl_name, seq_num, rule):
        """Get request to create a rule with given sequence number
        and configuration in the specified L2 ACL
        """
        url = self.l2_acl_rule_path.format(acl_name=acl_name)
        payload = {
            'openconfig-acl:acl-entry': [{
                'sequence-id': seq_num,
                'config': {
                    'sequence-id': seq_num
                },
                'l2': {
                    'config': {}
                },
                'actions': {
                    'config': {
                        'forwarding-action': action_value_to_payload_map[rule['action']]
                    }
                }
            }]
        }
        rule_l2_config = payload['openconfig-acl:acl-entry'][0]['l2']['config']

        if rule['source'].get('host'):
            rule_l2_config['source-mac'] = rule['source']['host']
        elif rule['source'].get('address'):
            rule_l2_config['source-mac'] = rule['source']['address']
            rule_l2_config['source-mac-mask'] = rule['source']['address_mask']

        if rule['destination'].get('host'):
            rule_l2_config['destination-mac'] = rule['destination']['host']
        elif rule['destination'].get('address'):
            rule_l2_config['destination-mac'] = rule['destination']['address']
            rule_l2_config['destination-mac-mask'] = rule['destination']['address_mask']

        if rule.get('ethertype'):
            if rule['ethertype'].get('value'):
                rule_l2_config['ethertype'] = ethertype_value_to_payload_map.get(rule['ethertype']['value'], int(rule['ethertype']['value'], 16))
            else:
                rule_l2_config['ethertype'] = ethertype_protocol_to_payload_map[next(iter(rule['ethertype']))]

        if rule.get('vlan_id') is not None:
            rule_l2_config['vlanid'] = rule['vlan_id']

        if rule.get('vlan_tag_format') and rule['vlan_tag_format'].get('multi_tagged'):
            rule_l2_config['vlan-tag-format'] = 'openconfig-acl-ext:MULTI_TAGGED'

        if rule.get('dei') is not None:
            rule_l2_config['dei'] = rule['dei']

        if rule.get('pcp'):
            if rule['pcp'].get('traffic_type'):
                rule_l2_config['pcp'] = pcp_traffic_to_value_map[rule['pcp']['traffic_type']]
            else:
                rule_l2_config['pcp'] = rule['pcp']['value']
                rule_l2_config['pcp-mask'] = rule['pcp']['mask']

        if rule.get('remark'):
            payload['openconfig-acl:acl-entry'][0]['config']['description'] = rule['remark']

        return {'path': url, 'method': POST, 'data': payload}

    def get_delete_l2_acl_request(self, acl_name):
        """Get request to delete L2 ACL with specified name"""
        url = self.l2_acl_path.format(acl_name=acl_name)
        return {'path': url, 'method': DELETE}

    def get_delete_l2_acl_remark_request(self, acl_name):
        """Get request to delete remark of the specified L2 ACL"""
        url = self.l2_acl_remark_path.format(acl_name=acl_name)
        return {'path': url, 'method': DELETE}

    def get_delete_l2_acl_rule_request(self, acl_name, seq_num):
        """Get request to delete the rule with given sequence number
        in the specified L2 ACL
        """
        url = self.l2_acl_rule_path.format(acl_name=acl_name)
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

        for acl in updated_config_list:
            if not acl.get('rules'):
                continue

            for rule in acl['rules']:
                self._check_required(['action', 'source', 'destination'], rule, ['config', 'rules'])
                for endpoint in ('source', 'destination'):
                    if rule[endpoint].get('any') is False:
                        self._invalid_rule('True is the only valid value for {0} -> any'.format(endpoint), acl['name'], rule['sequence_num'])
                    elif rule[endpoint].get('host'):
                        rule[endpoint]['host'] = rule[endpoint]['host'].lower()
                    elif rule[endpoint].get('address'):
                        rule[endpoint]['address'] = rule[endpoint]['address'].lower()
                        rule[endpoint]['address_mask'] = rule[endpoint]['address_mask'].lower()

                self._normalize_ethertype(rule)
                self._normalize_pcp(rule)
                self._normalize_vlan_tag_format(rule)

        return updated_config_list

    def _invalid_rule(self, err_msg, acl_name, seq_num):
        self._module.fail_json(msg='L2 ACL {0}, sequence number {1}: {2}'.format(acl_name, seq_num, err_msg))

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
    def _normalize_ethertype(rule):
        ethertype = rule.get('ethertype')
        if ethertype:
            if ethertype.get('value'):
                value = ethertype.pop('value')
                if value.startswith('0x'):
                    value = ETHERTYPE_FORMAT.format(int(value, 16))
                else:
                    # If the hexadecimal number is not enclosed within
                    # quotes, it will be passed as a string after being
                    # converted to decimal.
                    value = ETHERTYPE_FORMAT.format(int(value, 10))

                if value in ethertype_value_to_protocol_map:
                    ethertype[ethertype_value_to_protocol_map[value]] = True
                else:
                    ethertype['value'] = value
            else:
                # Remove ethertype option if its value is False
                if not next(iter(ethertype.values())):
                    del rule['ethertype']

    @staticmethod
    def _normalize_pcp(rule):
        pcp = rule.get('pcp')
        if pcp and pcp.get('value') is not None and pcp.get('mask') is None:
            pcp['traffic_type'] = pcp_value_to_traffic_map[pcp['value']]
            del pcp['value']

    @staticmethod
    def _normalize_vlan_tag_format(rule):
        vlan_tag_format = rule.get('vlan_tag_format')
        # Remove vlan_tag_format option if the value is False
        if vlan_tag_format and not vlan_tag_format.get('multi_tagged'):
            del rule['vlan_tag_format']

    @staticmethod
    def _convert_config_list_to_dict(config_list):
        config_dict = {}
        for config in config_list:
            acl_name = config['name']
            config_dict[acl_name] = {}
            config_dict[acl_name]['remark'] = config.get('remark')
            config_dict[acl_name]['rules'] = {}
            if config.get('rules'):
                for rule in config['rules']:
                    config_dict[acl_name]['rules'][rule['sequence_num']] = rule

        return config_dict

    def sort_config(self, configs):
        # natsort provides better result.
        # The use of natsort causes sanity error due to it is not available in
        # python version currently used.
        # new_config = natsorted(new_config, key=lambda x: x['name'])
        # For time-being, use simple "sort"
        configs.sort(key=lambda x: x['name'])

        for conf in configs:
            if conf.get('rules', []):
                conf['rules'].sort(key=lambda x: x['sequence_num'])
