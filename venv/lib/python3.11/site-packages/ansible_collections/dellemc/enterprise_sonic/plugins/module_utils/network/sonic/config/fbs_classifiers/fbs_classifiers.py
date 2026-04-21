#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_fbs_classifiers class
It is in this file where the current configuration (as list)
is compared to the provided configuration (as list) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy
from ansible.module_utils.connection import ConnectionError
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    remove_empties_from_list,
    update_states
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    edit_config,
    to_request
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF,
    get_new_config,
    get_formatted_config_diff
)

FBS_CLASSIFIERS_PATH = 'data/openconfig-fbs-ext:fbs/classifiers'
PATCH = 'patch'
DELETE = 'delete'
TEST_KEYS = [
    {'config': {'class_name': ''}}
]
TEST_KEYS_generate_config = [
    {'config': {'class_name': '', '__delete_op': __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF}}
]
enum_dict = {
    'ack': 'TCP_ACK',
    'acl': 'MATCH_ACL',
    'acl_ipv6': 'ACL_IPV6',
    'arp': 'ETHERTYPE_ARP',
    'auth': 'IP_AUTH',
    'fields': 'MATCH_FIELDS',
    'fin': 'TCP_FIN',
    'gre': 'IP_GRE',
    'icmp': 'IP_ICMP',
    'icmpv6': 58,
    'igmp': 'IP_IGMP',
    'ip': 'ACL_IPV4',
    'ipv4': 'ETHERTYPE_IPV4',
    'ipv6': 'ETHERTYPE_IPV6',
    'l2tp': 'IP_L2TP',
    'lldp': 'ETHERTYPE_LLDP',
    'mac': 'ACL_L2',
    'mpls': 'ETHERTYPE_MPLS',
    'pim': 'IP_PIM',
    'psh': 'TCP_PSH',
    'roce': 'ETHERTYPE_ROCE',
    'rst': 'TCP_RST',
    'rsvp': 'IP_RSVP',
    'syn': 'TCP_SYN',
    'tcp': 'IP_TCP',
    'udp': 'IP_UDP',
    'urg': 'TCP_URG',
    'vlan': 'ETHERTYPE_VLAN'
}


class Fbs_classifiers(ConfigBase):
    """
    The sonic_fbs_classifiers class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'fbs_classifiers',
    ]

    def __init__(self, module):
        super(Fbs_classifiers, self).__init__(module)

    def get_fbs_classifiers_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A list
        :returns: The current configuration as a list
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        fbs_classifiers_facts = facts['ansible_network_resources'].get('fbs_classifiers')
        if not fbs_classifiers_facts:
            return []
        return fbs_classifiers_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = []
        commands = []

        existing_fbs_classifiers_facts = self.get_fbs_classifiers_facts()
        commands, requests = self.set_config(existing_fbs_classifiers_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_fbs_classifiers_facts = self.get_fbs_classifiers_facts()

        result['before'] = existing_fbs_classifiers_facts
        if result['changed']:
            result['after'] = changed_fbs_classifiers_facts

        new_config = changed_fbs_classifiers_facts
        old_config = existing_fbs_classifiers_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_fbs_classifiers_facts, TEST_KEYS_generate_config)
            self.post_process_generated_config(new_config)
            result['after(generated)'] = new_config
        if self._module._diff:
            self.sort_lists_in_config(new_config)
            self.sort_lists_in_config(old_config)
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)

        result['warnings'] = warnings
        return result

    def set_config(self, existing_fbs_classifiers_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = remove_empties_from_list(self._module.params['config'])
        have = existing_fbs_classifiers_facts
        self.sort_lists_in_config(want)
        self.sort_lists_in_config(have)
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
        commands = []
        requests = []
        state = self._module.params['state']
        diff = get_diff(want, have, TEST_KEYS)

        if state == 'merged':
            commands, requests = self._state_merged(diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have, diff)
        elif state == 'overridden':
            commands, requests = self._state_overridden(want, have, diff)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have, diff)
        return commands, requests

    def _state_merged(self, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        requests = self.get_modify_classifiers_request(commands)

        if commands and len(requests) > 0:
            commands = update_states(commands, 'merged')
        else:
            commands = []

        return commands, requests

    def _state_replaced(self, want, have, diff):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        mod_commands = []
        replaced_config, requests = self.get_replaced_config(want, have)

        if replaced_config:
            commands.extend(update_states(replaced_config, 'deleted'))
            mod_commands = want
        else:
            mod_commands = diff

        if mod_commands:
            mod_request = self.get_modify_classifiers_request(mod_commands)

            if mod_request:
                requests.append(mod_request)
                commands.extend(update_states(mod_commands, 'replaced'))

        return commands, requests

    def _state_overridden(self, want, have, diff):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []
        mod_commands = None
        mod_request = None
        del_commands = get_diff(have, want, TEST_KEYS)

        if not del_commands and diff:
            mod_commands = diff
            mod_request = self.get_modify_classifiers_request(mod_commands)

        if del_commands:
            is_delete_all = True
            del_requests = self.get_delete_classifiers_requests(del_commands, is_delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(have, 'deleted'))
            mod_commands = want
            mod_request = self.get_modify_classifiers_request(mod_commands)

        if mod_request:
            requests.append(mod_request)
            commands.extend(update_states(mod_commands, 'overridden'))

        return commands, requests

    def _state_deleted(self, want, have, diff):
        """ The command generator when state is deleted
        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        is_delete_all = False
        requests = []

        if not want:
            commands = deepcopy(have)
            is_delete_all = True
        else:
            commands = get_diff(want, diff, TEST_KEYS)

        if commands:
            requests = self.get_delete_classifiers_requests(commands, is_delete_all)
            if len(requests) > 0:
                commands = update_states(commands, 'deleted')
        else:
            commands = []

        return commands, requests

    def get_modify_classifiers_request(self, commands):
        """Returns a patch request to modify the FBS classifiers configuration"""
        request = None
        classifier_list = []

        for classifier in commands:
            classifier_dict = {}
            class_name = classifier.get('class_name')
            class_description = classifier.get('class_description')
            match_acl = classifier.get('match_acl')
            match_hdr_fields = classifier.get('match_hdr_fields')
            match_type = classifier.get('match_type')

            if class_name:
                classifier_dict.update({'class-name': class_name, 'config': {'name': class_name}})
            if class_description:
                classifier_dict['config']['description'] = class_description
            if match_type:
                classifier_dict['config']['match-type'] = enum_dict[match_type]
            if match_acl:
                config_dict = {}
                acl_name = match_acl.get('acl_name')
                acl_type = match_acl.get('acl_type')

                if acl_name:
                    config_dict['acl-name'] = acl_name
                if acl_type:
                    if acl_type == 'ipv6':
                        acl_type = 'acl_' + acl_type
                    config_dict['acl-type'] = enum_dict[acl_type]
                classifier_dict['match-acl'] = {'config': config_dict}
            if match_hdr_fields:
                match_hdr_fields_dict = {}
                ip = match_hdr_fields.get('ip')
                l2 = match_hdr_fields.get('l2')
                transport = match_hdr_fields.get('transport')

                if ip:
                    config_dict = {}
                    dscp = ip.get('dscp')
                    protocol = ip.get('protocol')

                    if dscp is not None:
                        config_dict['dscp'] = dscp
                    if protocol:
                        config_dict['protocol'] = enum_dict[protocol]
                    match_hdr_fields_dict['ip'] = {'config': config_dict}
                if l2:
                    config_dict = {}
                    dei = l2.get('dei')
                    destination_mac = l2.get('destination_mac')
                    destination_mac_mask = l2.get('destination_mac_mask')
                    ethertype = l2.get('ethertype')
                    pcp = l2.get('pcp')
                    source_mac = l2.get('source_mac')
                    source_mac_mask = l2.get('source_mac_mask')
                    vlanid = l2.get('vlanid')

                    if dei is not None:
                        config_dict['dei'] = dei
                    if destination_mac:
                        config_dict['destination-mac'] = destination_mac
                    if destination_mac_mask:
                        config_dict['destination-mac-mask'] = destination_mac_mask
                    if ethertype:
                        config_dict['ethertype'] = enum_dict[ethertype]
                    if pcp is not None:
                        config_dict['pcp'] = pcp
                    if source_mac:
                        config_dict['source-mac'] = source_mac
                    if source_mac_mask:
                        config_dict['source-mac-mask'] = source_mac_mask
                    if vlanid:
                        config_dict['vlanid'] = vlanid
                    match_hdr_fields_dict['l2'] = {'config': config_dict}
                if transport:
                    config_dict = {}
                    destination_port = transport.get('destination_port')
                    icmp_code = transport.get('icmp_code')
                    icmp_type = transport.get('icmp_type')
                    source_port = transport.get('source_port')
                    tcp_flags = transport.get('tcp_flags')

                    if destination_port:
                        if destination_port.isnumeric():
                            destination_port = int(destination_port)
                        config_dict['destination-port'] = destination_port
                    if icmp_code:
                        config_dict['icmp-code'] = icmp_code
                    if icmp_type:
                        config_dict['icmp-type'] = icmp_type
                    if source_port:
                        if source_port.isnumeric():
                            source_port = int(source_port)
                        config_dict['source-port'] = source_port
                    if tcp_flags:
                        converted_flags = []
                        for flag in tcp_flags:
                            converted_flags.append(enum_dict[flag])
                        config_dict['tcp-flags'] = converted_flags
                    match_hdr_fields_dict['transport'] = {'config': config_dict}
                for ip_type in ('ipv4', 'ipv6'):
                    ip_cfg = match_hdr_fields.get(ip_type)
                    if ip_cfg:
                        config_dict = {}
                        destination_address = ip_cfg.get('destination_address')
                        source_address = ip_cfg.get('source_address')

                        if destination_address:
                            config_dict['destination-address'] = destination_address
                        if source_address:
                            config_dict['source-address'] = source_address
                        match_hdr_fields_dict[ip_type] = {'config': config_dict}
                classifier_dict['match-hdr-fields'] = match_hdr_fields_dict

            if classifier_dict:
                classifier_list.append(classifier_dict)
        if classifier_list:
            payload = {'openconfig-fbs-ext:classifiers': {'classifier': classifier_list}}
            request = {'path': FBS_CLASSIFIERS_PATH, 'method': PATCH, 'data': payload}

        return request

    def get_delete_classifiers_requests(self, commands, is_delete_all):
        """Returns a list of delete requests to delete the specified FBS classifiers configuration"""
        requests = []

        if is_delete_all:
            requests.append(self.get_delete_classifiers_request())
            return requests

        for classifier in commands:
            class_name = classifier.get('class_name')
            class_description = classifier.get('class_description')
            match_acl = classifier.get('match_acl')
            match_hdr_fields = classifier.get('match_hdr_fields')
            match_type = classifier.get('match_type')

            if class_name and not class_description and not match_acl and not match_hdr_fields and not match_type:
                requests.append(self.get_delete_classifiers_request(class_name))
            if class_description:
                attr_path = '/config/description'
                requests.append(self.get_delete_classifiers_request(class_name, attr_path))
            if match_type:
                self._module.fail_json(msg='Deletion of match_type not supported')
            if match_acl:
                attr_path = '/match-acl'
                requests.append(self.get_delete_classifiers_request(class_name, attr_path))
            if match_hdr_fields:
                ip = match_hdr_fields.get('ip')
                l2 = match_hdr_fields.get('l2')
                transport = match_hdr_fields.get('transport')

                if l2:
                    dei = l2.get('dei')
                    destination_mac = l2.get('destination_mac')
                    destination_mac_mask = l2.get('destination_mac_mask')
                    ethertype = l2.get('ethertype')
                    pcp = l2.get('pcp')
                    source_mac = l2.get('source_mac')
                    source_mac_mask = l2.get('source_mac_mask')
                    vlanid = l2.get('vlanid')

                    if dei is not None:
                        attr_path = '/match-hdr-fields/l2/config/dei'
                        requests.append(self.get_delete_classifiers_request(class_name, attr_path))
                    if destination_mac:
                        attr_path = '/match-hdr-fields/l2/config/destination-mac'
                        requests.append(self.get_delete_classifiers_request(class_name, attr_path))
                    if destination_mac_mask:
                        attr_path = '/match-hdr-fields/l2/config/destination-mac-mask'
                        requests.append(self.get_delete_classifiers_request(class_name, attr_path))
                    if ethertype:
                        attr_path = '/match-hdr-fields/l2/config/ethertype'
                        requests.append(self.get_delete_classifiers_request(class_name, attr_path))
                    if pcp is not None:
                        attr_path = '/match-hdr-fields/l2/config/pcp'
                        requests.append(self.get_delete_classifiers_request(class_name, attr_path))
                    if source_mac:
                        attr_path = '/match-hdr-fields/l2/config/source-mac'
                        requests.append(self.get_delete_classifiers_request(class_name, attr_path))
                    if source_mac_mask:
                        attr_path = '/match-hdr-fields/l2/config/source-mac-mask'
                        requests.append(self.get_delete_classifiers_request(class_name, attr_path))
                    if vlanid:
                        attr_path = '/match-hdr-fields/l2/config/vlanid'
                        requests.append(self.get_delete_classifiers_request(class_name, attr_path))
                if transport:
                    destination_port = transport.get('destination_port')
                    icmp_code = transport.get('icmp_code')
                    icmp_type = transport.get('icmp_type')
                    source_port = transport.get('source_port')
                    tcp_flags = transport.get('tcp_flags')

                    if destination_port:
                        attr_path = '/match-hdr-fields/transport/config/destination-port'
                        requests.append(self.get_delete_classifiers_request(class_name, attr_path))
                    if icmp_code:
                        attr_path = '/match-hdr-fields/transport/config/icmp-code'
                        requests.append(self.get_delete_classifiers_request(class_name, attr_path))
                    if icmp_type:
                        attr_path = '/match-hdr-fields/transport/config/icmp-type'
                        requests.append(self.get_delete_classifiers_request(class_name, attr_path))
                    if source_port:
                        attr_path = '/match-hdr-fields/transport/config/source-port'
                        requests.append(self.get_delete_classifiers_request(class_name, attr_path))
                    if tcp_flags:
                        for flag in tcp_flags:
                            attr_path = '/match-hdr-fields/transport/config/tcp-flags=%s' % (enum_dict[flag])
                            requests.append(self.get_delete_classifiers_request(class_name, attr_path))
                for ip_type in ('ipv4', 'ipv6'):
                    ip_cfg = match_hdr_fields.get(ip_type)
                    if ip_cfg:
                        destination_address = ip_cfg.get('destination_address')
                        source_address = ip_cfg.get('source_address')

                        if destination_address:
                            attr_path = '/match-hdr-fields/%s/config/destination-address' % (ip_type)
                            requests.append(self.get_delete_classifiers_request(class_name, attr_path))
                        if source_address:
                            attr_path = '/match-hdr-fields/%s/config/source-address' % (ip_type)
                            requests.append(self.get_delete_classifiers_request(class_name, attr_path))
                # IP must be deleted last due to dependecies
                if ip:
                    dscp = ip.get('dscp')
                    protocol = ip.get('protocol')

                    if dscp is not None:
                        attr_path = '/match-hdr-fields/ip/config/dscp'
                        requests.append(self.get_delete_classifiers_request(class_name, attr_path))
                    if protocol:
                        attr_path = '/match-hdr-fields/ip/config/protocol'
                        requests.append(self.get_delete_classifiers_request(class_name, attr_path))

        return requests

    def get_delete_classifiers_request(self, class_name=None, attr_path=None):
        url = FBS_CLASSIFIERS_PATH

        if class_name:
            url += '/classifier=%s' % (class_name)
        if attr_path:
            url += attr_path
        request = {'path': url, 'method': DELETE}
        return request

    def get_replaced_config(self, want, have):
        config_list = []
        requests = []
        classifier_dict = {classifier.get('class_name'): classifier for classifier in have}

        for classifier in want:
            config_dict = {}
            class_name = classifier.get('class_name')
            cfg_classifier = classifier_dict.get(class_name)

            if not cfg_classifier:
                continue
            class_description = classifier.get('class_description')
            match_type = classifier.get('match_type')
            match_acl = classifier.get('match_acl')
            match_hdr_fields = classifier.get('match_hdr_fields')
            cfg_class_description = cfg_classifier.get('class_description')
            cfg_match_type = cfg_classifier.get('match_type')
            cfg_match_acl = cfg_classifier.get('match_acl')
            cfg_match_hdr_fields = cfg_classifier.get('match_hdr_fields')

            if (class_description and cfg_class_description) or (match_type and cfg_match_type):
                # Handles 2 cases:
                # 1. class_description and/or match_type changed
                # 2. class_description or match_type is the same but one is not specified in 'want'
                if (class_description, match_type) != (cfg_class_description, cfg_match_type):
                    requests.append(self.get_delete_classifiers_request(class_name))
                    config_list.append(cfg_classifier)
                    continue
                # Handles the case of class_description and match_type being the same as 'have' configuration
                # but 'want' doesn't have any additonal configuration while 'have' has additional configuration
                if (not match_acl and not match_hdr_fields) and (cfg_match_acl or cfg_match_hdr_fields):
                    requests.append(self.get_delete_classifiers_request(class_name))
                    config_list.append(cfg_classifier)
                    continue

            if match_acl and cfg_match_acl and match_acl != cfg_match_acl:
                attr_path = '/match-acl'
                requests.append(self.get_delete_classifiers_request(class_name, attr_path))
                config_dict.update({'class_name': class_name, 'match_acl': cfg_match_acl})
            if match_hdr_fields and cfg_match_hdr_fields and match_hdr_fields != cfg_match_hdr_fields:
                attr_path = '/match-hdr-fields'
                requests.append(self.get_delete_classifiers_request(class_name, attr_path))
                config_dict.update({'class_name': class_name, 'match_hdr_fields': cfg_match_hdr_fields})
            if config_dict:
                config_list.append(config_dict)

        return config_list, requests

    def sort_lists_in_config(self, config):
        if config:
            config.sort(key=lambda x: x['class_name'])
            for classifier in config:
                if (classifier.get('match_hdr_fields') and classifier['match_hdr_fields'].get('transport') and
                        classifier['match_hdr_fields']['transport'].get('tcp_flags')):
                    classifier['match_hdr_fields']['transport']['tcp_flags'].sort()

    def post_process_generated_config(self, config):
        pop_list = []

        for classifier in config:
            match_hdr_fields = classifier.get('match_hdr_fields')
            if match_hdr_fields:
                transport = match_hdr_fields.get('transport')
                if transport:
                    if 'tcp_flags' in transport and not transport['tcp_flags']:
                        transport.pop('tcp_flags')
                        if not transport:
                            match_hdr_fields.pop('transport')
                            if not match_hdr_fields:
                                classifier.pop('match_hdr_fields')
            if 'class_name' in classifier and len(classifier) == 1:
                pop_list.insert(0, config.index(classifier))
        for idx in pop_list:
            config.pop(idx)
