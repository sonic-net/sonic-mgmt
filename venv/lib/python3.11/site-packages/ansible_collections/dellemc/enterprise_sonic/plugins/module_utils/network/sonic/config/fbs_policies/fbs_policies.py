#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_fbs_policies class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    edit_config,
    to_request
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    normalize_interface_name,
    remove_empties_from_list,
    update_states
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __MERGE_OP_DEFAULT,
    __DELETE_CONFIG_IF_NO_SUBCONFIG,
    __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF,
    get_new_config,
    get_formatted_config_diff
)

is_delete_all = False
FBS_POLICIES_PATH = 'data/openconfig-fbs-ext:fbs/policies'
PATCH = 'patch'
DELETE = 'delete'
TEST_KEYS = [
    {'config': {'policy_name': ''}},
    {'sections': {'class': ''}},
    {'mirror_sessions': {'session_name': ''}},
    {'egress_interfaces': {'intf_name': ''}},
    {'next_hops': {'address': '', 'vrf': ''}},
    {'next_hop_groups': {'group_name': ''}},
    {'replication_groups': {'group_name': ''}}
]


def __derive_fbs_policies_merge_op(key_set, command, exist_conf):
    # Current SONiC behavior overwrites mirror sessions for REST patch
    if command.get('mirror_sessions') and exist_conf.get('mirror_sessions'):
        exist_conf.pop('mirror_sessions')

    return __MERGE_OP_DEFAULT(key_set, command, exist_conf)


def __derive_fbs_policies_delete_op(key_set, command, exist_conf):
    if is_delete_all:
        return True, []
    return __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, exist_conf)


TEST_KEYS_generate_config = [
    {'config': {'policy_name': '', '__delete_op': __derive_fbs_policies_delete_op}},
    {'sections': {'class': '', '__merge_op': __derive_fbs_policies_merge_op, '__delete_op': __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'mirror_sessions': {'session_name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'egress_interfaces': {'intf_name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'next_hops': {'address': '', 'vrf': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'next_hop_groups': {'group_name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'replication_groups': {'group_name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}}
]
enum_dict = {
    'next_hop_group_ipv4': 'NEXT_HOP_GROUP_TYPE_IPV4',
    'next_hop_group_ipv6': 'NEXT_HOP_GROUP_TYPE_IPV6',
    'replication_group_ipv4': 'REPLICATION_GROUP_TYPE_IPV4',
    'replication_group_ipv6': 'REPLICATION_GROUP_TYPE_IPV6',
    'non_recursive': 'NEXT_HOP_TYPE_NON_RECURSIVE',
    'overlay': 'NEXT_HOP_TYPE_OVERLAY',
    'recursive': 'NEXT_HOP_TYPE_RECURSIVE',
    'acl-copp': 'POLICY_COPP',
    'copp': 'POLICY_COPP',
    'forwarding': 'POLICY_FORWARDING',
    'monitoring': 'POLICY_MONITORING',
    'qos': 'POLICY_QOS',
}


class Fbs_policies(ConfigBase):
    """
    The sonic_fbs_policies class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'fbs_policies',
    ]

    def __init__(self, module):
        super(Fbs_policies, self).__init__(module)

    def get_fbs_policies_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A list
        :returns: The current configuration as a list
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        fbs_policies_facts = facts['ansible_network_resources'].get('fbs_policies')
        if not fbs_policies_facts:
            return []
        return fbs_policies_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        commands = []

        existing_fbs_policies_facts = self.get_fbs_policies_facts()
        commands, requests = self.set_config(existing_fbs_policies_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        result['before'] = existing_fbs_policies_facts
        old_config = existing_fbs_policies_facts
        if self._module.check_mode:
            new_config = remove_empties_from_list(get_new_config(commands, existing_fbs_policies_facts, TEST_KEYS_generate_config))
            self.sort_lists_in_config(new_config)
            self.handle_default_entries(new_config, False)
            result['after(generated)'] = new_config
        else:
            new_config = self.get_fbs_policies_facts()
            if result['changed']:
                result['after'] = new_config
        if self._module._diff:
            self.sort_lists_in_config(new_config)
            self.sort_lists_in_config(old_config)
            result['diff'] = get_formatted_config_diff(old_config, new_config, self._module._verbosity)

        return result

    def set_config(self, existing_fbs_policies_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a list from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = remove_empties_from_list(self._module.params['config'])
        have = existing_fbs_policies_facts

        # Normalize interface names in egress_interfaces list
        if want:
            for policy in want:
                if policy.get('sections'):
                    for section in policy['sections']:
                        if section.get('forwarding') and section['forwarding'].get('egress_interfaces'):
                            normalize_interface_name(section['forwarding']['egress_interfaces'], self._module, 'intf_name')

        resp = self.set_state(want, have)
        return to_list(resp)

    def get_diff_fbs_policies(self, base_data, compare_data):
        """This method calculates the diff between base_data and compare_data
           while taking into account the special VRF value for an unspecified VRF"""
        cp_base_data = deepcopy(base_data)
        cp_compare_data = deepcopy(compare_data)

        for data in (cp_base_data, cp_compare_data):
            for policy in data:
                sections = policy.get('sections')

                if sections:
                    for section in sections:
                        forwarding = section.get('forwarding')

                        if forwarding:
                            next_hops = forwarding.get('next_hops')

                            if next_hops:
                                for hop in next_hops:
                                    address = hop.get('address')
                                    vrf = hop.get('vrf')

                                    if address and not vrf:
                                        if not self._module.check_mode:
                                            hop['vrf'] = 'openconfig-fbs-ext:INTERFACE_NETWORK_INSTANCE'
                                        else:
                                            hop['vrf'] = None
        return get_diff(cp_base_data, cp_compare_data, TEST_KEYS)

    def set_state(self, want, have):
        """ Select the appropriate function based on the state provided

        :param want: the desired configuration as a list
        :param have: the current configuration as a list
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, requests = [], []
        state = self._module.params['state']
        diff = self.get_diff_fbs_policies(want, have)

        if state == 'merged':
            commands, requests = self._state_merged(have, diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have, diff)
        elif state == 'overridden':
            commands, requests = self._state_overridden(want, have, diff)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have, diff)
        return commands, requests

    def _state_merged(self, have, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        requests = self.get_modify_policies_requests(commands, have)

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
        commands, mod_commands = [], []
        tmp_have = deepcopy(have)
        replaced_config, requests = self.get_replaced_config(want, have)

        if replaced_config:
            commands.extend(update_states(replaced_config, 'deleted'))
            mod_commands = want
            new_config = remove_empties_from_list(get_new_config(commands, tmp_have, TEST_KEYS_generate_config))
            tmp_have = new_config
        else:
            mod_commands = diff

        if mod_commands:
            mod_requests = self.get_modify_policies_requests(mod_commands, tmp_have)

            if mod_requests:
                requests.extend(mod_requests)
                commands.extend(update_states(mod_commands, 'replaced'))

        return commands, requests

    def _state_overridden(self, want, have, diff):
        """
        The command generator when state is overridden
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        global is_delete_all
        is_delete_all = False
        commands, requests = [], []
        mod_commands, mod_requests = None, None
        tmp_have = deepcopy(have)
        del_commands = self.get_diff_fbs_policies(have, want)
        self.handle_default_entries(del_commands)

        if del_commands:
            is_delete_all = True
            del_requests = self.get_delete_policies_requests(del_commands, is_delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(have, 'deleted'))
            new_config = remove_empties_from_list(get_new_config(commands, tmp_have, TEST_KEYS_generate_config))
            tmp_have = new_config
            mod_commands = want
            mod_requests = self.get_modify_policies_requests(mod_commands, tmp_have)
        elif diff:
            mod_commands = diff
            mod_requests = self.get_modify_policies_requests(mod_commands, tmp_have)

        if mod_requests:
            requests.extend(mod_requests)
            commands.extend(update_states(mod_commands, 'overridden'))

        return commands, requests

    def _state_deleted(self, want, have, diff):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        global is_delete_all
        is_delete_all = False
        requests = []

        if not want:
            commands = deepcopy(have)
            is_delete_all = True
        else:
            commands = self.get_diff_fbs_policies(want, diff)
            self.handle_default_entries(commands)

        if commands:
            requests = self.get_delete_policies_requests(commands, is_delete_all)
            if len(requests) > 0:
                commands = update_states(commands, 'deleted')
        else:
            commands = []

        return commands, requests

    @staticmethod
    def check_ars_disable(policy_name, classifier, config):
        """This method returns a boolean based on whether ars_disable has a value of true in the given config"""
        if config:
            match_policy = next((policy for policy in config if policy['policy_name'] == policy_name), None)
            if match_policy and match_policy.get('sections'):
                match_section = next((section for section in match_policy['sections'] if section['class'] == classifier), None)
                if match_section and match_section.get('forwarding') and match_section['forwarding'].get('ars_disable'):
                    return True
        return False

    def get_modify_policies_requests(self, commands, have):
        """This method returns a patch request to modify the FBS policies configuration"""
        requests = []
        policy_list = []

        for policy in commands:
            policy_dict = {}
            policy_name = policy.get('policy_name')
            policy_type = policy.get('policy_type')
            policy_description = policy.get('policy_description')
            sections = policy.get('sections')

            if policy_name:
                policy_dict.update({'policy-name': policy_name, 'config': {'name': policy_name}})
            if policy_type:
                if policy_type == 'copp' and policy_name != 'copp-system-policy':
                    self._module.fail_json(msg="Policy type 'copp' can only be configured for policy name 'copp-system-policy'")
                policy_dict['config']['type'] = enum_dict[policy_type]
            if policy_description:
                policy_dict['config']['description'] = policy_description
            if sections:
                section_list = []
                for section in sections:
                    section_dict = {}
                    classifier = section.get('class')
                    priority = section.get('priority')
                    section_description = section.get('section_description')
                    acl_copp = section.get('acl_copp')
                    qos = section.get('qos')
                    mirror_sessions = section.get('mirror_sessions')
                    forwarding = section.get('forwarding')

                    if classifier:
                        section_dict.update({'class': classifier, 'config': {'name': classifier}})
                    if priority is not None:
                        section_dict['config']['priority'] = priority
                    if section_description:
                        section_dict['config']['description'] = section_description
                    if acl_copp:
                        copp_dict = {}
                        cpu_queue_index = acl_copp.get('cpu_queue_index')
                        policer = acl_copp.get('policer')

                        if cpu_queue_index is not None:
                            copp_dict['config'] = {'cpu-queue-index': cpu_queue_index}
                        if policer:
                            copp_dict['policer'] = {'config': self.convert_policer_to_str(policer)}
                        if copp_dict:
                            section_dict['copp'] = copp_dict
                    if qos:
                        qos_dict = {}
                        output_queue_index = qos.get('output_queue_index')
                        policer = qos.get('policer')
                        remark = qos.get('remark')

                        if output_queue_index is not None:
                            qos_dict['queuing'] = {'config': {'output-queue-index': output_queue_index}}
                        if policer:
                            qos_dict['policer'] = {'config': self.convert_policer_to_str(policer)}
                        if remark:
                            config_dict = {}
                            set_dscp = remark.get('set_dscp')
                            set_dot1p = remark.get('set_dot1p')

                            if set_dscp is not None:
                                config_dict['set-dscp'] = set_dscp
                            if set_dot1p is not None:
                                config_dict['set-dot1p'] = set_dot1p
                            if config_dict:
                                qos_dict['remark'] = {'config': config_dict}
                        if qos_dict:
                            section_dict['qos'] = qos_dict
                    if mirror_sessions:
                        mirror_session_list = []
                        for session in mirror_sessions:
                            session_name = session.get('session_name')
                            if session_name:
                                mirror_session_list.append({'session-name': session_name, 'config': {'session-name': session_name}})
                        if mirror_session_list:
                            section_dict['monitoring'] = {'mirror-sessions': {'mirror-session': mirror_session_list}}
                    if forwarding:
                        forwarding_dict = {}
                        ars_disable = forwarding.get('ars_disable')
                        egress_interfaces = forwarding.get('egress_interfaces')
                        next_hops = forwarding.get('next_hops')
                        next_hop_groups = forwarding.get('next_hop_groups')
                        replication_groups = forwarding.get('replication_groups')

                        if ars_disable:
                            forwarding_dict['ars'] = {'config': {'disable': ars_disable}}

                        # Current SONiC behavior doesn't allow ars_disable to be patched to false,
                        # so ars_disable gets deleted instead. Also, it's necessary to make sure ars_disable
                        # is configured to true before deleting to avoid resource not found error.
                        if ars_disable is False and self.check_ars_disable(policy_name, classifier, have):
                            attr_path = '/sections/section=%s/forwarding/ars/config/disable' % (classifier)
                            requests.append(self.get_delete_policies_request(policy_name, attr_path))
                        if egress_interfaces:
                            egress_interface_list = []
                            for intf in egress_interfaces:
                                intf_dict = {}
                                intf_name = intf.get('intf_name')
                                priority = intf.get('priority')

                                if intf_name:
                                    intf_dict.update({'intf-name': intf_name, 'config': {'intf-name': intf_name}})
                                if priority:
                                    intf_dict['config']['priority'] = priority
                                if intf_dict:
                                    egress_interface_list.append(intf_dict)
                            if egress_interface_list:
                                forwarding_dict['egress-interfaces'] = {'egress-interface': egress_interface_list}
                        if next_hops:
                            next_hop_list = []
                            for hop in next_hops:
                                hop_dict = {}
                                address = hop.get('address')
                                vrf = hop.get('vrf')
                                priority = hop.get('priority')

                                if address:
                                    hop_dict.update({'ip-address': address, 'config': {'ip-address': address}})
                                if vrf:
                                    hop_dict['network-instance'] = vrf
                                    hop_dict['config']['network-instance'] = vrf
                                    # Special value for unspecified VRF should be hidden from the user
                                    if vrf == 'openconfig-fbs-ext:INTERFACE_NETWORK_INSTANCE':
                                        hop.pop('vrf')
                                if priority:
                                    hop_dict['config']['priority'] = priority
                                if hop_dict:
                                    next_hop_list.append(hop_dict)
                            if next_hop_list:
                                forwarding_dict['next-hops'] = {'next-hop': next_hop_list}
                        if next_hop_groups:
                            next_hop_groups_list = self.get_group_list_payload(next_hop_groups, 'next_hop_group_')
                            if next_hop_groups_list:
                                forwarding_dict['next-hop-groups'] = {'next-hop-group': next_hop_groups_list}
                        if replication_groups:
                            replication_groups_list = self.get_group_list_payload(replication_groups, 'replication_group_')
                            if replication_groups_list:
                                forwarding_dict['replication-groups'] = {'replication-group': replication_groups_list}
                        if forwarding_dict:
                            section_dict['forwarding'] = forwarding_dict
                    if section_dict:
                        section_list.append(section_dict)
                if section_list:
                    policy_dict['sections'] = {'section': section_list}
            if policy_dict:
                policy_list.append(policy_dict)
        if policy_list:
            payload = {'openconfig-fbs-ext:policies': {'policy': policy_list}}
            requests.append({'path': FBS_POLICIES_PATH, 'method': PATCH, 'data': payload})

        return requests

    def convert_policer_to_str(self, policer):
        policer_cp = policer.copy()
        for key in policer_cp:
            policer_cp[key] = str(policer_cp[key])

        return policer_cp

    def get_group_list_payload(self, groups_cfg, enum_prefix):
        """This method returns an OC formatted list constructed from groups_cfg that will
        be a part of the request payload"""
        group_list = []

        for group in groups_cfg:
            group_dict = {}
            group_name = group.get('group_name')
            group_type = group.get('group_type')
            priority = group.get('priority')

            if group_name:
                group_dict.update({'group-name': group_name, 'config': {'group-name': group_name}})
            if group_type:
                enum_key = enum_prefix + group_type
                group_dict['config']['group-type'] = enum_dict[enum_key]
            if priority:
                group_dict['config']['priority'] = priority
            if group_dict:
                group_list.append(group_dict)

        return group_list

    def get_delete_policies_requests(self, commands, is_delete_all):
        """This method returns a list of delete requests generated from commands"""
        requests = []

        if not commands:
            return requests
        if is_delete_all:
            requests.append(self.get_delete_policies_request())
            return requests

        for policy in commands:
            policy_name = policy.get('policy_name')
            policy_type = policy.get('policy_type')
            policy_description = policy.get('policy_description')
            sections = policy.get('sections')

            if policy_name and not policy_type and not policy_description and not sections:
                requests.append(self.get_delete_policies_request(policy_name))
            if policy_type:
                self._module.fail_json(msg='Deletion of policy_type not supported')
            if policy_description:
                attr_path = '/config/description'
                requests.append(self.get_delete_policies_request(policy_name, attr_path))
            if sections:
                for section in sections:
                    classifier = section.get('class')
                    priority = section.get('priority')
                    section_description = section.get('section_description')
                    acl_copp = section.get('acl_copp')
                    qos = section.get('qos')
                    mirror_sessions = section.get('mirror_sessions')
                    forwarding = section.get('forwarding')

                    if (classifier and priority is None and not section_description and not acl_copp and not qos and not mirror_sessions and not
                            forwarding):
                        attr_path = '/sections/section=%s' % (classifier)
                        requests.append(self.get_delete_policies_request(policy_name, attr_path))
                    if priority is not None:
                        self._module.fail_json(msg='Deletion of section priority not supported')
                    if section_description:
                        attr_path = '/sections/section=%s/config/description' % (classifier)
                        requests.append(self.get_delete_policies_request(policy_name, attr_path))
                    if acl_copp:
                        cpu_queue_index = acl_copp.get('cpu_queue_index')
                        policer = acl_copp.get('policer')

                        if cpu_queue_index is not None:
                            attr_path = '/sections/section=%s/copp/config/cpu-queue-index' % (classifier)
                            requests.append(self.get_delete_policies_request(policy_name, attr_path))
                        if policer:
                            for item in ('cbs', 'pbs', 'pir', 'cir'):
                                if policer.get(item):
                                    attr_path = '/sections/section=%s/copp/policer/config/%s' % (classifier, item)
                                    requests.append(self.get_delete_policies_request(policy_name, attr_path))
                    if qos:
                        output_queue_index = qos.get('output_queue_index')
                        policer = qos.get('policer')
                        remark = qos.get('remark')

                        if output_queue_index is not None:
                            attr_path = '/sections/section=%s/qos/queuing/config/output-queue-index' % (classifier)
                            requests.append(self.get_delete_policies_request(policy_name, attr_path))
                        if policer:
                            for item in ('cbs', 'pbs', 'pir', 'cir'):
                                if policer.get(item):
                                    attr_path = '/sections/section=%s/qos/policer/config/%s' % (classifier, item)
                                    requests.append(self.get_delete_policies_request(policy_name, attr_path))
                        if remark:
                            if remark.get('set_dscp') is not None:
                                attr_path = '/sections/section=%s/qos/remark/config/set-dscp' % (classifier)
                                requests.append(self.get_delete_policies_request(policy_name, attr_path))
                            if remark.get('set_dot1p') is not None:
                                attr_path = '/sections/section=%s/qos/remark/config/set-dot1p' % (classifier)
                                requests.append(self.get_delete_policies_request(policy_name, attr_path))
                    if mirror_sessions:
                        for session in mirror_sessions:
                            session_name = session.get('session_name')
                            if session_name:
                                attr_path = '/sections/section=%s/monitoring/mirror-sessions' % (classifier)
                                requests.append(self.get_delete_policies_request(policy_name, attr_path))
                    if forwarding:
                        ars_disable = forwarding.get('ars_disable')
                        egress_interfaces = forwarding.get('egress_interfaces')
                        next_hops = forwarding.get('next_hops')
                        next_hop_groups = forwarding.get('next_hop_groups')
                        replication_groups = forwarding.get('replication_groups')

                        if ars_disable is not None:
                            attr_path = '/sections/section=%s/forwarding/ars/config/disable' % (classifier)
                            requests.append(self.get_delete_policies_request(policy_name, attr_path))
                        if egress_interfaces:
                            for intf in egress_interfaces:
                                intf_name = intf.get('intf_name')
                                priority = intf.get('priority')

                                if intf_name and not priority:
                                    attr_path = '/sections/section=%s/forwarding/egress-interfaces/egress-interface=%s' % (classifier, intf_name)
                                    requests.append(self.get_delete_policies_request(policy_name, attr_path))
                                if priority:
                                    self._module.fail_json(msg='Deletion of egress interface priority not supported')
                        if next_hops:
                            for hop in next_hops:
                                address = hop.get('address')
                                vrf = hop.get('vrf')
                                priority = hop.get('priority')

                                if address and vrf and not priority:
                                    attr_path = '/sections/section=%s/forwarding/next-hops/next-hop=%s,%s'\
                                                % (classifier, address, vrf)
                                    requests.append(self.get_delete_policies_request(policy_name, attr_path))
                                # Special value for unspecified VRF should be hidden from the user
                                if vrf == 'openconfig-fbs-ext:INTERFACE_NETWORK_INSTANCE':
                                    hop.pop('vrf')
                                if priority:
                                    self._module.fail_json(msg='Deletion of next hop priority not supported')
                        if next_hop_groups:
                            for group in next_hop_groups:
                                group_name = group.get('group_name')
                                group_type = group.get('group_type')
                                priority = group.get('priority')

                                if group_name and not group_type and not priority:
                                    attr_path = '/sections/section=%s/forwarding/next-hop-groups/next-hop-group=%s' % (classifier, group_name)
                                    requests.append(self.get_delete_policies_request(policy_name, attr_path))
                                if group_type:
                                    attr_path = '/sections/section=%s/forwarding/next-hop-groups/next-hop-group=%s/config/group-type'\
                                                % (classifier, group_name)
                                    requests.append(self.get_delete_policies_request(policy_name, attr_path))
                                if priority:
                                    attr_path = '/sections/section=%s/forwarding/next-hop-groups/next-hop-group=%s/config/priority'\
                                                % (classifier, group_name)
                                    requests.append(self.get_delete_policies_request(policy_name, attr_path))
                        if replication_groups:
                            for group in replication_groups:
                                group_name = group.get('group_name')
                                group_type = group.get('group_type')
                                priority = group.get('priority')

                                if group_name and not group_type and not priority:
                                    attr_path = '/sections/section=%s/forwarding/replication-groups/replication-group=%s' % (classifier, group_name)
                                    requests.append(self.get_delete_policies_request(policy_name, attr_path))
                                if group_type:
                                    attr_path = '/sections/section=%s/forwarding/replication-groups/replication-group=%s/config/group-type'\
                                                % (classifier, group_name)
                                    requests.append(self.get_delete_policies_request(policy_name, attr_path))
                                if priority:
                                    attr_path = '/sections/section=%s/forwarding/replication-groups/replication-group=%s/config/priority'\
                                                % (classifier, group_name)
                                    requests.append(self.get_delete_policies_request(policy_name, attr_path))

        return requests

    def handle_default_entries(self, config, remove=True):
        """This method adds or removes the default entries from the FBS policies configuration"""
        for policy in config[:]:
            if policy.get('sections'):
                for section in policy['sections'][:]:
                    if remove and section.get('forwarding', {}).get('ars_disable') is False:
                        section['forwarding'].pop('ars_disable')
                        if not section['forwarding']:
                            section.pop('forwarding')
                            if len(section) == 1:
                                policy['sections'].remove(section)
                                if not policy['sections']:
                                    policy.pop('sections')
                                    if len(policy) == 1:
                                        config.remove(policy)
                    if not remove:
                        if 'forwarding' in section:
                            if section['forwarding'].get('ars_disable') is None:
                                section['forwarding']['ars_disable'] = False
                        else:
                            section.update({'forwarding': {'ars_disable': False}})

    def get_replaced_config(self, want, have):
        """This method returns the FBS policies configuration to be deleted and the respective delete requests"""
        config_list, requests = [], []
        cp_want = deepcopy(want)
        cp_have = deepcopy(have)
        self.handle_default_entries(cp_want)
        self.handle_default_entries(cp_have)
        self.sort_lists_in_config(cp_want)
        self.sort_lists_in_config(cp_have)

        if not cp_want or not cp_have:
            return config_list

        cfg_policy_dict = {policy.get('policy_name'): policy for policy in cp_have}
        for policy in cp_want:
            policy_name = policy.get('policy_name')
            cfg_policy = cfg_policy_dict.get(policy_name)

            if not cfg_policy:
                continue

            if policy != cfg_policy:
                requests.append(self.get_delete_policies_request(policy_name))
                config_list.append(cfg_policy)

        return config_list, requests

    @staticmethod
    def get_delete_policies_request(policy_name=None, attr_path=None):
        """This method constructs and returns an FBS policies delete request"""
        url = FBS_POLICIES_PATH

        if policy_name:
            url += '/policy=%s' % (policy_name)
        if attr_path:
            url += attr_path
        request = {'path': url, 'method': DELETE}
        return request

    @staticmethod
    def sort_lists_in_config(config):
        """This method sorts the lists in the FBS policies configuration"""
        if config:
            config.sort(key=lambda x: x['policy_name'])
            for policy in config:
                sections = policy.get('sections')
                if sections:
                    sections.sort(key=lambda x: x['class'])
                    for section in sections:
                        mirror_sessions = section.get('mirror_sessions')
                        forwarding = section.get('forwarding')

                        if mirror_sessions:
                            mirror_sessions.sort(key=lambda x: x['session_name'])
                        if forwarding:
                            egress_interfaces = forwarding.get('egress_interfaces')
                            next_hops = forwarding.get('next_hops')
                            next_hop_groups = forwarding.get('next_hop_groups')
                            replication_groups = forwarding.get('replication_groups')

                            if egress_interfaces:
                                egress_interfaces.sort(key=lambda x: x['intf_name'])
                            if next_hops:
                                next_hops.sort(key=lambda x: (x['address']))
                            if next_hop_groups:
                                next_hop_groups.sort(key=lambda x: x['group_name'])
                            if replication_groups:
                                replication_groups.sort(key=lambda x: x['group_name'])
