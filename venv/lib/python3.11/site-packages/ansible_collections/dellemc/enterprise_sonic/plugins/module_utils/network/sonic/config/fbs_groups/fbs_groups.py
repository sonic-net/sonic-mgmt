#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_fbs_groups class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
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
    remove_empties,
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

delete_all = False
replaced = False
FBS_PATH = 'data/openconfig-fbs-ext:fbs'
PATCH = 'patch'
DELETE = 'delete'
TEST_KEYS = [
    {'next_hop_groups': {'group_name': ''}},
    {'replication_groups': {'group_name': ''}},
    {'next_hops': {'entry_id': ''}},
]
enum_dict = {
    'next_hop_groups': {
        'ipv4': 'NEXT_HOP_GROUP_TYPE_IPV4',
        'ipv6': 'NEXT_HOP_GROUP_TYPE_IPV6'
    },
    'replication_groups': {
        'ipv4': 'REPLICATION_GROUP_TYPE_IPV4',
        'ipv6': 'REPLICATION_GROUP_TYPE_IPV6'
    },
    'count': 'NEXT_HOP_GROUP_THRESHOLD_COUNT',
    'percentage': 'NEXT_HOP_GROUP_THRESHOLD_PERCENTAGE',
    'non_recursive': 'NEXT_HOP_TYPE_NON_RECURSIVE',
    'overlay': 'NEXT_HOP_TYPE_OVERLAY',
    'recursive': 'NEXT_HOP_TYPE_RECURSIVE'
}


def __derive_fbs_groups_delete_op(key_set, command, exist_conf):
    if delete_all or replaced:
        new_conf = []
        return True, new_conf

    # Deletion of threshold_type will delete threshold_up and threshold_down
    if command.get('threshold_type'):
        if command.get('threshold_up') is None and exist_conf.get('threshold_up') is not None:
            command['threshold_up'] = exist_conf['threshold_up']
        if command.get('threshold_down') is None and exist_conf.get('threshold_down') is not None:
            command['threshold_down'] = exist_conf['threshold_down']

    done, new_conf = __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, exist_conf)
    return done, new_conf


TEST_KEYS_generate_config = [
    {'next_hop_groups': {'group_name': '', '__delete_op': __derive_fbs_groups_delete_op}},
    {'replication_groups': {'group_name': '', '__delete_op': __derive_fbs_groups_delete_op}},
    {'next_hops': {'entry_id': '', '__delete_op': __derive_fbs_groups_delete_op}}
]


class Fbs_groups(ConfigBase):
    """
    The sonic_fbs_groups class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'fbs_groups',
    ]

    def __init__(self, module):
        super(Fbs_groups, self).__init__(module)

    def get_fbs_groups_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        fbs_groups_facts = facts['ansible_network_resources'].get('fbs_groups')
        if not fbs_groups_facts:
            return {}
        return fbs_groups_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        commands = []

        existing_fbs_groups_facts = self.get_fbs_groups_facts()
        commands, requests = self.set_config(existing_fbs_groups_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True

        result['commands'] = commands
        result['before'] = existing_fbs_groups_facts
        old_config = existing_fbs_groups_facts

        if self._module.check_mode:
            new_config = remove_empties(get_new_config(commands, existing_fbs_groups_facts, TEST_KEYS_generate_config))
            self.sort_lists_in_config(new_config)
            self.handle_default_entries(new_config, False)
            result['after(generated)'] = new_config
        else:
            new_config = self.get_fbs_groups_facts()
            if result['changed']:
                result['after'] = new_config
        if self._module._diff:
            self.sort_lists_in_config(new_config)
            self.sort_lists_in_config(old_config)
            result['diff'] = get_formatted_config_diff(old_config, new_config, self._module._verbosity)

        return result

    def set_config(self, existing_fbs_groups_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = remove_empties(self._module.params['config'])
        have = existing_fbs_groups_facts
        resp = self.set_state(want, have)
        return to_list(resp)

    def get_modify_diff(self, want, have):
        """This method calculates the diff for modification, while taking into account
        the required non-key attributes"""
        mod_diff = get_diff(want, have, TEST_KEYS)
        if mod_diff:
            for groups_name in ('next_hop_groups', 'replication_groups'):
                groups = mod_diff.get(groups_name)
                if groups:
                    cfg_group_dict = {group.get('group_name'): group for group in have.get(groups_name, [])}
                    for group in groups:
                        group_name = group.get('group_name')
                        cfg_group = cfg_group_dict.get(group_name)

                        if not cfg_group:
                            continue
                        group_type = group.get('group_type')
                        next_hops = group.get('next_hops')
                        cfg_group_type = cfg_group.get('group_type')
                        cfg_next_hops = cfg_group.get('next_hops', [])

                        # group_type always required for modification
                        if not group_type and cfg_group_type:
                            group['group_type'] = cfg_group_type

                        if next_hops:
                            cfg_hop_dict = {hop.get('entry_id'): hop for hop in cfg_next_hops}
                            for hop in next_hops:
                                entry_id = hop.get('entry_id')
                                cfg_hop = cfg_hop_dict.get(entry_id)

                                if not cfg_hop:
                                    continue
                                ip_address = hop.get('ip_address')
                                cfg_ip_address = cfg_hop.get('ip_address')

                                # ip_address always required for modification
                                if not ip_address and cfg_ip_address:
                                    hop['ip_address'] = cfg_ip_address
        return mod_diff

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
        diff = self.get_modify_diff(want, have)

        if state == 'merged':
            commands, requests = self._state_merged(have, diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have, diff)
        elif state == 'overridden':
            commands, requests = self._state_overridden(want, have, diff)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        return commands, requests

    def _state_merged(self, have, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        requests = self.get_modify_fbs_groups_requests(commands, have)

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
        global replaced
        replaced = False
        commands, mod_commands = [], []
        tmp_have = deepcopy(have)
        replaced_config, requests = self.get_replaced_config(want, have)

        if replaced_config:
            replaced = True
            commands.extend(update_states(replaced_config, 'deleted'))
            mod_commands = want
            tmp_have = remove_empties(get_new_config(commands, tmp_have, TEST_KEYS_generate_config))
        else:
            mod_commands = diff

        if mod_commands:
            mod_requests = self.get_modify_fbs_groups_requests(mod_commands, tmp_have)

            if mod_requests:
                requests.extend(mod_requests)
                commands.extend(update_states(mod_commands, 'replaced'))

        return commands, requests

    def _state_overridden(self, want, have, diff):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        global delete_all
        delete_all = False
        commands, requests = [], []
        mod_commands, mod_requests = None, None
        tmp_have = deepcopy(have)
        del_commands = get_diff(have, want, TEST_KEYS)
        self.handle_default_entries(del_commands)

        if del_commands:
            delete_all = True
            del_requests = self.get_delete_fbs_groups_requests(del_commands, delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(have, 'deleted'))
            tmp_have = remove_empties(get_new_config(commands, tmp_have, TEST_KEYS_generate_config))
            mod_commands = want
            mod_requests = self.get_modify_fbs_groups_requests(mod_commands, tmp_have)
        elif diff:
            mod_commands = diff
            mod_requests = self.get_modify_fbs_groups_requests(mod_commands, tmp_have)

        if mod_requests:
            requests.extend(mod_requests)
            commands.extend(update_states(mod_commands, 'overridden'))

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted
        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        global delete_all
        delete_all = False
        requests = []
        diff = get_diff(want, have, TEST_KEYS)

        if not want:
            commands = deepcopy(have)
            delete_all = True
        else:
            commands = get_diff(want, diff, TEST_KEYS)
            self.handle_default_entries(commands)

        if commands:
            requests = self.get_delete_fbs_groups_requests(commands, delete_all)
            if len(requests) > 0:
                commands = update_states(commands, 'deleted')
        else:
            commands = []

        return commands, requests

    @staticmethod
    def check_single_copy(group_name, entry_id, config):
        """This method returns a boolean based on whether single_copy has a value of true in the given config"""
        if config:
            match_group = next((group for group in config if group['group_name'] == group_name), None)
            if match_group and match_group.get('next_hops'):
                match_hop = next((hop for hop in match_group['next_hops'] if hop['entry_id'] == entry_id), None)
                if match_hop and match_hop.get('single_copy'):
                    return True
        return False

    def get_modify_fbs_groups_requests(self, commands, have):
        """This method returns a single OC patch request constructed from commands"""
        requests = []

        if commands:
            fbs_dict = {}
            for groups_name in ('next_hop_groups', 'replication_groups'):
                groups = commands.get(groups_name)
                if groups:
                    group_list = []
                    for group in groups:
                        group_dict = {}
                        group_name = group.get('group_name')
                        group_description = group.get('group_description')
                        group_type = group.get('group_type')
                        next_hops = group.get('next_hops')

                        if group_name:
                            group_dict.update({'group-name': group_name, 'config': {'name': group_name}})
                        if group_description:
                            group_dict['config']['description'] = group_description
                        if group_type:
                            group_dict['config']['group-type'] = enum_dict[groups_name][group_type]
                        else:
                            self._module.fail_json(msg='group_type is required')
                        if groups_name == 'next_hop_groups':
                            threshold_type = group.get('threshold_type')
                            threshold_up = group.get('threshold_up')
                            threshold_down = group.get('threshold_down')

                            if threshold_type:
                                group_dict['config']['threshold-type'] = enum_dict[threshold_type]
                            if threshold_up is not None:
                                group_dict['config']['threshold-up'] = threshold_up
                            if threshold_down is not None:
                                group_dict['config']['threshold-down'] = threshold_down
                        if next_hops:
                            next_hop_list = []
                            for hop in next_hops:
                                hop_dict = {}
                                entry_id = hop.get('entry_id')
                                ip_address = hop.get('ip_address')
                                vrf = hop.get('vrf')
                                next_hop_type = hop.get('next_hop_type')

                                if entry_id:
                                    hop_dict.update({'entry-id': entry_id, 'config': {'entry-id': entry_id}})
                                if ip_address:
                                    hop_dict['config']['ip-address'] = ip_address
                                else:
                                    self._module.fail_json(msg='ip_address required for next-hop entry')
                                if vrf:
                                    hop_dict['config']['network-instance'] = vrf
                                if next_hop_type:
                                    hop_dict['config']['next-hop-type'] = enum_dict[next_hop_type]
                                if groups_name == 'replication_groups':
                                    single_copy = hop.get('single_copy')

                                    if single_copy:
                                        hop_dict['config']['single-copy'] = single_copy

                                    # Current SONiC behavior doesn't allow single_copy to be patched to false,
                                    # so single_copy gets deleted instead. Also, it's necessary to make sure single_copy
                                    # is configured to true before deleting to avoid resource not found error.
                                    if single_copy is False and self.check_single_copy(group_name, entry_id, have.get('replication_groups')):
                                        requests.append(self.get_delete_next_hops_request('replication-group', group_name, entry_id, 'single-copy'))

                                if hop_dict:
                                    next_hop_list.append(hop_dict)
                            if next_hop_list:
                                group_dict['next-hops'] = {'next-hop': next_hop_list}
                        if group_dict:
                            group_list.append(group_dict)
                    if group_list:
                        dict_name = groups_name.replace('_', '-')
                        list_name = dict_name.strip('s')
                        fbs_dict[dict_name] = {list_name: group_list}
            if fbs_dict:
                payload = {'openconfig-fbs-ext:fbs': fbs_dict}
                requests.append({'path': FBS_PATH, 'method': PATCH, 'data': payload})

        return requests

    def get_delete_fbs_groups_requests(self, commands, delete_all):
        """Returns OC delete requests"""
        requests = []

        if not commands:
            return requests
        if delete_all:
            requests.append(self.get_delete_groups_request('next-hop-group'))
            requests.append(self.get_delete_groups_request('replication-group'))
            return requests

        for groups_name in ('next_hop_groups', 'replication_groups'):
            groups = commands.get(groups_name)
            if groups:
                oc_group = groups_name.replace('_', '-').strip('s')
                for group in groups:
                    group_name = group.get('group_name')
                    if len(group) == 1:
                        requests.append(self.get_delete_groups_request(oc_group, group_name))
                    else:
                        group_description = group.get('group_description')
                        group_type = group.get('group_type')
                        next_hops = group.get('next_hops')

                        if group_description:
                            requests.append(self.get_delete_groups_request(oc_group, group_name, 'description'))
                        if group_type:
                            self._module.fail_json(msg='Deletion of group_type is not supported')
                        if groups_name == 'next_hop_groups':
                            threshold_type = group.get('threshold_type')
                            threshold_up = group.get('threshold_up')
                            threshold_down = group.get('threshold_down')

                            if threshold_up is not None:
                                requests.append(self.get_delete_groups_request(oc_group, group_name, 'threshold-up'))
                            if threshold_down is not None:
                                requests.append(self.get_delete_groups_request(oc_group, group_name, 'threshold-down'))
                            if threshold_type:
                                requests.append(self.get_delete_groups_request(oc_group, group_name, 'threshold-type'))

                        if next_hops:
                            for hop in next_hops:
                                entry_id = hop.get('entry_id')
                                if len(hop) == 1:
                                    requests.append(self.get_delete_next_hops_request(oc_group, group_name, entry_id))
                                else:
                                    ip_address = hop.get('ip_address')
                                    vrf = hop.get('vrf')
                                    next_hop_type = hop.get('next_hop_type')

                                    if ip_address:
                                        self._module.fail_json(msg='Deletion of ip_address not supported')
                                    if vrf:
                                        requests.append(self.get_delete_next_hops_request(oc_group, group_name, entry_id, 'network-instance'))
                                    if next_hop_type:
                                        requests.append(self.get_delete_next_hops_request(oc_group, group_name, entry_id, 'next-hop-type'))
                                    if groups_name == 'replication_groups':
                                        single_copy = hop.get('single_copy')

                                        if single_copy is not None:
                                            requests.append(self.get_delete_next_hops_request(oc_group, group_name, entry_id, 'single-copy'))

        return requests

    @staticmethod
    def get_delete_groups_request(group, group_name=None, attr=None):
        """This method returns a group delete request"""
        url = f'{FBS_PATH}/{group}s'

        if group_name:
            url += f'/{group}={group_name}'
        if attr:
            url += f'/config/{attr}'
        request = {'path': url, 'method': DELETE}
        return request

    @staticmethod
    def get_delete_next_hops_request(group, group_name, entry_id, attr=None):
        """This method returns a next-hop delete request"""
        url = f'{FBS_PATH}/{group}s/{group}={group_name}/next-hops/next-hop={entry_id}'

        if attr:
            url += f'/config/{attr}'
        request = {'path': url, 'method': DELETE}
        return request

    def handle_default_entries(self, config, remove=True):
        """This method adds or removes the default entries from the FBS groups configuration"""
        if config.get('replication_groups'):
            for group in config['replication_groups'][:]:
                if group.get('next_hops'):
                    for hop in group['next_hops'][:]:
                        if remove and hop.get('single_copy') is False:
                            hop.pop('single_copy')
                            if len(hop) == 1:
                                group['next_hops'].remove(hop)
                                if not group['next_hops']:
                                    group.pop('next_hops')
                                    if len(group) == 1:
                                        config['replication_groups'].remove(group)
                                        if not config['replication_groups']:
                                            config.pop('replication_groups')

                        if not remove:
                            if hop.get('single_copy') is None:
                                hop['single_copy'] = False

    def get_replaced_config(self, want, have):
        """This method returns the replaced FBS configuration and the corresponding delete requests"""
        config_dict = {}
        requests = []
        cp_want = deepcopy(want)
        cp_have = deepcopy(have)
        self.handle_default_entries(cp_want)
        self.handle_default_entries(cp_have)
        self.sort_lists_in_config(cp_want)
        self.sort_lists_in_config(cp_have)

        if not cp_want or not cp_have:
            return config_dict

        for groups_name in ('next_hop_groups', 'replication_groups'):
            groups_list = []
            groups = cp_want.get(groups_name)
            cfg_groups = cp_have.get(groups_name)

            if not cfg_groups:
                continue
            cfg_group_dict = {group.get('group_name'): group for group in cfg_groups}

            for group in groups:
                group_name = group.get('group_name')
                cfg_group = cfg_group_dict.get(group_name)

                if not cfg_group:
                    continue
                if group != cfg_group:
                    oc_group = groups_name.replace('_', '-').strip('s')
                    requests.append(self.get_delete_groups_request(oc_group, group_name, None))
                    groups_list.append(cfg_group)
            if groups_list:
                config_dict[groups_name] = groups_list

        return config_dict, requests

    @staticmethod
    def sort_lists_in_config(config):
        """This method sorts the lists in the FBS groups configuration"""
        if config:
            if config.get('next_hop_groups'):
                config['next_hop_groups'].sort(key=lambda x: x['group_name'])
                for group in config['next_hop_groups']:
                    if group.get('next_hops'):
                        group['next_hops'].sort(key=lambda x: x['entry_id'])
            if config.get('replication_groups'):
                config['replication_groups'].sort(key=lambda x: x['group_name'])
                for group in config['replication_groups']:
                    if group.get('next_hops'):
                        group['next_hops'].sort(key=lambda x: x['entry_id'])
