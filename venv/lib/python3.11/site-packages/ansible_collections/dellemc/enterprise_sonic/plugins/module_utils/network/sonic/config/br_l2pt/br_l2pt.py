from __future__ import absolute_import, division, print_function
__metaclass__ = type
#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_br_l2pt class
It is in this file where the current configuration (as list)
is compared to the provided configuration (as list) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    remove_none,
    get_ranges_in_list,
    remove_empties_from_list,
    sort_lists_by_interface_name,
    update_states
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF,
    get_new_config,
    get_formatted_config_diff
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible.module_utils.connection import ConnectionError
import re
from copy import deepcopy

PATCH = 'patch'
PUT = 'put'
DELETE = 'delete'

TEST_KEYS = [
    {'config': {'name': ''}},
    {'bridge_l2pt_params': {'protocol': ''}}
]
# Supported protocols for Bridge L2PT
supported_protocols = ['LLDP', 'LACP', 'STP', 'CDP']
replace = False


def __derive_br_l2pt_merge_op(key_set, command, exist_conf):
    new_conf = exist_conf

    if command:
        if len(command.keys()) == 1:
            return True, new_conf

        if not exist_conf or not exist_conf['bridge_l2pt_params'] or replace:
            return True, command

        l2pt_config = command['bridge_l2pt_params']
        for single_proto_config in l2pt_config:
            if single_proto_config.get('vlan_ids', []):
                new_ids = Br_l2pt.get_vlan_id_set(single_proto_config['vlan_ids'])
                exist_proto_config = next((cfg for cfg in exist_conf['bridge_l2pt_params'] if cfg['protocol'] == single_proto_config['protocol']), [])
                if exist_proto_config:
                    exist_ids = Br_l2pt.get_vlan_id_set(exist_proto_config['vlan_ids'])
                    vlans_merged = sorted(list(new_ids.union(exist_ids)))
                    for cfg in new_conf['bridge_l2pt_params']:
                        if cfg['protocol'] == single_proto_config['protocol']:
                            cfg['vlan_ids'] = [str(vrng[0]) if len(vrng) == 1 else f"{vrng[0]}-{vrng[-1]}"
                                               for vrng in get_ranges_in_list(vlans_merged)]
                elif single_proto_config['protocol'] in supported_protocols:
                    new_conf['bridge_l2pt_params'].append({'protocol': single_proto_config['protocol'],
                                                           'vlan_ids': single_proto_config['vlan_ids']})

    return True, new_conf


def __derive_br_l2pt_delete_op(key_set, command, exist_conf):
    new_conf = exist_conf
    if command:
        if len(command.keys()) == 1:
            return True, new_conf

        if not exist_conf:
            return True, new_conf

        if command.get('vlan_ids', []):
            new_ids = Br_l2pt.get_vlan_id_set(command['vlan_ids'])
            exist_ids = Br_l2pt.get_vlan_id_set(exist_conf['vlan_ids'])
            vlans_to_delete = new_ids.intersection(exist_ids)
            vlans_to_keep = sorted(list(exist_ids - vlans_to_delete))
            if len(exist_ids) >= len(new_ids):
                new_conf['protocol'] = command['protocol']
                new_conf['vlan_ids'] = [str(vrng[0]) if len(vrng) == 1 else f"{vrng[0]}-{vrng[-1]}"
                                        for vrng in get_ranges_in_list(vlans_to_keep)]
        else:
            # Protocol level delete
            new_conf = {}

    return True, new_conf


TEST_KEYS_generate_config = [
    {'config': {'name': '', '__merge_op': __derive_br_l2pt_merge_op, '__delete_op': __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'bridge_l2pt_params': {'protocol': '', '__delete_op': __derive_br_l2pt_delete_op}}
]


def remove_empty_protocols(config):
    new_config = []
    for intf_config in config:
        new_intf_config = {'name': intf_config['name'],
                           'bridge_l2pt_params': [cfg for cfg in intf_config['bridge_l2pt_params'] if cfg['vlan_ids']]}
        if new_intf_config['bridge_l2pt_params']:
            new_config.append(new_intf_config)
    return new_config


class Br_l2pt(ConfigBase):
    """
    The sonic_br_l2pt class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'br_l2pt',
    ]

    all_interfaces_path = 'data/openconfig-interfaces:interfaces'
    br_l2pt_intf_path = all_interfaces_path + '/interface={intf_name}'
    br_l2pt_intf_config_params_path = br_l2pt_intf_path + '/openconfig-interfaces-ext:bridge-l2pt-params'
    br_l2pt_intf_config_path = br_l2pt_intf_path + '/openconfig-interfaces-ext:bridge-l2pt-params/bridge-l2pt-param'
    br_l2pt_intf_proto_path = br_l2pt_intf_path + '/openconfig-interfaces-ext:bridge-l2pt-params/bridge-l2pt-param={protocol}'
    br_l2pt_intf_vlan_id_path = br_l2pt_intf_path + '/openconfig-interfaces-ext:bridge-l2pt-params/bridge-l2pt-param={protocol}/config/vlan-ids={vlan_ids}'

    payload_header = "openconfig-interfaces-ext:bridge-l2pt-param"

    def __init__(self, module):
        super(Br_l2pt, self).__init__(module)

    def get_br_l2pt_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A list
        :returns: The current configuration as a list
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        br_l2pt_facts = facts['ansible_network_resources'].get('br_l2pt')
        if not br_l2pt_facts:
            return []
        return br_l2pt_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        commands = []

        existing_br_l2pt_facts = self.get_br_l2pt_facts()
        commands, requests = self.set_config(existing_br_l2pt_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_br_l2pt_facts = self.get_br_l2pt_facts()

        result['before'] = Br_l2pt.sort_lists_in_config(existing_br_l2pt_facts)
        if result['changed']:
            result['after'] = Br_l2pt.sort_lists_in_config(changed_br_l2pt_facts)

        old_config = existing_br_l2pt_facts
        new_config = changed_br_l2pt_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_commands = remove_empties_from_list(commands)
            new_config = get_new_config(commands, old_config, TEST_KEYS_generate_config)
            result['after(generated)'] = Br_l2pt.sort_lists_in_config(remove_empty_protocols(new_config))

        if self._module._diff:
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)

        return result

    def set_config(self, existing_br_l2pt_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a list from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = remove_none(self._module.params['config'])
        have = existing_br_l2pt_facts
        resp = self.set_state(want, have)
        return to_list(resp)

    def set_state(self, want, have):
        """ Select the appropriate function based on the state provided

        :param want: the desired configuration as a list
        :param have: the current configuration as a list
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []
        state = self._module.params['state']

        if state == 'merged':
            commands, requests = self._state_merged(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have)
        elif state == 'overridden':
            commands, requests = self._state_overridden(want, have)

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = self.get_modify_br_l2pt_commands(want, have)
        requests = self.get_modify_br_l2pt_requests(commands)

        if commands and len(requests) > 0:
            commands = update_states(commands, 'merged')
        else:
            commands = []
        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        delete_all = False
        requests = []
        if not want:
            commands = deepcopy(have)
            delete_all = True
        else:
            commands = self.get_delete_br_l2pt_commands(want, have)

        if commands:
            requests = self.get_delete_br_l2pt_requests(commands, delete_all)
            if len(requests) > 0:
                commands = update_states(commands, 'deleted')
        else:
            commands = []

        return commands, requests

    def _state_replaced(self, want, have):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to replace the current configuration
                  of the provided objects
        """
        global replace
        replace = True

        return self.get_replace_override_br_l2pt_commands_requests(want, have, TEST_KEYS)

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to override the current configuration
                  of the provided objects
        """
        commands = []
        requests = []
        global replace
        replace = True

        if not want:
            del_commands = deepcopy(have)
        else:
            del_commands = self.get_delete_br_l2pt_overridden_commands(want, have)

        if del_commands:
            commands = update_states(del_commands, 'deleted')
            requests = self.get_delete_br_l2pt_requests(del_commands, True)

        mod_commands, mod_requests = self.get_replace_override_br_l2pt_commands_requests(want, have, TEST_KEYS)
        if mod_commands:
            commands.extend(update_states(mod_commands, 'overridden'))
            requests.extend(mod_requests)

        return commands, requests

    def get_modify_br_l2pt_commands(self, want, have, replace=False):
        """
        Get commands to modify or replace specific Bridge L2 Protocol Tunneling configurations
        based on the request, excluding redundant changes where possible.
        """
        # If no config exists, modify everything
        if not have:
            return want

        commands = []
        for intf in want:
            name = intf['name']
            want_proto_config = intf['bridge_l2pt_params']
            have_proto_config = next((h['bridge_l2pt_params'] for h in have if h['name'] == name), [])
            if replace or not have_proto_config:
                # Replace interface config (with replace op or empty existing config)
                if want_proto_config != have_proto_config:
                    command_dict = {'name': name, 'bridge_l2pt_params': want_proto_config}
                    commands.append(command_dict)
            elif have_proto_config and want_proto_config != have_proto_config:
                command_dict = {'name': name, 'bridge_l2pt_params': []}
                for single_proto_config in want_proto_config:
                    proto = single_proto_config['protocol']
                    match_proto_config = next((h for h in have_proto_config if h['protocol'] == proto), None)
                    if single_proto_config.get('vlan_ids', []):
                        if match_proto_config:
                            # If existing protocol config exists, find differences
                            want_vlans = self.get_vlan_id_set(single_proto_config['vlan_ids'])
                            have_vlans = self.get_vlan_id_set(match_proto_config['vlan_ids'])
                            # If incoming config adds new VLAN IDs to existing, add command
                            if not want_vlans.issubset(have_vlans):
                                command_dict['bridge_l2pt_params'].append(single_proto_config)
                        else:
                            # If existing protocol config empty, add incoming proto config
                            command_dict['bridge_l2pt_params'].append(single_proto_config)

                # Add commands for this interface
                if command_dict['bridge_l2pt_params']:
                    commands.append(command_dict)

        return commands

    def get_modify_br_l2pt_requests(self, commands, replace=False):
        """
        Get requests to modify or replace specific Bridge L2 Protocol Tunneling configurations
        based on the commands.
        """
        requests = []

        for command in commands:
            request = None
            name = command['name']
            payload = {self.payload_header: []}

            if re.search('Eth', name):
                proto_config = command['bridge_l2pt_params']
                # For each protocol's config, check if that protocol is supported and add request if so
                for single_proto_config in proto_config:
                    if single_proto_config['protocol'] in supported_protocols:
                        temp = {"protocol": single_proto_config['protocol']}
                        temp['config'] = {"protocol": single_proto_config['protocol'], "vlan-ids": self.replace_ranges(single_proto_config['vlan_ids'])}
                        payload[self.payload_header].append(temp)
                    else:
                        self._module.fail_json(msg="Protocol in config not supported: {}".format(single_proto_config['protocol']))

                # Either replace or merge config
                if replace:
                    request = {'path': self.br_l2pt_intf_config_path.format(intf_name=name), 'method': PUT, 'data': payload}
                else:
                    request = {'path': self.br_l2pt_intf_config_path.format(intf_name=name), 'method': PATCH, 'data': payload}

            requests.append(request)

        return requests

    def replace_ranges(self, vlan_ids):
        """
        Replace ranges that use a dash with two dots for REST request format.
        """
        new_vlan_ids = []
        for vid in vlan_ids:
            if "-" in vid:
                temp = vid.replace("-", "..")
            else:
                temp = int(vid)
            new_vlan_ids.append(temp)
        return new_vlan_ids

    def get_delete_br_l2pt_commands(self, want, have):
        """
        Get commands to delete Bridge L2 Protocol Tunneling configurations
        based on the existing config and requested deletions.
        """
        commands = []
        for intf in want:
            name = intf['name']
            want_proto_config = intf.get('bridge_l2pt_params', [])
            have_proto_config = next((h['bridge_l2pt_params'] for h in have if h['name'] == name), [])
            if have_proto_config:
                # Compare desired vs. existing configuration per protocol
                command_dict = {'name': name, 'bridge_l2pt_params': []}
                for single_proto_config in want_proto_config:
                    proto = single_proto_config['protocol']
                    match_proto_config = next((h for h in have_proto_config if h['protocol'] == proto), None)

                    if match_proto_config:
                        if not single_proto_config.get('vlan_ids', []):
                            # Delete all VLAN IDs for protocol
                            command_dict['bridge_l2pt_params'].append({'protocol': proto, 'vlan_ids': []})
                        else:
                            # Get VLAN IDs, flatten ranges, find intersection
                            want_vlans = self.get_vlan_id_set(single_proto_config['vlan_ids'])
                            have_vlans = self.get_vlan_id_set(match_proto_config['vlan_ids'])
                            vlans_to_delete = sorted(list(want_vlans.intersection(have_vlans)))
                            # Convert single IDs back to range format for command dict
                            if vlans_to_delete:
                                command_dict['bridge_l2pt_params'].append({'protocol': proto,
                                                                           'vlan_ids': [str(vrng[0]) if len(vrng) == 1 else f"{vrng[0]}-{vrng[-1]}"
                                                                                        for vrng in get_ranges_in_list(vlans_to_delete)]})
                # Add commands for this interface
                if command_dict['bridge_l2pt_params'] or not want_proto_config:
                    commands.append(command_dict)

        return commands

    def get_delete_br_l2pt_requests(self, commands, delete_all):
        """
        Get requests to delete Bridge L2 Protocol Tunneling configurations
        based on the commands.
        """
        requests = []

        for command in commands:
            name = command['name']
            if delete_all or not command['bridge_l2pt_params']:
                # Delete interface L2PT config
                requests.append({'path': self.br_l2pt_intf_config_params_path.format(intf_name=name), 'method': DELETE})
            elif re.search('Eth', name):
                proto_config = command['bridge_l2pt_params']
                for single_proto_config in proto_config:
                    if not single_proto_config.get('vlan_ids', []):
                        # Delete entire protocol config
                        uri = self.br_l2pt_intf_proto_path.format(intf_name=name, protocol=single_proto_config['protocol'])
                        requests.append({'path': uri, 'method': DELETE})
                    else:
                        # Delete specific VLAN IDs from protocol
                        for vrng in single_proto_config['vlan_ids']:
                            uri = self.br_l2pt_intf_vlan_id_path.format(intf_name=name,
                                                                        protocol=single_proto_config['protocol'],
                                                                        vlan_ids=vrng.replace("-", ".."))
                            requests.append({'path': uri, 'method': DELETE})

        return requests

    @staticmethod
    def get_vlan_id_set(vlan_range_list):
        """Convert a list of strings specifying single VLANs and VLAN
        ranges to a new set containing integer values and return."""
        vlan_id_set = set()
        if vlan_range_list:
            for vrng in vlan_range_list:
                if '-' in vrng:
                    start, end = vrng.split('-')
                    vlan_id_set.update(range(int(start), int(end) + 1))
                else:
                    # Single VLAN ID
                    vlan_id_set.add(int(vrng))

        return vlan_id_set

    def get_replace_override_br_l2pt_commands_requests(self, want, have, test_keys):
        """
        Get modification commands to replace/override Bridge L2 Protocol Tunneling configurations
        based on the replace/override request and the existing config.
        """
        commands = []
        requests = []
        diff = get_diff(want, have, test_keys)
        if diff:
            mod_commands = self.get_modify_br_l2pt_commands(want, have, replace=True)
            if mod_commands:
                commands = update_states(mod_commands, 'replaced')
                requests = self.get_modify_br_l2pt_requests(mod_commands, replace=True)
        return commands, requests

    def get_delete_br_l2pt_overridden_commands(self, want, have):
        """
        Get commands to delete Bridge L2 Protocol Tunneling configurations
        based on what is being overridden in the existing config.
        """
        commands = []
        # Delete existing interface configs not found in override request
        for intf in have:
            name = intf['name']
            want_proto_config = next((w['bridge_l2pt_params'] for w in want if w['name'] == name), [])
            if not want_proto_config:
                commands.append({'name': name, 'bridge_l2pt_params': intf.get('bridge_l2pt_params', [])})
        return commands

    @staticmethod
    def sort_lists_in_config(config):
        if config:
            sort_lists_by_interface_name(config, 'name')
            for single_config in config:
                if single_config.get('bridge_l2pt_params'):
                    sort_lists_by_interface_name(single_config['bridge_l2pt_params'], 'protocol')
        return config
