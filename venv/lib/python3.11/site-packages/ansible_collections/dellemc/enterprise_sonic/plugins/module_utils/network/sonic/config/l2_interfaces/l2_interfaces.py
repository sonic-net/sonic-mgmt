#
# -*- coding: utf-8 -*-
# © Copyright 2020 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_l2_interfaces class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

import traceback

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    get_ranges_in_list,
    update_states,
    normalize_interface_name
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    remove_empties,
    to_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import (
    Facts
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_CONFIG,
    __DELETE_CONFIG_IF_NO_SUBCONFIG,
    get_new_config,
    get_formatted_config_diff
)
from ansible.module_utils._text import to_native
from ansible.module_utils.connection import ConnectionError

LIB_IMP_ERR = None
ERR_MSG = None
try:
    import requests
    HAS_LIB = True
except Exception as e:
    HAS_LIB = False
    ERR_MSG = to_native(e)
    LIB_IMP_ERR = traceback.format_exc()

DELETE = 'delete'
PATCH = 'patch'
intf_key = 'openconfig-if-ethernet:ethernet'
port_chnl_key = 'openconfig-if-aggregate:aggregation'

TEST_KEYS = [
    {'allowed_vlans': {'vlan': ''}},
]
TEST_KEYS_formatted_diff = [
    {'config': {'name': '', '__delete_op': __DELETE_CONFIG}},
    {'allowed_vlans': {'vlan': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
]


class L2_interfaces(ConfigBase):
    """
    The sonic_l2_interfaces class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'l2_interfaces',
    ]

    def __init__(self, module):
        super(L2_interfaces, self).__init__(module)

    def get_l2_interfaces_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        l2_interfaces_facts = facts['ansible_network_resources'].get('l2_interfaces')
        if not l2_interfaces_facts:
            return []
        return l2_interfaces_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()

        existing_l2_interfaces_facts = self.get_l2_interfaces_facts()
        commands, requests = self.set_config(existing_l2_interfaces_facts)

        if commands:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_l2_interfaces_facts = self.get_l2_interfaces_facts()

        result['before'] = existing_l2_interfaces_facts
        if result['changed']:
            result['after'] = changed_l2_interfaces_facts

        new_config = changed_l2_interfaces_facts
        old_config = existing_l2_interfaces_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_l2_interfaces_facts,
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

    def set_config(self, existing_l2_interfaces_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        state = self._module.params['state']
        want = self._module.params['config']
        if want:
            # In state deleted, specific empty parameters are supported
            if state != 'deleted':
                want = [remove_empties(conf) for conf in want]
        else:
            want = []

        normalize_interface_name(want, self._module)
        have = existing_l2_interfaces_facts

        for intf in have:
            if not intf.get('access'):
                intf.update({'access': None})
            if not intf.get('trunk'):
                intf.update({'trunk': None})

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

        if state == 'overridden':
            commands, requests = self._state_overridden(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have)

        return commands, requests

    def _state_replaced(self, want, have):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []

        del_commands, del_requests = self.get_delete_commands_requests_for_replaced_overridden(want, have, 'replaced')
        if del_commands:
            commands = update_states(del_commands, 'deleted')
            requests = del_requests

        add_commands, add_requests = self.get_merge_commands_requests(want, have)
        if add_commands:
            commands.extend(update_states(add_commands, 'replaced'))
            requests.extend(add_requests)

        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []

        del_commands, del_requests = self.get_delete_commands_requests_for_replaced_overridden(want, have, 'overridden')
        if del_commands:
            commands = update_states(del_commands, 'deleted')
            requests = del_requests

        add_commands, add_requests = self.get_merge_commands_requests(want, have)
        if add_commands:
            commands.extend(update_states(add_commands, 'overridden'))
            requests.extend(add_requests)

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration at position-0
                  Requests necessary to merge to the current configuration
                  at position-1
        """
        commands, requests = self.get_merge_commands_requests(want, have)
        if commands:
            commands = update_states(commands, 'merged')

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        commands, requests = self.get_delete_commands_requests_for_deleted(want, have)
        if commands:
            commands = update_states(commands, 'deleted')

        return commands, requests

    def get_merge_commands_requests(self, want, have):
        """Returns the commands and requests necessary to merge the provided
        configurations into the current configuration
        """
        commands = []
        requests = []
        if not want:
            return commands, requests

        if have:
            diff = get_diff(want, have, TEST_KEYS)
        else:
            diff = want

        for cmd in diff:
            name = cmd['name']
            if name == 'eth0':
                continue

            if cmd.get('trunk') and cmd['trunk'].get('allowed_vlans'):
                match = next((cnf for cnf in have if cnf['name'] == name), None)
                if match:
                    cmd['trunk']['allowed_vlans'] = self.get_trunk_allowed_vlans_diff(cmd, match)
                    if not cmd['trunk']['allowed_vlans']:
                        cmd.pop('trunk')

            if cmd.get('access') or cmd.get('trunk'):
                commands.append(cmd)

        requests = self.get_create_l2_interface_requests(commands)
        return commands, requests

    def get_delete_commands_requests_for_deleted(self, want, have):
        """Returns the commands and requests necessary to remove the current
        configuration of the provided objects when state is deleted
        """
        commands = []
        requests = []
        if not have:
            return commands, requests

        if not want:
            # Delete all L2 interface config
            commands = [remove_empties(conf) for conf in have]
            requests = self.get_delete_all_switchport_requests(commands)
            return commands, requests

        for conf in want:
            name = conf['name']
            matched = next((cnf for cnf in have if cnf['name'] == name), None)
            if matched:
                # If both access and trunk are not mentioned, delete all config
                # in that interface
                if not conf.get('access') and not conf.get('trunk'):
                    command = {'name': name}
                    if matched.get('access'):
                        command['access'] = matched['access']
                    if matched.get('trunk'):
                        command['trunk'] = matched['trunk']

                    commands.append(command)
                    requests.extend(self.get_delete_all_switchport_requests([command]))
                else:
                    command = {}
                    if conf.get('access'):
                        access_match = matched.get('access')
                        if conf['access'].get('vlan'):
                            if access_match and access_match.get('vlan') == conf['access']['vlan']:
                                command['access'] = {'vlan': conf['access']['vlan']}
                                requests.append(self.get_access_delete_switchport_request(name))
                        else:
                            # If access -> vlan is mentioned without value,
                            # delete existing access vlan config
                            if access_match and access_match.get('vlan'):
                                command['access'] = {'vlan': access_match['vlan']}
                                requests.append(self.get_access_delete_switchport_request(name))

                    if conf.get('trunk'):
                        if conf['trunk'].get('allowed_vlans'):
                            trunk_vlans_to_delete = self.get_trunk_allowed_vlans_common(conf, matched)
                            if trunk_vlans_to_delete:
                                command['trunk'] = {'allowed_vlans': trunk_vlans_to_delete}
                                requests.extend(self.get_trunk_allowed_vlans_delete_switchport_requests(name, command['trunk']['allowed_vlans']))
                        else:
                            # If trunk -> allowed_vlans is mentioned without
                            # value, delete existing trunk allowed vlans config
                            trunk_match = matched.get('trunk')
                            if trunk_match and trunk_match.get('allowed_vlans'):
                                command['trunk'] = {'allowed_vlans': trunk_match['allowed_vlans'].copy()}
                                requests.extend(self.get_trunk_allowed_vlans_delete_switchport_requests(name, command['trunk']['allowed_vlans']))

                    if command:
                        command['name'] = name
                        commands.append(command)

        return commands, requests

    def get_delete_commands_requests_for_replaced_overridden(self, want, have, state):
        """Returns the commands and requests necessary to remove applicable
        current configurations when state is replaced or overridden
        """
        commands = []
        requests = []
        if not have:
            return commands, requests

        have_interfaces = self.get_interface_names(have)
        want_interfaces = self.get_interface_names(want)
        interfaces_to_replace = have_interfaces.intersection(want_interfaces)
        if state == 'overridden':
            interfaces_to_delete = have_interfaces.difference(want_interfaces)
        else:
            interfaces_to_delete = []

        if want:
            del_diff = get_diff(have, want, TEST_KEYS)
        else:
            del_diff = have

        for conf in del_diff:
            name = conf['name']

            # Delete all config in interfaces not specified in overridden
            if name in interfaces_to_delete:
                command = {'name': name}
                if conf.get('access'):
                    command['access'] = conf['access']
                if conf.get('trunk'):
                    command['trunk'] = conf['trunk']

                commands.append(command)
                requests.extend(self.get_delete_all_switchport_requests([command]))

            # Delete config in interfaces that are replaced/overridden
            elif name in interfaces_to_replace:
                command = {}

                if conf.get('access') and conf['access'].get('vlan'):
                    command['access'] = {'vlan': conf['access']['vlan']}
                    requests.append(self.get_access_delete_switchport_request(name))

                if conf.get('trunk') and conf['trunk'].get('allowed_vlans'):
                    matched = next((cnf for cnf in want if cnf['name'] == name), None)
                    if matched:
                        trunk_vlans_to_delete = self.get_trunk_allowed_vlans_diff(conf, matched)
                        if trunk_vlans_to_delete:
                            command['trunk'] = {'allowed_vlans': trunk_vlans_to_delete}
                            requests.extend(self.get_trunk_allowed_vlans_delete_switchport_requests(name, command['trunk']['allowed_vlans']))

                if command:
                    command['name'] = name
                    commands.append(command)

        return commands, requests

    def get_trunk_allowed_vlans_delete_switchport_requests(self, intf_name, allowed_vlans):
        """Returns the requests as a list to delete the trunk vlan ranges
        specified in allowed_vlans for the given interface
        """
        requests = []
        method = DELETE
        key = intf_key

        if intf_name.startswith('PortChannel'):
            key = port_chnl_key

        for each_allowed_vlan in allowed_vlans:
            vlan_id = each_allowed_vlan['vlan']

            if '-' in vlan_id:
                vlan_id = vlan_id.replace('-', '..')

            url = "data/openconfig-interfaces:interfaces/interface={0}/{1}/".format(intf_name, key)
            url += "openconfig-vlan:switched-vlan/config/"
            url += "trunk-vlans=" + vlan_id
            requests.append({"path": url, "method": method})
        return requests

    def get_access_delete_switchport_request(self, intf_name):
        """Returns the request as a dict to delete the access vlan
        configuration for the given interface
        """
        method = DELETE
        key = intf_key
        if intf_name.startswith('PortChannel'):
            key = port_chnl_key
        url = "data/openconfig-interfaces:interfaces/interface={}/{}/openconfig-vlan:switched-vlan/config/access-vlan"
        request = {"path": url.format(intf_name, key), "method": method}

        return request

    def get_delete_all_switchport_requests(self, configs):
        """Returns a list of requests to delete all switchport
        configuration for all interfaces specified in the config list
        """
        requests = []
        if not configs:
            return requests
        # Create URL and payload
        url = "data/openconfig-interfaces:interfaces/interface={}/{}/openconfig-vlan:switched-vlan/config"
        method = DELETE
        for intf in configs:
            name = intf['name']
            key = intf_key
            if name.startswith('PortChannel'):
                key = port_chnl_key
            request = {"path": url.format(name, key),
                       "method": method,
                       }
            requests.append(request)

        return requests

    def get_create_l2_interface_requests(self, configs):
        """Returns a list of requests to add the switchport
        configurations specified in the config list
        """
        requests = []
        if not configs:
            return requests

        # Create URL and payload
        url = "data/openconfig-interfaces:interfaces/interface={}/{}/openconfig-vlan:switched-vlan/config"
        method = PATCH
        for conf in configs:
            name = conf['name']
            key = intf_key
            if name.startswith('PortChannel'):
                key = port_chnl_key
            payload = self.build_create_payload(conf)
            request = {"path": url.format(name, key),
                       "method": method,
                       "data": payload
                       }
            requests.append(request)

        return requests

    def build_create_payload(self, conf):
        """Returns the payload to add the switchport configurations
        specified in the interface config
        """
        payload = {'openconfig-vlan:config': {}}
        trunk_payload = []

        if conf.get('access') and conf['access'].get('vlan'):
            payload['openconfig-vlan:config']['access-vlan'] = int(conf['access']['vlan'])

        if conf.get('trunk') and conf['trunk'].get('allowed_vlans'):
            for each_allowed_vlan in conf['trunk']['allowed_vlans']:
                vlan_val = each_allowed_vlan['vlan']
                if '-' in vlan_val:
                    trunk_payload.append('{0}'.format(vlan_val.replace('-', '..')))
                else:
                    trunk_payload.append(int(vlan_val))

            if trunk_payload:
                payload['openconfig-vlan:config']['trunk-vlans'] = trunk_payload

        return payload

    def get_trunk_allowed_vlans_common(self, config, match):
        """Returns the allowed vlan ranges that are common in the
        interface configurations specified by 'config' and 'match' in
        allowed_vlans spec format
        """
        trunk_vlans = []
        match_trunk_vlans = []
        if config.get('trunk') and config['trunk'].get('allowed_vlans'):
            trunk_vlans = config['trunk']['allowed_vlans']

        if not trunk_vlans:
            return []

        if match.get('trunk') and match['trunk'].get('allowed_vlans'):
            match_trunk_vlans = match['trunk']['allowed_vlans']

        if not match_trunk_vlans:
            return []

        trunk_vlans = self.get_vlan_id_list(trunk_vlans)
        match_trunk_vlans = self.get_vlan_id_list(match_trunk_vlans)
        return self.get_allowed_vlan_range_list(list(set(trunk_vlans).intersection(set(match_trunk_vlans))))

    def get_trunk_allowed_vlans_diff(self, config, match):
        """Returns the allowed vlan ranges present only in 'config'
        and and not in 'match' in allowed_vlans spec format
        """
        trunk_vlans = []
        match_trunk_vlans = []
        if config.get('trunk') and config['trunk'].get('allowed_vlans'):
            trunk_vlans = config['trunk']['allowed_vlans']

        if not trunk_vlans:
            return []

        if match.get('trunk') and match['trunk'].get('allowed_vlans'):
            match_trunk_vlans = match['trunk']['allowed_vlans']

        if not match_trunk_vlans:
            return trunk_vlans

        trunk_vlans = self.get_vlan_id_list(trunk_vlans)
        match_trunk_vlans = self.get_vlan_id_list(match_trunk_vlans)
        return self.get_allowed_vlan_range_list(list(set(trunk_vlans) - set(match_trunk_vlans)))

    @staticmethod
    def get_vlan_id_list(allowed_vlan_range_list):
        """Returns a list of all VLAN IDs specified in allowed_vlans list"""
        vlan_id_list = []
        if allowed_vlan_range_list:
            for vlan_range in allowed_vlan_range_list:
                vlan_val = vlan_range['vlan']
                if '-' in vlan_val:
                    start, end = vlan_val.split('-')
                    vlan_id_list.extend(range(int(start), int(end) + 1))
                else:
                    # Single VLAN ID
                    vlan_id_list.append(int(vlan_val))

        return vlan_id_list

    @staticmethod
    def get_allowed_vlan_range_list(vlan_id_list):
        """Returns the allowed_vlans list for given list of VLAN IDs"""
        allowed_vlan_range_list = []

        if vlan_id_list:
            vlan_id_list.sort()
            for vlan_range in get_ranges_in_list(vlan_id_list):
                allowed_vlan_range_list.append({'vlan': '-'.join(map(str, (vlan_range[0], vlan_range[-1])[:len(vlan_range)]))})

        return allowed_vlan_range_list

    @staticmethod
    def get_interface_names(configs):
        """Returns a set of interface names available in the given
        configs list
        """
        interface_names = set()
        for conf in configs:
            interface_names.add(conf['name'])

        return interface_names

    def sort_config(self, configs):
        # natsort provides better result.
        # The use of natsort causes sanity error due to it is not available in
        # python version currently used.
        # new_config = natsorted(new_config, key=lambda x: x['name'])
        # For time-being, use simple "sort"
        configs.sort(key=lambda x: x['name'])

        for conf in configs:
            if conf.get('trunk', {}) and conf['trunk'].get('allowed_vlans', []):
                conf['trunk']['allowed_vlans'].sort(key=lambda x: x['vlan'])
