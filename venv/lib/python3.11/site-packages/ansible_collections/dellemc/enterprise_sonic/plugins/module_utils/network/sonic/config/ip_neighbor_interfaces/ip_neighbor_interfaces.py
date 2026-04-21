#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_ip_neighbor_interfaces class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.common.validation import check_required_arguments
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
    search_obj_in_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    remove_empties_from_list,
    update_states,
    normalize_interface_name
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
from ansible.module_utils.connection import ConnectionError

DELETE = 'DELETE'
PATCH = 'PATCH'

TEST_KEYS = [
    {'config': {'name': ''}},
    {'ipv4_neighbors': {'ip': ''}},
    {'ipv6_neighbors': {'ip': ''}}
]
TEST_KEYS_generate_config = [
    {'config': {'name': ''}},
    {'ipv4_neighbors': {'ip': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'ipv6_neighbors': {'ip': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}}
]


class Ip_neighbor_interfaces(ConfigBase):
    """
    The sonic_ip_neighbor_interfaces class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'ip_neighbor_interfaces',
    ]

    non_vlan_neighbors_path = ('data/openconfig-interfaces:interfaces/interface={intf_name}'
                               '/subinterfaces/subinterface={sub_intf}/openconfig-if-ip:ipv{ip_version}/neighbors')
    vlan_neighbors_path = 'data/openconfig-interfaces:interfaces/interface={vlan_name}/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv{ip_version}/neighbors'

    def __init__(self, module):
        super(Ip_neighbor_interfaces, self).__init__(module)

    def get_ip_neighbor_interfaces_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        ip_neighbor_interfaces_facts = facts['ansible_network_resources'].get('ip_neighbor_interfaces')
        if not ip_neighbor_interfaces_facts:
            return []
        return ip_neighbor_interfaces_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}

        existing_ip_neighbor_interfaces_facts = self.get_ip_neighbor_interfaces_facts()
        commands, requests = self.set_config(existing_ip_neighbor_interfaces_facts)
        if commands:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True

        result['before'] = existing_ip_neighbor_interfaces_facts
        old_config = existing_ip_neighbor_interfaces_facts
        if self._module.check_mode:
            new_config = self.get_new_config(commands, old_config)
            self.sort_lists_in_config(new_config)
            result['after(generated)'] = new_config
        else:
            new_config = self.get_ip_neighbor_interfaces_facts()
            if result['changed']:
                result['after'] = new_config

        if self._module._diff:
            self.sort_lists_in_config(old_config)
            if not self._module.check_mode:
                self.sort_lists_in_config(new_config)
            result['diff'] = get_formatted_config_diff(old_config, new_config, self._module._verbosity)

        result['commands'] = commands
        return result

    def set_config(self, existing_ip_neighbor_interfaces_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self.validate_and_normalize_want(self._module.params['config'])
        have = existing_ip_neighbor_interfaces_facts
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
        if state in ('replaced', 'overridden'):
            commands, requests = self._state_replaced_overridden(want, have, state)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)
        return commands, requests

    def _state_replaced_overridden(self, want, have, state):
        """ The command generator when state is replaced or overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, del_commands = [], []
        requests, del_requests = [], []

        if have:
            for have_conf in have:
                intf_name = have_conf['name']
                conf = search_obj_in_list(intf_name, want, 'name')
                # Delete all interface IP neighbor config if not specified in 'overridden',
                # or if only interface name is specified
                if not conf:
                    if state == 'overridden':
                        del_commands.append({'name': intf_name})
                        del_requests.extend(self.get_delete_ip_neighbor_interfaces_requests(have_conf, have_conf, True))
                elif len(conf.keys()) == 1:
                    del_commands.append({'name': intf_name})
                    del_requests.extend(self.get_delete_ip_neighbor_interfaces_requests(have_conf, have_conf, True))
                else:
                    del_command = {}
                    for option in ('ipv4_neighbors', 'ipv6_neighbors'):
                        if option not in have_conf:
                            continue

                        if option not in conf:
                            del_command[option] = [{'ip': neighbor['ip']} for neighbor in have_conf[option]]
                        else:
                            del_opt_command = []
                            for have_neighbor in have_conf[option]:
                                neighbor = search_obj_in_list(have_neighbor['ip'], conf[option], 'ip')
                                if not neighbor:
                                    del_opt_command.append({'ip': have_neighbor['ip']})

                            if del_opt_command:
                                del_command[option] = del_opt_command

                    if del_command:
                        del_command['name'] = intf_name
                        del_commands.append(del_command)
                        del_requests.extend(self.get_delete_ip_neighbor_interfaces_requests(del_command, have_conf))

        if del_commands:
            commands = update_states(del_commands, 'deleted')
            new_have = self.get_new_config(commands, have)
            requests = del_requests
        else:
            new_have = have

        add_commands = get_diff(want, new_have, TEST_KEYS)
        if add_commands:
            commands.extend(update_states(add_commands, state))
            requests.extend(self.get_modify_ip_neighbor_interfaces_requests(add_commands))

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = get_diff(want, have, TEST_KEYS)
        requests = self.get_modify_ip_neighbor_interfaces_requests(commands)
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
        commands, requests = [], []
        if not have:
            return commands, requests
        elif not want:
            for have_conf in have:
                commands.append({'name': have_conf['name']})
                requests.extend(self.get_delete_ip_neighbor_interfaces_requests(have_conf, have_conf, True))
        else:
            for conf in want:
                intf_name = conf['name']
                have_conf = search_obj_in_list(intf_name, have, 'name')
                if not have_conf:
                    continue

                # Delete all neighbor config if only interface name is specified
                if len(conf.keys()) == 1:
                    commands.append(conf)
                    requests.extend(self.get_delete_ip_neighbor_interfaces_requests(conf, have_conf, True))
                    continue

                command = {}
                for option in ('ipv4_neighbors', 'ipv6_neighbors'):
                    if conf.get(option) and have_conf.get(option):
                        conf_neighbors = {neighbor['ip'] for neighbor in conf[option]}
                        have_neighbors = {neighbor['ip'] for neighbor in have_conf[option]}
                        del_neighbors = conf_neighbors.intersection(have_neighbors)
                        if del_neighbors:
                            command[option] = [{'ip': neighbor} for neighbor in del_neighbors]

                if command:
                    command['name'] = conf['name']
                    commands.append(command)
                    requests.extend(self.get_delete_ip_neighbor_interfaces_requests(command, have_conf))

        if commands:
            commands = update_states(commands, 'deleted')
        return commands, requests

    def get_delete_ip_neighbor_interfaces_requests(self, command, have_conf, delete_all=False):
        requests = []
        if delete_all or len(command.keys()) == 1:
            for option in ('ipv4_neighbors', 'ipv6_neighbors'):
                if have_conf.get(option):
                    requests.append({'path': self.get_neighbors_path(command['name'], option), 'method': DELETE})
        else:
            for option in ('ipv4_neighbors', 'ipv6_neighbors'):
                if option not in command:
                    continue

                url = self.get_neighbors_path(command['name'], option)
                for neighbor in command[option]:
                    requests.append({'path': url + '/neighbor=' + neighbor['ip'], 'method': DELETE})

        return requests

    def get_modify_ip_neighbor_interfaces_requests(self, commands):
        requests = []

        for command in commands:
            name = command['name']
            for option in ('ipv4_neighbors', 'ipv6_neighbors'):
                if option not in command:
                    continue

                url = self.get_neighbors_path(command['name'], option)
                for neighbor in command[option]:
                    payload = {
                        'openconfig-if-ip:neighbors': {
                            'neighbor': [{
                                'ip': neighbor['ip'],
                                'config': {'ip': neighbor['ip'], 'link-layer-address': neighbor['mac']}
                            }]
                        }
                    }
                    requests.append({'path': url, 'method': PATCH, 'data': payload})

        return requests

    def get_neighbors_path(self, intf_name, neighbor_type):
        ip_version = '4' if neighbor_type == 'ipv4_neighbors' else '6'
        if intf_name.startswith('Vlan'):
            return self.vlan_neighbors_path.format(vlan_name=intf_name, ip_version=ip_version)
        else:
            sub_intf = 0
            if '.' in intf_name:
                intf_name, sub_intf = intf_name.split('.')
            return self.non_vlan_neighbors_path.format(intf_name=intf_name, sub_intf=sub_intf, ip_version=ip_version)

    def get_new_config(self, commands, have):
        """Returns generated configuration based on commands and
        existing configuration"""
        state = self._module.params['state']
        new_conf = get_new_config(commands, have, TEST_KEYS_generate_config)
        if state == 'merged':
            return new_conf

        generated_conf = []
        for conf in new_conf:
            # Remove empty lists
            for option in ('ipv4_neighbors', 'ipv6_neighbors'):
                if option in conf and not conf[option]:
                    del conf[option]

            if len(conf.keys()) > 1:
                generated_conf.append(conf)

        return generated_conf

    def validate_and_normalize_want(self, want):
        state = self._module.params['state']
        if not want:
            if state != 'deleted':
                self._module.fail_json(msg='value of config parameter must not be empty for state {0}'.format(state))
            return []
        else:
            updated_want = remove_empties_from_list(want)
            normalize_interface_name(updated_want, self._module)
            if state != 'deleted':
                spec = {'mac': {'required': True}}
                for conf in updated_want:
                    for option in ('ipv4_neighbors', 'ipv6_neighbors'):
                        if option not in conf:
                            continue

                        for neighbor in conf[option]:
                            try:
                                check_required_arguments(spec, neighbor, ['config', option])
                            except TypeError as exc:
                                self._module.fail_json(msg=str(exc))

            return updated_want

    @staticmethod
    def sort_lists_in_config(config):
        if config:
            config.sort(key=lambda x: x['name'])
            for cfg in config:
                if cfg.get('ipv4_neighbors'):
                    cfg['ipv4_neighbors'].sort(key=lambda x: x['ip'])
                if cfg.get('ipv6_neighbors'):
                    cfg['ipv6_neighbors'].sort(key=lambda x: x['ip'])
