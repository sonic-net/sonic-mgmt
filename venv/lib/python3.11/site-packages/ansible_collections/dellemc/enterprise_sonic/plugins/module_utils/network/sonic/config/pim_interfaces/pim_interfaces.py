#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_pim_interfaces class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    update_states,
    normalize_interface_name,
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.bgp_utils import (
    get_all_vrfs
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    get_formatted_config_diff,
    get_new_config
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'patch'
DELETE = 'delete'
TEST_KEYS_GENERATE_CONFIG = [{'config': {'name': ''}}]


class Pim_interfaces(ConfigBase):
    """
    The sonic_pim_interfaces class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'pim_interfaces',
    ]

    network_instance_path = 'data/openconfig-network-instance:network-instances/network-instance={vrf}'
    pim_interfaces_path = network_instance_path + '/protocols/protocol=PIM,pim/pim/interfaces'
    pim_interface_path = pim_interfaces_path + '/interface={intf}'
    pim_interface_config_path = {
        'bfd_enable': pim_interface_path + '/enable-bfd/config/enabled',
        'bfd_profile': pim_interface_path + '/enable-bfd/config/bfd-profile',
        'drpriority': pim_interface_path + '/config/dr-priority',
        'hello_interval': pim_interface_path + '/config/hello-interval',
        'sparse_mode': pim_interface_path + '/config/mode'
    }
    pim_interface_options = ('bfd_enable', 'bfd_profile', 'drpriority', 'hello_interval', 'sparse_mode')

    def __init__(self, module):
        super(Pim_interfaces, self).__init__(module)
        self.interface_vrf_map = None

    def get_pim_interfaces_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        pim_interfaces_facts = facts['ansible_network_resources'].get('pim_interfaces')
        if not pim_interfaces_facts:
            return []
        return pim_interfaces_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        commands = list()

        existing_pim_interfaces_facts = self.get_pim_interfaces_facts()
        commands, requests = self.set_config(existing_pim_interfaces_facts)
        if commands:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True

        result['before'] = existing_pim_interfaces_facts
        old_config = existing_pim_interfaces_facts

        if self._module.check_mode:
            new_config = self.get_generated_config(commands, existing_pim_interfaces_facts)
            result['after(generated)'] = new_config
        else:
            changed_pim_interfaces_facts = self.get_pim_interfaces_facts()
            new_config = changed_pim_interfaces_facts
            if result['changed']:
                result['after'] = changed_pim_interfaces_facts

        if self._module._diff:
            if old_config:
                old_config.sort(key=lambda x: x['name'])
            if new_config:
                new_config.sort(key=lambda x: x['name'])
            result['diff'] = get_formatted_config_diff(old_config, new_config, self._module._verbosity)

        result['commands'] = commands
        result['warnings'] = warnings
        return result

    def set_config(self, existing_pim_interfaces_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        state = self._module.params['state']
        want = self._module.params['config']
        have = existing_pim_interfaces_facts
        if want:
            want = remove_empties_from_list(want)
            normalize_interface_name(want, self._module)

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
        if state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)
        elif state in ('replaced', 'overridden'):
            commands, requests = self._state_replaced_overridden(want, have)
        return commands, requests

    def _state_replaced_overridden(self, want, have):
        """ The command generator when state is replaced or overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, del_commands = [], []
        requests, del_requests = [], []
        state = self._module.params['state']

        if have:
            for have_conf in have:
                intf_name = have_conf['name']
                conf = next((cfg for cfg in want if cfg['name'] == intf_name), None)
                # Delete all PIM configurations for an interface, if
                # 1) Only the interface name is specified.
                # 2) State is overridden and interface name is not specified.
                if (state == 'overridden' and not conf) or (conf and len(conf.keys()) == 1):
                    del_commands.append(have_conf)
                    del_requests.append(self.get_delete_pim_interface_request(intf_name))
                elif conf:
                    del_command = {}
                    for option in self.pim_interface_options:
                        if have_conf.get(option) and option not in conf:
                            del_command[option] = have_conf[option]

                    if del_command:
                        del_command['name'] = intf_name
                        del_commands.append(del_command)
                        del_requests.extend(self.get_delete_requests(have_conf, del_command))

        if del_commands:
            new_have = self.get_diff(have, del_commands)
            commands = update_states(del_commands, 'deleted')
            requests = del_requests
        else:
            new_have = have

        add_commands = self.get_diff(want, new_have, True)
        if add_commands:
            commands.extend(update_states(add_commands, state))
            requests.extend(self.get_modify_pim_interface_requests(add_commands))

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        requests = []
        commands = self.get_diff(want, have, True)
        if commands:
            commands = update_states(commands, 'merged')
            requests = self.get_modify_pim_interface_requests(commands)

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        commands = []
        requests = []
        if not have:
            return commands, requests
        elif not want:
            commands = have
            requests.extend(self.get_delete_pim_interface_completely_requests(commands))
        else:
            for conf in want:
                intf_name = conf['name']
                have_conf = next((cfg for cfg in have if cfg['name'] == intf_name), None)
                if not have_conf:
                    continue

                # Delete all PIM configurations for an interface,
                # if only the interface name is specified.
                if len(conf.keys()) == 1:
                    commands.append(have_conf)
                    requests.append(self.get_delete_pim_interface_request(intf_name))
                else:
                    command = {}
                    for option in self.pim_interface_options:
                        if conf.get(option) and conf[option] == have_conf.get(option):
                            command[option] = conf[option]

                    if command:
                        command['name'] = intf_name
                        commands.append(command)
                        requests.extend(self.get_delete_requests(have_conf, command))

        if commands:
            commands = update_states(commands, "deleted")

        return commands, requests

    def get_modify_pim_interface_requests(self, commands):
        """Get requests to modify PIM configurations
        for all interfaces specified by the commands
        """
        requests = []
        for command in commands:
            intf = command['name']
            vrf = self._get_interface_vrf(intf)
            config_dict = {}
            bfd_config_dict = {}

            if 'drpriority' in command:
                config_dict['dr-priority'] = command['drpriority']
            if 'hello_interval' in command:
                config_dict['hello-interval'] = command['hello_interval']
            if 'sparse_mode' in command:
                if command['sparse_mode']:
                    config_dict['mode'] = 'PIM_MODE_SPARSE'
                else:
                    requests.append({'path': self.pim_interface_config_path['sparse_mode'].format(vrf=vrf, intf=intf), 'method': DELETE})

            if 'bfd_enable' in command:
                if command['bfd_enable']:
                    bfd_config_dict['enabled'] = command['bfd_enable']
                else:
                    requests.append({'path': self.pim_interface_config_path['bfd_enable'].format(vrf=vrf, intf=intf), 'method': DELETE})
            if 'bfd_profile' in command:
                bfd_config_dict['bfd-profile'] = command['bfd_profile']

            if config_dict or bfd_config_dict:
                url = self.pim_interfaces_path.format(vrf=vrf, intf=intf)
                payload = {
                    'openconfig-network-instance:interfaces': {
                        'interface': [{
                            'interface-id': intf,
                            'config': {'interface-id': intf}
                        }]
                    }
                }
                if config_dict:
                    payload['openconfig-network-instance:interfaces']['interface'][0]['config'].update(config_dict)
                if bfd_config_dict:
                    payload['openconfig-network-instance:interfaces']['interface'][0]['enable-bfd'] = {'config': bfd_config_dict}
                requests.append({'path': url, 'method': PATCH, 'data': payload})

        return requests

    def get_delete_specific_pim_interface_param_requests(self, command):
        """Get requests to delete specific interface PIM configurations"""
        requests = []
        vrf = self._get_interface_vrf(command['name'])
        for option in self.pim_interface_options:
            if option in command:
                requests.append({'path': self.pim_interface_config_path[option].format(vrf=vrf, intf=command['name']), 'method': DELETE})

        return requests

    def get_delete_pim_interface_request(self, intf_name):
        """Get request to delete all PIM configurations
        in the specified interface"""
        vrf = self._get_interface_vrf(intf_name)
        return {'path': self.pim_interface_path.format(vrf=vrf, intf=intf_name), 'method': DELETE}

    def get_delete_requests(self, have_conf, del_command):
        """Get requests to delete interface PIM configurations"""
        requests = []
        have_conf = have_conf.copy()
        # Remove default values
        for option in ('sparse_mode', 'bfd_enable'):
            if have_conf.get(option) is False:
                del have_conf[option]

        if have_conf == del_command:
            requests.append(self.get_delete_pim_interface_request(del_command['name']))
        else:
            requests.extend(self.get_delete_specific_pim_interface_param_requests(del_command))

        return requests

    def get_delete_pim_interface_completely_requests(self, commands):
        """Get requests to delete all interface PIM configurations"""
        requests = []
        vrfs = set()
        for command in commands:
            vrfs.add(self._get_interface_vrf(command['name']))

        for vrf in vrfs:
            requests.append({'path': self.pim_interfaces_path.format(vrf=vrf), 'method': DELETE})

        return requests

    @staticmethod
    def get_diff(base_cfg, compare_cfg, remove_defaults=False):
        diff = get_diff(base_cfg, compare_cfg)
        if remove_defaults:
            for cmd in diff:
                conf = next((cfg for cfg in compare_cfg if cfg['name'] == cmd['name']), {})
                # Remove default values
                for option in ('sparse_mode', 'bfd_enable'):
                    if cmd.get(option) is False and option not in conf:
                        del cmd[option]

        # Include only commands with options other than interface name
        diff = [cmd for cmd in diff if len(cmd.keys()) > 1]
        return diff

    def _get_interface_vrf(self, intf_name):
        """Get the mapping of VRF interfaces"""
        if self.interface_vrf_map is None:
            vrf_interfaces_path = self.network_instance_path + '/interfaces'
            method = 'GET'
            self.interface_vrf_map = {}

            vrf_list = get_all_vrfs(self._module)
            for vrf in vrf_list:
                request = {"path": vrf_interfaces_path.format(vrf=vrf), "method": method}
                try:
                    response = edit_config(self._module, to_request(self._module, request))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)

                response = response[0][1].get('openconfig-network-instance:interfaces')
                if response and response.get('interface'):
                    for interface in response['interface']:
                        self.interface_vrf_map[interface['id']] = vrf

        return self.interface_vrf_map.get(intf_name, 'default')

    @staticmethod
    def get_generated_config(commands, have):
        """Get generated config"""
        generated_config = []
        new_config = remove_empties_from_list(get_new_config(commands, have, TEST_KEYS_GENERATE_CONFIG))
        if new_config:
            for conf in new_config:
                default_entries = {'name': conf['name']}
                for option in ('sparse_mode', 'bfd_enable'):
                    if option in conf:
                        default_entries[option] = False

                if len(conf.keys()) > 1 and conf != default_entries:
                    generated_config.append(conf)

        return generated_config
