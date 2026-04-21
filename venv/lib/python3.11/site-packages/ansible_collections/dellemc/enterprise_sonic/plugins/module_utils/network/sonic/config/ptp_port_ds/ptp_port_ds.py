#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_ptp_port_ds class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from time import sleep

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.interfaces_util import (
    retrieve_port_num
)

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    update_states,
    remove_empties_from_list,
    normalize_interface_name
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    get_new_config,
    get_formatted_config_diff
)
from ansible.module_utils.connection import ConnectionError

TEST_KEYS = [
    {'config': {'interface': ''}}
]

TEST_KEYS_GENERATE_CONFIG = [{'config': {'interface': ''}}]

interface_port_num_map = {}

PATCH = 'patch'
PUT = 'put'
POST = 'post'
DELETE = 'delete'


class Ptp_port_ds(ConfigBase):
    """
    The sonic_ptp_port_ds class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'ptp_port_ds',
    ]

    ptp_instance_path = 'data/ietf-ptp:ptp/instance-list=0'
    ptp_port_path = ptp_instance_path + '/port-ds-list={number}'
    ptp_port_path_del_all = ptp_instance_path + '/port-ds-list'

    ptp_port_config_path = {
        'interface': ptp_port_path + '/underlying-interface',
        'role': ptp_port_path + '/ietf-ptp-ext:role',
        'local_priority': ptp_port_path + '/ietf-ptp-ext:local-priority',
        'unicast_table': ptp_port_path + '/ietf-ptp-ext:unicast-table',
    }

    ptp_port_unicast_table_del_path = ptp_port_path + '/ietf-ptp-ext:unicast-table={value}'

    ptp_port_options = ('role', 'local_priority', 'unicast_table')

    def __init__(self, module):
        super(Ptp_port_ds, self).__init__(module)

    def get_ptp_port_ds_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        ptp_port_ds_facts = facts['ansible_network_resources'].get('ptp_port_ds')
        if not ptp_port_ds_facts:
            return []
        return ptp_port_ds_facts

    @staticmethod
    def get_generated_config(commands, have):
        """Get generated config"""
        generated_config = []
        new_config = remove_empties_from_list(get_new_config(commands, have, TEST_KEYS_GENERATE_CONFIG))
        if new_config:
            for conf in new_config:
                if 'unicast_table' in conf and not conf['unicast_table']:
                    conf.pop('unicast_table', None)

                if len(conf.keys()) > 1:
                    generated_config.append(conf)

        return generated_config

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        commands = list()
        existing_ptp_port_ds_facts = self.get_ptp_port_ds_facts()
        commands, requests = self.set_config(existing_ptp_port_ds_facts)
        if commands:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                    sleep(1)
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True

        result['before'] = existing_ptp_port_ds_facts
        old_config = existing_ptp_port_ds_facts

        if self._module.check_mode:
            new_config = self.get_generated_config(commands, existing_ptp_port_ds_facts)
            result['after(generated)'] = new_config
        else:
            new_config = self.get_ptp_port_ds_facts()
            new_config = remove_empties_from_list(new_config)
            if result['changed']:
                result['after'] = new_config

        if self._module._diff:
            if old_config:
                old_config.sort(key=lambda x: x['interface'])
            if new_config:
                new_config.sort(key=lambda x: x['interface'])
            result['diff'] = get_formatted_config_diff(old_config, new_config, self._module._verbosity)

        result['commands'] = commands
        result['warnings'] = warnings
        return result

    def set_config(self, existing_ptp_port_ds_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)
        :#rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_ptp_port_ds_facts
        if want:
            want = remove_empties_from_list(want)
            normalize_interface_name(want, self._module, 'interface')

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
            diff = get_diff(want, have, TEST_KEYS)
            commands, requests = self._state_merged(diff)
        elif state == 'overridden' or state == 'replaced':
            commands, requests = self._state_replaced_or_overridden(want, have)

        return commands, requests

    def _state_replaced_or_overridden(self, want, have):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, del_commands = [], []
        requests, del_requests = [], []
        state = self._module.params['state']
        if have:
            for have_conf in have:
                intf_name = have_conf['interface']
                port_num = self.get_port_num_from_intf_name(intf_name)
                conf = next((cfg for cfg in want if cfg['interface'] == intf_name), None)
                # Delete all PTP port configurations , if
                # 1) Only the port is specified.
                # 2) State is overridden and port is not in want
                if (state == 'overridden' and not conf) or (conf and len(conf.keys()) == 1):
                    del_commands.append(have_conf)
                    del_requests.append(self.get_delete_ptp_port_request(port_num))
                elif conf:
                    del_command = {}
                    for option in self.ptp_port_options:
                        if have_conf.get(option):
                            if option == 'unicast_table':
                                res = [item for item in have_conf[option] if item not in conf.get(option, [])]
                                if res:
                                    del_command[option] = res
                            else:
                                if option not in conf:
                                    del_command[option] = have_conf[option]
                    if del_command:
                        del_command['interface'] = intf_name
                        del_commands.append(del_command)
                        del_requests.extend(self.get_delete_specific_ptp_port_param_requests(del_command, port_num))

        if del_commands:
            new_have = get_diff(have, del_commands, TEST_KEYS)
            commands = update_states(del_commands, 'deleted')
            requests = del_requests
        else:
            new_have = have

        add_commands = get_diff(want, new_have, TEST_KEYS)
        if add_commands:
            commands.extend(update_states(add_commands, state))
            requests.extend(self.get_modify_ptp_port_ds_param_requests(add_commands))

        return commands, requests

    def _state_merged(self, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """

        commands = diff
        requests = self.get_modify_ptp_port_ds_param_requests(commands)
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
        commands = []
        requests = []
        if not have:
            return commands, requests
        elif not want:
            commands = have
            requests.append(self.get_delete_all_ptp_port_request())
        else:
            for conf in want:
                intf_name = conf['interface']
                port_num_int = self.get_port_num_from_intf_name(intf_name)
                have_conf = next((cfg for cfg in have if cfg['interface'] == intf_name), None)
                if not have_conf:
                    continue

                # Delete all PTP configurations for a port,
                # if only the port number is specified.
                if len(conf.keys()) == 1:
                    commands.append(have_conf)
                    requests.append(self.get_delete_ptp_port_request(port_num_int))
                else:
                    command = {}
                    for option in self.ptp_port_options:
                        if conf.get(option):
                            if option == 'unicast_table':
                                res = list(set(conf[option]).intersection(have_conf.get(option, [])))
                                if res:
                                    command[option] = res
                            else:
                                if conf.get(option) and conf[option] == have_conf.get(option):
                                    command[option] = conf[option]

                    if command:
                        command['interface'] = intf_name
                        commands.append(command)
                        requests.extend(self.get_delete_requests(have_conf, command, port_num_int))

        if commands:
            commands = update_states(commands, "deleted")

        return commands, requests

    def get_modify_ptp_port_ds_param_requests(self, commands):
        """Get requests to modify PIM configurations
        for all interfaces specified by the commands
        """

        requests = []
        for command in commands:
            interface_name = command['interface']

            port_num = self.get_port_num_from_intf_name(interface_name)
            url = self.ptp_port_path.format(number=port_num)
            payload = {"ietf-ptp:port-ds-list": [{"port-number": port_num, "underlying-interface": command['interface']}]}
            requests.append({'path': url, 'method': PUT, 'data': payload})

            if 'role' in command and command['role'] is not None:
                payload = {'ietf-ptp-ext:role': command['role'].upper()}
                url = self.ptp_port_config_path['role'].format(number=port_num)
                requests.append({'path': url, 'method': PATCH, 'data': payload})

            if 'local_priority' in command and command['local_priority'] is not None:
                payload = {'ietf-ptp-ext:local-priority': command['local_priority']}
                url = self.ptp_port_config_path['local_priority'].format(number=port_num)
                requests.append({'path': url, 'method': PATCH, 'data': payload})

            if 'unicast_table' in command and command['unicast_table'] is not None:
                url = self.ptp_port_config_path['unicast_table'].format(number=port_num)
                payload = {'ietf-ptp-ext:unicast-table': [",".join(command['unicast_table'])]}
                requests.append({'path': url, 'method': PATCH, 'data': payload})

        return requests

    def get_delete_specific_ptp_port_param_requests(self, command, port_num):
        """Get requests to delete specific PTP Port configurations"""
        requests = []

        for option in self.ptp_port_options:
            if option == 'unicast_table':
                requests.append({'path': self.ptp_port_unicast_table_del_path.format(number=port_num, value="%2c".join(command[option])),
                                 'method': DELETE})
            elif option in command:
                requests.append({'path': self.ptp_port_config_path[option].format(number=port_num), 'method': DELETE})
        return requests

    def get_delete_requests(self, have_conf, del_command, port_num_int):
        """Get requests to delete PTP port configurations"""
        requests = []

        if have_conf == del_command:
            requests.append(self.get_delete_ptp_port_request(port_num_int))
        else:
            requests.extend(self.get_delete_specific_ptp_port_param_requests(del_command, port_num_int))

        return requests

    def get_delete_ptp_port_request(self, port_num):
        """Get request to delete all PTP configurations
        in the specified port"""
        return {'path': self.ptp_port_path.format(number=port_num), 'method': DELETE}

    def get_delete_all_ptp_port_request(self):
        """Get request to delete all PTP configurations
        in the specified port"""
        return {'path': self.ptp_port_path_del_all, 'method': DELETE}

    def get_port_num_from_intf_name(self, intf_name):
        if interface_port_num_map.get(intf_name) is None:
            interface_port_num_map[intf_name] = retrieve_port_num(self._module, intf_name)

        return interface_port_num_map[intf_name]
