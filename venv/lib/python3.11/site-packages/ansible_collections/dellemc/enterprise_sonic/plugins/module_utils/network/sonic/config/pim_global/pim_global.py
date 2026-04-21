#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_pim_global class
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
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    get_formatted_config_diff,
    get_new_config
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'patch'
DELETE = 'delete'
TEST_KEYS = [{'config': {'vrf_name': ''}}]
TEST_KEYS_GENERATE_CONFIG = [{'config': {'vrf_name': ''}}]


class Pim_global(ConfigBase):
    """
    The sonic_pim_global class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'pim_global',
    ]

    pim_global_path = (
        'data/openconfig-network-instance:network-instances/network-instance={vrf}'
        '/protocols/protocol=PIM,pim/pim/global'
    )
    pim_global_config_path = {
        'ecmp_enable': pim_global_path + '/config/ecmp-enabled',
        'ecmp_rebalance_enable': pim_global_path + '/config/ecmp-rebalance-enabled',
        'join_prune_interval': pim_global_path + '/config/join-prune-interval',
        'keepalive_timer': pim_global_path + '/config/keep-alive-timer',
        'ssm_prefix_list': pim_global_path + '/ssm/config/ssm-ranges'
    }
    # ECMP rebalance is placed before ECMP enable to
    # ensure the deletion is performed in the same order
    pim_global_options = ('ecmp_rebalance_enable', 'ecmp_enable', 'join_prune_interval', 'keepalive_timer', 'ssm_prefix_list')

    def __init__(self, module):
        super(Pim_global, self).__init__(module)

    def get_pim_global_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        pim_global_facts = facts['ansible_network_resources'].get('pim_global')
        if not pim_global_facts:
            return []
        return pim_global_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        commands = list()

        existing_pim_global_facts = self.get_pim_global_facts()
        commands, requests = self.set_config(existing_pim_global_facts)
        if commands:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True

        result['before'] = existing_pim_global_facts
        old_config = existing_pim_global_facts

        if self._module.check_mode:
            new_config = self.get_generated_config(commands, existing_pim_global_facts)
            result['after(generated)'] = new_config
        else:
            changed_pim_global_facts = self.get_pim_global_facts()
            new_config = changed_pim_global_facts
            if result['changed']:
                result['after'] = changed_pim_global_facts

        if self._module._diff:
            if old_config:
                old_config.sort(key=lambda x: x['vrf_name'])
            if new_config:
                new_config.sort(key=lambda x: x['vrf_name'])
            result['diff'] = get_formatted_config_diff(old_config, new_config, self._module._verbosity)

        result['commands'] = commands
        result['warnings'] = warnings
        return result

    def set_config(self, existing_pim_global_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        state = self._module.params['state']
        want = self._module.params['config']
        have = existing_pim_global_facts
        if want:
            want = remove_empties_from_list(want)
            self.validate_config(want, have)

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
                vrf_name = have_conf['vrf_name']
                conf = next((cfg for cfg in want if cfg['vrf_name'] == vrf_name), None)
                # Delete all global PIM configurations for a VRF, if
                # 1) Only the VRF name is specified.
                # 2) State is overridden and VRF name is not specified.
                if (state == 'overridden' and not conf) or (conf and len(conf.keys()) == 1):
                    del_commands.append(have_conf)
                    del_requests.append(self.get_delete_pim_global_vrf_request(vrf_name))
                elif conf:
                    del_command = {}
                    for option in self.pim_global_options:
                        if have_conf.get(option) and option not in conf:
                            del_command[option] = have_conf[option]

                    if del_command:
                        del_command['vrf_name'] = vrf_name
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
            requests.extend(self.get_modify_pim_global_requests(add_commands))

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
            requests = self.get_modify_pim_global_requests(commands)

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
            requests.extend(self.get_delete_pim_global_completely_requests(commands))
        else:
            for conf in want:
                vrf_name = conf['vrf_name']
                have_conf = next((cfg for cfg in have if cfg['vrf_name'] == vrf_name), {})
                if not have_conf:
                    continue

                # Delete all global PIM configurations for a VRF,
                # if only the VRF name is specified.
                if len(conf.keys()) == 1:
                    commands.append(have_conf)
                    requests.append(self.get_delete_pim_global_vrf_request(vrf_name))
                else:
                    command = {}
                    for option in self.pim_global_options:
                        if conf.get(option) and conf[option] == have_conf.get(option):
                            command[option] = conf[option]

                    if command:
                        command['vrf_name'] = vrf_name
                        commands.append(command)
                        requests.extend(self.get_delete_requests(have_conf, command))

        if commands:
            commands = update_states(commands, "deleted")

        return commands, requests

    def get_modify_pim_global_requests(self, commands):
        """Get requests to modify global PIM configurations
        for all VRFs specified by the commands
        """
        requests = []
        for command in commands:
            vrf = command['vrf_name']
            url = self.pim_global_path.format(vrf=vrf)
            vrf_requests = []
            config_dict = {}
            ssm_config_dict = {}

            if 'ecmp_enable' in command:
                if command['ecmp_enable']:
                    config_dict['ecmp-enabled'] = command['ecmp_enable']
                else:
                    vrf_requests.append({'path': self.pim_global_config_path['ecmp_enable'].format(vrf=vrf), 'method': DELETE})

            if 'join_prune_interval' in command:
                config_dict['join-prune-interval'] = command['join_prune_interval']
            if 'keepalive_timer' in command:
                config_dict['keep-alive-timer'] = command['keepalive_timer']
            if 'ssm_prefix_list' in command:
                ssm_config_dict['ssm-ranges'] = command['ssm_prefix_list']

            if config_dict or ssm_config_dict:
                payload = {'openconfig-network-instance:global': {}}
                if config_dict:
                    payload['openconfig-network-instance:global']['config'] = config_dict
                if ssm_config_dict:
                    payload['openconfig-network-instance:global']['ssm'] = {'config': ssm_config_dict}
                vrf_requests.append({'path': url, 'method': PATCH, 'data': payload})

            # Handle ECMP Rebalance configuration seperately
            # 1) For enabling, configure it after enabling ECMP
            # 2) For disabling, configure it before disabling ECMP
            if 'ecmp_rebalance_enable' in command:
                if command['ecmp_rebalance_enable']:
                    payload = {'openconfig-network-instance:global': {'config': {'ecmp-rebalance-enabled': command['ecmp_rebalance_enable']}}}
                    vrf_requests.append({'path': url, 'method': PATCH, 'data': payload})
                else:
                    vrf_requests.insert(0, {'path': self.pim_global_config_path['ecmp_rebalance_enable'].format(vrf=vrf), 'method': DELETE})

            requests.extend(vrf_requests)

        return requests

    def get_delete_specific_pim_global_param_requests(self, command):
        """Get requests to delete specific global PIM configurations"""
        requests = []
        for option in self.pim_global_options:
            if option in command:
                requests.append({'path': self.pim_global_config_path[option].format(vrf=command['vrf_name']), 'method': DELETE})

        return requests

    def get_delete_pim_global_vrf_request(self, vrf_name):
        """Get request to delete all global PIM configurations
        in the specified VRF
        """
        return {'path': self.pim_global_path.format(vrf=vrf_name), 'method': DELETE}

    def get_delete_requests(self, have_conf, del_command):
        """Get requests to delete global PIM configurations"""
        requests = []
        have_conf = have_conf.copy()
        # Remove default values
        for option in ('ecmp_enable', 'ecmp_rebalance_enable'):
            if have_conf.get(option) is False:
                del have_conf[option]

        if have_conf == del_command:
            requests.append(self.get_delete_pim_global_vrf_request(del_command['vrf_name']))
        else:
            requests.extend(self.get_delete_specific_pim_global_param_requests(del_command))

        return requests

    def get_delete_pim_global_completely_requests(self, commands):
        """Get requests to delete all global PIM configurations"""
        requests = []
        for command in commands:
            requests.append(self.get_delete_pim_global_vrf_request(command['vrf_name']))

        return requests

    def validate_config(self, want, have):
        """Validate the given config"""
        state = self._module.params['state']
        if state == 'deleted':
            for conf in want:
                have_conf = next((cfg for cfg in have if cfg['vrf_name'] == conf['vrf_name']), {})
                if conf.get('ecmp_enable') and not conf.get('ecmp_rebalance_enable') and have_conf.get('ecmp_rebalance_enable'):
                    self._module.fail_json(msg='ECMP cannot be disabled when ECMP Rebalance is enabled')
        else:
            for conf in want:
                have_conf = next((cfg for cfg in have if cfg['vrf_name'] == conf['vrf_name']), {})
                if conf.get('ecmp_enable') is False:
                    if (conf.get('ecmp_rebalance_enable')
                            or (state == 'merged' and conf.get('ecmp_rebalance_enable') is None and have_conf.get('ecmp_rebalance_enable'))):
                        self._module.fail_json(msg='ECMP cannot be disabled when ECMP Rebalance is enabled')

                if conf.get('ecmp_rebalance_enable'):
                    if conf.get('ecmp_enable') is False or (conf.get('ecmp_enable') is None and (state != 'merged' or not have_conf.get('ecmp_enable'))):
                        self._module.fail_json(msg='ECMP has to be enabled for configuring ECMP rebalance')

    @staticmethod
    def get_diff(base_cfg, compare_cfg, remove_defaults=False):
        diff = get_diff(base_cfg, compare_cfg, TEST_KEYS)
        if remove_defaults:
            for cmd in diff:
                conf = next((cfg for cfg in compare_cfg if cfg['vrf_name'] == cmd['vrf_name']), {})
                # Remove default values
                for option in ('ecmp_enable', 'ecmp_rebalance_enable'):
                    if cmd.get(option) is False and option not in conf:
                        del cmd[option]

        # Include only commands with options other than vrf_name
        diff = [cmd for cmd in diff if len(cmd.keys()) > 1]
        return diff

    @staticmethod
    def get_generated_config(commands, have):
        """Get generated config"""
        generated_config = []
        new_config = remove_empties_from_list(get_new_config(commands, have, TEST_KEYS_GENERATE_CONFIG))
        if new_config:
            default_entries = {'ecmp_enable': False, 'ecmp_rebalance_enable': False}
            for conf in new_config:
                # Add default values for after(generated)
                for option in ('ecmp_enable', 'ecmp_rebalance_enable'):
                    if option not in conf:
                        conf[option] = default_entries[option]

                default_entries['vrf_name'] = conf['vrf_name']
                if len(conf.keys()) > 1 and conf != default_entries:
                    generated_config.append(conf)

        return generated_config
