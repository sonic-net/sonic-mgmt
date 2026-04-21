#
# -*- coding: utf-8 -*-
# Copyright 2022 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_lldp_global class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    update_states
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


PATCH = 'patch'
DELETE = 'delete'


def __derive_lldp_global_config_delete_op(key_set, command, exist_conf):
    new_conf = exist_conf

    if 'enable' in command and command['enable'] is not None:
        new_conf['enable'] = True

    tlv_select = command.get('tlv_select', None)
    if tlv_select:
        if 'management_address' in tlv_select and tlv_select['management_address'] is not None:
            new_conf['tlv_select']['management_address'] = True
        if 'system_capabilities' in tlv_select and tlv_select['system_capabilities'] is not None:
            new_conf['tlv_select']['system_capabilities'] = True

    if command.get('hello_time', None):
        new_conf.pop('hello_time', None)

    if command.get('mode', None):
        new_conf.pop('mode', None)

    if command.get('multiplier', None):
        new_conf.pop('multiplier', None)

    if command.get('system_description', None):
        new_conf.pop('system_description', None)

    if command.get('system_name', None):
        new_conf.pop('system_name', None)

    return True, new_conf


TEST_KEYS_generate_config = [
    {'config': {'__delete_op': __derive_lldp_global_config_delete_op}},
]


class Lldp_global(ConfigBase):
    """
    The sonic_lldp_global class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'lldp_global',
    ]

    lldp_global_path = 'data/openconfig-lldp:lldp/config'
    lldp_global_config_path = {
        'enable': lldp_global_path + '/enabled',
        'hello_time': lldp_global_path + '/hello-timer',
        'mode': lldp_global_path + '/openconfig-lldp-ext:mode',
        'multiplier': lldp_global_path + '/openconfig-lldp-ext:multiplier',
        'system_description': lldp_global_path + '/system-description',
        'system_name': lldp_global_path + '/system-name',
        'tlv_select': lldp_global_path + '/suppress-tlv-advertisement',
    }
    lldp_suppress_tlv = '/data/openconfig-lldp:lldp/config/suppress-tlv-advertisement={lldp_suppress_tlv}'

    def __init__(self, module):
        super(Lldp_global, self).__init__(module)

    def get_lldp_global_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        lldp_global_facts = facts['ansible_network_resources'].get('lldp_global')
        if not lldp_global_facts:
            return []
        return lldp_global_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = []

        existing_lldp_global_facts = self.get_lldp_global_facts()
        commands, requests = self.set_config(existing_lldp_global_facts)
        if commands:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True

        changed_lldp_global_facts = self.get_lldp_global_facts()

        result['before'] = existing_lldp_global_facts
        if result['changed']:
            result['after'] = changed_lldp_global_facts

        result['commands'] = commands

        new_config = changed_lldp_global_facts
        old_config = existing_lldp_global_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_lldp_global_facts,
                                        TEST_KEYS_generate_config)
            result['after(generated)'] = new_config

        if self._module._diff:
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)
        result['warnings'] = warnings
        return result

    def set_config(self, existing_lldp_global_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_lldp_global_facts
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
        diff = get_diff(want, have)
        if state == 'deleted':
            commands, requests = self._state_deleted(want, have, diff)
        elif state == 'merged':
            commands, requests = self._state_merged(diff)
        return commands, requests

    def _state_merged(self, diff):
        """ The command generator when state is merged
        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        requests = []
        requests.extend(self.get_modify_specific_lldp_global_param_requests(commands))
        if commands and len(requests) > 0:
            commands = update_states(commands, 'merged')
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have, diff):
        """ The command generator when state is deleted
        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        commands = []
        requests = []

        if not want:
            commands = have
            requests.extend(self.get_delete_lldp_global_completely_requests(commands))
        else:
            commands = get_diff(want, diff)
            requests.extend(self.get_delete_specific_lldp_global_param_requests(commands, have))

        if len(requests) == 0:
            commands = []

        if commands:
            commands = update_states(commands, "deleted")

        return commands, requests

    def get_modify_specific_lldp_global_param_requests(self, command):
        """Get requests to modify specific LLDP Global configurations
        based on the command specified for the interface
        """
        requests = []

        if not command:
            return requests
        if 'enable' in command and command['enable'] is not None:
            payload = {'openconfig-lldp:enabled': command['enable']}
            url = self.lldp_global_config_path['enable']
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        if 'hello_time' in command and command['hello_time'] is not None:
            payload = {'openconfig-lldp:hello-timer': str(command['hello_time'])}
            url = self.lldp_global_config_path['hello_time']
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        if 'mode' in command and command['mode'] is not None:
            payload = {'openconfig-lldp-ext:mode': command['mode'].upper()}
            url = self.lldp_global_config_path['mode']
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        if 'multiplier' in command and command['multiplier'] is not None:
            payload = {'openconfig-lldp-ext:multiplier': int(command['multiplier'])}
            url = self.lldp_global_config_path['multiplier']
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        if 'system_name' in command and command['system_name'] is not None:
            payload = {'openconfig-lldp:system-name': command['system_name']}
            url = self.lldp_global_config_path['system_name']
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        if 'system_description' in command and command['system_description'] is not None:
            payload = {'openconfig-lldp:system-description': command['system_description']}
            url = self.lldp_global_config_path['system_description']
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        if 'tlv_select' in command:
            if 'management_address' in command['tlv_select']:
                payload = {'openconfig-lldp:suppress-tlv-advertisement': ["MANAGEMENT_ADDRESS"]}
                url = self.lldp_global_config_path['tlv_select']
                if command['tlv_select']['management_address'] is False:
                    requests.append({'path': url, 'method': PATCH, 'data': payload})
                elif command['tlv_select']['management_address'] is True:
                    url = self.lldp_suppress_tlv.format(lldp_suppress_tlv="MANAGEMENT_ADDRESS")
                    requests.append({'path': url, 'method': DELETE})
            if 'system_capabilities' in command['tlv_select']:
                payload = {'openconfig-lldp:suppress-tlv-advertisement': ["SYSTEM_CAPABILITIES"]}
                url = self.lldp_global_config_path['tlv_select']
                if command['tlv_select']['system_capabilities'] is False:
                    requests.append({'path': url, 'method': PATCH, 'data': payload})
                elif command['tlv_select']['system_capabilities'] is True:
                    url = self.lldp_suppress_tlv.format(lldp_suppress_tlv="SYSTEM_CAPABILITIES")
                    requests.append({'path': url, 'method': DELETE})
        return requests

    def get_delete_lldp_global_completely_requests(self, have):
        """Get requests to delete all existing LLDP global
        configurations in the chassis
        """
        default_config_dict = {"enable": True, "tlv_select": {"management_address": True, "system_capabilities": True}}
        requests = []
        if default_config_dict != have:
            return [{'path': self.lldp_global_path, 'method': DELETE}]
        return requests

    def get_delete_specific_lldp_global_param_requests(self, command, config):
        """Get requests to delete specific LLDP global configurations
        based on the command specified for the interface
        """
        requests = []

        if not command:
            return requests
        if 'hello_time' in command:
            url = self.lldp_global_config_path['hello_time']
            requests.append({'path': url, 'method': DELETE})

        if 'enable' in command:
            url = self.lldp_global_config_path['enable']
            payload = {}
            if command['enable'] is False:
                payload = {'openconfig-lldp:enabled': True}
            elif command['enable'] is True:
                payload = {'openconfig-lldp:enabled': False}
            if payload:
                requests.append({'path': url, 'method': PATCH, 'data': payload})
        if 'mode' in command:
            url = self.lldp_global_config_path['mode']
            requests.append({'path': url, 'method': DELETE})

        if 'multiplier' in command:
            url = self.lldp_global_config_path['multiplier']
            requests.append({'path': url, 'method': DELETE})

        if 'system_name' in command:
            url = self.lldp_global_config_path['system_name']
            requests.append({'path': url, 'method': DELETE})

        if 'system_description' in command:
            url = self.lldp_global_config_path['system_description']
            requests.append({'path': url, 'method': DELETE})
        # The tlv_select configs are enabled by default.Hence false leads deletion of configs.
        if 'tlv_select' in command:
            if 'management_address' in command['tlv_select']:
                payload = {'openconfig-lldp:suppress-tlv-advertisement': ["MANAGEMENT_ADDRESS"]}
                url = self.lldp_global_config_path['tlv_select']
                if command['tlv_select']['management_address'] is True:
                    requests.append({'path': url, 'method': PATCH, 'data': payload})
                elif command['tlv_select']['management_address'] is False:
                    url = self.lldp_suppress_tlv.format(lldp_suppress_tlv="MANAGEMENT_ADDRESS")
                    requests.append({'path': url, 'method': DELETE})
            if 'system_capabilities' in command['tlv_select']:
                payload = {'openconfig-lldp:suppress-tlv-advertisement': ["SYSTEM_CAPABILITIES"]}
                url = self.lldp_global_config_path['tlv_select']
                if command['tlv_select']['system_capabilities'] is True:
                    requests.append({'path': url, 'method': PATCH, 'data': payload})
                elif command['tlv_select']['system_capabilities'] is False:
                    url = self.lldp_suppress_tlv.format(lldp_suppress_tlv="SYSTEM_CAPABILITIES")
                    requests.append({'path': url, 'method': DELETE})
        return requests
