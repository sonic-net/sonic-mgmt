#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_dcbx class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re
from copy import deepcopy
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
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
    get_new_config,
    get_formatted_config_diff
)
from ansible.module_utils.connection import ConnectionError
import re

PATCH = 'patch'
DELETE = 'delete'

is_delete_all = False

TEST_KEYS = [
    {'interfaces': {'name': ''}}
]


def __derive_dcbx_interfaces_config_delete_op(key_set, command, exist_conf):
    new_conf = exist_conf
    if is_delete_all or len(command) == 1:
        new_conf['enabled'] = True
        new_conf['pfc_tlv_enabled'] = True
        new_conf['ets_configuration_tlv_enabled'] = True
        new_conf['ets_recommendation_tlv_enabled'] = True
        return True, new_conf

    if command.get('enabled') is not None:
        new_conf['enabled'] = True
    if command.get('pfc_tlv_enabled') is not None:
        new_conf['pfc_tlv_enabled'] = True
    if command.get('ets_configuration_tlv_enabled') is not None:
        new_conf['ets_configuration_tlv_enabled'] = True
    if command.get('ets_recommendation_tlv_enabled') is not None:
        new_conf['ets_recommendation_tlv_enabled'] = True

    return True, new_conf


TEST_KEYS_generate_config = [
    {'interfaces': {'name': '', '__delete_op': __derive_dcbx_interfaces_config_delete_op}}
]


class Dcbx(ConfigBase):
    """
    The sonic_dcbx_interfaces class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'dcbx',
    ]

    dcbx_config_path = 'data/openconfig-dcbx:dcbx/config'
    dcbx_interfaces_path = 'data/openconfig-dcbx:dcbx/interfaces'
    dcbx_path = 'data/openconfig-dcbx:dcbx'
    dcbx_intf_path = 'data/openconfig-dcbx:dcbx/interfaces/interface={intf_name}'

    dcbx_intf_config_path = {
        'enabled': dcbx_intf_path + '/config/enabled',
        'pfc-tlv-enabled': dcbx_intf_path + '/config/pfc-tlv-enabled',
        'ets-configuration-tlv-enabled': dcbx_intf_path + '/config/ets-configuration-tlv-enabled',
        'ets-recommendation-tlv-enabled': dcbx_intf_path + '/config/ets-recommendation-tlv-enabled'
    }

    def __init__(self, module):
        super(Dcbx, self).__init__(module)

    def get_dcbx_facts(self):
        """ Get the 'facts' (the current configuration)
        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(
            self.gather_subset, self.gather_network_resources)
        dcbx_facts = facts['ansible_network_resources'].get('dcbx')
        if not dcbx_facts:
            return {}
        return dcbx_facts

    def execute_module(self):
        """ Execute the module
        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = []
        commands = []

        existing_dcbx_facts = self.get_dcbx_facts()
        commands, requests = self.set_config(existing_dcbx_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(
                        self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True

        result['commands'] = commands
        result['before'] = existing_dcbx_facts

        new_config = {}
        if self._module.check_mode:
            new_config = get_new_config(commands, existing_dcbx_facts,
                                        TEST_KEYS_generate_config)

            self.sort_lists_in_config(new_config)
            result['after(generated)'] = new_config
        else:
            new_config = self.get_dcbx_facts()
            result['after'] = new_config

        if self._module._diff:
            self.sort_lists_in_config(new_config)
            self.sort_lists_in_config(existing_dcbx_facts)
            result['diff'] = get_formatted_config_diff(existing_dcbx_facts,
                                                       new_config,
                                                       self._module._verbosity)

        result['warnings'] = warnings
        return result

    def set_config(self, existing_dcbx_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_dcbx_facts
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
        diff = get_diff(want, have, TEST_KEYS)
        if state == 'deleted':
            commands, requests = self._state_deleted(want, have, diff)
        elif state == 'merged':
            commands, requests = self._state_merged(diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(diff, want, have)
        elif state == 'overridden':
            commands, requests = self._state_overridden(diff, want, have)
        return commands, requests

    def _state_merged(self, diff):
        """ The command generator when state is merged
        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        requests = self.get_modify_specific_dcbx_global_and_interfaces_param_requests(
            commands)

        if commands and len(requests) > 0:
            commands = update_states(commands, 'merged')
        else:
            commands = []

        return commands, requests

    def remove_default_entries(self, data):
        pop_list = []
        new_data = {}

        glbl = data.get('global')
        if glbl:
            enabled = glbl.get('enabled')
            if enabled is not True:
                glbl.pop('enabled')

        intfs = data.get('interfaces')
        if intfs:
            for intf in intfs:
                pop_item = False
                if 'pfc_tlv_enabled' in intf and intf.get('pfc_tlv_enabled') is True:
                    intf.pop('pfc_tlv_enabled')
                    pop_item = True
                if 'ets_configuration_tlv_enabled' in intf and intf.get('ets_configuration_tlv_enabled') is True:
                    intf.pop('ets_configuration_tlv_enabled')
                    pop_item = True
                if 'ets_recommendation_tlv_enabled' in intf and intf.get('ets_recommendation_tlv_enabled') is True:
                    intf.pop('ets_recommendation_tlv_enabled')
                    pop_item = True
                if 'enabled' in intf and intf.get('enabled') is True:
                    intf.pop('enabled')
                    pop_item = True
                if 'name' in intf and len(intf) == 1 and pop_item:
                    idx = intfs.index(intf)
                    pop_list.insert(0, idx)

            for idx in pop_list:
                intfs.pop(idx)
            if not intfs:
                data.pop('interfaces')

    def sort_lists_in_config(self, config):
        if 'interfaces' in config and config['interfaces'] is not None:
            config['interfaces'].sort(key=lambda x: x['name'])

    def _state_deleted(self, want, have, diff):
        """ The command generator when state is deleted
        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        commands = []
        requests = []

        global is_delete_all
        is_delete_all = False

        if not want:
            commands = deepcopy(have)
            is_delete_all = True
        else:
            commands = get_diff(want, diff, TEST_KEYS)
        self.remove_default_entries(commands)

        intf_commands = commands.get('interfaces')
        if intf_commands:
            commands['interfaces'] = remove_empties_from_list(intf_commands)

        requests = self.get_delete_dcbx_requests(commands, have, is_delete_all)
        if len(requests) == 0:
            commands = []

        if commands:
            commands = update_states(commands, "deleted")

        return commands, requests

    def _state_replaced(self, diff, want, have):
        """The command generator when state is replaced
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
        to the desired configuration
        """
        commands = []
        requests = []

        commands, requests = self.get_commands_requests_for_replaced_overridden(diff, want, have, 'replaced')

        return commands, requests

    def _state_overridden(self, diff, want, have):
        """The command generator when state is overridden
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
        to the desired configuration
        """
        commands = []
        requests = []
        commands, requests = self.get_commands_requests_for_replaced_overridden(diff, want, have, 'overridden')

        return commands, requests

    def get_commands_requests_for_replaced_overridden(self, diff, want, have, state):
        """Returns the commands and requests necessary to remove applicable
        current configurations when state is replaced or overridde and global_conf == defaultn
        """
        default_global_dcbx = {'enabled': False}
        default_interface_dcbx = {
            'pfc_tlv_enabled': True,
            'ets_configuration_tlv_enabled': True,
            'ets_recommendation_tlv_enabled': True,
            'enabled': True
        }
        commands = []
        requests = []
        del_commands = []
        add_commands = []

        if not have:
            commands = diff
            requests = self.get_modify_specific_dcbx_global_and_interfaces_param_requests(commands)
            if commands and len(requests) > 0:
                commands = update_states(commands, 'replaced')
            else:
                commands = []

            return commands, requests

        # Handle global configuration
        global_conf = have.get('global')
        if not global_conf:
            global_conf = {'enabled': False}

        match_global = want.get('global')

        if global_conf:
            if not match_global:
                if state == 'overridden' and global_conf != default_global_dcbx:
                    commands.extend(update_states([{'global': global_conf}], 'deleted'))
                    requests.append(self.get_delete_global_dcbx_request())
            else:
                if match_global == default_global_dcbx:
                    if global_conf != default_global_dcbx:
                        commands.extend(update_states([{'global': global_conf}], 'deleted'))
                        requests.append(self.get_delete_global_dcbx_request())
                elif global_conf != match_global:
                    commands.extend(update_states([{'global': match_global}], state))
                    requests.append(self.get_modify_global_dcbx_request({"openconfig-dcbx:enabled": True}))

        # Handle interface configurations
        del_interfaces = []
        add_interfaces = []
        # Handle interface configurations
        interfaces = have.get('interfaces', [])
        if interfaces:
            for conf in have.get('interfaces', []):
                intf_name = conf['name']
                intf_dcbx_conf = conf.get('enabled')
                intf_pfc_tlv_conf = conf.get('pfc_tlv_enabled')
                intf_ets_config_tlv_conf = conf.get('ets_configuration_tlv_enabled')
                intf_ets_reco_tlv_conf = conf.get('ets_recommendation_tlv_enabled')
                interfaces_want = want.get('interfaces', [])
                if interfaces_want:
                    match_obj = next((cmd for cmd in interfaces_want if cmd['name'] == intf_name), None)
                else:
                    match_obj = None

                if not match_obj:
                    if state == 'overridden' and (intf_dcbx_conf != default_interface_dcbx['enabled'] or
                                                  intf_pfc_tlv_conf != default_interface_dcbx['pfc_tlv_enabled'] or
                                                  intf_ets_config_tlv_conf != default_interface_dcbx['ets_configuration_tlv_enabled'] or
                                                  intf_ets_reco_tlv_conf != default_interface_dcbx['ets_recommendation_tlv_enabled']):
                        del_interfaces.append({'name': intf_name})
                        requests.append(self.get_delete_interface_dcbx_request(intf_name))
                    continue

                command = {'name': intf_name}
                delete_intf = False
                patch_intf_dcbx = False
                patch_intf_pfc = False
                patch_intf_ets_conf = False
                patch_intf_ets_reco = False

                match_intf_dcbx = match_obj.get('enabled', True)
                if match_intf_dcbx is None:
                    match_intf_dcbx = True

                match_intf_pfc_tlv = match_obj.get('pfc_tlv_enabled', True)
                if match_intf_pfc_tlv is None:
                    match_intf_pfc_tlv = True

                match_intf_ets_config_tlv = match_obj.get('ets_configuration_tlv_enabled', True)
                if match_intf_ets_config_tlv is None:
                    match_intf_ets_config_tlv = True

                match_intf_ets_reco_tlv = match_obj.get('ets_recommendation_tlv_enabled', True)
                if match_intf_ets_reco_tlv is None:
                    match_intf_ets_reco_tlv = True

                if match_intf_dcbx == intf_dcbx_conf and \
                   match_intf_pfc_tlv == intf_pfc_tlv_conf and \
                   match_intf_ets_config_tlv == intf_ets_config_tlv_conf and \
                   match_intf_ets_reco_tlv == intf_ets_reco_tlv_conf:
                    continue

                if intf_dcbx_conf is not None:
                    if match_intf_dcbx is None:
                        if intf_dcbx_conf != default_interface_dcbx['enabled']:
                            delete_intf = True

                    elif intf_dcbx_conf != match_intf_dcbx:
                        if match_intf_dcbx == default_interface_dcbx['enabled']:
                            delete_intf = True
                        else:
                            patch_intf_dcbx = True
                    elif match_intf_dcbx != default_interface_dcbx['enabled']:
                        patch_intf_dcbx = True

                if intf_pfc_tlv_conf is not None:
                    if match_intf_pfc_tlv is None:
                        if intf_pfc_tlv_conf != default_interface_dcbx['pfc_tlv_enabled']:
                            delete_intf = True
                    elif intf_pfc_tlv_conf != match_intf_pfc_tlv:
                        if match_intf_pfc_tlv == default_interface_dcbx['pfc_tlv_enabled']:
                            delete_intf = True
                        else:
                            patch_intf_pfc = True
                    elif match_intf_pfc_tlv != default_interface_dcbx['pfc_tlv_enabled']:
                        patch_intf_pfc = True

                if intf_ets_config_tlv_conf is not None:
                    if match_intf_ets_config_tlv is None:
                        if intf_ets_reco_tlv_conf != default_interface_dcbx['ets_recommendation_tlv_enabled']:
                            delete_intf = True
                    elif intf_ets_config_tlv_conf != match_intf_ets_config_tlv:
                        if match_intf_ets_config_tlv == default_interface_dcbx['ets_configuration_tlv_enabled']:
                            delete_intf = True
                        else:
                            patch_intf_ets_conf = True
                    elif match_intf_ets_config_tlv != default_interface_dcbx['ets_recommendation_tlv_enabled']:
                        patch_intf_ets_conf = True

                if intf_ets_reco_tlv_conf is not None:
                    if match_intf_ets_reco_tlv is None:
                        if intf_ets_reco_tlv_conf != default_interface_dcbx['ets_recommendation_tlv_enabled']:
                            delete_intf = True
                    elif intf_ets_reco_tlv_conf != match_intf_ets_reco_tlv:
                        if match_intf_ets_reco_tlv == default_interface_dcbx['ets_recommendation_tlv_enabled']:
                            delete_intf = True
                        else:
                            patch_intf_ets_reco = True
                    elif match_intf_ets_reco_tlv != default_interface_dcbx['ets_recommendation_tlv_enabled']:
                        patch_intf_ets_reco = True

                if delete_intf:
                    del_interfaces.append({'name': intf_name})
                    requests.append(self.get_delete_interface_dcbx_request(intf_name))

                if patch_intf_dcbx:
                    command['enabled'] = match_intf_dcbx
                    requests.append(self.get_modify_interface_dcbx_request(intf_name, 'enabled', {'enabled': match_intf_dcbx}))

                if patch_intf_pfc:
                    command['pfc_tlv_enabled'] = match_intf_pfc_tlv
                    requests.append(self.get_modify_interface_dcbx_request(intf_name, 'pfc-tlv-enabled', {'pfc-tlv-enabled': match_intf_pfc_tlv}))

                if patch_intf_ets_conf:
                    command['ets_configuration_tlv_enabled'] = match_intf_ets_config_tlv
                    requests.append(
                        self.get_modify_interface_dcbx_request(
                            intf_name,
                            'ets-configuration-tlv-enabled',
                            {'ets-configuration-tlv-enabled': match_intf_ets_config_tlv}
                        )
                    )

                if patch_intf_ets_reco:
                    command['ets_recommendation_tlv_enabled'] = match_intf_ets_reco_tlv
                    requests.append(
                        self.get_modify_interface_dcbx_request(
                            intf_name,
                            'ets-recommendation-tlv-enabled',
                            {'ets-recommendation-tlv-enabled': match_intf_ets_reco_tlv}
                        )
                    )

                if patch_intf_dcbx or patch_intf_pfc or patch_intf_ets_conf or patch_intf_ets_reco:
                    add_interfaces.append(command)

            if del_interfaces:
                del_commands.append({'interfaces': del_interfaces, 'state': 'deleted'})

            if add_interfaces:
                add_commands.append({'interfaces': add_interfaces, 'state': state})

            if del_commands:
                commands.extend(update_states(del_commands, 'deleted'))

            if add_commands:
                commands.extend(update_states(add_commands, state))

        return commands, requests

    def get_delete_global_dcbx_request(self):
        """Get request to delete the global DCBx configuration"""
        return {'path': 'data/openconfig-dcbx:dcbx/config', 'method': DELETE}

    def get_delete_interface_dcbx_request(self, intf_name):
        """Get request to delete the DCBx configuration for a specific interface"""
        return {'path': f'data/openconfig-dcbx:dcbx/interfaces/interface={intf_name}', 'method': DELETE}

    def get_modify_global_dcbx_request(self, config):
        """Get request to modify the global DCBx configuration"""
        return {'path': 'data/openconfig-dcbx:dcbx/config/enabled', 'method': PATCH, 'data': config}

    def get_modify_interface_dcbx_request(self, intf_name, type, config):
        """Get request to modify the DCBx configuration for a specific interface"""
        return {'path': f'data/openconfig-dcbx:dcbx/interfaces/interface={intf_name}/config/{type}', 'method': PATCH, 'data': config}

    def get_modify_specific_dcbx_global_and_interfaces_param_requests(self, commands):
        """Get requests to modify specific DCBx Global and interface configurations"""
        requests = []
        glbl = commands.get('global')
        if glbl:
            if 'enabled' in glbl:
                url = self.dcbx_config_path
                if glbl['enabled'] is not True:
                    requests.append({'path': url, 'method': DELETE})
                else:
                    payload = {"openconfig-dcbx:config": {"enabled": glbl['enabled']}}
                    requests.append(
                        {'path': url, 'method': PATCH, 'data': payload})
        interfaces = commands.get('interfaces')
        if interfaces:
            for intf in interfaces:
                name = intf['name']
                if re.search('Eth', name):
                    if 'enabled' in intf:
                        url = self.dcbx_intf_config_path['enabled'].format(
                            intf_name=name)
                        if intf['enabled'] is True:
                            requests.append({'path': url, 'method': DELETE})
                        else:
                            payload = {'enabled': intf['enabled']}
                            requests.append(
                                {'path': url, 'method': PATCH, 'data': payload})

                    if 'pfc_tlv_enabled' in intf:
                        url = self.dcbx_intf_config_path['pfc-tlv-enabled'].format(
                            intf_name=name)
                        if intf['pfc_tlv_enabled'] is True:
                            requests.append({'path': url, 'method': DELETE})
                        else:
                            payload = {'pfc-tlv-enabled': intf['pfc_tlv_enabled']}
                            requests.append(
                                {'path': url, 'method': PATCH, 'data': payload})

                    if 'ets_configuration_tlv_enabled' in intf:
                        url = self.dcbx_intf_config_path['ets-configuration-tlv-enabled'].format(
                            intf_name=name)
                        if intf['ets_configuration_tlv_enabled'] is True:
                            requests.append({'path': url, 'method': DELETE})
                        else:
                            payload = {
                                'ets-configuration-tlv-enabled': intf['ets_configuration_tlv_enabled']}
                            requests.append(
                                {'path': url, 'method': PATCH, 'data': payload})

                    if 'ets_recommendation_tlv_enabled' in intf:
                        url = self.dcbx_intf_config_path['ets-recommendation-tlv-enabled'].format(
                            intf_name=name)
                        if intf['ets_recommendation_tlv_enabled'] is True:
                            requests.append({'path': url, 'method': DELETE})
                        else:
                            payload = {
                                'ets-recommendation-tlv-enabled': intf['ets_recommendation_tlv_enabled']}
                            requests.append(
                                {'path': url, 'method': PATCH, 'data': payload})
                else:
                    self._module.fail_json(msg="Only physical/Ethernet interfaces are supported.")
        return requests

    def get_delete_dcbx_requests(self, commands, have, is_delete_all):
        requests = []
        if not commands:
            return requests
        if is_delete_all:
            dcbx_path = 'data/openconfig-dcbx:dcbx'
            request = {'path': dcbx_path, 'method': DELETE}
            requests.append(request)
        else:
            requests.extend(self.get_delete_specific_dcbx_interfaces_param_requests(
                commands, have))
            requests.extend(self.get_delete_dcbx_global_param_requests(commands, have))

        return requests

    def get_delete_dcbx_global_param_requests(self, command, have):
        requests = []
        dcbx_global = command.get('global')
        cfg_dcbx_global = have.get('global')
        if dcbx_global and cfg_dcbx_global:
            if 'enabled' in dcbx_global and dcbx_global.get('enabled') == cfg_dcbx_global.get('enabled'):
                url = self.dcbx_config_path
                requests.append({'path': url, 'method': DELETE})
            else:
                dcbx_global.pop('enabled')

        return requests

    def get_delete_specific_dcbx_interfaces_param_requests(self, command, have):
        """Get requests to delete specific DCBx global configurations
        based on the command specified for the interface
        """
        requests = []
        interfaces = command.get('interfaces')
        cfg_interfaces = have.get('interfaces')
        if interfaces and cfg_interfaces:
            cfg_intf_dict = {cfg_intf.get('name'): cfg_intf for cfg_intf in cfg_interfaces}
            for intf in interfaces:
                name = intf.get('name')
                intf_dict = {}
                cfg_intf = cfg_intf_dict.get(name)
                if not cfg_intf:
                    continue
                if re.search('Eth', name):
                    if len(intf) == 1:
                        if cfg_intf.get("enabled") and cfg_intf.get("pfc_tlv_enabled") and \
                           cfg_intf.get("ets_configuration_tlv_enabled") and \
                           cfg_intf.get("ets_recommendation_tlv_enabled"):
                            continue
                        url = self.dcbx_intf_path.format(intf_name=name)
                        requests.append({'path': url, 'method': DELETE})

                    if 'enabled' in intf and intf.get('enabled') == cfg_intf.get('enabled'):
                        url = self.dcbx_intf_config_path['enabled'].format(
                            intf_name=name)
                        requests.append({'path': url, 'method': DELETE})

                    if 'pfc_tlv_enabled' in intf and intf.get('pfc_tlv_enabled') == cfg_intf.get('pfc_tlv_enabled'):
                        url = self.dcbx_intf_config_path['pfc-tlv-enabled'].format(
                            intf_name=name)
                        requests.append({'path': url, 'method': DELETE})

                    if ('ets_configuration_tlv_enabled' in intf
                            and intf.get('ets_configuration_tlv_enabled') == cfg_intf.get('ets_configuration_tlv_enabled')):
                        url = self.dcbx_intf_config_path['ets-configuration-tlv-enabled'].format(
                            intf_name=name)
                        requests.append({'path': url, 'method': DELETE})

                    if ('ets_recommendation_tlv_enabled' in intf
                            and intf.get('ets_recommendation_tlv_enabled') == cfg_intf.get('ets_recommendation_tlv_enabled')):
                        url = self.dcbx_intf_config_path['ets-recommendation-tlv-enabled'].format(
                            intf_name=name)
                        requests.append({'path': url, 'method': DELETE})

        return requests

    @staticmethod
    def get_interface_names_and_global(config_list):
        """Get a set of interface names and the global configuration from the given config_list dict
        """
        interface_names = set()
        global_config = config_list.get('global', None)
        interfaces = config_list.get('interfaces', [])
        for config in interfaces:
            if 'name' in config:
                interface_names.add(config['name'])

        return interface_names, global_config
