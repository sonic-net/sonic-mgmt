#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_pms class
It is in this file where the current configuration (as list)
is compared to the provided configuration (as list) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    update_states,
    get_diff,
    remove_empties,
    normalize_interface_name,
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    get_new_config,
    get_formatted_config_diff
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'patch'
DELETE = 'delete'

PMS_URL = 'data/openconfig-pms-ext:port-security/interfaces'

DEFAULT_KEYS = {
    'max_allowed_macs': 1,
    'violation': 'PROTECT',
    'sticky_mac': False
}


class Pms(ConfigBase):
    """
    The sonic_pms class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'pms',
    ]

    def __init__(self, module):
        super(Pms, self).__init__(module)

    def get_pms_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A list
        :returns: The current configuration as a list
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        pms_facts = facts['ansible_network_resources'].get('pms')
        if not pms_facts:
            return []
        return pms_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        commands = list()

        existing_pms_facts = self.get_pms_facts()
        commands, requests = self.set_config(existing_pms_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        result['before'] = existing_pms_facts
        new_config = deepcopy(existing_pms_facts)

        if self._module.check_mode:
            new_config = self.get_new_config(commands, existing_pms_facts)
            new_config.sort(key=lambda x: x['name'])
            result['after(generated)'] = remove_empties_from_list(new_config)
        elif result['changed']:
            new_config = self.get_pms_facts()
            new_config.sort(key=lambda x: x['name'])
            result['after'] = new_config

        if self._module._diff:
            existing_pms_facts.sort(key=lambda x: x['name'])
            result['diff'] = get_formatted_config_diff(existing_pms_facts, new_config, self._module._verbosity)

        return result

    def set_config(self, existing_pms_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a list from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_pms_facts
        new_want = self.validate_normalize_config(want, have)
        resp = self.set_state(new_want, have)
        return to_list(resp)

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

        if state == 'overridden' or state == 'replaced':
            commands, requests = self._state_replaced_or_overridden(want, have, state)
        elif state == 'deleted' or state == 'merged':
            commands, requests = self._state_merged_or_deleted(want, have, state)

        return commands, requests

    def validate_normalize_config(self, want, have):
        new_want = deepcopy(want)
        new_want = remove_empties_from_list(new_want)
        state = self._module.params['state']
        normalize_interface_name(new_want, self._module)
        if state != 'deleted':
            for conf in new_want:
                if 'port_security_enable' in conf and conf['port_security_enable']:
                    name = conf.get('name')
                    match_have = next((cfg for cfg in have if cfg['name'] == name), None)
                    if not match_have:
                        for keys in DEFAULT_KEYS:
                            if keys not in conf:
                                conf[keys] = DEFAULT_KEYS[keys]
        return new_want

    def _state_merged_or_deleted(self, want, have, state):
        """ The command generator when state is merged or deleted

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, requests = [], []
        add_commands, del_commands, add_requests, del_requests = [], [], [], []
        if state == 'merged':
            diff = get_diff(want, have)
            add_commands, del_commands, add_requests, del_requests = self.get_create_pms_commands_requests(diff, have)
        else:
            is_delete_all = False
            if not want:
                commands_to_delete = have
                is_delete_all = True
            else:
                commands_to_delete = want
            add_commands, del_commands, add_requests, del_requests = self.get_delete_pms_commands_requests(commands_to_delete, have, is_delete_all)

        if del_commands and len(del_requests) > 0:
            commands.extend(update_states(del_commands, 'deleted'))
            requests.extend(del_requests)

        if add_commands and len(add_requests) > 0:
            commands.extend(update_states(add_commands, 'merged'))
            requests.extend(add_requests)

        return commands, requests

    def _state_replaced_or_overridden(self, want, have, state):
        """ The command generator when state is replaced or overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, requests = [], []
        add_config, del_config = self._get_replaced_overridden_config(want, have, state)
        if del_config:
            add_commands, del_commands, add_requests, del_requests = self.get_delete_pms_commands_requests(del_config, have, False)
            if del_commands and len(del_requests) > 0:
                commands.extend(update_states(del_commands, 'deleted'))
                requests.extend(del_requests)

            if add_commands and len(add_requests) > 0:
                commands.extend(update_states(add_commands, 'merged'))
                requests.extend(add_requests)

        if add_config:
            add_commands, del_commands, add_requests, del_requests = self.get_create_pms_commands_requests(add_config, [])
            if add_commands and len(add_requests) > 0:
                commands.extend(update_states(add_commands, state))
                requests.extend(add_requests)

        return commands, requests

    def _get_replaced_overridden_config(self, want, have, state):
        add_config, del_config = [], []
        if not want:
            return add_config, del_config
        if not have:
            return want, del_config

        for item in want:
            intf_name = item.get('name')
            match_have = next((cfg for cfg in have if cfg['name'] == item['name']), None)
            if not match_have:
                add_config.append(item)
            else:
                if len(item) == 2 and not item['port_security_enable']:
                    del_config.append({'name': intf_name, 'port_security_enable': True})
                    continue
                add_cfg, del_cfg = {}, {}
                diff_keys = set(item.items()) ^ set(match_have.items())
                for key in dict(diff_keys):
                    if key == 'port_security_enable' and not item['port_security_enable']:
                        del_cfg['port_security_enable'] = True
                    elif key in item and key in match_have and item[key] != match_have[key]:
                        add_cfg[key] = item[key]
                        del_cfg[key] = match_have[key]
                    elif key in item:
                        add_cfg[key] = item[key]
                    elif key in match_have:
                        del_cfg[key] = match_have[key]

                if add_cfg:
                    add_cfg['name'] = intf_name
                    add_cfg['port_security_enable'] = item['port_security_enable']
                    add_config.append(add_cfg)

                if del_cfg:
                    del_cfg['name'] = intf_name
                    del_cfg['port_security_enable'] = match_have['port_security_enable']
                    del_config.append(del_cfg)

        if state == 'overridden':
            for item in have:
                intf_name = item.get('name')
                match_want = next((cfg for cfg in want if cfg['name'] == item['name']), None)
                if not match_want:
                    del_config.append({'name': intf_name, 'port_security_enable': True})

        return add_config, del_config

    def get_create_pms_commands_requests(self, commands, have):
        add_commands, del_commands, add_requests, del_requests = [], [], [], []
        if not commands:
            return [], [], [], []

        patch_payload = []
        for cmd in commands:
            intf_name = cmd.get('name')
            pms_enable = cmd.get('port_security_enable')
            if pms_enable is not None and not pms_enable:
                match_have = next((cfg for cfg in have if cfg['name'] == intf_name), None)
                if match_have:
                    del_commands.append({'name': intf_name, 'port_security_enable': pms_enable})
                    del_requests.append(self._get_pms_interface_remove_request(intf_name))
            else:
                sub_payload = self._generate_pms_patch_payload(cmd, intf_name)
                if sub_payload:
                    add_commands.append(cmd)
                    patch_payload.append(sub_payload)

        if patch_payload:
            add_requests.append(self._get_pms_patch_requests(patch_payload))

        return add_commands, del_commands, add_requests, del_requests

    def get_delete_pms_commands_requests(self, commands, have, is_delete_all):
        add_commands, del_commands, add_requests, del_requests = [], [], [], []
        if not commands:
            return [], [], [], []

        patch_payload = []
        for cmd in commands:
            intf_name = cmd.get('name')
            pms_enable = cmd.get('port_security_enable')
            match_have = next((cfg for cfg in have if cfg['name'] == intf_name), None)
            if match_have:
                if (len(cmd) == 2 and pms_enable) or is_delete_all:
                    del_commands.append({'name': intf_name, 'port_security_enable': pms_enable})
                    del_requests.append(self._get_pms_interface_remove_request(intf_name))
                else:
                    add_cmd, del_cmd = {}, {}
                    diff_keys = set(cmd.keys()) & set(match_have.keys())
                    for key in list(diff_keys):
                        if key in DEFAULT_KEYS and match_have[key] != DEFAULT_KEYS[key]:
                            del_cmd[key] = match_have[key]
                            add_cmd[key] = DEFAULT_KEYS[key]
                    if add_cmd:
                        sub_payload = self._generate_pms_patch_payload(add_cmd, intf_name)
                        if sub_payload:
                            patch_payload.append(sub_payload)
                        add_cmd['name'] = intf_name
                        add_cmd['port_security_enable'] = pms_enable
                        add_commands.append(add_cmd)

                    if del_cmd:
                        del_cmd['name'] = intf_name
                        del_commands.append(del_cmd)
        if patch_payload:
            add_requests.append(self._get_pms_patch_requests(patch_payload))

        return add_commands, del_commands, add_requests, del_requests

    def _get_pms_interface_remove_request(self, name):
        return {
            'path': PMS_URL + "/interface=" + name,
            'method': DELETE
        }

    def _get_pms_patch_requests(self, payload):
        return {
            'path': PMS_URL,
            'method': PATCH,
            'data': {
                "openconfig-pms-ext:interfaces": {"interface": payload}
            }
        }

    def _generate_pms_patch_payload(self, conf, name):
        sub_payload = {
            'name': name,
            'admin-enable': conf.get('port_security_enable'),
            'maximum': conf.get('max_allowed_macs'),
            'violation': conf.get('violation'),
            'sticky-mac': conf.get('sticky_mac')
        }
        sub_payload = remove_empties(sub_payload)
        return {'name': name, 'config': sub_payload} if len(sub_payload) > 1 else None

    def __derive_pms_interface_merge_op(self, key_set, command, exist_conf):
        new_conf = exist_conf
        if command:
            if len(command.keys()) == 2:
                return True, new_conf
            for attr in command:
                new_conf[attr] = command[attr]
        return True, new_conf

    def __derive_pms_interface_delete_op(self, key_set, command, exist_conf):
        new_conf = exist_conf
        if command:
            if len(command.keys()) == 2 and command.get('port_security_enable'):
                return True, {}
            for attr in command:
                if attr in new_conf:
                    new_conf[attr] = None
        return True, new_conf

    def get_new_config(self, commands, have):
        """Returns generated configuration based on commands and
        existing configuration"""
        key_set = [
            {'config': {'name': '',
                        '__delete_op': self.__derive_pms_interface_delete_op,
                        '__merge_op': self.__derive_pms_interface_merge_op}},
        ]

        return remove_empties_from_list(get_new_config(commands, have, key_set))
