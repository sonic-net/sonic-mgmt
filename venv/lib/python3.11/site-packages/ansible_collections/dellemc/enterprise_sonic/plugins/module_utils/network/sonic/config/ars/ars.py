#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_ars class
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
    get_new_config,
    get_formatted_config_diff
)

ARS_PATH = 'data/openconfig-system:system/openconfig-system-ext:adaptive-routing-switching'
PATCH = 'patch'
DELETE = 'delete'
delete_all = False
is_replaced = False
TEST_KEYS = [
    {'ars_objects': {'name': ''}},
    {'port_bindings': {'name': ''}},
    {'port_profiles': {'name': ''}},
    {'profiles': {'name': ''}}
]
enum_dict = {
    0.0: '0',
    1.0: '1',
    2.5: '2.5',
    4.0: '4',
    5.0: '5',
    10.0: '10',
    20.0: '20',
    40.0: '40',
    80.0: '80',
    'fixed': 'ARS_MODE_FIXED',
    'flowlet-quality': 'ARS_MODE_FLOWLET_QUALITY',
    'flowlet-random': 'ARS_MODE_FLOWLET_RANDOM',
    'packet-quality': 'ARS_MODE_PER_PACKET_QUALITY',
    'packet-random': 'ARS_MODE_PER_PACKET_RANDOM'
}
DEFAULTS_MAP = {
    'ars_objects': {
        'idle_time': 80,
        'max_flows': 256,
        'mode': 'flowlet-quality'
    },
    'port_profiles': {
        'enable': False,
        'load_future_weight': 10,
        'load_past_weight': 80,
        'load_scaling_factor': 0.0,
    },
    'profiles': {
        'algorithm': 'EWMA',
        'load_current_max_val': 6291456,
        'load_current_min_val': 1048576,
        'load_future_max_val': 12582912,
        'load_future_min_val': 2097152,
        'load_past_max_val': 6000,
        'load_past_min_val': 3000,
        'port_load_current': False,
        'port_load_exponent': 2,
        'port_load_future': True,
        'port_load_future_weight': 2,
        'port_load_past': True,
        'port_load_past_weight': 2,
        'random_seed': 10,
        'sampling_interval': 16
    }
}


class Ars(ConfigBase):
    """
    The sonic_ars class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'ars',
    ]

    def __init__(self, module):
        super(Ars, self).__init__(module)

    def get_ars_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        ars_facts = facts['ansible_network_resources'].get('ars')
        if not ars_facts:
            return {}
        return ars_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        commands = []

        existing_ars_facts = self.get_ars_facts()
        commands, requests = self.set_config(existing_ars_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands
        result['before'] = existing_ars_facts
        old_config = existing_ars_facts

        if self._module.check_mode:
            new_config = self.get_new_config(commands, existing_ars_facts)
            self.sort_lists_in_config(new_config)
            result['after(generated)'] = new_config
        else:
            new_config = self.get_ars_facts()
            if result['changed']:
                result['after'] = new_config
        if self._module._diff:
            self.sort_lists_in_config(new_config)
            self.sort_lists_in_config(old_config)
            result['diff'] = get_formatted_config_diff(old_config, new_config, self._module._verbosity)

        return result

    def set_config(self, existing_ars_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = remove_empties(self._module.params['config'])
        have = existing_ars_facts
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
        commands, requests = [], []
        state = self._module.params['state']
        diff = get_diff(want, have, TEST_KEYS)

        if state == 'merged':
            commands, requests = self._state_merged(diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have, diff)
        elif state == 'overridden':
            commands, requests = self._state_overridden(want, have, diff)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have, diff)
        return commands, requests

    def _state_replaced(self, want, have, diff):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        global is_replaced
        is_replaced = False
        commands = []
        mod_commands = None
        replaced_config, requests = self.get_replaced_config(want, have)
        self.remove_default_entries(replaced_config)

        if replaced_config:
            is_replaced = True
            commands.extend(update_states(replaced_config, 'deleted'))
            mod_commands = want
        else:
            mod_commands = diff

        if mod_commands:
            mod_request = self.get_modify_ars_request(mod_commands)
            if mod_request:
                requests.append(mod_request)
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
        mod_commands, mod_request = None, None
        del_commands = get_diff(have, want, TEST_KEYS)
        self.remove_default_entries(del_commands)

        if del_commands:
            delete_all = True
            del_requests = self.get_delete_ars_requests(del_commands, delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(have, 'deleted'))
            mod_commands = want
            mod_request = self.get_modify_ars_request(mod_commands)
        elif diff:
            mod_commands = diff
            mod_request = self.get_modify_ars_request(mod_commands)

        if mod_request:
            requests.append(mod_request)
            commands.extend(update_states(mod_commands, 'overridden'))

        return commands, requests

    def _state_merged(self, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        requests = self.get_modify_ars_request(commands)

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
        global delete_all
        delete_all = False
        commands, requests = [], []

        if not have:
            return commands, requests
        elif not want:
            commands = deepcopy(have)
            delete_all = True
        else:
            commands = get_diff(want, diff, TEST_KEYS)
            self.remove_default_entries(commands, True)

        if commands:
            requests = self.get_delete_ars_requests(commands, delete_all)
            if len(requests) > 0:
                commands = update_states(commands, 'deleted')
        else:
            commands = []

        return commands, requests

    def get_modify_ars_request(self, commands):
        """This method returns a patch request generated from commands"""
        request = None

        if commands:
            cmds = deepcopy(commands)
            ars_dict = {}
            if cmds.get('profiles'):
                profile_list = []
                for profile in cmds['profiles']:
                    if 'algorithm' in profile:
                        profile['algo'] = profile.pop('algorithm')
                    profile_list.append({'name': profile['name'], 'config': self.get_renamed_dict(profile)})
                if profile_list:
                    ars_dict['ars-profile'] = {'profile': profile_list}

            if cmds.get('switch_binding'):
                switchbind_list = [{'name': 'SWITCH', 'config': {'name': 'SWITCH', 'profile': cmds['switch_binding']['profile']}}]
                ars_dict['ars-switch-bind'] = {'switchbind': switchbind_list}

            if cmds.get('port_profiles'):
                portprofile_list = []
                for profile in cmds['port_profiles']:
                    profile_dict = self.get_renamed_dict(profile)
                    if profile_dict.get('load-scaling-factor') is not None:
                        profile_dict['load-scaling-factor'] = enum_dict[profile_dict['load-scaling-factor']]
                    portprofile_list.append({'name': profile['name'], 'config': profile_dict})
                if portprofile_list:
                    ars_dict['ars-port-profile'] = {'portprofile': portprofile_list}

            if cmds.get('port_bindings'):
                portbind_list = []
                for bind in cmds['port_bindings']:
                    if not bind.get('profile'):
                        self._module.fail_json(msg='Must specify a profile for %s port binding.' % (bind['name']))
                    portbind_list.append({'name': bind['name'], 'config': bind})
                if portbind_list:
                    ars_dict['ars-port-bind'] = {'portbind': portbind_list}

            if cmds.get('ars_objects'):
                arsobject_list = []
                for obj in cmds['ars_objects']:
                    obj_dict = self.get_renamed_dict(obj)
                    if obj_dict.get('mode'):
                        obj_dict['mode'] = enum_dict[obj_dict['mode']]
                    arsobject_list.append({'name': obj_dict['name'], 'config': obj_dict})
                if arsobject_list:
                    ars_dict['ars-object'] = {'arsobject': arsobject_list}

            if ars_dict:
                payload = {'openconfig-system-ext:adaptive-routing-switching': ars_dict}
                request = {'path': ARS_PATH, 'method': PATCH, 'data': payload}

        return request

    @staticmethod
    def get_renamed_dict(cfg_dict):
        """This method renames the keys in a dictionary by replacing underscores with hyphens"""
        renamed_dict = {}
        for key in cfg_dict:
            new_key = key.replace('_', '-')
            renamed_dict[new_key] = cfg_dict[key]

        return renamed_dict

    def get_delete_ars_requests(self, commands, delete_all):
        """This method returns a list of delete requests generated from commands"""
        requests = []

        if not commands:
            return requests
        if delete_all:
            requests.append({'path': ARS_PATH, 'method': DELETE})
            return requests

        if commands.get('ars_objects'):
            for obj in commands['ars_objects']:
                name = obj['name']
                if len(obj) == 1:
                    requests.append(self.get_delete_ars_object(name))
                    continue
                for key in obj:
                    if key == 'name':
                        continue
                    if obj.get(key):
                        attr = key.replace('_', '-')
                        requests.append(self.get_delete_ars_object(name, attr))

        if commands.get('port_bindings'):
            for bind in commands['port_bindings']:
                requests.append(self.get_delete_port_bind(bind['name']))

        if commands.get('switch_binding'):
            requests.append(self.get_delete_switch_bind())

        if commands.get('port_profiles'):
            for profile in commands.get('port_profiles'):
                name = profile['name']
                if len(profile) == 1:
                    requests.append(self.get_delete_port_profile(name))
                    continue
                for key in profile:
                    if key == 'name':
                        continue
                    if profile.get(key) is not None:
                        attr = key.replace('_', '-')
                        requests.append(self.get_delete_port_profile(name, attr))

        if commands.get('profiles'):
            for profile in commands.get('profiles'):
                name = profile['name']
                if len(profile) == 1:
                    requests.append(self.get_delete_profile(name))
                    continue
                for key in profile:
                    if key == 'name':
                        continue
                    if profile.get(key) is not None:
                        if key == 'algorithm':
                            attr = 'algo'
                        else:
                            attr = key.replace('_', '-')
                        requests.append(self.get_delete_profile(name, attr))

        return requests

    @staticmethod
    def get_delete_ars_object(name=None, attr=None):
        url = '%s/ars-object' % (ARS_PATH)
        if name:
            url += '/arsobject=%s' % (name)
        if attr:
            url += '/config/%s' % (attr)
        request = {'path': url, 'method': DELETE}
        return request

    @staticmethod
    def get_delete_port_bind(name=None):
        url = '%s/ars-port-bind' % (ARS_PATH)
        if name:
            url += '/portbind=%s' % (name)
        request = {'path': url, 'method': DELETE}
        return request

    @staticmethod
    def get_delete_port_profile(name=None, attr=None):
        url = '%s/ars-port-profile' % (ARS_PATH)
        if name:
            url += '/portprofile=%s' % (name)
        if attr:
            url += '/config/%s' % (attr)
        request = {'path': url, 'method': DELETE}
        return request

    @staticmethod
    def get_delete_profile(name=None, attr=None):
        url = '%s/ars-profile' % (ARS_PATH)
        if name:
            url += '/profile=%s' % (name)
        if attr:
            url += '/config/%s' % (attr)
        request = {'path': url, 'method': DELETE}
        return request

    @staticmethod
    def get_delete_switch_bind():
        url = '%s/ars-switch-bind/switchbind=SWITCH' % (ARS_PATH)
        request = {'path': url, 'method': DELETE}
        return request

    @staticmethod
    def sort_lists_in_config(config):
        """This method sorts the lists in the ARS configuration"""
        if config:
            ars_lists = ['ars_objects', 'port_bindings', 'port_profiles', 'profiles']
            for ars_list in ars_lists:
                if config.get(ars_list):
                    config[ars_list].sort(key=lambda x: x['name'])

    def remove_default_entries(self, data, is_state_deleted=False):
        """This method removes the default entries from the ARS configuration"""
        if data:
            ars_lists = ['ars_objects', 'port_profiles', 'profiles']
            for ars_list in ars_lists:
                if data.get(ars_list):
                    pop_list = []
                    for idx, ars_dict in enumerate(data[ars_list]):
                        if len(ars_dict) == 1:
                            continue
                        key_pop_list = []
                        for key in ars_dict:
                            if key not in DEFAULTS_MAP[ars_list]:
                                continue
                            if ars_dict[key] == DEFAULTS_MAP[ars_list][key]:
                                key_pop_list.append(key)
                        for key in key_pop_list:
                            ars_dict.pop(key)
                        if len(ars_dict) == 1 and is_state_deleted:
                            pop_list.insert(0, idx)
                    for idx in pop_list:
                        data[ars_list].pop(idx)
                    if not data[ars_list]:
                        data.pop(ars_list)

    def add_default_entries(self, data):
        """This method adds the default entries to the ARS configuration"""
        ars_lists = ['ars_objects', 'port_profiles', 'profiles']

        for ars_list in ars_lists:
            if data.get(ars_list):
                for item in data[ars_list]:
                    for key in DEFAULTS_MAP[ars_list]:
                        item.setdefault(key, DEFAULTS_MAP[ars_list][key])

    def get_replaced_config(self, want, have):
        """This method returns the ARS configuration to be deleted and the respective delete requests"""
        config_dict = {}
        requests = []
        new_want = deepcopy(want)
        self.add_default_entries(new_want)
        self.sort_lists_in_config(new_want)
        self.sort_lists_in_config(have)

        if not new_want or not have:
            return config_dict, requests

        if new_want.get('ars_objects') and have.get('ars_objects'):
            if new_want['ars_objects'] != have['ars_objects']:
                requests.append(self.get_delete_ars_object())
                config_dict['ars_objects'] = have['ars_objects']
            else:
                want.pop('ars_objects')
        if new_want.get('port_bindings') and have.get('port_bindings'):
            if new_want['port_bindings'] != have['port_bindings']:
                requests.append(self.get_delete_port_bind())
                config_dict['port_bindings'] = have['port_bindings']
            else:
                want.pop('port_bindings')
        if new_want.get('switch_binding') and have.get('switch_binding'):
            if new_want['switch_binding'] != have['switch_binding']:
                requests.append(self.get_delete_switch_bind())
                config_dict['switch_binding'] = have['switch_binding']
            else:
                want.pop('switch_binding')
        if new_want.get('port_profiles') and have.get('port_profiles'):
            if new_want['port_profiles'] != have['port_profiles']:
                requests.append(self.get_delete_port_profile())
                config_dict['port_profiles'] = have['port_profiles']
            else:
                want.pop('port_profiles')
        if new_want.get('profiles') and have.get('profiles'):
            if new_want['profiles'] != have['profiles']:
                requests.append(self.get_delete_profile())
                config_dict['profiles'] = have['profiles']
            else:
                want.pop('profiles')

        return config_dict, requests

    def __derive_ars_delete_op(self, key_set, command, exist_conf):
        """Returns new ARS configuration on delete operation"""
        if delete_all:
            return True, {}

        new_conf = exist_conf
        ars_lists = ['ars_objects', 'port_bindings', 'port_profiles', 'profiles']

        for ars_list in ars_lists:
            if is_replaced:
                new_conf.pop(ars_list, None)
                continue
            pop_list = []
            for idx, ars_dict in enumerate(command.get(ars_list, [])):
                if len(ars_dict) == 1:
                    pop_list.insert(0, idx)
                    continue
                for key in ars_dict:
                    if key == 'name':
                        continue
                    if key in DEFAULTS_MAP.get(ars_list, {}):
                        new_conf[ars_list][idx][key] = DEFAULTS_MAP[ars_list][key]
                    else:
                        new_conf[ars_list][idx].pop(key)
                        if len(new_conf[ars_list][idx]) == 1:
                            pop_list.insert(0, idx)
            for idx in pop_list:
                new_conf[ars_list].pop(idx)
            if ars_list in new_conf and not new_conf[ars_list]:
                new_conf.pop(ars_list)

        if command.get('switch_binding'):
            new_conf.pop('switch_binding')

        return True, new_conf

    def get_new_config(self, commands, have):
        """Returns generated configuration based on commands and
            existing configuration"""
        key_set = [
            {'config': {'__delete_op': self.__derive_ars_delete_op}},
            {'ars_objects': {'name': ''}},
            {'port_bindings': {'name': ''}},
            {'port_profiles': {'name': ''}},
            {'profiles': {'name': ''}}
        ]
        new_config = get_new_config(commands, have, key_set)
        self.add_default_entries(new_config)

        return new_config
