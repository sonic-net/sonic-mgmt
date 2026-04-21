#
# -*- coding: utf-8 -*-
# Copyright 2020 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_lag_interfaces class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import (
    deepcopy
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
    remove_empties,
    search_obj_in_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    update_states,
    get_diff,
    get_normalize_interface_name,
    normalize_interface_name,
    remove_empties_from_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
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
TEST_KEYS = [
    {'config': {'name': ''}},
    {'interfaces': {'member': ''}},
]
DEFAULT_VALUES = {
    'fallback': False,
    'fast_rate': False,
    'graceful_shutdown': False,
    'min_links': 1,
    'lacp_individual': {
        'enable': False,
        'timeout': 3
    }
}
ESI_TYPE_VALUE_TO_PAYLOAD = {
    'ethernet_segment_id': 'TYPE_0_OPERATOR_CONFIGURED',
    'auto_lacp': 'TYPE_1_LACP_BASED',
    'auto_system_mac': 'TYPE_3_MAC_BASED'
}


class Lag_interfaces(ConfigBase):
    """
    The sonic_lag_interfaces class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'lag_interfaces',
    ]

    interface_path = 'data/openconfig-interfaces:interfaces/interface={name}'
    lag_member_path = interface_path + '/openconfig-if-ethernet:ethernet/config/openconfig-if-aggregate:aggregate-id'
    lag_interface_config_root_path = interface_path + '/openconfig-if-aggregate:aggregation/config'
    lag_interface_config_path = {
        'graceful_shutdown': lag_interface_config_root_path + '/graceful-shutdown-mode',
        'lacp_individual': {
            'enable': lag_interface_config_root_path + '/lacp-individual',
            'timeout': lag_interface_config_root_path + '/lacp-individual-timeout',
        },
        'min_links': lag_interface_config_root_path + '/min-links',
        'system_mac': lag_interface_config_root_path + '/system-mac'
    }
    eth_seg_path = 'data/openconfig-network-instance:network-instances/network-instance=default/evpn/ethernet-segments'
    lag_interface_eth_seg_path = eth_seg_path + '/ethernet-segment={name}'
    lag_interface_eth_seg_df_pref_path = lag_interface_eth_seg_path + '/df-election/config/preference'

    def __init__(self, module):
        super(Lag_interfaces, self).__init__(module)

    def get_lag_interfaces_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        lag_interfaces_facts = facts['ansible_network_resources'].get('lag_interfaces')
        if not lag_interfaces_facts:
            return []
        return lag_interfaces_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = []
        commands = []
        existing_lag_interfaces_facts = self.get_lag_interfaces_facts()
        commands, requests = self.set_config(existing_lag_interfaces_facts)
        if commands:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        result['before'] = existing_lag_interfaces_facts
        old_config = existing_lag_interfaces_facts
        if self._module.check_mode:
            new_config = self.get_new_config(commands, existing_lag_interfaces_facts)
            self.sort_config(new_config)
            result['after(generated)'] = new_config
        else:
            new_config = self.get_lag_interfaces_facts()
            if result['changed']:
                result['after'] = new_config

        if self._module._diff:
            self.sort_config(old_config)
            if not self._module.check_mode:
                self.sort_config(new_config)
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)
        result['warnings'] = warnings
        return result

    def set_config(self, existing_lag_interfaces_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_lag_interfaces_facts
        want = self.validate_and_normalize_want(want, have)
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
                lag_name = have_conf['name']
                conf = search_obj_in_list(lag_name, want, 'name')

                if not conf:
                    # Delete all LAG interfaces that are not specified in 'overridden'
                    if state == 'overridden':
                        del_commands.append({'name': lag_name})
                        del_requests.extend(self.get_delete_lag_interface_requests(have_conf))
                    continue

                if conf['mode'] != have_conf['mode']:
                    # If mode is changed, delete and reconfigure the LAG interface
                    del_commands.append({'name': lag_name})
                    del_requests.extend(self.get_delete_lag_interface_requests(have_conf))
                    continue

                del_command = {}
                have_conf = deepcopy(have_conf)
                self.remove_defaults(have_conf)

                del_members = self.get_member_names(have_conf).difference(self.get_member_names(conf))
                if del_members:
                    del_command['members'] = self.get_members_dict(del_members)

                for option in ('fallback', 'fast_rate', 'graceful_shutdown', 'min_links', 'system_mac'):
                    if have_conf.get(option) is not None and option not in conf:
                        del_command[option] = have_conf[option]

                if have_conf.get('lacp_individual'):
                    if conf.get('lacp_individual'):
                        lacp, have_lacp = conf['lacp_individual'], have_conf['lacp_individual']
                        for option in ('enable', 'timeout'):
                            if have_lacp.get(option) is not None and option not in lacp:
                                del_command.setdefault('lacp_individual', {})
                                del_command['lacp_individual'][option] = have_lacp[option]
                    else:
                        del_command['lacp_individual'] = have_conf['lacp_individual']

                if have_conf.get('ethernet_segment'):
                    if conf.get('ethernet_segment'):
                        if have_conf['ethernet_segment'].get('df_preference') and 'df_preference' not in conf['ethernet_segment']:
                            del_command['ethernet_segment'] = {
                                'esi_type': have_conf['ethernet_segment']['esi_type'],
                                'df_preference': have_conf['ethernet_segment']['df_preference']
                            }
                    else:
                        del_command['ethernet_segment'] = have_conf['ethernet_segment']

                if del_command:
                    del_command['name'] = lag_name
                    del_commands.append(del_command)
                    del_requests.extend(self.get_delete_lag_interface_param_requests(del_command))

        if del_commands:
            commands = update_states(del_commands, 'deleted')
            new_have = self.get_new_config(commands, have)
            requests = del_requests
        else:
            new_have = have

        add_commands = self.get_diff(want, new_have)
        if add_commands:
            commands.extend(update_states(add_commands, state))
            requests.extend(self.get_modify_lag_interfaces_requests(add_commands, new_have))

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands, requests = [], []
        diff = self.get_diff(want, have)
        if diff:
            commands = update_states(diff, 'merged')
            requests = self.get_modify_lag_interfaces_requests(diff, have)

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
        # if want is none, then delete all the lag interfaces and all portchannels
        elif not want:
            requests.extend(self.get_delete_all_lag_interfaces_requests())
            for conf in have:
                commands.append({'name': conf['name']})
            commands = update_states(commands, 'deleted')
        else:  # delete specific lag interfaces and specific portchannels
            for conf in want:
                lag_name = conf['name']
                have_conf = search_obj_in_list(lag_name, have, 'name')
                if not have_conf:
                    continue

                # Delete LAG interface if only name is specified
                if len(conf.keys()) == 1:
                    commands.append({'name': lag_name})
                    requests.extend(self.get_delete_lag_interface_requests(have_conf))
                else:
                    command = {}
                    have_conf = deepcopy(have_conf)
                    self.remove_defaults(have_conf)
                    if len(have_conf.keys()) == 1:
                        continue

                    if conf.get('members') and have_conf.get('members') and have_conf['members'].get('interfaces'):
                        # If members -> interfaces is mentioned without value,
                        # delete all existing members
                        if 'interfaces' in conf['members'] and not conf['members']['interfaces']:
                            command['members'] = have_conf['members']
                        else:
                            del_members = self.get_member_names(conf).intersection(self.get_member_names(have_conf))
                            if del_members:
                                command['members'] = self.get_members_dict(del_members)

                    for option in ('fallback', 'fast_rate', 'graceful_shutdown', 'min_links', 'system_mac'):
                        if conf.get(option) is not None and conf[option] == have_conf.get(option):
                            command[option] = conf[option]

                    if conf.get('lacp_individual') and have_conf.get('lacp_individual'):
                        lacp, have_lacp = conf['lacp_individual'], have_conf['lacp_individual']
                        for option in ('enable', 'timeout'):
                            if lacp.get(option) is not None and lacp[option] == have_lacp.get(option):
                                command.setdefault('lacp_individual', {})
                                command['lacp_individual'][option] = lacp[option]

                    if conf.get('ethernet_segment') and have_conf.get('ethernet_segment'):
                        eth_seg, have_eth_seg = conf['ethernet_segment'], have_conf['ethernet_segment']
                        df_pref, have_df_pref = eth_seg.get('df_preference'), have_eth_seg.get('df_preference')
                        if eth_seg.get('esi_type') and eth_seg['esi_type'] == have_eth_seg.get('esi_type'):
                            if eth_seg.get('esi'):
                                if eth_seg['esi'] == have_eth_seg.get('esi') and (not df_pref or df_pref == have_df_pref):
                                    command['ethernet_segment'] = eth_seg
                            else:
                                # When df_preference is specified without esi, then delete only df_preference.
                                if not df_pref or df_pref == have_df_pref:
                                    command['ethernet_segment'] = eth_seg

                    if command:
                        command['name'] = lag_name
                        commands.append(command)
                        requests.extend(self.get_delete_lag_interface_param_requests(command))

        if commands:
            commands = update_states(commands, 'deleted')

        return commands, requests

    def get_modify_lag_interfaces_requests(self, commands, have):
        """Get requests to modify LAG configurations based on the
        command specified for the LAG interface"""
        requests = []
        for cmd in commands:
            have_obj = search_obj_in_list(cmd['name'], have, 'name')
            # Create LAG interface if it does not exist
            if not have_obj:
                requests.append(self.get_create_lag_interface_request(cmd))

            config_dict = {}
            for option in ('fallback', 'fast_rate', 'min_links', 'system_mac'):
                if cmd.get(option) is not None:
                    config_dict[option.replace('_', '-')] = cmd[option]
            if cmd.get('graceful_shutdown') is not None:
                config_dict['graceful-shutdown-mode'] = 'ENABLE' if cmd['graceful_shutdown'] else 'DISABLE'
            if cmd.get('lacp_individual'):
                if cmd['lacp_individual'].get('enable') is not None:
                    config_dict['lacp-individual'] = 'enable' if cmd['lacp_individual']['enable'] else 'disable'
                if cmd['lacp_individual'].get('timeout') is not None:
                    config_dict['lacp-individual-timeout'] = cmd['lacp_individual']['timeout']

            if config_dict:
                url = self.lag_interface_config_root_path.format(name=cmd['name'])
                payload = {'openconfig-if-aggregate:config': config_dict}
                requests.append({'path': url, 'method': PATCH, 'data': payload})

            if cmd.get('members'):
                requests.extend(self.get_add_lag_members_requests(cmd))

        ethernet_segment_request = self.get_modify_ethernet_segment_request(commands, have)
        if ethernet_segment_request:
            requests.append(ethernet_segment_request)

        return requests

    def get_create_lag_interface_request(self, command):
        """Get request to create LAG interface specified in command"""
        url = 'data/openconfig-interfaces:interfaces'
        payload = {
            'openconfig-interfaces:interfaces': {
                'interface': [{
                    'name': command['name'],
                    'config': {'name': command['name']}
                }]
            }
        }
        if command.get('mode') == 'static':
            payload['openconfig-interfaces:interfaces']['interface'][0]['openconfig-if-aggregate:aggregation'] = {
                'config': {'lag-type': command['mode'].upper()}
            }

        return {'path': url, 'method': PATCH, 'data': payload}

    def get_add_lag_members_requests(self, command):
        """Get requests to add LAG members specified in command"""
        requests = []
        if command and command.get('members') and command['members'].get('interfaces'):
            interfaces = command['members']['interfaces']
            for member in interfaces:
                url = self.lag_member_path.format(name=member['member'])
                payload = {'openconfig-if-aggregate:aggregate-id': command['name']}
                requests.append({'path': url, 'method': PATCH, 'data': payload})

        return requests

    def get_modify_ethernet_segment_request(self, commands, have):
        """Get request to modify ethernet segment configuration for
        all LAG interfaces based on commands"""
        es_payload = []
        request = None

        for cmd in commands:
            po_name = cmd['name']
            cmd_es = cmd.get('ethernet_segment')
            if cmd_es:
                have_po = search_obj_in_list(po_name, have, 'name')
                have_es = have_po.get('ethernet_segment', {}) if have_po else {}

                esi_type = cmd_es['esi_type'] if cmd_es.get('esi_type') else have_es.get('esi_type')
                esi = cmd_es.get('esi')
                if esi_type in ('auto_lacp', 'auto_system_mac'):
                    esi = 'AUTO'
                elif esi_type == 'ethernet_segment_id':
                    if not esi:
                        esi = have_es['esi']
                    esi = ''.join(esi.split(':'))
                esi_type = ESI_TYPE_VALUE_TO_PAYLOAD.get(esi_type)

                es_payload_item = {
                    'name': po_name,
                    'config': {
                        'name': po_name,
                        'esi-type' : esi_type,
                        'esi' : esi,
                        'interface': po_name
                    }
                }
                if cmd_es.get('df_preference'):
                    es_payload_item['df-election'] = {'config': {'preference': cmd_es['df_preference']}}

                es_payload.append(es_payload_item)

        if es_payload:
            payload = {
                'openconfig-network-instance:ethernet-segments': {
                    'ethernet-segment': es_payload
                }
            }
            request = {'path': self.eth_seg_path, 'method': PATCH, 'data': payload}

        return request

    def get_delete_all_lag_interfaces_requests(self):
        """Get requests to delete all LAG interfaces"""
        # 1) Delete all lag members
        # 2) Delete all lag interfaces
        requests = [
            {'path': 'data/sonic-portchannel:sonic-portchannel/PORTCHANNEL_MEMBER/PORTCHANNEL_MEMBER_LIST', 'method': DELETE},
            {'path': 'data/sonic-portchannel:sonic-portchannel/PORTCHANNEL/PORTCHANNEL_LIST', 'method': DELETE}
        ]
        return requests

    def get_delete_lag_interface_requests(self, command):
        """Get requests to delete the LAG interface specified in command"""
        requests = []
        lag_name = command['name']
        if command.get('ethernet_segment'):
            requests.append({'path': self.lag_interface_eth_seg_path.format(name=lag_name), 'method': DELETE})

        requests.append({'path': self.interface_path.format(name=lag_name), 'method': DELETE})
        return requests

    def get_delete_lag_interface_param_requests(self, command):
        """Get requests to delete LAG interface configurations specified
        in command"""
        requests = []
        patch_payload = {}
        lag_name = command['name']
        if command.get('members') and command['members'].get('interfaces'):
            for member in command['members']['interfaces']:
                requests.append({'path': self.lag_member_path.format(name=member['member']), "method": DELETE})

        if command.get('system_mac'):
            url = self.lag_interface_config_path['system_mac'].format(name=lag_name)
            requests.append({'path': url, 'method': DELETE})

        if command.get('ethernet_segment'):
            eth_seg = command['ethernet_segment']
            if eth_seg.get('esi_type'):
                if not eth_seg.get('esi') and eth_seg.get('df_preference'):
                    url = self.lag_interface_eth_seg_df_pref_path.format(name=lag_name)
                    requests.append({'path': url, 'method': DELETE})
                else:
                    url = self.lag_interface_eth_seg_path.format(name=lag_name)
                    requests.append({'path': url, 'method': DELETE})

        # Set to default value on delete
        for option in ('fallback', 'fast_rate'):
            if command.get(option):
                patch_payload[option.replace('_', '-')] = DEFAULT_VALUES[option]
        if command.get('graceful_shutdown'):
            patch_payload['graceful-shutdown-mode'] = 'DISABLE'
        if command.get('min_links'):
            patch_payload['min-links'] = DEFAULT_VALUES['min_links']
        if command.get('lacp_individual'):
            if command['lacp_individual'].get('enable'):
                patch_payload['lacp-individual'] = 'disable'
            if command['lacp_individual'].get('timeout'):
                patch_payload['lacp-individual-timeout'] = DEFAULT_VALUES['lacp_individual']['timeout']

        if patch_payload:
            url = self.lag_interface_config_root_path.format(name=lag_name)
            payload = {'openconfig-if-aggregate:config': patch_payload}
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        return requests

    def sort_config(self, configs):
        # natsort provides better result.
        # The use of natsort causes sanity error due to it is not available in
        # python version currently used.
        # new_config = natsorted(new_config, key=lambda x: x['name'])
        # For time-being, use simple "sort"
        configs.sort(key=lambda x: x['name'])

        for conf in configs:
            if conf.get('members', {}) and conf['members'].get('interfaces', []):
                conf['members']['interfaces'].sort(key=lambda x: x['member'])

    def validate_and_normalize_want(self, want, have):
        state = self._module.params['state']
        if not want:
            if state in ('overridden', 'merged', 'replaced'):
                self._module.fail_json(msg='value of config parameter must not be empty for state {0}'.format(state))
            return []

        if state != 'deleted':
            updated_want = remove_empties_from_list(want)
        else:
            # In state deleted, empty members -> interfaces is supported.
            updated_want = []
            for conf in want:
                delete_all_members = False
                if conf.get('members') and 'interfaces' in conf['members'] and not conf['members']['interfaces']:
                    delete_all_members = True
                updated_conf = remove_empties(conf)
                if updated_conf:
                    if delete_all_members:
                        updated_conf['members'] = {'interfaces': []}
                    updated_want.append(updated_conf)

        normalize_interface_name(updated_want, self._module)
        for conf in updated_want:
            have_obj = search_obj_in_list(conf['name'], have, 'name')
            if conf.get('mode'):
                if have_obj and conf['mode'] != have_obj['mode'] and state == 'merged':
                    self._module.fail_json(msg='cannot modify mode for existing portchannel: {1}'.format(conf['name']))
            elif state != 'deleted':
                # For new LAG interface, set default mode to 'lacp'
                if have_obj and state == 'merged':
                    conf['mode'] = have_obj['mode']
                else:
                    conf['mode'] = 'lacp'

            es = conf.get('ethernet_segment')
            if es:
                esi_type = es.get('esi_type')
                esi = es.get('esi')
                if esi_type:
                    if esi_type in ('auto_lacp', 'auto_system_mac'):
                        if esi and esi != 'AUTO':
                            self._module.fail_json(msg='value of esi must be "AUTO" for esi_type {0}'.format(esi_type))
                        if not esi and state != 'deleted':
                            es['esi'] = 'AUTO'
                    else:
                        if not esi and state != 'deleted':
                            self._module.fail_json(msg='value of esi must be provided for esi_type {0}'.format(esi_type))

            if conf.get('members') and conf['members'].get('interfaces'):
                for member in conf['members']['interfaces']:
                    if member.get('member'):
                        member['member'] = get_normalize_interface_name(member['member'], self._module)

        return updated_want

    @staticmethod
    def get_diff(base_cfg, compare_cfg):
        compare_cfg = deepcopy(compare_cfg)
        # Add default values, if not present
        for cfg in compare_cfg:
            for option in ('fallback', 'fast_rate', 'graceful_shutdown', 'min_links'):
                cfg.setdefault(option, DEFAULT_VALUES[option])

            if cfg.get('mode') == 'lacp':
                cfg.setdefault('lacp_individual', {})
                for option in ('enable', 'timeout'):
                    cfg['lacp_individual'].setdefault(option, DEFAULT_VALUES['lacp_individual'][option])

        return get_diff(base_cfg, compare_cfg, TEST_KEYS)

    @staticmethod
    def remove_defaults(conf):
        """Remove default values in given LAG interface configuration"""
        if conf:
            for option in ('fallback', 'fast_rate', 'graceful_shutdown', 'min_links'):
                if conf.get(option) == DEFAULT_VALUES[option]:
                    del conf[option]

            if conf.get('lacp_individual'):
                for option in ('enable', 'timeout'):
                    if conf['lacp_individual'].get(option) == DEFAULT_VALUES['lacp_individual'][option]:
                        del conf['lacp_individual'][option]

                if not conf['lacp_individual']:
                    del conf['lacp_individual']

    @staticmethod
    def get_member_names(conf):
        """Get a set of names of the members available in given LAG
        interface configuration"""
        member_names = set()
        if conf and conf.get('members') and conf['members'].get('interfaces'):
            for member in conf['members']['interfaces']:
                member_names.add(member['member'])
        return member_names

    @staticmethod
    def get_members_dict(member_names):
        """Get a members dict based on the given list of member names"""
        members_dict = {}
        if member_names:
            interfaces_list = []
            for member_name in member_names:
                interfaces_list.append({'member': member_name})
            members_dict['interfaces'] = interfaces_list

        return members_dict

    def __derive_lag_interface_delete_op(self, key_set, command, exist_conf):
        """Returns LAG interface's new configuration on delete operation"""
        new_conf = exist_conf
        if command:
            if len(command.keys()) == 1:
                return True, {}

            if 'members' in command:
                remaining_members = self.get_member_names(new_conf).difference(self.get_member_names(command))
                if remaining_members:
                    new_conf['members'] = self.get_members_dict(remaining_members)
                else:
                    del new_conf['members']

            if 'system_mac' in command:
                del new_conf['system_mac']

            if 'ethernet_segment' in command:
                eth_seg = command['ethernet_segment']
                # When esi_type and df_preference is specified without esi, then df_preference is only deleted.
                if eth_seg.get('df_preference') and not eth_seg.get('esi'):
                    del new_conf['ethernet_segment']['df_preference']
                else:
                    del new_conf['ethernet_segment']

            # Set to default value on delete
            for option in ('fallback', 'fast_rate', 'graceful_shutdown', 'min_links'):
                if option in command:
                    new_conf[option] = DEFAULT_VALUES[option]
            if 'lacp_individual' in command:
                for option in ('enable', 'timeout'):
                    if option in command['lacp_individual']:
                        new_conf['lacp_individual'][option] = DEFAULT_VALUES['lacp_individual'][option]

        return True, new_conf

    def get_new_config(self, commands, have):
        """Returns generated configuration based on commands and
        existing configuration"""
        key_set = [
            {'config': {'name': '', '__delete_op': self.__derive_lag_interface_delete_op}},
            {'interfaces': {'member': ''}}
        ]
        return get_new_config(commands, have, key_set)
