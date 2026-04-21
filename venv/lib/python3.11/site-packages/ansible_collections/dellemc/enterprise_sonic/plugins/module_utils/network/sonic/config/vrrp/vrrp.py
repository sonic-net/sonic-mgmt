#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_vrrp class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
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
    remove_matching_defaults,
    normalize_interface_name,
    get_normalize_interface_name,
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    get_new_config,
    get_formatted_config_diff,
    __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF,
    __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'patch'
DELETE = 'delete'

IPV4_PATH = '/openconfig-if-ip:ipv4/addresses/address=1.1.1.1/'
IPV6_PATH = '/openconfig-if-ip:ipv6/addresses/address=1::1/'

TEST_KEYS = [
    {'config': {'name': ''}},
    {'group': {'virtual_router_id': '', 'afi': ''}},
    {'virtual_address': {'address': ''}},
    {'track_interface': {'interface': '', 'priority_increment': ''}}
]

TEST_KEYS_formatted_diff = [
    {'config': {'name': '', '__delete_op': __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'group': {'virtual_router_id': '', 'afi': '', '__delete_op': __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'virtual_address': {'address': '', '__delete_op': __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'track_interface': {'interface': '', '__delete_op': __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF}}
]

DEFAULT_ENTRIES = [
    [
        {'name': 'group'},
        {'name': 'priority', 'default': 100}
    ],
    [
        {'name': 'group'},
        {'name': 'preempt', 'default': True}
    ],
    [
        {'name': 'group'},
        {'name': 'advertisement_interval', 'default': 1}
    ],
    [
        {'name': 'group'},
        {'name': 'version', 'default': 2}
    ],
    [
        {'name': 'group'},
        {'name': 'use_v2_checksum', 'default': False}
    ],
]

DEFAULT_ATTRIBUTES = {
    'priority': 100,
    'preempt': True,
    'advertisement_interval': 1,
    'version': 2,
    'use_v2_checksum': False
}


class Vrrp(ConfigBase):
    """
    The sonic_vrrp class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'vrrp',
    ]

    vrrp_path = 'data/openconfig-interfaces:interfaces/interface={intf_name}'
    vrrp_vlan_path = vrrp_path + '/openconfig-vlan:routed-vlan'
    vrrp_intf_path = vrrp_path + '/subinterfaces/subinterface={intf_index}'

    vrrp_config_path = {
        'virtual_router_id': 'vrrp',
        'preempt': 'vrrp/vrrp-group={vrid}/config/preempt',
        'use_v2_checksum': 'vrrp/vrrp-group={vrid}/config/openconfig-interfaces-ext:use-v2-checksum',
        'priority': 'vrrp/vrrp-group={vrid}/config/priority',
        'advertisement_interval': 'vrrp/vrrp-group={vrid}/config/advertisement-interval',
        'version': 'vrrp/vrrp-group={vrid}/config/openconfig-interfaces-ext:version',
        'virtual_address': 'vrrp/vrrp-group={vrid}/config/virtual-address',
        'track_interface': 'vrrp/vrrp-group={vrid}/openconfig-interfaces-ext:vrrp-track'
    }

    vrrp_attributes = ('preempt', 'version', 'use_v2_checksum', 'priority', 'advertisement_interval', 'virtual_address', 'track_interface')

    def __init__(self, module):
        super(Vrrp, self).__init__(module)

    def get_vrrp_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        vrrp_facts = facts['ansible_network_resources'].get('vrrp')
        if not vrrp_facts:
            return []
        return vrrp_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        existing_vrrp_facts = self.get_vrrp_facts()
        commands, requests = self.set_config(existing_vrrp_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True

        result['before'] = existing_vrrp_facts
        old_config = existing_vrrp_facts

        if self._module.check_mode:
            result.pop('after', None)
            new_config = self._get_generated_config(commands, existing_vrrp_facts, self._module.params['state'])
            self.sort_lists_in_config(new_config)
            result['after(generated)'] = new_config
        else:
            changed_vrrp_facts = self.get_vrrp_facts()
            new_config = changed_vrrp_facts
            self.sort_lists_in_config(new_config)
            if result['changed']:
                result['after'] = changed_vrrp_facts

        if self._module._diff:
            self.sort_lists_in_config(old_config)
            self.sort_lists_in_config(new_config)
            result['diff'] = get_formatted_config_diff(old_config, new_config, self._module._verbosity)

        result['commands'] = commands
        result['warnings'] = warnings
        return result

    def set_config(self, existing_vrrp_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_vrrp_facts
        if want:
            want = remove_empties_from_list(want)
            normalize_interface_name(want, self._module)
            for config in want:
                if config.get('group'):
                    for group in config['group']:
                        track_intf = group.get('track_interface', [])
                        for track in track_intf:
                            track['interface'] = get_normalize_interface_name(track['interface'], self._module)
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
        commands = []
        requests = []
        state = self._module.params['state']

        if state in ('overridden', 'replaced'):
            commands, requests = self._state_replaced_or_overridden(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)
        return commands, requests

    def _state_replaced_or_overridden(self, want, have):
        """ The command generator when state is replaced or overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, requests = [], []
        state = self._module.params['state']
        add_config, del_config, del_requests = self._get_replaced_overridden_config(want, have, state)
        if del_config and len(del_requests) > 0:
            requests.extend(del_requests)
            commands.extend(update_states(del_config, 'deleted'))

        if add_config:
            mod_requests = self.get_create_vrrp_requests(add_config)
            if len(mod_requests) > 0:
                requests.extend(mod_requests)
                commands.extend(update_states(add_config, state))

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = remove_empties_from_list(get_diff(want, have))
        requests = self.get_create_vrrp_requests(commands)

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
        is_delete_all = False
        if not want:
            new_want = self.get_all_vrrps(have)
            is_delete_all = True
        else:
            new_want = deepcopy(want)
            for default_entry in DEFAULT_ENTRIES:
                remove_matching_defaults(new_want, default_entry)
            new_want = remove_empties_from_list(new_want)

        commands, requests = self.get_delete_vrrp_commands_requests(new_want, have, is_delete_all)

        if commands and len(requests) > 0:
            commands = update_states(commands, 'deleted')
        else:
            commands = []

        return commands, requests

    def _get_replaced_overridden_config(self, want, have, state):
        add_config, del_config = [], []
        del_requests = []
        for cmd in want:
            name = cmd.get('name')
            groups = cmd.get('group', [])
            match = next((m for m in have if m['name'] == name), None)

            if not match:
                add_config.append(cmd)
            else:
                add_cfg, del_cfg = {}, {}
                for group in groups:
                    vr_id = group.get('virtual_router_id')
                    afi = group.get('afi')
                    match_group = next((g for g in match['group'] if g['virtual_router_id'] == vr_id and g['afi'] == afi), None)
                    if not match_group:
                        add_cfg.setdefault('group', []).append(group)
                    else:
                        add_group, del_group = {}, {}
                        for attr in self.vrrp_attributes:
                            if attr in group:
                                if attr not in match_group:
                                    add_group[attr] = group[attr]
                                elif group[attr] != match_group[attr]:
                                    if attr == 'virtual_address':
                                        add_vip, del_vip = [], []
                                        want_vip = set(self.get_vip_addresses(group[attr]))
                                        match_vip = set(self.get_vip_addresses(match_group[attr]))
                                        for vip in want_vip.difference(match_vip):
                                            add_vip.append({'address': vip})
                                        for vip in match_vip.difference(want_vip):
                                            del_vip.append({'address': vip})
                                        if add_vip:
                                            add_group[attr] = add_vip
                                        if del_vip:
                                            del_group[attr] = del_vip
                                    elif attr == 'track_interface':
                                        add_track, del_track = [], []
                                        for track in group[attr]:
                                            match_track = next((t for t in match_group[attr] if t['interface'] == track['interface']), None)
                                            if not match_track:
                                                add_track.append(track)
                                            elif track['priority_increment'] != match_track['priority_increment']:
                                                add_track.append(track)
                                                del_track.append(match_track)
                                        for match_track in match_group[attr]:
                                            track = next((t for t in group[attr] if t['interface'] == match_track['interface']), None)
                                            if not track:
                                                del_track.append(match_track)
                                        if add_track:
                                            add_group[attr] = add_track
                                        if del_track:
                                            del_group[attr] = del_track
                                    else:
                                        add_group[attr] = group[attr]
                            elif attr in match_group:
                                if attr not in DEFAULT_ATTRIBUTES or match_group[attr] != DEFAULT_ATTRIBUTES[attr]:
                                    del_group[attr] = match_group[attr]
                        if add_group:
                            add_group['virtual_router_id'] = vr_id
                            add_group['afi'] = afi
                            add_cfg.setdefault('group', []).append(add_group)
                        if del_group:
                            del_group['virtual_router_id'] = vr_id
                            del_group['afi'] = afi
                            del_cfg.setdefault('group', []).append(del_group)
                            commands, requests = self.get_delete_specific_vrrp_param_commands_requests(match_group, vr_id, del_group, name)
                            if commands:
                                del_requests.extend(requests)
                if add_cfg:
                    add_cfg['name'] = name
                    add_config.append(add_cfg)
                if del_cfg:
                    del_cfg['name'] = name
                    del_config.append(del_cfg)

        if state == 'overridden':
            for conf in have:
                name = conf['name']
                want_conf = next((w for w in want if w['name'] == name), None)

                if not want_conf:
                    del_config.append({'name': name})
                    commands, requests = self.get_delete_all_vrrp_groups_commands_requests(conf.get('group', []), name)
                    if commands:
                        del_requests.extend(requests)
                else:
                    del_cfg = {}
                    for group in conf['group']:
                        vr_id = group.get('virtual_router_id')
                        afi = group.get('afi')
                        want_groups = [] if want_conf.get('group') is None else want_conf['group']
                        match_group = next((g for g in want_groups if g['virtual_router_id'] == vr_id and g['afi'] == afi), None)
                        if not match_group:
                            del_cfg.setdefault('group', []).append({'virtual_router_id': vr_id, 'afi': afi})
                            commands, requests = self.get_delete_vrrp_group_command_request(name, group)
                            if commands:
                                del_requests.extend(requests)
                    if del_cfg:
                        if not any(cfg.get('name') == name for cfg in del_config):
                            del_cfg['name'] = name
                            del_config.append(del_cfg)
                        else:
                            for cfg in del_config:
                                if cfg['name'] == name:
                                    cfg['group'].append(del_cfg)
                                    break
        return add_config, del_config, del_requests

    def get_create_vrrp_requests(self, commands):
        """ Get list of requests to create/modify VRRP and VRRP6 configurations
        for all interfaces specified by the commands
        """
        requests = []

        if not commands:
            return requests

        for cmd in commands:
            name = cmd.get('name', None)
            group_list = cmd.get('group', [])
            if group_list:
                for group in group_list:
                    virtual_router_id = group.get('virtual_router_id', None)
                    if 'Vlan' in name:
                        keypath = self.vrrp_vlan_path.format(intf_name=name)
                    else:
                        parent_intf, sub_intf = name.split('.') if '.' in name else (name, 0)
                        keypath = self.vrrp_intf_path.format(intf_name=parent_intf, intf_index=sub_intf)
                    requests.extend(self.get_create_specific_vrrp_param_requests(virtual_router_id, group, keypath))

        return requests

    def get_create_specific_vrrp_param_requests(self, virtual_router_id, group, keypath):
        """ Get list of requests to create/modify VRRP and VRRP6 configurations
        based on the command specified for the interface
        """
        requests = []

        afi = group.get('afi')
        ip_path = IPV4_PATH if afi == 'ipv4' else IPV6_PATH
        vip_addresses = self.get_vip_addresses(group.get('virtual_address'))
        preempt = group.get('preempt')
        advertisement_interval = group.get('advertisement_interval')
        priority = group.get('priority')
        version = group.get('version')
        use_v2_checksum = group.get('use_v2_checksum')
        track_interfaces = self.get_track_interfaces(group.get('track_interface'))
        if not virtual_router_id or not afi:
            return requests

        def update_requests(attr, payload):
            url = keypath + ip_path + self.vrrp_config_path[attr].format(vrid=virtual_router_id)
            return {'path': url, 'method': PATCH, 'data': payload}

        payload = {
            'openconfig-if-ip:vrrp': {
                'vrrp-group':
                [
                    {
                        'virtual-router-id': virtual_router_id,
                        'config': {'virtual-router-id': virtual_router_id}
                    }
                ]
            }
        }

        url = keypath + ip_path + self.vrrp_config_path['virtual_router_id']

        requests.append({'path': url, 'method': PATCH, 'data': payload})

        if vip_addresses:
            requests.append(update_requests('virtual_address', {'openconfig-if-ip:virtual-address': vip_addresses}))

        if preempt is not None:
            requests.append(update_requests('preempt', {'openconfig-if-ip:preempt': preempt}))

        if advertisement_interval:
            requests.append(update_requests('advertisement_interval', {'openconfig-if-ip:advertisement-interval': advertisement_interval}))

        if priority:
            requests.append(update_requests('priority', {'openconfig-if-ip:priority': priority}))

        if version:
            requests.append(update_requests('version', {'openconfig-interfaces-ext:version': version}))

        if use_v2_checksum is not None:
            requests.append(update_requests('use_v2_checksum', {'openconfig-if-ip:use-v2-checksum': use_v2_checksum}))

        if track_interfaces:
            for track in track_interfaces:
                payload = {
                    'openconfig-interfaces-ext:vrrp-track': {
                        'vrrp-track-interface': [
                            {
                                'track-intf': track['interface'],
                                'config': {
                                    'track-intf': track['interface'],
                                    'priority-increment': int(track['priority_increment']),
                                },
                            }
                        ]
                    }
                }
                requests.append(update_requests('track_interface', payload))
        return requests

    def get_delete_vrrp_commands_requests(self, want, have, is_delete_all):
        """ Get list of requests to delete VRRP and VRRP6 configurations
        for all interfaces specified by the commands
        """
        commands, requests = [], []
        for cmd in want:
            del_cmd = {}
            name = cmd.get('name')
            match_have = next((cnf for cnf in have if cnf['name'] == name), None)
            group_list = [] if cmd.get('group') is None else cmd['group']

            if is_delete_all:
                if match_have:
                    if match_have.get('group'):
                        del_group, request = self.get_delete_all_vrrp_groups_commands_requests(match_have['group'], name)
                        if del_group:
                            commands.append({'name': name})
                            requests.extend(request)
            else:
                del_groups = []
                match_group_list = [] if not match_have else match_have.get('group', [])
                if group_list:
                    for group in group_list:
                        del_group = {}
                        virtual_router_id = group.get('virtual_router_id')
                        afi = group.get('afi')
                        match_group = next((g for g in match_group_list if g['virtual_router_id'] == virtual_router_id and g['afi'] == afi), None)
                        if match_group:
                            del_group = None
                            if len(group.keys()) == 2:
                                del_group, request = self.get_delete_vrrp_group_command_request(name, group)
                            else:
                                del_group, request = self.get_delete_specific_vrrp_param_commands_requests(match_group, virtual_router_id, group, name)

                            if del_group:
                                del_groups.append(del_group)
                                requests.extend(request)
                    if del_groups:
                        del_cmd['group'] = del_groups
                elif match_group_list:
                    del_group, request = self.get_delete_all_vrrp_groups_commands_requests(match_group_list, name)
                    if del_group:
                        commands.append({'name': name})
                        requests.extend(request)

            if del_cmd:
                del_cmd['name'] = name
                commands.append(del_cmd)
        return commands, requests

    def get_delete_all_vrrp_groups_commands_requests(self, groups, intf_name):
        commands, requests, last_vrrp = [], [], []
        groups = [] if groups is None else groups
        for group in groups:
            virtual_router_id = group.get('virtual_router_id')
            # VRRP with VRRP ID 1 can be removed only if other VRRP
            # groups are removed first
            # Hence the check
            command, request = self.get_delete_vrrp_group_command_request(intf_name, group)
            if command:
                commands.append(command)
                if virtual_router_id == 1:
                    last_vrrp.extend(request)
                else:
                    requests.extend(request)
        if last_vrrp:
            requests.extend(last_vrrp)

        return commands, requests

    def get_delete_vrrp_group_command_request(self, intf_name, group):
        """ Get list of requests to delete the entire VRRP and VRRP6 group configurations
        based on the specified interface
        """
        command, request = [], []
        virtual_router_id = group.get('virtual_router_id')
        afi = group.get('afi')
        if not virtual_router_id or not afi:
            return command, request

        ip_path = IPV4_PATH if afi == 'ipv4' else IPV6_PATH
        if 'Vlan' in intf_name:
            keypath = self.vrrp_vlan_path.format(intf_name=intf_name)
        else:
            parent_intf, sub_intf = intf_name.split('.') if '.' in intf_name else (intf_name, 0)
            keypath = self.vrrp_intf_path.format(intf_name=parent_intf, intf_index=sub_intf)
        url = '{0}{1}vrrp/vrrp-group={2}'.format(keypath, ip_path, virtual_router_id)

        track_interfaces = self.get_track_interfaces(group.get('track_interface'))

        for track_intf in track_interfaces:
            if track_intf.get('interface'):
                track_url = url + "/openconfig-interfaces-ext:vrrp-track/vrrp-track-interface={0}".format(track_intf.get('interface'))
                request.append({'path': track_url, 'method': DELETE})

        command = {'virtual_router_id': virtual_router_id, 'afi': afi}
        request.append({'path': url, 'method': DELETE})

        return command, request

    def get_delete_specific_vrrp_param_commands_requests(self, cfg_group, virtual_router_id, group, intf_name):
        """ Get list of requests to delete VRRP and VRRP6 configurations
        based on the command specified for the interface
        """
        commands, requests = {}, []

        afi = group['afi']
        vip_addresses = self.get_vip_addresses(group.get('virtual_address'))
        ip_path = IPV4_PATH if afi == 'ipv4' else IPV6_PATH
        track_interfaces = self.get_track_interfaces(group.get('track_interface'))

        if not virtual_router_id or not afi:
            return commands, requests

        cfg_vip_addresses = self.get_vip_addresses(cfg_group.get('virtual_address'))
        cfg_track_interfaces = self.get_track_interfaces(cfg_group.get('track_interface'))

        if 'Vlan' in intf_name:
            keypath = self.vrrp_vlan_path.format(intf_name=intf_name)
        else:
            parent_intf, sub_intf = intf_name.split('.') if '.' in intf_name else (intf_name, 0)
            keypath = self.vrrp_intf_path.format(intf_name=parent_intf, intf_index=sub_intf)

        if vip_addresses and cfg_vip_addresses:
            del_vip_list = []
            for addr in set(vip_addresses).intersection(set(cfg_vip_addresses)):
                del_url = keypath + ip_path + self.vrrp_config_path['virtual_address'].format(vrid=virtual_router_id) + '=' + addr
                del_vip_list.append({'address': addr})
                requests.append({'path': del_url, 'method': DELETE})
            if del_vip_list:
                commands['virtual_address'] = del_vip_list

        for attr in ('preempt', 'advertisement_interval', 'priority', 'version', 'use_v2_checksum'):
            if group.get(attr) is not None and cfg_group.get(attr) is not None and group[attr] == cfg_group[attr]:
                requests.append({'path': keypath + ip_path + self.vrrp_config_path[attr].format(vrid=virtual_router_id), 'method': DELETE})
                commands[attr] = group[attr]

        if track_interfaces and cfg_track_interfaces:
            del_track_list = []
            for track in track_interfaces:
                interface = track['interface']
                for cfg_track in cfg_track_interfaces:
                    cfg_interface = cfg_track['interface']
                    if interface == cfg_interface:
                        track_url = self.vrrp_config_path['track_interface'].format(vrid=virtual_router_id) + '/vrrp-track-interface=' + interface
                        requests.append({'path': keypath + ip_path + track_url, 'method': DELETE})
                        del_track_list.append({'interface': track['interface'], 'priority_increment': track.get('priority_increment')})
            if del_track_list:
                commands['track_interface'] = del_track_list
        if commands:
            commands['virtual_router_id'] = virtual_router_id
            commands['afi'] = afi
        return commands, requests

    def sort_lists_in_config(self, config):
        if config:
            config.sort(key=lambda x: x['name'])
            for cfg in config:
                if cfg.get('group'):
                    cfg['group'].sort(key=lambda x: (x['virtual_router_id'], x['afi']))
                    for group in cfg['group']:
                        if group.get('virtual_address'):
                            group['virtual_address'].sort(key=lambda x: x['address'])
                        if group.get('track_interface'):
                            group['track_interface'].sort(key=lambda x: x['interface'])

    @staticmethod
    def get_vip_addresses(vip_addresses_list):
        """ Get a set of virtual IP/IPv6 addresses available in the given
        vip_addresses list
        """
        vip_addresses = []
        if not vip_addresses_list:
            return vip_addresses

        for addr in vip_addresses_list:
            if addr.get('address'):
                vip_addresses.append(addr['address'])

        return vip_addresses

    @staticmethod
    def get_track_interfaces(track_interfaces_list):
        """ Get a set of track interface groups available in the given
        track_interfaces list
        """
        track_interfaces = []
        if not track_interfaces_list:
            return track_interfaces

        for track_interface in track_interfaces_list:
            if track_interface['interface'] and track_interface['priority_increment']:
                track_interfaces.append(track_interface)

        return track_interfaces

    @staticmethod
    def _get_generated_config(commands, have, state):
        """Get generated config"""
        new_config = remove_empties_from_list(get_new_config(commands, have, TEST_KEYS_formatted_diff))
        if new_config:
            for conf in new_config:
                # Add default values for after(generated)
                groups = conf.get('group', [])
                for group in groups:
                    afi = group.get('afi')
                    for option in DEFAULT_ATTRIBUTES:
                        if option not in group:
                            if afi == 'ipv6' and option in ('use_v2_checksum', 'version'):
                                continue
                            group[option] = DEFAULT_ATTRIBUTES[option]
        return new_config

    @staticmethod
    def get_all_vrrps(have):
        vrrp_groups = []
        for cmd in have:
            name = cmd.get('name')
            vrrp_groups.append({'name': name})
        return vrrp_groups
