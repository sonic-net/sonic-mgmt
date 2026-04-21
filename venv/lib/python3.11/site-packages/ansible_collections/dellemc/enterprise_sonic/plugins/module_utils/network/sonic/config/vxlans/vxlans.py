#
# -*- coding: utf-8 -*-
# © Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_vxlans class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    update_states,
    get_replaced_config,
    remove_empties_from_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_CONFIG_IF_NO_SUBCONFIG,
    get_new_config,
    get_formatted_config_diff
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'patch'
DELETE = 'delete'
TEST_KEYS = [
    {'vlan_map': {'vlan': '', 'vni': ''}},
    {'vrf_map': {'vni': '', 'vrf': ''}},
    {'suppress_vlan_neigh': {'vlan_name': ''}},
]
test_keys_generate_config = [
    {'config': {'name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'vlan_map': {'vlan': '', 'vni': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'vrf_map': {'vni': '', 'vrf': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    ['suppress_vlan_neigh', {'vlan_name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}],
]


class Vxlans(ConfigBase):
    """
    The sonic_vxlans class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'vxlans',
    ]

    def __init__(self, module):
        super(Vxlans, self).__init__(module)

    def get_vxlans_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        vxlans_facts = facts['ansible_network_resources'].get('vxlans')
        if not vxlans_facts:
            return []
        return vxlans_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}

        existing_vxlans_facts = self.get_vxlans_facts()
        commands, requests = self.set_config(existing_vxlans_facts)

        if commands and requests:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_vxlans_facts = self.get_vxlans_facts()

        result['before'] = existing_vxlans_facts
        if result['changed']:
            result['after'] = changed_vxlans_facts

        new_config = changed_vxlans_facts
        old_config = existing_vxlans_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_vxlans_facts,
                                        test_keys_generate_config)
            new_config = self.post_process_generated_config(new_config)
            result['after(generated)'] = new_config

        if self._module._diff:
            self.sort_lists_in_config(new_config)
            self.sort_lists_in_config(old_config)
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)
        return result

    def set_config(self, existing_vxlans_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_vxlans_facts
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

        if state == 'overridden':
            commands, requests = self._state_overridden(want, have, diff)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(have, diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have, diff)

        return commands, requests

    def _state_replaced(self, want, have, diff):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, requests = [], []
        replaced_config = get_replaced_config(want, have, TEST_KEYS)

        if replaced_config:
            self.sort_lists_in_config(replaced_config)
            self.sort_lists_in_config(have)
            is_delete_all = replaced_config == have
            if is_delete_all:
                del_requests = self.get_delete_all_vxlan_request(have)
                have = []
            else:
                del_requests = self.get_delete_vxlan_request(replaced_config, have)

            requests.extend(del_requests)
            commands.extend(update_states(replaced_config, 'deleted'))
            commands = want
        else:
            commands = diff

        if commands:
            requests.extend(self.get_create_vxlans_request(commands, have))
            if len(requests) > 0:
                commands.extend(update_states(commands, "replaced"))

        return commands, requests

    def _state_overridden(self, want, have, diff):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, requests = [], []
        mod_commands, mod_requests = None, None
        del_commands = get_diff(have, want, TEST_KEYS)

        if del_commands:
            del_requests = self.get_delete_all_vxlan_request(have)
            requests.extend(del_requests)
            commands.extend(update_states(have, 'deleted'))
            have = []
            mod_commands = want
            mod_requests = self.get_create_vxlans_request(mod_commands, have)
        elif diff:
            mod_commands = diff
            mod_requests = self.get_create_vxlans_request(mod_commands, have)

        if mod_requests:
            requests.extend(mod_requests)
            commands.extend(update_states(mod_commands, 'overridden'))

        return commands, requests

    def _state_merged(self, have, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration at position-0
                  Requests necessary to merge to the current configuration
                  at position-1
        """
        commands = diff
        requests = self.get_create_vxlans_request(commands, have)

        if len(requests) == 0:
            commands = []

        if commands:
            commands = update_states(commands, "merged")

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """

        requests = []
        is_delete_all = False
        # if want is none, then delete all the vxlans
        if not want or len(have) == 0:
            commands = have
            is_delete_all = True
        else:
            commands = want

        if is_delete_all:
            requests = self.get_delete_all_vxlan_request(have)
        else:
            requests = self.get_delete_vxlan_request(commands, have)

        if len(requests) == 0:
            commands = []

        if commands:
            commands = update_states(commands, "deleted")

        return commands, requests

    def get_create_vxlans_request(self, configs, have):
        requests = []

        if not configs:
            return requests

        tunnel_requests = self.get_create_tunnel_request(configs, have)
        vlan_map_requests = self.get_create_vlan_map_request(configs, have)
        vrf_map_requests = self.get_create_vrf_map_request(configs, have)
        suppress_vlan_neigh_requests = self.get_create_suppress_vlan_neigh_request(configs)

        if tunnel_requests:
            requests.extend(tunnel_requests)
        if vlan_map_requests:
            requests.extend(vlan_map_requests)
        if vrf_map_requests:
            requests.extend(vrf_map_requests)
        if suppress_vlan_neigh_requests:
            requests.extend(suppress_vlan_neigh_requests)

        return requests

    def get_delete_all_vxlan_request(self, have):
        requests = []

        # Need to delete in reverse order of creation.
        # vrf_map needs to be cleared before vlan_map
        # vlan_map needs to be cleared before tunnel(source-ip)
        for conf in have:
            name = conf['name']
            suppress_vlan_neigh_list = conf.get('suppress_vlan_neigh', [])
            vlan_map_list = conf.get('vlan_map', [])
            vrf_map_list = conf.get('vrf_map', [])
            src_ip = conf.get('source_ip')
            primary_ip = conf.get('primary_ip')
            external_ip = conf.get('external_ip')
            evpn_nvo = conf.get('evpn_nvo')

            if suppress_vlan_neigh_list:
                requests.extend(self.get_delete_suppress_vlan_neigh_request(conf, suppress_vlan_neigh_list))
            if vrf_map_list:
                requests.extend(self.get_delete_vrf_map_request(conf, vrf_map_list))
            if vlan_map_list:
                requests.extend(self.get_delete_vlan_map_request(conf, name, vlan_map_list))
            if src_ip:
                requests.extend(self.get_delete_src_ip_request(conf, name, src_ip))
            if primary_ip:
                requests.extend(self.get_delete_primary_ip_request(conf, name, primary_ip))
            if external_ip:
                requests.extend(self.get_delete_external_ip_request(conf, name, external_ip))
            if evpn_nvo:
                requests.extend(self.get_delete_evpn_request(conf, conf, evpn_nvo))
            requests.extend(self.get_delete_tunnel_request(name))

        return requests

    def get_delete_vxlan_request(self, configs, have):
        requests = []

        if not configs:
            return requests

        # Need to delete in the reverse order of creation.
        # vrf_map needs to be cleared before vlan_map
        # vlan_map needs to be cleared before tunnel(source-ip)
        for conf in configs:

            name = conf['name']
            src_ip = conf.get('source_ip')
            evpn_nvo = conf.get('evpn_nvo')
            primary_ip = conf.get('primary_ip')
            external_ip = conf.get('external_ip')
            vlan_map_list = conf.get('vlan_map')
            vrf_map_list = conf.get('vrf_map')
            suppress_vlan_neigh_list = conf.get('suppress_vlan_neigh')

            matched = next((each_vxlan for each_vxlan in have if each_vxlan['name'] == name), None)

            is_delete_full = False
            if (name and vlan_map_list is None and vrf_map_list is None and
                    src_ip is None and evpn_nvo is None and primary_ip is None and
                    external_ip is None and suppress_vlan_neigh_list is None):
                is_delete_full = True
                vrf_map_list = matched.get("vrf_map", [])
                vlan_map_list = matched.get("vlan_map", [])
                suppress_vlan_neigh_list = matched.get("suppress_vlan_neigh", [])

            if vlan_map_list is not None and len(vlan_map_list) == 0 and matched:
                vlan_map_list = matched.get("vlan_map", [])
            if vrf_map_list is not None and len(vrf_map_list) == 0 and matched:
                vrf_map_list = matched.get("vrf_map", [])
            if suppress_vlan_neigh_list is not None and len(suppress_vlan_neigh_list) == 0 and matched:
                suppress_vlan_neigh_list = matched.get("suppress_vlan_neigh", [])

            if suppress_vlan_neigh_list:
                requests.extend(self.get_delete_suppress_vlan_neigh_request(matched, suppress_vlan_neigh_list))
            if vrf_map_list:
                requests.extend(self.get_delete_vrf_map_request(matched, vrf_map_list))
            if vlan_map_list:
                requests.extend(self.get_delete_vlan_map_request(matched, name, vlan_map_list))
            if src_ip:
                requests.extend(self.get_delete_src_ip_request(matched, name, src_ip))
            if evpn_nvo:
                requests.extend(self.get_delete_evpn_request(conf, matched, evpn_nvo))
            if primary_ip:
                requests.extend(self.get_delete_primary_ip_request(matched, name, primary_ip))
            if external_ip:
                requests.extend(self.get_delete_external_ip_request(matched, name, external_ip))
            if is_delete_full:
                requests.extend(self.get_delete_tunnel_request(name))

        return requests

    @staticmethod
    def get_create_evpn_request(evpn_nvo, name):
        # Create URL and payload
        url = "data/sonic-vxlan:sonic-vxlan/EVPN_NVO/EVPN_NVO_LIST"
        evpn_nvo_list = [{'name': evpn_nvo, 'source_vtep': name}]
        payload = {'sonic-vxlan:EVPN_NVO_LIST': evpn_nvo_list}
        request = {"path": url, "method": PATCH, "data": payload}

        return request

    def get_create_tunnel_request(self, configs, have):
        # Create URL and payload
        requests = []
        url = "data/sonic-vxlan:sonic-vxlan/VXLAN_TUNNEL"
        have_evpn_nvo_dict = {conf.get('name'): conf['evpn_nvo'] for conf in have if conf.get('evpn_nvo')}

        for conf in configs:
            vtep_ip_dict = {}
            vtep_ip_dict['name'] = conf['name']

            if conf.get('source_ip'):
                vtep_ip_dict['src_ip'] = conf['source_ip']
            if conf.get('primary_ip'):
                vtep_ip_dict['primary_ip'] = conf['primary_ip']
            if conf.get('external_ip'):
                vtep_ip_dict['external_ip'] = conf['external_ip']
            if vtep_ip_dict:
                payload = {'sonic-vxlan:VXLAN_TUNNEL': {'VXLAN_TUNNEL_LIST': [vtep_ip_dict]}}
                request = {"path": url, "method": PATCH, "data": payload}
                requests.append(request)
            if conf.get('evpn_nvo'):
                requests.append(self.get_create_evpn_request(conf['evpn_nvo'], conf['name']))
            # Create evpn_nvo if not specified or not already configured when source_ip is specified
            elif conf.get('source_ip') and not have_evpn_nvo_dict.get(conf['name']):
                requests.append(self.get_create_evpn_request('nvo1', conf['name']))

        return requests

    def get_create_vlan_map_request(self, configs, have):
        # Create URL and payload
        requests = []
        for conf in configs:
            new_vlan_map_list = conf.get('vlan_map', [])
            if new_vlan_map_list:
                for each_vlan_map in new_vlan_map_list:
                    name = conf['name']
                    vlan = each_vlan_map.get('vlan')
                    vni = each_vlan_map.get('vni')
                    matched = next((each_vxlan for each_vxlan in have if each_vxlan['name'] == name), None)

                    is_change_needed = True
                    if matched:
                        matched_vlan_map_list = matched.get('vlan_map', [])
                        if matched_vlan_map_list:
                            matched_vlan_map = next((e_vlan_map for e_vlan_map in matched_vlan_map_list if e_vlan_map['vni'] == vni), None)
                            if matched_vlan_map:
                                if matched_vlan_map['vlan'] == vlan:
                                    is_change_needed = False

                    if is_change_needed:
                        payload = self.build_create_vlan_map_payload(conf, each_vlan_map)
                        url = "data/sonic-vxlan:sonic-vxlan/VXLAN_TUNNEL_MAP"
                        request = {"path": url, "method": PATCH, "data": payload}
                        requests.append(request)

        return requests

    def build_create_vlan_map_payload(self, conf, vlan_map):
        payload_url, vlan_map_dict = {}, {}
        vlan_map_dict['name'] = conf['name']
        vlan_map_dict['mapname'] = f"map_{vlan_map['vni']}_Vlan{vlan_map['vlan']}"
        vlan_map_dict['vlan'] = f"Vlan{vlan_map['vlan']}"
        vlan_map_dict['vni'] = vlan_map['vni']

        payload_url['sonic-vxlan:VXLAN_TUNNEL_MAP'] = {'VXLAN_TUNNEL_MAP_LIST': [vlan_map_dict]}

        return payload_url

    def get_create_vrf_map_request(self, configs, have):
        # Create URL and payload
        requests = []
        for conf in configs:
            new_vrf_map_list = conf.get('vrf_map', [])
            if new_vrf_map_list:
                for each_vrf_map in new_vrf_map_list:
                    name = conf['name']
                    vrf = each_vrf_map.get('vrf')
                    vni = each_vrf_map.get('vni')
                    matched = next((each_vxlan for each_vxlan in have if each_vxlan['name'] == name), None)

                    is_change_needed = True
                    if matched:
                        matched_vrf_map_list = matched.get('vrf_map', [])
                        if matched_vrf_map_list:
                            matched_vrf_map = next((e_vrf_map for e_vrf_map in matched_vrf_map_list if e_vrf_map['vni'] == vni), None)
                            if matched_vrf_map:
                                if matched_vrf_map['vrf'] == vrf:
                                    is_change_needed = False

                    if is_change_needed:
                        payload = self.build_create_vrf_map_payload(each_vrf_map)
                        url = f"data/sonic-vrf:sonic-vrf/VRF/VRF_LIST={vrf}/vni"
                        request = {"path": url, "method": PATCH, "data": payload}
                        requests.append(request)

        return requests

    def build_create_vrf_map_payload(self, vrf_map):
        payload_url = {"sonic-vrf:vni": vrf_map['vni']}
        return payload_url

    def get_create_suppress_vlan_neigh_request(self, configs):
        # Create URL and payload
        requests, vlan_list = [], []
        payload = {}

        for conf in configs:
            new_suppress_vlan_neigh_list = conf.get('suppress_vlan_neigh', [])
            if new_suppress_vlan_neigh_list:
                for each_suppress_vlan_neigh in new_suppress_vlan_neigh_list:
                    vlan_name = each_suppress_vlan_neigh.get('vlan_name')
                    vlan_list.append(vlan_name)

                payload.update(self.build_create_suppress_vlan_neigh_payload(vlan_list))
                url = "data/sonic-vxlan:sonic-vxlan/SUPPRESS_VLAN_NEIGH"
                request = {"path": url, "method": PATCH, "data": payload}
                requests.append(request)

        return requests

    def build_create_suppress_vlan_neigh_payload(self, vlan_list):
        payload_url = {}
        vlans = []

        for vlan in vlan_list:
            suppress_vlan_neigh_dict = {}
            suppress_vlan_neigh_dict['name'] = vlan
            suppress_vlan_neigh_dict['suppress'] = 'on'
            vlans.append(suppress_vlan_neigh_dict)
        payload_url['sonic-vxlan:SUPPRESS_VLAN_NEIGH'] = {'SUPPRESS_VLAN_NEIGH_LIST': vlans}
        return payload_url

    def get_delete_evpn_request(self, conf, matched, del_evpn_nvo):
        # Create URL and payload
        requests = []

        url = "data/sonic-vxlan:sonic-vxlan/EVPN_NVO/EVPN_NVO_LIST={evpn_nvo}"

        is_change_needed = False
        if matched:
            matched_evpn_nvo = matched.get('evpn_nvo', None)
            if matched_evpn_nvo and matched_evpn_nvo == del_evpn_nvo:
                is_change_needed = True

        if is_change_needed:
            request = {"path": url.format(evpn_nvo=conf['evpn_nvo']), "method": DELETE}
            requests.append(request)

        return requests

    def get_delete_tunnel_request(self, name):
        # Create URL and payload
        requests = []

        url = f"data/sonic-vxlan:sonic-vxlan/VXLAN_TUNNEL/VXLAN_TUNNEL_LIST={name}"
        requests.append({"path": url, "method": DELETE})

        return requests

    def get_delete_src_ip_request(self, matched, name, del_source_ip):
        # Create URL and payload
        requests = []

        url = f"data/sonic-vxlan:sonic-vxlan/VXLAN_TUNNEL/VXLAN_TUNNEL_LIST={name}/src_ip"

        is_change_needed = False
        if matched:
            matched_source_ip = matched.get('source_ip')
            if matched_source_ip and matched_source_ip == del_source_ip:
                is_change_needed = True

        if is_change_needed:
            request = {"path": url.format(name=name), "method": DELETE}
            requests.append(request)

        return requests

    def get_delete_primary_ip_request(self, matched, name, del_primary_ip):
        # Create URL and payload
        requests = []

        url = "data/sonic-vxlan:sonic-vxlan/VXLAN_TUNNEL/VXLAN_TUNNEL_LIST={name}/primary_ip"

        is_change_needed = False
        if matched:
            matched_primary_ip = matched.get('primary_ip')
            if matched_primary_ip and matched_primary_ip == del_primary_ip:
                is_change_needed = True

        if is_change_needed:
            request = {"path": url.format(name=name), "method": DELETE}
            requests.append(request)

        return requests

    def get_delete_external_ip_request(self, matched, name, external_ip):
        requests = []
        url = "data/sonic-vxlan:sonic-vxlan/VXLAN_TUNNEL/VXLAN_TUNNEL_LIST={name}/external_ip"

        if matched:
            matched_external_ip = matched.get('external_ip')
            if matched_external_ip and matched_external_ip == external_ip:
                request = {"path": url.format(name=name), "method": DELETE}
                requests.append(request)

        return requests

    def get_delete_vlan_map_request(self, matched, name, del_vlan_map_list):
        # Create URL and payload
        requests = []

        for each_vlan_map in del_vlan_map_list:
            vlan = each_vlan_map.get('vlan')
            vni = each_vlan_map.get('vni')

            is_change_needed = False
            if matched:
                matched_vlan_map_list = matched.get('vlan_map')
                if matched_vlan_map_list:
                    matched_vlan_map = next((e_vlan_map for e_vlan_map in matched_vlan_map_list if e_vlan_map['vni'] == vni), None)
                    if matched_vlan_map:
                        if matched_vlan_map['vlan'] == vlan:
                            is_change_needed = True

            if is_change_needed:
                map_name = f"map_{vni}_Vlan{vlan}"
                url = f"data/sonic-vxlan:sonic-vxlan/VXLAN_TUNNEL_MAP/VXLAN_TUNNEL_MAP_LIST={name},{map_name}"
                request = {"path": url, "method": DELETE}
                requests.append(request)

        return requests

    def get_delete_vrf_map_request(self, matched, del_vrf_map_list):
        # Create URL and payload
        requests = []

        for each_vrf_map in del_vrf_map_list:
            vrf = each_vrf_map.get('vrf')
            vni = each_vrf_map.get('vni')

            is_change_needed = False
            if matched:
                matched_vrf_map_list = matched.get('vrf_map')
                if matched_vrf_map_list:
                    matched_vrf_map = next((e_vrf_map for e_vrf_map in matched_vrf_map_list if e_vrf_map['vni'] == vni), None)
                    if matched_vrf_map:
                        if matched_vrf_map['vrf'] == vrf:
                            is_change_needed = True

            if is_change_needed:
                url = f"data/sonic-vrf:sonic-vrf/VRF/VRF_LIST={vrf}/vni"
                request = {"path": url, "method": DELETE}
                requests.append(request)

        return requests

    def get_delete_suppress_vlan_neigh_request(self, matched, del_suppress_vlan_neigh_list):
        # Create URL and payload
        requests = []

        for each_suppress_vlan_neigh in del_suppress_vlan_neigh_list:
            vlan_name = each_suppress_vlan_neigh.get('vlan_name')

            is_change_needed = False
            if matched:
                matched_suppress_vlan_neigh_list = matched.get('suppress_vlan_neigh')
                if matched_suppress_vlan_neigh_list:
                    matched_suppress_vlan_neigh = next(
                        (e_svn for e_svn in matched_suppress_vlan_neigh_list if e_svn['vlan_name'] == vlan_name), None)
                    if matched_suppress_vlan_neigh:
                        is_change_needed = True

            if is_change_needed:
                url = f"data/sonic-vxlan:sonic-vxlan/SUPPRESS_VLAN_NEIGH/SUPPRESS_VLAN_NEIGH_LIST={vlan_name}"
                request = {"path": url, "method": DELETE}
                requests.append(request)

        return requests

    def sort_lists_in_config(self, config):
        if config:
            config.sort(key=lambda x: x['name'])
            for cfg in config:
                if 'vlan_map' in cfg and cfg['vlan_map']:
                    cfg['vlan_map'].sort(key=lambda x: x['vni'])
                if 'vrf_map' in cfg and cfg['vrf_map']:
                    cfg['vrf_map'].sort(key=lambda x: x['vni'])
                if 'suppress_vlan_neigh' in cfg and cfg['suppress_vlan_neigh']:
                    cfg['suppress_vlan_neigh'].sort(key=lambda x: x['vlan_name'])

    def post_process_generated_config(self, configs):
        confs = remove_empties_from_list(configs)
        if confs:
            for conf in confs[:]:
                vlan_map = conf.get('vlan_map')
                vrf_map = conf.get('vrf_map')
                suppress_vlan_neigh = conf.get('suppress_vlan_neigh')
                if not vlan_map and not vrf_map and not suppress_vlan_neigh:
                    confs.remove(conf)
        return confs
