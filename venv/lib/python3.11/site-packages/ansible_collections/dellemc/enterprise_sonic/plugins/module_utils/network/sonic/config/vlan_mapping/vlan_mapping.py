#
# -*- coding: utf-8 -*-
# Copyright 2023 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_vlan_mapping class
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
    update_states,
    remove_empties_from_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_ranges_in_list
)
from ansible.module_utils.connection import ConnectionError


TEST_KEYS = [
    {'config': {'name': ''}},
    {'mapping': {'service_vlan': ''}},
    {'match_single_tags': {'outer_vlan': ''}},
    {'match_double_tags': {'inner_vlan': '', 'outer_vlan': ''}},
]
interface_url = "data/openconfig-interfaces:interfaces/interface={}"
mapped_vlans_url = interface_url + "/openconfig-interfaces-ext:mapped-vlans"
mapped_vlan_url = mapped_vlans_url + "/mapped-vlan={}"


class Vlan_mapping(ConfigBase):
    """
    The sonic_vlan_mapping class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'vlan_mapping',
    ]

    def __init__(self, module):
        super(Vlan_mapping, self).__init__(module)

    def get_vlan_mapping_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        vlan_mapping_facts = facts['ansible_network_resources'].get('vlan_mapping')
        if not vlan_mapping_facts:
            return []
        return vlan_mapping_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()

        existing_vlan_mapping_facts = self.get_vlan_mapping_facts()
        commands, requests = self.set_config(existing_vlan_mapping_facts)

        if commands:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_vlan_mapping_facts = self.get_vlan_mapping_facts()

        result['before'] = existing_vlan_mapping_facts
        if result['changed']:
            result['after'] = changed_vlan_mapping_facts

        result['warnings'] = warnings
        return result

    def set_config(self, existing_vlan_mapping_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = remove_empties_from_list(self._module.params['config'])
        have = existing_vlan_mapping_facts
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

        have = self.convert_vlan_ids_range(have)
        want = self.convert_vlan_ids_range(want)
        diff = get_diff(want, have, TEST_KEYS)

        if state == 'overridden':
            commands, requests = self._state_overridden(want, have, diff)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have, diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have, diff)

        ret_commands = remove_empties_from_list(commands)
        return ret_commands, requests

    def _state_replaced(self, want, have, diff):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []
        replaced_config = self.get_replaced_config(want, have)

        add_commands = []
        if replaced_config:
            del_requests = self.get_delete_vlan_mapping_requests(replaced_config, have,
                                                                 is_delete_all=False,
                                                                 state='replaced')
            requests.extend(del_requests)
            commands.extend(update_states(replaced_config, "deleted"))
            add_commands = want
        else:
            add_commands = diff

        if add_commands:
            add_requests = self.get_create_vlan_mapping_requests(add_commands, have)
            if len(add_requests) > 0:
                requests.extend(add_requests)
                commands.extend(update_states(add_commands, "replaced"))

        return commands, requests

    def _state_overridden(self, want, have, diff):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []

        r_diff = get_diff(have, want, TEST_KEYS)
        if have and (diff or r_diff):
            del_requests = self.get_delete_vlan_mapping_requests(have, have, is_delete_all=True)
            requests.extend(del_requests)
            commands.extend(update_states(have, "deleted"))
            have = []

        if not have and want:
            want_commands = want
            want_requests = self.get_create_vlan_mapping_requests(want_commands, have)
            if len(want_requests) > 0:
                requests.extend(want_requests)
                commands.extend(update_states(want_commands, "overridden"))

        return commands, requests

    def _state_merged(self, want, have, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        requests = self.get_create_vlan_mapping_requests(commands, have)

        if commands and len(requests):
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
            commands = have
            is_delete_all = True
        else:
            commands = want

        requests.extend(self.get_delete_vlan_mapping_requests(commands, have, is_delete_all))

        if len(requests) == 0:
            commands = []

        if commands:
            commands = update_states(commands, 'deleted')

        return commands, requests

    def get_delete_vlan_mapping_requests(self, commands, have, is_delete_all, state='deleted'):
        """ Get list of requests to delete vlan mapping configurations
        for all interfaces specified by the commands
        """
        url = mapped_vlan_url
        method = "DELETE"
        requests = []

        # Delete all vlan mappings
        if is_delete_all:
            for cmd in commands:
                name = cmd.get('name', None)
                interface_name = name.replace('/', '%2f')
                mapping_list = cmd.get('mapping', [])

                if mapping_list:
                    for mapping in mapping_list:
                        service_vlan = mapping.get('service_vlan', None)
                        path = url.format(interface_name, service_vlan)
                        request = {"path": path, "method": method}
                        requests.append(request)

            return requests
        else:
            for cmd in commands:
                name = cmd.get('name', None)
                interface_name = name.replace('/', '%2f')
                mapping_list = cmd.get('mapping', [])

                # Checks if there is a interface matching the delete command
                have_interface_name = None
                have_mapping_list = []
                for conf in have:
                    conf_name = conf.get('name', None)
                    conf_interface_name = conf_name.replace('/', '%2f')
                    conf_mapping_list = conf.get('mapping', [])
                    if interface_name == conf_interface_name:
                        have_mapping_list = conf_mapping_list
                        break

                # Delete part or all of single mapping
                if mapping_list and have_mapping_list:
                    requests.extend(self.get_delete_vlan_mapping_mapping_requests(interface_name,
                                                                                  mapping_list,
                                                                                  have_mapping_list,
                                                                                  state))
                # Delete all mappings in an interface
                else:
                    if have_mapping_list:
                        for mapping in have_mapping_list:
                            service_vlan = mapping.get('service_vlan', None)
                            path = url.format(interface_name, service_vlan)
                            request = {"path": path, "method": method}
                            requests.append(request)

        return requests

    def get_delete_vlan_mapping_mapping_requests(self, interface_name, mapping_list,
                                                 have_mapping_list, state='deleted'):
        url = mapped_vlan_url
        method = "DELETE"
        requests = []

        if mapping_list:
            for mapping in mapping_list:
                service_vlan = mapping.get('service_vlan', None)

                # Checks if there is a vlan mapping matching the delete command
                have_service_vlan = None
                for have_mapping in have_mapping_list:
                    tmp_service_vlan = have_mapping.get('service_vlan', None)
                    if tmp_service_vlan == service_vlan:
                        have_service_vlan = tmp_service_vlan
                        break

                if service_vlan and have_service_vlan:
                    dot1q_tun = mapping.get('dot1q_tunnel', None)
                    vlan_trans = mapping.get('vlan_translation', None)
                    have_dot1q_tun = have_mapping.get('dot1q_tunnel', None)
                    have_vlan_trans = have_mapping.get('vlan_translation', None)

                    if dot1q_tun is not None and have_dot1q_tun:
                        # Delete dot1q_tunnel
                        dt_requests = self.get_delete_vlan_mapping_mapping_dot1q_tunnel_requests(
                            interface_name, service_vlan, dot1q_tun, have_dot1q_tun)
                        if dt_requests:
                            requests.extend(dt_requests)

                    if vlan_trans is not None and have_vlan_trans:
                        # Delete vlan translation
                        vt_requests = self.get_delete_vlan_mapping_mapping_translation_requests(
                            interface_name, service_vlan, vlan_trans, have_vlan_trans, state)
                        if vt_requests:
                            requests.extend(vt_requests)

                    if dot1q_tun is None and vlan_trans is None:
                        if have_dot1q_tun or have_vlan_trans:
                            # Delete entire mapping
                            path = url.format(interface_name, service_vlan)
                            request = {"path": path, "method": method}
                            requests.append(request)

        return requests

    def get_delete_vlan_mapping_mapping_dot1q_tunnel_requests(self,
                                                              interface_name, service_vlan,
                                                              dot1q_tun, have_dot1q_tun):
        dot1q_tun_url = mapped_vlan_url + "/match/single-tagged"
        priority_url = mapped_vlan_url + "/ingress-mapping/config/mapped-vlan-priority"
        vlan_ids_url = mapped_vlan_url + "/match/single-tagged/config/vlan-ids={}"
        method = "DELETE"
        requests = []

        vlan_ids = dot1q_tun.get('vlan_ids', None)
        priority = dot1q_tun.get('priority', None)
        have_vlan_ids = have_dot1q_tun.get('vlan_ids', None)
        have_priority = have_dot1q_tun.get('priority', None)

        if vlan_ids or priority:
            # Delete priority
            if priority and have_priority:
                path = priority_url.format(interface_name, service_vlan)
                request = {"path": path, "method": method}
                requests.append(request)

            # Delete vlan ids
            if vlan_ids and have_vlan_ids:
                vlan_ids_str = ""
                same_vlan_ids_list = self.get_vlan_ids_diff(vlan_ids, have_vlan_ids, same=True)
                num_same_vlan_ids = list(map(int, same_vlan_ids_list))
                range_in_list = get_ranges_in_list(num_same_vlan_ids)

                for sublist in range_in_list:
                    vlan_ids_str = ""
                    if len(sublist) > 1:
                        min_num = min(sublist)
                        max_num = max(sublist)
                        vlan_ids_str = str(min_num) + ".." + str(max_num)
                    else:
                        vlan_ids_str = str(sublist[0])

                    path = vlan_ids_url.format(interface_name, service_vlan, vlan_ids_str)
                    request = {"path": path, "method": method}
                    requests.append(request)
        # Delete entire dot1q_tunnel
        else:
            if have_vlan_ids or have_priority:
                path = dot1q_tun_url.format(interface_name, service_vlan)
                request = {"path": path, "method": method}
                requests.append(request)

        return requests

    def get_delete_vlan_mapping_mapping_translation_requests(self,
                                                             interface_name, service_vlan,
                                                             vlan_trans, have_vlan_trans,
                                                             state='deleted'):
        url = mapped_vlan_url
        vlan_trans_ms_url = mapped_vlan_url + "/match/match-single-tags"
        vlan_trans_md_url = mapped_vlan_url + "/match/match-double-tags"
        method = "DELETE"
        requests = []

        multi_tag = vlan_trans.get('multi_tag', None)
        ms_tags = vlan_trans.get('match_single_tags', None)
        md_tags = vlan_trans.get('match_double_tags', None)

        have_multi_tag = have_vlan_trans.get('multi_tag', False)

        have_ms_tags = have_vlan_trans.get('match_single_tags', None)
        have_md_tags = have_vlan_trans.get('match_double_tags', None)

        if multi_tag is not None:
            if (state == 'replaced' and multi_tag != have_multi_tag) or \
               (state == 'deleted' and have_multi_tag):
                # Delete entire translation
                path = url.format(interface_name, service_vlan)
                request = {"path": path, "method": method}
                requests.append(request)
                return requests

        if ms_tags is not None and have_ms_tags:
            # Delete match_single_tags
            ms_requests = self.get_delete_vlan_mapping_mapping_ms_tags_requests(
                interface_name, service_vlan, ms_tags, have_ms_tags)
            if ms_requests:
                requests.extend(ms_requests)

        if md_tags is not None and have_md_tags:
            # Delete match_double_tags
            md_requests = self.get_delete_vlan_mapping_mapping_md_tags_requests(
                interface_name, service_vlan, md_tags, have_md_tags)
            if md_requests:
                requests.extend(md_requests)

        if ms_tags is None and md_tags is None and multi_tag is None:
            if have_ms_tags or have_md_tags or have_multi_tag is not None:
                # Delete entire translation
                path = url.format(interface_name, service_vlan)
                request = {"path": path, "method": method}
                requests.append(request)

        return requests

    def get_delete_vlan_mapping_mapping_ms_tags_requests(self,
                                                         interface_name, service_vlan,
                                                         ms_tags, have_ms_tags):
        ms_tags_url = mapped_vlan_url + "/match/match-single-tags"
        ms_tag_url = mapped_vlan_url + "/match/match-single-tags/match-single-tag={}"
        ms_tag_priority_url = ms_tag_url + "/config/priority"
        method = "DELETE"
        requests = []

        if have_ms_tags:
            if ms_tags:
                for ms_tag in ms_tags:
                    outer_vlan = ms_tag.get('outer_vlan', None)
                    have_outer_vlan = None
                    for have_ms_tag in have_ms_tags:
                        tmp_vlan = have_ms_tag.get('outer_vlan', None)
                        if outer_vlan == tmp_vlan:
                            have_outer_vlan = tmp_vlan
                            break

                    if outer_vlan and have_outer_vlan:
                        priority = ms_tag.get('priority', None)
                        have_priority = have_ms_tag.get('priority', None)
                        if priority:
                            if have_priority:
                                # Delete priority
                                path = ms_tag_priority_url.format(interface_name, service_vlan,
                                                                  outer_vlan)
                                request = {"path": path, "method": method}
                                requests.append(request)
                        else:
                            # Delete entire tag
                            path = ms_tag_url.format(interface_name, service_vlan, outer_vlan)
                            request = {"path": path, "method": method}
                            requests.append(request)
            else:
                # Delete entire match-single-tags
                path = ms_tags_url.format(interface_name, service_vlan)
                request = {"path": path, "method": method}
                requests.append(request)

        return requests

    def get_delete_vlan_mapping_mapping_md_tags_requests(self,
                                                         interface_name, service_vlan,
                                                         md_tags, have_md_tags):
        md_tags_url = mapped_vlan_url + "/match/match-double-tags"
        md_tag_url = mapped_vlan_url + "/match/match-double-tags/match-double-tag={},{}"
        md_tag_priority_url = md_tag_url + "/config/priority"
        method = "DELETE"
        requests = []

        if have_md_tags:
            if md_tags:
                for md_tag in md_tags:
                    inner_vlan = md_tag.get('inner_vlan', None)
                    outer_vlan = md_tag.get('outer_vlan', None)
                    have_inner_vlan = None
                    have_outer_vlan = None
                    for have_md_tag in have_md_tags:
                        tmp_inner_vlan = have_md_tag.get('inner_vlan', None)
                        tmp_outer_vlan = have_md_tag.get('outer_vlan', None)
                        if inner_vlan == tmp_inner_vlan and outer_vlan == tmp_outer_vlan:
                            have_inner_vlan = tmp_inner_vlan
                            have_outer_vlan = tmp_outer_vlan
                            break

                    if inner_vlan and have_inner_vlan and outer_vlan and have_outer_vlan:
                        priority = md_tag.get('priority', None)
                        have_priority = have_md_tag.get('priority', None)
                        if priority:
                            if have_priority:
                                # Delete priority
                                path = md_tag_priority_url.format(interface_name, service_vlan,
                                                                  outer_vlan, inner_vlan)
                                request = {"path": path, "method": method}
                                requests.append(request)
                        else:
                            # Delete entire tag
                            path = md_tag_url.format(interface_name, service_vlan,
                                                     outer_vlan, inner_vlan)
                            request = {"path": path, "method": method}
                            requests.append(request)
            else:
                # Delete entire match-double-tags
                path = md_tags_url.format(interface_name, service_vlan)
                request = {"path": path, "method": method}
                requests.append(request)

        return requests

    def get_create_vlan_mapping_requests(self, commands, have):
        """ Get list of requests to create/modify vlan mapping configurations
        for all interfaces specified by the commands
        """
        requests = []
        if not commands:
            return requests

        for cmd in commands:
            name = cmd.get('name', None)
            interface_name = name.replace('/', '%2f')
            mapping_list = cmd.get('mapping', [])

            if mapping_list:
                for mapping in mapping_list:
                    request = self.get_create_vlan_mapping_mapping_requests(interface_name,
                                                                            mapping)
                    if request:
                        requests.append(request)
        return requests

    def get_create_vlan_mapping_mapping_requests(self, interface_name, mapping):
        url = mapped_vlans_url
        body = {}
        method = "PATCH"

        service_vlan = mapping.get('service_vlan', None)
        match_data = dict()
        ing_data = dict()
        egr_data = dict()
        request = dict()

        if 'dot1q_tunnel' in mapping:
            dot1q = mapping['dot1q_tunnel']
            vlan_ids = dot1q.get('vlan_ids', [])
            priority = dot1q.get('priority', None)
            if vlan_ids:
                match_data = {'single-tagged': {'config': {'vlan-ids': self.get_vlan_int_list(vlan_ids)}}}
            if priority:
                ing_data = {'config': {'vlan-stack-action': 'PUSH', 'mapped-vlan-priority': priority}}
                egr_data = {'config': {'vlan-stack-action': 'POP', 'mapped-vlan-priority': priority}}
            else:
                ing_data = {'config': {'vlan-stack-action': 'PUSH'}}
                egr_data = {'config': {'vlan-stack-action': 'POP'}}

            if match_data:
                body = {
                    'openconfig-interfaces-ext:mapped-vlans': {
                        'mapped-vlan': [
                            {
                                'vlan-id': service_vlan,
                                'config': {'vlan-id': service_vlan},
                                'match': match_data,
                                'ingress-mapping': ing_data,
                                'egress-mapping': egr_data
                            }
                        ]
                    }
                }
            else:
                body = {
                    'openconfig-interfaces-ext:mapped-vlans': {
                        'mapped-vlan': [
                            {
                                'vlan-id': service_vlan,
                                'config': {'vlan-id': service_vlan},
                                'ingress-mapping': ing_data,
                                'egress-mapping': egr_data
                            }
                        ]
                    }
                }

        elif 'vlan_translation' in mapping:
            multi_tag = mapping['vlan_translation'].get('multi_tag', False)
            ms_tags = mapping['vlan_translation'].get('match_single_tags', None)
            md_tags = mapping['vlan_translation'].get('match_double_tags', None)

            if ms_tags:
                m_s_tags = []
                for ms_tag in ms_tags:
                    outer_vlan = ms_tag.get('outer_vlan', None)
                    priority = ms_tag.get('priority', None)
                    if priority:
                        m_s_tag = {'outer-vlan': outer_vlan,
                                   'config': {'outer-vlan': outer_vlan,
                                              'priority': priority}}
                    else:
                        m_s_tag = {'outer-vlan': outer_vlan,
                                   'config': {'outer-vlan': outer_vlan}}
                    m_s_tags.append(m_s_tag)

                if m_s_tags:
                    match_data['match-single-tags'] = {'match-single-tag': m_s_tags}

            if md_tags:
                m_d_tags = []
                for md_tag in md_tags:
                    inner_vlan = md_tag.get('inner_vlan', None)
                    outer_vlan = md_tag.get('outer_vlan', None)
                    priority = md_tag.get('priority', None)
                    if priority:
                        m_d_tag = {'inner-vlan': inner_vlan,
                                   'outer-vlan': outer_vlan,
                                   'config': {'inner-vlan': inner_vlan,
                                              'outer-vlan': outer_vlan,
                                              'priority': priority}}
                    else:
                        m_d_tag = {'inner-vlan': inner_vlan,
                                   'outer-vlan': outer_vlan,
                                   'config': {'inner-vlan': inner_vlan,
                                              'outer-vlan': outer_vlan}}
                    m_d_tags.append(m_d_tag)

                if m_d_tags:
                    match_data['match-double-tags'] = {'match-double-tag': m_d_tags}

            ing_data = {'config': {'vlan-stack-action': 'SWAP'}}
            egr_data = {'config': {'vlan-stack-action': 'SWAP'}}

            if match_data:
                body = {
                    'openconfig-interfaces-ext:mapped-vlans': {
                        'mapped-vlan': [
                            {
                                'vlan-id': service_vlan,
                                'config': {'vlan-id': service_vlan,
                                           'multi-tag': multi_tag},
                                'match': match_data,
                                'ingress-mapping': ing_data,
                                'egress-mapping': egr_data
                            }
                        ]
                    }
                }
            else:
                body = {
                    'openconfig-interfaces-ext:mapped-vlans': {
                        'mapped-vlan': [
                            {
                                'vlan-id': service_vlan,
                                'config': {'vlan-id': service_vlan,
                                           'multi-tag': multi_tag},
                                'ingress-mapping': ing_data,
                                'egress-mapping': egr_data
                            }
                        ]
                    }
                }

        if body:
            request = {"path": url.format(interface_name), "method": method, "data": body}
        return request

    def get_vlan_ids_diff(self, vlan_ids, have_vlan_ids, same):
        """ Takes two vlan id lists and finds the difference.
        :param vlan_ids: list of vlan ids that is looking for diffs
        :param have_vlan_ids: list of vlan ids that is being compared to
        :param same: if true will instead return list of shared values
        :rtype: list(str)
        """
        results = []

        for vlan_id in vlan_ids:
            if same:
                if vlan_id in have_vlan_ids:
                    results.append(vlan_id)
            else:
                if vlan_id not in have_vlan_ids:
                    results.append(vlan_id)

        return results

    def vlanIdsRangeStr(self, vlanList):
        rangeList = []
        for vid in vlanList:
            if "-" in vid:
                vidList = vid.split("-")
                lower = int(vidList[0])
                upper = int(vidList[1])
                for i in range(lower, upper + 1):
                    rangeList.append(str(i))
            else:
                rangeList.append(vid)
        return rangeList

    def convert_vlan_ids_range(self, config):

        interface_index = 0
        for conf in config:
            name = conf.get('name', None)
            interface_name = name.replace('/', '%2f')
            mapping_list = conf.get('mapping', [])

            if mapping_list:
                mapping_index = 0
                for mapping in mapping_list:
                    if mapping.get('dot1q_tunnel', None):
                        vlan_ids = mapping['dot1q_tunnel'].get('vlan_ids', None)

                        if vlan_ids:
                            dot1q_tun = config[interface_index]['mapping'][mapping_index]['dot1q_tunnel']
                            dot1q_tun['vlan_ids'] = self.vlanIdsRangeStr(vlan_ids)
                    mapping_index = mapping_index + 1
            interface_index = interface_index + 1

        return config

    def get_vlan_int_list(self, str_list):
        int_list = []
        for str_vid in str_list:
            int_list.append(int(str_vid))
        return int_list

    def get_replaced_config(self, want, have):
        rpld_config = []
        for cmd in want:
            name = cmd.get('name', None)
            interface_name = name.replace('/', '%2f')
            mapping_list = cmd.get('mapping', [])

            have_interface_name = None
            have_mapping_list = []
            for conf in have:
                conf_name = conf.get('name', None)
                conf_interface_name = conf_name.replace('/', '%2f')
                conf_mapping_list = conf.get('mapping', [])
                if interface_name == conf_interface_name:
                    have_mapping_list = conf_mapping_list
                    break

            rpld_mapping_list = None
            if have_mapping_list:
                if mapping_list:
                    rpld_mapping_list = self.get_replaced_vlan_mapping_mapping(
                        mapping_list, have_mapping_list)
                else:
                    rpld_mapping_list = None

            if rpld_mapping_list is not None:
                rpld_config.append({'name': interface_name, 'mapping': rpld_mapping_list})

        return rpld_config

    def get_replaced_vlan_mapping_mapping(self, mapping_list, have_mapping_list):
        rpld_mapping_list = []

        for mapping in mapping_list:
            service_vlan = mapping.get('service_vlan', None)
            have_service_vlan = None
            for have_mapping in have_mapping_list:
                tmp_service_vlan = have_mapping.get('service_vlan', None)
                if tmp_service_vlan == service_vlan:
                    have_service_vlan = tmp_service_vlan
                    break

            rpld_mapping = {}
            if service_vlan and have_service_vlan:
                dot1q_tun = mapping.get('dot1q_tunnel', None)
                vlan_trans = mapping.get('vlan_translation', None)
                have_dot1q_tun = have_mapping.get('dot1q_tunnel', None)
                have_vlan_trans = have_mapping.get('vlan_translation', None)

                if dot1q_tun and have_dot1q_tun:
                    if self.diff_dot1q_tunnel(dot1q_tun, have_dot1q_tun):
                        rpld_mapping = {'service_vlan': service_vlan,
                                        'dot1q_tunnel': {}}

                if vlan_trans and have_vlan_trans:
                    rpld_trans = self.get_replaced_vlan_mapping_mapping_translation(
                        vlan_trans, have_vlan_trans)
                    if rpld_trans is not None:
                        rpld_mapping = {'service_vlan': service_vlan,
                                        'vlan_translation': rpld_trans}
            if rpld_mapping:
                rpld_mapping_list.append(rpld_mapping)

        if not rpld_mapping_list:
            return None
        else:
            return rpld_mapping_list

    def get_replaced_vlan_mapping_mapping_translation(self, vlan_trans, have_vlan_trans):
        rpld_trans = {}

        multi_tag = vlan_trans.get('multi_tag', None)
        ms_tags = vlan_trans.get('match_single_tags', None)
        md_tags = vlan_trans.get('match_double_tags', None)

        have_multi_tag = have_vlan_trans.get('multi_tag', False)
        have_ms_tags = have_vlan_trans.get('match_single_tags', None)
        have_md_tags = have_vlan_trans.get('match_double_tags', None)

        if multi_tag is not None:
            if have_multi_tag != multi_tag:
                rpld_trans['multi_tag'] = multi_tag
                return rpld_trans

        if ms_tags and have_ms_tags:
            if self.diff_ms_tags(ms_tags, have_ms_tags):
                rpld_trans['match_single_tags'] = []

        if md_tags and have_md_tags:
            if self.diff_md_tags(md_tags, have_md_tags):
                rpld_trans['match_double_tags'] = []

        if not rpld_trans:
            return None
        else:
            return rpld_trans

    def diff_dot1q_tunnel(self, dot1q_tun, have_dot1q_tun):
        vlan_ids = dot1q_tun.get('vlan_ids', None)
        priority = dot1q_tun.get('priority', None)
        have_vlan_ids = have_dot1q_tun.get('vlan_ids', None)
        have_priority = have_dot1q_tun.get('priority', None)
        if vlan_ids:
            vlan_ids = sorted(vlan_ids)
        if have_vlan_ids:
            have_vlan_ids = sorted(have_vlan_ids)
        if priority != have_priority or vlan_ids != have_vlan_ids:
            return True
        else:
            return False

    def diff_ms_tags(self, ms_tags, have_ms_tags, rev_way=False):

        if len(ms_tags) != len(have_ms_tags):
            return True

        ms_diff = False

        for ms_tag in ms_tags:
            outer_vlan = ms_tag.get('outer_vlan', None)
            in_it = False
            for h_ms_tag in have_ms_tags:
                h_outer_vlan = h_ms_tag.get('outer_vlan', None)
                if outer_vlan == h_outer_vlan:
                    in_it = True
                    break

            if in_it:
                priority = ms_tag.get('priority', None)
                h_priority = h_ms_tag.get('priority', None)
                if priority != h_priority:
                    ms_diff = True
            else:
                ms_diff = True

            if ms_diff:
                return ms_diff

        if not rev_way:
            ms_diff = self.diff_ms_tags(have_ms_tags, ms_tags, rev_way=True)

        return ms_diff

    def diff_md_tags(self, md_tags, have_md_tags, rev_way=False):

        if len(md_tags) != len(have_md_tags):
            return True

        md_diff = False

        for md_tag in md_tags:
            outer_vlan = md_tag.get('outer_vlan', None)
            inner_vlan = md_tag.get('inner_vlan', None)
            in_it = False
            for h_md_tag in have_md_tags:
                h_outer_vlan = h_md_tag.get('outer_vlan', None)
                h_inner_vlan = h_md_tag.get('inner_vlan', None)
                if outer_vlan == h_outer_vlan and inner_vlan == h_inner_vlan:
                    in_it = True
                    break

            if in_it:
                priority = md_tag.get('priority', None)
                h_priority = h_md_tag.get('priority', None)
                if priority != h_priority:
                    md_diff = True
            else:
                md_diff = True

            if md_diff:
                return md_diff

        if not rev_way:
            md_diff = self.diff_md_tags(have_md_tags, md_tags, rev_way=True)

        return md_diff
