#
# -*- coding: utf-8 -*-
# © Copyright 2020 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_vrfs class
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
    get_diff,
    update_states,
    normalize_interface_name
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_CONFIG_IF_NO_SUBCONFIG,
    get_new_config,
    get_formatted_config_diff
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'patch'
DELETE = 'DELETE'
MGMT_VRF_NAME = 'mgmt'
TEST_KEYS = [
    {'interfaces': {'name': ''}}
]
TEST_KEYS_formatted_diff = [
    {'config': {'name': ''}},
    {'interfaces': {'name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}}
]


class Vrfs(ConfigBase):
    """
    The sonic_vrfs class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'vrfs',
    ]

    delete_all_flag = False

    def __init__(self, module):
        super(Vrfs, self).__init__(module)

    def get_vrf_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        vrf_interfaces_facts = facts['ansible_network_resources'].get('vrfs')
        if not vrf_interfaces_facts:
            return []
        return vrf_interfaces_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        commands = list()

        existing_vrf_interfaces_facts = self.get_vrf_facts()
        commands, requests = self.set_config(existing_vrf_interfaces_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_vrf_interfaces_facts = self.get_vrf_facts()

        result['before'] = existing_vrf_interfaces_facts
        if result['changed']:
            result['after'] = changed_vrf_interfaces_facts

        new_config = changed_vrf_interfaces_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_vrf_interfaces_facts,
                                        TEST_KEYS_formatted_diff)
            result['after(generated)'] = new_config

        if self._module._diff:
            result['diff'] = get_formatted_config_diff(existing_vrf_interfaces_facts,
                                                       new_config,
                                                       self._module._verbosity)
        result['warnings'] = warnings
        return result

    def set_config(self, existing_vrf_interfaces_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_vrf_interfaces_facts
        if want is None:
            want = []

        for each in want:
            if each.get("members", None):
                interfaces = each["members"].get("interfaces", None)
                if interfaces:
                    interfaces = normalize_interface_name(interfaces, self._module)
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
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have, diff)
        elif state == 'overridden':
            commands, requests = self._state_overridden(want, have)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have)

        return commands, requests

    def _state_merged(self, want, have, diff):
        """ The command generator when state is merged

        :param want: the additive configuration as a dictionary
        :param obj_in_have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        requests = []
        if commands:
            requests = self.get_create_requests(commands, have)

        if len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []
        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :param want: the objects from which the configuration should be removed
        :param obj_in_have: the current configuration as a dictionary
        :param interface_type: interface type
        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        # if want is none, then delete all the vrfs
        if not want:
            commands = self.preprocess_mgmt_vrf_for_deleted(have)
            self.delete_all_flag = True
        else:
            commands = want
            self.delete_all_flag = False

        requests = []
        if commands:
            requests = self.get_delete_vrf_interface_requests(commands, have)

        if len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []

        return commands, requests

    def _state_replaced(self, want, have):
        """ The command generator when state is replaced

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :param diff: the difference between want and have
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []

        replaced_config = self.get_replaced_config(have, want)
        self.sort_config(replaced_config)
        self.sort_config(want)

        if replaced_config and replaced_config != want:
            self.delete_all_flag = False
            del_requests = self.get_delete_vrf_interface_requests(replaced_config, have, 'replaced')
            requests.extend(del_requests)
            commands.extend(update_states(replaced_config, "deleted"))
            replaced_config = []

        if not replaced_config and want:
            add_commands = want
            add_requests = self.get_create_requests(add_commands, have)

            if len(add_requests) > 0:
                requests.extend(add_requests)
                commands.extend(update_states(add_commands, "replaced"))

        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :param diff: the difference between want and have
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        self.sort_config(have)
        self.sort_config(want)

        commands = []
        requests = []
        want, have = self.preprocess_mgmt_vrf_for_overridden(want, have)

        if have and have != want:
            self.delete_all_flag = True
            del_requests = self.get_delete_vrf_interface_requests(have, have)
            requests.extend(del_requests)
            commands.extend(update_states(have, "deleted"))
            have = []

        if not have and want:
            add_commands = want
            add_requests = self.get_create_requests(add_commands, have)

            if len(add_requests) > 0:
                requests.extend(add_requests)
                commands.extend(update_states(add_commands, "overridden"))

        return commands, requests

    def get_delete_vrf_interface_requests(self, configs, have, state=None):
        requests = []
        if not configs:
            return requests

        # Create URL and payload
        method = DELETE
        for conf in configs:
            name = conf['name']
            empty_flag = False
            members = conf.get('members', None)
            if members:
                interfaces = members.get('interfaces', None)
            if members is None:
                empty_flag = True
            elif members is not None and interfaces is None:
                empty_flag = True
            matched = next((have_cfg for have_cfg in have if have_cfg['name'] == name), None)
            if not matched:
                continue

            # if members are not mentioned delet the vrf name
            adjusted_delete_all_flag = name != MGMT_VRF_NAME and self.delete_all_flag
            adjusted_empty_flag = empty_flag
            if state == 'replaced':
                adjusted_empty_flag = empty_flag and name != MGMT_VRF_NAME

            if adjusted_delete_all_flag or adjusted_empty_flag:
                url = 'data/openconfig-network-instance:network-instances/network-instance={0}'.format(name)
                request = {"path": url, "method": method}
                requests.append(request)
            else:
                have_members = matched.get('members', None)
                conf_members = conf.get('members', None)

                if have_members:
                    have_intf = have_members.get('interfaces', None)
                    conf_intf = conf_members.get('interfaces', None)
                    if conf_intf:
                        for del_mem in conf_intf:
                            if del_mem in have_intf:
                                url = 'data/openconfig-network-instance:network-instances/'
                                url = url + 'network-instance={0}/interfaces/interface={1}'.format(name, del_mem['name'])
                                request = {"path": url, "method": method}
                                requests.append(request)

        return requests

    def get_create_requests(self, configs, have):
        requests = []
        if not configs:
            return requests

        requests_vrf = self.get_create_vrf_requests(configs, have)
        if requests_vrf:
            requests.extend(requests_vrf)

        requests_vrf_intf = self.get_create_vrf_interface_requests(configs, have)
        if requests_vrf_intf:
            requests.extend(requests_vrf_intf)
        return requests

    def get_create_vrf_requests(self, configs, have):
        requests = []
        if not configs:
            return requests
        # Create URL and payload
        method = PATCH
        for conf in configs:
            if conf.get("name", None):
                name = conf["name"]
                matched = next((have_cfg for have_cfg in have if have_cfg['name'] == name), None)
                if not matched:
                    url = 'data/openconfig-network-instance:network-instances'
                    payload = self.build_create_vrf_payload(conf)
                    request = {"path": url, "method": method, "data": payload}
                    requests.append(request)
        return requests

    def get_create_vrf_interface_requests(self, configs, have):
        requests = []
        if not configs:
            return requests

        # Create URL and payload
        method = PATCH
        for conf in configs:
            if conf.get("members", None):
                if conf["members"].get("interfaces", None):
                    url = 'data/openconfig-network-instance:network-instances/network-instance={0}/interfaces/interface'.format(conf["name"])
                    payload = self.build_create_vrf_interface_payload(conf)
                    if payload:
                        request = {"path": url, "method": method, "data": payload}
                        requests.append(request)

        return requests

    def build_create_vrf_payload(self, conf):
        name = conf['name']

        netw_inst = dict({'name': name})
        netw_inst['config'] = dict({'name': name})
        netw_inst['config'].update({'enabled': True})
        netw_inst['config'].update({'type': 'L3VRF'})
        netw_inst_arr = [netw_inst]

        return dict({'openconfig-network-instance:network-instances': {'network-instance': netw_inst_arr}})

    def build_create_vrf_interface_payload(self, conf):
        members = conf["members"].get("interfaces", None)
        network_inst_payload = dict()
        if members:
            network_inst_payload.update({"openconfig-network-instance:interface": []})
            for member in members:
                if member["name"]:
                    member_config_payload = dict({"id": member["name"]})
                    member_payload = dict({"id": member["name"], "config": member_config_payload})
                    network_inst_payload["openconfig-network-instance:interface"].append(member_payload)

        return network_inst_payload

    def get_vrf_name(self, vrf):
        return vrf.get('name')

    def get_interface_name(self, intf):
        return intf.get('name')

    def sort_config(self, conf):
        if conf:
            conf.sort(key=self.get_vrf_name)
            for vrf in conf:
                if vrf.get('members', None) and vrf['members'].get('interfaces', None):
                    vrf['members']['interfaces'].sort(key=self.get_interface_name)

    def get_replaced_config(self, have, want):

        replaced_vrfs = []
        for vrf in want:
            vrf_name = vrf['name']
            have_vrf = next((h_vrf for h_vrf in have if h_vrf['name'] == vrf_name), None)
            if have_vrf:
                replaced_vrfs.append(have_vrf)

        return replaced_vrfs

    def preprocess_mgmt_vrf_for_deleted(self, have):
        new_have = have
        conf = next((vrf for vrf in new_have if vrf['name'] == MGMT_VRF_NAME), None)
        if conf:
            new_have = deepcopy(have)
            new_have.remove(conf)
        return new_have

    def preprocess_mgmt_vrf_for_overridden(self, want, have):
        new_want = deepcopy(want)
        new_have = deepcopy(have)
        h_conf = next((vrf for vrf in new_have if vrf['name'] == MGMT_VRF_NAME), None)
        if h_conf:
            conf = next((vrf for vrf in new_want if vrf['name'] == MGMT_VRF_NAME), None)
            if conf:
                mv_intfs = []
                if conf.get('members', None) and conf['members'].get('interfaces', None):
                    mv_intfs = conf['members'].get('interfaces', [])

                h_mv_intfs = []
                if h_conf.get('members', None) and h_conf['members'].get('interfaces', None):
                    h_mv_intfs = h_conf['members'].get('interfaces', [])

                mv_intfs.sort(key=lambda x: x['name'])
                h_mv_intfs.sort(key=lambda x: x['name'])
                if mv_intfs == h_mv_intfs:
                    new_want.remove(conf)
                    new_have.remove(h_conf)
                elif not h_mv_intfs:
                    new_have.remove(h_conf)
            else:
                new_have.remove(h_conf)

        return new_want, new_have
