#
# -*- coding: utf-8 -*-
# Copyright 2022 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_ip_neighbor class
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
    remove_empties
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import (
    Facts
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    update_states,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    get_new_config,
    get_formatted_config_diff
)
from ansible.module_utils.connection import ConnectionError

GET = 'get'
PATCH = 'patch'
PUT = 'put'
DELETE = 'delete'
GLB_URL = 'data/openconfig-neighbor:neighbor-globals/neighbor-global'
URL = 'data/openconfig-neighbor:neighbor-globals/neighbor-global=Values'
CONFIG_URL = 'data/openconfig-neighbor:neighbor-globals/neighbor-global=Values/config'

IP_NEIGH_CONFIG_DEFAULT = {
    'ipv4_arp_timeout': 180,
    'ipv4_drop_neighbor_aging_time': 300,
    'ipv6_drop_neighbor_aging_time': 300,
    'ipv6_nd_cache_expiry': 180,
    'num_local_neigh': 0
}

IP_NEIGH_CONFIG_REQ_DEFAULT = {
    'name': 'Values',
    'ipv4-arp-timeout': 180,
    'ipv4-drop-neighbor-aging-time': 300,
    'ipv6-drop-neighbor-aging-time': 300,
    'ipv6-nd-cache-expiry': 180,
    'num-local-neigh': 0
}


def __derive_ip_neighbor_config_delete_op(key_set, command, exist_conf):
    new_conf = exist_conf

    if 'ipv4_arp_timeout' in command:
        new_conf['ipv4_arp_timeout'] = IP_NEIGH_CONFIG_DEFAULT['ipv4_arp_timeout']

    if 'ipv4_drop_neighbor_aging_time' in command:
        new_conf['ipv4_drop_neighbor_aging_time'] = \
            IP_NEIGH_CONFIG_DEFAULT['ipv4_drop_neighbor_aging_time']

    if 'ipv6_drop_neighbor_aging_time' in command:
        new_conf['ipv6_drop_neighbor_aging_time'] = \
            IP_NEIGH_CONFIG_DEFAULT['ipv6_drop_neighbor_aging_time']

    if 'ipv6_nd_cache_expiry' in command:
        new_conf['ipv6_nd_cache_expiry'] = IP_NEIGH_CONFIG_DEFAULT['ipv6_nd_cache_expiry']

    if 'num_local_neigh' in command:
        new_conf['num_local_neigh'] = IP_NEIGH_CONFIG_DEFAULT['num_local_neigh']

    return True, new_conf


TEST_KEYS_formatted_diff = [
    {'config': {'__delete_op': __derive_ip_neighbor_config_delete_op}},
]


class Ip_neighbor(ConfigBase):
    """
    The sonic_ip_neighbor class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'ip_neighbor',
    ]

    def __init__(self, module):
        super(Ip_neighbor, self).__init__(module)

    def get_ip_neighbor_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        ip_neighbor_facts = facts['ansible_network_resources'].get('ip_neighbor')
        if not ip_neighbor_facts:
            requests = self.build_create_all_requests()
            try:
                edit_config(self._module, to_request(self._module, requests))
            except ConnectionError as exc:
                self._module.fail_json(msg=str(exc), code=exc.code)

            facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
            ip_neighbor_facts = facts['ansible_network_resources'].get('ip_neighbor')

            if not ip_neighbor_facts:
                err_msg = "IP neighbor module: get facts failed."
                self._module.fail_json(msg=err_msg, code=500)

        return ip_neighbor_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        commands = list()
        requests = list()

        existing_ip_neighbor_facts = self.get_ip_neighbor_facts()

        commands, requests = self.set_config(existing_ip_neighbor_facts)

        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_ip_neighbor_facts = self.get_ip_neighbor_facts()

        result['before'] = existing_ip_neighbor_facts
        if result['changed']:
            result['after'] = changed_ip_neighbor_facts

        new_config = changed_ip_neighbor_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_ip_neighbor_facts,
                                        TEST_KEYS_formatted_diff)
            result['after(generated)'] = new_config

        if self._module._diff:
            result['diff'] = get_formatted_config_diff(existing_ip_neighbor_facts,
                                                       new_config,
                                                       self._module._verbosity)
        result['warnings'] = warnings
        return result

    def set_config(self, existing_ip_neighbor_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_ip_neighbor_facts

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
        want = remove_empties(want)

        if state == 'merged':
            commands, requests = self._state_merged(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have)
        elif state == 'overridden':
            commands, requests = self._state_overridden(want, have)

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = get_diff(want, have)
        requests = []

        if commands:
            requests = self.build_merge_requests(commands)

        if len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        delete_all = False
        if not want:
            tmp_commands = have
            delete_all = True
        else:
            tmp_commands = want
            tmp_commands = self.preprocess_delete_commands(tmp_commands, have)

        commands = get_diff(tmp_commands, IP_NEIGH_CONFIG_DEFAULT)

        requests = []
        if commands:
            requests = self.build_delete_requests(commands, delete_all)

        if len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []

        return commands, requests

    def _state_replaced(self, want, have):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        new_want = self.augment_want_with_default(want)
        commands = get_diff(new_want, have)

        requests = []
        if commands:
            requests = self.build_merge_requests(commands)

        if len(requests) > 0:
            commands = update_states(commands, "replaced")
        else:
            commands = []

        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        new_want = self.augment_want_with_default(want)
        commands = get_diff(new_want, have)

        requests = []
        if commands:
            requests = self.build_merge_requests(commands)

        if len(requests) > 0:
            commands = update_states(commands, "overridden")
        else:
            commands = []

        return commands, requests

    def preprocess_delete_commands(self, commands, have):
        new_commands = dict()

        if 'ipv4_arp_timeout' in commands:
            new_commands['ipv4_arp_timeout'] = have['ipv4_arp_timeout']

        if 'ipv4_drop_neighbor_aging_time' in commands:
            new_commands['ipv4_drop_neighbor_aging_time'] = have['ipv4_drop_neighbor_aging_time']

        if 'ipv6_drop_neighbor_aging_time' in commands:
            new_commands['ipv6_drop_neighbor_aging_time'] = have['ipv6_drop_neighbor_aging_time']

        if 'ipv6_nd_cache_expiry' in commands:
            new_commands['ipv6_nd_cache_expiry'] = have['ipv6_nd_cache_expiry']

        if 'num_local_neigh' in commands:
            new_commands['num_local_neigh'] = have['num_local_neigh']

        return new_commands

    def augment_want_with_default(self, want):
        new_want = IP_NEIGH_CONFIG_DEFAULT.copy()

        if 'ipv4_arp_timeout' in want:
            new_want['ipv4_arp_timeout'] = want['ipv4_arp_timeout']

        if 'ipv4_drop_neighbor_aging_time' in want:
            new_want['ipv4_drop_neighbor_aging_time'] = want['ipv4_drop_neighbor_aging_time']

        if 'ipv6_drop_neighbor_aging_time' in want:
            new_want['ipv6_drop_neighbor_aging_time'] = want['ipv6_drop_neighbor_aging_time']

        if 'ipv6_nd_cache_expiry' in want:
            new_want['ipv6_nd_cache_expiry'] = want['ipv6_nd_cache_expiry']

        if 'num_local_neigh' in want:
            new_want['num_local_neigh'] = want['num_local_neigh']

        return new_want

    def build_create_all_requests(self):
        requests = []
        payload = {
            "openconfig-neighbor:neighbor-global":
                [{"name": "Values",
                  "config": IP_NEIGH_CONFIG_REQ_DEFAULT}]
        }
        method = PUT

        request = {"path": GLB_URL, "method": method, "data": payload}
        requests.append(request)
        return requests

    def build_merge_requests(self, conf):
        requests = []
        ip_neigh_config = dict()

        if 'ipv4_arp_timeout' in conf:
            ip_neigh_config['ipv4-arp-timeout'] = conf['ipv4_arp_timeout']

        if 'ipv4_drop_neighbor_aging_time' in conf:
            ip_neigh_config['ipv4-drop-neighbor-aging-time'] = conf['ipv4_drop_neighbor_aging_time']

        if 'ipv6_drop_neighbor_aging_time' in conf:
            ip_neigh_config['ipv6-drop-neighbor-aging-time'] = conf['ipv6_drop_neighbor_aging_time']

        if 'ipv6_nd_cache_expiry' in conf:
            ip_neigh_config['ipv6-nd-cache-expiry'] = conf['ipv6_nd_cache_expiry']

        if 'num_local_neigh' in conf:
            ip_neigh_config['num-local-neigh'] = conf['num_local_neigh']

        if ip_neigh_config:
            payload = {'config': ip_neigh_config}
            method = PATCH
            requests = {"path": CONFIG_URL, "method": method, "data": payload}

        return requests

    def build_delete_requests(self, conf, delete_all):
        requests = []
        method = DELETE

        if delete_all:
            request = {"path": URL, "method": method}
            requests.append(request)
            return requests

        if 'ipv4_arp_timeout' in conf:
            req_url = CONFIG_URL + '/ipv4-arp-timeout'
            request = {"path": req_url, "method": method}
            requests.append(request)

        if 'ipv4_drop_neighbor_aging_time' in conf:
            req_url = CONFIG_URL + '/ipv4-drop-neighbor-aging-time'
            request = {"path": req_url, "method": method}
            requests.append(request)

        if 'ipv6_drop_neighbor_aging_time' in conf:
            req_url = CONFIG_URL + '/ipv6-drop-neighbor-aging-time'
            request = {"path": req_url, "method": method}
            requests.append(request)

        if 'ipv6_nd_cache_expiry' in conf:
            req_url = CONFIG_URL + '/ipv6-nd-cache-expiry'
            request = {"path": req_url, "method": method}
            requests.append(request)

        if 'num_local_neigh' in conf:
            req_url = CONFIG_URL + '/num-local-neigh'
            request = {"path": req_url, "method": method}
            requests.append(request)

        return requests
