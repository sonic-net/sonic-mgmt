#
# -*- coding: utf-8 -*-
# © Copyright 2020 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_port_group class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

"""
The use of natsort causes sanity error due to it is not available in python version currently used.
When natsort becomes available, the code here and below using it will be applied.
from natsort import (
    natsorted,
    ns
)
"""
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import (
    Facts,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    update_states,
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_CONFIG_IF_NO_SUBCONFIG,
    get_new_config,
    get_formatted_config_diff
)
from ansible.module_utils.connection import ConnectionError

GET = "get"
PATCH = 'patch'
DELETE = 'delete'
url = 'data/openconfig-port-group:port-groups/port-group'

TEST_KEYS = [
    {
        'config': {'id': ''}
    }
]
TEST_KEYS_formatted_diff = [
    {'config': {'id': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}}
]


class Port_group(ConfigBase):
    """
    The sonic_port_group class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'port_group',
    ]

    pg_default_speeds_ready = False
    pg_default_speeds = []

    def __init__(self, module):
        super(Port_group, self).__init__(module)

        if not Port_group.pg_default_speeds_ready:
            Port_group.pg_default_speeds = self.get_port_group_default_speed()
            Port_group.pg_default_speeds_ready = True

    def get_port_group_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        port_group_facts = facts['ansible_network_resources'].get('port_group')
        if not port_group_facts:
            return []
        return port_group_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()

        existing_port_group_facts = self.get_port_group_facts()
        commands, requests = self.set_config(existing_port_group_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_port_group_facts = self.get_port_group_facts()

        result['before'] = existing_port_group_facts
        if result['changed']:
            result['after'] = changed_port_group_facts

        new_config = changed_port_group_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_port_group_facts,
                                        TEST_KEYS_formatted_diff)
            # See the above comment about natsort module
            # new_config = natsorted(new_config, key=lambda x: x['id'])
            result['after(generated)'] = new_config

        if self._module._diff:
            result['diff'] = get_formatted_config_diff(existing_port_group_facts,
                                                       new_config,
                                                       self._module._verbosity)
        result['warnings'] = warnings
        return result

    def set_config(self, existing_port_group_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_port_group_facts

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

        tmp_want = remove_empties_from_list(want)
        new_want = self.remove_empty_dict_from_list(tmp_want)

        new_diff = self.remove_empty_dict_from_list(diff)

        if state == 'overridden':
            commands, requests = self._state_overridden(new_want, have, new_diff)
        elif state == 'deleted':
            commands, requests = self._state_deleted(new_want, have, new_diff)
        elif state == 'merged':
            commands, requests = self._state_merged(new_want, have, new_diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(new_want, have, new_diff)

        return commands, requests

    def _state_replaced(self, want, have, diff):
        """ The command generator when state is replaced

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :param diff: the difference between want and have
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = diff
        requests = []
        if commands:
            requests = self.build_merge_requests(commands)

        if len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []

        return commands, requests

    def _state_overridden(self, want, have, diff):
        """ The command generator when state is overridden

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :param diff: the difference between want and have
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        new_want = self.patch_want_with_default(want)
        commands = get_diff(new_want, have, TEST_KEYS)
        requests = []
        if commands:
            requests = self.build_merge_requests(commands)

        if len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []

        return commands, requests

    def _state_merged(self, want, have, diff):
        """ The command generator when state is merged

        :param want: the additive configuration as a dictionary
        :param have: the current configuration as a dictionary
        :param diff: the difference between want and have
        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        requests = []
        if commands:
            requests = self.build_merge_requests(commands)

        if len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have, diff):
        """ The command generator when state is deleted

        :param want: the objects from which the configuration should be removed
        :param have: the current configuration as a dictionary
        :param diff: the difference between want and have
        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        # if want is none, then delete all the port groups

        if not want:
            tmp_commands = have
        else:
            tmp_commands = want
            tmp_commands = self.preprocess_delete_commands(tmp_commands, have)

        commands = get_diff(tmp_commands, Port_group.pg_default_speeds, TEST_KEYS)

        requests = []
        if commands:
            requests = self.build_delete_requests(commands)

        if len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []

        return commands, requests

    def search_port_groups(self, id, pgs):

        found_pg = dict()
        if pgs is not None:
            for pg in pgs:
                if pg['id'] == id:
                    found_pg = pg
        return found_pg

    def preprocess_delete_commands(self, commands, have):
        new_commands = []
        for cmd in commands:
            pg_id = cmd['id']
            pg = self.search_port_groups(pg_id, have)
            if pg:
                new_cmd = {'id': pg_id, 'speed': pg['speed']}
                new_commands.append(new_cmd)

        return new_commands

    def remove_empty_dict_from_list(self, dict_list):
        new_dict_list = []
        if dict_list:
            for dictt in dict_list:
                if dictt:
                    new_dict_list.append(dictt)

        return new_dict_list

    def build_delete_requests(self, confs):
        requests = []

        for conf in confs:
            pg_id = conf['id']
            method = DELETE
            pg_url = (url + '=%s/config/speed') % (pg_id)
            request = {"path": pg_url, "method": method}
            requests.append(request)

        return requests

    def build_merge_requests(self, confs):
        requests = []
        pgs = []
        for conf in confs:
            pg_id = conf['id']
            if 'speed' in conf:
                pg_conf = {'id': pg_id, 'speed': 'openconfig-if-ethernet:' + conf['speed']}
                pg = {'id': pg_id, 'config': pg_conf}
                pgs.append(pg)

        if pgs:
            payload = {"openconfig-port-group:port-group": pgs}
            method = PATCH
            pg_url = url
            request = {"path": pg_url, "method": method, "data": payload}
            requests.append(request)

        return requests

    def patch_want_with_default(self, want):
        new_want = list()
        for dpg in Port_group.pg_default_speeds:
            pg_id = dpg['id']
            pg = self.search_port_groups(pg_id, want)
            if pg:
                new_pg = {'id': pg_id, 'speed': pg['speed']}
            else:
                new_pg = {'id': pg_id, 'speed': dpg['speed']}

            new_want.append(new_pg)
        return new_want

    def get_port_group_default_speed(self):
        """Get all the port group default speeds"""

        pgs_request = [{"path": "data/openconfig-port-group:port-groups/port-group", "method": GET}]
        try:
            pgs_response = edit_config(self._module, to_request(self._module, pgs_request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        pgs_config = []
        if "openconfig-port-group:port-group" in pgs_response[0][1]:
            pgs_config = pgs_response[0][1].get("openconfig-port-group:port-group", [])

        pgs_dft_speeds = []
        for pg_config in pgs_config:
            pg_state = dict()
            if 'state' in pg_config:
                pg_state['id'] = pg_config['id']
                dft_speed_str = pg_config['state'].get('default-speed', None)
                if dft_speed_str:
                    pg_state['speed'] = dft_speed_str.split(":", 1)[-1]
                    pgs_dft_speeds.append(pg_state)

        return pgs_dft_speeds
