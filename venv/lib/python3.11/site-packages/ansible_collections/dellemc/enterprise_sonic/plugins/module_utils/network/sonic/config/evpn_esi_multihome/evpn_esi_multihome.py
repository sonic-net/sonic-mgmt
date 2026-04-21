#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_evpn_esi_multihome class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    update_states,
    get_diff,
    remove_none
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    get_new_config,
    get_formatted_config_diff
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts

PATCH = "patch"
DELETE = "delete"
EVPN_MH_PATH = 'data/openconfig-network-instance:network-instances/network-instance=default/evpn/evpn-mh/config'


class Evpn_esi_multihome(ConfigBase):
    """
    The sonic_evpn_esi_multihome class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'evpn_esi_multihome',
    ]

    def __init__(self, module):
        super(Evpn_esi_multihome, self).__init__(module)

    def get_evpn_esi_multihome_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        evpn_esi_multihome_facts = facts['ansible_network_resources'].get('evpn_esi_multihome')
        if evpn_esi_multihome_facts is None:
            return {}
        return evpn_esi_multihome_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        commands = []
        existing_evpn_esi_multihome_facts = self.get_evpn_esi_multihome_facts()
        commands, requests = self.set_config(existing_evpn_esi_multihome_facts)

        if commands and requests:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True

        result['commands'] = commands
        result['before'] = existing_evpn_esi_multihome_facts
        old_config = existing_evpn_esi_multihome_facts

        if self._module.check_mode:
            new_config = get_new_config(commands, existing_evpn_esi_multihome_facts)
            result['after(generated)'] = new_config
        else:
            new_config = self.get_evpn_esi_multihome_facts()
            if result['changed']:
                result['after'] = new_config
        if self._module._diff:
            result['diff'] = get_formatted_config_diff(old_config, new_config, self._module._verbosity)

        return result

    def set_config(self, existing_evpn_esi_multihome_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: Two lists
        :returns: the commands and requests necessary to migrate the current configuration
                  to the desired configuration
        """
        want = remove_none(self._module.params['config'])
        have = existing_evpn_esi_multihome_facts
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
        if state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)
        elif state == 'overridden' or state == 'replaced':
            commands, requests = self._state_replaced_or_overridden(want, have, state)
        return commands, requests

    def _state_replaced_or_overridden(self, want, have, state):
        """
        The command generator when state is overridden
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []

        if not want:
            return commands, requests

        del_commands = get_diff(have, want)
        merged_commands = None
        merged_request = None

        if del_commands:
            del_requests = self.get_delete_evpn_esi_mh_requests(have, True)
            requests.extend(del_requests)
            commands.extend(update_states(have, "deleted"))
            merged_commands = want
            merged_request = self.get_create_evpn_esi_mh_request(merged_commands)
        else:
            merged_commands = get_diff(want, have)
            if merged_commands:
                merged_request = self.get_create_evpn_esi_mh_request(merged_commands)

        if merged_request:
            requests.append(merged_request)
            commands.extend(update_states(merged_commands, state))

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A list and a dict
        :returns: the commands and requests necessary to merge the provided into
                  the current configuration
        """
        commands = get_diff(want, have)
        requests = self.get_create_evpn_esi_mh_request(commands)

        if commands and len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :rtype: Two lists
        :returns: the commands and requests necessary to remove the current configuration
                  of the provided objects
        """
        requests = []
        commands = []

        if not have:
            return commands, requests

        delete_all = False

        if not want:
            commands = deepcopy(have)
            delete_all = True
        else:
            diff = get_diff(want, have)
            commands = get_diff(want, diff)

        requests = self.get_delete_evpn_esi_mh_requests(commands, delete_all)

        if commands and len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []

        return commands, requests

    def get_create_evpn_esi_mh_request(self, config):
        """ Creates the request for creating the evpn_esi_mh object
        :rtype: A dict
        :returns: the request for creating the evpn_esi_mh object
        """
        cfg_dict = {}
        request = None

        if not config:
            return request

        if config.get('df_election_time') is not None:
            cfg_dict['df-election-time'] = config['df_election_time']
        if config.get('es_activation_delay') is not None:
            cfg_dict['es-activation-delay'] = config['es_activation_delay']
        if config.get('mac_holdtime') is not None:
            cfg_dict['mac-holdtime'] = config['mac_holdtime']
        if config.get('neigh_holdtime') is not None:
            cfg_dict['neigh-holdtime'] = config['neigh_holdtime']
        if config.get('startup_delay') is not None:
            cfg_dict['startup-delay'] = config['startup_delay']

        request_info = {'openconfig-network-instance:config': cfg_dict}

        request = {'path': EVPN_MH_PATH, 'method': PATCH, 'data': request_info}
        return request

    def get_delete_evpn_esi_mh_request(self, attr=None, is_delete_all=False):
        url = EVPN_MH_PATH
        # For delete all, the configuration must be deleted at this url to truly remove the entry from DB
        if is_delete_all:
            url = url.replace('/config', '')
        elif attr:
            url = '{0}/{1}'.format(url, attr)
        request = {'path': url, 'method': DELETE}
        return request

    def get_delete_evpn_esi_mh_requests(self, configs, delete_all):
        """ Creates the request for deleting the evpn_esi_mh object

        :rtype: A list
        :returns: the requests for deleting the evpn_esi_mh object
        """
        requests = []
        if not configs:
            return requests

        if delete_all:
            requests.append(self.get_delete_evpn_esi_mh_request(None, delete_all))
            return requests

        if configs.get('df_election_time') is not None:
            requests.append(self.get_delete_evpn_esi_mh_request('df-election-time'))

        if configs.get('es_activation_delay') is not None:
            requests.append(self.get_delete_evpn_esi_mh_request('es-activation-delay'))

        if configs.get('mac_holdtime') is not None:
            requests.append(self.get_delete_evpn_esi_mh_request('mac-holdtime'))

        if configs.get('neigh_holdtime') is not None:
            requests.append(self.get_delete_evpn_esi_mh_request('neigh-holdtime'))

        if configs.get('startup_delay') is not None:
            requests.append(self.get_delete_evpn_esi_mh_request('startup-delay'))

        return requests
