#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_ptp_default_ds class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

import copy
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
    get_normalize_interface_name,
    remove_empties
)
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


class Ptp_default_ds(ConfigBase):
    """
    The sonic_ptp_default_ds class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'ptp_default_ds',
    ]

    ptp_default_ds_path = 'data/ietf-ptp:ptp/instance-list=0/default-ds'
    ptp_default_ds_config_path = {
        'priority1': ptp_default_ds_path + '/priority1',
        'priority2': ptp_default_ds_path + '/priority2',
        'domain_number': ptp_default_ds_path + '/domain-number',
        'log_announce_interval': ptp_default_ds_path + '/ietf-ptp-ext:log-announce-interval',
        'announce_receipt_timeout': ptp_default_ds_path + '/ietf-ptp-ext:announce-receipt-timeout',
        'log_sync_interval': ptp_default_ds_path + '/ietf-ptp-ext:log-sync-interval',
        'log_min_delay_req_interval': ptp_default_ds_path + '/ietf-ptp-ext:log-min-delay-req-interval',
        'two_step_flag': ptp_default_ds_path + '/two-step-flag',
        'clock_type': ptp_default_ds_path + '/ietf-ptp-ext:clock-type',
        'network_transport': ptp_default_ds_path + '/ietf-ptp-ext:network-transport',
        'unicast_multicast': ptp_default_ds_path + '/ietf-ptp-ext:unicast-multicast',
        'domain_profile': ptp_default_ds_path + '/ietf-ptp-ext:domain-profile',
        'source_interface': ptp_default_ds_path + '/ietf-ptp-ext:source-interface',
    }

    def __init__(self, module):
        super(Ptp_default_ds, self).__init__(module)

    def get_ptp_default_ds_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        ptp_default_ds_facts = facts['ansible_network_resources'].get('ptp_default_ds')
        if not ptp_default_ds_facts:
            return []
        return ptp_default_ds_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = []

        existing_ptp_default_ds_facts = self.get_ptp_default_ds_facts()
        commands, requests = self.set_config(existing_ptp_default_ds_facts)
        if commands:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True

        old_config = existing_ptp_default_ds_facts
        result['before'] = old_config
        result['commands'] = commands

        if self._module.check_mode:
            new_config = get_new_config(commands, existing_ptp_default_ds_facts)
            result['after(generated)'] = new_config
        else:
            new_config = self.get_ptp_default_ds_facts()
            if result['changed']:
                result['after'] = new_config

        if self._module._diff:
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)
        result['warnings'] = warnings
        return result

    def set_config(self, existing_ptp_default_ds_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']

        if want:
            want = remove_empties(want)

            if want.get("source_interface") is not None:
                want["source_interface"] = get_normalize_interface_name(want["source_interface"], self._module)
        have = existing_ptp_default_ds_facts
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
        diff = get_diff(want, have)
        if state == 'deleted':
            commands, requests = self._state_deleted(want, have, diff)
        elif state == 'merged':
            commands, requests = self._state_merged(diff)
        elif state == 'overridden' or state == 'replaced':
            commands, requests = self._state_replaced_or_overridden(want, have, state)

        return commands, requests

    def _state_replaced_or_overridden(self, want, have, state):
        """ The command generator when state is replaced or overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []

        new_have = copy.deepcopy(have)

        if len(new_have) == 1 and new_have.get("domain_number") is not None:
            if len(want) == 1 and want.get("domain_number") is not None and want == new_have:
                return commands, requests
            if new_have["domain_number"] == 0:
                new_have.pop("domain_number")

        if want == new_have:
            return commands, requests

        if new_have:
            requests.extend(self.get_delete_ptp_default_ds_completely_requests(new_have))
            commands.extend(update_states(new_have, "deleted"))

        if want:
            mod_requests = self.get_modify_specific_ptp_default_ds_param_requests(want)
            if len(mod_requests) > 0:
                requests.extend(mod_requests)
                commands.extend(update_states(want, state))

        return commands, requests

    def _state_merged(self, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        requests = self.get_modify_specific_ptp_default_ds_param_requests(commands)
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
        commands = []
        requests = []
        new_have = copy.deepcopy(have)

        if len(new_have) == 1 and new_have.get("domain_number") is not None:
            new_have.pop("domain_number")

        if not new_have:
            return commands, requests
        elif not want:
            commands = new_have
            requests.extend(self.get_delete_ptp_default_ds_completely_requests(commands))
        else:
            commands = get_diff(want, diff)
            requests.extend(self.get_delete_specific_ptp_default_ds_param_requests(commands, new_have))
        if len(requests) == 0:
            commands = []

        if commands:
            commands = update_states(commands, "deleted")

        return commands, requests

    def get_modify_specific_ptp_default_ds_param_requests(self, command):
        """Get requests to modify specific PTP default ds configurations
        based on the command specified for the interface
        """
        requests = []

        if not command:
            return requests

        # The order of PTP default ds modify requests are to be retained to avoid REST failures
        options = ('priority1', 'priority2', 'clock_type', 'network_transport', 'unicast_multicast',
                   'domain_number', 'domain_profile', 'two_step_flag', 'source_interface',
                   'log_announce_interval', 'announce_receipt_timeout', 'log_sync_interval',
                   'log_min_delay_req_interval')
        for option in options:
            if command.get(option) is not None:
                path = self.ptp_default_ds_config_path[option]
                payload = {path.split("/")[-1]: command[option]}
                requests.append({'path': path, 'method': PATCH, 'data': payload})

        return requests

    def get_delete_ptp_default_ds_completely_requests(self, have):
        """Get requests to delete all existing PTP default ds
        configurations in the chassis
        """
        requests = []
        if have:
            url = self.ptp_default_ds_path
            requests.append({'path': url, 'method': DELETE})

        return requests

    def get_delete_specific_ptp_default_ds_param_requests(self, command, config):
        """Get requests to delete specific PTP default ds configurations
        based on the command specified for the interface
        """
        requests = []

        if not command:
            return requests

        # The order of PTP default ds delete requests are to be retained to avoid REST failures
        options = ('priority1', 'priority2', 'source_interface', 'log_announce_interval',
                   'announce_receipt_timeout', 'log_sync_interval', 'log_min_delay_req_interval',
                   'two_step_flag', 'domain_profile', 'domain_number', 'network_transport',
                   'unicast_multicast', 'clock_type')
        for option in options:
            if option in command:
                requests.append({'path': self.ptp_default_ds_config_path[option], 'method': DELETE})

        return requests
