#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_qos_scheduler class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from copy import deepcopy
from ansible.module_utils.connection import ConnectionError
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    get_replaced_config,
    remove_empties_from_list,
    update_states
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_CONFIG_IF_NO_SUBCONFIG,
    get_new_config,
    get_formatted_config_diff
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)


QOS_SCHEDULER_PATH = '/data/openconfig-qos:qos/scheduler-policies'
PATCH = 'patch'
DELETE = 'delete'
TEST_KEYS = [
    {'config': {'name': ''}},
    {'schedulers': {'sequence': ''}}
]
TEST_KEYS_formatted_diff = [
    {'config': {'name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'schedulers': {'sequence': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}}
]


class Qos_scheduler(ConfigBase):
    """
    The sonic_qos_scheduler class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'qos_scheduler',
    ]

    def __init__(self, module):
        super(Qos_scheduler, self).__init__(module)

    def get_qos_scheduler_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        qos_scheduler_facts = facts['ansible_network_resources'].get('qos_scheduler')
        if not qos_scheduler_facts:
            return []
        return qos_scheduler_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = []
        commands = []

        existing_qos_scheduler_facts = self.get_qos_scheduler_facts()
        commands, requests = self.set_config(existing_qos_scheduler_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_qos_scheduler_facts = self.get_qos_scheduler_facts()

        result['before'] = existing_qos_scheduler_facts
        if result['changed']:
            result['after'] = changed_qos_scheduler_facts

        new_config = changed_qos_scheduler_facts
        old_config = existing_qos_scheduler_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_qos_scheduler_facts,
                                        TEST_KEYS_formatted_diff)
            result['after(generated)'] = new_config
        if self._module._diff:
            self.sort_lists_in_config(new_config)
            self.sort_lists_in_config(old_config)
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)

        result['warnings'] = warnings
        return result

    def set_config(self, existing_qos_scheduler_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = remove_empties_from_list(self._module.params['config'])
        have = remove_empties_from_list(existing_qos_scheduler_facts)
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
        diff = get_diff(want, have, TEST_KEYS)

        if state == 'overridden':
            commands, requests = self._state_overridden(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have, diff)
        return commands, requests

    def _state_replaced(self, want, have, diff):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        self.get_error_msg(want, 'Replaced')
        commands = []
        requests = []
        replaced_config = get_replaced_config(want, have, TEST_KEYS)

        mod_commands = []
        if replaced_config:
            self.sort_lists_in_config(replaced_config)
            self.sort_lists_in_config(have)
            is_delete_all = replaced_config == have
            del_requests = self.get_delete_qos_scheduler_requests(replaced_config, have, is_delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(replaced_config, 'deleted'))
            mod_commands = want
        else:
            mod_commands = diff

        if mod_commands:
            mod_request = self.get_modify_qos_scheduler_request(mod_commands)

            if mod_request:
                requests.append(mod_request)
                commands.extend(update_states(mod_commands, 'replaced'))
        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        self.get_error_msg(want, 'Overridden')
        commands = []
        requests = []
        self.sort_lists_in_config(want)
        self.sort_lists_in_config(have)

        new_have = deepcopy(have)
        self.filter_scheduler_policies(new_have)
        if new_have and new_have != want:
            is_delete_all = True
            del_requests = self.get_delete_qos_scheduler_requests(new_have, None, is_delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(new_have, 'deleted'))
            new_have = []

        if not new_have and want:
            mod_commands = want
            mod_request = self.get_modify_qos_scheduler_request(mod_commands)

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
        requests = self.get_modify_qos_scheduler_request(commands)

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
        is_delete_all = False

        if not want:
            commands = deepcopy(have)
            is_delete_all = True
            self.filter_scheduler_policies(commands)
        else:
            commands = deepcopy(want)

        requests = self.get_delete_qos_scheduler_requests(commands, have, is_delete_all)

        if commands and len(requests) > 0:
            commands = update_states(commands, 'deleted')
        else:
            commands = []
        return commands, requests

    def get_modify_qos_scheduler_request(self, commands):
        request = None

        if commands:
            policy_list = []
            for policy in commands:
                policy_dict = {}
                name = policy.get('name')
                schedulers = policy.get('schedulers')
                if schedulers:
                    scheduler_list = []
                    for scheduler in schedulers:
                        cfg_dict = {}
                        trtc_cfg_dict = {}
                        scheduler_dict = {}
                        sequence = scheduler.get('sequence')
                        scheduler_type = scheduler.get('scheduler_type')
                        weight = scheduler.get('weight')
                        meter_type = scheduler.get('meter_type')
                        cir = scheduler.get('cir')
                        pir = scheduler.get('pir')
                        cbs = scheduler.get('cbs')
                        pbs = scheduler.get('pbs')

                        if sequence is not None:
                            if not (0 <= sequence <= 47 or sequence == 255):
                                self._module.fail_json(msg='Sequence attribute out of range. Please specify a sequence value within range 0-47'
                                                       ' for a CPU queue or a value of 255 for a port queue.')
                            else:
                                cfg_dict['sequence'] = sequence
                        if scheduler_type:
                            cfg_dict['priority'] = scheduler_type.upper()
                        if weight:
                            cfg_dict['weight'] = weight
                        if meter_type:
                            cfg_dict['meter-type'] = meter_type.upper()
                        if cir:
                            trtc_cfg_dict['cir'] = str(cir)
                        if pir:
                            trtc_cfg_dict['pir'] = str(pir)
                        if cbs:
                            trtc_cfg_dict['bc'] = cbs
                        if pbs:
                            trtc_cfg_dict['be'] = pbs

                        if cfg_dict:
                            scheduler_dict['sequence'] = sequence
                            scheduler_dict['config'] = cfg_dict
                        if trtc_cfg_dict:
                            scheduler_dict['two-rate-three-color'] = {'config': trtc_cfg_dict}
                        if scheduler_dict:
                            scheduler_list.append(scheduler_dict)
                    if scheduler_list:
                        policy_dict['schedulers'] = {'scheduler': scheduler_list}
                if name:
                    policy_dict['name'] = name
                    policy_dict['config'] = {'name': name}
                if policy_dict:
                    policy_list.append(policy_dict)
            if policy_list:
                payload = {'openconfig-qos:scheduler-policies': {'scheduler-policy': policy_list}}
                request = {'path': QOS_SCHEDULER_PATH, 'method': PATCH, 'data': payload}

        return request

    def get_delete_qos_scheduler_requests(self, commands, have, is_delete_all):
        requests = []

        if not commands:
            return requests

        if is_delete_all:
            requests.append({'path': QOS_SCHEDULER_PATH, 'method': DELETE})
            return requests

        config_list = []
        for policy in commands:
            index = commands.index(policy)
            name = policy.get('name')
            schedulers = policy.get('schedulers')

            for cfg_policy in have:
                cfg_name = cfg_policy.get('name')
                cfg_schedulers = cfg_policy.get('schedulers')

                if name == cfg_name:
                    if schedulers:
                        schedulers_list = []
                        for scheduler in schedulers:
                            sequence = scheduler.get('sequence')
                            scheduler_type = scheduler.get('scheduler_type')
                            weight = scheduler.get('weight')
                            meter_type = scheduler.get('meter_type')
                            cir = scheduler.get('cir')
                            pir = scheduler.get('pir')
                            cbs = scheduler.get('cbs')
                            pbs = scheduler.get('pbs')

                            if cfg_schedulers:
                                for cfg_scheduler in cfg_schedulers:
                                    scheduler_dict = {}
                                    cfg_sequence = cfg_scheduler.get('sequence')
                                    cfg_scheduler_type = cfg_scheduler.get('scheduler_type')
                                    cfg_weight = cfg_scheduler.get('weight')
                                    cfg_meter_type = cfg_scheduler.get('meter_type')
                                    cfg_cir = cfg_scheduler.get('cir')
                                    cfg_pir = cfg_scheduler.get('pir')
                                    cfg_cbs = cfg_scheduler.get('cbs')
                                    cfg_pbs = cfg_scheduler.get('pbs')

                                    if sequence is not None and sequence == cfg_sequence:
                                        # Weight must be deleted before scheduler type
                                        if weight and weight == cfg_weight:
                                            requests.append(self.get_delete_scheduler_cfg_attr(name, sequence, 'weight'))
                                            scheduler_dict.update({'sequence': sequence, 'weight': weight})
                                        if scheduler_type and scheduler_type == cfg_scheduler_type:
                                            requests.append(self.get_delete_scheduler_cfg_attr(name, sequence, 'priority'))
                                            scheduler_dict.update({'sequence': sequence, 'scheduler_type': scheduler_type})
                                        if meter_type and meter_type == cfg_meter_type:
                                            requests.append(self.get_delete_scheduler_cfg_attr(name, sequence, 'meter-type'))
                                            scheduler_dict.update({'sequence': sequence, 'meter_type': meter_type})
                                        if cir and cir == cfg_cir:
                                            requests.append(self.get_delete_trtc_cfg_attr(name, sequence, 'cir'))
                                            scheduler_dict.update({'sequence': sequence, 'cir': cir})
                                        if pir and pir == cfg_pir:
                                            requests.append(self.get_delete_trtc_cfg_attr(name, sequence, 'pir'))
                                            scheduler_dict.update({'sequence': sequence, 'pir': pir})
                                        if cbs and cbs == cfg_cbs:
                                            requests.append(self.get_delete_trtc_cfg_attr(name, sequence, 'bc'))
                                            scheduler_dict.update({'sequence': sequence, 'cbs': cbs})
                                        if pbs and pbs == cfg_pbs:
                                            requests.append(self.get_delete_trtc_cfg_attr(name, sequence, 'be'))
                                            scheduler_dict.update({'sequence': sequence, 'pbs': pbs})
                                        if not scheduler_type and not weight and not meter_type and not cir and not pir and not cbs and not pbs:
                                            requests.append(self.get_delete_scheduler_sequence(name, sequence))
                                            scheduler_dict.update({'sequence': sequence})
                                        if scheduler_dict:
                                            schedulers_list.append(scheduler_dict)
                                        break
                        if schedulers_list:
                            config_list.append({'name': name, 'schedulers': schedulers_list})

                    # Deletion of scheduler policy by name
                    else:
                        requests.append(self.get_delete_scheduler_policy(name))
                        config_list.append({'name': name})
                    break

        commands = config_list
        return requests

    def sort_lists_in_config(self, config):
        if config:
            config.sort(key=lambda x: x['name'])
            for policy in config:
                if 'schedulers' in policy and policy['schedulers']:
                    policy['schedulers'].sort(key=lambda x: x['sequence'])

    def filter_scheduler_policies(self, config):
        if config:
            index = None
            for policy in config:
                name = policy.get('name')
                if name == 'copp-scheduler-policy':
                    index = config.index(policy)
                    break
            if index is not None:
                config.pop(index)
                config = remove_empties_from_list(config)

    def get_error_msg(self, want, state):
        if want:
            for policy in want:
                name = policy.get('name')
                if name == 'copp-scheduler-policy':
                    self._module.fail_json(msg=state + ' not supported for copp-scheduler-policy. Use merged and/or deleted state(s).')

    def get_delete_scheduler_policy(self, name):
        url = '%s/scheduler-policy=%s' % (QOS_SCHEDULER_PATH, name)
        request = {'path': url, 'method': DELETE}

        return request

    def get_delete_scheduler_sequence(self, name, sequence):
        url = '%s/scheduler-policy=%s/schedulers/scheduler=%s' % (QOS_SCHEDULER_PATH, name, sequence)
        request = {'path': url, 'method': DELETE}

        return request

    def get_delete_scheduler_cfg_attr(self, name, sequence, attr):
        url = '%s/scheduler-policy=%s/schedulers/scheduler=%s/config/%s' % (QOS_SCHEDULER_PATH, name, sequence, attr)
        request = {'path': url, 'method': DELETE}

        return request

    def get_delete_trtc_cfg_attr(self, name, sequence, attr):
        url = '%s/scheduler-policy=%s/schedulers/scheduler=%s/two-rate-three-color/config/%s' % (QOS_SCHEDULER_PATH, name, sequence, attr)
        request = {'path': url, 'method': DELETE}

        return request
