#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_bgp class
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
    remove_empties,
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
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF,
    get_new_config,
    get_formatted_config_diff
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import to_request
from ansible.module_utils.connection import ConnectionError
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.bgp_utils import (
    convert_bgp_asn,
    to_bgp_as_notation_request_type
)

PATCH = 'patch'
POST = 'post'
DELETE = 'delete'
PUT = 'put'

TEST_KEYS = [{'config': {'vrf_name': '', 'bgp_as': ''}}]

is_delete_all = False


def __derive_bgp_delete_op(key_set, command, exist_conf):
    if is_delete_all:
        new_conf = []
        return True, new_conf

    return __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, exist_conf)


def __derive_bgp_timer_delete_op(key_set, command, exist_conf):
    new_conf = exist_conf
    if command.get('holdtime', None):
        new_conf['holdtime'] = 180
    if command.get('keepalive_interval', None):
        new_conf['holdtime'] = 60
    return True, new_conf


TEST_KEYS_generate_config = [
    {'config': {'vrf_name': '', 'bgp_as': '', '__delete_op': __derive_bgp_delete_op}},
    {'bestpath': {'__delete_op': __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'as_path': {'__delete_op': __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'on_startup': {'__delete_op': __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'med': {'__delete_op': __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'timers': {'__delete_op': __derive_bgp_timer_delete_op}}
]


class Bgp(ConfigBase):
    """
    The sonic_bgp class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'bgp',
    ]

    network_instance_path = '/data/openconfig-network-instance:network-instances/network-instance'
    protocol_bgp_path = 'protocols/protocol=BGP,bgp/bgp'
    log_neighbor_changes_path = 'logging-options/config/log-neighbor-state-changes'
    holdtime_path = 'config/hold-time'
    keepalive_path = 'config/keepalive-interval'
    graceful_restart_path = 'graceful-restart/config'

    def __init__(self, module):
        super(Bgp, self).__init__(module)

    def get_bgp_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        bgp_facts = facts['ansible_network_resources'].get('bgp')
        if not bgp_facts:
            bgp_facts = []
        return bgp_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        existing_bgp_facts = self.get_bgp_facts()
        commands, requests = self.set_config(existing_bgp_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_bgp_facts = self.get_bgp_facts()

        result['before'] = existing_bgp_facts
        if result['changed']:
            result['after'] = changed_bgp_facts

        new_config = changed_bgp_facts
        old_config = existing_bgp_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_bgp_facts,
                                        TEST_KEYS_generate_config)
            new_config = self.post_process_generated_config(new_config)
            old_config = remove_empties_from_list(old_config)
            result['after(generated)'] = new_config

        if self._module._diff:
            self.sort_lists_in_config(new_config)
            self.sort_lists_in_config(old_config)
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)
        result['warnings'] = warnings
        return result

    def set_config(self, existing_bgp_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        if want:
            want = [remove_empties(conf) for conf in want]
            convert_bgp_asn(want)
        else:
            want = []

        have = existing_bgp_facts
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

        if state == 'overridden':
            commands, requests = self._state_overridden(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have)
        return commands, requests

    def _state_replaced(self, want, have):
        """ The command generator when state is replaced
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []

        del_commands, del_requests = self.get_delete_commands_requests_for_replaced_overridden(want, have, 'replaced')
        if del_commands:
            commands = update_states(del_commands, 'deleted')
            requests = del_requests

        add_commands = get_diff(want, have, TEST_KEYS)
        if add_commands:
            for command in add_commands:
                as_val = command['bgp_as']
                vrf_name = command['vrf_name']

                # max_med -> on_startup options are modified or deleted at once.
                # Diff might not reflect the correct commands if only one of
                # them is modified. So, update the command with want value.
                if command.get('max_med'):
                    for cfg in want:
                        if cfg['vrf_name'] == vrf_name and cfg['bgp_as'] == as_val:
                            command['max_med'] = cfg['max_med']
                            break

            commands.extend(update_states(add_commands, 'replaced'))
            requests.extend(self.get_modify_bgp_requests(add_commands, have))

        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []

        del_commands, del_requests = self.get_delete_commands_requests_for_replaced_overridden(want, have, 'overridden')
        if del_commands:
            commands = update_states(del_commands, 'deleted')
            requests = del_requests

        add_commands = get_diff(want, have, TEST_KEYS)
        if add_commands:
            for command in add_commands:
                as_val = command['bgp_as']
                vrf_name = command['vrf_name']
                # max_med -> on_startup options are modified or deleted at once.
                # Diff will not reflect the correct commands if only one of
                # them is modified. So, update the command with want value.
                if command.get('max_med'):
                    for cfg in want:
                        if cfg['vrf_name'] == vrf_name and cfg['bgp_as'] == as_val:
                            command['max_med'] = cfg['max_med']
                            break

            commands.extend(update_states(add_commands, 'overridden'))
            requests.extend(self.get_modify_bgp_requests(add_commands, have))

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :param want: the additive configuration as a dictionary
        :param obj_in_have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = get_diff(want, have, TEST_KEYS)
        requests = self.get_modify_bgp_requests(commands, have)
        if commands and len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :param want: the objects from which the configuration should be removed
        :param obj_in_have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        global is_delete_all
        is_delete_all = False
        # if want is none, then delete all the bgps

        if not want:
            commands = have
            is_delete_all = True
        else:
            commands = want

        requests = self.get_delete_bgp_requests(commands, have, is_delete_all)

        if commands and len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []

        return commands, requests

    def get_delete_single_bgp_request(self, vrf_name):
        delete_path = '%s=%s/%s' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        return ({'path': delete_path, 'method': DELETE})

    def get_delete_max_med_requests(self, vrf_name, max_med, match):
        requests = []

        match_max_med = match.get('max_med', None)
        if not max_med or not match_max_med:
            return requests

        generic_del_path = '%s=%s/%s/global/' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)

        match_max_med_on_startup = match.get('max_med', {}).get('on_startup')
        if match_max_med_on_startup:
            requests.append({'path': generic_del_path + "max-med/config/time", 'method': DELETE})
            requests.append({'path': generic_del_path + "max-med/config/max-med-val", 'method': DELETE})

        return requests

    def get_delete_bestpath_requests(self, vrf_name, bestpath, match):
        requests = []

        match_bestpath = match.get('bestpath', None)
        if not bestpath or not match_bestpath:
            return requests

        route_selection_del_path = '%s=%s/%s/global/route-selection-options/config/' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        multi_paths_del_path = '%s=%s/%s/global/use-multiple-paths/ebgp/config/' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        generic_del_path = '%s=%s/%s/global/' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)

        if bestpath.get('compare_routerid', None) and match_bestpath.get('compare_routerid', None):
            url = '%s=%s/%s/global/route-selection-options' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
            route_selection_cfg = {}
            route_selection_cfg['external-compare-router-id'] = False
            payload = {'route-selection-options': {'config': route_selection_cfg}}
            requests.append({'path': url, 'data': payload, 'method': PATCH})
            # requests.append({'path': route_selection_del_path + "external-compare-router-id", 'method': DELETE})

        match_as_path = match_bestpath.get('as_path', None)
        as_path = bestpath.get('as_path', None)
        if as_path and match_as_path:
            if as_path.get('confed', None) is not None and match_as_path.get('confed', None):
                requests.append({'path': route_selection_del_path + "compare-confed-as-path", 'method': DELETE})
            if as_path.get('ignore', None) is not None and match_as_path.get('ignore', None):
                requests.append({'path': route_selection_del_path + "ignore-as-path-length", 'method': DELETE})
            if as_path.get('multipath_relax', None) is not None and match_as_path.get('multipath_relax', None):
                requests.append({'path': multi_paths_del_path + "allow-multiple-as", 'method': DELETE})
            if as_path.get('multipath_relax_as_set', None) is not None and match_as_path.get('multipath_relax_as_set', None):
                requests.append({'path': multi_paths_del_path + "as-set", 'method': DELETE})

        match_bandwidth = match_bestpath.get('bandwidth', None)
        bandwidth = bestpath.get('bandwidth', None)
        if bandwidth and match_bandwidth and bandwidth == match_bandwidth:
            requests.append({'path': route_selection_del_path + "compare-linkbw", 'method': DELETE})

        match_med = match_bestpath.get('med', None)
        med = bestpath.get('med', None)
        if med and match_med:
            if med.get('confed', None) is not None and match_med.get('confed', None):
                requests.append({'path': route_selection_del_path + "med-confed", 'method': DELETE})
            if med.get('missing_as_worst', None) is not None and match_med.get('missing_as_worst', None):
                requests.append({'path': route_selection_del_path + "med-missing-as-worst", 'method': DELETE})
            if med.get('always_compare_med', None) is not None and match_med.get('always_compare_med', None):
                requests.append({'path': route_selection_del_path + "always-compare-med", 'method': DELETE})
            if med.get('max_med_val', None) is not None and match_med.get('max_med_val', None):
                requests.append({'path': generic_del_path + "max-med/config/admin-max-med-val", 'method': DELETE})

        return requests

    def get_delete_graceful_restart_requests(self, vrf_name, graceful_restart, match):
        requests = []
        graceful_restart_del_path = '%s=%s/%s/global/graceful-restart/config/' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        match_graceful_restart = match.get('graceful_restart', None)

        if graceful_restart and match_graceful_restart:
            if graceful_restart.get('enabled') and graceful_restart['enabled'] == match_graceful_restart.get('enabled'):
                requests.append({'path': graceful_restart_del_path + "enabled", 'method': DELETE})
            if graceful_restart.get('restart_time') is not None and graceful_restart['restart_time'] == match_graceful_restart.get('restart_time'):
                requests.append({'path': graceful_restart_del_path + "restart-time", 'method': DELETE})
            if graceful_restart.get('stale_routes_time') is not None and \
                    graceful_restart['stale_routes_time'] == match_graceful_restart.get('stale_routes_time'):
                requests.append({'path': graceful_restart_del_path + "stale-routes-time", 'method': DELETE})
            if graceful_restart.get('preserve_fw_state') and graceful_restart['preserve_fw_state'] == match_graceful_restart.get('preserve_fw_state'):
                requests.append({'path': graceful_restart_del_path + "preserve-fw-state", 'method': DELETE})

        return requests

    def get_delete_all_bgp_requests(self, commands):
        requests = []
        for cmd in commands:
            requests.append(self.get_delete_single_bgp_request(cmd['vrf_name']))
        return requests

    def get_delete_specific_bgp_param_request(self, command, match):
        vrf_name = command['vrf_name']
        requests = []

        router_id = command.get('router_id', None)
        as_notation = command.get('as_notation', None)
        rt_delay = command.get('rt_delay', None)
        timers = command.get('timers', None)
        holdtime = None
        keepalive = None
        if timers:
            holdtime = command['timers'].get('holdtime', None)
            keepalive = command['timers'].get('keepalive_interval', None)
        log_neighbor_changes = command.get('log_neighbor_changes', None)
        bestpath = command.get('bestpath', None)

        if router_id and match.get('router_id', None):
            url = '%s=%s/%s/global/config/router-id' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
            requests.append({"path": url, "method": DELETE})

        if as_notation and match.get('as_notation', None):
            url = '%s=%s/%s/global/config/as-notation' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
            requests.append({"path": url, "method": DELETE})

        if rt_delay and match.get('rt_delay', None):
            url = '%s=%s/%s/global/config/route-map-process-delay' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
            requests.append({"path": url, "method": DELETE})

        if holdtime and match['timers'].get('holdtime', None) != 180:
            url = '%s=%s/%s/global/config/hold-time' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
            requests.append({"path": url, "method": DELETE})

        if keepalive and match['timers'].get('keepalive_interval', None) != 60:
            url = '%s=%s/%s/global/config/keepalive-interval' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
            requests.append({"path": url, "method": DELETE})

        # Delete the log_neighbor_changes only when existing values is True.
        if log_neighbor_changes is not None and match.get('log_neighbor_changes', None):
            del_log_neighbor_req = self.get_modify_log_change_request(vrf_name, False)
            if del_log_neighbor_req:
                requests.append(del_log_neighbor_req)

        bestpath_del_reqs = self.get_delete_bestpath_requests(vrf_name, bestpath, match)
        if bestpath_del_reqs:
            requests.extend(bestpath_del_reqs)

        max_med = command.get('max_med', None)
        max_med_del_reqs = self.get_delete_max_med_requests(vrf_name, max_med, match)
        if max_med_del_reqs:
            requests.extend(max_med_del_reqs)

        graceful_restart = command.get('graceful_restart', None)
        graceful_restart_del_reqs = self.get_delete_graceful_restart_requests(vrf_name, graceful_restart, match)
        if graceful_restart_del_reqs:
            requests.extend(graceful_restart_del_reqs)

        return requests

    def get_delete_bgp_requests(self, commands, have, is_delete_all):
        requests = []
        if is_delete_all:
            requests = self.get_delete_all_bgp_requests(commands)
        else:
            for cmd in commands:
                vrf_name = cmd['vrf_name']
                as_val = cmd['bgp_as']

                match = next((cfg for cfg in have if cfg['vrf_name'] == vrf_name and cfg['bgp_as'] == as_val), None)
                if not match:
                    continue
                # if there is specific parameters to delete then delete those alone
                if cmd.get('router_id', None) or cmd.get('as_notation', None) or cmd.get('log_neighbor_changes', None) or cmd.get('bestpath', None) \
                        or cmd.get('rt_delay', None) or cmd.get('graceful_restart', None):
                    requests.extend(self.get_delete_specific_bgp_param_request(cmd, match))
                else:
                    # delete entire bgp
                    requests.append(self.get_delete_single_bgp_request(vrf_name))

        if requests:
            # reorder the requests to get default vrfs at end of the requests. so deletion will get success
            default_vrf_reqs = []
            other_vrf_reqs = []
            for req in requests:
                if '=default/' in req['path']:
                    default_vrf_reqs.append(req)
                else:
                    other_vrf_reqs.append(req)
            requests.clear()
            requests.extend(other_vrf_reqs)
            requests.extend(default_vrf_reqs)

        return requests

    def get_modify_multi_paths_req(self, vrf_name, as_path):
        request = None
        if not as_path:
            return request

        method = PATCH
        multipath_cfg = {}

        as_path_multipath_relax = as_path.get('multipath_relax', None)
        as_path_multipath_relax_as_set = as_path.get('multipath_relax_as_set', None)

        if as_path_multipath_relax is not None:
            multipath_cfg['allow-multiple-as'] = as_path_multipath_relax
        if as_path_multipath_relax_as_set is not None:
            multipath_cfg['as-set'] = as_path_multipath_relax_as_set

        payload = {"openconfig-network-instance:config": multipath_cfg}
        if payload:
            url = '%s=%s/%s/global/use-multiple-paths/ebgp/config' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
            request = {"path": url, "method": method, "data": payload}

        return request

    def get_modify_route_selection_req(self, vrf_name, compare_routerid, as_path, med, bandwidth):
        requests = []
        if compare_routerid is None and not as_path and not med and not bandwidth:
            return requests

        route_selection_cfg = {}

        as_path_confed = None
        as_path_ignore = None

        med_confed = None
        med_missing_as_worst = None
        always_compare_med = None

        if compare_routerid is not None:
            route_selection_cfg['external-compare-router-id'] = compare_routerid

        if as_path:
            as_path_confed = as_path.get('confed', None)
            as_path_ignore = as_path.get('ignore', None)
            if as_path_confed is not None:
                route_selection_cfg['compare-confed-as-path'] = as_path_confed
            if as_path_ignore is not None:
                route_selection_cfg['ignore-as-path-length'] = as_path_ignore

        if bandwidth:
            # Do the translation for the values here from cli format to REST format
            bandwidth = bandwidth.replace("default_weight", "DEFAULT_WT").replace("ignore_weight", "IGNORE_LB").replace("skip_missing", "SKIP_MISSING")
            route_selection_cfg['compare-linkbw'] = bandwidth

        if med:
            med_confed = med.get('confed', None)
            med_missing_as_worst = med.get('missing_as_worst', None)
            always_compare_med = med.get('always_compare_med', None)
            if med_confed is not None:
                route_selection_cfg['med-confed'] = med_confed
            if med_missing_as_worst is not None:
                route_selection_cfg['med-missing-as-worst'] = med_missing_as_worst
            if always_compare_med is not None:
                route_selection_cfg['always-compare-med'] = always_compare_med
        method = PATCH
        payload = {'route-selection-options': {'config': route_selection_cfg}}

        if payload:
            url = '%s=%s/%s/global/route-selection-options' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
            request = {"path": url, "method": method, "data": payload}
            requests.append(request)

        return requests

    def get_modify_bestpath_requests(self, vrf_name, bestpath):
        requests = []
        if not bestpath:
            return requests

        compare_routerid = bestpath.get('compare_routerid', None)
        as_path = bestpath.get('as_path', None)
        bandwidth = bestpath.get('bandwidth', None)
        med = bestpath.get('med', None)

        route_selection_req = self.get_modify_route_selection_req(vrf_name, compare_routerid, as_path, med, bandwidth)
        if route_selection_req:
            requests.extend(route_selection_req)
        multi_paths_req = self.get_modify_multi_paths_req(vrf_name, as_path)
        if multi_paths_req:
            requests.append(multi_paths_req)

        return requests

    def get_modify_max_med_requests(self, vrf_name, max_med):
        request = None
        method = PATCH
        payload = {}
        config = {}
        on_startup_time = max_med.get('on_startup', {}).get('timer')
        on_startup_med = max_med.get('on_startup', {}).get('med_val')

        if on_startup_time is not None:
            config['time'] = on_startup_time

        if on_startup_med is not None:
            if on_startup_time is not None:
                config['max-med-val'] = on_startup_med
            else:
                self._module.fail_json(msg='timer must be provided if med_val is present for max_med configuration.')

        if config:
            payload = {
                'max-med': {
                    'config': config
                }
            }

        if payload:
            url = '%s=%s/%s/global/max-med' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
            request = {"path": url, "method": method, "data": payload}

        return [request]

    def get_modify_log_change_request(self, vrf_name, log_neighbor_changes):
        request = None
        method = PATCH
        payload = {}

        if log_neighbor_changes is not None:
            payload['log-neighbor-state-changes'] = log_neighbor_changes

        if payload:
            url = '%s=%s/%s/global/%s' % (self.network_instance_path, vrf_name, self.protocol_bgp_path, self.log_neighbor_changes_path)
            request = {"path": url, "method": method, "data": payload}

        return request

    def get_modify_holdtime_request(self, vrf_name, holdtime):
        request = None
        method = PATCH
        payload = {}

        if holdtime is not None:
            payload['hold-time'] = holdtime

        if payload:
            url = '%s=%s/%s/global/%s' % (self.network_instance_path, vrf_name, self.protocol_bgp_path, self.holdtime_path)
            request = {"path": url, "method": method, "data": payload}

        return request

    def get_modify_keepalive_request(self, vrf_name, keepalive_interval):
        request = None
        method = PATCH
        payload = {}

        if keepalive_interval is not None:
            payload['keepalive-interval'] = keepalive_interval

        if payload:
            url = '%s=%s/%s/global/%s' % (self.network_instance_path, vrf_name, self.protocol_bgp_path, self.keepalive_path)
            request = {"path": url, "method": method, "data": payload}

        return request

    def get_new_bgp_request(self, vrf_name, as_val, as_notation):
        request = None
        url = None
        method = PATCH
        payload = {}

        cfg = {}
        if as_val:
            as_cfg = {'config': {'as': as_val.to_request_attr_fmt()}}
            if as_notation:
                as_cfg['config']['as-notation'] = to_bgp_as_notation_request_type(as_notation)
            global_cfg = {'global': as_cfg}
            cfg = {'bgp': global_cfg}
            cfg['name'] = "bgp"
            cfg['identifier'] = "openconfig-policy-types:BGP"

        if cfg:
            payload['openconfig-network-instance:protocol'] = [cfg]
            url = '%s=%s/protocols/protocol/' % (self.network_instance_path, vrf_name)
            request = {"path": url, "method": method, "data": payload}

        return request

    def get_modify_global_config_request(self, vrf_name, router_id, as_val, rt_delay, as_notation):
        request = None
        method = PATCH
        payload = {}

        cfg = {}
        if router_id:
            cfg['router-id'] = router_id
        if as_val:
            cfg['as'] = as_val.to_request_attr_fmt()
        if rt_delay:
            cfg['route-map-process-delay'] = rt_delay
        if as_notation:
            cfg['as-notation'] = to_bgp_as_notation_request_type(as_notation)

        if cfg:
            payload['openconfig-network-instance:config'] = cfg
            url = '%s=%s/%s/global/config' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
            request = {"path": url, "method": method, "data": payload}

        return request

    def get_modify_graceful_restart_request(self, vrf_name, graceful_restart):
        request = None
        method = PATCH

        if graceful_restart:
            payload = {'openconfig-network-instance:config': {k.replace('_', '-'): v for k, v in graceful_restart.items()}}
            url = '%s=%s/%s/global/%s' % (self.network_instance_path, vrf_name, self.protocol_bgp_path, self.graceful_restart_path)
            request = {"path": url, "method": method, "data": payload}

        return request

    def get_modify_bgp_requests(self, commands, have):
        requests = []
        if not commands:
            return requests

        # Create URL and payload
        for conf in commands:
            vrf_name = conf['vrf_name']
            as_val = None
            router_id = None
            log_neighbor_changes = None
            bestpath = None
            max_med = None
            holdtime = None
            keepalive_interval = None
            rt_delay = None
            as_notation = None
            graceful_restart = None

            if 'bgp_as' in conf:
                as_val = conf['bgp_as']
            if 'router_id' in conf:
                router_id = conf['router_id']
            if 'log_neighbor_changes' in conf:
                log_neighbor_changes = conf['log_neighbor_changes']
            if 'bestpath' in conf:
                bestpath = conf['bestpath']
            if 'max_med' in conf:
                max_med = conf['max_med']
            if 'rt_delay' in conf:
                rt_delay = conf['rt_delay']
            if 'timers' in conf and conf['timers']:
                if 'holdtime' in conf['timers']:
                    holdtime = conf['timers']['holdtime']
                if 'keepalive_interval' in conf['timers']:
                    keepalive_interval = conf['timers']['keepalive_interval']
            if 'as_notation' in conf:
                as_notation = conf['as_notation']
            if 'graceful_restart' in conf:
                graceful_restart = conf['graceful_restart']

            if not any(cfg for cfg in have if cfg['vrf_name'] == vrf_name and (cfg['bgp_as'] == as_val)):
                new_bgp_req = self.get_new_bgp_request(vrf_name, as_val, as_notation)
                if new_bgp_req:
                    requests.append(new_bgp_req)

            global_req = self.get_modify_global_config_request(vrf_name, router_id, as_val, rt_delay, as_notation)
            if global_req:
                requests.append(global_req)

            log_neighbor_changes_req = self.get_modify_log_change_request(vrf_name, log_neighbor_changes)
            if log_neighbor_changes_req:
                requests.append(log_neighbor_changes_req)

            if holdtime:
                holdtime_req = self.get_modify_holdtime_request(vrf_name, holdtime)
                if holdtime_req:
                    requests.append(holdtime_req)

            if keepalive_interval:
                keepalive_req = self.get_modify_keepalive_request(vrf_name, keepalive_interval)
                if keepalive_req:
                    requests.append(keepalive_req)

            if bestpath:
                bestpath_reqs = self.get_modify_bestpath_requests(vrf_name, bestpath)
                if bestpath_reqs:
                    requests.extend(bestpath_reqs)

            if max_med:
                max_med_reqs = self.get_modify_max_med_requests(vrf_name, max_med)
                if max_med_reqs:
                    requests.extend(max_med_reqs)

            if graceful_restart:
                graceful_restart_req = self.get_modify_graceful_restart_request(vrf_name, graceful_restart)
                if graceful_restart_req:
                    requests.append(graceful_restart_req)

        return requests

    def get_delete_commands_requests_for_replaced_overridden(self, want, have, state):
        """Returns the commands and requests necessary to remove applicable
        current configurations when state is replaced or overridden
        """
        commands = []
        requests = []
        if not have:
            return commands, requests

        for conf in have:
            as_val = conf['bgp_as']
            vrf_name = conf['vrf_name']

            match_cfg = next((cfg for cfg in want if cfg['vrf_name'] == vrf_name and cfg['bgp_as'] == as_val), None)
            # Delete entire BGP if not specified in overridden
            if not match_cfg:
                if state == 'overridden':
                    commands.append(conf)
                    requests.append(self.get_delete_single_bgp_request(vrf_name))
                continue

            # Delete config in BGP AS that are replaced/overridden
            # - Modified attributes are not deleted, since they will be
            #   updated by merge.
            # - log_neighbor_changes is enabled by default, therefore
            #   it will be enabled if not specified and currently
            #   disabled for an existing BGP AS.
            command = {}

            if conf.get('router_id') and not match_cfg.get('router_id'):
                command['router_id'] = conf['router_id']

            if conf.get('as_notation') and not match_cfg.get('as_notation'):
                command['as_notation'] = conf['as_notation']

            if conf.get('rt_delay') and match_cfg.get('rt_delay') is None:
                command['rt_delay'] = conf['rt_delay']

            if not conf.get('log_neighbor_changes') and match_cfg.get('log_neighbor_changes') is None:
                command['log_neighbor_changes'] = False
                requests.append(self.get_modify_log_change_request(vrf_name, True))

            # max_med -> on_startup options are deleted at once.
            # Update the commands appropriately.
            if conf.get('max_med') and (not match_cfg.get('max_med') or conf['max_med']['on_startup'] != match_cfg['max_med']['on_startup']):
                command['max_med'] = conf['max_med']

            if conf.get('timers'):
                timer_command = {}
                timers = conf['timers']
                match_timers = match_cfg.get('timers', {})
                if timers.get('holdtime') is not None and match_timers.get('holdtime') is None and timers['holdtime'] != 180:
                    timer_command['holdtime'] = timers['holdtime']
                if timers.get('keepalive_interval') is not None and match_timers.get('keepalive_interval') is None and timers['keepalive_interval'] != 60:
                    timer_command['keepalive_interval'] = timers['keepalive_interval']

                if timer_command:
                    command['timers'] = timer_command

            if conf.get('bestpath'):
                bestpath_command = {}
                bestpath = conf['bestpath']
                match_bestpath = match_cfg.get('bestpath', {})
                if bestpath.get('as_path'):
                    as_path_command = {}
                    as_path = bestpath['as_path']
                    match_as_path = match_bestpath.get('as_path', {})
                    for option in ('confed', 'ignore', 'multipath_relax', 'multipath_relax_as_set'):
                        if as_path.get(option) and match_as_path.get(option) is None:
                            as_path_command[option] = True

                    if as_path_command:
                        bestpath_command['as_path'] = as_path_command

                if bestpath.get('bandwidth') and match_bestpath.get('bandwidth') is None:
                    bestpath_command['bandwidth'] = bestpath.get("bandwidth")

                if bestpath.get('compare_routerid') and match_bestpath.get('compare_routerid') is None:
                    bestpath_command['compare_routerid'] = True

                if bestpath.get('med'):
                    med_command = {}
                    med = bestpath['med']
                    match_med = match_bestpath.get('med', {})
                    for option in ('confed', 'missing_as_worst', 'always_compare_med'):
                        if med.get(option) and match_med.get(option) is None:
                            med_command[option] = True

                    if med_command:
                        bestpath_command['med'] = med_command

                if bestpath_command:
                    command['bestpath'] = bestpath_command

            if conf.get('graceful_restart'):
                gr_command = {}
                conf_gr = conf['graceful_restart']
                match_gr = match_cfg.get('graceful_restart', {})
                if conf_gr.get('enabled') and match_gr.get('enabled') is None:
                    gr_command['enabled'] = True
                if conf_gr.get('restart_time') and match_gr.get('restart_time') is None:
                    gr_command['restart_time'] = conf_gr['restart_time']
                if conf_gr.get('stale_routes_time') and match_gr.get('stale_routes_time') is None:
                    gr_command['stale_routes_time'] = conf_gr['stale_routes_time']
                if conf_gr.get('preserve_fw_state') and match_gr.get('preserve_fw_state') is None:
                    gr_command['preserve_fw_state'] = True

                if gr_command:
                    command['graceful_restart'] = gr_command

            if command:
                command['bgp_as'] = as_val
                command['vrf_name'] = vrf_name
                commands.append(command)
                requests.extend(self.get_delete_specific_bgp_param_request(command, command))

        if requests:
            # reorder the requests to get default vrfs at end of the requests. so deletion will get success
            default_vrf_reqs = []
            other_vrf_reqs = []
            for req in requests:
                if '=default/' in req['path']:
                    default_vrf_reqs.append(req)
                else:
                    other_vrf_reqs.append(req)
            requests.clear()
            requests.extend(other_vrf_reqs)
            requests.extend(default_vrf_reqs)

        return commands, requests

    def sort_lists_in_config(self, configs):
        if configs:
            configs.sort(key=lambda x: (x['bgp_as'], x['vrf_name']))

    def post_process_generated_config(self, configs):
        confs = remove_empties_from_list(configs)
        if confs:
            for conf in confs[:]:
                keys = conf.keys()
                if len(keys) <= 2:
                    confs.remove(conf)
        return confs
