#
# -*- coding: utf-8 -*-
# Copyright 2023 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_sflow class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy

from ansible.module_utils.connection import ConnectionError
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
    validate_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils \
    import (
        get_diff,
        update_states,
        to_request,
        edit_config,
        get_normalize_interface_name,
        get_replaced_config
    )


class Sflow(ConfigBase):
    """
    The sonic_sflow class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'sflow',
    ]

    sflow_uri = "data/openconfig-sampling-sflow:sampling/sflow"

    sflow_diff_test_keys = [{"collectors": {"port": "", "address": "", "network_instance": ""}},
                            {"interfaces": {"name": ""}}]

    def __init__(self, module):
        super(Sflow, self).__init__(module)

    def get_sflow_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        sflow_facts = facts['ansible_network_resources'].get('sflow')
        if not sflow_facts:
            return []
        return sflow_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()

        existing_sflow_facts = self.get_sflow_facts()
        commands, requests = self.set_config(existing_sflow_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.errno)
            result['changed'] = True
        result['commands'] = commands
        changed_sflow_facts = self.get_sflow_facts()

        result['before'] = existing_sflow_facts
        if result['changed']:
            result['after'] = changed_sflow_facts

        result['warnings'] = warnings
        return result

    def set_config(self, existing_sflow_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_sflow_facts

        resp = self.set_state(want, have)
        return to_list(resp)

    def set_state(self, want, have):
        """ Select the appropriate function based on the state provided

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A tuple
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration, and REST requests that do it
        """
        commands = []
        requests = []
        want = self.validate_normalize_config(want)
        state = self._module.params['state']
        if state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)
        elif state == 'overridden':
            commands, requests = self._state_overridden(want, have)
        else:
            commands, requests = self._state_replaced(want, have)
        return commands, requests

    def _state_replaced(self, want, have):
        """ The command generator when state is replaced

        :rtype: A tuple of lists
        :returns: A list of what commands and state necessary to migrate the current configuration
                  to the desired configuration, and a list of requests needed to make changes
        """
        commands = []
        requests = []

        replaced_config = get_replaced_config(want, have, test_keys=self.sflow_diff_test_keys)
        if replaced_config:
            requests.extend(self.get_deleted_requests(replaced_config, have))
            commands.extend(update_states(replaced_config, "deleted"))
            add_commands = want
        else:
            diff = get_diff(want, have, test_keys=self.sflow_diff_test_keys)
            add_commands = diff

        if add_commands:
            self.create_patch_sflow_root_request(add_commands, requests)
            commands.extend(update_states(add_commands, "replaced"))

        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden

        :rtype: A tuple of lists
        :returns: A list of what commands and state necessary to migrate the current configuration
                  to the desired configuration, and a list of requests needed to make changes
        """
        commands = []
        requests = []

        self.fill_defaults(want)
        remove_diff = get_diff(have, want, test_keys=self.sflow_diff_test_keys)
        introduced_diff = get_diff(want, have, test_keys=self.sflow_diff_test_keys)

        remove_diff = self.get_overridden_must_delete_config(remove_diff, introduced_diff)

        if remove_diff is not None and len(remove_diff) > 0:
            # deleted will take empty as clear all, override having empty remove differences is do nothing.
            # so need to check
            requests.extend(self.get_deleted_requests(remove_diff, have))
            commands = update_states(remove_diff, "deleted")
        requestsTwo = []
        commandsTwo = []
        if introduced_diff is not None and len(introduced_diff) > 0:
            self.create_patch_sflow_root_request(introduced_diff, requestsTwo)
            commandsTwo = update_states(introduced_diff, "overridden")

        # combining two lists of changes
        commands.extend(commandsTwo)
        requests.extend(requestsTwo)

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A tuple of lists
        :returns: A list of what commands and state necessary to merge the provided into
                  the current configuration, and a list of requests needed to make changes
        """

        if not want:
            # nothing to do here
            return [], []

        commands = get_diff(want, have, test_keys=self.sflow_diff_test_keys)

        requests = self.create_patch_sflow_root_request(commands, [])

        if commands and len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []
        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :rtype: A tuple of lists
        :returns: A list of what commands and state necessary to remove the current configuration
                  of the provided objects, and a list of requests needed to make changes
        """
        commands = {}
        requests = []

        # don't want to interpret none values. if want to delete all, empty lists or dicts must be passed

        if len(want) == 0:
            # for the "clear all config" instance. passing in empty dictionary to deleted means clear everything
            want = have

        if want.get("enabled") and have.get("enabled"):
            # default value is false so only need to do the "delete" (actually reset) if values are true and match
            commands.update({"enabled": have["enabled"]})

        if "polling_interval" in want and "polling_interval" in have and want["polling_interval"] == have["polling_interval"]:
            # want to make sure setting specified and match
            commands.update({"polling_interval": have["polling_interval"]})

        if "max_header_size" in want and "max_header_size" in have and want["max_header_size"] == have["max_header_size"] and have["max_header_size"] != 128:
            # want to make sure setting specified and match
            commands.update({"max_header_size": have["max_header_size"]})

        if "agent" in want and "agent" in have and want["agent"] == have["agent"]:
            commands.update({"agent": have["agent"]})

        if "sampling_rate" in want and "sampling_rate" in have and want["sampling_rate"] == have["sampling_rate"]:
            commands.update({"sampling_rate": have["sampling_rate"]})

        if ("collectors" in want or len(want) == 0) and "collectors" in have:
            # either clear all settings, all collectors or certain collectors here
            to_delete_list = have["collectors"]
            if len(want["collectors"]) > 0:
                # a specified non-empty list means no longer clear everything
                to_delete_list = want["collectors"]

            deleted_list = []

            have_collectors_dict = {(collector["address"], collector["network_instance"], collector["port"]): collector for collector in have["collectors"]}

            for collector in to_delete_list:
                found_match = (collector["address"], collector["network_instance"], collector["port"]) in have_collectors_dict
                if found_match:
                    deleted_list.append(have_collectors_dict[(collector["address"], collector["network_instance"], collector["port"])])
            if len(deleted_list) > 0:
                commands.update({"collectors": deleted_list})

        if ("interfaces" in want or len(want) == 0) and "interfaces" in have:
            # either clear all settings, all interfaces, or certain interfaces
            to_delete_list = have["interfaces"]
            if len(want["interfaces"]) > 0:
                # a specified non-empty list means no longer clear everything
                to_delete_list = want["interfaces"]

            deleted_list = []

            have_interfaces_dict = {interface["name"]: interface for interface in have["interfaces"]}

            for to_delete_interface in to_delete_list:
                if to_delete_interface["name"] in have_interfaces_dict:
                    matched_interface = have_interfaces_dict[to_delete_interface["name"]]
                    if to_delete_interface.keys() == {"name"}:
                        # just name specified means delete what is in have
                        deleted_list.append(have_interfaces_dict[to_delete_interface["name"]])
                    else:
                        filtered_delete_interface = {}

                        if to_delete_interface.get("enabled") and matched_interface.get("enabled"):
                            filtered_delete_interface.update({"enabled": matched_interface["enabled"]})

                        if "sampling_rate" in to_delete_interface and "sampling_rate" in matched_interface and \
                                to_delete_interface.get("sampling_rate") == matched_interface.get("sampling_rate"):
                            filtered_delete_interface.update({"sampling_rate": matched_interface["sampling_rate"]})

                        if len(filtered_delete_interface) > 0:
                            filtered_delete_interface.update({"name": matched_interface["name"]})
                            # greater than one to account for name always being inside
                            deleted_list.append(filtered_delete_interface)
            if len(deleted_list) > 0:
                commands.update({"interfaces": deleted_list})

        requests = self.get_deleted_requests(commands, have)

        if commands and len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []
        return commands, requests

    def validate_normalize_config(self, config):
        '''validates and normalizes interface names in passed in config
        :returns: config object that has been validated and normalized'''
        config = remove_none(config)
        config = validate_config(self._module.argument_spec, {"config": config})["config"]
        # validation will add a bunch of Nones where values are missing in partially filled config dicts
        config = remove_none(config)
        if config is not None and config.get("polling_interval") is not None:
            if not (int(config["polling_interval"]) == 0 or int(config["polling_interval"]) in range(5, 301)):
                self._module.fail_json(msg="polling interval out of range. must be 0 or in the range 5-300 inclusive", code=1)
        if config is not None and config.get("max_header_size") is not None:
            if not (int(config["max_header_size"] % 128) == 0 and int(config["max_header_size"]) in range(128, 1024)):
                self._module.fail_json(msg="Invalid max header size. must be multiple of 128 the range 128-1024 inclusive", code=1)
        if config is not None and config.get("agent") is not None:
            config["agent"] = get_normalize_interface_name(config.get("agent", ""), self._module)
        if config is not None and config.get("interfaces") is not None:
            for interface in config["interfaces"]:
                interface["name"] = get_normalize_interface_name(interface.get("name", ""), self._module)
        return config

    def create_patch_sflow_root_request(self, to_update_config_dict, request_list):
        '''builds REST request for patching on sflow root endpoint, which can update all sflow information in one REST request.
        Uses given config as what needs to be updated without further checks. adds request to passed in request list and returns list'''

        method = "PATCH"
        root_data_key = "openconfig-sampling-sflow:sflow"

        if len(to_update_config_dict) == 0:
            return request_list

        request_body = {}
        has_data = False

        # config always required in this endpoint
        request_body["config"] = self.create_config_request_body(to_update_config_dict)
        if len(request_body["config"]) > 0:
            has_data = True

        if "collectors" in to_update_config_dict:
            collector_body = self.create_collectors_list_request_body(to_update_config_dict)
            if len(collector_body) > 0:
                request_body.update({"collectors": {"collector": collector_body}})
                has_data = True

        if "interfaces" in to_update_config_dict:
            interface_body = self.create_interface_list_request_body(to_update_config_dict)
            if len(interface_body) > 0:
                request_body.update({"interfaces": {"interface": interface_body}})
                has_data = True

        if has_data:
            request_list.append({"path": self.sflow_uri, "method": method, "data": {root_data_key: request_body}})
        return request_list

    def create_config_request_body(self, config_dict):
        '''does format transformation and creates and returns dictionary that holds all sflow global settings that were passed in.
        Takes a dictionary in argspect format and returns the matching REST formatted fields for global config'''
        request_config = {}
        if "enabled" in config_dict:
            request_config["enabled"] = config_dict["enabled"]
        if "polling_interval" in config_dict:
            request_config["polling-interval"] = config_dict["polling_interval"]
        if "max_header_size" in config_dict:
            request_config["sample-size"] = config_dict["max_header_size"]
        if "agent" in config_dict:
            request_config["agent"] = config_dict["agent"]
        if "sampling_rate" in config_dict:
            request_config["sampling-rate"] = config_dict["sampling_rate"]
        return request_config

    def create_collectors_list_request_body(self, config_dict):
        '''does format transformation and creates and returns a list of sflow collectors with the settings passed in.
        Takes a dictionary for all config in argspec format and returns the collectors listed in REST API format'''
        collector_list = []
        for collector in config_dict["collectors"]:
            collector_request = {"address": collector["address"],
                                 "network-instance": collector["network_instance"],
                                 "port": collector["port"]}
            # since REST needs the collector list item with its settings and a nested config with a copy of those same settings
            collector_request.update({"config": dict(collector_request)})
            collector_list.append(collector_request)
        return collector_list

    def create_interface_list_request_body(self, config_dict):
        '''does format transformation and creates and returns a list of sflow interfaces with the settings passed in.
        Takes a dictionary for all config in argspec format and returns all interfaces listed that have configuration. Returns list in REST API format'''
        interface_list = []
        for interface in config_dict["interfaces"]:
            interface_config_request = {}
            if "enabled" in interface:
                interface_config_request["enabled"] = interface["enabled"]
            if "sampling_rate" in interface:
                interface_config_request["sampling-rate"] = interface["sampling_rate"]
            if len(interface_config_request) == 0:
                # listed interface doesn't actually have any configured settings, but name is hanging around
                continue
            interface_config_request["name"] = interface["name"]
            interface_list.append({"name": interface["name"],
                                   "config": interface_config_request})
        return interface_list

    def get_deleted_requests(self, to_delete, have):
        '''get list of requests needed to delete all settings in to_delete. have is needed to help delete multiple collectors at once and all of an interface'''
        requests = []
        if "enabled" in to_delete:
            requests.append({"path": "data/openconfig-sampling-sflow:sampling/sflow/config/enabled", "method": "PUT",
                             "data": {"openconfig-sampling-sflow:enabled": False}})
        if "polling_interval" in to_delete:
            requests.append({"path": "data/openconfig-sampling-sflow:sampling/sflow/config/polling-interval", "method": "DELETE"})
        if "max_header_size" in to_delete:
            requests.append({"path": "data/openconfig-sampling-sflow:sampling/sflow/config/sample-size", "method": "DELETE"})
        if "agent" in to_delete:
            requests.append({"path": "data/openconfig-sampling-sflow:sampling/sflow/config/agent", "method": "DELETE"})
        if "sampling_rate" in to_delete:
            requests.append({"path": "data/openconfig-sampling-sflow:sampling/sflow/config/sampling-rate", "method": "DELETE"})
        if "collectors" in to_delete:
            have_collectors_dict = {(collector["address"], collector["network_instance"], collector["port"]): collector for collector in have["collectors"]}
            to_delete_collectors_dict = {(collector["address"], collector["network_instance"], collector["port"]): collector
                                         for collector in to_delete["collectors"]}
            if set(have_collectors_dict.keys()) == set(to_delete_collectors_dict.keys()):
                # if all the collectors match, is possible to delete all at once rather than go through the list deleting individually
                requests.append({"path": "data/openconfig-sampling-sflow:sampling/sflow/collectors", "method": "DELETE"})
            else:
                for collector in to_delete["collectors"]:
                    requests.append({"path": "data/openconfig-sampling-sflow:sampling/sflow/collectors/collector=" +
                                    collector["address"] + "," + str(collector["port"]) + "," +
                                    collector["network_instance"], "method": "DELETE"})
        if "interfaces" in to_delete:
            # can't call delete on interfaces list endpoint, must delete individual interface
            requests.extend(self.get_delete_interface_requests(to_delete, have))
        return requests

    def get_delete_interface_requests(self, to_delete, have):
        '''get list of requests needed to delete the list of interfaces in to_delete. have is needed to decide
        if interface or indivual attributes for interfaces
        should be deleted'''
        requests = []
        for del_interface in to_delete["interfaces"]:
            for interface in have.get("interfaces", []):
                if del_interface["name"] == interface["name"]:
                    if del_interface.keys() == {"name"} or set(del_interface.keys()) == set(interface.keys()):
                        requests.append({"path": "data/openconfig-sampling-sflow:sampling/sflow/interfaces/interface=" + interface["name"], "method": "DELETE"})
                    else:
                        if "enabled" in del_interface:
                            requests.append({"path": "data/openconfig-sampling-sflow:sampling/sflow/interfaces/interface=" + interface["name"] +
                                             "/config/enabled", "method": "PATCH",
                                             "data": {"openconfig-sampling-sflow:enabled": False}})
                        if "sampling_rate" in del_interface:
                            requests.append({"path": "data/openconfig-sampling-sflow:sampling/sflow/interfaces/interface=" + interface["name"] +
                                             "/config/sampling-rate", "method": "DELETE"})
                    break
        return requests

    def fill_defaults(self, config):
        '''modifies the given original config object to add sflow default values that are missing. returns the config for chaining purposes'''
        if "enabled" not in config:
            config["enabled"] = False
        for interface in config.get("interfaces", []):
            if "enabled" not in interface:
                interface["enabled"] = False
        return config

    def get_overridden_must_delete_config(self, remove_diff, introduced_diff):
        '''specifically for overridden and replaced states, finds and builds collection of which config settings need to be deleted and without anything that is
        getting replaced with new values. `get_diff` will return collection of both things that need to be deleted and things that will have new values.'''
        result = {}
        if "agent" in remove_diff and "agent" not in introduced_diff:
            result["agent"] = remove_diff["agent"]
        if "enabled" in remove_diff and "enabled" not in introduced_diff:
            result["enabled"] = remove_diff["enabled"]
        if "polling_interval" in remove_diff and "polling_interval" not in introduced_diff:
            result["polling_interval"] = remove_diff["polling_interval"]
        if "max_header_size" in remove_diff and "max_header_size" not in introduced_diff:
            result["max_header_size"] = remove_diff["max_header_size"]
        if "sampling_rate" in remove_diff and "sampling_rate" not in introduced_diff:
            result["sampling_rate"] = remove_diff["sampling_rate"]
        if "collectors" in remove_diff:
            result["collectors"] = remove_diff["collectors"]
        if "interfaces" in remove_diff:
            if "interfaces" not in introduced_diff:
                # nothing being substituded, everything is being deleted
                result["interfaces"] = remove_diff["interfaces"]
            else:
                # need to go through interfaces and ignore ones that don't need to be deleted
                # only interfaces that are in have and not want or have settings that are in have and not want need to be deleted
                result["interfaces"] = []
                for interface_r in remove_diff['interfaces']:
                    match_interface = None
                    # find matching interface in introduced
                    for interface_i in introduced_diff['interfaces']:
                        if interface_r['name'] == interface_i['name']:
                            match_interface = deepcopy(interface_r)

                            for interface_setting in interface_r:
                                if interface_setting != "name" and interface_setting in interface_i:
                                    del match_interface[interface_setting]
                            if len(match_interface) > 1:
                                # if only name key left, everything else matches and will get substituted.
                                # name left in becuase needed if there's any settings that do need deleting
                                result["interfaces"].append(match_interface)
                            break

                    if match_interface is None:
                        result["interfaces"].append(interface_r)
        return result


def remove_none(config):
    '''goes through nested dictionary items and removes any keys that have None as value.
    enables using empty list/dict to specify clear everything for that section and differentiate this
    'clear everything' case from when no value was given
    remove_empties in ansible utils will remove empty lists and dicts as well as None'''
    if isinstance(config, dict):
        for k, v in list(config.items()):
            if v is not None:
                remove_none(v)
            if v is None:
                del config[k]
    elif isinstance(config, list):
        for item in list(config):
            if item is not None:
                remove_none(item)
            if item is None:
                config.remove(item)
    return config
