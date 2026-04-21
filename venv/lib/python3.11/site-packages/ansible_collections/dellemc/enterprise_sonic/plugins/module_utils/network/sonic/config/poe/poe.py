#
# -*- coding: utf-8 -*-
# Copyright 2023 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_poe class
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
    validate_config,
    remove_empties,
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.poe_utils import (
    poe_str2enum,
    remove_none
)

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_OP_DEFAULT,
    get_new_config,
    get_formatted_config_diff
)


def derive_deleted_interface_config(key_set, command, exist_conf):
    nu, new_conf = __DELETE_OP_DEFAULT(key_set, command, deepcopy(exist_conf))
    if len(new_conf) == 1:
        # if deleted everything and just key left, means no config
        return True, {}
    if "enabled" in command and "enabled" in exist_conf and command["enabled"] == exist_conf["enabled"]:
        new_conf["enabled"] = False
    return nu, new_conf


def derive_delete_config(key_set, command, exist_conf):
    nu, new_conf = __DELETE_OP_DEFAULT(key_set, command, deepcopy(exist_conf))
    if "global" in command and "global" in exist_conf:
        nu, new_conf["global"] = __DELETE_OP_DEFAULT(set(), command["global"], exist_conf["global"])
    if "interfaces" in command and "interfaces" in exist_conf:
        new_conf["interfaces"] = list_generate_diff_helper({"name"}, command["interfaces"], exist_conf["interfaces"], derive_deleted_interface_config)
    if "cards" in command and "cards" in exist_conf:
        # using a function made for handling interfaces for cards because they don't conflict
        new_conf["cards"] = list_generate_diff_helper({"card_id"}, command["cards"], exist_conf["cards"], derive_deleted_interface_config)
    new_conf = remove_empties(new_conf)
    if len(new_conf) == 0:
        # if deleted everything and just key left, means no config
        return True, []
    return True, new_conf


def list_generate_diff_helper(key_set, command, existing_conf, delete_handler):
    if len(existing_conf) == 0:
        # early return there's nothing to delete
        return existing_conf
    command_dict = {tuple(c[field] for field in key_set): c for c in command}
    existing_dict = {tuple(c[field] for field in key_set): c for c in existing_conf}

    new_conf = []
    # for every existing item, either deleting or not
    # keys only in command and not existing do not affect anything
    for e_key, e_data in existing_dict.items():
        if e_key in command_dict:
            # existing has a matching command for deleting, process it
            nu, new_item = delete_handler(key_set, command_dict[e_key], e_data)
            if new_item:
                new_conf.append(new_item)
        else:
            # existing has no matching command for deleting, can't be changed so keep it
            new_conf.append(e_data)
    return new_conf


TEST_KEYS_generate_config = [
    {"config": {"__delete_op": derive_delete_config}},
    {"cards": {"card_id": ""}},
    {"interfaces": {"name": "", "__delete_op": derive_deleted_interface_config}},
]


class Poe(ConfigBase):
    """
    The sonic_poe class
    """

    diff_keys = [
        {"cards": {"card_id": ""}},
        {"interfaces": {"name": ""}}
    ]

    poe_root_uri = "data/openconfig-poe:poe"
    interfaces_root_uri = "data/openconfig-interfaces:interfaces"

    poe_setting_prefix = "openconfig-if-poe-ext:"
    '''prefix for interface's PoE settings'''

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'poe',
    ]

    # tracks keys and values still entirely unsupported by platforms
    # unsupported_values_dict should have same nesting scheme as argspec.
    # if key is unsupported specify blank value, otherwise fill in with list of values or singular value that isn't supported
    # keep key in if it has sub sections that have unsupported values
    unsupported_values = {
        "cards": "",
        "global": {
            "auto_reset": "",
            "power_mgmt_model": [
                'dynamic-priority',
                'static',
                'static-priority'
            ],
            "usage_threshold": "",
        },
        "interfaces": {
            "priority": ['medium'],
            "detection": [
                '2pt-dot3af',
                '2pt-dot3af+legacy',
                '4pt-dot3af',
                '4pt-dot3af+legacy',
                'legacy'
            ],
            "power_up_mode": "",
            "power_pairs": "",
            "power_limit_type": "",
            "power_limit": "",
            "high_power": "",
            "disconnect_type": "",
            "four_pair": "",
            "use_spare_pair": "",
            "power_classification": ""
        }
    }

    def __init__(self, module):
        super(Poe, self).__init__(module)

    def get_poe_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        poe_facts = facts['ansible_network_resources'].get('poe')
        if not poe_facts:
            return []
        return poe_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()

        existing_poe_facts = self.get_poe_facts()
        commands, requests = self.set_config(existing_poe_facts)

        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.errno)
            result['changed'] = True
        result['commands'] = commands

        result['before'] = existing_poe_facts
        # setting new config to a default value, if there are changes then set to changed value
        new_config = existing_poe_facts

        if self._module.check_mode:
            new_config = get_new_config(commands, existing_poe_facts,
                                        TEST_KEYS_generate_config)
            result['after(generated)'] = new_config
        elif result['changed']:
            new_config = self.get_poe_facts()
            result['after'] = new_config

        if self._module._diff:
            result['config_diff'] = get_formatted_config_diff(existing_poe_facts,
                                                              new_config)

        result['warnings'] = warnings
        return result

    def set_config(self, existing_poe_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: a list with two dictionaries, the first are commands necessary to migrate the
                  current configuration to the desired configuration, the second is list of requests
                  that would make that change
        """
        want = self._module.params['config']
        have = existing_poe_facts
        resp = self.set_state(want, have)
        return to_list(resp)

    def set_state(self, want, have):
        """ Select the appropriate function based on the state provided

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: a list with two dictionaries, the first are commands necessary to migrate the
                  current configuration to the desired configuration, the second is list of requests
                  that would make that change
        """
        state = self._module.params['state']
        want = self.validate_normalize_config(want)
        if state == 'overridden':
            result = self._state_overridden(want, have)
        elif state == 'deleted':
            result = self._state_deleted(want, have)
        elif state == 'merged':
            result = self._state_merged(want, have)
        elif state == 'replaced':
            result = self._state_replaced(want, have)
        return result

    def _state_replaced(self, want, have):
        """ The command generator when state is replaced

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: a list with two dictionaries, the first are commands necessary to migrate the
                  current configuration to the desired configuration, the second is list of requests
                  that would make that change
        """

        commands = []
        requests = []

        replaced_config = get_replaced_config(want, have, test_keys=self.diff_keys)
        # contains existing individual cards and interfaces that are different, contains global section if there's differences
        add_commands = get_diff(want, have, test_keys=self.diff_keys)
        if replaced_config:
            requests.extend(self.make_delete_requests(replaced_config, have))
            commands.extend(update_states(replaced_config, "deleted"))
            # special processing for replaced parts since might have deleted more the difference
            for section in replaced_config:
                # section refers to list of cards, list of interfaces or global settings
                if section in add_commands:
                    # if some portion of a section is being deleted as part of "replaced" state handling
                    # and there are differences to add, add full content from 'want' instead of just difference.
                    # For other sections, use the 'get_diff' result so that commands to add/modify configuration are sent only
                    # for added or changed attributes in that section.
                    add_commands[section] = want[section]

        if add_commands:
            requests.extend(self.make_merged_requests(add_commands))
            commands.extend(update_states(add_commands, "replaced"))

        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: a list with two dictionaries, the first are commands necessary to migrate the
                  current configuration to the desired configuration, the second is list of requests
                  that would make that change
        """
        commands = []
        requests = []
        remove_diff = get_diff(have, want, test_keys=self.diff_keys)
        # all things in have not in want or in both but different
        introduced_diff = get_diff(want, have, test_keys=self.diff_keys)
        # all things in want not in have or in both but different

        remove_diff = self.get_overridden_must_delete_config(remove_diff, introduced_diff)
        # all settings for cards/interfaces that arent in introduced, and all global settings in have but not in introduced

        if remove_diff is not None and len(remove_diff) > 0:
            # deleted will take empty as clear all, override having empty remove differences means do nothing.
            # so need to check and prevent clearing
            requests.extend(self.make_delete_requests(remove_diff, have))
            commands = update_states(remove_diff, "deleted")
        if introduced_diff is not None and len(introduced_diff) > 0:
            requestsTwo = self.make_merged_requests(introduced_diff)
            commandsTwo = update_states(introduced_diff, "overridden")
            commands.extend(commandsTwo)
            requests.extend(requestsTwo)

        return commands, requests

    def _state_merged(self, want, have):
        """ The generator that builds commands and requests needed when state is merged

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A tuple of lists
        :returns: a list with two dictionaries, the first are commands necessary to migrate the
                  current configuration to the desired configuration, the second is list of requests
                  that would make that change
        """
        commands = []
        requests = []
        if want is None:
            return commands, requests

        # merged only cares about things in want that are different from have. that's the exact list of changes
        commands = get_diff(want, have, test_keys=self.diff_keys)
        requests = self.make_merged_requests(commands)

        if commands and len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []
        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: a list with two dictionaries, the first are commands necessary to migrate the
                  current configuration to the desired configuration, the second is list of requests
                  that would make that change
        """
        commands = {}
        requests = []
        if not have:
            # nothing that could be deleted
            return [], requests
        elif not want:
            # giving an option to clear all, either None or empty config dict
            want = have

        if want.get("cards") is not None and have.get("cards") is not None:
            to_delete_list = have["cards"]
            if len(want["cards"]) > 0:
                to_delete_list = want["cards"]

            deleted_list = []

            for card_d in to_delete_list:
                for card_h in have["cards"]:
                    if card_d["card_id"] == card_h["card_id"]:
                        # found matching card definition
                        if card_d.keys() == {"card_id"}:
                            # if just card id (its key) was specified, assuming want to delete whole card
                            deleted_list.append(card_h)
                        else:
                            # find all settings in card that should be deleted
                            filtered_delete = deepcopy(card_d)
                            for setting in card_d:
                                # only settings with matching values should be deleted, so throw out anythign that doesn't match
                                if setting not in card_h or card_d[setting] != card_h[setting]:
                                    # id will always remain in filtered_delete because the two cards have the same id
                                    del filtered_delete[setting]
                            if filtered_delete.keys() == card_h.keys():
                                # if all settings are the same, then assume want to delete whole interface
                                deleted_list.append(filtered_delete)
                            elif len(filtered_delete) > 1:
                                # greater than 1 to account for id being inside
                                deleted_list.append(filtered_delete)
                        break
            if len(deleted_list) > 0:
                commands["cards"] = deleted_list

        if want.get("interfaces") is not None and have.get("interfaces") is not None:
            # find list of interfaces to process what needs to be deleted
            # assuming want to delete everything unless a specific list is passed in
            to_delete_list = have["interfaces"]
            if len(want["interfaces"]) > 0:
                to_delete_list = want["interfaces"]

            deleted_list = []

            for interface_d in to_delete_list:
                for interface_h in have["interfaces"]:
                    if interface_d["name"] == interface_h["name"]:
                        # found matching interface definition
                        if interface_d.keys() == {"name"}:
                            # if just interface name (its key) was specified, assuming want to delete whole interface
                            deleted_list.append(interface_h)
                        else:
                            # find all settings in interface that should be deleted
                            filtered_delete = deepcopy(interface_d)
                            for setting in interface_d:
                                # only settings with matching values should be deleted, so throw out anythign that doesn't match
                                if setting not in interface_h or interface_d[setting] != interface_h[setting]:
                                    # name (the key) always remains in filtered_delete because the two interfaces have the same name
                                    del filtered_delete[setting]
                            if filtered_delete.keys() == interface_h.keys():
                                # if all settings are the same, then assume want to delete whole interface
                                deleted_list.append(filtered_delete)
                            elif len(filtered_delete) > 1:
                                # greater than 1 to account for name being inside
                                deleted_list.append(filtered_delete)
                        break
            if len(deleted_list) > 0:
                commands["interfaces"] = deleted_list
        if "global" in want and "global" in have:
            if len(want["global"]) == 0:
                # allow specifying blank for global section causes delete all global
                deleted_global_settings = have["global"]
            else:
                deleted_global_settings = {}
                for setting in ["auto_reset", "power_mgmt_model", "usage_threshold"]:
                    if setting in want["global"] and setting in have["global"] and want["global"][setting] == have["global"][setting]:
                        deleted_global_settings.update({setting: have["global"][setting]})
            if len(deleted_global_settings) > 0:
                commands["global"] = deleted_global_settings
        requests = self.make_delete_requests(commands, have)
        if commands and len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []
        return commands, requests

    def check_for_support(self, config, unsupported_values_dict):
        '''recursive search config for any config keys or their values that aren't supported. assumes that both config
        and unsuported_values_dict are at the same 'depth' of the config argspec.'''
        # for every key in config check if it is in no_support_dict
        if isinstance(config, list):
            for item in config:
                self.check_for_support(item, unsupported_values_dict)
        else:
            for key, values in config.items():
                # if key is in no_support_dict check if value is empty
                if key in unsupported_values_dict:
                    if isinstance(unsupported_values_dict[key], list):
                        if values in unsupported_values_dict[key]:
                            self._module.fail_json(msg="value of {value} for key {key} not supported on platforms".format(value=values, key=key))
                    elif isinstance(unsupported_values_dict[key], dict):
                        self.check_for_support(config[key], unsupported_values_dict[key])
                    elif unsupported_values_dict[key]:
                        if values == unsupported_values_dict[key]:
                            self._module.fail_json(msg="value of {value} for key {key} not supported on platforms".format(value=values, key=key))
                    else:
                        self._module.fail_json(msg="key {key} not supported on platforms".format(key=key))

    def validate_normalize_config(self, config):
        '''validates passed in config against argspec and if it has values for power_limit and usage_threshold, checks they are in range.
        passes back config with interface names normalized'''
        # first removing null values so validate doesn't break
        config = remove_none(config)
        self.check_for_support(config, self.unsupported_values)
        # validate returns validated config that is rooted at the root of argspec and with added nulls for fields of nested objects that
        # didn't have a value passed in but some fields in the object did
        config = validate_config(self._module.argument_spec, {"config": config})["config"]
        # not really using the none values in this module so getting thrown out. Use empty lists for clear
        config = remove_none(config)
        if "interfaces" in config and config["interfaces"] is not None:
            for interface in config["interfaces"]:
                interface["name"] = get_normalize_interface_name(interface.get("name", ""), self._module)
                if "power_limit" in interface and interface["power_limit"] is not None \
                        and interface["power_limit"] not in range(0, 99901):
                    self._module.fail_json(msg="interface {intf_name} has invalid power limit, must be between 0 and 99900".format(intf_name=interface['name']))
        if "cards" in config and config["cards"] is not None:
            for card in config["cards"]:
                if "usage_threshold" in card and card["usage_threshold"] is not None \
                        and card["usage_threshold"] not in range(1, 100):
                    self._module.fail_json(msg="card {id} has invalid usage threshold value, must be between 1 and 99".format(id=card["card_id"]))
        if "global" in config and config["global"] is not None:
            if "usage_threshold" in config["global"] and config["global"]["usage_threshold"] is not None\
                    and config["global"]["usage_threshold"] not in range(1, 100):
                self._module.fail_json(msg="global config has invalid usage threshold value, must be between 1 and 99 inclusive")
        return config

    def make_merged_requests(self, commands):
        '''append all requests needed to merge in requested changes

        :param commands: requested changes to all PoE config specified in PoE argspec format
        :returns: the request list to make merge changes requested'''
        requests = []
        requests.extend(self.make_patch_poe_root_request(commands))

        if "interfaces" in commands:
            requests.extend(self.make_interfaces_requests(commands["interfaces"]))
        return requests

    def make_patch_poe_root_request(self, commands):
        '''builds request to patch changes to PoE global card and other cards

        :param commands: requested changes to all PoE config in PoE argspec format
        :returns: a list of requests to patch changes to PoE global card and other cards.
        may be empty if nothing needs to be changed'''
        requests = []
        root_request_body = {}
        cards_list_body = self.make_cards_list_request_body(commands.get("cards", {}))
        if len(cards_list_body) > 0:
            root_request_body.update({"cards": {"card": cards_list_body}})

        global_config_body = self.make_global_config_request_body(commands.get("global", {}))
        if len(global_config_body) > 0:
            root_request_body.update({"global": {"config": global_config_body}})

        if len(root_request_body) > 0:
            requests.append(
                {
                    "path": self.poe_root_uri,
                    "method": "patch",
                    "data": {"openconfig-poe:poe": root_request_body}
                }
            )
        return requests

    def make_global_config_request_body(self, global_config):
        '''make the body for a patch/put request that changes global PoE config.

        :param global_config: the global section of PoE config in PoE argspec format

        :rtype: a dictionary
        :returns: REST API format dictionary holding the global PoE settings passed in'''
        config_body = {}
        config_body["auto-reset-mode"] = global_config.get("auto_reset")
        config_body["power-management-model"] = poe_str2enum(global_config.get("power_mgmt_model"))
        config_body["power-usage-threshold"] = global_config.get("usage_threshold")
        return remove_empties(config_body)

    def make_cards_list_request_body(self, cards_config):
        '''make the body for a patch/put request that changes PoE cards config.

        :param cards_config: list of dictionaries where each item is a PoE cards' config in PoE argspec format

        :rtype: list
        :returns: a list of cards and config in the REST API's format for PoE cards'''
        card_list = []
        for card_config in cards_config:
            card_body = {}
            card_body["auto-reset-mode"] = card_config.get("auto_reset")
            card_body["power-management-model"] = poe_str2enum(card_config.get("power_mgmt_model"))
            card_body["power-usage-threshold"] = card_config.get("usage_threshold")
            card_body = remove_empties(card_body)
            if len(card_body) > 0:
                # if none of settings that could be changed were found to have values to change, don't  send an unnecessary command to device.
                card_body["card-id"] = card_config["card_id"]
                card_list.append({"card-id": card_config["card_id"], "config": card_body})
        return card_list

    def make_interfaces_requests(self, interfaces_config):
        '''build the request to patch in changes to multiple interfaces' PoE settings

        :param interfaces_config: list of interfaces' PoE config dictionaries in PoE argspec format

        :rtype: list
        :returns: A list of requests needed to patch in the requested changes to interfaces' PoE config'''
        requests = []
        interfaces_body = []

        for interface_config in interfaces_config:
            interface_body = self.make_interface_request_body(interface_config)
            if len(interface_body) > 0:
                # module knowing whether or not changes were made depends on if there are requests,
                # so need to make sure all data and requests are in fact making changes
                interfaces_body.append(
                    {
                        "name": interface_config["name"],
                        "openconfig-if-ethernet:ethernet": {
                            "openconfig-if-poe:poe": {"config": interface_body}
                        }
                    }
                )
        if len(interfaces_body) > 0:
            requests.append(
                {
                    "path": self.interfaces_root_uri,
                    # don't use PUT. PoE is only a subsection of all interface settings and this resource
                    # module will only ever be handling that subsection and PUT will erase all other subsections
                    "method": "patch",
                    "data": {
                        "openconfig-interfaces:interfaces": {
                            "interface": interfaces_body
                        }
                    }
                }
            )
        return requests

    def make_interface_request_body(self, interface_config):
        '''make the body for a patch/put request that changes PoE settings on an interface.

        :param interface_confg: dictionary of config for one interface. specified in PoE argspec format

        :rtype: dictionary
        :returns: REST API format dictionary holding the PoE settings passed in'''
        interface_body = {}
        # For each attribute type to be included in the request, translate the user input as needed
        # and format the corresponding REST API attribute to be specified in the request.
        if "detection" in interface_config:
            # since detection mode strings have some overlap with other categroies, poe_str2enum requires prepending 'detection-'
            interface_body[self.poe_setting_prefix + "detection-mode"] = poe_str2enum("detection-" + interface_config["detection"])
        if "disconnect_type" in interface_config:
            interface_body[self.poe_setting_prefix + "disconnect-type"] = poe_str2enum(interface_config["disconnect_type"])
        if "enabled" in interface_config:
            interface_body["enabled"] = interface_config["enabled"]
        if "four_pair" in interface_config:
            interface_body[self.poe_setting_prefix + "four-pair-mode"] = interface_config["four_pair"]
        if "high_power" in interface_config:
            interface_body[self.poe_setting_prefix + "high-power-mode"] = interface_config["high_power"]
        if "power_classification" in interface_config:
            interface_body[self.poe_setting_prefix + "power-classification-mode"] = \
                poe_str2enum(interface_config["power_classification"])
        if "power_limit" in interface_config:
            interface_body[self.poe_setting_prefix + "power-limit"] = interface_config["power_limit"]
        if "power_limit_type" in interface_config:
            interface_body[self.poe_setting_prefix + "power-limit-type"] = \
                poe_str2enum(interface_config["power_limit_type"])
        if "power_limit_type" in interface_config:
            interface_body[self.poe_setting_prefix + "power-pairs"] = poe_str2enum(interface_config["power_pairs"])
        if "power_up_mode" in interface_config:
            interface_body[self.poe_setting_prefix + "powerup-mode"] = poe_str2enum(interface_config["power_up_mode"])
        if "priority" in interface_config:
            interface_body[self.poe_setting_prefix + "priority"] = interface_config["priority"].upper()
        if "use_spare_pair" in interface_config:
            interface_body[self.poe_setting_prefix + "use-spare-pair"] = interface_config["use_spare_pair"]
        return remove_empties(interface_body)

    def make_delete_requests(self, to_delete, have):
        '''get all requests needed to delete the given configuration from device
        :param to_delete: config to delete specified in PoE argspec format
        :param have: current configuration specified in PoE argspec format
        :rtype: list
        :returns: list of requests needed to delete config'''

        requests = []
        if "global" in to_delete:
            if "auto_reset" in to_delete["global"]:
                requests.append({"path": "data/openconfig-poe:poe/global/config/auto-reset-mode", "method": "DELETE"})
            if "power_mgmt_model" in to_delete["global"]:
                requests.append({"path": "data/openconfig-poe:poe/global/config/power-management-model", "method": "DELETE"})
            if "usage_threshold" in to_delete["global"]:
                requests.append({"path": "data/openconfig-poe:poe/global/config/power-usage-threshold", "method": "DELETE"})
        if "cards" in to_delete:
            requests.extend(self.make_delete_card_requests(to_delete["cards"], have.get("cards", [])))
        if "interfaces" in to_delete:
            requests.extend(self.make_delete_interface_requests(to_delete["interfaces"], have.get("interfaces", [])))
        return requests

    def make_delete_card_requests(self, to_delete, have):
        '''get all requests needed to delete the given cards. have is needed to decide if whole card or individual attribues need to be deleted

        :param to_delete: list of card configs to delete specified in PoE argspec format. assumes all entries have to be deleted
        :param have: current list of card configurations specified in PoE argspec format
        :rtype: list
        :returns: list of requests needed to delete the given card configs'''
        requests = []
        for card_d in to_delete:
            for card_h in have:
                # assumption for to_delete means that all cards in to_delete are also in have, this has already been checked before this function
                if card_d["card_id"] == card_h["card_id"]:
                    if card_d.keys() == {"name"} or set(card_d.keys()) == set(card_h.keys()):
                        requests.append({"path": "data/openconfig-poe:poe/cards/card={card_id}".format(card_id=card_h["card_id"]), "method": "DELETE"})
                    else:
                        if "auto_reset" in card_d:
                            requests.append({"path": "data/openconfig-poe:poe/cards/card={card_id}/config/auto-reset-mode"
                                             .format(card_id=card_h["card_id"]), "method": "DELETE"})
                        if "power_mgmt_model" in card_d:
                            requests.append({"path": "data/openconfig-poe:poe/cards/card={card_id}/config/power-management-model"
                                             .format(card_id=card_h["card_id"]), "method": "DELETE"})
                        if "usage_threshold" in card_d:
                            requests.append({"path": "data/openconfig-poe:poe/cards/card={card_id}/config/power-usage-threshold"
                                             .format(card_id=card_h["card_id"]), "method": "DELETE"})
                    break

        return requests

    def make_delete_interface_requests(self, to_delete, have):
        '''get all requests needed to delete the given interfaces. have is needed to decide if whole interface or individual attribues need to be deleted

        :param to_delete: list of interface configs to delete specified in PoE argspec format
        :param have: current list of interface configurations specified in PoE argspec format
        :rtype: list
        :returns: list of requests needed to delete the given interface configs'''

        interface_poe_setting_name = "data/openconfig-interfaces:interfaces/interface={if_name}/openconfig-if-ethernet:ethernet/" + \
                                     "openconfig-if-poe:poe/config/openconfig-if-poe-ext:{setting}"
        requests = []
        for interface_d in to_delete:
            for interface_h in have:
                # since assuming all entries have to be deleted, means can assume that there is a match in current configuration
                if interface_d["name"] == interface_h["name"]:
                    if interface_d.keys() == {"name"} or set(interface_d.keys()) == set(interface_h.keys()):
                        requests.append({"path": "data/openconfig-interfaces:interfaces/interface={if_name}".format(if_name=interface_h["name"]) +
                                         "/openconfig-if-ethernet:ethernet/openconfig-if-poe:poe/config", "method": "DELETE"})
                    else:
                        if "enabled" in interface_d:
                            requests.append({"path": "data/openconfig-interfaces:interfaces/interface={if_name}".format(if_name=interface_h["name"]) +
                                             "/openconfig-if-ethernet:ethernet/openconfig-if-poe:poe/config/enabled", "method": "patch",
                                             "data": {"openconfig-if-poe:enabled": False}})
                        if "priority" in interface_d:
                            requests.append({"path": interface_poe_setting_name.format(if_name=interface_h["name"], setting="priority"), "method": "DELETE"})
                        if "detection" in interface_d:
                            requests.append({"path": interface_poe_setting_name.format(if_name=interface_h["name"], setting="detection-mode"),
                                             "method": "DELETE"})
                        if "power_up_mode" in interface_d:
                            requests.append({"path": interface_poe_setting_name.format(if_name=interface_h["name"], setting="powerup-mode"),
                                             "method": "DELETE"})
                        if "power_pairs" in interface_d:
                            requests.append({"path": interface_poe_setting_name.format(if_name=interface_h["name"], setting="power-pairs"),
                                             "method": "DELETE"})
                        if "power_limit_type" in interface_d:
                            requests.append({"path": interface_poe_setting_name.format(if_name=interface_h["name"], setting="power-limit-type"),
                                             "method": "DELETE"})
                        if "power_limit" in interface_d:
                            requests.append({"path": interface_poe_setting_name.format(if_name=interface_h["name"], setting="power-limit"),
                                             "method": "DELETE"})
                        if "high_power" in interface_d:
                            requests.append({"path": interface_poe_setting_name.format(if_name=interface_h["name"], setting="high-power-mode"),
                                             "method": "DELETE"})
                        if "disconnect_type" in interface_d:
                            requests.append({"path": interface_poe_setting_name.format(if_name=interface_h["name"], setting="disconnect-type"),
                                             "method": "DELETE"})
                        if "four_pair" in interface_d:
                            requests.append({"path": interface_poe_setting_name.format(if_name=interface_h["name"], setting="four-pair-mode"),
                                             "method": "DELETE"})
                        if "use_spare_pair" in interface_d:
                            requests.append({"path": interface_poe_setting_name.format(if_name=interface_h["name"], setting="use-spare-pair"),
                                             "method": "DELETE"})
                        if "power_classification" in interface_d:
                            requests.append({"path": interface_poe_setting_name.format(if_name=interface_h["name"], setting="power-classification-mode"),
                                             "method": "DELETE"})
                    break
        return requests

    def get_overridden_must_delete_config(self, remove_diff, introduced_diff):
        '''specifically for overridden state, finds and builds collection of which config settings won't be replaced by new values when merging new config,
        in other words needs to be deleted. `get_diff` will return collection of both things that need to be deleted and things that will have new values.'''
        result = {}
        if "global" in remove_diff:
            # possible to have global section in only one of two inputs
            result["global"] = {}
            for key in ["auto_reset", "power_mgmt_model", "usage_threshold"]:
                if key in remove_diff["global"] and key not in introduced_diff.get("global", {}):
                    result["global"][key] = remove_diff["global"][key]
        if "cards" in remove_diff:
            if "cards" not in introduced_diff:
                # nothing being substituded, everything is being deleted
                result["cards"] = remove_diff["cards"]
            else:
                result["cards"] = self.get_override_must_delete_lists(remove_diff["cards"], introduced_diff["cards"], ["card_id"])
        if "interfaces" in remove_diff:
            if "interfaces" not in introduced_diff:
                result["interfaces"] = remove_diff["interfaces"]
            else:
                result["interfaces"] = self.get_override_must_delete_lists(remove_diff["interfaces"], introduced_diff["interfaces"], ["name"])
        return result

    def get_override_must_delete_lists(self, remove_diff, introduced_diff, key_fields):
        '''
        takes two lists of dictionaries and finds settings in items or whole items in remove_diff that aren't in introduced
        :param remove_diff: the list of items that want to be removed during overridden state
        :param introduced_diff: the list of items that want to be added during overridden state
        :param key_fields: names of the fields in each item that identify items apart'''
        result = []
        for item_r in remove_diff:
            matched = None
            for item_i in introduced_diff:
                key_r = tuple(item_r[field] for field in key_fields)
                key_i = tuple(item_i[field] for field in key_fields)
                if key_i == key_r:
                    matched = deepcopy(item_r)
                    for item_setting in item_r:
                        if item_setting not in key_fields and item_setting in item_i:
                            # key fields needed for identification, keeping in
                            del matched[item_setting]
                    if len(matched) > len(key_fields):
                        # only need to delete the fields that aren't the keys so only add if more options are found
                        result.append(matched)
                    break
            if matched is None:
                result.append(item_r)
        return result
