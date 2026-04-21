#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_ospf_area class
It is in this file where the current configuration (as list)
is compared to the provided configuration (as list) and the command set
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
    validate_config,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils \
    import (
        get_diff,
        update_states,
        to_request,
        edit_config,
        remove_empties
    )
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_OP_DEFAULT,
    __DELETE_SAME_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF,
    get_new_config,
    get_formatted_config_diff
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_none
)


def list_generate_deleted_config_helper(key_set, command, existing_conf, delete_handler):
    '''helps with delete state generate config for this module. takes config that are list structures and
    if there is matching entry in commands, calls passed in handler on the item. Does some preprocessing, if
    commands is empty list empty out current config.'''
    if command == []:
        # command being empty list means clear list
        return []
    if len(existing_conf) == 0:
        # early return there's nothing to delete
        return existing_conf
    if key_set:
        command_dict = {tuple(c[field] for field in key_set): c for c in command}
        existing_dict = {tuple(c[field] for field in key_set): c for c in existing_conf}
    else:
        command_dict = {c: c for c in command}
        existing_dict = {c: c for c in existing_conf}

    new_conf = []
    # for every existing item, either deleting or not
    # keys only in command and not existing do not affect anything
    for e_key, e_data in existing_dict.items():
        if e_key in command_dict:
            # existing has a matching command for deleting, process it
            nu, new_item = delete_handler(key_set, command_dict[e_key], e_data)
            if new_item:
                # filter out if whole item was deleted. only keep items with something leftover
                new_conf.append(new_item)
        else:
            # existing has no matching command for deleting, can't be changed so keep it
            new_conf.append(e_data)
    return new_conf


def derive_delete_area(key_set, command, exist_conf):

    if len(command) == 2:
        # implementation is specifying just area id keys means delete the area
        return True, {}

    # default delete seems to be unable to handle case where existing config has many keys, and command
    # only specifies a list to clear by providing an empty list, and no other keys. Not all existing keys need
    # to be deleted, but default thinks existing should be cleared

    new_conf = deepcopy(exist_conf)
    command_data_keys = [key for key in command.keys() if key not in ["ranges", "networks", "stub", "virtual_links", "vrf_name", "area_id"]]
    exist_data_keys = [key for key in exist_conf.keys() if key not in ["ranges", "networks", "stub", "virtual_links", "vrf_name", "area_id"]]
    both = set(command_data_keys).intersection(exist_data_keys)
    if both:
        for k in both:
            if command[k] == exist_conf[k]:
                del new_conf[k]

    if "networks" in command and "networks" in exist_conf:
        # new_conf's networks will be things in existing that aren't in command
        if command["networks"] == []:
            new_conf["networks"] = []
        else:
            new_conf["networks"] = list(set(new_conf["networks"]) - set(command["networks"]))
    if "ranges" in command and "ranges" in exist_conf:
        new_conf["ranges"] = list_generate_deleted_config_helper({"prefix"}, command["ranges"], exist_conf["ranges"], derive_delete_key)
    if "stub" in command and "stub" in exist_conf:
        nu, new_conf["stub"] = __DELETE_OP_DEFAULT({}, command["stub"], exist_conf["stub"])
    if "virtual_links" in command and "virtual_links" in exist_conf:
        new_conf["virtual_links"] = list_generate_deleted_config_helper(
            {"router_id"}, command["virtual_links"],
            exist_conf["virtual_links"],
            derive_delete_vlink
        )
    new_conf = remove_empties(new_conf)
    if not new_conf or len(new_conf) == 2:
        # area after deleting everything specified is empty or just the keys, disregard it
        return True, {}
    else:
        return True, new_conf


def derive_delete_vlink(key_set, command, exist_conf):

    if len(command) == 1:
        # only virtual link id specified, delete the virtual link
        return True, {}

    # have to try clearing all subsections first and then can know if it is ok to delete virtual link
    command_data_keys = [key for key in command.keys() if key not in ["router_id", "authentication", "message_digest_list"]]
    exist_data_keys = [key for key in exist_conf.keys() if key not in ["router_id", "authentication", "message_digest_list"]]
    both = set(command_data_keys).intersection(exist_data_keys)
    if both:
        for k in both:
            if command[k] == exist_conf[k]:
                del exist_conf[k]
    if "authentication" in command and "authentication" in exist_conf:
        nu, new_auth = __DELETE_SAME_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF(
            {"key_id"},
            command["authentication"] if command["authentication"] else exist_conf["authentication"],
            exist_conf["authentication"]
        )
        exist_conf["authentication"] = new_auth

    if "message_digest_list" in command and "message_digest_list" in exist_conf:
        if command["message_digest_list"] == []:
            exist_conf["message_digest_list"] = []
        else:
            md_keys_after = []
            mdk_c_keys = {mdk["key_id"]: mdk for mdk in command.get("message_digest_list", [])}
            for md_key in exist_conf["message_digest_list"]:
                md_key_c = mdk_c_keys[md_key["key_id"]]

                if md_key_c:
                    if len(md_key_c) == 1:
                        continue
                    nu, new_md_key = __DELETE_SAME_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF({"key_id"}, md_key_c, md_key)
                    if new_md_key:
                        md_keys_after.append(new_md_key)
                else:
                    md_keys_after.append(md_key)
            exist_conf["message_digest_list"] = md_keys_after
    # have taken care of subsections, now for the virtual link
    exist_conf = remove_empties(exist_conf)
    if exist_conf.keys() == key_set:
        return True, {}
    else:
        return True, exist_conf


def derive_delete_key(key_set, command, exist_conf):
    if command.keys() == key_set:
        return True, {}
    else:
        return __DELETE_SAME_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, exist_conf)


TEST_KEYS_generate_config = [
    {"config": {"area_id": "", "vrf_name": "", "__delete_op": derive_delete_area}},
    {"ranges": {"prefix": "", "__delete_op": derive_delete_key}},
    {"virtual_links": {"router_id": "", "__delete_op": derive_delete_vlink}},
    {"message_digest_list": {"key_id": "", "__delete_op": derive_delete_key}}
]


class Ospf_area(ConfigBase):
    """
    The sonic_ospf_area class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'ospf_area',
    ]

    TEST_KEYS = [
        {"config": {"area_id": "", "vrf_name": ""}},
        {"ranges": {"prefix": ""}},
        {"virtual_links": {"router_id": ""}},
        {"message_digest_list": {"key_id": ""}}
    ]

    ospf_uri = "data/openconfig-network-instance:network-instances/network-instance={vrf}/protocols/protocol=OSPF,ospfv2/ospfv2"
    # URI to ospf settings for one network_instance
    ospf_area_uri = ospf_uri + "/areas/area={area_id}"
    # URI to ospf area settings for one network_instance
    ospf_propagation_uri = ospf_uri + "/global/inter-area-propagation-policies/openconfig-ospfv2-ext:inter-area-policy={area_id}"
    # URI to ospf inter-area-propagation-policies settings for one network_instance
    ospf_key_extn = "openconfig-ospfv2-ext:"
    auth_type_conversion = {"message_digest": "MD5HMAC", "text": "TEXT", "none": "NONE"}

    def __init__(self, module):
        super(Ospf_area, self).__init__(module)

    def get_ospf_area_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A list
        :returns: The current configuration as a list of areas' config
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        ospf_area_facts = facts['ansible_network_resources'].get('ospf_area')
        if not ospf_area_facts:
            return []
        return ospf_area_facts["config"]

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = []
        commands = []
        existing_ospf_area_facts = self.get_ospf_area_facts()
        commands, requests = self.set_config(existing_ospf_area_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        result['before'] = existing_ospf_area_facts
        new_config = deepcopy(existing_ospf_area_facts)
        # just used for diff mode, setting it to a default value that would show no differences. If there are changes then set to changed value

        if self._module.check_mode:
            new_config = get_new_config(commands, existing_ospf_area_facts,
                                        TEST_KEYS_generate_config)
            result['after(generated)'] = new_config
        elif result['changed']:
            new_config = self.get_ospf_area_facts()
            result['after'] = new_config
        if self._module._diff:
            new_config.sort(key=lambda x: (x['area_id'], x['vrf_name']))
            existing_ospf_area_facts.sort(key=lambda x: (x['area_id'], x['vrf_name']))
            result['config_diff'] = get_formatted_config_diff(existing_ospf_area_facts,
                                                              new_config,
                                                              self._module._verbosity)

        result['warnings'] = warnings
        return result

    def set_config(self, existing_ospf_area_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_ospf_area_facts

        resp = self.set_state(want, have)
        return to_list(resp)

    def set_state(self, want, have):
        """ Select the appropriate function based on the state provided

        :param want: the desired configuration as a list
        :param have: the current configuration as a list
        :rtype: A tuple
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration, and REST requests that do it
        """
        commands = []
        requests = []
        state = self._module.params['state']
        want = self.validate_normalize_config(want, have, state)
        if state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)
        elif state == 'overridden':
            commands, requests = self._state_overridden(want, have)
        else:
            commands, requests = self._state_replaced(want, have)
        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A tuple of lists
        :returns: A list of the commands and state needed to merge the user-specified
                  new and modified configuration commands into the current
                  configuration, and a list of the corresponding requests that
                  need to be sent to the device to make the specified changes
        """
        commands = []
        requests = []
        if want is None:
            return commands, requests

        diff = get_diff(want, have, test_keys=self.TEST_KEYS)
        diff = self.post_process_diff(want, diff)
        requests = self.build_areas_merge_requests(diff)
        commands = diff
        if commands and len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :rtype: A tuple of lists
        :returns: A list of the commands and state needed to delete the user-specified
                  configuration commands from the current
                  configuration, and a list of the corresponding requests that
                  need to be sent to the device to make the specified changes
        """
        commands = []
        requests = []
        if not have:
            return commands, requests
        if not want:
            # empty or None assume delete everything
            commands = have
            requests = self.build_areas_delete_requests(commands, have, delete_everything=True)
        else:
            commands = self.get_delete_and_clears_recursive(
                want,
                have,
                next((k["config"] for k in self.TEST_KEYS if "config" in k), {}),
                test_keys=self.TEST_KEYS
            )

            commands = self.post_process_diff(want, commands, merged_mode=False)
            # commands is things in want that are in have and are not different aka same
            self.remove_default_entries(commands)
            requests = self.build_areas_delete_requests(commands, have)
        if commands and len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []
        return commands, requests

    def get_delete_and_clears_recursive(self, want, have, key_fields=None, test_keys=None):
        ''' get config that should be deleted because they match or wanted config says to clear everything.
        assumes want and have are argspec format and start at same level. any lists in config must have its key in test_keys,
        "config" if root of config, and the names of fields that create a key for each item must be passed to each item inside list

        :param key_fields: list or dict (only looks at the keys of dict) holding the names of the fields that create an identifying key for configuration item.
        If want and have are dictionary, then the fields in want and have that create a key for want or have
        If want and have are lists of dictionaries then the fields in want and have that create a key for each list entry
        If its lists of strings, then each string is the key'''
        if key_fields is None:
            key_fields = {}
        if test_keys is None:
            test_keys = self.TEST_KEYS
        # fill in defaults for helper information

        if isinstance(want, dict):
            if want.keys() == key_fields.keys():
                # special case if want only has keys, then that means clear object
                # returning what to delete
                return have
            present_fields = set(want.keys()) & set(have.keys())
            # list of all fields inside the config we are looking at
            commands = {}
            for field_name in present_fields:
                if field_name not in key_fields and field_name in want and field_name in have:
                    # handling deletion checks, only need to if field is in both want and have
                    if isinstance(want[field_name], list):
                        key_filter = [k[field_name] for k in test_keys if field_name in k]
                        # want to find key fields for nested items, first step is finding if it is in test_keys
                        sub_section = self.get_delete_and_clears_recursive(
                            want[field_name],
                            have[field_name],
                            key_fields=key_filter[0] if key_filter else {},
                            test_keys=test_keys
                        )
                        if sub_section:
                            commands[field_name] = sub_section
                    elif isinstance(want[field_name], dict):
                        sub_section = self.get_delete_and_clears_recursive(want[field_name], have[field_name], key_fields={}, test_keys=test_keys)
                        if sub_section:
                            commands[field_name] = sub_section
                    else:
                        if want[field_name] == have[field_name]:
                            commands[field_name] = want[field_name]
            if commands:
                for key_field in key_fields:
                    commands[key_field] = want[key_field]
            return commands
        if isinstance(want, list):
            if len(want) == 0:
                # special case logic of blank lists means clear everything
                # returning what to delete
                return have
            elif isinstance(want[0], str):
                # list of primitive types. cannot do logic of finding keyfields but set logic works
                # returning what to delete
                return list(set(want) & set(have))
            else:
                commands = []
                # use keys to find which items we need to figure out what to delete inside
                # create dictionary mapping from each item's identifier to item. identifier can be made of multiple fields in item
                want_item_keys = {tuple(item[field] for field in key_fields): item for item in want}
                have_item_keys = {tuple(item[field] for field in key_fields): item for item in have}

                matched_item_keys = set(want_item_keys.keys()) & set(have_item_keys.keys())
                # list items that are present in both want and have
                # only need to look for deletes when an item appears in both

                for item_key in matched_item_keys:
                    # for each item, get things that should be deleted
                    # key fields need to be passed to get right formatting back
                    sub_section = self.get_delete_and_clears_recursive(want_item_keys[item_key], have_item_keys[item_key], key_fields, test_keys)
                    if sub_section:
                        commands.append(sub_section)
                return commands

    def _state_replaced(self, want, have):
        """ The command generator when state is replaced

        :rtype: A tuple of lists
        :returns: A list of what commands and state necessary to migrate the current configuration
                  to the desired configuration, and a list of requests needed to make changes
        """
        commands = []
        requests = []

        replace_commands = []
        add_commands = []

        area_h_keys = {(area["area_id"], area["vrf_name"]): area for area in have}
        # to make it easy, if an area appears in both have and want, just delete the whole area definition from have and then replace with the want
        for area_w in want:
            area_h = area_h_keys.get((area_w["area_id"], area_w["vrf_name"]), None)

            if area_h is None:
                # new area, no previous definition. which means always need to add it
                add_commands.append(area_w)
                continue

            diff_remove = get_diff([area_h], [area_w], test_keys=self.TEST_KEYS)
            self.remove_default_entries(diff_remove)
            diff_add = get_diff([area_w], [area_h], test_keys=self.TEST_KEYS)
            if diff_remove and len(diff_remove) > 0:
                # there are differences between have and want, so removing the whole area and replace
                replace_commands.append(area_h)
                add_commands.append(area_w)
            elif diff_add and len(diff_add) > 0:
                # just new differences to add
                add_commands.append(area_w)

        replace_commands = self.post_process_diff(want, replace_commands, merged_mode=False)
        add_commands = self.post_process_diff(want, add_commands)

        if not want:
            return commands, requests
        if replace_commands:
            requests.extend(self.build_areas_delete_requests(replace_commands, have, delete_everything=True))
            commands.extend(update_states(replace_commands, "deleted"))
        if add_commands:
            requests.extend(self.build_areas_merge_requests(add_commands))
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
        areas_w_keys = {(area["vrf_name"], area["area_id"]): area for area in want}
        areas_h_keys = {(area["vrf_name"], area["area_id"]): area for area in have}

        area_keys = set(areas_w_keys.keys()) | set(areas_h_keys.keys())

        deleted_commands = []
        added_commands = []

        for area_key in area_keys:
            if area_key in areas_h_keys and area_key not in areas_w_keys:
                # override: any areas that are in have but not in want are deleted
                deleted_commands.append(areas_h_keys[area_key])
            elif area_key not in areas_h_keys and area_key in areas_w_keys:
                # override: any areas that are in want but not in have are added
                added_commands.append(areas_w_keys[area_key])
            elif area_key in areas_h_keys and area_key in areas_w_keys:
                diff_remove = get_diff([areas_h_keys[area_key]], [areas_w_keys[area_key]], test_keys=self.TEST_KEYS)
                diff_add = get_diff([areas_w_keys[area_key]], [areas_h_keys[area_key]], test_keys=self.TEST_KEYS)
                if diff_remove and len(diff_remove) > 0:
                    # just deleting and adding the whole areas
                    deleted_commands.append(areas_h_keys[area_key])
                    added_commands.append(areas_w_keys[area_key])
                elif diff_add and len(diff_add) > 0:
                    added_commands.append(areas_w_keys[area_key])

        deleted_commands = self.post_process_diff(have, deleted_commands, merged_mode=False)
        added_commands = self.post_process_diff(want, added_commands)

        if deleted_commands:
            requests.extend(self.build_areas_delete_requests(deleted_commands, have, delete_everything=True))
            commands.extend(update_states(deleted_commands, "deleted"))
        if added_commands:
            requests.extend(self.build_areas_merge_requests(added_commands))
            commands.extend(update_states(added_commands, "overridden"))
        return commands, requests

    def validate_normalize_config(self, config, have, state):
        '''validates config and and normalizes format of data. Normalization includes formatting area id, checking setting default cost,
        and filling in auth key information.
        :returns: config object that has been validated and normalized'''
        if not config:
            return []
        config = {"config": config}
        config = remove_none(config)
        # validate_config returns validated user input config. The returned data is based on the
        # argspec definition. At each nested level of the argspec for which the user has specified
        # one or more attributes, the returned data contains added nulls for any attributes that
        # were not specified by the user input.
        config = validate_config(self._module.argument_spec, config)
        # not really using the none values in this module so getting thrown out. Use empty lists for clear
        config = remove_none(config)["config"]
        area_h_keys = {(area["area_id"], area["vrf_name"]): area for area in have}
        for area in config:
            try:
                area['area_id'] = self.format_area_name(area['area_id'])
            except Exception as exc:
                self._module.fail_json(msg=str(exc))

            if state != "deleted":
                # only when trying to merge is it an issue if default cost is being set when not stub or NSSA
                # finding out if default_cost can be set depends on have and commands
                area_h = area_h_keys.get((area['area_id'], area['vrf_name']), None)
                can_set_cost = (area_h is not None and area_h.get("stub", {}).get('enabled', False)) or area.get("stub", {}).get('enabled', False)
                if area.get("default_cost") and not can_set_cost:
                    self._module.fail_json(msg="cannot set default cost for area id {area_id} in ".format(area_id=area['area_id']) +
                                           "vrf {vrf_name} because it is not stub or NSSA area".format(vrf_name=area['vrf_name']))

            for virtual_link in area.get("virtual_links", []):
                if "authentication" in virtual_link:
                    if state != "deleted":
                        # key is always going to either be encrypted or not.
                        # key_encrypted field only really should exist if key exists so fill in encrypted if missing and defaults to false
                        if "key" in virtual_link["authentication"] and "key_encrypted" not in virtual_link["authentication"]:
                            virtual_link["authentication"]["key_encrypted"] = False
                for md_key in virtual_link.get("message_digest_list", []):
                    if state != "deleted":
                        if "key" not in md_key:
                            # any state that is adding config cannot have a missing key
                            self._module.fail_json(msg="area id'd {area_id} for vrf ".format(area_id=area['area_id']) +
                                                       "{vrf_name} has missing key ".format(vrf_name=area['vrf_name']) +
                                                       "for key_id {id} in message_digest_list ".format(id=md_key["key_id"]) +
                                                       "section of virtual link {vlink}".format(vlink=virtual_link['router_id']))
                        if "key_encrypted" not in md_key:
                            md_key["key_encrypted"] = False
        return config

    def format_area_name(self, area_id):
        """area names in playbook can be single numbers or as four octet numbers, switch works with area names as the latter.
        make sure things are in octect format by applying formatting where needed"""
        if area_id.count(".") < 3:
            area_int = int(area_id)
            return ".".join([str(area_int >> 24 & 0xff), str(area_int >> 16 & 0xff), str(area_int >> 8 & 0xff), str(area_int & 0xff)])
        return area_id

    def post_process_diff(self, want, diff, merged_mode=True):
        '''post process the diff between want and have by keeping any wanted auth key settings together.
        :param want: the config that the difference is based off of. the first item in the get_diff call
        :param diff: the diff between want and have config in argspec format. assumes diff is a subset of want'''
        # whatever values were set for key and key encrypted should be kept together
        post_cleaned_diff = []
        area_w_keys = {(area["area_id"], area["vrf_name"]): area for area in want}

        for area_d in diff:
            area_w = area_w_keys.get((area_d["area_id"], area_d["vrf_name"]), None)
            if merged_mode and len(area_w) == 2:
                # commands has an area with no settings to merge, that doesn't show up in facts because it can break other stuff,
                # so putting in step to ignore
                continue
            if not area_w:
                continue

            virtual_w_keys = {vl["router_id"]: vl for vl in area_w.get("virtual_links", [])}
            for virtual_d in area_d.get("virtual_links", []):
                # virtual_d = virtual_d_keys.get(virtual_w["router_id"], None)
                virtual_w = virtual_w_keys.get(virtual_d["router_id"], None)
                if not virtual_w:
                    continue
                # key always has a key_encrypted setting. They are defined together so they must travel as a pair. Handle violations of this
                # requirement presented by the default 'get_diff'
                # ie playbook may specify encrypted key A, and device has encrypted key B. get diff will find the keys different, not the key_encrypted
                # setting and only the key goes into the diff. The diff is missing the encrypted setting so it needs to grab that from existing settings.
                if virtual_d.get("authentication", {}).get("key") and virtual_d.get("authentication", {}).get("key_encrypted") is None \
                        and virtual_w.get("authentication", {}).get("key_encrypted") is not None:
                    # specified a different key that is also encrypted. fix that error in diff
                    virtual_d["authentication"]["key_encrypted"] = virtual_w["authentication"]["key_encrypted"]
                if not virtual_d.get("authentication", {}).get("key") and virtual_d.get("authentication", {}).get("key_encrypted") is not None \
                        and virtual_w.get("authentication", {}).get("key"):
                    # same key but different encryption
                    # this is likely error situation since single key can't work for both un- and encrypted
                    # and just make sure two are together for easier debugging
                    virtual_d["authentication"]["key"] = virtual_w["authentication"]["key"]

                mdk_w_keys = {mdk["key_id"]: mdk for mdk in virtual_w.get("message_digest_list", [])}
                for md_key_d in virtual_d.get("message_digest_list", []):
                    md_key_w = mdk_w_keys.get(md_key_d["key_id"], None)
                    if not md_key_d:
                        # message digest key didn't end up with a difference, so nothing to do
                        continue
                    if md_key_d.get("key") and md_key_d.get("key_encrypted") is None \
                            and md_key_w.get("key_encrypted") is not None:
                        # specified a different key that is also encrypted. fixes that error
                        md_key_d["key_encrypted"] = md_key_w["key_encrypted"]
                    if not md_key_d.get("key") and md_key_d.get("key_encrypted") is not None \
                            and md_key_w.get("key"):
                        # same key but different encryption
                        # this is likely error situation since single key can't work for both un- and encrypted
                        # and just make sure two are together for easier debugging
                        md_key_d["key"] = md_key_w["key"]
            if merged_mode:
                area_d = remove_empties(area_d)
            post_cleaned_diff.append(area_d)
        return post_cleaned_diff

    def build_areas_merge_requests(self, want):
        '''takes a list of areas and builds up all requests to patch in wanted changes'''
        requests = []
        formatted_bodies = {}
        vlink_requests = []
        # tracking all formatted lists that will go into the final requests for each vrf

        # list of areas is not organized by VRF and REST requests are being consolidated into a call on each VRF, so need to sort the area list.
        # Also the organization is different between REST and argspec, argspec has config that goes into ospf areas and
        # ospf global inter-area-propagation-policies of the REST format.
        # Since REST has two distinct subsections, these are formatted separately and then conbimned into one REST request
        for area in want:
            # if an area is passed in, assuming want to create it no matter what settings (or just area id) passed in, so area has to exist
            formatted_area = self.format_area_options_to_rest(area)
            formatted_area_policy = self.format_area_policy_to_rest(area)
            if "virtual_links" in area:
                # merging vlinks is done as a separate request from rest of area settings.
                # Area settings go to the vrf configuration endpoint, vlinks go to the virtual link endpoint.
                # This allows vlinks with just the router id with no other settings specified to be created.
                # These requests still depend on area being created first, so on the safe side, getting area requests first before handlign virtual links
                vlink_requests.extend(self.build_area_vlink_merge_requests(
                    self.ospf_area_uri.format(vrf=area["vrf_name"], area_id=area["area_id"]),
                    area["virtual_links"]
                ))
            # consolidate by Vrf
            if (formatted_area or formatted_area_policy) and area["vrf_name"] not in formatted_bodies:
                formatted_bodies[area["vrf_name"]] = {"areas": [], "propagation": []}
            if formatted_area:
                formatted_bodies[area["vrf_name"]]["areas"].append(formatted_area)
            if formatted_area_policy:
                formatted_bodies[area["vrf_name"]]["propagation"].append(formatted_area_policy)

        # build requests on vrf
        for vrf in formatted_bodies:
            vrf_request_body = {}
            if formatted_bodies[vrf]["areas"]:
                vrf_request_body["areas"] = {"area": formatted_bodies[vrf]["areas"]}
            if formatted_bodies[vrf]["propagation"]:
                vrf_request_body["global"] = {"inter-area-propagation-policies": {
                    self.ospf_key_extn + "inter-area-policy": formatted_bodies[vrf]["propagation"]
                }}
            if vrf_request_body:
                requests.append({"path": self.ospf_uri.format(vrf=vrf), "method": "PATCH", "data": {"openconfig-network-instance:ospfv2": vrf_request_body}})
        requests.extend(vlink_requests)
        return requests

    def build_area_vlink_merge_requests(self, path_root, want_vlinks):
        '''build requests for an area's virtual links
        :param path_root: the URI for the specific area the vlinks are being added in
        :param want_vlinks: the list of virtual links to be added'''
        requests = []
        formatted_vlinks = self.format_vlinks_to_rest(want_vlinks)
        if formatted_vlinks:
            # endpoint is an area's virtual links.
            requests.append({"path": path_root + "/virtual-links",
                             "method": "PATCH", "data": {"openconfig-network-instance:virtual-links": {"virtual-link": formatted_vlinks}}})
        return requests

    def format_area_options_to_rest(self, want):
        '''takes a single area config and formats it for the body of an REST patch request.
        Only formats the part that fall under the area object in REST format, except for vlinks which are added separately'''
        formatted_area = {}

        formatted_config = self.format_area_config_to_rest(want)
        if formatted_config:
            formatted_area["config"] = formatted_config

        formatted_stub_config = {}
        if "stub" in want:
            # need enabled flag in stub so can make a stub without setting other settings
            if "enabled" in want["stub"]:
                formatted_stub_config["enable"] = want["stub"]["enabled"]
            if "no_summary" in want["stub"]:
                formatted_stub_config["no-summary"] = want["stub"]["no_summary"]
        if "default_cost" in want:
            formatted_stub_config["default-cost"] = want["default_cost"]

        # can't set default_cost on an area that isn't stub or NSAA.

        if formatted_stub_config:
            formatted_area[self.ospf_key_extn + "stub"] = {"config": formatted_stub_config}

        if "networks" in want:
            formatted_networks = self.format_area_networks_to_rest(want["networks"])
            if formatted_networks:
                formatted_area[self.ospf_key_extn + "networks"] = {"network": formatted_networks}

        # skip adding formatted virtual links into area settings because that will be added separately
        if formatted_area:
            # either settings found to be merged into the areas part of ospf settings or there's settings in the inter-area-policies section
            formatted_area["identifier"] = want["area_id"]
        return formatted_area

    def format_area_config_to_rest(self, want):
        '''takes config wanting to be merged and formats the body of the area object's config in REST format'''
        formatted_config = {}
        if "authentication_type" in want:
            formatted_config[self.ospf_key_extn + "authentication-type"] = self.auth_type_conversion[want["authentication_type"]]
        if "shortcut" in want:
            formatted_config[self.ospf_key_extn + "shortcut"] = want["shortcut"].upper()
        formatted_config["identifier"] = want["area_id"]
        return formatted_config

    def format_area_networks_to_rest(self, want):
        formatted_networks = []
        for network_prefix in want:
            formatted_network = {"address-prefix": network_prefix, "config": {"address-prefix": network_prefix}}
            formatted_networks.append(formatted_network)
        return formatted_networks

    def format_vlinks_to_rest(self, want):
        '''takes a list of virtual link settings and formats it for REST requests'''
        formatted_vlinks = []
        for vlink_settings in want:
            formatted_vlink = {}
            formatted_vlink_config = {}
            if "enabled" in vlink_settings:
                formatted_vlink_config[self.ospf_key_extn + "enable"] = vlink_settings["enabled"]
            if "dead_interval" in vlink_settings:
                formatted_vlink_config[self.ospf_key_extn + "dead-interval"] = vlink_settings["dead_interval"]
            if "hello_interval" in vlink_settings:
                formatted_vlink_config[self.ospf_key_extn + "hello-interval"] = vlink_settings["hello_interval"]
            if "retransmit_interval" in vlink_settings:
                formatted_vlink_config[self.ospf_key_extn + "retransmission-interval"] = vlink_settings["retransmit_interval"]
            if "transmit_delay" in vlink_settings:
                formatted_vlink_config[self.ospf_key_extn + "transmit-delay"] = vlink_settings["transmit_delay"]
            if "authentication" in vlink_settings:
                if "auth_type" in vlink_settings["authentication"]:
                    formatted_vlink_config[self.ospf_key_extn + "authentication-type"] = \
                        self.auth_type_conversion[vlink_settings["authentication"]["auth_type"]]
                if "key" in vlink_settings["authentication"]:
                    formatted_vlink_config[self.ospf_key_extn + "authentication-key"] = vlink_settings["authentication"]["key"]
                if "key_encrypted" in vlink_settings["authentication"]:
                    formatted_vlink_config[self.ospf_key_extn + "authentication-key-encrypted"] = vlink_settings["authentication"]["key_encrypted"]
            if "message_digest_list" in vlink_settings:
                formatted_vlink[self.ospf_key_extn + "md-authentications"] = {"md-authentication":
                                                                              self.format_md_keys_to_rest(vlink_settings["message_digest_list"])}
            formatted_vlink_config["remote-router-id"] = vlink_settings["router_id"]
            formatted_vlink["config"] = formatted_vlink_config
            formatted_vlink["remote-router-id"] = vlink_settings["router_id"]
            formatted_vlinks.append(formatted_vlink)
        return formatted_vlinks

    def format_md_keys_to_rest(self, want):
        '''takes the list of message digest keys in argspec format and formats it for REST body'''
        formatted_keys = []
        for message_key_settings in want:
            formatted_key_config = {}
            if "key_encrypted" in message_key_settings:
                formatted_key_config["authentication-key-encrypted"] = message_key_settings["key_encrypted"]
            formatted_key_config["authentication-key-id"] = message_key_settings["key_id"]
            if "key" in message_key_settings:
                formatted_key_config["authentication-md5-key"] = message_key_settings["key"]
            else:
                self._module.fail_json(msg="message digest key is required in md_authentications")
            formatted_keys.append({"authentication-key-id": message_key_settings["key_id"], "config": formatted_key_config})
        return formatted_keys

    def format_area_policy_to_rest(self, want):
        '''formats area's settings that should go into the inter-area-propagation-policies section of ospf'''
        formatted_area_policy = {}
        if "ranges" in want:
            formatted_ranges = self.format_ranges_to_rest(want["ranges"])
            if formatted_ranges:
                formatted_area_policy["ranges"] = {"range": formatted_ranges}
        if "filter_list_in" in want:
            formatted_area_policy["filter-list-in"] = {"config": {"name": want["filter_list_in"]}}
        if "filter_list_out" in want:
            formatted_area_policy["filter-list-out"] = {"config": {"name": want["filter_list_out"]}}
        if formatted_area_policy:
            formatted_area_policy["src-area"] = want["area_id"]
        return formatted_area_policy

    def format_ranges_to_rest(self, want):
        '''format the ranges an area advertises into REST body format. Takes a list of ranges'''
        formatted_ranges = []
        for range_settings in want:
            formatted_range_config = {}
            if "advertise" in range_settings:
                formatted_range_config["advertise"] = range_settings["advertise"]
            if "cost" in range_settings:
                formatted_range_config["metric"] = range_settings["cost"]
            if "substitute" in range_settings:
                # note it is mispelled in REST
                formatted_range_config["substitue-prefix"] = range_settings["substitute"]
            # can add range even without other settings
            formatted_range_config["address-prefix"] = range_settings["prefix"]
            formatted_ranges.append({"address-prefix": range_settings["prefix"], "config": formatted_range_config})
        return formatted_ranges

    def build_areas_delete_requests(self, commands, have, delete_everything=False):
        '''takes in a list of areas and builds all required 'delete' requests for the specified areas
        :param commands: list of areas to make delete requests for. assumed to be a subset of have
        :param have: the current config in argspec format, at the top level of definition
        :param delete_everything: whether to delete config for all area'''
        requests = []
        area_h_keys = {(area["area_id"], area["vrf_name"]): area for area in have}
        for area_c in commands:
            # want to match so can find out if commands specifies everything within existing area so can de a delete all of area
            matched_have = area_h_keys.get((area_c["area_id"], area_c["vrf_name"]), None)
            if not matched_have:
                # would mean nothing to delete, just ignore. should not hit since commands should be a subset of have
                continue
            area_delete_requests = self.build_area_delete_requests(area_c, matched_have, delete_everything)
            requests.extend(area_delete_requests)
        return requests

    def build_area_delete_requests(self, commands, have, delete_everything=False):
        '''builds the requests to delete configuration under the areas section of config for a single area. takes a pair of single area commands and have.
        returns tuple of whether everything in area was deleted and requests to cause changes'''
        requests = []
        # can't go directly to deleting area, need to check for ranges, network, virtual links -
        # most of nested and complex settings - and delete those first (and separately from area)
        if len(commands) == 2 or delete_everything:
            # allow specifying area id to mean clear it
            delete_everything = True
            commands = have
        # while clearing subsections for area, area itself may get removed in certain cases, for example clearing virtual links when it is the only
        # config inside area.
        # This variable tracks if above has happened. It updates regardless of whether or not module clears all settings for area, but
        # is only used in case of clearing all settings and area. This prevents module from making a second unnecessary and
        # error-causing request in cases where area is removed early.
        area_already_deleted = False

        ranges_all_gone, ranges_delete_requests = self.build_area_delete_ranges_requests(
            self.ospf_propagation_uri.format(vrf=commands["vrf_name"], area_id=commands["area_id"]),
            commands.get("ranges", None),
            have.get("ranges", [])
        )
        requests.extend(ranges_delete_requests)

        networks_all_gone, networks_delete_requests = self.build_area_delete_networks_requests(
            self.ospf_area_uri.format(vrf=commands["vrf_name"], area_id=commands["area_id"]),
            commands.get("networks", None),
            have.get("networks", [])
        )
        requests.extend(networks_delete_requests)

        if "authentication_type" in commands:
            requests.append({"path": self.ospf_area_uri.format(vrf=commands["vrf_name"], area_id=commands["area_id"])
                             + "/config/openconfig-ospfv2-ext:authentication-type", "method": "DELETE"})
            if all(x in ["authentication_type", "networks", "ranges", "area_id", "vrf_name"] for x in commands.keys()) \
                    and networks_all_gone and ranges_all_gone:
                # if this is the only setting left in area then it causes area delete
                area_already_deleted = True
        if "shortcut" in commands:
            requests.append({"path": self.ospf_area_uri.format(vrf=commands["vrf_name"], area_id=commands["area_id"])
                            + "/config/openconfig-ospfv2-ext:shortcut", "method": "DELETE"})
            if all(x in ["shortcut", "networks", "ranges", "area_id", "vrf_name"] for x in commands.keys()) \
                    and networks_all_gone and ranges_all_gone:
                # if this is the only setting left in area then it causes area delete
                area_already_deleted = True

        vlink_all_gone, vlink_delete_requests, vlink_deleted_area = self.build_area_virtual_links_delete_requests(
            self.ospf_area_uri.format(vrf=commands["vrf_name"], area_id=commands["area_id"]),
            commands.get("virtual_links", None),
            have.get("virtual_links", [])
        )
        # if no stub or propagation settings, then area_already_deleted value would be whatever vlink_deleted_area is
        # if there are either of those settings, then vlink_deleted_area is only guessing if area was deleted based off of vlinks
        # and could be incorrect because of the other settings being there. but it is ok to set it because this variable is only
        # used when clearing everything so those sections will end up deleting area.
        area_already_deleted = area_already_deleted or \
            (all(x not in ["default_cost", "stub", "filter_list_in", "filter_list_out"] for x in commands.keys()) and vlink_deleted_area)
        requests.extend(vlink_delete_requests)

        # gathering stub deletions before checking area all gone because
        # it is used to check if area can be deleted
        stub_all_gone, stub_delete_requests, stub_deleted_area = self.build_area_stub_delete_requests(
            self.ospf_area_uri.format(vrf=commands["vrf_name"], area_id=commands["area_id"]),
            commands,
            have
        )
        area_already_deleted = area_already_deleted or (all(x not in ["filter_list_in", "filter_list_out"] for x in commands.keys()) and stub_deleted_area)
        requests.extend(stub_delete_requests)

        # This section, for 'propagation endpoint', handles the inter-area propagation policies
        # this doesn't use a "propagation_all_gone" flag because the nested subection ranges are dealt with separately above.
        # The other settings of filter lists are nested in propagation in REST API but are in root area settings for argspec.
        # This means that a simple check that commands and want (assuming this was passed commands that are in and the same value as have)
        # are the same length is enough to cover the same behaviors
        propagation_delete_requests, propagation_deleted_area = self.build_area_delete_propagation_requests(
            commands,
            have,
            ranges_all_gone,
            ranges_delete_requests)
        requests.extend(propagation_delete_requests)
        area_already_deleted = area_already_deleted or propagation_deleted_area

        if delete_everything or \
                (len(commands) == len(have) and stub_all_gone and vlink_all_gone and ranges_all_gone and networks_all_gone):
            # delete all settings for area.
            # either only area id was specified or any form of clear data,
            # or all settings are named and for the more complex nested subsections of argspec,
            # those subsections also match and are cleared (need the extra flag since length only compares the subsections existence not contents)
            # there are cases where deleting sub-sections causes area to disappear. need to make sure to delete
            # area too so need to check when adding that is needed
            if not area_already_deleted:
                requests.append({'path': self.ospf_area_uri.format(vrf=commands["vrf_name"], area_id=commands["area_id"]), 'method': 'DELETE'})
            return requests
        return requests

    def build_area_stub_delete_requests(self, request_root, commands, have):
        '''builds the requests to delete a single area's stub config. takes a pair of single area commands and have.
        returns a tuple of whether everything in stub config was deleted and requests to cause changes'''
        requests = []
        relevant_have = {"default_cost": have.get("default_cost", None),
                         "no_summary": have.get('stub', {}).get("no_summary", None),
                         "enabled": have.get('stub', {}).get("enabled", None)}
        relevant_commands = {"default_cost": commands.get("default_cost", None),
                             "no_summary": commands.get('stub', {}).get("no_summary", None),
                             "enabled": commands.get('stub', {}).get("enabled", None)}
        relevant_have = remove_empties(relevant_have)
        relevant_commands = remove_empties(relevant_commands)

        if "default_cost" in relevant_commands:
            requests.append({"path": request_root +
                             "/openconfig-ospfv2-ext:stub/config/default-cost", "method": "DELETE"})
        if "no_summary" in relevant_commands:
            requests.append({"path": request_root +
                             "/openconfig-ospfv2-ext:stub/config/no-summary", "method": "DELETE"})
        if "enabled" in relevant_commands:
            requests.append({"path": request_root +
                             "/openconfig-ospfv2-ext:stub/config/enable", "method": "DELETE"})
        if len(relevant_have) == len(relevant_commands):
            # either clearing everything left or there's nothing
            # actually clearing stuff means deleting area
            # area having nothing related to stub also ends up in this case. requests will be empty.
            return True, requests, len(requests) > 0

        # Not all stub configuration is being deleted. (It is also possible that none of the stub options requested
        # for deletion match any current configuration. In that case, no stub configuration is being deleted.)
        return False, requests, False

    def build_area_delete_networks_requests(self, request_root, commands, have):
        if commands is None:
            return len(have) == 0, []
        if len(have) == 0:
            return True, []
        if len(commands) == len(have) or len(commands) == 0:
            return True, [{"path": request_root + "/openconfig-ospfv2-ext:networks/network", "method": "DELETE"}]
        requests = []
        for address_prefix in commands:
            network_string = address_prefix.replace("/", "%2F")
            requests.append({"path": request_root + "/openconfig-ospfv2-ext:networks/network=" + network_string, "method": "DELETE"})
        return False, requests

    def build_area_virtual_links_delete_requests(self, request_root, commands, have):
        '''builds the requests to delete a single area's virtual link config.
        takes a pair of an area's virtual link commands and have.
        returns a tuple of whether everything in area's virtual link config was deleted and requests to cause changes'''
        if commands is None:
            return len(have) == 0, [], False
        requests = []
        partial_deletes = False
        vlink_deleted_area = False
        if len(have) == 0:
            return True, [], vlink_deleted_area
        if len(commands) == 0:
            return True, [{"path": request_root + "/virtual-links/virtual-link", "method": "DELETE"}], True
        vlink_h_keys = {vlink["router_id"]: vlink for vlink in have}
        for vlink_c in commands:
            matched_vlink = vlink_h_keys[vlink_c["router_id"]]
            if not matched_vlink:
                continue
            vlink_uri = request_root + "/virtual-links/virtual-link=" + vlink_c["router_id"]
            if len(vlink_c) == 1:
                # just the remote router id specified so deleting everything inside a
                # virtual link. don't need to process individual attribute delete requests
                # so delete the vlink and move to next
                requests.append({"path": vlink_uri, "method": "DELETE"})
                continue

            # check vlink subsections to see if they were also all deleted or need individual delete requests
            # doing this first as this is used to determine if can just do one request to delete this vlink
            if "message_digest_list" in vlink_c:
                md_all_gone, md_auth_requests = self.build_area_md_auth_delete_requests(vlink_uri, vlink_c["message_digest_list"],
                                                                                        matched_vlink["message_digest_list"])
            else:
                # no message digest keys, means subsection does not need any work on it
                md_all_gone = True
                md_auth_requests = []

            if len(vlink_c) == len(matched_vlink) and md_all_gone:
                # deleting everything inside a virtual link. don't need to process individual attribute delete requests
                # so delete the vlink and move to next
                requests.append({"path": request_root + "/virtual-links/virtual-link=" + vlink_c["router_id"], "method": "DELETE"})
                continue
            partial_deletes = True
            # deleting individual attributes of a vlink, set flag for info that st least one interface needs to delete individual attributes
            requests.extend(md_auth_requests)
            if "enabled" in vlink_c:
                requests.append({"path": vlink_uri + "/config/openconfig-ospfv2-ext:enable", "method": "DELETE"})
            if "dead_interval" in vlink_c:
                requests.append({"path": vlink_uri + "/config/openconfig-ospfv2-ext:dead-interval", "method": "DELETE"})
            if "hello_interval" in vlink_c:
                requests.append({"path": vlink_uri + "/config/openconfig-ospfv2-ext:hello-interval", "method": "DELETE"})
            if "retransmit_interval" in vlink_c:
                requests.append({"path": vlink_uri + "/config/openconfig-ospfv2-ext:retransmission-interval", "method": "DELETE"})
            if "transmit_delay" in vlink_c:
                requests.append({"path": vlink_uri + "/config/openconfig-ospfv2-ext:transmit-delay", "method": "DELETE"})
            if "authentication" in vlink_c:
                if "auth_type" in vlink_c["authentication"] or len(vlink_c["authentication"]) == 0:
                    requests.append({"path": vlink_uri + "/config/openconfig-ospfv2-ext:authentication-type", "method": "DELETE"})
                if "key" in vlink_c["authentication"] or len(vlink_c["authentication"]) == 0:
                    requests.append({"path": vlink_uri + "/config/openconfig-ospfv2-ext:authentication-key", "method": "DELETE"})
                if "key_encrypted" in vlink_c["authentication"] or len(vlink_c["authentication"]) == 0:
                    requests.append({"path": vlink_uri + "/config/openconfig-ospfv2-ext:authentication-key-encrypted", "method": "DELETE"})
        if len(commands) == len(have) and not partial_deletes:
            return True, [{"path": request_root + "/virtual-links/virtual-link", "method": "DELETE"}], True if len(commands) < 2 else False
        return False, requests, False

    def build_area_md_auth_delete_requests(self, request_root, commands, have):
        '''builds the requests to delete message digest keys for a single area's virtual link config.
        takes a pair of an area's virtual link's message digest commands and have
        returns a tuple of whether everything in message digest keys was deleted and requests to cause changes'''
        requests = []
        if len(have) == 0:
            # nothing in message digest keys to delete
            return True, []
        elif len(commands) == len(have) or len(commands) == 0:
            # commands should only contain keys that are in have
            # deleted everything in have, just return one command to delete root
            return True, [{"path": request_root + "/openconfig-ospfv2-ext:md-authentications/md-authentication", "method": "DELETE"}]
        for md_c in commands:
            # For md key deletion, only the specified key_id is used. If a key value
            # and/or encrypted state are specified in the user playbook, they are
            # ignored. These attributes are deleted from the configuration for the
            # specified key_id solely based on the key_id value specified.
            requests.append({"path": request_root + "/openconfig-ospfv2-ext:md-authentications/md-authentication=" + str(md_c["key_id"]), "method": "DELETE"})
        return False, requests

    def build_area_delete_propagation_requests(self, commands, have, ranges_all_gone, ranges_delete_requests):
        '''builds the requests to delete a single area's propagation config. takes a single area commands and have.
        This has a weird edge case.
        Ranges are a part of inter-area-policy, but deleting on the specific inter-area-policy for this area in the REST API will not delete ranges as well.
        Deleting area depends on deleting all of the ranges, so that is collected and handled in area.
        So this section won't be handling ranges but also needs to know if ranges are cleared to check if ok to delete the whole policy.
        returns a tuple of if all propagation settings were deleted and requests to cause changes'''
        requests = []
        request_root = self.ospf_propagation_uri.format(vrf=commands["vrf_name"], area_id=commands["area_id"])
        area_deleted = False

        # doing filter list removes if necessary
        if "filter_list_in" in commands:
            requests.append({"path": request_root + "/filter-list-in", "method": "DELETE"})
        if "filter_list_out" in commands:
            requests.append({"path": request_root + "/filter-list-out", "method": "DELETE"})

        relevant_have = {"filter_list_in": have.get("filter_list_in", None), "filter_list_out": have.get("filter_list_out", None),
                         "ranges": have.get("ranges", None)}
        relevant_commands = {"filter_list_in": commands.get("filter_list_in", None),
                             "filter_list_out": commands.get("filter_list_out", None), "ranges": commands.get("ranges", None)}
        relevant_have = remove_empties(relevant_have)
        relevant_commands = remove_empties(relevant_commands)

        if len(relevant_commands) != len(relevant_have) or not ranges_all_gone:
            # didn't call to clear everything
            return requests, area_deleted

        if len(relevant_commands) > 0 and relevant_have.keys() != {"ranges"}:
            # deleting everything case, and actually have deleted things
            # if just ranges are deleted then don't try to delete on root, deleting ranges will do that
            delete_all_list = [{"path": request_root, "method": "DELETE"}]
            return delete_all_list, True
        # nothing for propagation - that isn't ranges settings - deleted
        return [], area_deleted

    def build_area_delete_ranges_requests(self, request_root, commands, have):
        '''builds list of requests to delete one area's settings for ranges. takes one area's commands and have list of ranges.
        Commands has to be a subset of have.
        returns a tuple of whether everything in ranges was deleted and requests to cause changes'''
        if commands is None:
            return len(have) == 0, []
        requests = []
        partial_deletes = False
        if len(have) == 0:
            # nothing in ranges to delete
            return True, []
        if len(commands) == 0:
            return True, [{"path": request_root + "/ranges/range", "method": "DELETE"}]
        range_h_keys = {range["prefix"]: range for range in have}
        for range_c in commands:
            matched_range = range_h_keys[range_c["prefix"]]
            if not matched_range:
                # should not hit as commands must be a subset of have
                continue

            range_string = range_c["prefix"].replace("/", "%2F")
            if len(range_c) == 1 or len(range_c) == len(matched_range):
                # only the range prefix specified or same number of fields specified means delete the whoe range
                requests.append({"path": request_root + "/ranges/range=" + range_string, "method": "DELETE"})
                continue

            partial_deletes = True
            if "cost" in range_c:
                requests.append({"path": request_root + "/ranges/range=" + range_string + "/config/metric", "method": "DELETE"})
            if "substitute" in range_c:
                # it actually is mispelled as substitue in REST
                requests.append({"path": request_root + "/ranges/range=" + range_string + "/config/substitue-prefix",
                                 "method": "DELETE"})
            # advertise cannot be deleted so set to default true
            if range_c.get("advertise") is False:
                requests.append({"path": request_root + "/ranges/range=" + range_string + "/config/advertise", "method": "PATCH",
                                 "data": {"openconfig-ospfv2-ext:advertise": True}})
        if len(commands) == len(have) and not partial_deletes:
            # deleting all ranges
            return True, [{"path": request_root + "/ranges/range", "method": "DELETE"}]
        return False, requests

    def remove_default_entries(self, data):
        if data:
            area_pop_list = []
            for area in data:
                if area.get("ranges"):
                    range_pop_list = []
                    for range_c in area["ranges"]:
                        if range_c.get("advertise"):
                            range_c.pop("advertise")
                            if len(range_c) == 1:
                                range_idx = area["ranges"].index(range_c)
                                range_pop_list.insert(0, range_idx)
                    for range_idx in range_pop_list:
                        area["ranges"].pop(range_idx)

                    if not area["ranges"]:
                        area.pop("ranges")
                        if len(area) == 2:
                            area_idx = data.index(area)
                            area_pop_list.insert(0, area_idx)

            for area_idx in area_pop_list:
                data.pop(area_idx)
