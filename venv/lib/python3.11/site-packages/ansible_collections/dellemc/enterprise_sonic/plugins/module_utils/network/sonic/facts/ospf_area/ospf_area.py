#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic ospf_area fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy

from ansible.module_utils.connection import ConnectionError
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    remove_empties,
    validate_config,
    generate_dict
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic \
    import to_request, edit_config

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.bgp_utils import (
    get_all_vrfs
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ospf_area.ospf_area import Ospf_areaArgs


class Ospf_areaFacts(object):
    """ The sonic ospf_area fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Ospf_areaArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = generate_dict(facts_argument_spec)

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for ospf_area
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """

        if not data:
            data = self.get_ospf_info()

        data = self.render_config(data)
        data = {"config": data}
        # validate can add empties to config where values do not really exist
        cleaned_data = remove_empties(
            validate_config(self.argument_spec, data)
        )
        if "state" in cleaned_data:
            del cleaned_data["state"]
        if "config" not in cleaned_data:
            cleaned_data["config"] = []

        ansible_facts['ansible_network_resources'].pop('ospf_area', None)
        if cleaned_data:
            ansible_facts['ansible_network_resources'].update({"ospf_area": cleaned_data})

        return ansible_facts

    def render_config(self, data):
        '''Takes REST "GET" data fetched from device and returns a copy that is formatted like argspec.
           The input is assumed to be a dict with vrf names as keys. The 'values' for each VRF contain
           JSON data for the areas of that vrf.
            :rtype: dictionary
            :returns: dictionary that has options in same format as defined in argspec.
            Note returned dict also has the config key in shown argspec, but not the state key'''
        formatted_data = {}
        ospf_key_ext = "openconfig-ospfv2-ext:"
        for vrf, ospf_settings in data.items():
            # go through each area for this vrf
            for area in ospf_settings.get("areas", {}).get("area", []):
                if "identifier" not in area:
                    # these are indentifying keys, area is invalid if doesn't have it
                    self._module.fail_json(msg="area for vrf {vrf} retrieved from device is missing identifier".format(vrf=vrf))
                formatted_area = {}
                # only try grabbing settings in the JSON subsections if the sections exist
                if "config" in area:
                    # authentication type should only have these two values
                    if area["config"].get(ospf_key_ext + "authentication-type") == "MD5HMAC":
                        formatted_area["authentication_type"] = "message_digest"
                    elif area["config"].get(ospf_key_ext + "authentication-type") == "TEXT":
                        formatted_area["authentication_type"] = "text"
                    # doing if check on shortcut since it can be just lowecased if it is inside,
                    # a none return will cause issues
                    if ospf_key_ext + "shortcut" in area["config"]:
                        formatted_area["shortcut"] = area["config"][ospf_key_ext + "shortcut"].replace("openconfig-ospfv2-ext:", "").lower()

                if ospf_key_ext + "stub" in area and "config" in area[ospf_key_ext + "stub"]:
                    # If a value is currently configured for the stub 'default-cost' attribute,
                    # store it in the output 'facts' as the 'default_cost' for the area.
                    # Note: If OSPF NSSA is implemented for SONIC in the future with
                    # a different configurable "default cost" value, edits will need to be made.
                    formatted_area["default_cost"] = area[ospf_key_ext + "stub"]["config"].get("default-cost")
                    # other settings are under stub subsection
                    formatted_area["stub"] = {}
                    formatted_area["stub"]["enabled"] = area[ospf_key_ext + "stub"]["config"].get("enable")
                    formatted_area["stub"]["no_summary"] = area[ospf_key_ext + "stub"]["config"].get("no-summary")
                if "virtual-links" in area and area["virtual-links"].get("virtual-link"):
                    formatted_area["virtual_links"] = []
                    for vlink_settings in area["virtual-links"]["virtual-link"]:
                        formatted_virtual_link = {}
                        if "remote-router-id" not in vlink_settings:
                            self._module.fail_json(msg="virtual link in area {area}".format(area=area["area_id"]) +
                                                   " for vrf {vrf} retrieved from device is missing remote-router-id identifier".format(vrf=vrf))
                        formatted_virtual_link["router_id"] = vlink_settings.get('remote-router-id')

                        if "config" in vlink_settings:
                            formatted_virtual_link["enabled"] = vlink_settings["config"].get(ospf_key_ext + "enable")
                            formatted_virtual_link["dead_interval"] = vlink_settings["config"].get(ospf_key_ext + "dead-interval")
                            formatted_virtual_link["hello_interval"] = vlink_settings["config"].get(ospf_key_ext + "hello-interval")
                            formatted_virtual_link["retransmit_interval"] = vlink_settings["config"].get(ospf_key_ext + "retransmission-interval")
                            formatted_virtual_link["transmit_delay"] = vlink_settings["config"].get(ospf_key_ext + "transmit-delay")

                            formatted_vlink_auth = {}
                            if vlink_settings["config"].get(ospf_key_ext + "authentication-type") == "MD5HMAC":
                                formatted_vlink_auth["auth_type"] = "message_digest"
                            elif vlink_settings["config"].get(ospf_key_ext + "authentication-type") == "TEXT":
                                formatted_vlink_auth["auth_type"] = "text"
                            # if auth type is none, don't need to display
                            formatted_vlink_auth["key"] = vlink_settings["config"].get(ospf_key_ext + "authentication-key")
                            if formatted_vlink_auth["key"]:
                                # for some reason this stays around
                                formatted_vlink_auth["key_encrypted"] = vlink_settings["config"].get(ospf_key_ext + "authentication-key-encrypted")
                            if formatted_vlink_auth:
                                formatted_virtual_link["authentication"] = formatted_vlink_auth

                        if ospf_key_ext + "md-authentications" in vlink_settings and \
                                vlink_settings[ospf_key_ext + "md-authentications"].get("md-authentication"):
                            formatted_virtual_link["message_digest_list"] = []
                            for md5_settings in vlink_settings[ospf_key_ext + "md-authentications"]["md-authentication"]:
                                formatted_md5 = {}
                                if "authentication-key-id" not in md5_settings:
                                    self._module.fail_json(msg="md authentication key in virtual link" +
                                                           " {link} in area {area} for".format(link=vlink_settings["remote-router-id"], area=area["area_id"]) +
                                                           " vrf {vrf} retrieved from device is missing authentication-key-id identifier".format(vrf=vrf))
                                formatted_md5["key_id"] = md5_settings["authentication-key-id"]
                                if "config" in md5_settings:
                                    formatted_md5["key"] = md5_settings["config"].get("authentication-md5-key")
                                    formatted_md5["key_encrypted"] = md5_settings["config"].get("authentication-key-encrypted")
                                formatted_virtual_link["message_digest_list"].append(formatted_md5)
                        formatted_area["virtual_links"].append(formatted_virtual_link)
                if ospf_key_ext + "networks" in area:
                    formatted_area["networks"] = []
                    for network in area[ospf_key_ext + "networks"].get("network", []):
                        if network.get("address-prefix"):
                            formatted_area["networks"].append(network["address-prefix"])
                if formatted_area:
                    formatted_area["area_id"] = area["identifier"]
                    formatted_area["vrf_name"] = vrf
                    formatted_data[(vrf, formatted_area["area_id"])] = formatted_area

            for inter_area_policy in ospf_settings.get("global", {}).get("inter-area-propagation-policies", {}).get(ospf_key_ext + "inter-area-policy", []):
                # since two separate lists, combining them. doing check of if area found just in case, but area should always be found
                # at this point
                if "src-area" not in inter_area_policy:
                    self._module.fail_json(msg="inter area policy for vrf" +
                                           " {vrf} retrieved from device is missing src-area identifier".format(vrf=vrf))
                if (vrf, inter_area_policy["src-area"]) in formatted_data:
                    formatted_area = formatted_data[(vrf, inter_area_policy["src-area"])]
                else:
                    formatted_area = {}
                if "filter-list-in" in inter_area_policy:
                    formatted_area["filter_list_in"] = inter_area_policy.get("filter-list-in", {}).get("config", {}).get("name")
                if "filter-list-out" in inter_area_policy:
                    formatted_area["filter_list_out"] = inter_area_policy.get("filter-list-out", {}).get("config", {}).get("name")
                if "ranges" in inter_area_policy:
                    formatted_area["ranges"] = []
                    for area_range in inter_area_policy["ranges"].get("range"):
                        if "address-prefix" not in area_range:
                            self._module.fail_json(msg="range in area {area} for vrf {vrf}".format(area=area["area_id"], vrf=vrf) +
                                                   " retrieved from device is missing address-prefix identifier")
                        formatted_range = {}
                        formatted_range["prefix"] = area_range["address-prefix"]
                        if "config" in area_range:
                            formatted_range["advertise"] = area_range["config"].get("advertise")
                            formatted_range["cost"] = area_range["config"].get("metric")
                            # note that substitute is mispelled in openconfig
                            formatted_range["substitute"] = area_range["config"].get("substitue-prefix")
                        formatted_area["ranges"].append(formatted_range)
                if (vrf, inter_area_policy["src-area"]) not in formatted_data and formatted_area:
                    # if these fields aren't inside means somehow missed area in areas list but there's inter-area policies for it.
                    # needed to move adding keys here to prevent reporting area exists all the time including when policies doesn't find any settings
                    formatted_area["area_id"] = inter_area_policy["src-area"]
                    formatted_area["vrf_name"] = vrf
                    formatted_data[(vrf, formatted_area["area_id"])] = formatted_area
        return [remove_empties(area) for area in formatted_data.values()]

    def get_ospf_info(self):
        '''get the top level of ospf data from device
        :rtype: dictionary
        :returns: dictionary of vrf name to their ospf settings
        '''
        ospf_path = 'data/openconfig-network-instance:network-instances/network-instance={vrf}' + \
            '/protocols/protocol=OSPF,ospfv2/ospfv2'
        method = "GET"

        ospf_settings = {}

        vrf_list = get_all_vrfs(self._module)
        for vrf in vrf_list:
            request = {"path": ospf_path.format(vrf=vrf), "method": method}
            try:
                response = edit_config(self._module, to_request(self._module, request))
            except ConnectionError as exc:
                self._module.fail_json(msg=str(exc))
            try:
                response_body = response[0][1].get("openconfig-network-instance:ospfv2", {})
            except Exception as exc:
                self._module.fail_json(msg=str(exc))

            if response_body:
                ospf_settings[vrf] = response_body
        return ospf_settings
