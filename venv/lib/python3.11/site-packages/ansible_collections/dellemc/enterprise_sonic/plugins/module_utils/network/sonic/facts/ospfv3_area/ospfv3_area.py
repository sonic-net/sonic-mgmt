from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy

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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ospfv3_area.ospfv3_area import Ospfv3_areaArgs

from ansible.module_utils.connection import ConnectionError


class Ospfv3_areaFacts(object):
    """ The sonic ospfv3_area fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Ospfv3_areaArgs.argument_spec
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
        """ Populate the facts for ospfv3_area
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """

        if not data:
            data = self.get_ospfv3_area_info()

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

        ansible_facts['ansible_network_resources'].pop('ospfv3_area', None)
        if cleaned_data:
            ansible_facts['ansible_network_resources'].update({"ospfv3_area": cleaned_data})

        return ansible_facts

    def render_config(self, data):
        '''Takes REST "GET" data fetched from device and returns a copy that is formatted like argspec.
           The input is assumed to be a dict with vrf names as keys. The 'values' for each VRF contain
           JSON data for the areas of that vrf.
            :rtype: dictionary
            :returns: dictionary that has options in same format as defined in argspec.
            Note returned dict also has the config key in shown argspec, but not the state key'''
        formatted_data = {}
        ospf_key_ext = "openconfig-ospfv3-ext:"
        for vrf, ospf_settings in data.items():
            # Go through each area for this VRF
            for area in ospf_settings.get("areas", {}).get("area", []):
                if "identifier" not in area:
                    # These are identifying keys, area is invalid if it doesn't have it
                    self._module.fail_json(
                        msg=f"Area for VRF {vrf} retrieved from device is missing identifier"
                    )

                formatted_area = {
                    "area_id": area["identifier"],
                    "vrf_name": vrf
                }

                # Handle stub
                if ospf_key_ext + "stub" in area and "config" in area[ospf_key_ext + "stub"]:
                    formatted_area["stub"] = {
                        "enabled": area[ospf_key_ext + "stub"]["config"].get("enable"),
                        "no_summary": area[ospf_key_ext + "stub"]["config"].get("no-summary")
                    }

                # Handle nssa
                if ospf_key_ext + "nssa" in area and "config" in area[ospf_key_ext + "nssa"]:
                    nssa_config = area[ospf_key_ext + "nssa"]["config"]
                    formatted_area["nssa"] = {
                        "enabled": nssa_config.get("enable"),
                        "no_summary": nssa_config.get("no-summary"),
                        "default_originate": {
                            "enabled": nssa_config.get("default-route-originate"),
                            "metric": nssa_config.get("default-route-metric"),
                            "metric_type": nssa_config.get("default-route-metric-type")
                        },
                        "ranges": []
                    }

                    # Only process default_originate if enabled
                    if formatted_area["nssa"]["default_originate"]["enabled"] is not None:
                        formatted_area["nssa"].pop("no_summary")
                        if formatted_area["nssa"]["default_originate"]["metric_type"] is not None:
                            formatted_area["nssa"]["default_originate"]["metric_type"] = int(
                                formatted_area["nssa"]["default_originate"]["metric_type"].split("TYPE_")[1]
                            )

                    # Only process no_summary if enabled
                    if formatted_area["nssa"].get("no_summary") is not None:
                        formatted_area["nssa"].pop("default_originate")

                    # Process ranges inside nssa
                    for range_entry in area[ospf_key_ext + "nssa"].get("ranges", {}).get("range", []):
                        if "address-prefix" not in range_entry:
                            message = f"Range in area {area.get('identifier', 'unknown')} for VRF {vrf} retrieved is missing address-prefix identifier"
                            self._module.fail_json(
                                msg=message
                            )
                        formatted_range = {
                            "prefix": range_entry["address-prefix"]
                        }

                        formatted_range["advertise"] = range_entry["config"].get("advertise")
                        formatted_range["cost"] = range_entry["config"].get("cost")

                        formatted_area["nssa"]["ranges"].append(formatted_range)

                # Add to formatted data
                formatted_data[(vrf, formatted_area["area_id"])] = formatted_area

            for inter_area_policy in ospf_settings.get("global", {}).get(ospf_key_ext + "inter-area-propagation-policies", {}).get("inter-area-policy", []):
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
                        formatted_area["ranges"].append(formatted_range)
                if (vrf, inter_area_policy["src-area"]) not in formatted_data and formatted_area:
                    # if these fields aren't inside means somehow missed area in areas list but there's inter-area policies for it.
                    # needed to move adding keys here to prevent reporting area exists all the time including when policies doesn't find any settings
                    formatted_area["area_id"] = inter_area_policy["src-area"]
                    formatted_area["vrf_name"] = vrf
                    formatted_data[(vrf, formatted_area["area_id"])] = formatted_area
        return [remove_empties(area) for area in formatted_data.values()]

    def get_ospfv3_area_info(self):
        '''get the top level of ospfv3_area data from device
        :rtype: dictionary
        :returns: dictionary of vrf name to their ospf settings
        '''
        ospf_path = '/data/openconfig-network-instance:network-instances/network-instance={vrf}' + \
            '/protocols/protocol=OSPF3,ospfv3/ospfv3'
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
                response_body = response[0][1].get("openconfig-network-instance:ospfv3", {})
            except Exception as exc:
                self._module.fail_json(msg=str(exc))

            if response_body:
                ospf_settings[vrf] = response_body
        return ospf_settings
