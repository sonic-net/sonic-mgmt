# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
    name: santricity_volume
    author:
        - Nathan Swartz (@swartzn)
        - Vu Tran (@VuTran007)
    short_description: NetApp E-Series manage storage volumes
    description:
        - Collect volumes from NetApp E/EF-series storage array for defined host.
"""

EXAMPLES = r"""
- name: Collect volume information for defined host
  ansible.builtin.set_fact:
    volumes: "{{ lookup('netapp_eseries.santricity.santricity_volume', hostvars[inventory_hostname])) }}"
"""

import re
from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
from itertools import product


class LookupModule(LookupBase):

    def run(self, inventory, **kwargs):
        if isinstance(inventory, list):
            inventory = inventory[0]

        if ("eseries_storage_pool_configuration" not in inventory.keys() or not isinstance(inventory["eseries_storage_pool_configuration"], list) or
                len(inventory["eseries_storage_pool_configuration"]) == 0):
            return list()

        vol_list = list()
        for sp_info in inventory["eseries_storage_pool_configuration"]:
            if "name" not in sp_info.keys():
                continue
            if "volumes" in sp_info.keys() and ("criteria_volume_count" in sp_info.keys() or "criteria_reserve_free_capacity_pct" in sp_info.keys()):
                raise AnsibleError("Incompatible parameters: You cannot specify both volumes with either criteria_volume_count or "
                                   "criteria_reserve_free_capacity for any given eseries_storage_pool_configuration entry.")
            if ("common_volume_configuration" in sp_info.keys() and isinstance(sp_info["common_volume_configuration"], dict) and
                    "size" in sp_info["common_volume_configuration"].keys() and "criteria_reserve_free_capacity_pct" in sp_info.keys()):
                raise AnsibleError("Incompatible parameters: You cannot specify both size in common_volume_configuration with "
                                   "criteria_reserve_free_capacity for any given eseries_storage_pool_configuration entry.")

            if "volumes" not in sp_info.keys():
                if "criteria_volume_count" in sp_info.keys():
                    if "common_volume_configuration" not in sp_info:
                        sp_info.update({"common_volume_configuration": {}})

                    reserve_free_capacity_pct = sp_info["criteria_reserve_free_capacity_pct"] if "criteria_reserve_free_capacity_pct" in sp_info.keys() else 0.0
                    volume_size = (100.0 - reserve_free_capacity_pct) / sp_info["criteria_volume_count"]
                    count_digits = len(str(sp_info["criteria_volume_count"]))

                    if "size" not in sp_info["common_volume_configuration"].keys():
                        sp_info["common_volume_configuration"].update({"size": volume_size, "size_unit": "pct"})
                    if "host" not in sp_info["common_volume_configuration"].keys() and "common_volume_host" in sp_info.keys():
                        sp_info["common_volume_configuration"].update({"host": sp_info["common_volume_host"]})

                    if (("eseries_remove_all_configuration_state" in inventory and inventory["eseries_remove_all_configuration_state"] == "absent") or
                            ("state" in sp_info and sp_info["state"] == "absent") or
                            ("state" not in sp_info and "eseries_volume_state" in inventory and inventory["eseries_volume_state"] == "absent")):
                        sp_info["common_volume_configuration"].update({"state": "absent"})
                    else:
                        sp_info["common_volume_configuration"].update({"state": "present"})

                    for count in range(sp_info["criteria_volume_count"]):
                        if "volumes" not in sp_info.keys():
                            sp_info.update({"volumes": []})
                        sp_info["volumes"].append({"name": "[pool]_%0*d" % (count_digits, count)})
                else:
                    continue

            elif not isinstance(sp_info["volumes"], list):
                raise AnsibleError("Volumes must be a list")

            for sp in patternize(sp_info["name"], inventory):
                for vol_info in sp_info["volumes"]:

                    if not isinstance(vol_info, dict):
                        raise AnsibleError("Volume in the storage pool, %s, must be a dictionary." % sp_info["name"])

                    for vol in patternize(vol_info["name"], inventory, storage_pool=sp):
                        vol_options = dict()

                        # Add common_volume_configuration information
                        combined_volume_metadata = {}
                        if "common_volume_configuration" in sp_info:
                            for option, value in sp_info["common_volume_configuration"].items():
                                vol_options.update({option: value})
                            if "volume_metadata" in sp_info["common_volume_configuration"].keys():
                                combined_volume_metadata.update(sp_info["common_volume_configuration"]["volume_metadata"])

                        # Add/update volume specific information
                        for option, value in vol_info.items():
                            vol_options.update({option: value})
                        if "volume_metadata" in vol_info.keys():
                            combined_volume_metadata.update(vol_info["volume_metadata"])
                            vol_options.update({"volume_metadata": combined_volume_metadata})

                        if (("eseries_remove_all_configuration_state" in inventory and inventory["eseries_remove_all_configuration_state"] == "absent") or
                                ("state" in sp_info and sp_info["state"] == "absent") or
                                ("state" not in sp_info and "eseries_volume_state" in inventory and inventory["eseries_volume_state"] == "absent")):
                            vol_options.update({"state": "absent"})
                        else:
                            vol_options.update({"state": "present"})

                        vol_options.update({"name": vol, "storage_pool_name": sp})
                        vol_list.append(vol_options)
        return vol_list


def patternize(pattern, inventory, storage_pool=None):
    """Generate list of strings determined by a pattern"""
    if storage_pool:
        pattern = pattern.replace("[pool]", storage_pool)

    if inventory:
        inventory_tokens = re.findall(r"\[[a-zA-Z0-9_]*\]", pattern)
        for token in inventory_tokens:
            pattern = pattern.replace(token, str(inventory[token[1:-1]]))

    tokens = re.findall(r"\[[0-9]-[0-9]\]|\[[a-z]-[a-z]\]|\[[A-Z]-[A-Z]\]", pattern)
    segments = "%s".join(re.split(r"\[[0-9]-[0-9]\]|\[[a-z]-[a-z]\]|\[[A-Z]-[A-Z]\]", pattern))

    if len(tokens) == 0:
        return [pattern]

    combinations = []
    for token in tokens:
        start, stop = token[1:-1].split("-")

        try:
            start = int(start)
            stop = int(stop)
            combinations.append([str(number) for number in range(start, stop + 1)])
        except ValueError:
            combinations.append([chr(number) for number in range(ord(start), ord(stop) + 1)])

    return [segments % subset for subset in list(product(*combinations))]
