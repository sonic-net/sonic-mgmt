# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
    name: santricity_storage_pool
    author:
        - Nathan Swartz (@swartzn)
        - Vu Tran (@VuTran007)
    short_description: Storage pool information
    description:
        - Retrieves storage pool information from the inventory
    options:
        state:
            description:
                - Define the state of storage pool.
            choices:
                - absent
                - present
            type: str
"""

EXAMPLES = r"""
- name: set facts for storage pool to be absent
  ansible.builtin.set_fact:
    absent_storage_pool: "{{ lookup('netapp_eseries.santricity.santricity_storage_pool', hostvars[inventory_hostname], state='absent') }}"
"""

import re
from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
from itertools import product


class LookupModule(LookupBase):

    # pylint: disable=arguments-renamed
    def run(self, inventory, state, **kwargs):
        if isinstance(inventory, list):
            inventory = inventory[0]

        if ("eseries_storage_pool_configuration" not in inventory or not isinstance(inventory["eseries_storage_pool_configuration"], list) or
                len(inventory["eseries_storage_pool_configuration"]) == 0):
            return list()

        sp_list = list()
        for sp_info in inventory["eseries_storage_pool_configuration"]:

            if not isinstance(sp_info, dict) or "name" not in sp_info:
                raise AnsibleError("eseries_storage_pool_configuration must contain a list of dictionaries containing the necessary information.")

            for sp in patternize(sp_info["name"], inventory):
                if (("eseries_remove_all_configuration_state" in inventory and inventory["eseries_remove_all_configuration_state"] == "absent") or
                        ("state" in sp_info and sp_info["state"] == "absent") or
                        ("state" not in sp_info and "eseries_storage_pool_state" in inventory and inventory["eseries_storage_pool_state"] == "absent")):
                    sp_options = {"state": "absent"}
                else:
                    sp_options = {"state": "present"}

                for option in sp_info.keys():
                    sp_options.update({option: sp_info[option]})

                sp_options.update({"name": sp})

                if sp_options["state"] == state:
                    sp_list.append(sp_options)

        return sp_list


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
