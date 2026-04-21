# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
    name: santricity_host
    author:
        - Nathan Swartz (@swartzn)
        - Vu Tran (@VuTran007)
    short_description: Collects host information
    description:
        - Collects current host, expected host and host group inventory definitions.
    options:
        inventory:
            description:
                - E-Series storage array inventory, hostvars[inventory_hostname].
                - Run na_santricity_facts prior to calling
            required: True
            type: raw
        volumes:
            description:
                - Volume information returned from santricity_volume lookup plugin which expands
            type: raw
"""
from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase


class LookupModule(LookupBase):

    # pylint: disable=arguments-renamed
    def run(self, inventory, volumes, **kwargs):
        if isinstance(inventory, list):
            inventory = inventory[0]

        if not isinstance(volumes, list):
            volumes = [volumes]

        if ("eseries_storage_pool_configuration" not in inventory or not isinstance(inventory["eseries_storage_pool_configuration"], list) or
                len(inventory["eseries_storage_pool_configuration"]) == 0):
            return list()

        if "eseries_storage_pool_configuration" not in inventory.keys():
            raise AnsibleError("eseries_storage_pool_configuration must be defined. See nar_santricity_host role documentation.")

        info = {"current_hosts": {}, "expected_hosts": {}, "host_groups": {}}

        groups = []
        hosts = []
        non_inventory_hosts = []
        non_inventory_groups = []
        for group in inventory["groups"].keys():
            groups.append(group)
            hosts.extend(inventory["groups"][group])

        if "eseries_host_object" in inventory.keys():
            non_inventory_hosts = [host["name"] for host in inventory["eseries_host_object"]]
            non_inventory_groups = [host["group"] for host in inventory["eseries_host_object"] if "group" in host]

        for volume in volumes:
            if volume["state"] == "present" and "host" in volume.keys():

                if volume["host"] in groups:
                    # Add all expected group hosts
                    for expected_host in inventory["groups"][volume["host"]]:
                        if "host_type" in volume:
                            info["expected_hosts"].update({expected_host: {"state": "present",
                                                                           "host_type": volume["host_type"],
                                                                           "group": volume["host"]}})
                        else:
                            info["expected_hosts"].update({expected_host: {"state": "present",
                                                                           "group": volume["host"]}})

                    info["host_groups"].update({volume["host"]: inventory["groups"][volume["host"]]})

                elif volume["host"] in hosts:
                    if "host_type" in volume:
                        info["expected_hosts"].update({volume["host"]: {"state": "present",
                                                                        "host_type": volume["host_type"],
                                                                        "group": None}})
                    else:
                        info["expected_hosts"].update({volume["host"]: {"state": "present",
                                                                        "group": None}})
                elif volume["host"] not in non_inventory_hosts and volume["host"] not in non_inventory_groups:
                    raise AnsibleError("Expected host or host group does not exist in your Ansible inventory and is not specified in"
                                       " eseries_host_object variable! [%s]." % volume["host"])

        return [info]
