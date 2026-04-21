# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
    name: santricity_lun_mapping
    author:
        - Nathan Swartz (@swartzn)
        - Vu Tran (@VuTran007)
    short_description: NetApp E-Series manage lun mappings
    description:
        - Create, delete, or modify mappings between a volume and a targeted host/host+ group.
    options:
        array_facts:
            description:
                - E-Series storage array facts
                - Run na_santricity_facts prior to calling
            required: True
            type: raw
        volumes:
            description:
                - Volume information returned from santricity_volume lookup plugin which expands
            type: raw
"""

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError


class LookupModule(LookupBase):

    # pylint: disable=arguments-renamed
    def run(self, array_facts, volumes, **kwargs):
        if isinstance(array_facts, list):
            array_facts = array_facts[0]

        if isinstance(volumes, dict):   # This means that there is only one volume and volumes was stripped of its list
            volumes = [volumes]

        if "storage_array_facts" not in array_facts.keys():
            # Don't throw exceptions unless you want run to terminate!!!
            # raise AnsibleError("Storage array information not available. Collect facts using na_santricity_facts module.")
            return list()

        # Remove any absent volumes
        volumes = [vol for vol in volumes if "state" not in vol or vol["state"] == "present"]

        self.array_facts = array_facts["storage_array_facts"]
        self.luns_by_target = self.array_facts["netapp_luns_by_target"]
        self.access_volume_lun = self.array_facts["netapp_default_hostgroup_access_volume_lun"]

        # Search for volumes that have a specified host or host group initiator
        mapping_info = list()
        for volume in volumes:
            if "host" in volume.keys():

                # host initiator is already mapped on the storage system
                if volume["host"] in self.luns_by_target:

                    used_luns = [lun for name, lun in self.luns_by_target[volume["host"]]]
                    for host_group in self.array_facts["netapp_host_groups"]:
                        if volume["host"] == host_group["name"]:    # target is an existing host group
                            for host in host_group["hosts"]:
                                used_luns.extend([lun for name, lun in self.luns_by_target[host]])
                            break
                        elif volume["host"] in host_group["hosts"]:     # target is an existing host in the host group.
                            used_luns.extend([lun for name, lun in self.luns_by_target[host_group["name"]]])
                            break

                    for name, lun in self.luns_by_target[volume["host"]]:

                        # Check whether volume is mapped to the expected host
                        if name == volume["name"]:
                            # Check whether lun option differs from existing lun
                            if "lun" in volume and volume["lun"] != lun:
                                self.change_volume_mapping_lun(volume["name"], volume["host"], volume["lun"])
                                lun = volume["lun"]

                                if lun in used_luns:
                                    raise AnsibleError("Volume [%s] cannot be mapped to host or host group [%s] using lun number %s!"
                                                       % (name, volume["host"], lun))

                            mapping_info.append({"volume": volume["name"], "target": volume["host"], "lun": lun})
                            break

                    # Volume has not been mapped to host initiator
                    else:

                        # Check whether lun option has been used
                        if "lun" in volume:
                            if volume["lun"] in used_luns:
                                for target in self.array_facts["netapp_luns_by_target"].keys():
                                    for mapped_volume, mapped_lun in [entry for entry in self.array_facts["netapp_luns_by_target"][target] if entry]:
                                        if volume["lun"] == mapped_lun:
                                            if volume["name"] != mapped_volume:
                                                raise AnsibleError("Volume [%s] cannot be mapped to host or host group [%s] using lun number %s!"
                                                                   % (volume["name"], volume["host"], volume["lun"]))
                                            else:   # volume is being remapped with the same lun number
                                                self.remove_volume_mapping(mapped_volume, target)
                            lun = volume["lun"]
                        else:
                            lun = self.next_available_lun(used_luns)

                        mapping_info.append({"volume": volume["name"], "target": volume["host"], "lun": lun})
                        self.add_volume_mapping(volume["name"], volume["host"], lun)

                else:
                    raise AnsibleError("The host or host group [%s] is not defined!" % volume["host"])
            else:
                mapping_info.append({"volume": volume["name"]})

        return mapping_info

    def next_available_lun(self, used_luns):
        """Find next available lun numbers."""
        if self.access_volume_lun is not None:
            used_luns.append(self.access_volume_lun)

        lun = 1
        while lun in used_luns:
            lun += 1

        return lun

    def add_volume_mapping(self, name, host, lun):
        """Add volume mapping to record table (luns_by_target)."""
        # Find associated group and the groups hosts
        for host_group in self.array_facts["netapp_host_groups"]:

            if host == host_group["name"]:
                # add to group
                self.luns_by_target[host].append([name, lun])

                # add to hosts
                for hostgroup_host in host_group["hosts"]:
                    self.luns_by_target[hostgroup_host].append([name, lun])

                break
        else:
            self.luns_by_target[host].append([name, lun])

    def remove_volume_mapping(self, name, host):
        """remove volume mapping to record table (luns_by_target)."""
        # Find associated group and the groups hosts
        for host_group in self.array_facts["netapp_host_groups"]:
            if host == host_group["name"]:
                # add to group
                for entry in self.luns_by_target[host_group["name"]]:
                    if entry[0] == name:
                        del entry
                # add to hosts
                for hostgroup_host in host_group["hosts"]:
                    for entry in self.luns_by_target[hostgroup_host]:
                        if entry[0] == name:
                            del entry
                break
        else:
            for index, entry in enumerate(self.luns_by_target[host]):
                if entry[0] == name:
                    self.luns_by_target[host].pop(index)

    def change_volume_mapping_lun(self, name, host, lun):
        """remove volume mapping to record table (luns_by_target)."""
        self.remove_volume_mapping(name, host)
        self.add_volume_mapping(name, host, lun)
