#!/usr/bin/python

# (c) 2020, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: na_santricity_lun_mapping
author:
    - Kevin Hulquest (@hulquest)
    - Nathan Swartz (@ndswartz)
short_description: NetApp E-Series manage lun mappings
description:
     - Create, delete, or modify mappings between a volume and a targeted host/host+ group.
extends_documentation_fragment:
    - netapp_eseries.santricity.santricity.santricity_doc
options:
  state:
    description:
      - Present will ensure the mapping exists, absent will remove the mapping.
    type: str
    required: False
    choices: ["present", "absent"]
    default: "present"
  target:
    description:
      - The name of host or hostgroup you wish to assign to the mapping
      - If omitted, the default hostgroup is used.
      - If the supplied I(volume_name) is associated with a different target, it will be updated to what is supplied here.
    type: str
    required: False
  volume_name:
    description:
      - The name of the volume you wish to include in the mapping.
      - Use ACCESS_VOLUME to reference the in-band access management volume.
    type: str
    required: True
    aliases:
        - volume
  lun:
    description:
      - The LUN value you wish to give the mapping.
      - If the supplied I(volume_name) is associated with a different LUN, it will be updated to what is supplied here.
      - LUN value will be determine by the storage-system when not specified.
    type: int
    required: false
'''

EXAMPLES = '''
---
    - name: Map volume1 to the host target host1
      na_santricity_lun_mapping:
        ssid: "1"
        api_url: "https://192.168.1.100:8443/devmgr/v2"
        api_username: "admin"
        api_password: "adminpass"
        validate_certs: true
        state: present
        target: host1
        volume: volume1
    - name: Delete the lun mapping between volume1 and host1
      na_santricity_lun_mapping:
        ssid: "1"
        api_url: "https://192.168.1.100:8443/devmgr/v2"
        api_username: "admin"
        api_password: "adminpass"
        validate_certs: true
        state: absent
        target: host1
        volume: volume1
'''
RETURN = '''
msg:
    description: success of the module
    returned: always
    type: str
    sample: Lun mapping is complete
'''
from ansible_collections.netapp_eseries.santricity.plugins.module_utils.santricity import NetAppESeriesModule
from ansible.module_utils._text import to_native


class NetAppESeriesLunMapping(NetAppESeriesModule):
    def __init__(self):
        ansible_options = dict(state=dict(required=False, choices=["present", "absent"], default="present"),
                               target=dict(required=False, default=None),
                               volume_name=dict(required=True, aliases=["volume"]),
                               lun=dict(type="int", required=False))

        super(NetAppESeriesLunMapping, self).__init__(ansible_options=ansible_options,
                                                      web_services_version="02.00.0000.0000",
                                                      supports_check_mode=True)

        args = self.module.params
        self.state = args["state"] == "present"
        self.target = args["target"] if args["target"] else "DEFAULT_HOSTGROUP"
        self.volume = args["volume_name"] if args["volume_name"] != "ACCESS_VOLUME" else "Access"
        self.lun = args["lun"]
        self.check_mode = self.module.check_mode
        self.mapping_info = None

        if not self.url.endswith('/'):
            self.url += '/'

    def update_mapping_info(self):
        """Collect the current state of the storage array."""
        response = None
        try:
            rc, response = self.request("storage-systems/%s/graph" % self.ssid)
        except Exception as error:
            self.module.fail_json(msg="Failed to retrieve storage array graph. Id [%s]. Error [%s]" % (self.ssid, to_native(error)))

        # Create dictionary containing host/cluster references mapped to their names
        target_reference = {}
        target_name = {}
        target_type = {}

        for host in response["storagePoolBundle"]["host"]:
            target_reference.update({host["hostRef"]: host["name"]})
            target_name.update({host["name"]: host["hostRef"]})
            target_type.update({host["name"]: "host"})

        for cluster in response["storagePoolBundle"]["cluster"]:

            # Verify there is no ambiguity between target's type (ie host and group have the same name)
            if cluster["name"] == self.target and self.target in target_name.keys():
                self.module.fail_json(msg="Ambiguous target type: target name is used for both host and group targets! Id [%s]" % self.ssid)

            target_reference.update({cluster["clusterRef"]: cluster["name"]})
            target_name.update({cluster["name"]: cluster["clusterRef"]})
            target_type.update({cluster["name"]: "group"})

        target_reference.update({"0000000000000000000000000000000000000000": "DEFAULT_HOSTGROUP"})
        target_name.update({"DEFAULT_HOSTGROUP": "0000000000000000000000000000000000000000"})
        target_type.update({"DEFAULT_HOSTGROUP": "group"})

        volume_reference = {}
        volume_name = {}
        lun_name = {}
        for volume in response["volume"]:
            volume_reference.update({volume["volumeRef"]: volume["name"]})
            volume_name.update({volume["name"]: volume["volumeRef"]})
            if volume["listOfMappings"]:
                lun_name.update({volume["name"]: volume["listOfMappings"][0]["lun"]})
        for volume in response["highLevelVolBundle"]["thinVolume"]:
            volume_reference.update({volume["volumeRef"]: volume["name"]})
            volume_name.update({volume["name"]: volume["volumeRef"]})
            if volume["listOfMappings"]:
                lun_name.update({volume["name"]: volume["listOfMappings"][0]["lun"]})

        volume_name.update({response["sa"]["accessVolume"]["name"]: response["sa"]["accessVolume"]["accessVolumeRef"]})
        volume_reference.update({response["sa"]["accessVolume"]["accessVolumeRef"]: response["sa"]["accessVolume"]["name"]})

        # Build current mapping object
        self.mapping_info = dict(lun_mapping=[dict(volume_reference=mapping["volumeRef"],
                                                   map_reference=mapping["mapRef"],
                                                   lun_mapping_reference=mapping["lunMappingRef"],
                                                   lun=mapping["lun"]
                                                   ) for mapping in response["storagePoolBundle"]["lunMapping"]],
                                 volume_by_reference=volume_reference,
                                 volume_by_name=volume_name,
                                 lun_by_name=lun_name,
                                 target_by_reference=target_reference,
                                 target_by_name=target_name,
                                 target_type_by_name=target_type)

    def get_lun_mapping(self):
        """Find the matching lun mapping reference.

        Returns: tuple(bool, int, int): contains volume match, volume mapping reference and mapping lun
        """
        target_match = False
        reference = None
        lun = None

        self.update_mapping_info()

        # Verify that when a lun is specified that it does not match an existing lun value unless it is associated with
        # the specified volume (ie for an update)
        if self.lun and any((self.lun == lun_mapping["lun"] and
                             self.target == self.mapping_info["target_by_reference"][lun_mapping["map_reference"]] and
                             self.volume != self.mapping_info["volume_by_reference"][lun_mapping["volume_reference"]]
                             ) for lun_mapping in self.mapping_info["lun_mapping"]):
            self.module.fail_json(msg="Option lun value is already in use for target! Array Id [%s]." % self.ssid)

        # Verify volume and target exist if needed for expected state.
        if self.state:
            if self.volume not in self.mapping_info["volume_by_name"].keys():
                self.module.fail_json(msg="Volume does not exist. Id [%s]." % self.ssid)
            if self.target and self.target not in self.mapping_info["target_by_name"].keys():
                self.module.fail_json(msg="Target does not exist. Id [%s'." % self.ssid)

        for lun_mapping in self.mapping_info["lun_mapping"]:

            # Find matching volume reference
            if lun_mapping["volume_reference"] == self.mapping_info["volume_by_name"][self.volume]:
                reference = lun_mapping["lun_mapping_reference"]
                lun = lun_mapping["lun"]

                # Determine if lun mapping is attached to target with the
                if (lun_mapping["map_reference"] in self.mapping_info["target_by_reference"].keys() and
                        self.mapping_info["target_by_reference"][lun_mapping["map_reference"]] == self.target and
                        (self.lun is None or lun == self.lun)):
                    target_match = True

        return target_match, reference, lun

    def update(self):
        """Execute the changes the require changes on the storage array."""
        target_match, lun_reference, lun = self.get_lun_mapping()
        update = (self.state and not target_match) or (not self.state and lun_reference)

        if update and not self.check_mode:
            try:
                if self.state:
                    body = dict()
                    target = None if not self.target else self.mapping_info["target_by_name"][self.target]
                    if target:
                        body.update(dict(targetId=target))
                    if self.lun is not None:
                        body.update(dict(lun=self.lun))

                    if lun_reference:

                        rc, response = self.request("storage-systems/%s/volume-mappings/%s/move" % (self.ssid, lun_reference), method="POST", data=body)
                    else:
                        body.update(dict(mappableObjectId=self.mapping_info["volume_by_name"][self.volume]))
                        rc, response = self.request("storage-systems/%s/volume-mappings" % self.ssid, method="POST", data=body)

                else:   # Remove existing lun mapping for volume and target
                    rc, response = self.request("storage-systems/%s/volume-mappings/%s" % (self.ssid, lun_reference), method="DELETE")
            except Exception as error:
                self.module.fail_json(msg="Failed to update storage array lun mapping. Id [%s]. Error [%s]" % (self.ssid, to_native(error)))

        self.module.exit_json(msg="Lun mapping is complete.", changed=update)


def main():
    mapping = NetAppESeriesLunMapping()
    mapping.update()


if __name__ == "__main__":
    main()
