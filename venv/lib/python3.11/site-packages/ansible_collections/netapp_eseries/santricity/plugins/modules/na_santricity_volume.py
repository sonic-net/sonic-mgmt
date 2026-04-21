#!/usr/bin/python

# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: na_santricity_volume
short_description: NetApp E-Series manage storage volumes (standard and thin)
description:
    - Create or remove volumes (standard and thin) for NetApp E/EF-series storage arrays.
author:
    - Nathan Swartz (@swartzn)
    - Vu Tran (@VuTran007)
extends_documentation_fragment:
    - netapp_eseries.santricity.santricity.santricity_doc
options:
    state:
        description:
            - Whether the specified volume should exist
        type: str
        choices: ["present", "absent"]
        default: "present"
    name:
        description:
            - The name of the volume to manage.
        type: str
        required: true
    storage_pool_name:
        description:
            - Required only when requested I(state=="present").
            - Name of the storage pool wherein the volume should reside.
        type: str
        required: false
    size_unit:
        description:
            - The unit used to interpret the size parameter
            - pct unit defines a percent of total usable storage pool size.
        type: str
        choices: ["bytes", "b", "kb", "mb", "gb", "tb", "pb", "eb", "zb", "yb", "pct"]
        default: "gb"
    size:
        description:
            - Required only when I(state=="present").
            - Size of the volume in I(size_unit).
            - Size of the virtual volume in the case of a thin volume in I(size_unit).
            - Maximum virtual volume size of a thin provisioned volume is 256tb; however other OS-level restrictions may exist.
        type: float
        required: true
    size_tolerance_b:
        description:
            - Tolerance for total volume size measured in bytes; so, if the total volumes size is within
              +/- I(size_tolerance_b) then no resizing will be expected.
            - This parameter can be useful in the case of existing volumes not created by na_santricity_volume
              since providing the exact size can be difficult due to volume alignment and overhead.
        type: int
        required: false
        default: 10485760
    segment_size_kb:
        description:
            - Segment size of the volume
            - All values are in kibibytes.
            - Some common choices include 8, 16, 32, 64, 128, 256, and 512 but options are system
              dependent.
            - Retrieve the definitive system list from M(netapp_eseries.santricity.na_santricity_facts)
              under segment_sizes.
            - When the storage pool is a raidDiskPool then the segment size must be 128kb.
            - Segment size migrations are not allowed in this module
        type: int
        default: 128
    thin_provision:
        description:
            - Whether the volume should be thin provisioned.
            - Thin volumes can only be created when I(raid_level=="raidDiskPool").
            - Generally, use of thin-provisioning is not recommended due to performance impacts.
        type: bool
        default: false
        required: false
    thin_volume_repo_size:
        description:
            - This value (in size_unit) sets the allocated space for the thin provisioned repository.
            - Initial value must between or equal to 4gb and 256gb in increments of 4gb.
            - During expansion operations the increase must be between or equal to 4gb and 256gb in increments of 4gb.
            - This option has no effect during expansion if I(thin_volume_expansion_policy=="automatic").
            - Generally speaking you should almost always use I(thin_volume_expansion_policy=="automatic).
        type: int
        required: false
    thin_volume_max_repo_size:
        description:
            - This is the maximum amount the thin volume repository will be allowed to grow.
            - Only has significance when I(thin_volume_expansion_policy=="automatic").
            - When the pct I(thin_volume_repo_size) of I(thin_volume_max_repo_size) exceeds
              I(thin_volume_growth_alert_threshold) then a warning will be issued and the storage array will execute
              the I(thin_volume_expansion_policy) policy.
            - Expansion operations when I(thin_volume_expansion_policy=="automatic") will increase the maximum
              repository size.
            - Default will be the same as I(size).
        type: float
        required: false
    thin_volume_expansion_policy:
        description:
            - This is the thin volume expansion policy.
            - When I(thin_volume_expansion_policy=="automatic") and I(thin_volume_growth_alert_threshold) is exceed the
              I(thin_volume_max_repo_size) will be automatically expanded.
            - When I(thin_volume_expansion_policy=="manual") and I(thin_volume_growth_alert_threshold) is exceeded the
              storage system will wait for manual intervention.
            - The thin volume_expansion policy can not be modified on existing thin volumes in this module.
            - Generally speaking you should almost always use I(thin_volume_expansion_policy=="automatic).
        type: str
        choices: ["automatic", "manual"]
        default: "automatic"
        required: false
    thin_volume_growth_alert_threshold:
        description:
            - This is the thin provision repository utilization threshold (in percent).
            - When the pct of used storage of the maximum repository size exceeds this value then a alert will
              be issued and the I(thin_volume_expansion_policy) will be executed.
            - Values must be between or equal to 10 and 99.
        type: int
        default: 95
        required: false
    owning_controller:
        description:
            - Specifies which controller will be the primary owner of the volume
            - Not specifying will allow the controller to choose ownership.
        type: str
        choices: ["A", "B"]
        required: false
    ssd_cache_enabled:
        description:
            - Whether an existing SSD cache should be enabled on the volume (fails if no SSD cache defined)
            - The default value is to ignore existing SSD cache setting.
        type: bool
        default: false
        required: false
    data_assurance_enabled:
        description:
            - Determines whether data assurance (DA) should be enabled for the volume
            - Only available when creating a new volume and on a storage pool with drives supporting the DA capability.
        type: bool
        default: false
        required: false
    read_cache_enable:
        description:
            - Indicates whether read caching should be enabled for the volume.
        type: bool
        default: true
        required: false
    read_ahead_enable:
        description:
            - Indicates whether or not automatic cache read-ahead is enabled.
            - This option has no effect on thinly provisioned volumes since the architecture for thin volumes cannot
              benefit from read ahead caching.
        type: bool
        default: true
        required: false
    write_cache_enable:
        description:
            - Indicates whether write-back caching should be enabled for the volume.
        type: bool
        default: true
        required: false
    write_cache_mirror_enable:
        description:
            - Indicates whether write cache mirroring should be enabled.
        type: bool
        default: true
        required: false
    cache_without_batteries:
        description:
            - Indicates whether caching should be used without battery backup.
            - Warning, I(cache_without_batteries==true) and the storage system looses power and there is no battery backup, data will be lost!
        type: bool
        default: false
        required: false
    workload_name:
        description:
            - Label for the workload defined by the metadata.
            - When I(workload_name) and I(metadata) are specified then the defined workload will be added to the storage
              array.
            - When I(workload_name) exists on the storage array but the metadata is different then the workload
              definition will be updated. (Changes will update all associated volumes!)
            - Existing workloads can be retrieved using M(netapp_eseries.santricity.na_santricity_facts).
        type: str
        required: false
    workload_metadata:
        description:
            - Dictionary containing meta data for the use, user, location, etc of the volume (dictionary is arbitrarily
              defined for whatever the user deems useful)
            - When I(workload_name) exists on the storage array but the metadata is different then the workload
              definition will be updated. (Changes will update all associated volumes!)
            - I(workload_name) must be specified when I(metadata) are defined.
            - Dictionary key cannot be longer than 16 characters
            - Dictionary values cannot be longer than 60 characters
        type: dict
        required: false
        aliases:
            - metadata
    volume_metadata:
        description:
            - Dictionary containing metadata for the volume itself.
            - Dictionary key cannot be longer than 14 characters
            - Dictionary values cannot be longer than 240 characters
        type: dict
        required: false
    allow_expansion:
        description:
            - Allows volume size to expand to meet the required specification.
            - Warning, when I(allows_expansion==false) and the existing volume needs to be expanded the module will continue with a warning.
        type: bool
        default: false
        required: false
    wait_for_initialization:
        description:
            - Forces the module to wait for expansion operations to complete before continuing.
        type: bool
        default: false
        required: false
"""
EXAMPLES = """
- name: Create simple volume with workload tags (volume meta data)
  na_santricity_volume:
    ssid: "1"
    api_url: "https://192.168.1.100:8443/devmgr/v2"
    api_username: "admin"
    api_password: "adminpass"
    validate_certs: true
    state: present
    name: volume
    storage_pool_name: storage_pool
    size: 300
    size_unit: gb
    workload_name: volume_tag
    metadata:
      key1: value1
      key2: value2

- name: Create a thin volume
  na_santricity_volume:
    ssid: "1"
    api_url: "https://192.168.1.100:8443/devmgr/v2"
    api_username: "admin"
    api_password: "adminpass"
    validate_certs: true
    state: present
    name: volume1
    storage_pool_name: storage_pool
    size: 131072
    size_unit: gb
    thin_provision: true
    thin_volume_repo_size: 32
    thin_volume_max_repo_size: 1024

- name: Expand thin volume's virtual size
  na_santricity_volume:
    ssid: "1"
    api_url: "https://192.168.1.100:8443/devmgr/v2"
    api_username: "admin"
    api_password: "adminpass"
    validate_certs: true
    state: present
    name: volume1
    storage_pool_name: storage_pool
    size: 262144
    size_unit: gb
    thin_provision: true
    thin_volume_repo_size: 32
    thin_volume_max_repo_size: 1024

- name: Expand thin volume's maximum repository size
  na_santricity_volume:
    ssid: "1"
    api_url: "https://192.168.1.100:8443/devmgr/v2"
    api_username: "admin"
    api_password: "adminpass"
    validate_certs: true
    state: present
    name: volume1
    storage_pool_name: storage_pool
    size: 262144
    size_unit: gb
    thin_provision: true
    thin_volume_repo_size: 32
    thin_volume_max_repo_size: 2048

- name: Delete volume
  na_santricity_volume:
    ssid: "1"
    api_url: "https://192.168.1.100:8443/devmgr/v2"
    api_username: "admin"
    api_password: "adminpass"
    validate_certs: true
    state: absent
    name: volume
"""
RETURN = """
msg:
    description: State of volume
    type: str
    returned: always
    sample: "Standard volume [workload_vol_1] has been created."
"""

import time

from ansible_collections.netapp_eseries.santricity.plugins.module_utils.santricity import NetAppESeriesModule
from ansible.module_utils._text import to_native


class NetAppESeriesVolume(NetAppESeriesModule):
    VOLUME_CREATION_BLOCKING_TIMEOUT_SEC = 300
    MAXIMUM_VOLUME_METADATA_KEY_LENGTH = 14
    MAXIMUM_VOLUME_METADATA_VALUE_LENGTH = 240
    MAXIMUM_VOLUME_METADATA_VALUE_SEGMENT_LENGTH = 60

    def __init__(self):
        ansible_options = dict(
            state=dict(choices=["present", "absent"], default="present"),
            name=dict(required=True, type="str"),
            storage_pool_name=dict(type="str"),
            size_unit=dict(default="gb", choices=["bytes", "b", "kb", "mb", "gb", "tb", "pb", "eb", "zb", "yb", "pct"], type="str"),
            size=dict(type="float", required=True),
            size_tolerance_b=dict(type="int", required=False, default=10485760),
            segment_size_kb=dict(type="int", default=128, required=False),
            owning_controller=dict(type="str", choices=["A", "B"], required=False),
            ssd_cache_enabled=dict(type="bool", default=False),
            data_assurance_enabled=dict(type="bool", default=False),
            thin_provision=dict(type="bool", default=False),
            thin_volume_repo_size=dict(type="int", required=False),
            thin_volume_max_repo_size=dict(type="float", required=False),
            thin_volume_expansion_policy=dict(type="str", choices=["automatic", "manual"], default="automatic", required=False),
            thin_volume_growth_alert_threshold=dict(type="int", default=95),
            read_cache_enable=dict(type="bool", default=True),
            read_ahead_enable=dict(type="bool", default=True),
            write_cache_enable=dict(type="bool", default=True),
            write_cache_mirror_enable=dict(type="bool", default=True),
            cache_without_batteries=dict(type="bool", default=False),
            workload_name=dict(type="str", required=False),
            workload_metadata=dict(type="dict", required=False, aliases=["metadata"]),
            volume_metadata=dict(type="dict", required=False),
            allow_expansion=dict(type="bool", default=False),
            wait_for_initialization=dict(type="bool", default=False))

        required_if = [
            ["state", "present", ["storage_pool_name", "size"]],
            ["thin_provision", "true", ["thin_volume_repo_size"]]
        ]

        super(NetAppESeriesVolume, self).__init__(ansible_options=ansible_options,
                                                  web_services_version="02.00.0000.0000",
                                                  supports_check_mode=True,
                                                  required_if=required_if)

        args = self.module.params
        self.state = args["state"]
        self.name = args["name"]
        self.storage_pool_name = args["storage_pool_name"]
        self.size_unit = args["size_unit"]
        self.size_tolerance_b = args["size_tolerance_b"]
        self.segment_size_kb = args["segment_size_kb"]

        if args["size"]:
            if self.size_unit == "pct":
                if args["thin_provision"]:
                    self.module.fail_json(msg="'pct' is an invalid size unit for thin provisioning! Array [%s]." % self.ssid)
                self.size_percent = args["size"]
            else:
                self.size_b = self.convert_to_aligned_bytes(args["size"])

        self.owning_controller_id = None
        if args["owning_controller"]:
            self.owning_controller_id = "070000000000000000000001" if args["owning_controller"] == "A" else "070000000000000000000002"

        self.read_cache_enable = args["read_cache_enable"]
        self.read_ahead_enable = args["read_ahead_enable"]
        self.write_cache_enable = args["write_cache_enable"]
        self.write_cache_mirror_enable = args["write_cache_mirror_enable"]
        self.ssd_cache_enabled = args["ssd_cache_enabled"]
        self.cache_without_batteries = args["cache_without_batteries"]
        self.data_assurance_enabled = args["data_assurance_enabled"]

        self.thin_provision = args["thin_provision"]
        self.thin_volume_expansion_policy = args["thin_volume_expansion_policy"]
        self.thin_volume_growth_alert_threshold = int(args["thin_volume_growth_alert_threshold"])
        self.thin_volume_repo_size_b = None
        self.thin_volume_max_repo_size_b = None

        if args["thin_volume_repo_size"]:
            self.thin_volume_repo_size_b = self.convert_to_aligned_bytes(args["thin_volume_repo_size"])
        if args["thin_volume_max_repo_size"]:
            self.thin_volume_max_repo_size_b = self.convert_to_aligned_bytes(args["thin_volume_max_repo_size"])

        self.workload_name = args["workload_name"]
        self.allow_expansion = args["allow_expansion"]
        self.wait_for_initialization = args["wait_for_initialization"]

        # convert metadata to a list of dictionaries containing the keys "key" and "value" corresponding to
        #   each of the workload attributes dictionary entries
        self.metadata = []
        if self.state == "present" and args["workload_metadata"]:
            if not self.workload_name:
                self.module.fail_json(msg="When metadata is specified then the name for the workload must be specified. Array [%s]." % self.ssid)

            for key, value in args["workload_metadata"].items():
                self.metadata.append({"key": key, "value": value})

        self.volume_metadata = []
        if self.state == "present" and args["volume_metadata"]:
            for key, value in args["volume_metadata"].items():
                key, value = str(key), str(value)

                if len(key) > self.MAXIMUM_VOLUME_METADATA_KEY_LENGTH:
                    self.module.fail_json(msg="Volume metadata keys must be less than %s characters long. Array [%s]."
                                              % (str(self.MAXIMUM_VOLUME_METADATA_KEY_LENGTH), self.ssid))

                if len(value) > self.MAXIMUM_VOLUME_METADATA_VALUE_LENGTH:
                    self.module.fail_json(msg="Volume metadata values must be less than %s characters long. Array [%s]."
                                              % (str(self.MAXIMUM_VOLUME_METADATA_VALUE_LENGTH), self.ssid))

                if value:
                    for index, start in enumerate(range(0, len(value), self.MAXIMUM_VOLUME_METADATA_VALUE_SEGMENT_LENGTH)):
                        if len(value) > start + self.MAXIMUM_VOLUME_METADATA_VALUE_SEGMENT_LENGTH:
                            self.volume_metadata.append({"key": "%s~%s" % (key, str(index)),
                                                         "value": value[start:start + self.MAXIMUM_VOLUME_METADATA_VALUE_SEGMENT_LENGTH]})
                        else:
                            self.volume_metadata.append({"key": "%s~%s" % (key, str(index)), "value": value[start:len(value)]})
                else:
                    self.volume_metadata.append({"key": "%s~0" % key, "value": ""})

        if self.state == "present" and self.thin_provision:
            if not self.thin_volume_max_repo_size_b:
                self.thin_volume_max_repo_size_b = self.size_b

            if not self.thin_volume_expansion_policy:
                self.thin_volume_expansion_policy = "automatic"

            if self.size_b > 256 * 1024 ** 4:
                self.module.fail_json(msg="Thin provisioned volumes must be less than or equal to 256tb is size."
                                          " Attempted size [%sg]" % (self.size_b * 1024 ** 3))

            if (self.thin_volume_repo_size_b and self.thin_volume_max_repo_size_b and
                    self.thin_volume_repo_size_b > self.thin_volume_max_repo_size_b):
                self.module.fail_json(msg="The initial size of the thin volume must not be larger than the maximum"
                                          " repository size. Array [%s]." % self.ssid)

            if self.thin_volume_growth_alert_threshold < 10 or self.thin_volume_growth_alert_threshold > 99:
                self.module.fail_json(msg="thin_volume_growth_alert_threshold must be between or equal to 10 and 99."
                                          "thin_volume_growth_alert_threshold [%s]. Array [%s]."
                                          % (self.thin_volume_growth_alert_threshold, self.ssid))

        self.volume_detail = None
        self.pool_detail = None
        self.workload_id = None

    def convert_to_aligned_bytes(self, size):
        """Convert size to the truncated byte size that aligns on the segment size."""
        size_bytes = int(size * self.SIZE_UNIT_MAP[self.size_unit])
        segment_size_bytes = int(self.segment_size_kb * self.SIZE_UNIT_MAP["kb"])
        segment_count = int(size_bytes / segment_size_bytes)
        return segment_count * segment_size_bytes

    def get_volume(self):
        """Retrieve volume details from storage array."""
        volumes = list()
        thin_volumes = list()
        try:
            rc, volumes = self.request("storage-systems/%s/volumes" % self.ssid)
        except Exception as err:
            self.module.fail_json(msg="Failed to obtain list of thick volumes.  Array Id [%s]. Error[%s]."
                                      % (self.ssid, to_native(err)))
        try:
            rc, thin_volumes = self.request("storage-systems/%s/thin-volumes" % self.ssid)
        except Exception as err:
            self.module.fail_json(msg="Failed to obtain list of thin volumes.  Array Id [%s]. Error[%s]."
                                      % (self.ssid, to_native(err)))

        volume_detail = [volume for volume in volumes + thin_volumes if volume["name"] == self.name]
        return volume_detail[0] if volume_detail else dict()

    def wait_for_volume_availability(self, retries=VOLUME_CREATION_BLOCKING_TIMEOUT_SEC / 5):
        """Waits until volume becomes available.

        :raises AnsibleFailJson when retries are exhausted.
        """
        if retries == 0:
            self.module.fail_json(msg="Timed out waiting for the volume %s to become available. Array [%s]."
                                      % (self.name, self.ssid))
        if not self.get_volume():
            time.sleep(5)
            self.wait_for_volume_availability(retries=retries - 1)

    def wait_for_volume_action(self, timeout=None):
        """Waits until volume action is complete is complete.
        :param: int timeout: Wait duration measured in seconds. Waits indefinitely when None.
        """
        action = "unknown"
        percent_complete = None
        while action != "complete":
            time.sleep(5)

            try:
                rc, operations = self.request("storage-systems/%s/symbol/getLongLivedOpsProgress" % self.ssid)

                # Search long lived operations for volume
                action = "complete"
                for operation in operations["longLivedOpsProgress"]:
                    if operation["volAction"] is not None:
                        for key in operation.keys():
                            if (operation[key] is not None and "volumeRef" in operation[key] and
                                    (operation[key]["volumeRef"] == self.volume_detail["id"] or
                                     ("storageVolumeRef" in self.volume_detail and operation[key]["volumeRef"] == self.volume_detail["storageVolumeRef"]))):
                                action = operation["volAction"]
                                percent_complete = operation["init"]["percentComplete"]
            except Exception as err:
                self.module.fail_json(msg="Failed to get volume expansion progress. Volume [%s]. Array Id [%s]."
                                          " Error[%s]." % (self.name, self.ssid, to_native(err)))

            if timeout is not None:
                if timeout <= 0:
                    self.module.warn("Expansion action, %s, failed to complete during the allotted time. Time remaining"
                                     " [%s]. Array Id [%s]." % (action, percent_complete, self.ssid))
                    self.module.fail_json(msg="Expansion action failed to complete. Time remaining [%s]. Array Id [%s]." % (percent_complete, self.ssid))
                if timeout:
                    timeout -= 5

            self.module.log("Expansion action, %s, is %s complete." % (action, percent_complete))
        self.module.log("Expansion action is complete.")

    def get_storage_pool(self):
        """Retrieve storage pool details from the storage array."""
        storage_pools = list()
        try:
            rc, storage_pools = self.request("storage-systems/%s/storage-pools" % self.ssid)
        except Exception as err:
            self.module.fail_json(msg="Failed to obtain list of storage pools.  Array Id [%s]. Error[%s]."
                                      % (self.ssid, to_native(err)))

        pool_detail = [storage_pool for storage_pool in storage_pools if storage_pool["name"] == self.storage_pool_name]
        return pool_detail[0] if pool_detail else dict()

    def check_storage_pool_sufficiency(self):
        """Perform a series of checks as to the sufficiency of the storage pool for the volume."""
        if not self.pool_detail:
            self.module.fail_json(msg='Requested storage pool (%s) not found' % self.storage_pool_name)

        if not self.volume_detail:
            if self.thin_provision and not self.pool_detail['diskPool']:
                self.module.fail_json(msg='Thin provisioned volumes can only be created on raid disk pools.')

            if (self.data_assurance_enabled and not
                    (self.pool_detail["protectionInformationCapabilities"]["protectionInformationCapable"] and
                     self.pool_detail["protectionInformationCapabilities"]["protectionType"] == "type2Protection")):
                self.module.fail_json(msg="Data Assurance (DA) requires the storage pool to be DA-compatible."
                                          " Array [%s]." % self.ssid)

            if int(self.pool_detail["freeSpace"]) < self.size_b and not self.thin_provision:
                self.module.fail_json(msg="Not enough storage pool free space available for the volume's needs."
                                          " Array [%s]." % self.ssid)
        else:
            # Check for expansion
            if (int(self.pool_detail["freeSpace"]) < int(self.volume_detail["totalSizeInBytes"]) - self.size_b and
                    not self.thin_provision):
                self.module.fail_json(msg="Not enough storage pool free space available for the volume's needs."
                                          " Array [%s]." % self.ssid)

    def update_workload_tags(self, check_mode=False):
        """Check the status of the workload tag and update storage array definitions if necessary.

        When the workload attributes are not provided but an existing workload tag name is, then the attributes will be
        used.

        :return bool: Whether changes were required to be made."""
        change_required = False
        workload_tags = None
        request_body = None
        ansible_profile_id = None

        if self.workload_name:
            try:
                rc, workload_tags = self.request("storage-systems/%s/workloads" % self.ssid)
            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve storage array workload tags. Array [%s]" % self.ssid)

            ansible_profile_id = "Other_1"
            request_body = dict(name=self.workload_name,
                                profileId=ansible_profile_id,
                                workloadInstanceIndex=None,
                                isValid=True)

            # evaluate and update storage array when needed
            for tag in workload_tags:
                if tag["name"] == self.workload_name:
                    self.workload_id = tag["id"]

                    if not self.metadata:
                        break

                    # Determine if core attributes (everything but profileId) is the same
                    metadata_set = set(tuple(sorted(attr.items())) for attr in self.metadata)
                    tag_set = set(tuple(sorted(attr.items()))
                                  for attr in tag["workloadAttributes"] if attr["key"] != "profileId")
                    if metadata_set != tag_set:
                        self.module.log("Workload tag change is required!")
                        change_required = True

                    # only perform the required action when check_mode==False
                    if change_required and not check_mode:
                        self.metadata.append(dict(key="profileId", value=ansible_profile_id))
                        request_body.update(dict(isNewWorkloadInstance=False,
                                                 isWorkloadDataInitialized=True,
                                                 isWorkloadCardDataToBeReset=True,
                                                 workloadAttributes=self.metadata))
                        try:
                            rc, resp = self.request("storage-systems/%s/workloads/%s" % (self.ssid, tag["id"]),
                                                    data=request_body, method="POST")
                        except Exception as error:
                            self.module.fail_json(msg="Failed to create new workload tag. Array [%s]. Error [%s]"
                                                      % (self.ssid, to_native(error)))
                        self.module.log("Workload tag [%s] required change." % self.workload_name)
                    break

            # existing workload tag not found so create new workload tag
            else:
                change_required = True
                self.module.log("Workload tag creation is required!")

                if change_required and not check_mode:
                    if self.metadata:
                        self.metadata.append(dict(key="profileId", value=ansible_profile_id))
                    else:
                        self.metadata = [dict(key="profileId", value=ansible_profile_id)]

                    request_body.update(dict(isNewWorkloadInstance=True,
                                             isWorkloadDataInitialized=False,
                                             isWorkloadCardDataToBeReset=False,
                                             workloadAttributes=self.metadata))
                    try:
                        rc, resp = self.request("storage-systems/%s/workloads" % self.ssid,
                                                method="POST", data=request_body)
                        self.workload_id = resp["id"]
                    except Exception as error:
                        self.module.fail_json(msg="Failed to create new workload tag. Array [%s]. Error [%s]"
                                                  % (self.ssid, to_native(error)))
                self.module.log("Workload tag [%s] was added." % self.workload_name)

        return change_required

    def get_volume_property_changes(self):
        """Retrieve the volume update request body when change(s) are required.

        :raise AnsibleFailJson when attempting to change segment size on existing volume.
        :return dict: request body when change(s) to a volume's properties are required.
        """
        change = False
        request_body = dict(flashCache=self.ssd_cache_enabled, metaTags=[],
                            cacheSettings=dict(readCacheEnable=self.read_cache_enable,
                                               writeCacheEnable=self.write_cache_enable,
                                               mirrorEnable=self.write_cache_mirror_enable))

        # check for invalid modifications
        if self.segment_size_kb * 1024 != int(self.volume_detail["segmentSize"]):
            self.module.fail_json(msg="Existing volume segment size is %s and cannot be modified."
                                      % self.volume_detail["segmentSize"])

        # common thick/thin volume properties
        if (self.read_cache_enable != self.volume_detail["cacheSettings"]["readCacheEnable"] or
                self.write_cache_enable != self.volume_detail["cacheSettings"]["writeCacheEnable"] or
                self.write_cache_mirror_enable != self.volume_detail["cacheSettings"]["mirrorEnable"] or
                self.ssd_cache_enabled != self.volume_detail["flashCached"]):
            change = True

        # controller ownership
        if self.owning_controller_id and self.owning_controller_id != self.volume_detail["preferredManager"]:
            change = True
            request_body.update(dict(owningControllerId=self.owning_controller_id))

        # volume meta tags
        request_body["metaTags"].extend(self.volume_metadata)
        for entry in self.volume_metadata:
            if entry not in self.volume_detail["metadata"]:
                change = True

        if self.workload_name:
            request_body["metaTags"].extend([{"key": "workloadId", "value": self.workload_id},
                                             {"key": "volumeTypeId", "value": "volume"}])

            if ({"key": "workloadId", "value": self.workload_id} not in self.volume_detail["metadata"] or
                    {"key": "volumeTypeId", "value": "volume"} not in self.volume_detail["metadata"]):
                change = True

        if len(self.volume_detail["metadata"]) != len(request_body["metaTags"]):
            change = True

        # thick/thin volume specific properties
        if self.thin_provision:
            if self.thin_volume_growth_alert_threshold != int(self.volume_detail["growthAlertThreshold"]):
                change = True
                request_body.update(dict(growthAlertThreshold=self.thin_volume_growth_alert_threshold))
            if self.thin_volume_expansion_policy != self.volume_detail["expansionPolicy"]:
                change = True
                request_body.update(dict(expansionPolicy=self.thin_volume_expansion_policy))
        else:
            if self.read_ahead_enable != (int(self.volume_detail["cacheSettings"]["readAheadMultiplier"]) > 0):
                change = True
                request_body["cacheSettings"].update(dict(readAheadEnable=self.read_ahead_enable))
            if self.cache_without_batteries != self.volume_detail["cacheSettings"]["cwob"]:
                change = True
                request_body["cacheSettings"].update(dict(cacheWithoutBatteries=self.cache_without_batteries))

        return request_body if change else dict()

    def get_expand_volume_changes(self):
        """Expand the storage specifications for the existing thick/thin volume.

        :raise AnsibleFailJson when a thick/thin volume expansion request fails.
        :return dict: dictionary containing all the necessary values for volume expansion request
        """
        request_body = dict()

        if self.size_b < int(self.volume_detail["capacity"]) - self.size_tolerance_b:
            self.module.fail_json(msg="Reducing the size of volumes is not permitted. Volume [%s]. Array [%s]"
                                      % (self.name, self.ssid))

        if self.volume_detail["thinProvisioned"]:
            if self.size_b > int(self.volume_detail["capacity"]) + self.size_tolerance_b:
                request_body.update(dict(sizeUnit="bytes", newVirtualSize=self.size_b))
                self.module.log("Thin volume virtual size have been expanded.")

            if self.volume_detail["expansionPolicy"] == "automatic":
                if self.thin_volume_max_repo_size_b > int(self.volume_detail["provisionedCapacityQuota"]) + self.size_tolerance_b:
                    request_body.update(dict(sizeUnit="bytes", newRepositorySize=self.thin_volume_max_repo_size_b))
                    self.module.log("Thin volume maximum repository size have been expanded (automatic policy).")

            elif self.volume_detail["expansionPolicy"] == "manual":
                if self.thin_volume_repo_size_b > int(self.volume_detail["currentProvisionedCapacity"]) + self.size_tolerance_b:
                    change = self.thin_volume_repo_size_b - int(self.volume_detail["currentProvisionedCapacity"])
                    if change < 4 * 1024 ** 3 or change > 256 * 1024 ** 3 or change % (4 * 1024 ** 3) != 0:
                        self.module.fail_json(msg="The thin volume repository increase must be between or equal to 4gb"
                                                  " and 256gb in increments of 4gb. Attempted size [%sg]."
                                                  % (self.thin_volume_repo_size_b * 1024 ** 3))

                    request_body.update(dict(sizeUnit="bytes", newRepositorySize=self.thin_volume_repo_size_b))
                    self.module.log("Thin volume maximum repository size have been expanded (manual policy).")

        elif self.size_b > int(self.volume_detail["capacity"]) + self.size_tolerance_b:
            request_body.update(dict(sizeUnit="bytes", expansionSize=self.size_b))
            self.module.log("Volume storage capacities have been expanded.")

        if request_body and not self.allow_expansion:
            self.module.warn("Expansion not allowed! Change allow_expansion flag to true to allow volume expansions. Array Id [%s]." % self.ssid)
            return dict()

        return request_body

    def create_volume(self):
        """Create thick/thin volume according to the specified criteria."""
        body = dict(name=self.name, poolId=self.pool_detail["id"], sizeUnit="bytes",
                    dataAssuranceEnabled=self.data_assurance_enabled)

        if self.volume_metadata:
            body.update({"metaTags": self.volume_metadata})

        if self.thin_provision:
            body.update(dict(virtualSize=self.size_b,
                             repositorySize=self.thin_volume_repo_size_b,
                             maximumRepositorySize=self.thin_volume_max_repo_size_b,
                             expansionPolicy=self.thin_volume_expansion_policy,
                             growthAlertThreshold=self.thin_volume_growth_alert_threshold))
            try:
                rc, volume = self.request("storage-systems/%s/thin-volumes" % self.ssid, data=body, method="POST")
            except Exception as error:
                self.module.fail_json(msg="Failed to create thin volume.  Volume [%s].  Array Id [%s]. Error[%s]."
                                          % (self.name, self.ssid, to_native(error)))

            self.module.log("New thin volume created [%s]." % self.name)

        else:
            body.update(dict(size=self.size_b, segSize=self.segment_size_kb))
            try:
                rc, volume = self.request("storage-systems/%s/volumes" % self.ssid, data=body, method="POST")
            except Exception as error:
                self.module.fail_json(msg="Failed to create volume.  Volume [%s].  Array Id [%s]. Error[%s]."
                                          % (self.name, self.ssid, to_native(error)))

            self.module.log("New volume created [%s]." % self.name)

    def update_volume_properties(self):
        """Update existing thin-volume or volume properties.

        :raise AnsibleFailJson when either thick/thin volume update request fails.
        :return bool: whether update was applied
        """
        self.wait_for_volume_availability()
        self.volume_detail = self.get_volume()

        request_body = self.get_volume_property_changes()

        if request_body:
            if self.thin_provision:
                try:
                    rc, resp = self.request("storage-systems/%s/thin-volumes/%s"
                                            % (self.ssid, self.volume_detail["id"]), data=request_body, method="POST")
                except Exception as error:
                    self.module.fail_json(msg="Failed to update thin volume properties. Volume [%s]. Array Id [%s]."
                                              " Error[%s]." % (self.name, self.ssid, to_native(error)))
            else:
                try:
                    rc, resp = self.request("storage-systems/%s/volumes/%s" % (self.ssid, self.volume_detail["id"]),
                                            data=request_body, method="POST")
                except Exception as error:
                    self.module.fail_json(msg="Failed to update volume properties. Volume [%s]. Array Id [%s]."
                                              " Error[%s]." % (self.name, self.ssid, to_native(error)))
            return True
        return False

    def expand_volume(self):
        """Expand the storage specifications for the existing thick/thin volume.

        :raise AnsibleFailJson when a thick/thin volume expansion request fails.
        """
        request_body = self.get_expand_volume_changes()
        if request_body:
            if self.volume_detail["thinProvisioned"]:
                try:
                    rc, resp = self.request("storage-systems/%s/thin-volumes/%s/expand"
                                            % (self.ssid, self.volume_detail["id"]), data=request_body, method="POST")
                except Exception as err:
                    self.module.fail_json(msg="Failed to expand thin volume. Volume [%s]. Array Id [%s]. Error[%s]."
                                              % (self.name, self.ssid, to_native(err)))
                self.module.log("Thin volume specifications have been expanded.")

            else:
                try:
                    rc, resp = self.request(
                        "storage-systems/%s/volumes/%s/expand" % (self.ssid, self.volume_detail['id']),
                        data=request_body, method="POST")
                except Exception as err:
                    self.module.fail_json(msg="Failed to expand volume.  Volume [%s].  Array Id [%s]. Error[%s]."
                                              % (self.name, self.ssid, to_native(err)))

                self.module.log("Volume storage capacities have been expanded.")

    def delete_volume(self):
        """Delete existing thin/thick volume."""
        if self.thin_provision:
            try:
                rc, resp = self.request("storage-systems/%s/thin-volumes/%s" % (self.ssid, self.volume_detail["id"]),
                                        method="DELETE")
            except Exception as error:
                self.module.fail_json(msg="Failed to delete thin volume. Volume [%s]. Array Id [%s]. Error[%s]."
                                          % (self.name, self.ssid, to_native(error)))
            self.module.log("Thin volume deleted [%s]." % self.name)
        else:
            try:
                rc, resp = self.request("storage-systems/%s/volumes/%s" % (self.ssid, self.volume_detail["id"]),
                                        method="DELETE")
            except Exception as error:
                self.module.fail_json(msg="Failed to delete volume. Volume [%s]. Array Id [%s]. Error[%s]."
                                          % (self.name, self.ssid, to_native(error)))
            self.module.log("Volume deleted [%s]." % self.name)

    def apply(self):
        """Determine and apply any changes necessary to satisfy the specified criteria.

        :raise AnsibleExitJson when completes successfully"""
        change = False
        msg = None

        self.volume_detail = self.get_volume()
        self.pool_detail = self.get_storage_pool()

        if self.pool_detail and self.size_unit == "pct":
            space_mb = round(float(self.pool_detail["totalRaidedSpace"]), -8) / 1024 ** 2 - 100
            self.size_unit = "mb"
            self.size_b = self.convert_to_aligned_bytes(space_mb * (self.size_percent / 100))

        # Determine whether changes need to be applied to existing workload tags
        if self.state == 'present' and self.update_workload_tags(check_mode=True):
            change = True

        # Determine if any changes need to be applied
        if self.volume_detail:
            if self.state == 'absent':
                change = True

            elif self.state == 'present':
                # Must check the property changes first as it makes sure the segment size has no change before
                # using the size to determine if the volume expansion is needed which will cause an irrelevant
                # error message to show up.
                if self.get_volume_property_changes() or self.get_expand_volume_changes():
                    change = True

        elif self.state == 'present':
            if self.thin_provision and (self.thin_volume_repo_size_b < 4 * 1024 ** 3 or
                                        self.thin_volume_repo_size_b > 256 * 1024 ** 3 or
                                        self.thin_volume_repo_size_b % (4 * 1024 ** 3) != 0):
                self.module.fail_json(msg="The initial thin volume repository size must be between 4gb and 256gb in"
                                          " increments of 4gb. Attempted size [%sg]."
                                          % (self.thin_volume_repo_size_b * 1024 ** 3))
            change = True

        self.module.log("Update required: [%s]." % change)

        # Apply any necessary changes
        if change and not self.module.check_mode:
            if self.state == 'present':
                if self.update_workload_tags():
                    msg = "Workload tag change occurred."

                if not self.volume_detail:
                    self.check_storage_pool_sufficiency()
                    self.create_volume()
                    self.update_volume_properties()
                    msg = msg[:-1] + " and volume [%s] was created." if msg else "Volume [%s] has been created."
                else:
                    if self.update_volume_properties():
                        msg = "Volume [%s] properties were updated."

                    if self.get_expand_volume_changes():
                        self.expand_volume()
                        msg = msg[:-1] + " and was expanded." if msg else "Volume [%s] was expanded."

                if self.wait_for_initialization:
                    self.module.log("Waiting for volume operation to complete.")
                    self.wait_for_volume_action()

            elif self.state == 'absent':
                self.delete_volume()
                msg = "Volume [%s] has been deleted."

        else:
            msg = "Volume [%s] does not exist." if self.state == 'absent' else "Volume [%s] exists."

        self.module.exit_json(msg=(msg % self.name if msg and "%s" in msg else msg), changed=change)


def main():
    volume = NetAppESeriesVolume()
    volume.apply()


if __name__ == '__main__':
    main()
