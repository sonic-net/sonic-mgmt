#!/usr/bin/python

# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
module: na_santricity_snapshot
short_description: NetApp E-Series storage system's snapshots.
description: Manage NetApp E-Series manage the storage system's snapshots.
author:
    - Nathan Swartz (@swartzn)
    - Vu Tran (@VuTran007)
extends_documentation_fragment:
    - netapp_eseries.santricity.santricity.santricity_doc
options:
  state:
    description:
      - When I(state==absent) ensures the I(type) has been removed.
      - When I(state==present) ensures the I(type) is available.
      - When I(state==rollback) the consistency group will be rolled back to the point-in-time snapshot images selected by I(pit_name or pit_timestamp).
      - I(state==rollback) will always return changed since it is not possible to evaluate the current state of the base volume in relation to a snapshot image.
    type: str
    choices:
      - absent
      - present
      - rollback
    default: present
    required: false
  type:
    description:
      - Type of snapshot object to effect.
      - Group indicates a snapshot consistency group; consistency groups may have one or more base volume members which are defined in I(volumes).
      - Pit indicates a snapshot consistency group point-in-time image(s); a snapshot image will be taken of each base volume when I(state==present).
      - Warning! When I(state==absent and type==pit), I(pit_name) or I(pit_timestamp) must be defined and all point-in-time images created prior to the
        selection will also be deleted.
      - View indicates a consistency group snapshot volume of particular point-in-time image(s); snapshot volumes will be created for each base volume member.
      - Views are created from images from a single point-in-time so once created they cannot be modified.
    type: str
    default: group
    choices:
      - group
      - pit
      - view
    required: false
  group_name:
    description:
      - Name of the snapshot consistency group or snapshot volume.
      - Be sure to use different names for snapshot consistency groups and snapshot volumes to avoid name conflicts.
    type: str
    required: true
  volumes:
    description:
      - Details for each consistency group base volume for defining reserve capacity, preferred reserve capacity storage pool, and snapshot volume options.
      - When I(state==present and type==group) the volume entries will be used to add or remove base volume from a snapshot consistency group.
      - When I(state==present and type==view) the volume entries will be used to select images from a point-in-time for their respective snapshot volumes.
      - If I(state==present and type==view) and I(volume) is not specified then all volumes will be selected with the defaults.
      - Views are created from images from a single point-in-time so once created they cannot be modified.
      - When I(state==rollback) then I(volumes) can be used to specify which base volumes to rollback; otherwise all consistency group volumes will rollback.
    type: list
    elements: dict
    required: false
    suboptions:
      volume:
        description:
          - Base volume for consistency group.
        type: str
        required: true
      reserve_capacity_pct:
        description:
          - Percentage of base volume capacity to reserve for snapshot copy-on-writes (COW).
          - Used to define reserve capacity for both snapshot consistency group volume members and snapshot volumes.
        type: int
        default: 40
        required: false
      preferred_reserve_storage_pool:
        description:
          - Preferred storage pool or volume group for the reserve capacity volume.
          - The base volume's storage pool or volume group will be selected by default if not defined.
          - Used to specify storage pool or volume group for both snapshot consistency group volume members and snapshot volumes
        type: str
        required: false
      snapshot_volume_writable:
        description:
          - Whether snapshot volume of base volume images should be writable.
        type: bool
        default: true
        required: false
      snapshot_volume_validate:
        description:
          - Whether snapshot volume should be validated which includes both a media scan and parity validation.
        type: bool
        default: false
        required: false
      snapshot_volume_host:
        description:
          - Host or host group to map snapshot volume.
        type: str
        required: false
      snapshot_volume_lun:
        description:
          - LUN ID for snapshot volume.
        type: int
        required: false
  maximum_snapshots:
    description:
      - Total number of snapshot images to maintain.
    type: int
    default: 32
    required: false
  reserve_capacity_pct:
    description:
      - Default percentage of base volume capacity to reserve for snapshot copy-on-writes (COW).
      - Used to define reserve capacity for both snapshot consistency group volume members and snapshot volumes.
    type: int
    default: 40
    required: false
  preferred_reserve_storage_pool:
    description:
      - Default preferred storage pool or volume group for the reserve capacity volume.
      - The base volume's storage pool or volume group will be selected by default if not defined.
      - Used to specify storage pool or volume group for both snapshot consistency group volume members and snapshot volumes
    type: str
    required: false
  alert_threshold_pct:
    description:
      - Percent of filled reserve capacity to issue alert.
    type: int
    default: 75
    required: false
  reserve_capacity_full_policy:
    description:
      - Policy for full reserve capacity.
      - Purge deletes the oldest snapshot image for the base volume in the consistency group.
      - Reject writes to base volume (keep snapshot images valid).
    choices:
      - purge
      - reject
    type: str
    default: purge
    required: false
  rollback_priority:
    description:
      - Storage system priority given to restoring snapshot point in time.
    type: str
    choices:
      - highest
      - high
      - medium
      - low
      - lowest
    default: medium
    required: false
  rollback_backup:
    description:
      - Whether a point-in-time snapshot should be taken prior to performing a rollback.
    type: bool
    default: true
    required: false
  pit_name:
    description:
      - Name of a consistency group's snapshot images.
    type: str
    required: false
  pit_description:
    description:
      - Arbitrary description for a consistency group's snapshot images
    type: str
    required: false
  pit_timestamp:
    description:
      - Snapshot image timestamp in the YYYY-MM-DD HH:MM:SS (AM|PM) (hours, minutes, seconds, and day-period are optional)
      - Define only as much time as necessary to distinguish the desired snapshot image from the others.
      - 24 hour time will be assumed if day-period indicator (AM, PM) is not specified.
      - The terms latest and oldest may be used to select newest and oldest consistency group images.
      - Mutually exclusive with I(pit_name or pit_description)
    type: str
    required: false
  view_name:
    description:
      - Consistency group snapshot volume group.
      - Required when I(state==volume) or when ensuring the views absence when I(state==absent).
    type: str
    required: false
  view_host:
    description:
      - Default host or host group to map snapshot volumes.
    type: str
    required: false
  view_writable:
    description:
      - Default whether snapshot volumes should be writable.
    type: bool
    default: true
    required: false
  view_validate:
    description:
      - Default whether snapshop volumes should be validated.
    type: bool
    default: false
    required: false
notes:
  - Key-value pairs are used to keep track of snapshot names and descriptions since the snapshot point-in-time images do have metadata associated with their
    data structures; therefore, it is necessary to clean out old keys that are no longer associated with an actual image. This cleaning action is performed each
    time this module is executed.
"""
EXAMPLES = """
- name: Ensure snapshot consistency group exists.
  na_santricity_snapshot:
    ssid: "1"
    api_url: https://192.168.1.100:8443/devmgr/v2
    api_username: admin
    api_password: adminpass
    state: present
    type: group
    group_name: snapshot_group1
    volumes:
      - volume: vol1
        reserve_capacity_pct: 20
        preferred_reserve_storage_pool: vg1
      - volume: vol2
        reserve_capacity_pct: 30
      - volume: vol3
    alert_threshold_pct: 80
    maximum_snapshots: 30
- name: Take the current consistency group's base volumes point-in-time snapshot images.
  na_santricity_snapshot:
    ssid: "1"
    api_url: https://192.168.1.100:8443/devmgr/v2
    api_username: admin
    api_password: adminpass
    state: present
    type: pit
    group_name: snapshot_group1
    pit_name: pit1
    pit_description: Initial consistency group's point-in-time snapshot images.
- name: Ensure snapshot consistency group view exists and is mapped to host group.
  na_santricity_snapshot:
    ssid: "1"
    api_url: https://192.168.1.100:8443/devmgr/v2
    api_username: admin
    api_password: adminpass
    state: present
    type: view
    group_name: snapshot_group1
    pit_name: pit1
    view_name: view1
    view_host: view1_hosts_group
    volumes:
      - volume: vol1
        reserve_capacity_pct: 20
        preferred_reserve_storage_pool: vg4
        snapshot_volume_writable: false
        snapshot_volume_validate: true
      - volume: vol2
        reserve_capacity_pct: 20
        preferred_reserve_storage_pool: vg4
        snapshot_volume_writable: true
        snapshot_volume_validate: true
      - volume: vol3
        reserve_capacity_pct: 20
        preferred_reserve_storage_pool: vg4
        snapshot_volume_writable: false
        snapshot_volume_validate: true
    alert_threshold_pct: 80
    maximum_snapshots: 30
- name: Rollback base volumes to consistency group's point-in-time pit1.
  na_santricity_snapshot:
    ssid: "1"
    api_url: https://192.168.1.100:8443/devmgr/v2
    api_username: admin
    api_password: adminpass
    state: present
    type: group
    group_name: snapshot_group1
    pit_name: pit1
    rollback: true
    rollback_priority: high
- name: Ensure snapshot consistency group view no longer exists.
  na_santricity_snapshot:
    ssid: "1"
    api_url: https://192.168.1.100:8443/devmgr/v2
    api_username: admin
    api_password: adminpass
    state: absent
    type: view
    group_name: snapshot_group1
    view_name: view1
- name: Ensure that the consistency group's base volumes point-in-time snapshot images pit1 no longer exists.
  na_santricity_snapshot:
    ssid: "1"
    api_url: https://192.168.1.100:8443/devmgr/v2
    api_username: admin
    api_password: adminpass
    state: absent
    type: image
    group_name: snapshot_group1
    pit_name: pit1
- name: Ensure snapshot consistency group no longer exists.
  na_santricity_snapshot:
    ssid: "1"
    api_url: https://192.168.1.100:8443/devmgr/v2
    api_username: admin
    api_password: adminpass
    state: absent
    type: group
    group_name: snapshot_group1
"""
RETURN = """
changed:
  description: Whether changes have been made.
  type: bool
  returned: always
group_changes:
  description: All changes performed to the consistency group.
  type: dict
  returned: always
deleted_metadata_keys:
  description: Keys that were purged from the key-value datastore.
  type: list
  returned: always
"""
from datetime import datetime
import re
from time import sleep

from ansible_collections.netapp_eseries.santricity.plugins.module_utils.santricity import NetAppESeriesModule


class NetAppESeriesSnapshot(NetAppESeriesModule):
    def __init__(self):
        ansible_options = dict(state=dict(type="str", default="present", choices=["absent", "present", "rollback"], required=False),
                               type=dict(type="str", default="group", choices=["group", "pit", "view"], required=False),
                               group_name=dict(type="str", required=True),
                               volumes=dict(type="list", elements="dict", required=False,
                                            options=dict(volume=dict(type="str", required=True),
                                                         reserve_capacity_pct=dict(type="int", default=40, required=False),
                                                         preferred_reserve_storage_pool=dict(type="str", required=False),
                                                         snapshot_volume_writable=dict(type="bool", default=True, required=False),
                                                         snapshot_volume_validate=dict(type="bool", default=False, required=False),
                                                         snapshot_volume_host=dict(type="str", default=None, required=False),
                                                         snapshot_volume_lun=dict(type="int", default=None, required=False))),
                               maximum_snapshots=dict(type="int", default=32, required=False),
                               reserve_capacity_pct=dict(type="int", default=40, required=False),
                               preferred_reserve_storage_pool=dict(type="str", required=False),
                               alert_threshold_pct=dict(type="int", default=75, required=False),
                               reserve_capacity_full_policy=dict(type="str", default="purge", choices=["purge", "reject"], required=False),
                               rollback_priority=dict(type="str", default="medium", choices=["highest", "high", "medium", "low", "lowest"], required=False),
                               rollback_backup=dict(type="bool", default=True, required=False),
                               pit_name=dict(type="str", required=False),
                               pit_description=dict(type="str", required=False),
                               pit_timestamp=dict(type="str", required=False),
                               view_name=dict(type="str", required=False),
                               view_host=dict(type="str", default=None, required=False),
                               view_writable=dict(type="bool", default=True, required=False),
                               view_validate=dict(type="bool", default=False, required=False))

        super(NetAppESeriesSnapshot, self).__init__(ansible_options=ansible_options,
                                                    web_services_version="05.00.0000.0000",
                                                    supports_check_mode=True)
        args = self.module.params
        self.state = args["state"]
        self.type = args["type"]
        self.group_name = args["group_name"]
        self.maximum_snapshots = args["maximum_snapshots"]
        self.reserve_capacity_pct = args["reserve_capacity_pct"]
        self.preferred_reserve_storage_pool = args["preferred_reserve_storage_pool"]
        self.alert_threshold_pct = args["alert_threshold_pct"]
        self.reserve_capacity_full_policy = "purgepit" if args["reserve_capacity_full_policy"] == "purge" else "failbasewrites"
        self.rollback_priority = args["rollback_priority"]
        self.rollback_backup = args["rollback_backup"]
        self.rollback_priority = args["rollback_priority"]
        self.pit_name = args["pit_name"]
        self.pit_description = args["pit_description"]
        self.view_name = args["view_name"]
        self.view_host = args["view_host"]
        self.view_writable = args["view_writable"]
        self.view_validate = args["view_validate"]

        # Complete volume definitions.
        self.volumes = {}
        if args["volumes"]:
            for volume_info in args["volumes"]:
                reserve_capacity_pct = volume_info["reserve_capacity_pct"] if "reserve_capacity_pct" in volume_info else self.reserve_capacity_pct
                snapshot_volume_writable = volume_info["snapshot_volume_writable"] if "snapshot_volume_writable" in volume_info else self.view_writable
                snapshot_volume_validate = volume_info["snapshot_volume_validate"] if "snapshot_volume_validate" in volume_info else self.view_validate
                snapshot_volume_host = volume_info["snapshot_volume_host"] if "snapshot_volume_host" in volume_info else self.view_host
                snapshot_volume_lun = volume_info["snapshot_volume_lun"] if "snapshot_volume_lun" in volume_info else None
                if "preferred_reserve_storage_pool" in volume_info and volume_info["preferred_reserve_storage_pool"]:
                    preferred_reserve_storage_pool = volume_info["preferred_reserve_storage_pool"]
                else:
                    preferred_reserve_storage_pool = self.preferred_reserve_storage_pool

                self.volumes.update({volume_info["volume"]: {"reserve_capacity_pct": reserve_capacity_pct,
                                                             "preferred_reserve_storage_pool": preferred_reserve_storage_pool,
                                                             "snapshot_volume_writable": snapshot_volume_writable,
                                                             "snapshot_volume_validate": snapshot_volume_validate,
                                                             "snapshot_volume_host": snapshot_volume_host,
                                                             "snapshot_volume_lun": snapshot_volume_lun}})

        # Check and convert pit_timestamp to datetime object. volume: snap-vol1
        self.pit_timestamp = None
        self.pit_timestamp_tokens = 0
        if args["pit_timestamp"]:
            if args["pit_timestamp"] in ["newest", "oldest"]:
                self.pit_timestamp = args["pit_timestamp"]
            elif re.match("[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} (AM|PM|am|pm)", args["pit_timestamp"]):
                self.pit_timestamp = datetime.strptime(args["pit_timestamp"], "%Y-%m-%d %I:%M:%S %p")
                self.pit_timestamp_tokens = 6
            elif re.match("[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2} (AM|PM|am|pm)", args["pit_timestamp"]):
                self.pit_timestamp = datetime.strptime(args["pit_timestamp"], "%Y-%m-%d %I:%M %p")
                self.pit_timestamp_tokens = 5
            elif re.match("[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2} (AM|PM|am|pm)", args["pit_timestamp"]):
                self.pit_timestamp = datetime.strptime(args["pit_timestamp"], "%Y-%m-%d %I %p")
                self.pit_timestamp_tokens = 4
            elif re.match("[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}", args["pit_timestamp"]):
                self.pit_timestamp = datetime.strptime(args["pit_timestamp"], "%Y-%m-%d %H:%M:%S")
                self.pit_timestamp_tokens = 6
            elif re.match("[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}", args["pit_timestamp"]):
                self.pit_timestamp = datetime.strptime(args["pit_timestamp"], "%Y-%m-%d %H:%M")
                self.pit_timestamp_tokens = 5
            elif re.match("[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}", args["pit_timestamp"]):
                self.pit_timestamp = datetime.strptime(args["pit_timestamp"], "%Y-%m-%d %H")
                self.pit_timestamp_tokens = 4
            elif re.match("[0-9]{4}-[0-9]{2}-[0-9]{2}", args["pit_timestamp"]):
                self.pit_timestamp = datetime.strptime(args["pit_timestamp"], "%Y-%m-%d")
                self.pit_timestamp_tokens = 3
            else:
                self.module.fail_json(msg="Invalid argument! pit_timestamp must be in the form YYYY-MM-DD HH:MM:SS (AM|PM) (time portion is optional)."
                                          " Array [%s]." % self.ssid)

        # Check for required arguments
        if self.state == "present":
            if self.type == "group":
                if not self.volumes:
                    self.module.fail_json(msg="Missing argument! Volumes must be defined to create a snapshot consistency group."
                                              " Group [%s]. Array [%s]" % (self.group_name, self.ssid))
            elif self.type == "pit":
                if self.pit_timestamp and self.pit_name:
                    self.module.fail_json(msg="Invalid arguments! Either define pit_name with or without pit_description or pit_timestamp."
                                              " Group [%s]. Array [%s]" % (self.group_name, self.ssid))

            elif self.type == "view":
                if not self.view_name:
                    self.module.fail_json(msg="Missing argument! view_name must be defined to create a snapshot consistency group view."
                                              " Group [%s]. Array [%s]" % (self.group_name, self.ssid))
                if not (self.pit_name or self.pit_timestamp):
                    self.module.fail_json(msg="Missing argument! Either pit_name or pit_timestamp must be defined to create a consistency group point-in-time"
                                              " snapshot. Group [%s]. Array [%s]" % (self.group_name, self.ssid))
        elif self.state == "rollback":
            if not (self.pit_name or self.pit_timestamp):
                self.module.fail_json(msg="Missing argument! Either pit_name or pit_timestamp must be defined to create a consistency group point-in-time"
                                          " snapshot. Group [%s]. Array [%s]" % (self.group_name, self.ssid))
        else:
            if self.type == "pit":
                if self.pit_name and self.pit_timestamp:
                    self.module.fail_json(msg="Invalid arguments! Either define pit_name or pit_timestamp."
                                              " Group [%s]. Array [%s]" % (self.group_name, self.ssid))
                if not (self.pit_name or self.pit_timestamp):
                    self.module.fail_json(msg="Missing argument! Either pit_name or pit_timestamp must be defined to create a consistency group point-in-time"
                                              " snapshot. Group [%s]. Array [%s]" % (self.group_name, self.ssid))
            elif self.type == "view":
                if not self.view_name:
                    self.module.fail_json(msg="Missing argument! view_name must be defined to create a snapshot consistency group view."
                                              " Group [%s]. Array [%s]" % (self.group_name, self.ssid))

        # Check whether request needs to be forwarded on to the controller web services rest api.
        self.url_path_prefix = ""
        if not self.is_embedded():
            if self.ssid == "0" or self.ssid.lower() == "proxy":
                self.module.fail_json(msg="Snapshot is not a valid operation for SANtricity Web Services Proxy! ssid cannot be '0' or 'proxy'."
                                          " Array [%s]" % self.ssid)
            self.url_path_prefix = "storage-systems/%s/forward/devmgr/v2/" % self.ssid

        self.cache = {"get_consistency_group": {},
                      "get_all_storage_pools_by_id": {},
                      "get_all_storage_pools_by_name": {},
                      "get_all_volumes_by_id": {},
                      "get_all_volumes_by_name": {},
                      "get_all_hosts_and_hostgroups_by_name": {},
                      "get_all_hosts_and_hostgroups_by_id": {},
                      "get_mapping_by_id": {},
                      "get_mapping_by_name": {},
                      "get_all_concat_volumes_by_id": {},
                      "get_pit_images_by_timestamp": {},
                      "get_pit_images_by_name": {},
                      "get_pit_images_metadata": {},
                      "get_unused_pit_key_values": [],
                      "get_pit_info": None,
                      "get_consistency_group_view": {},
                      "view_changes_required": []}

    def get_all_storage_pools_by_id(self):
        """Retrieve and return all storage pools/volume groups."""
        if not self.cache["get_all_storage_pools_by_id"]:
            try:
                rc, storage_pools = self.request("storage-systems/%s/storage-pools" % self.ssid)

                for storage_pool in storage_pools:
                    self.cache["get_all_storage_pools_by_id"].update({storage_pool["id"]: storage_pool})
                    self.cache["get_all_storage_pools_by_name"].update({storage_pool["name"]: storage_pool})
            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve volumes! Error [%s]. Array [%s]." % (error, self.ssid))

        return self.cache["get_all_storage_pools_by_id"]

    def get_all_storage_pools_by_name(self):
        """Retrieve and return all storage pools/volume groups."""
        if not self.cache["get_all_storage_pools_by_name"]:
            self.get_all_storage_pools_by_id()

        return self.cache["get_all_storage_pools_by_name"]

    def get_all_volumes_by_id(self):
        """Retrieve and return a dictionary of all thick and thin volumes keyed by id."""
        if not self.cache["get_all_volumes_by_id"]:
            try:
                rc, thick_volumes = self.request("storage-systems/%s/volumes" % self.ssid)
                rc, thin_volumes = self.request("storage-systems/%s/thin-volumes" % self.ssid)

                for volume in thick_volumes + thin_volumes:
                    self.cache["get_all_volumes_by_id"].update({volume["id"]: volume})
                    self.cache["get_all_volumes_by_name"].update({volume["name"]: volume})
            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve volumes! Error [%s]. Array [%s]." % (error, self.ssid))

        return self.cache["get_all_volumes_by_id"]

    def get_all_volumes_by_name(self):
        """Retrieve and return a dictionary of all thick and thin volumes keyed by name."""
        if not self.cache["get_all_volumes_by_name"]:
            self.get_all_volumes_by_id()

        return self.cache["get_all_volumes_by_name"]

    def get_all_hosts_and_hostgroups_by_id(self):
        """Retrieve and return a dictionary of all host and host groups keyed by name."""
        if not self.cache["get_all_hosts_and_hostgroups_by_id"]:
            try:
                rc, hostgroups = self.request("storage-systems/%s/host-groups" % self.ssid)
                # hostgroup_by_id = {hostgroup["id"]: hostgroup for hostgroup in hostgroups}
                hostgroup_by_id = dict((hostgroup["id"], hostgroup) for hostgroup in hostgroups)

                rc, hosts = self.request("storage-systems/%s/hosts" % self.ssid)
                for host in hosts:
                    if host["clusterRef"] != "0000000000000000000000000000000000000000":
                        hostgroup_name = hostgroup_by_id[host["clusterRef"]]["name"]

                        if host["clusterRef"] not in self.cache["get_all_hosts_and_hostgroups_by_id"].keys():
                            hostgroup_by_id[host["clusterRef"]].update({"hostgroup": True, "host_ids": [host["id"]]})
                            self.cache["get_all_hosts_and_hostgroups_by_id"].update({host["clusterRef"]: hostgroup_by_id[host["clusterRef"]]})
                            self.cache["get_all_hosts_and_hostgroups_by_name"].update({hostgroup_name: hostgroup_by_id[host["clusterRef"]]})
                        else:
                            self.cache["get_all_hosts_and_hostgroups_by_id"][host["clusterRef"]]["host_ids"].append(host["id"])
                            self.cache["get_all_hosts_and_hostgroups_by_name"][hostgroup_name]["host_ids"].append(host["id"])

                    self.cache["get_all_hosts_and_hostgroups_by_id"].update({host["id"]: host, "hostgroup": False})
                    self.cache["get_all_hosts_and_hostgroups_by_name"].update({host["name"]: host, "hostgroup": False})
            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve all host and host group objects! Error [%s]. Array [%s]." % (error, self.ssid))

        return self.cache["get_all_hosts_and_hostgroups_by_id"]

    def get_all_hosts_and_hostgroups_by_name(self):
        """Retrieve and return a dictionary of all thick and thin volumes keyed by name."""
        if not self.cache["get_all_hosts_and_hostgroups_by_name"]:
            self.get_all_hosts_and_hostgroups_by_id()

        return self.cache["get_all_hosts_and_hostgroups_by_name"]

    def get_mapping_by_id(self):
        """Retrieve and return a dictionary of """
        if not self.cache["get_mapping_by_id"]:
            existing_hosts_and_hostgroups_by_id = self.get_all_hosts_and_hostgroups_by_id()
            existing_hosts_and_hostgroups_by_name = self.get_all_hosts_and_hostgroups_by_name()
            try:
                rc, mappings = self.request("storage-systems/%s/volume-mappings" % self.ssid)

                for mapping in mappings:
                    host_ids = [mapping["mapRef"]]
                    map_entry = {mapping["lun"]: mapping["volumeRef"]}

                    if mapping["type"] == "cluster":
                        host_ids = existing_hosts_and_hostgroups_by_id[mapping["mapRef"]]["host_ids"]
                        if mapping["mapRef"] in self.cache["get_mapping_by_id"].keys():
                            self.cache["get_mapping_by_id"][mapping["mapRef"]].update(map_entry)
                            self.cache["get_mapping_by_name"][mapping["mapRef"]].update(map_entry)
                        else:
                            self.cache["get_mapping_by_id"].update({mapping["mapRef"]: map_entry})
                            self.cache["get_mapping_by_name"].update({mapping["mapRef"]: map_entry})

                    for host_id in host_ids:
                        if host_id in self.cache["get_mapping_by_id"].keys():
                            self.cache["get_mapping_by_id"][mapping["mapRef"]].update(map_entry)
                            self.cache["get_mapping_by_name"][mapping["mapRef"]].update(map_entry)
                        else:
                            self.cache["get_mapping_by_id"].update({host_id: map_entry})
                            self.cache["get_mapping_by_name"].update({host_id: map_entry})
            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve all volume map definitions! Error [%s]. Array [%s]." % (error, self.ssid))

        return self.cache["get_mapping_by_id"]

    def get_mapping_by_name(self):
        """Retrieve and return a dictionary of """
        if not self.cache["get_mapping_by_name"]:
            self.get_mapping_by_id()

        return self.cache["get_mapping_by_name"]

    def get_all_concat_volumes_by_id(self):
        """Retrieve and return a dictionary of all thick and thin volumes keyed by id."""
        if not self.cache["get_all_concat_volumes_by_id"]:
            try:
                rc, concat_volumes = self.request("storage-systems/%s/repositories/concat" % self.ssid)

                for volume in concat_volumes:
                    self.cache["get_all_concat_volumes_by_id"].update({volume["id"]: volume})
            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve reserve capacity volumes! Error [%s]. Array [%s]." % (error, self.ssid))

        return self.cache["get_all_concat_volumes_by_id"]

    def get_consistency_group(self):
        """Retrieve consistency groups and return information on the expected group."""
        existing_volumes = self.get_all_volumes_by_id()

        if not self.cache["get_consistency_group"]:
            try:
                rc, consistency_groups = self.request("storage-systems/%s/consistency-groups" % self.ssid)

                for consistency_group in consistency_groups:
                    if consistency_group["label"] == self.group_name:
                        rc, member_volumes = self.request("storage-systems/%s/consistency-groups/%s/member-volumes" % (self.ssid, consistency_group["id"]))

                        self.cache["get_consistency_group"].update({"consistency_group_id": consistency_group["cgRef"],
                                                                    "alert_threshold_pct": consistency_group["fullWarnThreshold"],
                                                                    "maximum_snapshots": consistency_group["autoDeleteLimit"],
                                                                    "rollback_priority": consistency_group["rollbackPriority"],
                                                                    "reserve_capacity_full_policy": consistency_group["repFullPolicy"],
                                                                    "sequence_numbers": consistency_group["uniqueSequenceNumber"],
                                                                    "base_volumes": []})

                        for member_volume in member_volumes:
                            base_volume = existing_volumes[member_volume["volumeId"]]
                            base_volume_size_b = int(base_volume["totalSizeInBytes"])
                            total_reserve_capacity_b = int(member_volume["totalRepositoryCapacity"])
                            reserve_capacity_pct = int(round(float(total_reserve_capacity_b) / float(base_volume_size_b) * 100))

                            rc, concat = self.request("storage-systems/%s/repositories/concat/%s" % (self.ssid, member_volume["repositoryVolume"]))

                            self.cache["get_consistency_group"]["base_volumes"].append({"name": base_volume["name"],
                                                                                        "id": base_volume["id"],
                                                                                        "base_volume_size_b": base_volume_size_b,
                                                                                        "total_reserve_capacity_b": total_reserve_capacity_b,
                                                                                        "reserve_capacity_pct": reserve_capacity_pct,
                                                                                        "repository_volume_info": concat})
                        break

            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve snapshot consistency groups! Error [%s]. Array [%s]." % (error, self.ssid))

        return self.cache["get_consistency_group"]

    def get_candidate(self, volume_name, volume_info):
        """Return candidate for volume."""
        existing_storage_pools_by_id = self.get_all_storage_pools_by_id()
        existing_storage_pools_by_name = self.get_all_storage_pools_by_name()
        existing_volumes_by_name = self.get_all_volumes_by_name()

        if volume_name in existing_volumes_by_name:
            base_volume_storage_pool_id = existing_volumes_by_name[volume_name]["volumeGroupRef"]
            base_volume_storage_pool_name = existing_storage_pools_by_id[base_volume_storage_pool_id]["name"]

            preferred_reserve_storage_pool = base_volume_storage_pool_id
            if volume_info["preferred_reserve_storage_pool"]:
                if volume_info["preferred_reserve_storage_pool"] in existing_storage_pools_by_name:
                    preferred_reserve_storage_pool = existing_storage_pools_by_name[volume_info["preferred_reserve_storage_pool"]]["id"]
                else:
                    self.module.fail_json(msg="Preferred storage pool or volume group does not exist! Storage pool [%s]. Group [%s]."
                                              " Array [%s]." % (volume_info["preferred_reserve_storage_pool"], self.group_name, self.ssid))

            volume_info.update({"name": volume_name,
                                "id": existing_volumes_by_name[volume_name]["id"],
                                "storage_pool_name": base_volume_storage_pool_name,
                                "storage_pool_id": base_volume_storage_pool_id,
                                "preferred_reserve_storage_pool": preferred_reserve_storage_pool,
                                "candidate": None})

        else:
            self.module.fail_json(msg="Volume does not exist! Volume [%s]. Group [%s]. Array [%s]." % (volume_name, self.group_name, self.ssid))

        candidate_request = {"candidateRequest": {"baseVolumeRef": volume_info["id"],
                                                  "percentCapacity": volume_info["reserve_capacity_pct"],
                                                  "concatVolumeType": "snapshot"}}
        try:
            rc, candidates = self.request("storage-systems/%s/repositories/concat/single" % self.ssid, method="POST", data=candidate_request)
            for candidate in candidates:
                if candidate["volumeGroupId"] == volume_info["preferred_reserve_storage_pool"]:
                    volume_info["candidate"] = candidate
                    break
            else:
                self.module.fail_json(msg="Failed to retrieve capacity volume candidate in preferred storage pool or volume group!"
                                          " Volume [%s]. Group [%s]. Array [%s]." % (volume_info["name"], self.group_name, self.ssid))
        except Exception as error:
            self.module.fail_json(msg="Failed to get reserve capacity candidates!"
                                      " Volumes %s. Group [%s]. Array [%s]. Error [%s]" % (volume_info["name"], self.group_name, self.ssid, error))

        return volume_info

    def get_pit_images_metadata(self):
        """Retrieve and return consistency group snapshot images' metadata keyed on timestamps."""
        if not self.cache["get_pit_images_metadata"]:
            try:
                rc, key_values = self.request(self.url_path_prefix + "key-values")

                for entry in key_values:
                    if re.search("ansible\\|%s\\|" % self.group_name, entry["key"]):
                        name = entry["key"].replace("ansible|%s|" % self.group_name, "")
                        values = entry["value"].split("|")
                        if len(values) == 3:
                            timestamp, image_id, description = values
                            self.cache["get_pit_images_metadata"].update({timestamp: {"name": name, "description": description}})

            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve consistency group snapshot images metadata!  Array [%s]. Error [%s]." % (self.ssid, error))

        return self.cache["get_pit_images_metadata"]

    def get_pit_images_by_timestamp(self):
        """Retrieve and return snapshot images."""
        if not self.cache["get_pit_images_by_timestamp"]:
            group_id = self.get_consistency_group()["consistency_group_id"]
            images_metadata = self.get_pit_images_metadata()
            existing_volumes_by_id = self.get_all_volumes_by_id()

            try:
                rc, images = self.request("storage-systems/%s/consistency-groups/%s/snapshots" % (self.ssid, group_id))
                for image_info in images:

                    metadata = {"id": "", "name": "", "description": ""}
                    if image_info["pitTimestamp"] in images_metadata.keys():
                        metadata = images_metadata[image_info["pitTimestamp"]]

                    timestamp = datetime.fromtimestamp(int(image_info["pitTimestamp"]))
                    info = {"id": image_info["id"],
                            "name": metadata["name"],
                            "timestamp": timestamp,
                            "description": metadata["description"],
                            "sequence_number": image_info["pitSequenceNumber"],
                            "base_volume_id": image_info["baseVol"],
                            "base_volume_name": existing_volumes_by_id[image_info["baseVol"]]["name"],
                            "image_info": image_info}

                    if timestamp not in self.cache["get_pit_images_by_timestamp"].keys():
                        self.cache["get_pit_images_by_timestamp"].update({timestamp: {"sequence_number": image_info["pitSequenceNumber"], "images": [info]}})
                        if metadata["name"]:
                            self.cache["get_pit_images_by_name"].update({metadata["name"]: {"sequence_number": image_info["pitSequenceNumber"],
                                                                                            "images": [info]}})
                    else:
                        self.cache["get_pit_images_by_timestamp"][timestamp]["images"].append(info)
                        if metadata["name"]:
                            self.cache["get_pit_images_by_name"][metadata["name"]]["images"].append(info)

            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve consistency group snapshot images!"
                                          " Group [%s]. Array [%s]. Error [%s]." % (self.group_name, self.ssid, error))

        return self.cache["get_pit_images_by_timestamp"]

    def get_pit_images_by_name(self):
        """Retrieve and return snapshot images."""
        if not self.cache["get_pit_images_by_name"]:
            self.get_pit_images_by_timestamp()

        return self.cache["get_pit_images_by_name"]

    def get_unused_pit_key(self):
        """Determine all embedded pit key-values that do not match existing snapshot images."""
        if not self.cache["get_unused_pit_key_values"]:
            try:
                rc, images = self.request("storage-systems/%s/snapshot-images" % self.ssid)
                rc, key_values = self.request("key-values")

                for key_value in key_values:
                    key = key_value["key"]
                    value = key_value["value"]
                    if re.match("ansible\\|.*\\|.*", value):
                        for image in images:
                            if str(image["pitTimestamp"]) == value.split("|")[0]:
                                break
                        else:
                            self.cache["get_unused_pit_key_values"].append(key)
            except Exception as error:
                self.module.warn("Failed to retrieve all snapshots to determine all key-value pairs that do no match a point-in-time snapshot images!"
                                 " Array [%s]. Error [%s]." % (self.ssid, error))

        return self.cache["get_unused_pit_key_values"]

    def get_pit_info(self):
        """Determine consistency group's snapshot images base on provided arguments (pit_name or timestamp)."""

        def _check_timestamp(timestamp):
            """Check whether timestamp matches I(pit_timestamp)"""
            return (self.pit_timestamp.year == timestamp.year and
                    self.pit_timestamp.month == timestamp.month and
                    self.pit_timestamp.day == timestamp.day and
                    (self.pit_timestamp_tokens < 4 or self.pit_timestamp.hour == timestamp.hour) and
                    (self.pit_timestamp_tokens < 5 or self.pit_timestamp.minute == timestamp.minute) and
                    (self.pit_timestamp_tokens < 6 or self.pit_timestamp.second == timestamp.second))

        if self.cache["get_pit_info"] is None:
            group = self.get_consistency_group()
            pit_images_by_timestamp = self.get_pit_images_by_timestamp()
            pit_images_by_name = self.get_pit_images_by_name()

            if self.pit_name:
                if self.pit_name in pit_images_by_name.keys():
                    self.cache["get_pit_info"] = pit_images_by_name[self.pit_name]

                    if self.pit_timestamp:
                        for image in self.cache["get_pit_info"]["images"]:
                            if not _check_timestamp(image["timestamp"]):
                                self.module.fail_json(msg="Snapshot image does not exist that matches both name and supplied timestamp!"
                                                          " Group [%s]. Image [%s]. Array [%s]." % (self.group_name, image, self.ssid))
            elif self.pit_timestamp and pit_images_by_timestamp:
                sequence_number = None
                if self.pit_timestamp == "newest":
                    sequence_number = group["sequence_numbers"][-1]

                    for image_timestamp in pit_images_by_timestamp.keys():
                        if int(pit_images_by_timestamp[image_timestamp]["sequence_number"]) == int(sequence_number):
                            self.cache["get_pit_info"] = pit_images_by_timestamp[image_timestamp]
                            break
                elif self.pit_timestamp == "oldest":
                    sequence_number = group["sequence_numbers"][0]
                    for image_timestamp in pit_images_by_timestamp.keys():
                        if int(pit_images_by_timestamp[image_timestamp]["sequence_number"]) == int(sequence_number):
                            self.cache["get_pit_info"] = pit_images_by_timestamp[image_timestamp]
                            break
                else:
                    for image_timestamp in pit_images_by_timestamp.keys():
                        if _check_timestamp(image_timestamp):
                            if sequence_number and sequence_number != pit_images_by_timestamp[image_timestamp]["sequence_number"]:
                                self.module.fail_json(msg="Multiple snapshot images match the provided timestamp and do not have the same sequence number!"
                                                          " Group [%s]. Array [%s]." % (self.group_name, self.ssid))

                            sequence_number = pit_images_by_timestamp[image_timestamp]["sequence_number"]
                            self.cache["get_pit_info"] = pit_images_by_timestamp[image_timestamp]

        if self.state != "absent" and self.type != "pit" and self.cache["get_pit_info"] is None:
            self.module.fail_json(msg="Snapshot consistency group point-in-time image does not exist! Name [%s]. Timestamp [%s]. Group [%s]."
                                      " Array [%s]." % (self.pit_name, self.pit_timestamp, self.group_name, self.ssid))

        return self.cache["get_pit_info"]

    def create_changes_required(self):
        """Determine the required state changes for creating a new consistency group."""
        changes = {"create_group": {"name": self.group_name,
                                    "alert_threshold_pct": self.alert_threshold_pct,
                                    "maximum_snapshots": self.maximum_snapshots,
                                    "reserve_capacity_full_policy": self.reserve_capacity_full_policy,
                                    "rollback_priority": self.rollback_priority},
                   "add_volumes": self.volumes}

        return changes

    def update_changes_required(self):
        """Determine the required state changes for updating an existing consistency group."""
        group = self.get_consistency_group()
        changes = {"update_group": {},
                   "add_volumes": [],
                   "remove_volumes": [],
                   "expand_reserve_capacity": [],
                   "trim_reserve_capacity": []}

        # Check if consistency group settings need to be updated.
        if group["alert_threshold_pct"] != self.alert_threshold_pct:
            changes["update_group"].update({"alert_threshold_pct": self.alert_threshold_pct})
        if group["maximum_snapshots"] != self.maximum_snapshots:
            changes["update_group"].update({"maximum_snapshots": self.maximum_snapshots})
        if group["rollback_priority"] != self.rollback_priority:
            changes["update_group"].update({"rollback_priority": self.rollback_priority})
        if group["reserve_capacity_full_policy"] != self.reserve_capacity_full_policy:
            changes["update_group"].update({"reserve_capacity_full_policy": self.reserve_capacity_full_policy})

        # Check if base volumes need to be added or removed from consistency group.
        # remaining_base_volumes = {base_volumes["name"]: base_volumes for base_volumes in group["base_volumes"]}  # NOT python2.6 compatible
        remaining_base_volumes = dict((base_volumes["name"], base_volumes) for base_volumes in group["base_volumes"])
        add_volumes = {}
        expand_volumes = {}

        for volume_name, volume_info in self.volumes.items():
            reserve_capacity_pct = volume_info["reserve_capacity_pct"]
            if volume_name in remaining_base_volumes:

                # Check if reserve capacity needs to be expanded or trimmed.
                base_volume_reserve_capacity_pct = remaining_base_volumes[volume_name]["reserve_capacity_pct"]
                if reserve_capacity_pct > base_volume_reserve_capacity_pct:
                    expand_reserve_capacity_pct = reserve_capacity_pct - base_volume_reserve_capacity_pct
                    expand_volumes.update({volume_name: {"reserve_capacity_pct": expand_reserve_capacity_pct,
                                                         "preferred_reserve_storage_pool": volume_info["preferred_reserve_storage_pool"],
                                                         "reserve_volume_id": remaining_base_volumes[volume_name]["repository_volume_info"]["id"]}})

                elif reserve_capacity_pct < base_volume_reserve_capacity_pct:
                    existing_volumes_by_id = self.get_all_volumes_by_id()
                    existing_volumes_by_name = self.get_all_volumes_by_name()
                    existing_concat_volumes_by_id = self.get_all_concat_volumes_by_id()
                    trim_pct = base_volume_reserve_capacity_pct - reserve_capacity_pct

                    # Check whether there are any snapshot images; if there are then throw an exception indicating that a trim operation
                    #   cannot be done when snapshots exist.
                    for timestamp, image in self.get_pit_images_by_timestamp():
                        if existing_volumes_by_id(image["base_volume_id"])["name"] == volume_name:
                            self.module.fail_json(msg="Reserve capacity cannot be trimmed when snapshot images exist for base volume!"
                                                      " Base volume [%s]. Group [%s]. Array [%s]." % (volume_name, self.group_name, self.ssid))

                    # Collect information about all that needs to be trimmed to meet or exceed required trim percentage.
                    concat_volume_id = remaining_base_volumes[volume_name]["repository_volume_info"]["id"]
                    concat_volume_info = existing_concat_volumes_by_id[concat_volume_id]
                    base_volume_info = existing_volumes_by_name[volume_name]
                    base_volume_size_bytes = int(base_volume_info["totalSizeInBytes"])

                    total_member_volume_size_bytes = 0
                    member_volumes_to_trim = []
                    for trim_count, member_volume_id in enumerate(reversed(concat_volume_info["memberRefs"][1:])):
                        member_volume_info = existing_volumes_by_id[member_volume_id]
                        member_volumes_to_trim.append(member_volume_info)

                        total_member_volume_size_bytes += int(member_volume_info["totalSizeInBytes"])
                        total_trimmed_size_pct = round(total_member_volume_size_bytes / base_volume_size_bytes * 100)

                        if total_trimmed_size_pct >= trim_pct:
                            changes["trim_reserve_capacity"].append({"concat_volume_id": concat_volume_id, "trim_count": trim_count + 1})

                            # Expand after trim if needed.
                            if total_trimmed_size_pct > trim_pct:
                                expand_reserve_capacity_pct = total_trimmed_size_pct - trim_pct
                                expand_volumes.update({volume_name: {"reserve_capacity_pct": expand_reserve_capacity_pct,
                                                                     "preferred_reserve_storage_pool": volume_info["preferred_reserve_storage_pool"],
                                                                     "reserve_volume_id": remaining_base_volumes[volume_name]["repository_volume_info"]["id"]}})
                            break
                    else:
                        initial_reserve_volume_info = existing_volumes_by_id[concat_volume_info["memberRefs"][0]]
                        minimum_capacity_pct = round(int(initial_reserve_volume_info["totalSizeInBytes"]) / base_volume_size_bytes * 100)
                        self.module.fail_json(msg="Cannot delete initial reserve capacity volume! Minimum reserve capacity percent [%s]. Base volume [%s]. "
                                                  "Group [%s]. Array [%s]." % (minimum_capacity_pct, volume_name, self.group_name, self.ssid))

                remaining_base_volumes.pop(volume_name)
            else:
                add_volumes.update({volume_name: {"reserve_capacity_pct": reserve_capacity_pct,
                                                  "preferred_reserve_storage_pool": volume_info["preferred_reserve_storage_pool"]}})

        changes["add_volumes"] = add_volumes
        changes["expand_reserve_capacity"] = expand_volumes
        changes["remove_volumes"] = remaining_base_volumes
        return changes

    def get_consistency_group_view(self):
        """Determine and return consistency group view."""
        group_id = self.get_consistency_group()["consistency_group_id"]

        if not self.cache["get_consistency_group_view"]:
            try:
                rc, views = self.request("storage-systems/%s/consistency-groups/%s/views" % (self.ssid, group_id))

                # Check for existing view (collection of snapshot volumes for a consistency group) within consistency group.
                for view in views:
                    if view["name"] == self.view_name:
                        self.cache["get_consistency_group_view"] = view
                        self.cache["get_consistency_group_view"].update({"snapshot_volumes": []})

                        # Determine snapshot volumes associated with view.
                        try:
                            rc, snapshot_volumes = self.request("storage-systems/%s/snapshot-volumes" % self.ssid)

                            for snapshot_volume in snapshot_volumes:
                                if (snapshot_volume["membership"] and
                                        snapshot_volume["membership"]["viewType"] == "member" and
                                        snapshot_volume["membership"]["cgViewRef"] == view["cgViewRef"]):
                                    self.cache["get_consistency_group_view"]["snapshot_volumes"].append(snapshot_volume)
                        except Exception as error:
                            self.module.fail_json(msg="Failed to retrieve host mapping information!."
                                                      " Group [%s]. Array [%s]. Error [%s]." % (self.group_name, self.ssid, error))
            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve consistency group's views!"
                                          " Group [%s]. Array [%s]. Error [%s]." % (self.group_name, self.ssid, error))

        return self.cache["get_consistency_group_view"]

    def create_view_changes_required(self):
        """Determine whether snapshot consistency group point-in-time view needs to be created."""
        changes = {}
        snapshot_images_info = self.get_pit_info()
        changes.update({"name": self.view_name,
                        "sequence_number": snapshot_images_info["sequence_number"],
                        "images": snapshot_images_info["images"],
                        "volumes": self.volumes})

        return changes

    def update_view_changes_required(self):
        """Determine the changes required for snapshot consistency group point-in-time view."""
        changes = {"expand_reserve_capacity": [],
                   "trim_reserve_capacity": [],
                   "map_snapshot_volumes_mapping": [],
                   "unmap_snapshot_volumes_mapping": [],
                   "move_snapshot_volumes_mapping": [],
                   "update_snapshot_volumes_writable": []}
        view = self.get_consistency_group_view()
        host_objects_by_name = self.get_all_hosts_and_hostgroups_by_name()
        host_objects_by_id = self.get_all_hosts_and_hostgroups_by_id()
        existing_volumes_by_id = self.get_all_volumes_by_id()
        if view:
            if len(view["snapshot_volumes"]) != len(self.volumes):
                self.module.fail_json(msg="Cannot add or remove snapshot volumes once view is created! Group [%s]. Array [%s]." % (self.group_name, self.ssid))

            expand_volumes = {}
            writable_volumes = {}
            for snapshot_volume in view["snapshot_volumes"]:
                for volume_name, volume_info in self.volumes.items():
                    if existing_volumes_by_id[snapshot_volume["baseVol"]]["name"] == volume_name:

                        # Check snapshot volume needs mapped to host or hostgroup.
                        if volume_info["snapshot_volume_host"] and not snapshot_volume["listOfMappings"]:
                            changes["map_snapshot_volumes_mapping"].append({"mappableObjectId": snapshot_volume["id"],
                                                                            "lun": volume_info["snapshot_volume_lun"],
                                                                            "targetId": host_objects_by_name[volume_info["snapshot_volume_host"]]["id"]})

                        # Check snapshot volume needs unmapped to host or hostgroup.
                        elif not volume_info["snapshot_volume_host"] and snapshot_volume["listOfMappings"]:
                            changes["unmap_snapshot_volumes_mapping"].append({"snapshot_volume_name": snapshot_volume["name"],
                                                                              "lun_mapping_reference": snapshot_volume["listOfMappings"][0]["lunMappingRef"]})

                        # Check host mapping needs moved
                        elif (snapshot_volume["listOfMappings"] and
                              ((volume_info["snapshot_volume_host"] != host_objects_by_id[snapshot_volume["listOfMappings"][0]["mapRef"]]["name"]) or
                               (volume_info["snapshot_volume_lun"] != snapshot_volume["listOfMappings"][0]["lun"]))):
                            changes["move_snapshot_volumes_mapping"].append({"lunMappingRef": snapshot_volume["listOfMappings"][0]["lunMappingRef"],
                                                                             "lun": volume_info["snapshot_volume_lun"],
                                                                             "mapRef": host_objects_by_name[volume_info["snapshot_volume_host"]]["id"]})
                        # Check writable mode
                        if volume_info["snapshot_volume_writable"] != (snapshot_volume["accessMode"] == "readWrite"):
                            volume_info.update({"snapshot_volume_id": snapshot_volume["id"]})
                            writable_volumes.update({volume_name: volume_info})

                        # Check reserve capacity.
                        if volume_info["snapshot_volume_writable"] and snapshot_volume["accessMode"] == "readWrite":
                            current_reserve_capacity_pct = int(round(float(snapshot_volume["repositoryCapacity"]) /
                                                                     float(snapshot_volume["baseVolumeCapacity"]) * 100))
                            if volume_info["reserve_capacity_pct"] > current_reserve_capacity_pct:
                                expand_reserve_capacity_pct = volume_info["reserve_capacity_pct"] - current_reserve_capacity_pct
                                expand_volumes.update({volume_name: {"reserve_capacity_pct": expand_reserve_capacity_pct,
                                                                     "preferred_reserve_storage_pool": volume_info["preferred_reserve_storage_pool"],
                                                                     "reserve_volume_id": snapshot_volume["repositoryVolume"]}})

                            elif volume_info["reserve_capacity_pct"] < current_reserve_capacity_pct:
                                existing_volumes_by_id = self.get_all_volumes_by_id()
                                existing_volumes_by_name = self.get_all_volumes_by_name()
                                existing_concat_volumes_by_id = self.get_all_concat_volumes_by_id()
                                trim_pct = current_reserve_capacity_pct - volume_info["reserve_capacity_pct"]

                                # Collect information about all that needs to be trimmed to meet or exceed required trim percentage.
                                concat_volume_id = snapshot_volume["repositoryVolume"]
                                concat_volume_info = existing_concat_volumes_by_id[concat_volume_id]
                                base_volume_info = existing_volumes_by_name[volume_name]
                                base_volume_size_bytes = int(base_volume_info["totalSizeInBytes"])

                                total_member_volume_size_bytes = 0
                                member_volumes_to_trim = []
                                for trim_count, member_volume_id in enumerate(reversed(concat_volume_info["memberRefs"][1:])):
                                    member_volume_info = existing_volumes_by_id[member_volume_id]
                                    member_volumes_to_trim.append(member_volume_info)

                                    total_member_volume_size_bytes += int(member_volume_info["totalSizeInBytes"])
                                    total_trimmed_size_pct = round(total_member_volume_size_bytes / base_volume_size_bytes * 100)

                                    if total_trimmed_size_pct >= trim_pct:
                                        changes["trim_reserve_capacity"].append({"concat_volume_id": concat_volume_id, "trim_count": trim_count + 1})

                                        # Expand after trim if needed.
                                        if total_trimmed_size_pct > trim_pct:
                                            expand_reserve_capacity_pct = total_trimmed_size_pct - trim_pct
                                            expand_volumes.update({
                                                volume_name: {"reserve_capacity_pct": expand_reserve_capacity_pct,
                                                              "preferred_reserve_storage_pool": volume_info["preferred_reserve_storage_pool"],
                                                              "reserve_volume_id": snapshot_volume["repositoryVolume"]}})
                                        break
                                else:
                                    initial_reserve_volume_info = existing_volumes_by_id[concat_volume_info["memberRefs"][0]]
                                    minimum_capacity_pct = round(int(initial_reserve_volume_info["totalSizeInBytes"]) / base_volume_size_bytes * 100)
                                    self.module.fail_json(msg="Cannot delete initial reserve capacity volume! Minimum reserve capacity percent [%s]. "
                                                              "Base volume [%s]. Group [%s]. Array [%s]." % (minimum_capacity_pct, volume_name,
                                                                                                             self.group_name, self.ssid))
            changes.update({"expand_reserve_capacity": expand_volumes,
                            "update_snapshot_volumes_writable": writable_volumes})
        return changes

    def rollback_changes_required(self):
        """Determine the changes required for snapshot consistency group point-in-time rollback."""
        return self.get_pit_info()

    def remove_snapshot_consistency_group(self, info):
        """remove a new snapshot consistency group."""
        try:
            rc, resp = self.request("storage-systems/%s/consistency-groups/%s" % (self.ssid, info["consistency_group_id"]), method="DELETE")
        except Exception as error:
            self.module.fail_json(msg="Failed to remove snapshot consistency group! Group [%s]. Array [%s]." % (self.group_name, self.ssid))

    def create_snapshot_consistency_group(self, group_info):
        """Create a new snapshot consistency group."""
        consistency_group_request = {"name": self.group_name,
                                     "fullWarnThresholdPercent": group_info["alert_threshold_pct"],
                                     "autoDeleteThreshold": group_info["maximum_snapshots"],
                                     "repositoryFullPolicy": group_info["reserve_capacity_full_policy"],
                                     "rollbackPriority": group_info["rollback_priority"]}

        try:
            rc, group = self.request("storage-systems/%s/consistency-groups" % self.ssid, method="POST", data=consistency_group_request)
            self.cache["get_consistency_group"].update({"consistency_group_id": group["cgRef"]})
        except Exception as error:
            self.module.fail_json(msg="Failed to remove snapshot consistency group! Group [%s]. Array [%s]." % (self.group_name, self.ssid))

    def update_snapshot_consistency_group(self, group_info):
        """Create a new snapshot consistency group."""
        group_id = self.get_consistency_group()["consistency_group_id"]
        consistency_group_request = {"name": self.group_name}
        if "alert_threshold_pct" in group_info.keys():
            consistency_group_request.update({"fullWarnThresholdPercent": group_info["alert_threshold_pct"]})
        if "maximum_snapshots" in group_info.keys():
            consistency_group_request.update({"autoDeleteThreshold": group_info["maximum_snapshots"]})
        if "reserve_capacity_full_policy" in group_info.keys():
            consistency_group_request.update({"repositoryFullPolicy": group_info["reserve_capacity_full_policy"]})
        if "rollback_priority" in group_info.keys():
            consistency_group_request.update({"rollbackPriority": group_info["rollback_priority"]})

        try:
            rc, group = self.request("storage-systems/%s/consistency-groups/%s" % (self.ssid, group_id), method="POST", data=consistency_group_request)
            return group["cgRef"]
        except Exception as error:
            self.module.fail_json(msg="Failed to remove snapshot consistency group! Group [%s]. Array [%s]." % (self.group_name, self.ssid))

    def add_base_volumes(self, volumes):
        """Add base volume(s) to the consistency group."""
        group_id = self.get_consistency_group()["consistency_group_id"]
        member_volume_request = {"volumeToCandidates": {}}

        for volume_name, volume_info in volumes.items():
            candidate = self.get_candidate(volume_name, volume_info)
            member_volume_request["volumeToCandidates"].update({volume_info["id"]: candidate["candidate"]["candidate"]})

        try:
            rc, resp = self.request("storage-systems/%s/consistency-groups/%s/member-volumes/batch" % (self.ssid, group_id),
                                    method="POST", data=member_volume_request)
        except Exception as error:
            self.module.fail_json(msg="Failed to add reserve capacity volume! Base volumes %s. Group [%s]. Error [%s]."
                                      " Array [%s]." % (", ".join(volume for volume in member_volume_request.keys()), self.group_name, error, self.ssid))

    def remove_base_volumes(self, volume_info_list):
        """Add base volume(s) to the consistency group."""
        group_id = self.get_consistency_group()["consistency_group_id"]

        for name, info in volume_info_list.items():
            try:
                rc, resp = self.request("storage-systems/%s/consistency-groups/%s/member-volumes/%s" % (self.ssid, group_id, info["id"]), method="DELETE")
            except Exception as error:
                self.module.fail_json(msg="Failed to remove reserve capacity volume! Base volume [%s]. Group [%s]. Error [%s]. "
                                          "Array [%s]." % (name, self.group_name, error, self.ssid))

    def expand_reserve_capacities(self, reserve_volumes):
        """Expand base volume(s) reserve capacity."""
        for volume_name, volume_info in reserve_volumes.items():
            candidate = self.get_candidate(volume_name, volume_info)
            expand_request = {"repositoryRef": volume_info["reserve_volume_id"],
                              "expansionCandidate": candidate["candidate"]["candidate"]}
            try:
                rc, resp = self.request("/storage-systems/%s/repositories/concat/%s/expand" % (self.ssid, volume_info["reserve_volume_id"]),
                                        method="POST", data=expand_request)
            except Exception as error:
                self.module.fail_json(msg="Failed to expand reserve capacity volume! Group [%s]. Error [%s]. Array [%s]." % (self.group_name, error, self.ssid))

    def trim_reserve_capacities(self, trim_reserve_volume_info_list):
        """trim base volume(s) reserve capacity."""
        for info in trim_reserve_volume_info_list:
            trim_request = {"concatVol": info["concat_volume_id"],
                            "trimCount": info["trim_count"],
                            "retainRepositoryMembers": False}
            try:
                rc, trim = self.request("storage-systems/%s/symbol/trimConcatVolume?verboseErrorResponse=true" % self.ssid, method="POST", data=trim_request)
            except Exception as error:
                self.module.fail_json(msg="Failed to trim reserve capacity. Group [%s]. Array [%s]. Error [%s]." % (self.group_name, self.ssid, error))

    def create_pit_images(self):
        """Generate snapshot image(s) for the base volumes in the consistency group."""
        group_id = self.get_consistency_group()["consistency_group_id"]

        try:
            rc, images = self.request("storage-systems/%s/consistency-groups/%s/snapshots" % (self.ssid, group_id), method="POST")

            # Embedded web services should store the pit_image metadata since sending it to the proxy will be written to it instead.
            if self.pit_name:
                try:
                    rc, key_values = self.request(self.url_path_prefix + "key-values/ansible|%s|%s" % (self.group_name, self.pit_name), method="POST",
                                                  data="%s|%s|%s" % (images[0]["pitTimestamp"], self.pit_name, self.pit_description))
                except Exception as error:
                    self.module.fail_json(msg="Failed to create metadata for snapshot images!"
                                              " Group [%s]. Array [%s]. Error [%s]." % (self.group_name, self.ssid, error))
        except Exception as error:
            self.module.fail_json(msg="Failed to create consistency group snapshot images!"
                                      " Group [%s]. Array [%s]. Error [%s]." % (self.group_name, self.ssid, error))

    def remove_pit_images(self, pit_info):
        """Remove selected snapshot point-in-time images."""
        group_id = self.get_consistency_group()["consistency_group_id"]

        pit_sequence_number = int(pit_info["sequence_number"])
        sequence_numbers = set(int(pit_image["sequence_number"]) for timestamp, pit_image in self.get_pit_images_by_timestamp().items()
                               if int(pit_image["sequence_number"]) < pit_sequence_number)
        sequence_numbers.add(pit_sequence_number)

        for sequence_number in sorted(sequence_numbers):

            try:
                rc, images = self.request("storage-systems/%s/consistency-groups/%s/snapshots/%s" % (self.ssid, group_id, sequence_number), method="DELETE")
            except Exception as error:
                self.module.fail_json(msg="Failed to create consistency group snapshot images!"
                                          " Group [%s]. Array [%s]. Error [%s]." % (self.group_name, self.ssid, error))

        # Embedded web services should store the pit_image metadata since sending it to the proxy will be written to it instead.
        if self.pit_name:
            try:
                rc, key_values = self.request(self.url_path_prefix + "key-values/ansible|%s|%s" % (self.group_name, self.pit_name), method="DELETE")
            except Exception as error:
                self.module.fail_json(msg="Failed to delete metadata for snapshot images!"
                                          " Group [%s]. Array [%s]. Error [%s]." % (self.group_name, self.ssid, error))

    def cleanup_old_pit_metadata(self, keys):
        """Delete unused point-in-time image metadata."""
        for key in keys:
            try:
                rc, images = self.request("key-values/%s" % key, method="DELETE")
            except Exception as error:
                self.module.fail_json(msg="Failed to purge unused point-in-time image metadata! Key [%s]. Array [%s]."
                                          " Error [%s]." % (key, self.ssid, error))

    def create_view(self, view_info):
        """Generate consistency group view."""
        group_id = self.get_consistency_group()["consistency_group_id"]
        view_request = {"name": view_info["name"],
                        "pitSequenceNumber": view_info["sequence_number"],
                        "requests": []}

        for volume_name, volume_info in view_info["volumes"].items():
            candidate = None
            if volume_info["snapshot_volume_writable"]:
                candidate = self.get_candidate(volume_name, volume_info)

            for image in view_info["images"]:
                if volume_name == image["base_volume_name"]:
                    view_request["requests"].append({"pitId": image["id"],
                                                     "candidate": candidate["candidate"]["candidate"] if candidate else None,
                                                     "accessMode": "readWrite" if volume_info["snapshot_volume_writable"] else "readOnly",
                                                     "scanMedia": volume_info["snapshot_volume_validate"],
                                                     "validateParity": volume_info["snapshot_volume_validate"]})
                    break
            else:
                self.module.fail_json(msg="Base volume does not exist! Volume [%s]. Group [%s]. Array [%s]." % (volume_name, self.group_name, self.ssid))
        try:
            rc, images = self.request("storage-systems/%s/consistency-groups/%s/views/batch" % (self.ssid, group_id), method="POST", data=view_request)

            # Determine snapshot volume mappings
            view = self.get_consistency_group_view()
            existing_volumes_by_id = self.get_all_volumes_by_id()
            existing_hosts_by_name = self.get_all_hosts_and_hostgroups_by_name()
            for volume_name, volume_info in self.volumes.items():
                if volume_info["snapshot_volume_host"]:
                    for snapshot_volume in view["snapshot_volumes"]:
                        if volume_name == existing_volumes_by_id[snapshot_volume["baseVol"]]["name"]:
                            snapshot_volume_map_request = {"mappableObjectId": snapshot_volume["id"],
                                                           "lun": volume_info["snapshot_volume_lun"],
                                                           "targetId": existing_hosts_by_name[volume_info["snapshot_volume_host"]]["id"]}
                            try:
                                rc, mapping = self.request("storage-systems/%s/volume-mappings" % self.ssid, method="POST", data=snapshot_volume_map_request)
                            except Exception as error:
                                self.module.fail_json(msg="Failed to map snapshot volume! Snapshot volume [%s]. View [%s]. Group [%s]. Array [%s]."
                                                          " Error [%s]" % (snapshot_volume["name"], self.view_name, self.group_name, self.ssid, error))
                            break
        except Exception as error:
            self.module.fail_json(msg="Failed to create consistency group snapshot volumes!"
                                      " Group [%s]. Array [%s]. Error [%s]." % (self.group_name, self.ssid, error))

    def map_view(self, map_information_list):
        """Map consistency group point-in-time snapshot volumes to host or host group."""
        existing_volumes = self.get_all_volumes_by_id()
        existing_host_or_hostgroups = self.get_all_hosts_and_hostgroups_by_id()
        for map_request in map_information_list:
            try:
                rc, mapping = self.request("storage-systems/%s/volume-mappings" % self.ssid, method="POST", data=map_request)
            except Exception as error:
                self.module.fail_json(msg="Failed to map snapshot volume! Snapshot volume [%s]. Target [%s]. Lun [%s]. Group [%s]. Array [%s]."
                                          " Error [%s]." % (existing_volumes[map_request["mappableObjectId"]],
                                                            existing_host_or_hostgroups[map_request["targetId"]],
                                                            map_request["lun"], self.group_name, self.ssid, error))

    def unmap_view(self, unmap_info_list):
        """Unmap consistency group point-in-time snapshot volumes from host or host group."""
        for unmap_info in unmap_info_list:
            try:
                rc, unmap = self.request("storage-systems/%s/volume-mappings/%s" % (self.ssid, unmap_info["lun_mapping_reference"]), method="DELETE")
            except Exception as error:
                self.module.fail_json(msg="Failed to unmap snapshot volume! Snapshot volume [%s]. View [%s]. Group [%s]. Array [%s]."
                                          " Error [%s]." % (unmap_info["snapshot_volume_name"], self.view_name, self.group_name, self.ssid, error))

    def move_view_mapping(self, map_information_list):
        """Move consistency group point-in-time snapshot volumes to a different host or host group."""
        existing_volumes = self.get_all_volumes_by_id()
        existing_host_or_hostgroups = self.get_all_hosts_and_hostgroups_by_id()
        for map_request in map_information_list:
            try:
                rc, mapping = self.request("storage-systems/%s/symbol/moveLUNMapping?verboseErrorResponse=true" % self.ssid, method="POST", data=map_request)
            except Exception as error:
                self.module.fail_json(msg="Failed to move snapshot volume mapping! Snapshot volume [%s]. Target [%s]. Lun [%s]. Group [%s]. Array [%s]."
                                          " Error [%s]." % (existing_volumes[map_request["mappableObjectId"]],
                                                            existing_host_or_hostgroups[map_request["targetId"]],
                                                            map_request["lun"], self.group_name, self.ssid, error))

    def convert_view_to_writable(self, convert_view_information_list):
        """Make consistency group point-in-time snapshot volumes writable."""
        for volume_name, volume_info in convert_view_information_list.items():
            candidate = self.get_candidate(volume_name, volume_info)
            convert_request = {"fullThreshold": self.alert_threshold_pct,
                               "repositoryCandidate": candidate["candidate"]["candidate"]}
            try:
                rc, convert = self.request("/storage-systems/%s/snapshot-volumes/%s/convertReadOnly" % (self.ssid, volume_info["snapshot_volume_id"]),
                                           method="POST", data=convert_request)
            except Exception as error:
                self.module.fail_json(msg="Failed to convert snapshot volume to read/write! Snapshot volume [%s]. View [%s] Group [%s]. Array [%s]."
                                          " Error [%s]." % (volume_info["snapshot_volume_id"], self.view_name, self.group_name, self.ssid, error))

    def remove_view(self, view_id):
        """Remove a consistency group view."""
        group_id = self.get_consistency_group()["consistency_group_id"]

        try:
            rc, images = self.request("storage-systems/%s/consistency-groups/%s/views/%s" % (self.ssid, group_id, view_id), method="DELETE")
        except Exception as error:
            self.module.fail_json(msg="Failed to create consistency group snapshot volumes!"
                                      " Group [%s]. Array [%s]. Error [%s]." % (self.group_name, self.ssid, error))

    def rollback(self, rollback_info):
        """Rollback consistency group base volumes to point-in-time snapshot images."""
        group_info = self.get_consistency_group()
        group_id = group_info["consistency_group_id"]

        if self.rollback_backup:
            self.create_pit_images()

        # Ensure consistency group rollback priority is set correctly prior to rollback.
        if self.rollback_priority:
            try:
                rc, resp = self.request("storage-systems/%s/consistency-groups/%s" % (self.ssid, group_id), method="POST",
                                        data={"rollbackPriority": self.rollback_priority})
            except Exception as error:
                self.module.fail_json(msg="Failed to updated consistency group rollback priority!"
                                          " Group [%s]. Array [%s]. Error [%s]." % (self.group_name, self.ssid, error))

        try:
            rc, resp = self.request("storage-systems/%s/symbol/startPITRollback" % self.ssid, method="POST",
                                    data={"pitRef": [image["id"] for image in rollback_info["images"]]})
        except Exception as error:
            self.module.fail_json(msg="Failed to initiate rollback operations!" " Group [%s]. Array [%s]. Error [%s]." % (self.group_name, self.ssid, error))

    def complete_volume_definitions(self):
        """Determine the complete self.volumes structure."""
        group = self.get_consistency_group()

        if not self.volumes:
            for volume in group["base_volumes"]:
                self.volumes.update({volume["name"]: {"reserve_capacity_pct": self.reserve_capacity_pct,
                                                      "preferred_reserve_storage_pool": self.preferred_reserve_storage_pool,
                                                      "snapshot_volume_writable": self.view_writable,
                                                      "snapshot_volume_validate": self.view_validate,
                                                      "snapshot_volume_host": self.view_host,
                                                      "snapshot_volume_lun": None}})

        # Ensure a preferred_reserve_storage_pool has been selected
        existing_storage_pools_by_id = self.get_all_storage_pools_by_id()
        existing_storage_pools_by_name = self.get_all_storage_pools_by_name()
        existing_volumes_by_name = self.get_all_volumes_by_name()
        existing_volumes_by_id = self.get_all_volumes_by_id()
        existing_mappings = self.get_mapping_by_id()
        existing_host_and_hostgroup_by_id = self.get_all_hosts_and_hostgroups_by_id()
        existing_host_and_hostgroup_by_name = self.get_all_hosts_and_hostgroups_by_name()
        for volume_name, volume_info in self.volumes.items():
            base_volume_storage_pool_id = existing_volumes_by_name[volume_name]["volumeGroupRef"]
            base_volume_storage_pool_name = existing_storage_pools_by_id[base_volume_storage_pool_id]["name"]

            # Check storage group information.
            if not volume_info["preferred_reserve_storage_pool"]:
                volume_info["preferred_reserve_storage_pool"] = base_volume_storage_pool_name
            elif volume_info["preferred_reserve_storage_pool"] not in existing_storage_pools_by_name.keys():
                self.module.fail_json(msg="Preferred storage pool or volume group does not exist! Storage pool [%s]. Group [%s]."
                                          " Array [%s]." % (volume_info["preferred_reserve_storage_pool"], self.group_name, self.ssid))

            # Check host mapping information
            if self.state == "present" and self.type == "view":
                view_info = self.get_consistency_group_view()

                if volume_info["snapshot_volume_host"]:
                    if volume_info["snapshot_volume_host"] not in existing_host_and_hostgroup_by_name:
                        self.module.fail_json(msg="Specified host or host group does not exist! Host [%s]. Group [%s]."
                                                  " Array [%s]." % (volume_info["snapshot_volume_host"], self.group_name, self.ssid))

                    if not volume_info["snapshot_volume_lun"]:
                        if view_info:
                            for snapshot_volume in view_info["snapshot_volumes"]:
                                if snapshot_volume["listOfMappings"]:
                                    mapping = snapshot_volume["listOfMappings"][0]
                                    if (volume_name == existing_volumes_by_id[snapshot_volume["baseVol"]]["name"] and
                                            volume_info["snapshot_volume_host"] == existing_host_and_hostgroup_by_id[mapping["mapRef"]]["name"]):
                                        volume_info["snapshot_volume_lun"] = mapping["lun"]
                                        break
                            else:
                                host_id = existing_host_and_hostgroup_by_name[volume_info["snapshot_volume_host"]]["id"]
                                for next_lun in range(1, 100):

                                    if host_id not in existing_mappings.keys():
                                        existing_mappings.update({host_id: {}})

                                    if next_lun not in existing_mappings[host_id].keys():
                                        volume_info["snapshot_volume_lun"] = next_lun
                                        existing_mappings[host_id].update({next_lun: None})
                                        break

    def apply(self):
        """Apply any required snapshot state changes."""
        changes_required = False
        group = self.get_consistency_group()
        group_changes = {}

        # Determine which changes are required.
        if group:

            # Determine whether changes are required.
            if self.state == "absent":
                if self.type == "group":
                    if self.group_name:
                        changes_required = True
                elif self.type == "pit":
                    group_changes = self.get_pit_info()
                    if group_changes:
                        changes_required = True
                elif self.type == "view":
                    group_changes = self.get_consistency_group_view()
                    if group_changes:
                        changes_required = True

            elif self.state == "present":
                self.complete_volume_definitions()

                if self.type == "group":
                    group_changes = self.update_changes_required()
                    if (group_changes["update_group"] or
                            group_changes["add_volumes"] or
                            group_changes["remove_volumes"] or
                            group_changes["expand_reserve_capacity"] or
                            group_changes["trim_reserve_capacity"]):
                        changes_required = True

                elif self.type == "pit":
                    changes_required = True

                elif self.type == "view":
                    if self.get_consistency_group_view():
                        group_changes = self.update_view_changes_required()
                        if (group_changes["expand_reserve_capacity"] or
                                group_changes["trim_reserve_capacity"] or
                                group_changes["map_snapshot_volumes_mapping"] or
                                group_changes["unmap_snapshot_volumes_mapping"] or
                                group_changes["move_snapshot_volumes_mapping"] or
                                group_changes["update_snapshot_volumes_writable"]):
                            changes_required = True
                    else:
                        group_changes = self.create_view_changes_required()
                        changes_required = True

            elif self.state == "rollback":
                self.complete_volume_definitions()
                if not self.volumes:
                    for volume in group["base_volumes"]:
                        self.volumes.update({volume["name"]: None})
                group_changes = self.rollback_changes_required()
                if group_changes:
                    changes_required = True

        else:
            if self.state == "present":
                if self.type == "group":
                    self.complete_volume_definitions()
                    group_changes = self.create_changes_required()
                    changes_required = True
                elif self.type == "pit":
                    self.module.fail_json(msg="Snapshot point-in-time images cannot be taken when the snapshot consistency group does not exist!"
                                              " Group [%s]. Array [%s]." % (self.group_name, self.ssid))
                elif self.type == "view":
                    self.module.fail_json(msg="Snapshot view cannot be created when the snapshot consistency group does not exist!"
                                              " Group [%s]. Array [%s]." % (self.group_name, self.ssid))
            elif self.state == "rollback":
                self.module.fail_json(msg="Rollback operation is not available when the snapshot consistency group does not exist!"
                                          " Group [%s]. Array [%s]." % (self.group_name, self.ssid))

        # Determine if they're any key-value pairs that need to be cleaned up since snapshot pit images were deleted outside of this module.
        unused_pit_keys = self.get_unused_pit_key()

        # Apply any required changes.
        if (changes_required or unused_pit_keys) and not self.module.check_mode:
            if group:
                if self.state == "absent":
                    if self.type == "group":
                        self.remove_snapshot_consistency_group(group)
                    elif self.type == "pit":
                        self.remove_pit_images(group_changes)
                    elif self.type == "view":
                        self.remove_view(group_changes["id"])

                elif self.state == "present":

                    if self.type == "group":
                        if group_changes["update_group"]:
                            self.update_snapshot_consistency_group(group_changes["update_group"])
                        if group_changes["add_volumes"]:
                            self.add_base_volumes(group_changes["add_volumes"])
                        if group_changes["remove_volumes"]:
                            self.remove_base_volumes(group_changes["remove_volumes"])
                        if group_changes["trim_reserve_capacity"]:
                            self.trim_reserve_capacities(group_changes["trim_reserve_capacity"])
                            if group_changes["expand_reserve_capacity"]:
                                sleep(15)
                        if group_changes["expand_reserve_capacity"]:
                            self.expand_reserve_capacities(group_changes["expand_reserve_capacity"])

                    elif self.type == "pit":
                        self.create_pit_images()

                    elif self.type == "view":
                        view = self.get_consistency_group_view()
                        if view:
                            if group_changes["trim_reserve_capacity"]:
                                self.trim_reserve_capacities(group_changes["trim_reserve_capacity"])
                                if group_changes["expand_reserve_capacity"]:
                                    sleep(15)
                            if group_changes["expand_reserve_capacity"]:
                                self.expand_reserve_capacities(group_changes["expand_reserve_capacity"])
                            if group_changes["map_snapshot_volumes_mapping"]:
                                self.map_view(group_changes["map_snapshot_volumes_mapping"])
                            if group_changes["unmap_snapshot_volumes_mapping"]:
                                self.unmap_view(group_changes["unmap_snapshot_volumes_mapping"])
                            if group_changes["move_snapshot_volumes_mapping"]:
                                self.move_view_mapping(group_changes["move_snapshot_volumes_mapping"])
                            if group_changes["update_snapshot_volumes_writable"]:
                                self.convert_view_to_writable(group_changes["update_snapshot_volumes_writable"])
                        else:
                            self.create_view(group_changes)

                elif self.state == "rollback":
                    self.rollback(group_changes)

            elif self.type == "group":
                self.create_snapshot_consistency_group(group_changes["create_group"])
                self.add_base_volumes(group_changes["add_volumes"])

            if unused_pit_keys:
                self.cleanup_old_pit_metadata()

        self.module.exit_json(changed=changes_required, group_changes=group_changes, deleted_metadata_keys=unused_pit_keys)


def main():
    snapshot = NetAppESeriesSnapshot()
    snapshot.apply()


if __name__ == "__main__":
    main()
