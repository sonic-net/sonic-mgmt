#!/usr/bin/python

# Copyright: (c) 2021, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" Ansible module for managing Snapshots on Dell Technologies (Dell) PowerFlex"""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
module: snapshot
version_added: '1.0.0'
short_description: Manage Snapshots on Dell PowerFlex
description:
- Managing snapshots on PowerFlex Storage System includes
  creating, getting details, mapping/unmapping to/from SDC,
  modifying the attributes and deleting snapshot.

author:
- Akash Shendge (@shenda1) <ansible.team@dell.com>

extends_documentation_fragment:
  - dellemc.powerflex.powerflex

options:
  snapshot_name:
    description:
    - The name of the snapshot.
    - Mandatory for create operation.
    - Specify either I(snapshot_name) or I(snapshot_id) (but not both) for any operation.
    type: str
  snapshot_id:
    description:
    - The ID of the Snapshot.
    type: str
  vol_name:
    description:
    - The name of the volume for which snapshot will be taken.
    - Specify either I(vol_name) or I(vol_id) while creating snapshot.
    type: str
  vol_id:
    description:
    - The ID of the volume.
    type: str
  read_only:
    description:
    - Specifies whether mapping of the created snapshot volume will have
      read-write access or limited to read-only access.
    - If C(true), snapshot is created with read-only access.
    - If C(false), snapshot is created with read-write access.
    type: bool
  size:
    description:
    - The size of the snapshot.
    type: int
  cap_unit:
    description:
    - The unit of the volume size. It defaults to C(GB), if not specified.
    choices: ['GB' , 'TB']
    type: str
  snapshot_new_name:
    description:
    - New name of the snapshot. Used to rename the snapshot.
    type: str
  allow_multiple_mappings:
    description:
    - Specifies whether to allow multiple mappings or not.
    type: bool
  desired_retention:
    description:
    - The retention value for the Snapshot.
    - If the desired_retention is not mentioned during creation, snapshot
      will be created with unlimited retention.
    - Maximum supported desired retention is 31 days.
    type: int
  retention_unit:
    description:
    - The unit for retention. It defaults to C(hours), if not specified.
    choices: [hours, days]
    type: str
  sdc:
    description:
    - Specifies SDC parameters.
    type: list
    elements: dict
    suboptions:
      sdc_name:
        description:
        - Name of the SDC.
        - Specify either I(sdc_name), I(sdc_id) or I(sdc_ip).
        - Mutually exclusive with I(sdc_id) and I(sdc_ip).
        type: str
      sdc_id:
        description:
        - ID of the SDC.
        - Specify either I(sdc_name), I(sdc_id) or I(sdc_ip).
        - Mutually exclusive with I(sdc_name) and I(sdc_ip).
        type: str
      sdc_ip:
        description:
        - IP of the SDC.
        - Specify either I(sdc_name), I(sdc_id) or I(sdc_ip).
        - Mutually exclusive with I(sdc_id) and I(sdc_ip).
        type: str
      access_mode:
        description:
        - Define the access mode for all mappings of the snapshot.
        choices: ['READ_WRITE', 'READ_ONLY', 'NO_ACCESS']
        type: str
      bandwidth_limit:
        description:
        - Limit of snapshot network bandwidth.
        - Need to mention in multiple of 1024 Kbps.
        - To set no limit, 0 is to be passed.
        type: int
      iops_limit:
        description:
        - Limit of snapshot IOPS.
        - Minimum IOPS limit is 11 and specify 0 for unlimited iops.
        type: int
  sdc_state:
    description:
    - Mapping state of the SDC.
    choices: ['mapped', 'unmapped']
    type: str
  remove_mode:
    description:
    - Removal mode for the snapshot.
    - It defaults to C(ONLY_ME), if not specified.
    choices: ['ONLY_ME', 'INCLUDING_DESCENDANTS']
    type: str
  state:
    description:
    - State of the snapshot.
    choices: ['present', 'absent']
    required: true
    type: str
notes:
  - The I(check_mode) is not supported.
'''

EXAMPLES = r'''
- name: Create snapshot
  dellemc.powerflex.snapshot:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_name: "ansible_snapshot"
    vol_name: "ansible_volume"
    read_only: false
    desired_retention: 2
    state: "present"

- name: Get snapshot details using snapshot id
  dellemc.powerflex.snapshot:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_id: "fe6cb28200000007"
    state: "present"

- name: Map snapshot to SDC
  dellemc.powerflex.snapshot:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_id: "fe6cb28200000007"
    sdc:
      - sdc_ip: "198.10.xxx.xxx"
      - sdc_id: "663ac0d200000001"
    allow_multiple_mappings: true
    sdc_state: "mapped"
    state: "present"

- name: Modify the attributes of SDC mapped to snapshot
  dellemc.powerflex.snapshot:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_id: "fe6cb28200000007"
    sdc:
      - sdc_ip: "198.10.xxx.xxx"
        iops_limit: 11
        bandwidth_limit: 4096
      - sdc_id: "663ac0d200000001"
        iops_limit: 20
        bandwidth_limit: 2048
    allow_multiple_mappings: true
    sdc_state: "mapped"
    state: "present"

- name: Extend the size of snapshot
  dellemc.powerflex.snapshot:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_id: "fe6cb28200000007"
    size: 16
    state: "present"

- name: Unmap SDCs from snapshot
  dellemc.powerflex.snapshot:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_id: "fe6cb28200000007"
    sdc:
      - sdc_ip: "198.10.xxx.xxx"
      - sdc_id: "663ac0d200000001"
    sdc_state: "unmapped"
    state: "present"

- name: Rename snapshot
  dellemc.powerflex.snapshot:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_id: "fe6cb28200000007"
    snapshot_new_name: "ansible_renamed_snapshot_10"
    state: "present"

- name: Delete snapshot
  dellemc.powerflex.snapshot:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_id: "fe6cb28200000007"
    remove_mode: "ONLY_ME"
    state: "absent"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: 'false'

snapshot_details:
    description: Details of the snapshot.
    returned: When snapshot exists
    type: dict
    contains:
        ancestorVolumeId:
            description: The ID of the root of the specified volume's V-Tree.
            type: str
        ancestorVolumeName:
            description: The name of the root of the specified volume's V-Tree.
            type: str
        creationTime:
            description: The creation time of the snapshot.
            type: int
        id:
            description: The ID of the snapshot.
            type: str
        mappedSdcInfo:
            description: The details of the mapped SDC.
            type: dict
            contains:
                sdcId:
                    description: ID of the SDC.
                    type: str
                sdcName:
                    description: Name of the SDC.
                    type: str
                sdcIp:
                    description: IP of the SDC.
                    type: str
                accessMode:
                    description: Mapping access mode for the specified snapshot.
                    type: str
                limitIops:
                    description: IOPS limit for the SDC.
                    type: int
                limitBwInMbps:
                    description: Bandwidth limit for the SDC.
                    type: int
        name:
            description: Name of the snapshot.
            type: str
        secureSnapshotExpTime:
            description: Expiry time of the snapshot.
            type: int
        sizeInKb:
            description: Size of the snapshot.
            type: int
        sizeInGb:
            description: Size of the snapshot.
            type: int
        retentionInHours:
            description: Retention of the snapshot in hours.
            type: int
        storagePoolId:
            description: The ID of the Storage pool in which snapshot resides.
            type: str
        storagePoolName:
            description: The name of the Storage pool in which snapshot resides.
            type: str
    sample: {
        "accessModeLimit": "ReadOnly",
        "ancestorVolumeId": "cdd883cf00000002",
        "ancestorVolumeName": "ansible-volume-1",
        "autoSnapshotGroupId": null,
        "compressionMethod": "Invalid",
        "consistencyGroupId": "22f1e80c00000001",
        "creationTime": 1631619229,
        "dataLayout": "MediumGranularity",
        "id": "cdd883d000000004",
        "links": [
            {
                "href": "/api/instances/Volume::cdd883d000000004",
                "rel": "self"
            },
            {
                "href": "/api/instances/Volume::cdd883d000000004/relationships
                        /Statistics",
                "rel": "/api/Volume/relationship/Statistics"
            },
            {
                "href": "/api/instances/Volume::cdd883cf00000002",
                "rel": "/api/parent/relationship/ancestorVolumeId"
            },
            {
                "href": "/api/instances/VTree::6e86255c00000001",
                "rel": "/api/parent/relationship/vtreeId"
            },
            {
                "href": "/api/instances/StoragePool::e0d8f6c900000000",
                "rel": "/api/parent/relationship/storagePoolId"
            }
        ],
        "lockedAutoSnapshot": false,
        "lockedAutoSnapshotMarkedForRemoval": false,
        "managedBy": "ScaleIO",
        "mappedSdcInfo": null,
        "name": "ansible_vol_snap_1",
        "notGenuineSnapshot": false,
        "originalExpiryTime": 0,
        "pairIds": null,
        "replicationJournalVolume": false,
        "replicationTimeStamp": 0,
        "retentionInHours": 0,
        "retentionLevels": [],
        "secureSnapshotExpTime": 0,
        "sizeInGb": 16,
        "sizeInKb": 16777216,
        "snplIdOfAutoSnapshot": null,
        "snplIdOfSourceVolume": null,
        "storagePoolId": "e0d8f6c900000000",
        "storagePoolName": "pool1",
        "timeStampIsAccurate": false,
        "useRmcache": false,
        "volumeReplicationState": "UnmarkedForReplication",
        "volumeType": "Snapshot",
        "vtreeId": "6e86255c00000001"
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell\
    import utils
from datetime import datetime, timedelta
import time
import copy

LOG = utils.get_logger('snapshot')


class PowerFlexSnapshot(object):
    """Class with Snapshot operations"""

    def __init__(self):
        """ Define all parameters required by this module"""
        self.module_params = utils.get_powerflex_gateway_host_parameters()
        self.module_params.update(get_powerflex_snapshot_parameters())

        mutually_exclusive = [['snapshot_name', 'snapshot_id'],
                              ['vol_name', 'vol_id'],
                              ['snapshot_id', 'vol_name'],
                              ['snapshot_id', 'vol_id']]

        required_together = [['sdc', 'sdc_state']]

        required_one_of = [['snapshot_name', 'snapshot_id']]

        # initialize the Ansible module
        self.module = AnsibleModule(
            argument_spec=self.module_params,
            supports_check_mode=False,
            mutually_exclusive=mutually_exclusive,
            required_together=required_together,
            required_one_of=required_one_of)

        utils.ensure_required_libs(self.module)

        try:
            self.powerflex_conn = utils.get_powerflex_gateway_host_connection(
                self.module.params)
            LOG.info("Got the PowerFlex system connection object instance")
        except Exception as e:
            LOG.error(str(e))
            self.module.fail_json(msg=str(e))

    def get_storage_pool(self, storage_pool_id):
        """Get storage pool details
            :param storage_pool_id: The storage pool id
            :return: Storage pool details
        """

        try:
            return self.powerflex_conn.storage_pool.get(
                filter_fields={'id': storage_pool_id})

        except Exception as e:
            errormsg = "Failed to get the storage pool %s with error " \
                       "%s" % (storage_pool_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_snapshot(self, snapshot_name=None, snapshot_id=None):
        """Get snapshot details
            :param snapshot_name: Name of the snapshot
            :param snapshot_id: ID of the snapshot
            :return: Details of snapshot if exist.
        """

        id_or_name = snapshot_id if snapshot_id else snapshot_name

        try:
            filters = {'id': snapshot_id}
            if snapshot_name:
                filters = {'name': snapshot_name}
            snapshot_details = self.powerflex_conn.volume.get(
                filter_fields=filters)

            if len(snapshot_details) == 0:
                msg = "Snapshot with identifier %s is not found" % id_or_name
                LOG.error(msg)
                return None

            if len(snapshot_details) > 1:
                errormsg = "Multiple instances of snapshot " \
                           "exist with name {0}".format(snapshot_name)
                self.module.fail_json(msg=errormsg)

            # Add ancestor volume name
            self.add_ancestor(snapshot_details)

            # Add size in GB
            self.add_size_in_kb(snapshot_details)

            # Add storage pool name
            self.add_storage_pool_name(snapshot_details)

            # Add retention in hours
            self.add_retention_in_hours(snapshot_details)

            # Match volume details with snapshot details
            if any([self.module.params['vol_name'],
                    self.module.params['vol_id']]):
                self.match_vol_details(snapshot_details[0])
            return snapshot_details[0]
        except Exception as e:
            errormsg = "Failed to get the snapshot %s with error %s" % (
                id_or_name, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def add_retention_in_hours(self, snapshot_details):
        if 'secureSnapshotExpTime' in snapshot_details[0] and\
                'creationTime' in snapshot_details[0]:
            if snapshot_details[0]['secureSnapshotExpTime'] != 0:
                expiry_obj = datetime.fromtimestamp(
                    snapshot_details[0]['secureSnapshotExpTime'])
                creation_obj = datetime.fromtimestamp(
                    snapshot_details[0]['creationTime'])
                # Get datetime diff in hours
                td_hour = int(round(get_datetime_diff_in_minuets(expiry_obj, creation_obj) / 60))
                snapshot_details[0]['retentionInHours'] = td_hour
            else:
                snapshot_details[0]['retentionInHours'] = 0

    def add_storage_pool_name(self, snapshot_details):
        if 'storagePoolId' in snapshot_details[0] and \
                snapshot_details[0]['storagePoolId']:
            sp = self.get_storage_pool(snapshot_details[0]['storagePoolId'])
            if len(sp) > 0:
                snapshot_details[0]['storagePoolName'] = sp[0]['name']

    def add_size_in_kb(self, snapshot_details):
        if 'sizeInKb' in snapshot_details[0] and \
                snapshot_details[0]['sizeInKb']:
            snapshot_details[0]['sizeInGb'] = utils.get_size_in_gb(
                snapshot_details[0]['sizeInKb'], 'KB')

    def add_ancestor(self, snapshot_details):
        if 'ancestorVolumeId' in snapshot_details[0] and \
                snapshot_details[0]['ancestorVolumeId']:
            vol = self.get_volume(
                vol_id=snapshot_details[0]['ancestorVolumeId'])
            snapshot_details[0]['ancestorVolumeName'] = vol['name']

    def match_vol_details(self, snapshot):
        """Match the given volume details with the response
            :param snapshot: The snapshot details
        """
        vol_name = self.module.params['vol_name']
        vol_id = self.module.params['vol_id']

        try:
            if vol_name and vol_name != snapshot['ancestorVolumeName']:
                errormsg = "Given volume name do not match with the " \
                           "corresponding snapshot details."
                self.module.fail_json(msg=errormsg)

            if vol_id and vol_id != snapshot['ancestorVolumeId']:
                errormsg = "Given volume ID do not match with the " \
                           "corresponding snapshot details."
                self.module.fail_json(msg=errormsg)
        except Exception as e:
            errormsg = "Failed to match volume details with the snapshot " \
                       "with error %s" % str(e)
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_volume(self, vol_name=None, vol_id=None):
        """Get the volume id
            :param vol_name: The name of the volume
            :param vol_id: The ID of the volume
            :return: The volume details
        """

        try:
            if vol_name:
                vol_details = self.powerflex_conn.volume.get(
                    filter_fields={'name': vol_name})
            else:
                vol_details = self.powerflex_conn.volume.get(
                    filter_fields={'id': vol_id})

            if len(vol_details) == 0:
                error_msg = "Unable to find volume with name {0}".format(
                    vol_name)
                self.module.fail_json(msg=error_msg)
            return vol_details[0]
        except Exception as e:
            errormsg = "Failed to get the volume %s with error " \
                       "%s" % (vol_name, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_sdc_id(self, sdc_name=None, sdc_ip=None, sdc_id=None):
        """Get the SDC ID
            :param sdc_name: The name of the SDC
            :param sdc_ip: The IP of the SDC
            :param sdc_id: The ID of the SDC
            :return: The ID of the SDC
        """

        if sdc_name:
            id_ip_name = sdc_name
        elif sdc_ip:
            id_ip_name = sdc_ip
        else:
            id_ip_name = sdc_id

        try:
            if sdc_name:
                sdc_details = self.powerflex_conn.sdc.get(
                    filter_fields={'name': sdc_name})
            elif sdc_ip:
                sdc_details = self.powerflex_conn.sdc.get(
                    filter_fields={'sdcIp': sdc_ip})
            else:
                sdc_details = self.powerflex_conn.sdc.get(
                    filter_fields={'id': sdc_id})

            if len(sdc_details) == 0:
                error_msg = "Unable to find SDC with identifier {0}".format(
                    id_ip_name)
                self.module.fail_json(msg=error_msg)
            return sdc_details[0]['id']
        except Exception as e:
            errormsg = "Failed to get the SDC %s with error " \
                       "%s" % (id_ip_name, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_system_id(self):
        """Get system id"""

        try:
            resp = self.powerflex_conn.system.get()

            if len(resp) == 0:
                self.module.fail_json(msg="No system exist on the given host.")

            if len(resp) > 1:
                self.module.fail_json(msg="Multiple systems exist on the "
                                          "given host.")
            return resp[0]['id']
        except Exception as e:
            msg = "Failed to get system id with error %s" % str(e)
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def create_snapshot(self, snapshot_name, vol_id, system_id,
                        access_mode, retention):
        """Create snapshot
            :param snapshot_name: The name of the snapshot
            :param vol_id: The ID of the source volume
            :param system_id: The system id
            :param access_mode: Access mode for the snapshot
            :param retention: The retention for the snapshot
            :return: Boolean indicating if create operation is successful
        """
        LOG.debug("Creating Snapshot")

        try:
            self.powerflex_conn.system.snapshot_volumes(
                system_id=system_id,
                snapshot_defs=[utils.SnapshotDef(vol_id, snapshot_name)],
                access_mode=access_mode,
                retention_period=retention
            )

            return True
        except Exception as e:
            errormsg = "Create snapshot %s operation failed with " \
                       "error %s" % (snapshot_name, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def modify_retention(self, snapshot_id, new_retention):
        """Modify snapshot retention
            :param snapshot_id: The snapshot id
            :param new_retention: Desired retention of the snapshot
            :return: Boolean indicating if modifying retention is successful
        """

        try:
            self.powerflex_conn.volume.set_retention_period(snapshot_id,
                                                            new_retention)
            return True
        except Exception as e:
            errormsg = "Modify retention of snapshot %s operation failed " \
                       "with error %s" % (snapshot_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def modify_size(self, snapshot_id, new_size):
        """Modify snapshot size
            :param snapshot_id: The snapshot id
            :param new_size: Size of the snapshot
            :return: Boolean indicating if extend operation is successful
        """

        try:
            self.powerflex_conn.volume.extend(snapshot_id, new_size)
            return True
        except Exception as e:
            errormsg = "Extend snapshot %s operation failed with " \
                       "error %s" % (snapshot_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def modify_snap_access_mode(self, snapshot_id, snap_access_mode):
        """Modify access mode of snapshot
            :param snapshot_id: The snapshot id
            :param snap_access_mode: Access mode of the snapshot
            :return: Boolean indicating if modifying access mode of
                     snapshot is successful
        """

        try:
            self.powerflex_conn.volume.set_volume_access_mode_limit(
                volume_id=snapshot_id, access_mode_limit=snap_access_mode)
            return True
        except Exception as e:
            errormsg = "Modify access mode of snapshot %s operation " \
                       "failed with error %s" % (snapshot_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def modify_access_mode(self, snapshot_id, access_mode_list):
        """Modify access mode of SDCs mapped to snapshot
            :param snapshot_id: The snapshot id
            :param access_mode_list: List containing SDC ID's whose access mode
                   is to modified
            :return: Boolean indicating if modifying access mode is successful
        """

        try:
            changed = False
            for temp in access_mode_list:
                if temp['accessMode']:
                    self.powerflex_conn.volume.set_access_mode_for_sdc(
                        volume_id=snapshot_id, sdc_id=temp['sdc_id'],
                        access_mode=temp['accessMode'])
                    changed = True
            return changed
        except Exception as e:
            errormsg = "Modify access mode of SDC %s operation failed " \
                       "with error %s" % (temp['sdc_id'], str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def modify_limits(self, payload):
        """Modify IOPS and bandwidth limits of SDC's mapped to snapshot
            :param snapshot_id: The snapshot id
            :param limits_dict: Dict containing SDC ID's whose bandwidth and
                   IOPS is to modified
            :return: Boolean indicating if modifying limits is successful
        """

        try:
            changed = False
            if payload['bandwidth_limit'] is not None or \
                    payload['iops_limit'] is not None:
                self.powerflex_conn.volume.set_mapped_sdc_limits(**payload)
                changed = True
            return changed
        except Exception as e:
            errormsg = "Modify bandwidth/iops limits of SDC %s operation " \
                       "failed with error %s" % (payload['sdc_id'], str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def rename_snapshot(self, snapshot_id, new_name):
        """Rename snapshot
            :param snapshot_id: The snapshot id
            :param new_name: The new name of the snapshot
            :return: Boolean indicating if rename operation is successful
        """

        try:
            self.powerflex_conn.volume.rename(snapshot_id, new_name)
            return True
        except Exception as e:
            errormsg = "Rename snapshot %s operation failed with " \
                       "error %s" % (snapshot_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def delete_snapshot(self, snapshot_id, remove_mode):
        """Delete snapshot
            :param snapshot_id: The snapshot id
            :param remove_mode: Removal mode for the snapshot
            :return: Boolean indicating if delete operation is successful
        """

        try:
            self.powerflex_conn.volume.delete(snapshot_id, remove_mode)
            return True
        except Exception as e:
            errormsg = "Delete snapshot %s operation failed with " \
                       "error %s" % (snapshot_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def validate_desired_retention(self, desired_retention, retention_unit):
        """Validates the specified desired retention.
            :param desired_retention: Desired retention of the snapshot
            :param retention_unit: Retention unit for snapshot
        """

        if desired_retention is not None:
            if retention_unit == 'hours' and (desired_retention < 1 or
                                              desired_retention > 744):
                self.module.fail_json(msg="Please provide a valid integer as the"
                                      " desired retention between 1 and 744.")
            elif retention_unit == 'days' and (desired_retention < 1 or
                                               desired_retention > 31):
                self.module.fail_json(msg="Please provide a valid integer as the"
                                      " desired retention between 1 and 31.")

    def unmap_snapshot_from_sdc(self, snapshot, sdc):
        """Unmap SDC's from snapshot
            :param snapshot: Snapshot details
            :param sdc: List of SDCs to be unmapped
            :return: Boolean indicating if unmap operation is successful
        """

        current_sdcs = snapshot['mappedSdcInfo']
        current_sdc_ids = []
        sdc_id_list = []

        if current_sdcs:
            for temp in current_sdcs:
                current_sdc_ids.append(temp['sdcId'])

        for temp in sdc:
            if 'sdc_name' in temp and temp['sdc_name']:
                sdc_id = self.get_sdc_id(sdc_name=temp['sdc_name'])
            elif 'sdc_ip' in temp and temp['sdc_ip']:
                sdc_id = self.get_sdc_id(sdc_ip=temp['sdc_ip'])
            else:
                sdc_id = self.get_sdc_id(sdc_id=temp['sdc_id'])
            if sdc_id in current_sdc_ids:
                sdc_id_list.append(sdc_id)

        LOG.info("SDC IDs to remove %s", sdc_id_list)

        if len(sdc_id_list) == 0:
            return False

        try:
            for sdc_id in sdc_id_list:
                self.powerflex_conn.volume.remove_mapped_sdc(
                    snapshot['id'], sdc_id)
            return True
        except Exception as e:
            errormsg = "Unmap SDC %s from snapshot %s failed with error " \
                       "%s" % (sdc_id, snapshot['id'], str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def map_snapshot_to_sdc(self, snapshot, sdc):
        """Map SDC's to snapshot
            :param snapshot: Snapshot details
            :param sdc: List of SDCs
            :return: Boolean indicating if mapping operation is successful
        """

        current_sdcs = snapshot['mappedSdcInfo']
        sdc_id_list = []
        sdc_map_list = []
        sdc_modify_list1 = []
        sdc_modify_list2 = []

        current_sdc_ids = self.populate_current_sdcs_ids(current_sdcs)

        for temp in sdc:
            sdc_id = self.get_sdc_id_from(temp)
            if sdc_id not in current_sdc_ids:
                sdc_id_list.append(sdc_id)
                self.update_sdc_details(temp, sdc_id)
                sdc_map_list.append(temp)
            else:
                access_mode_dict, limits_dict = check_for_sdc_modification(
                    snapshot, sdc_id, temp)
                self.update_sdc_modify_lists(
                    sdc_modify_list1, sdc_modify_list2, access_mode_dict, limits_dict)

        LOG.info("SDC to add: %s", sdc_map_list)

        if not sdc_map_list:
            return False, sdc_modify_list1, sdc_modify_list2

        try:
            changed = False
            for sdc in sdc_map_list:
                payload = {
                    "volume_id": snapshot['id'],
                    "sdc_id": sdc['sdc_id'],
                    "access_mode": sdc['access_mode'],
                    "allow_multiple_mappings": self.module.params['allow_multiple_mappings']
                }
                self.powerflex_conn.volume.add_mapped_sdc(**payload)

                if sdc['bandwidth_limit'] or sdc['iops_limit']:
                    payload = {
                        "volume_id": snapshot['id'],
                        "sdc_id": sdc['sdc_id'],
                        "bandwidth_limit": sdc['bandwidth_limit'],
                        "iops_limit": sdc['iops_limit']
                    }

                    self.powerflex_conn.volume.set_mapped_sdc_limits(**payload)
                changed = True
            return changed, sdc_modify_list1, sdc_modify_list2

        except Exception as e:
            errormsg = "Mapping snapshot %s to SDC %s " \
                       "failed with error %s" % (snapshot['name'],
                                                 sdc['sdc_id'], str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def update_sdc_modify_lists(self, sdc_modify_list1, sdc_modify_list2,
                                access_mode_dict, limits_dict):
        if access_mode_dict:
            sdc_modify_list1.append(access_mode_dict)
        if limits_dict:
            sdc_modify_list2.append(limits_dict)

    def update_sdc_details(self, temp, sdc_id):
        temp['sdc_id'] = sdc_id
        if 'access_mode' in temp:
            temp['access_mode'] = get_access_mode(temp['access_mode'])
        if 'bandwidth_limit' not in temp:
            temp['bandwidth_limit'] = None
        if 'iops_limit' not in temp:
            temp['iops_limit'] = None

    def get_sdc_id_from(self, temp):
        sdc_id = None
        if 'sdc_name' in temp and temp['sdc_name']:
            sdc_id = self.get_sdc_id(sdc_name=temp['sdc_name'])
        elif 'sdc_ip' in temp and temp['sdc_ip']:
            sdc_id = self.get_sdc_id(sdc_ip=temp['sdc_ip'])
        else:
            sdc_id = self.get_sdc_id(sdc_id=temp['sdc_id'])
        return sdc_id

    def populate_current_sdcs_ids(self, current_sdcs):
        current_sdc_ids = []
        if current_sdcs:
            for temp in current_sdcs:
                current_sdc_ids.append(temp['sdcId'])
        return current_sdc_ids

    def validate_parameters(self):
        """Validate the input parameters"""

        sdc = self.module.params['sdc']
        cap_unit = self.module.params['cap_unit']
        size = self.module.params['size']
        desired_retention = self.module.params['desired_retention']
        retention_unit = self.module.params['retention_unit']

        param_list = ['snapshot_name', 'snapshot_id', 'vol_name', 'vol_id']
        for param in param_list:
            if self.module.params[param] is not None and \
                    len(self.module.params[param].strip()) == 0:
                error_msg = "Please provide valid %s" % param
                self.module.fail_json(msg=error_msg)

        if sdc:
            for temp in sdc:
                if (all([temp['sdc_id'], temp['sdc_ip']]) or
                        all([temp['sdc_id'], temp['sdc_name']]) or
                        all([temp['sdc_ip'], temp['sdc_name']])):
                    self.module.fail_json(msg="sdc_id, sdc_ip and sdc_name "
                                              "are mutually exclusive")

        if (cap_unit is not None) and not size:
            self.module.fail_json(msg="cap_unit can be specified along "
                                      "with size")

        if (retention_unit is not None) and not desired_retention:
            self.module.fail_json(msg="retention_unit can be specified along "
                                      "with desired_retention")

    def perform_module_operation(self):
        """
        Perform different actions on snapshot based on parameters passed in
        the playbook
        """
        snapshot_name = self.module.params['snapshot_name']
        snapshot_id = self.module.params['snapshot_id']
        vol_name = self.module.params['vol_name']
        vol_id = self.module.params['vol_id']
        read_only = self.module.params['read_only']
        size = self.module.params['size']
        cap_unit = self.module.params['cap_unit']
        snapshot_new_name = self.module.params['snapshot_new_name']
        sdc = copy.deepcopy(self.module.params['sdc'])
        sdc_state = self.module.params['sdc_state']
        desired_retention = self.module.params['desired_retention']
        retention_unit = self.module.params['retention_unit']
        remove_mode = self.module.params['remove_mode']
        state = self.module.params['state']

        # result is a dictionary to contain end state and snapshot details
        changed = False
        is_modified = False
        result = dict(
            changed=False,
            snapshot_details={}
        )

        self.validate_parameters()

        cap_unit = self.get_cap_unit(size, cap_unit)

        retention_unit = self.get_retention_unit(
            desired_retention, retention_unit)

        self.validate_desired_retention(desired_retention, retention_unit)

        snapshot_details = self.get_snapshot(snapshot_name, snapshot_id)

        if snapshot_details:
            snap_access_mode = None
            if read_only is not None:
                snap_access_mode = self.get_mode(read_only)
            is_modified, flag1, flag2, flag3 = check_snapshot_modified(
                snapshot_details, desired_retention, retention_unit, size,
                cap_unit, snap_access_mode)

        if state == 'present' and not snapshot_details:
            self.validate_create(snapshot_name, snapshot_id, vol_name,
                                 vol_id, snapshot_new_name, remove_mode)
            changed = self.create_snapshot_with_detail(snapshot_name, vol_name,
                                                       read_only, size,
                                                       cap_unit,
                                                       desired_retention,
                                                       retention_unit)
            if changed:
                snapshot_details = self.get_snapshot(snapshot_name)

        if is_modified:
            changed = self.modify_val(size, cap_unit, desired_retention,
                                      retention_unit, snapshot_details,
                                      snap_access_mode, flag1, flag2, flag3)

        if state == 'present' and snapshot_details and sdc and sdc_state == 'mapped':
            changed = self.sdc_state_mapped(sdc, snapshot_details)

        if state == 'present' and snapshot_details and sdc and \
                sdc_state == 'unmapped':
            changed = self.unmap_snapshot_from_sdc(snapshot_details, sdc)

        if state == 'present' and snapshot_details and \
                snapshot_new_name is not None:
            self.validate_snap_shot_new_name(snapshot_new_name)
            changed = self.rename_snapshot(snapshot_details['id'],
                                           snapshot_new_name)
            snapshot_name = self.assign_snapshot_name(
                snapshot_new_name, changed)

        if state == 'absent' and snapshot_details:
            remove_mode = self.get_remove_mode(remove_mode)
            changed = self.delete_snapshot(snapshot_details['id'], remove_mode)

        if state == 'present':
            snapshot_details = self.get_snapshot(snapshot_name, snapshot_id)
            result['snapshot_details'] = snapshot_details

        result['changed'] = changed
        self.module.exit_json(**result)

    def assign_snapshot_name(self, snapshot_new_name, changed):
        if changed:
            snapshot_name = snapshot_new_name
        return snapshot_name

    def get_remove_mode(self, remove_mode):
        if remove_mode is None:
            remove_mode = "ONLY_ME"
        return remove_mode

    def get_retention_unit(self, desired_retention, retention_unit):
        if desired_retention and not retention_unit:
            retention_unit = 'hours'
        return retention_unit

    def get_cap_unit(self, size, cap_unit):
        if size and not cap_unit:
            cap_unit = 'GB'
        return cap_unit

    def validate_snap_shot_new_name(self, snapshot_new_name):
        if len(snapshot_new_name.strip()) == 0:
            self.module.fail_json(msg="Please provide valid snapshot "
                                  "name.")

    def sdc_state_mapped(self, sdc, snapshot_details):
        changed_mode = False
        changed_limits = False

        map_changed, access_mode_list, limits_list = \
            self.map_snapshot_to_sdc(snapshot_details, sdc)

        if len(access_mode_list) > 0:
            changed_mode = self.modify_access_mode(
                snapshot_details['id'], access_mode_list)

        if len(limits_list) > 0:
            for temp in limits_list:
                payload = {
                    "volume_id": snapshot_details['id'],
                    "sdc_id": temp['sdc_id'],
                    "bandwidth_limit": temp['bandwidth_limit'],
                    "iops_limit": temp['iops_limit']
                }
                changed_limits = self.modify_limits(payload)
        return changed_mode or changed_limits or map_changed

    def modify_val(self, size, cap_unit, desired_retention, retention_unit,
                   snapshot_details, snap_access_mode, flag1, flag2, flag3):
        if flag1:
            retention = calculate_retention(desired_retention,
                                            retention_unit)
            changed = self.modify_retention(snapshot_details['id'],
                                            retention)
        if flag2:
            new_size = size
            if cap_unit == 'TB':
                new_size = size * 1024
            changed = self.modify_size(snapshot_details['id'], new_size)

        if flag3:
            changed = self.modify_snap_access_mode(
                snapshot_details['id'], snap_access_mode)
        return changed

    def create_snapshot_with_detail(self, snapshot_name, vol_name, read_only,
                                    size, cap_unit, desired_retention,
                                    retention_unit):
        if vol_name:
            vol = self.get_volume(vol_name=vol_name)
            vol_id = vol['id']

        retention = 0
        if desired_retention:
            retention = calculate_retention(desired_retention,
                                            retention_unit)

        system_id = self.get_system_id()
        access_mode = self.get_mode(read_only)

        changed = self.create_snapshot(snapshot_name, vol_id, system_id,
                                       access_mode, retention)
        if changed:
            snapshot_details = self.get_snapshot(snapshot_name)

        if size:
            if cap_unit == 'GB':
                new_size = size * 1024 * 1024
            else:
                new_size = size * 1024 * 1024 * 1024

            if new_size != snapshot_details['sizeInKb']:
                if cap_unit == 'TB':
                    size = size * 1024
                changed = self.modify_size(snapshot_details['id'], size)
        return changed

    def get_mode(self, read_only):
        ret_mode = None
        if read_only:
            ret_mode = 'ReadOnly'
        else:
            ret_mode = 'ReadWrite'
        return ret_mode

    def validate_create(self, snapshot_name, snapshot_id, vol_name, vol_id,
                        snapshot_new_name, remove_mode):
        if snapshot_id:
            self.module.fail_json(msg="Creation of snapshot is allowed "
                                  "using snapshot_name only, "
                                  "snapshot_id given.")

        if snapshot_name is None or len(snapshot_name.strip()) == 0:
            self.module.fail_json(msg="Please provide valid snapshot "
                                  "name.")

        if vol_name is None and vol_id is None:
            self.module.fail_json(msg="Please provide volume details to "
                                  "create new snapshot")

        if snapshot_new_name is not None:
            self.module.fail_json(msg="snapshot_new_name is not required"
                                  " while creating snapshot")

        if remove_mode:
            self.module.fail_json(msg="remove_mode is not required while "
                                  "creating snapshot")


def check_snapshot_modified(snapshot=None, desired_retention=None,
                            retention_unit=None, size=None, cap_unit=None,
                            access_mode=None):
    """Check if snapshot modification is required
        :param snapshot: Snapshot details
        :param desired_retention: Desired retention of the snapshot
        :param retention_unit: Retention unit for snapshot
        :param size: Size of the snapshot
        :param cap_unit: Capacity unit for the snapshot
        :param access_mode: Access mode of the snapshot
        :return: Boolean indicating if modification is needed
    """

    expiration_timestamp = None
    is_timestamp_modified = False
    is_size_modified = False
    is_access_modified = False
    is_modified = False

    snap_creation_timestamp = get_snap_creation_time(snapshot)

    if desired_retention:
        expiration_timestamp = get_expiration_timestamp(desired_retention,
                                                        retention_unit,
                                                        snap_creation_timestamp)

    if 'secureSnapshotExpTime' in snapshot and expiration_timestamp and \
            snapshot['secureSnapshotExpTime'] != expiration_timestamp:
        existing_timestamp = snapshot['secureSnapshotExpTime']
        new_timestamp = expiration_timestamp

        info_message = 'The existing timestamp is: %s and the new ' \
                       'timestamp is: %s' % (existing_timestamp,
                                             new_timestamp)
        LOG.info(info_message)

        existing_time_obj = datetime.fromtimestamp(existing_timestamp)
        new_time_obj = datetime.fromtimestamp(new_timestamp)

        td = get_datetime_diff_in_minuets(existing_time_obj, new_time_obj)

        LOG.info("Time difference: %s", td)

        # A delta of two minutes is treated as idempotent
        if td > 2:
            is_timestamp_modified = True

    if size:
        new_size = get_new_size(size, cap_unit)
        if new_size != snapshot['sizeInKb']:
            is_size_modified = True

    if access_mode and snapshot['accessModeLimit'] != access_mode:
        is_access_modified = True

    if is_timestamp_modified or is_size_modified or is_access_modified:
        is_modified = True
    return is_modified, is_timestamp_modified, is_size_modified, is_access_modified


def get_datetime_diff_in_minuets(dt1, dt2):
    """
    Calculates the difference in two datetime objects.
    Args:
        dt1 (datetime): The first datetime object.
        dt2 (datetime): The second datetime object.
    Returns:
        int: The difference in minutes between dt1 and dt2.
    Raises:
        TypeError: If dt1 or dt2 are None.
    """
    if dt1 is None:
        raise ValueError("First datetime cannot be None")
    if dt2 is None:
        raise ValueError("Second datetime cannot be None")
    if not isinstance(dt1, datetime):
        raise TypeError(f"First parameter is not a datetime object, it is {type(dt1).__name__}.")
    if not isinstance(dt2, datetime):
        raise TypeError(f"Second parameter not a datetime object, it is {type(dt2).__name__}.")

    if dt1 > dt2:
        td = dt1 - dt2
    else:
        td = dt2 - dt1
    return int(round(td.total_seconds() / 60))


def get_new_size(size, cap_unit):
    if cap_unit == 'GB':
        new_size = size * 1024 * 1024
    else:
        new_size = size * 1024 * 1024 * 1024
    return new_size


def get_expiration_timestamp(desired_retention, retention_unit,
                             snap_creation_timestamp):
    if retention_unit == 'hours':
        expiration_timestamp = \
            datetime.fromtimestamp(snap_creation_timestamp) + \
            timedelta(hours=desired_retention)
        expiration_timestamp = time.mktime(expiration_timestamp.timetuple())
    else:
        expiration_timestamp = \
            datetime.fromtimestamp(snap_creation_timestamp) + \
            timedelta(days=desired_retention)
        expiration_timestamp = time.mktime(expiration_timestamp.timetuple())
    return expiration_timestamp


def get_snap_creation_time(snapshot):
    snap_creation_timestamp = None
    if 'creationTime' in snapshot:
        snap_creation_timestamp = snapshot['creationTime']
    return snap_creation_timestamp


def calculate_retention(desired_retention=None, retention_unit=None):
    """
    :param desired_retention: Desired retention of the snapshot
    :param retention_unit: Retention unit for snapshot
    :return: Retention in minutes
    """

    retention = 0
    if retention_unit == 'days':
        retention = desired_retention * 24 * 60
    else:
        retention = desired_retention * 60
    return retention


def check_for_sdc_modification(snapshot, sdc_id, sdc_details):
    """
    :param snapshot: The snapshot details
    :param sdc_id: The ID of the SDC
    :param sdc_details: The details of SDC
    :return: Dictionary with SDC attributes to be modified
    """
    access_mode_dict = dict()
    limits_dict = dict()

    for sdc in snapshot['mappedSdcInfo']:
        if sdc['sdcId'] == sdc_id:
            update_access_mode(sdc_id, sdc_details, access_mode_dict, sdc)
            if sdc['limitIops'] != sdc_details['iops_limit'] or \
                    sdc['limitBwInMbps'] != sdc_details['bandwidth_limit']:
                limits_dict['sdc_id'] = sdc_id
                limits_dict['iops_limit'] = None
                limits_dict['bandwidth_limit'] = None
                if sdc['limitIops'] != sdc_details['iops_limit']:
                    limits_dict['iops_limit'] = sdc_details['iops_limit']
                if sdc['limitBwInMbps'] != get_limits_in_mb(sdc_details['bandwidth_limit']):
                    limits_dict['bandwidth_limit'] = \
                        sdc_details['bandwidth_limit']
            break
    return access_mode_dict, limits_dict


def update_access_mode(sdc_id, sdc_details, access_mode_dict, sdc):
    if sdc['accessMode'] != get_access_mode(sdc_details['access_mode']):
        access_mode_dict['sdc_id'] = sdc_id
        access_mode_dict['accessMode'] = get_access_mode(
            sdc_details['access_mode'])


def get_limits_in_mb(limits):
    """
    :param limits: Limits in KB
    :return: Limits in MB
    """

    if limits:
        return limits / 1024


def get_access_mode(access_mode):
    """
    :param access_mode: Access mode of the SDC
    :return: The enum for the access mode
    """

    access_mode_dict = {
        "READ_WRITE": "ReadWrite",
        "READ_ONLY": "ReadOnly",
        "NO_ACCESS": "NoAccess"
    }
    return access_mode_dict.get(access_mode)


def get_powerflex_snapshot_parameters():
    """This method provide parameter required for the Ansible snapshot
    module on PowerFlex"""
    return dict(
        snapshot_name=dict(), snapshot_id=dict(),
        vol_name=dict(), vol_id=dict(),
        read_only=dict(required=False, type='bool'),
        size=dict(required=False, type='int'),
        cap_unit=dict(choices=['GB', 'TB']),
        snapshot_new_name=dict(),
        allow_multiple_mappings=dict(required=False, type='bool'),
        sdc=dict(
            type='list', elements='dict', options=dict(
                sdc_id=dict(), sdc_ip=dict(),
                sdc_name=dict(),
                access_mode=dict(choices=['READ_WRITE', 'READ_ONLY',
                                          'NO_ACCESS']),
                bandwidth_limit=dict(type='int'),
                iops_limit=dict(type='int')
            )
        ),
        desired_retention=dict(type='int'),
        retention_unit=dict(choices=['hours', 'days']),
        remove_mode=dict(choices=['ONLY_ME', 'INCLUDING_DESCENDANTS']),
        sdc_state=dict(choices=['mapped', 'unmapped']),
        state=dict(required=True, type='str', choices=['present', 'absent'])
    )


def main():
    """ Create PowerFlex Snapshot object and perform actions on it
        based on user input from playbook"""
    obj = PowerFlexSnapshot()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
