#!/usr/bin/python
# Copyright: (c) 2020-2025, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module for managing storage pool on Unity"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
module: storagepool
version_added: '1.1.0'
short_description: Manage storage pool on Unity
description:
- Managing storage pool on Unity storage system contains the operations
  Get details of storage pool,
  Create a storage pool,
  Modify storage pool.

extends_documentation_fragment:
  - dellemc.unity.unity

author:
- Ambuj Dubey (@AmbujDube) <ansible.team@dell.com>

options:
  pool_name:
    description:
    - Name of the storage pool, unique in the storage system.
    type: str

  pool_id:
    description:
    - Unique identifier of the pool instance.
    type: str

  new_pool_name:
    description:
    - New name of the storage pool, unique in the storage system.
    type: str

  pool_description:
    description:
    - The description of the storage pool.
    type: str

  fast_cache:
    description:
    - Indicates whether the fast cache is enabled for the storage pool.
    - C(Enabled) - FAST Cache is enabled for the pool.
    - C(Disabled) - FAST Cache is disabled for the pool.
    choices: [enabled, disabled]
    type: str

  fast_vp:
    description:
    - Indicates whether to enable scheduled data relocations for the pool.
    - C(Enabled) - Enabled scheduled data relocations for the pool.
    - C(Disabled) - Disabled scheduled data relocations for the pool.
    choices: [enabled, disabled]
    type: str

  raid_groups:
    description:
    - Parameters to create RAID group from the disks and add it to the pool.
    type: dict
    suboptions:
      disk_group_id:
        description:
        - Id of the disk group.
        type: str

      disk_num:
        description:
        - Number of disks.
        type: int

      raid_type:
        description:
        - RAID group types or RAID levels.
        choices: [None, RAID5, RAID0, RAID1, RAID3, RAID10, RAID6, Mixed, Automatic]
        type: str

      stripe_width :
        description:
        - RAID group stripe widths, including parity or mirror disks.
        choices: ['BEST_FIT', '2', '4', '5', '6', '8', '9', '10', '12', '13', '14', '16']
        type: str

  alert_threshold:
    description:
    - Threshold at which the system will generate alerts about the free space in the pool, specified as a percentage.
    - Minimum threshold limit is 50.
    - Maximum threshold limit is 84.
    type: int

  is_harvest_enabled:
    description:
    - Enable/Disable automatic deletion of snapshots based on pool space usage.
    type: bool

  pool_harvest_high_threshold:
    description:
    - Max threshold for space used in pool beyond which the system automatically starts deleting snapshots in the pool.
    - Applies when the automatic deletion of snapshots based on pool space usage is enabled for the system and pool.
    - Minimum pool harvest high threshold value is 1.
    - Maximum pool harvest high threshold value is 99.
    type: float

  pool_harvest_low_threshold:
    description:
    - Min threshold for space used in pool below which the system automatically stops deletion of snapshots in the pool.
    - Applies when the automatic deletion of snapshots based on pool space usage is enabled for the system and pool.
    - Minimum pool harvest low threshold value is 0.
    - Maximum pool harvest low threshold value is 98.
    type: float

  is_snap_harvest_enabled:
    description:
    - Enable/Disable automatic deletion of snapshots based on pool space usage.
    type: bool

  snap_harvest_high_threshold:
    description:
    - Max threshold for space used in snapshot beyond which the system automatically starts deleting snapshots in the pool.
    - Applies when the automatic deletion of snapshots based on pool space usage is enabled for the pool.
    - Minimum snap harvest high threshold value is 1.
    - Maximum snap harvest high threshold value is 99.
    type: float

  snap_harvest_low_threshold:
    description:
    - Min threshold for space used in snapshot below which the system will stop automatically deleting snapshots in the pool.
    - Applies when the automatic deletion of snapshots based on pool space usage is enabled for the pool.
    - Minimum snap harvest low threshold value is 0.
    - Maximum snap harvest low threshold value is 98.
    type: float

  pool_type:
    description:
    - Indicates storage pool type.
    choices: [TRADITIONAL, DYNAMIC]
    type: str

  state:
    description:
    - Define whether the storage pool should exist or not.
    - C(Present) - indicates that the storage pool should exist on the system.
    - C(Absent) - indicates that the storage pool should not exist on the system.
    choices: [absent, present]
    type: str
    required: true

notes:
- Deletion of storage pool is not allowed through Ansible module.
- The I(check_mode) is not supported.
'''

EXAMPLES = r'''
- name: Get Storage pool details using pool_name
  storagepool:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    pool_name: "{{pool_name}}"
    state: "present"

- name: Get Storage pool details using pool_id
  storagepool:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    pool_id: "{{pool_id}}"
    state: "present"

- name: Modify Storage pool attributes using pool_name
  storagepool:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    pool_name: "{{pool_name}}"
    new_pool_name: "{{new_pool_name}}"
    pool_description: "{{pool_description}}"
    fast_cache: "{{fast_cache_enabled}}"
    fast_vp: "{{fast_vp_enabled}}"
    state: "present"

- name: Modify Storage pool attributes using pool_id
  storagepool:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    pool_id: "{{pool_id}}"
    new_pool_name: "{{new_pool_name}}"
    pool_description: "{{pool_description}}"
    fast_cache: "{{fast_cache_enabled}}"
    fast_vp: "{{fast_vp_enabled}}"
    state: "present"

- name: Create a StoragePool
  storagepool:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    pool_name: "Test"
    pool_description: "test pool"
    raid_groups:
      disk_group_id: "dg_16"
      disk_num: 2
      raid_type: "RAID10"
      stripe_width: "BEST_FIT"
    alert_threshold: 50
    is_harvest_enabled: true
    pool_harvest_high_threshold: 60
    pool_harvest_low_threshold: 40
    is_snap_harvest_enabled: true
    snap_harvest_high_threshold: 70
    snap_harvest_low_threshold: 50
    fast_vp: "enabled"
    fast_cache: "enabled"
    pool_type: "DYNAMIC"
    state: "present"
'''

RETURN = r'''
 changed:
    description: Whether or not the storage pool has changed.
    returned: always
    type: bool
    sample: true

 storage_pool_details:
    description: The storage pool details.
    returned: When storage pool exists.
    type: dict
    contains:
        id:
            description: Pool id, unique identifier of the pool.
            type: str
        name:
            description: Pool name, unique in the storage system.
            type: str
        is_fast_cache_enabled:
            description: Indicates whether the fast cache is enabled for the storage
                         pool.
                         true - FAST Cache is enabled for the pool.
                         false - FAST Cache is disabled for the pool.
            type: bool
        is_fast_vp_enabled:
            description: Indicates whether to enable scheduled data relocations
                         for the storage pool.
                         true - Enabled scheduled data relocations for the pool.
                         false - Disabled scheduled data relocations for the pool.
            type: bool
        size_free_with_unit:
            description: Indicates size_free with its appropriate unit
                         in human readable form.
            type: str
        size_subscribed_with_unit:
            description: Indicates size_subscribed with its appropriate unit in
                         human readable form.
            type: str
        size_total_with_unit:
            description: Indicates size_total with its appropriate unit in human
                         readable form.
            type: str
        size_used_with_unit:
            description: Indicates size_used with its appropriate unit in human
                         readable form.
            type: str
        snap_size_subscribed_with_unit:
            description: Indicates snap_size_subscribed with its
                         appropriate unit in human readable form.
            type: str
        snap_size_used_with_unit:
            description: Indicates snap_size_used with its
                         appropriate unit in human readable form.
            type: str
        drives:
            description: Indicates information about the drives
                         associated with the storage pool.
            type: list
            contains:
                id:
                    description: Unique identifier of the drive.
                    type: str
                name:
                    description: Indicates name of the drive.
                    type: str
                size:
                    description: Indicates size of the drive.
                    type: str
                disk_technology:
                    description: Indicates disk technology of the drive.
                    type: str
                tier_type:
                    description: Indicates tier type of the drive.
                    type: str
    sample: {
        "alert_threshold": 50,
        "creation_time": "2022-03-08 14:05:32+00:00",
        "description": "",
        "drives": [
            {
                "disk_technology": "SAS",
                "id": "dpe_disk_22",
                "name": "DPE Drive 22",
                "size": 590860984320,
                "tier_type": "PERFORMANCE"
            },
            {
                "disk_technology": "SAS",
                "id": "dpe_disk_23",
                "name": "DPE Drive 23",
                "size": 590860984320,
                "tier_type": "PERFORMANCE"
            },
            {
                "disk_technology": "SAS",
                "id": "dpe_disk_24",
                "name": "DPE Drive 24",
                "size": 590860984320,
                "tier_type": "PERFORMANCE"
            }
        ],
        "existed": true,
        "harvest_state": "UsageHarvestStateEnum.IDLE",
        "hash": 8744642897210,
        "health": {
            "UnityHealth": {
                "hash": 8744642799842
            }
        },
        "id": "pool_280",
        "is_all_flash": false,
        "is_empty": false,
        "is_fast_cache_enabled": false,
        "is_fast_vp_enabled": false,
        "is_harvest_enabled": true,
        "is_snap_harvest_enabled": true,
        "metadata_size_subscribed": 105763569664,
        "metadata_size_used": 57176752128,
        "name": "test_pool",
        "object_id": 12884902146,
        "pool_fast_vp": {
            "UnityPoolFastVp": {
                "hash": 8744647518980
            }
        },
        "pool_space_harvest_high_threshold": 59.0,
        "pool_space_harvest_low_threshold": 40.0,
        "pool_type": "StoragePoolTypeEnum.DYNAMIC",
        "raid_type": "RaidTypeEnum.RAID10",
        "rebalance_progress": null,
        "size_free": 470030483456,
        "size_free_with_unit": "437.75 GB",
        "size_subscribed": 447215820800,
        "size_subscribed_with_unit": "416.5 GB",
        "size_total": 574720311296,
        "size_total_with_unit": "535.25 GB",
        "size_used": 76838068224,
        "size_used_with_unit": "71.56 GB",
        "snap_size_subscribed": 128851369984,
        "snap_size_subscribed_with_unit": "120.0 GB",
        "snap_size_used": 2351104,
        "snap_size_used_with_unit": "2.24 MB",
        "snap_space_harvest_high_threshold": 80.0,
        "snap_space_harvest_low_threshold": 60.0,
        "tiers": {
            "UnityPoolTierList": [
                {
                    "disk_count": [
                        0,
                        3,
                        0
                    ],
                    "existed": true,
                    "hash": 8744643017382,
                    "name": [
                        "Extreme Performance",
                        "Performance",
                        "Capacity"
                    ],
                    "pool_units": [
                        null,
                        {
                            "UnityPoolUnitList": [
                                {
                                    "UnityPoolUnit": {
                                        "hash": 8744642786759,
                                        "id": "rg_4"
                                    }
                                },
                                {
                                    "UnityPoolUnit": {
                                        "hash": 8744642786795,
                                        "id": "rg_5"
                                    }
                                }
                            ]
                        },
                        null
                    ],
                    "raid_type": [
                        "RaidTypeEnum.NONE",
                        "RaidTypeEnum.RAID10",
                        "RaidTypeEnum.NONE"
                    ],
                    "size_free": [
                        0,
                        470030483456,
                        0
                    ],
                    "size_moving_down": [
                        0,
                        0,
                        0
                    ],
                    "size_moving_up": [
                        0,
                        0,
                        0
                    ],
                    "size_moving_within": [
                        0,
                        0,
                        0
                    ],
                    "size_total": [
                        0,
                        574720311296,
                        0
                    ],
                    "size_used": [
                        0,
                        104689827840,
                        0
                    ],
                    "stripe_width": [
                        null,
                        "RaidStripeWidthEnum._2",
                        null
                    ],
                    "tier_type": [
                        "TierTypeEnum.EXTREME_PERFORMANCE",
                        "TierTypeEnum.PERFORMANCE",
                        "TierTypeEnum.CAPACITY"
                    ]
                }
            ]
        }
    }

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.unity.plugins.module_utils.storage.dell \
    import utils

LOG = utils.get_logger('storagepool')

application_type = "Ansible/1.7.1"


class StoragePool(object):
    """Class with storage pool operations"""

    def __init__(self):
        """ Define all parameters required by this module"""
        self.module_params = utils.get_unity_management_host_parameters()
        self.module_params.update(get_storagepool_parameters())

        mutually_exclusive = [['pool_name', 'pool_id']]
        required_one_of = [['pool_name', 'pool_id']]

        # initialize the Ansible module
        self.module = AnsibleModule(argument_spec=self.module_params,
                                    supports_check_mode=False,
                                    mutually_exclusive=mutually_exclusive,
                                    required_one_of=required_one_of)
        utils.ensure_required_libs(self.module)

        self.conn = utils.\
            get_unity_unisphere_connection(self.module.params, application_type)

    def get_details(self, pool_id=None, pool_name=None):
        """ Get storage pool details"""
        try:
            api_response = self.conn.get_pool(_id=pool_id, name=pool_name)
            details = api_response._get_properties()
            if details['existed'] is False:
                self.module.exit_json(msg="Pool does not exist", failed=True)
            is_fast_vp_enabled = api_response._get_property_from_raw(
                'pool_fast_vp')
            if is_fast_vp_enabled:
                is_fast_vp_enabled = is_fast_vp_enabled.is_schedule_enabled
            details['is_fast_vp_enabled'] = is_fast_vp_enabled

            details['size_free_with_unit'] = utils.\
                convert_size_with_unit(int(details['size_free']))

            details['size_subscribed_with_unit'] = utils.\
                convert_size_with_unit(int(details['size_subscribed']))

            details['size_total_with_unit'] = utils.\
                convert_size_with_unit(int(details['size_total']))

            details['size_used_with_unit'] = utils.\
                convert_size_with_unit(int(details['size_used']))

            details['snap_size_subscribed_with_unit'] = utils.\
                convert_size_with_unit(int(details['snap_size_subscribed']))

            details['snap_size_used_with_unit'] = utils.\
                convert_size_with_unit(int(details['snap_size_used']))

            pool_instance = utils.UnityPool.get(self.conn._cli, details['id'])
            pool_tier_list = []
            pool_tier_list.append((pool_instance.tiers)._get_properties())
            pool_tier_dict = {}
            pool_tier_dict['UnityPoolTierList'] = pool_tier_list
            details['tiers'] = pool_tier_dict
            return details
        except Exception as e:
            error = str(e)
            check_list = ['not found', 'no attribute']
            if any(ele in error for ele in check_list):
                error_message = "pool details are not found"
                LOG.info(error_message)
                return None
            error_message = 'Get details of storage pool failed with ' \
                            'error: {0}'.format(str(e))
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

    def is_pool_modification_required(self, storage_pool_details):
        """ Check if attributes of storage pool needs to be modified
        """
        try:
            if self.module.params['new_pool_name'] and \
                    self.module.params['new_pool_name'] != \
                    storage_pool_details['name']:
                return True

            if self.module.params['pool_description'] is not None and \
                    self.module.params['pool_description'] != \
                    storage_pool_details['description']:
                return True

            if self.module.params['fast_cache']:
                if (self.module.params['fast_cache'] == "enabled" and
                    not storage_pool_details['is_fast_cache_enabled']) or\
                   (self.module.params['fast_cache'] == "disabled" and storage_pool_details['is_fast_cache_enabled']):
                    return True

            if self.module.params['fast_vp']:
                if (self.module.params['fast_vp'] == "enabled" and
                    not storage_pool_details['is_fast_vp_enabled']) or \
                    (self.module.params['fast_vp'] == "disabled" and
                        storage_pool_details['is_fast_vp_enabled']):
                    return True

            LOG.info("modify not required")
            return False

        except Exception as e:
            error_message = 'Failed to determine if any modification'\
                'required for pool attributes with error: {0}'.format(str(e))
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

    def pool_modify(self, id, new_pool_name,
                    pool_description, fast_cache, fast_vp):
        """ Modify attributes of storage pool """
        pool_obj = utils.UnityPool.get(self.conn._cli, id)
        try:
            pool_obj.modify(name=new_pool_name, description=pool_description,
                            is_fast_cache_enabled=fast_cache,
                            is_fastvp_enabled=fast_vp)
            new_storage_pool_details = self.get_details(pool_id=id,
                                                        pool_name=None)
            LOG.info("Modification Successful")
            return new_storage_pool_details
        except Exception as e:
            if self.module.params['pool_id']:
                pool_identifier = self.module.params['pool_id']
            else:
                pool_identifier = self.module.params['pool_name']
            error_message = 'Modify attributes of storage pool {0} ' \
                'failed with error: {1}'.format(pool_identifier, str(e))
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

    def get_pool_drives(self, pool_id=None, pool_name=None):
        """ Get pool drives attached to pool"""
        pool_identifier = pool_id or pool_name
        pool_drives_list = []
        try:
            drive_instances = utils.UnityDiskList.get(self.conn._cli)
            if drive_instances:
                for drive in drive_instances:
                    if drive.pool and (drive.pool.id == pool_identifier or drive.pool.name == pool_identifier):
                        pool_drive = {"id": drive.id, "name": drive.name, "size": drive.size,
                                      "disk_technology": drive.disk_technology.name,
                                      "tier_type": drive.tier_type.name}
                        pool_drives_list.append(pool_drive)
            LOG.info("Successfully retrieved pool drive details")
            return pool_drives_list
        except Exception as e:
            error_message = 'Get details of pool drives failed with ' \
                            'error: {0}'.format(str(e))
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

    def get_raid_type_enum(self, raid_type):
        """ Get raid_type_enum.
             :param raid_type: The raid_type
             :return: raid_type enum
        """

        if raid_type in utils.RaidTypeEnum.__members__:
            return utils.RaidTypeEnum[raid_type]
        else:
            errormsg = "Invalid choice %s for Raid Type" % raid_type
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_raid_stripe_width_enum(self, stripe_width):
        """ Get raid_stripe_width enum.
             :param stripe_width: The raid_stripe_width
             :return: raid_stripe_width enum
        """
        if stripe_width != "BEST_FIT":
            stripe_width = "_" + stripe_width
        if stripe_width in utils.RaidStripeWidthEnum.__members__:
            return utils.RaidStripeWidthEnum[stripe_width]
        else:
            errormsg = "Invalid choice %s for stripe width" % stripe_width
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_pool_type_enum(self, pool_type):
        """ Get the storage pool_type enum.
             :param pool_type: The pool_type
             :return: pool_type enum
        """

        if pool_type == "TRADITIONAL":
            return 1
        elif pool_type == "DYNAMIC":
            return 2
        else:
            errormsg = "Invalid choice %s for Storage Pool Type" % pool_type
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_raid_groups(self, raid_groups):
        """ Get the raid groups for creating pool"""
        try:
            disk_obj = utils.UnityDiskGroup.get(self.conn._cli, _id=raid_groups['disk_group_id'])
            disk_num = raid_groups['disk_num']
            raid_type = raid_groups['raid_type']
            raid_type = self.get_raid_type_enum(raid_type) \
                if raid_type else None
            stripe_width = raid_groups['stripe_width']
            stripe_width = self.get_raid_stripe_width_enum(stripe_width) \
                if stripe_width else None
            raid_group = utils.RaidGroupParameter(disk_group=disk_obj,
                                                  disk_num=disk_num, raid_type=raid_type,
                                                  stripe_width=stripe_width)
            raid_groups = [raid_group]
            return raid_groups
        except Exception as e:
            error_message = 'Failed to create storage pool with error: %s' % str(e)
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

    def validate_create_pool_params(self, alert_threshold=None,
                                    pool_harvest_high_threshold=None,
                                    pool_harvest_low_threshold=None,
                                    snap_harvest_high_threshold=None,
                                    snap_harvest_low_threshold=None):
        """ Validates params for creating pool"""
        if alert_threshold and (alert_threshold < 50 or alert_threshold > 84):
            errormsg = "Alert threshold is not in the allowed value range of 50 - 84"
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)
        if pool_harvest_high_threshold and (pool_harvest_high_threshold < 1 or pool_harvest_high_threshold > 99):
            errormsg = "Pool harvest high threshold is not in the allowed value range of 1 - 99"
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)
        if pool_harvest_low_threshold and (pool_harvest_low_threshold < 0 or pool_harvest_low_threshold > 98):
            errormsg = "Pool harvest low threshold is not in the allowed value range of 0 - 98"
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)
        if snap_harvest_high_threshold and (snap_harvest_high_threshold < 1 or snap_harvest_high_threshold > 99):
            errormsg = "Snap harvest high threshold is not in the allowed value range of 1 - 99"
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)
        if snap_harvest_low_threshold and (snap_harvest_low_threshold < 0 or snap_harvest_low_threshold > 98):
            errormsg = "Snap harvest low threshold is not in the allowed value range of 0 - 98"
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def create_pool(self, name, raid_groups):
        """ Creates a StoragePool"""
        try:
            pool_obj = utils.UnityPool.get(self.conn._cli)
            pool_description = self.module.params['pool_description']
            raid_groups = self.get_raid_groups(raid_groups) \
                if raid_groups else None
            alert_threshold = self.module.params['alert_threshold']
            pool_harvest_high_threshold = None
            pool_harvest_low_threshold = None
            snap_harvest_high_threshold = None
            snap_harvest_low_threshold = None
            is_harvest_enabled = self.module.params['is_harvest_enabled']
            if is_harvest_enabled:
                pool_harvest_high_threshold = self.module.params['pool_harvest_high_threshold']
                pool_harvest_low_threshold = self.module.params['pool_harvest_low_threshold']
            is_snap_harvest_enabled = self.module.params['is_snap_harvest_enabled']
            if is_snap_harvest_enabled:
                snap_harvest_high_threshold = self.module.params['snap_harvest_high_threshold']
                snap_harvest_low_threshold = self.module.params['snap_harvest_low_threshold']
            self.validate_create_pool_params(alert_threshold=alert_threshold,
                                             pool_harvest_high_threshold=pool_harvest_high_threshold,
                                             pool_harvest_low_threshold=pool_harvest_low_threshold,
                                             snap_harvest_high_threshold=snap_harvest_high_threshold,
                                             snap_harvest_low_threshold=snap_harvest_low_threshold)
            pool_type = self.module.params['pool_type']
            pool_type = self.get_pool_type_enum(pool_type) \
                if pool_type else None
            fast_vp = self.module.params['fast_vp']
            if fast_vp:
                if fast_vp == "enabled":
                    fast_vp = True
                else:
                    fast_vp = False

            pool_obj.create(self.conn._cli, name=name, description=pool_description, raid_groups=raid_groups,
                            alert_threshold=alert_threshold,
                            is_harvest_enabled=is_harvest_enabled,
                            is_snap_harvest_enabled=is_snap_harvest_enabled,
                            pool_harvest_high_threshold=pool_harvest_high_threshold,
                            pool_harvest_low_threshold=pool_harvest_low_threshold,
                            snap_harvest_high_threshold=snap_harvest_high_threshold,
                            snap_harvest_low_threshold=snap_harvest_low_threshold,
                            is_fastvp_enabled=fast_vp,
                            pool_type=pool_type)
            LOG.info("Creation of storage pool successful")
            storage_pool_details = self.get_details(pool_name=name)
            changed = True
            return changed, storage_pool_details
        except Exception as e:
            error_message = 'Failed to create storage pool with error: %s' % str(e)
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

    def perform_module_operation(self):
        """
        Perform different actions on storage pool module based on parameters
        chosen in playbook
        """
        pool_name = self.module.params['pool_name']
        pool_id = self.module.params['pool_id']
        new_pool_name = self.module.params['new_pool_name']
        pool_description = self.module.params['pool_description']
        fast_cache = self.module.params['fast_cache']
        fast_vp = self.module.params['fast_vp']
        state = self.module.params['state']
        raid_groups = self.module.params['raid_groups']
        if fast_cache:
            if fast_cache == "enabled":
                fast_cache = True
            else:
                fast_cache = False

        if fast_vp:
            if fast_vp == "enabled":
                fast_vp = True
            else:
                fast_vp = False

        # result is a dictionary that contains changed status and storage pool details
        result = dict(
            changed=False,
            storage_pool_details={}
        )

        storage_pool_details = self.get_details(pool_id, pool_name)
        result['storage_pool_details'] = storage_pool_details

        if state == 'absent' and storage_pool_details:
            error_message = 'Deletion of storage pool is not allowed through'\
                            ' Ansible module'
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

        # Create storage pool
        if state == 'present' and not storage_pool_details:
            if pool_name is not None and len(pool_name) != 0:
                result['changed'], storage_pool_details \
                    = self.create_pool(name=pool_name, raid_groups=raid_groups)
                result['storage_pool_details'] = storage_pool_details
            else:
                error_message = 'The parameter pool_name length is 0. It'\
                                ' is too short. The min length is 1'
                LOG.error(error_message)
                self.module.fail_json(msg=error_message)

        # Get pool drive details
        if result['storage_pool_details']:
            result['storage_pool_details']['drives'] = self.get_pool_drives(pool_id=pool_id, pool_name=pool_name)

        if state == 'present' and storage_pool_details:
            if new_pool_name is not None and len(new_pool_name) == 0:
                error_message = 'The parameter new_pool_name length is 0. It'\
                                ' is too short. The min length is 1'
                LOG.error(error_message)
                self.module.fail_json(msg=error_message)
            pool_modify_flag = self.\
                is_pool_modification_required(storage_pool_details)
            LOG.info("Storage pool modification flag %s",
                     str(pool_modify_flag))

            if pool_modify_flag:
                result['storage_pool_details'] = \
                    self.pool_modify(storage_pool_details['id'], new_pool_name,
                                     pool_description, fast_cache, fast_vp)
                result['changed'] = True
        self.module.exit_json(**result)


def get_storagepool_parameters():
    """This method provides parameters required for the ansible storage pool
       module on Unity"""
    return dict(
        pool_name=dict(required=False, type='str'),
        pool_id=dict(required=False, type='str'),
        new_pool_name=dict(required=False, type='str'),
        pool_description=dict(required=False, type='str'),
        fast_cache=dict(required=False, type='str', choices=['enabled',
                                                             'disabled']),
        fast_vp=dict(required=False, type='str', choices=['enabled',
                                                          'disabled']),
        state=dict(required=True, type='str', choices=['present', 'absent']),
        raid_groups=dict(required=False, type='dict', options=dict(
            disk_group_id=dict(required=False, type='str'),
            disk_num=dict(required=False, type='int'),
            raid_type=dict(required=False, type='str', choices=['None', 'RAID5', 'RAID0', 'RAID1', 'RAID3', 'RAID10',
                                                                'RAID6', 'Mixed', 'Automatic']),
            stripe_width=dict(required=False, type='str', choices=['BEST_FIT', '2', '4', '5',
                                                                   '6', '8', '9', '10', '12', '13', '14', '16']))),
        alert_threshold=dict(required=False, type='int'),
        is_harvest_enabled=dict(required=False, type='bool'),
        pool_harvest_high_threshold=dict(required=False, type='float'),
        pool_harvest_low_threshold=dict(required=False, type='float'),
        is_snap_harvest_enabled=dict(required=False, type='bool'),
        snap_harvest_high_threshold=dict(required=False, type='float'),
        snap_harvest_low_threshold=dict(required=False, type='float'),
        pool_type=dict(required=False, type='str', choices=['TRADITIONAL', 'DYNAMIC'])
    )


def main():
    """ Create Unity storage pool object and perform action on it
        based on user input from playbook"""
    obj = StoragePool()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
