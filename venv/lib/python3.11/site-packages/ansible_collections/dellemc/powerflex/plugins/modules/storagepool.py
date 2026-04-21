#!/usr/bin/python

# Copyright: (c) 2021-24, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module for managing Dell Technologies (Dell) PowerFlex storage pool"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: storagepool

version_added: '1.0.0'

short_description: Managing Dell PowerFlex storage pool

description:
- Dell PowerFlex storage pool module includes getting the details of
  storage pool, creating a new storage pool, and modifying the attribute of
  a storage pool.

extends_documentation_fragment:
  - dellemc.powerflex.powerflex

author:
- Arindam Datta (@dattaarindam) <ansible.team@dell.com>
- P Srinivas Rao (@srinivas-rao5) <ansible.team@dell.com>
- Trisha Datta (@trisha-dell) <ansible.team@dell.com>

options:
  storage_pool_name:
    description:
    - The name of the storage pool.
    - If more than one storage pool is found with the same name then
      protection domain id/name is required to perform the task.
    - Mutually exclusive with I(storage_pool_id).
    type: str
  storage_pool_id:
    description:
    - The id of the storage pool.
    - It is auto generated, hence should not be provided during
      creation of a storage pool.
    - Mutually exclusive with I(storage_pool_name).
    type: str
  protection_domain_name:
    description:
    - The name of the protection domain.
    - During creation of a pool, either protection domain name or id must be
      mentioned.
    - Mutually exclusive with I(protection_domain_id).
    type: str
  protection_domain_id:
    description:
    - The id of the protection domain.
    - During creation of a pool, either protection domain name or id must
      be mentioned.
    - Mutually exclusive with I(protection_domain_name).
    type: str
  media_type:
    description:
    - Type of devices in the storage pool.
    type: str
    choices: ['HDD', 'SSD', 'TRANSITIONAL']
  storage_pool_new_name:
    description:
    - New name for the storage pool can be provided.
    - This parameter is used for renaming the storage pool.
    type: str
  use_rfcache:
    description:
    - Enable/Disable RFcache on a specific storage pool.
    type: bool
  use_rmcache:
    description:
    - Enable/Disable RMcache on a specific storage pool.
    type: bool
  enable_zero_padding:
    description:
    - Enable/Disable zero padding on a specific storage pool.
    type: bool
  rep_cap_max_ratio:
    description:
    - Set replication journal capacity of a storage pool.
    type: int
  enable_rebalance:
    description:
    - Enable/Disable rebalance on a specific storage pool.
    type: bool
  spare_percentage:
    description:
    - Set the spare percentage of a specific storage pool.
    type: int
  rmcache_write_handling_mode :
    description:
    - Set RM cache write handling mode of a storage pool.
    - I(Passthrough) Writes skip the cache and are stored in storage only.
    - I(Cached) Writes are stored in both cache and storage (the default).
    - Caching is only performed for IOs whose size is a multiple of 4k bytes.
    type: str
    choices: ['Cached', 'Passthrough']
    default: 'Cached'
  enable_rebuild:
    description:
    - Enable/Disable rebuild of a specific storage pool.
    type: bool
  enable_fragmentation:
    description:
    - Enable/Disable fragmentation of a specific storage pool.
    type: bool
  parallel_rebuild_rebalance_limit:
    description:
    - Set rebuild/rebalance parallelism limit of a storage pool.
    type: int
  persistent_checksum:
    description:
    - Enable/Disable persistent checksum of a specific storage pool.
    type: dict
    suboptions:
      enable:
        description:
        - Enable / disable persistent checksum.
        type: bool
      validate_on_read:
        description:
        - Validate checksum upon reading data.
        type: bool
      builder_limit:
        description:
        - Bandwidth limit in KB/s for the checksum building process.
        - Valid range is 1024 to 10240.
        default: 3072
        type: int
  protected_maintenance_mode_io_priority_policy:
    description:
    - Set protected maintenance mode I/O priority policy of a storage pool.
    type: dict
    suboptions:
      policy:
        description:
        - The I/O priority policy for protected maintenance mode.
        - C(unlimited) Protected maintenance mode IOPS are not limited
        - C(limitNumOfConcurrentIos)Limit the number of allowed concurrent protected maintenance mode
          migration I/Os to the value defined for I(concurrent_ios_per_device).
        - C(favorAppIos) Always limit the number of allowed concurrent protected maintenance mode
          migration I/Os to value defined for I(concurrent_ios_per_device).
        - If application I/Os are in progress, should also limit the bandwidth of
          protected maintenance mode migration I/Os to the limit defined for the I(bw_limit_per_device).
        type: str
        choices: ['unlimited', 'limitNumOfConcurrentIos', 'favorAppIos']
        default: 'limitNumOfConcurrentIos'
      concurrent_ios_per_device:
        description:
        - The maximum number of concurrent protected maintenance mode migration I/Os per device.
        - Valid range is 1 to 20.
        type: int
      bw_limit_per_device:
        description:
        - The maximum bandwidth of protected maintenance mode migration I/Os,
          in KB per second, per device.
        - Valid range is 1024 to 1048576.
        type: int
  vtree_migration_io_priority_policy:
    description:
    - Set the I/O priority policy for V-Tree migration for a specific Storage Pool.
    type: dict
    suboptions:
      policy:
        description:
        - The I/O priority policy for protected maintenance mode.
        - C(limitNumOfConcurrentIos) Limit the number of allowed concurrent V-Tree
          migration I/Os (default) to the I(concurrent_ios_per_device).
        - C(favorAppIos) Always limit the number of allowed concurrent
          V-Tree migration I/Os to defined for I(concurrent_ios_per_device).
        - If application I/Os are in progress, should also limit the bandwidth of
          V-Tree migration I/Os to the limit defined for the I(bw_limit_per_device).
        type: str
        choices: ['limitNumOfConcurrentIos', 'favorAppIos']
      concurrent_ios_per_device:
        description:
        - The maximum number of concurrent V-Tree migration I/Os per device.
        - Valid range is 1 to 20
        type: int
      bw_limit_per_device:
        description:
        - The maximum bandwidth of V-Tree migration I/Os,
          in KB per second, per device.
        - Valid range is 1024 to 25600.
        type: int
  rebalance_io_priority_policy:
    description:
    - Set the rebalance I/O priority policy for a Storage Pool.
    type: dict
    suboptions:
      policy:
        description:
        - Policy to use for rebalance I/O priority.
        - C(unlimited) Rebalance I/Os are not limited.
        - C(limitNumOfConcurrentIos) Limit the number of allowed concurrent rebalance I/Os.
        - C(favorAppIos) Limit the number and bandwidth of rebalance I/Os when application I/Os are in progress.
        type: str
        choices: ['unlimited', 'limitNumOfConcurrentIos', 'favorAppIos']
        default: 'favorAppIos'
      concurrent_ios_per_device:
        description:
        - The maximum number of concurrent rebalance I/Os per device.
        - Valid range is 1 to 20.
        type: int
      bw_limit_per_device:
        description:
        - The maximum bandwidth of rebalance I/Os, in KB/s, per device.
        - Valid range is 1024 to 1048576.
        type: int
  cap_alert_thresholds:
    description:
    - Set the threshold for triggering capacity usage alerts.
    - Alerts thresholds are calculated from each Storage Pool
      capacity after deducting the defined amount of spare capacity.
    type: dict
    suboptions:
      high_threshold:
        description:
        - Threshold of the non-spare capacity of the Storage Pool that will trigger a
          high-priority alert, expressed as a percentage.
        - This value must be lower than the I(critical_threshold).
        type: int
      critical_threshold:
        description:
        - Threshold of the non-spare capacity of the Storage Pool that will trigger a
          critical-priority alert, expressed as a percentage.
        type: int
  state:
    description:
    - State of the storage pool.
    type: str
    choices: ["present", "absent"]
    required: true
notes:
  - TRANSITIONAL media type is supported only during modification.
  - The I(check_mode) is supported.
'''

EXAMPLES = r'''
- name: Get the details of storage pool by name
  dellemc.powerflex.storagepool:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    storage_pool_name: "sample_pool_name"
    protection_domain_name: "sample_protection_domain"
    state: "present"

- name: Get the details of storage pool by id
  dellemc.powerflex.storagepool:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    storage_pool_id: "abcd1234ab12r"
    state: "present"

- name: Create a new Storage pool
  dellemc.powerflex.storagepool:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    storage_pool_name: "{{ pool_name }}"
    protection_domain_name: "{{ protection_domain_name }}"
    cap_alert_thresholds:
      high_threshold: 30
      critical_threshold: 50
    media_type: "TRANSITIONAL"
    enable_zero_padding: true
    rep_cap_max_ratio: 40
    rmcache_write_handling_mode: "Passthrough"
    spare_percentage: 80
    enable_rebalance: false
    enable_fragmentation: false
    enable_rebuild: false
    use_rmcache: true
    use_rfcache: true
    parallel_rebuild_rebalance_limit: 3
    protected_maintenance_mode_io_priority_policy:
      policy: "unlimited"
    rebalance_io_priority_policy:
      policy: "unlimited"
    vtree_migration_io_priority_policy:
      policy: "limitNumOfConcurrentIos"
      concurrent_ios_per_device: 10
    persistent_checksum:
      enable: false
    state: "present"

- name: Modify a Storage pool by name
  dellemc.powerflex.storagepool:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    storage_pool_name: "{{ pool_name }}"
    protection_domain_name: "{{ protection_domain_name }}"
    storage_pool_new_name: "pool_name_new"
    cap_alert_thresholds:
      high_threshold: 50
      critical_threshold: 70
    enable_zero_padding: false
    rep_cap_max_ratio: 60
    rmcache_write_handling_mode: "Passthrough"
    spare_percentage: 90
    enable_rebalance: true
    enable_fragmentation: true
    enable_rebuild: true
    use_rmcache: true
    use_rfcache: true
    parallel_rebuild_rebalance_limit: 6
    protected_maintenance_mode_io_priority_policy:
      policy: "limitNumOfConcurrentIos"
      concurrent_ios_per_device: 4
    rebalance_io_priority_policy:
      policy: "favorAppIos"
      concurrent_ios_per_device: 10
      bw_limit_per_device: 4096
    vtree_migration_io_priority_policy:
      policy: "limitNumOfConcurrentIos"
      concurrent_ios_per_device: 10
    persistent_checksum:
      enable: true
      validate_on_read: true
      builder_limit: 1024
    state: "present"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: 'false'
storage_pool_details:
    description: Details of the storage pool.
    returned: When storage pool exists
    type: dict
    contains:
        mediaType:
            description: Type of devices in the storage pool.
            type: str
        useRfcache:
            description: Enable/Disable RFcache on a specific storage pool.
            type: bool
        useRmcache:
            description: Enable/Disable RMcache on a specific storage pool.
            type: bool
        id:
            description: ID of the storage pool under protection domain.
            type: str
        name:
            description: Name of the storage pool under protection domain.
            type: str
        protectionDomainId:
            description: ID of the protection domain in which pool resides.
            type: str
        protectionDomainName:
            description: Name of the protection domain in which pool resides.
            type: str
        "statistics":
            description: Statistics details of the storage pool.
            type: dict
            contains:
                "capacityInUseInKb":
                    description: Total capacity of the storage pool.
                    type: str
                "unusedCapacityInKb":
                    description: Unused capacity of the storage pool.
                    type: str
                "deviceIds":
                    description: Device Ids of the storage pool.
                    type: list
    sample: {
        "addressSpaceUsage": "Normal",
        "addressSpaceUsageType": "DeviceCapacityLimit",
        "backgroundScannerBWLimitKBps": 3072,
        "backgroundScannerMode": "DataComparison",
        "bgScannerCompareErrorAction": "ReportAndFix",
        "bgScannerReadErrorAction": "ReportAndFix",
        "capacityAlertCriticalThreshold": 90,
        "capacityAlertHighThreshold": 80,
        "capacityUsageState": "Normal",
        "capacityUsageType": "NetCapacity",
        "checksumEnabled": false,
        "compressionMethod": "Invalid",
        "dataLayout": "MediumGranularity",
        "externalAccelerationType": "None",
        "fglAccpId": null,
        "fglExtraCapacity": null,
        "fglMaxCompressionRatio": null,
        "fglMetadataSizeXx100": null,
        "fglNvdimmMetadataAmortizationX100": null,
        "fglNvdimmWriteCacheSizeInMb": null,
        "fglOverProvisioningFactor": null,
        "fglPerfProfile": null,
        "fglWriteAtomicitySize": null,
        "fragmentationEnabled": true,
        "id": "e0d8f6c900000000",
        "links": [
            {
                "href": "/api/instances/StoragePool::e0d8f6c900000000",
                "rel": "self"
            },
            {
                "href": "/api/instances/StoragePool::e0d8f6c900000000
                        /relationships/Statistics",
                "rel": "/api/StoragePool/relationship/Statistics"
            },
            {
                "href": "/api/instances/StoragePool::e0d8f6c900000000
                        /relationships/SpSds",
                "rel": "/api/StoragePool/relationship/SpSds"
            },
            {
                "href": "/api/instances/StoragePool::e0d8f6c900000000
                        /relationships/Volume",
                "rel": "/api/StoragePool/relationship/Volume"
            },
            {
                "href": "/api/instances/StoragePool::e0d8f6c900000000
                        /relationships/Device",
                "rel": "/api/StoragePool/relationship/Device"
            },
            {
                "href": "/api/instances/StoragePool::e0d8f6c900000000
                        /relationships/VTree",
                "rel": "/api/StoragePool/relationship/VTree"
            },
            {
                "href": "/api/instances/ProtectionDomain::9300c1f900000000",
                "rel": "/api/parent/relationship/protectionDomainId"
            }
        ],
        "statistics": {
                "BackgroundScannedInMB": 3466920,
                "activeBckRebuildCapacityInKb": 0,
                "activeEnterProtectedMaintenanceModeCapacityInKb": 0,
                "aggregateCompressionLevel": "Uncompressed",
                "atRestCapacityInKb": 1248256,
                "backgroundScanCompareErrorCount": 0,
                "backgroundScanFixedCompareErrorCount": 0,
                "bckRebuildReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "bckRebuildWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "capacityAvailableForVolumeAllocationInKb": 369098752,
                "capacityInUseInKb": 2496512,
                "capacityInUseNoOverheadInKb": 2496512,
                "capacityLimitInKb": 845783040,
                "compressedDataCompressionRatio": 0.0,
                "compressionRatio": 1.0,
                "currentFglMigrationSizeInKb": 0,
                "deviceIds": [
                ],
                "enterProtectedMaintenanceModeCapacityInKb": 0,
                "enterProtectedMaintenanceModeReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "enterProtectedMaintenanceModeWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "exitProtectedMaintenanceModeReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "exitProtectedMaintenanceModeWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "exposedCapacityInKb": 0,
                "failedCapacityInKb": 0,
                "fwdRebuildReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "fwdRebuildWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "inMaintenanceCapacityInKb": 0,
                "inMaintenanceVacInKb": 0,
                "inUseVacInKb": 184549376,
                "inaccessibleCapacityInKb": 0,
                "logWrittenBlocksInKb": 0,
                "maxCapacityInKb": 845783040,
                "migratingVolumeIds": [
                ],
                "migratingVtreeIds": [
                ],
                "movingCapacityInKb": 0,
                "netCapacityInUseInKb": 1248256,
                "normRebuildCapacityInKb": 0,
                "normRebuildReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "normRebuildWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "numOfDeviceAtFaultRebuilds": 0,
                "numOfDevices": 3,
                "numOfIncomingVtreeMigrations": 0,
                "numOfVolumes": 8,
                "numOfVolumesInDeletion": 0,
                "numOfVtrees": 8,
                "overallUsageRatio": 73.92289,
                "pendingBckRebuildCapacityInKb": 0,
                "pendingEnterProtectedMaintenanceModeCapacityInKb": 0,
                "pendingExitProtectedMaintenanceModeCapacityInKb": 0,
                "pendingFwdRebuildCapacityInKb": 0,
                "pendingMovingCapacityInKb": 0,
                "pendingMovingInBckRebuildJobs": 0,
                "persistentChecksumBuilderProgress": 100.0,
                "persistentChecksumCapacityInKb": 414720,
                "primaryReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "primaryReadFromDevBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "primaryReadFromRmcacheBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "primaryVacInKb": 92274688,
                "primaryWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "protectedCapacityInKb": 2496512,
                "protectedVacInKb": 184549376,
                "provisionedAddressesInKb": 2496512,
                "rebalanceCapacityInKb": 0,
                "rebalanceReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "rebalanceWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "rfacheReadHit": 0,
                "rfacheWriteHit": 0,
                "rfcacheAvgReadTime": 0,
                "rfcacheAvgWriteTime": 0,
                "rfcacheIoErrors": 0,
                "rfcacheIosOutstanding": 0,
                "rfcacheIosSkipped": 0,
                "rfcacheReadMiss": 0,
                "rmPendingAllocatedInKb": 0,
                "rmPendingThickInKb": 0,
                "rplJournalCapAllowed": 0,
                "rplTotalJournalCap": 0,
                "rplUsedJournalCap": 0,
                "secondaryReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "secondaryReadFromDevBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "secondaryReadFromRmcacheBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "secondaryVacInKb": 92274688,
                "secondaryWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "semiProtectedCapacityInKb": 0,
                "semiProtectedVacInKb": 0,
                "snapCapacityInUseInKb": 0,
                "snapCapacityInUseOccupiedInKb": 0,
                "snapshotCapacityInKb": 0,
                "spSdsIds": [
                    "abdfe71b00030001",
                    "abdce71d00040001",
                    "abdde71e00050001"
                ],
                "spareCapacityInKb": 84578304,
                "targetOtherLatency": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "targetReadLatency": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "targetWriteLatency": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "tempCapacityInKb": 0,
                "tempCapacityVacInKb": 0,
                "thickCapacityInUseInKb": 0,
                "thinAndSnapshotRatio": 73.92289,
                "thinCapacityAllocatedInKm": 184549376,
                "thinCapacityInUseInKb": 0,
                "thinUserDataCapacityInKb": 2496512,
                "totalFglMigrationSizeInKb": 0,
                "totalReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "totalWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "trimmedUserDataCapacityInKb": 0,
                "unreachableUnusedCapacityInKb": 0,
                "unusedCapacityInKb": 758708224,
                "userDataCapacityInKb": 2496512,
                "userDataCapacityNoTrimInKb": 2496512,
                "userDataReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "userDataSdcReadLatency": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "userDataSdcTrimLatency": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "userDataSdcWriteLatency": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "userDataTrimBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "userDataWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "volMigrationReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "volMigrationWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "volumeAddressSpaceInKb": 922XXXXX,
                "volumeAllocationLimitInKb": 3707XXXXX,
                "volumeIds": [
                    "456afc7900XXXXXXXX"
                ],
                "vtreeAddresSpaceInKb": 92274688,
                "vtreeIds": [
                    "32b1681bXXXXXXXX",
                ]
        },
        "mediaType": "HDD",
        "name": "pool1",
        "numOfParallelRebuildRebalanceJobsPerDevice": 2,
        "persistentChecksumBuilderLimitKb": 3072,
        "persistentChecksumEnabled": true,
        "persistentChecksumState": "Protected",
        "persistentChecksumValidateOnRead": false,
        "protectedMaintenanceModeIoPriorityAppBwPerDeviceThresholdInKbps": null,
        "protectedMaintenanceModeIoPriorityAppIopsPerDeviceThreshold": null,
        "protectedMaintenanceModeIoPriorityBwLimitPerDeviceInKbps": 10240,
        "protectedMaintenanceModeIoPriorityNumOfConcurrentIosPerDevice": 1,
        "protectedMaintenanceModeIoPriorityPolicy": "limitNumOfConcurrentIos",
        "protectedMaintenanceModeIoPriorityQuietPeriodInMsec": null,
        "protectionDomainId": "9300c1f900000000",
        "protectionDomainName": "domain1",
        "rebalanceEnabled": true,
        "rebalanceIoPriorityAppBwPerDeviceThresholdInKbps": null,
        "rebalanceIoPriorityAppIopsPerDeviceThreshold": null,
        "rebalanceIoPriorityBwLimitPerDeviceInKbps": 10240,
        "rebalanceIoPriorityNumOfConcurrentIosPerDevice": 1,
        "rebalanceIoPriorityPolicy": "favorAppIos",
        "rebalanceIoPriorityQuietPeriodInMsec": null,
        "rebuildEnabled": true,
        "rebuildIoPriorityAppBwPerDeviceThresholdInKbps": null,
        "rebuildIoPriorityAppIopsPerDeviceThreshold": null,
        "rebuildIoPriorityBwLimitPerDeviceInKbps": 10240,
        "rebuildIoPriorityNumOfConcurrentIosPerDevice": 1,
        "rebuildIoPriorityPolicy": "limitNumOfConcurrentIos",
        "rebuildIoPriorityQuietPeriodInMsec": null,
        "replicationCapacityMaxRatio": 32,
        "rmcacheWriteHandlingMode": "Cached",
        "sparePercentage": 10,
        "useRfcache": false,
        "useRmcache": false,
        "vtreeMigrationIoPriorityAppBwPerDeviceThresholdInKbps": null,
        "vtreeMigrationIoPriorityAppIopsPerDeviceThreshold": null,
        "vtreeMigrationIoPriorityBwLimitPerDeviceInKbps": 10240,
        "vtreeMigrationIoPriorityNumOfConcurrentIosPerDevice": 1,
        "vtreeMigrationIoPriorityPolicy": "favorAppIos",
        "vtreeMigrationIoPriorityQuietPeriodInMsec": null,
        "zeroPaddingEnabled": true
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell.libraries.powerflex_base \
    import PowerFlexBase
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell.libraries.configuration \
    import Configuration
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell \
    import utils

LOG = utils.get_logger('storagepool')


class PowerFlexStoragePool(PowerFlexBase):
    """Class with StoragePool operations"""

    def __init__(self):
        """ Define all parameters required by this module"""
        """ initialize the ansible module """
        mutually_exclusive = [['storage_pool_name', 'storage_pool_id'],
                              ['protection_domain_name', 'protection_domain_id'],
                              ['storage_pool_id', 'protection_domain_name'],
                              ['storage_pool_id', 'protection_domain_id']]

        required_one_of = [['storage_pool_name', 'storage_pool_id']]

        ansible_module_params = {
            'argument_spec': get_powerflex_storagepool_parameters(),
            'supports_check_mode': True,
            'mutually_exclusive': mutually_exclusive,
            'required_one_of': required_one_of
        }
        super().__init__(AnsibleModule, ansible_module_params)

        utils.ensure_required_libs(self.module)
        self.result = dict(
            changed=False,
            storage_pool_details={}
        )

    def get_protection_domain(
            self, protection_domain_name=None, protection_domain_id=None
    ):
        """Get the details of a protection domain in a given PowerFlex storage
        system"""
        return Configuration(self.powerflex_conn, self.module).get_protection_domain(
            protection_domain_name=protection_domain_name, protection_domain_id=protection_domain_id)

    def get_storage_pool(self, storage_pool_id=None, storage_pool_name=None,
                         pd_id=None):
        """Get storage pool details
            :param pd_id: ID of the protection domain
            :param storage_pool_name: The name of the storage pool
            :param storage_pool_id: The storage pool id
            :return: Storage pool details
        """
        name_or_id = storage_pool_id if storage_pool_id \
            else storage_pool_name
        try:
            filter_fields = {}
            if storage_pool_id:
                filter_fields = {'id': storage_pool_id}
            if storage_pool_name:
                filter_fields.update({'name': storage_pool_name})
            if pd_id:
                filter_fields.update({'protectionDomainId': pd_id})
            pool_details = self.powerflex_conn.storage_pool.get(
                filter_fields=filter_fields)
            if pool_details != []:
                if len(pool_details) > 1:

                    err_msg = "More than one storage pool found with {0}," \
                              " Please provide protection domain Name/Id" \
                              " to fetch the unique" \
                              " storage pool".format(storage_pool_name)
                    LOG.error(err_msg)
                    self.module.fail_json(msg=err_msg)
                elif len(pool_details) == 1:
                    pool_details = pool_details[0]
                    statistics = self.powerflex_conn.storage_pool.get_statistics(pool_details['id'])
                    pool_details['statistics'] = statistics if statistics else {}
                    pd_id = pool_details['protectionDomainId']
                    pd_name = self.get_protection_domain(
                        protection_domain_id=pd_id)['name']
                    # adding protection domain name in the pool details
                    pool_details['protectionDomainName'] = pd_name
                    return pool_details

            return None

        except Exception as e:
            errormsg = "Failed to get the storage pool {0} with error " \
                       "{1}".format(name_or_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def create_storage_pool(self, pool_name, pd_id, media_type,
                            use_rfcache=None, use_rmcache=None):
        """
        Create a storage pool
        :param pool_name: Name of the storage pool
        :param pd_id: ID of the storage pool
        :param media_type: Type of storage device in the pool
        :param use_rfcache: Enable/Disable RFcache on pool
        :param use_rmcache: Enable/Disable RMcache on pool
        :return: True, if the operation is successful
        """
        try:
            if media_type == "Transitional":
                self.module.fail_json(msg="TRANSITIONAL media type is not"
                                          " supported during creation."
                                          " Please enter a valid media type")

            if pd_id is None:
                self.module.fail_json(
                    msg="Please provide protection domain details for "
                        "creation of a storage pool")
            if not self.module.check_mode:
                pool_id = self.powerflex_conn.storage_pool.create(
                    media_type=media_type,
                    protection_domain_id=pd_id, name=pool_name,
                    use_rfcache=use_rfcache, use_rmcache=use_rmcache)['id']

            return self.get_storage_pool(storage_pool_id=pool_id,
                                         pd_id=pd_id)

        except Exception as e:
            errormsg = "Failed to create the storage pool {0} with error " \
                       "{1}".format(pool_name, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def verify_protection_domain(self, pool_details):
        """
        :param pool_details: Details of the storage pool
        :param pd_name: Name of the protection domain
        :param pd_id: Id of the protection domain
        """
        pd_name = self.module.params['protection_domain_name']
        pd_id = self.module.params['protection_domain_id']
        if pool_details is not None:
            if pd_id and pd_id != pool_details['protectionDomainId']:
                self.module.fail_json(msg="Entered protection domain id does not"
                                          " match with the storage pool's "
                                          "protection domain id. Please enter "
                                          "a correct protection domain id.")

            if pd_name and pd_name != pool_details['protectionDomainName']:
                self.module.fail_json(msg="Entered protection domain name does"
                                          " not match with the storage pool's "
                                          "protection domain name. Please enter"
                                          " a correct protection domain name.")

    def verify_storage_pool_name(self):
        if (self.module.params['storage_pool_name'] is not None and
                (len(self.module.params['storage_pool_name'].strip()) == 0)) or \
                (self.module.params['storage_pool_new_name'] is not None and
                    (len(self.module.params['storage_pool_new_name'].strip()) == 0)):
            self.module.fail_json(
                msg="Empty or white spaced string provided for "
                    "storage pool name. Provide valid storage"
                    " pool name.")

    def set_persistent_checksum(self, pool_details, pool_params):
        try:
            if pool_params['persistent_checksum']['enable']:
                if pool_details['persistentChecksumEnabled'] is not True:
                    self.powerflex_conn.storage_pool.set_persistent_checksum(
                        storage_pool_id=pool_details['id'],
                        enable=pool_params['persistent_checksum']['enable'],
                        validate=pool_params['persistent_checksum']['validate_on_read'],
                        builder_limit=pool_params['persistent_checksum']['builder_limit'])
                else:
                    self.powerflex_conn.storage_pool.modify_persistent_checksum(
                        storage_pool_id=pool_details['id'],
                        validate=pool_params['persistent_checksum']['validate_on_read'],
                        builder_limit=pool_params['persistent_checksum']['builder_limit'])

            pool_details = self.get_storage_pool(storage_pool_id=pool_details['id'])
            return pool_details

        except Exception as e:
            err_msg = "Failed to set persistent checksum with error " \
                      "{0}".format(str(e))
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

    def to_modify_persistent_checksum(self, pool_details, pool_params):
        checksum_dict = dict()
        if pool_params['persistent_checksum']['enable'] is not None and \
                pool_params['persistent_checksum']['enable'] != pool_details['persistentChecksumEnabled']:
            checksum_dict['enable'] = pool_params['persistent_checksum']['enable']

        if pool_params['persistent_checksum']['validate_on_read'] is not None and \
                pool_params['persistent_checksum']['validate_on_read'] != pool_details['persistentChecksumValidateOnRead'] and \
                pool_params['persistent_checksum']['enable'] is True:
            checksum_dict['validate_on_read'] = pool_params['persistent_checksum']['validate_on_read']

        if pool_params['persistent_checksum']['builder_limit'] is not None and \
                pool_params['persistent_checksum']['builder_limit'] != pool_details['persistentChecksumBuilderLimitKb'] and \
                pool_params['persistent_checksum']['enable'] is True:
            checksum_dict['builder_limit'] = pool_params['persistent_checksum']['builder_limit']

        return checksum_dict

    def to_modify_rebalance_io_priority_policy(self, pool_details, pool_params):

        policy_dict = {
            'policy': None,
            'concurrent_ios': None,
            'bw_limit': None
        }
        modify = False
        if pool_params['rebalance_io_priority_policy']['policy'] is not None and \
                pool_params['rebalance_io_priority_policy']['policy'] != pool_details['rebalanceIoPriorityPolicy']:
            policy_dict['policy'] = pool_params['rebalance_io_priority_policy']['policy']
            modify = True

        if pool_params['rebalance_io_priority_policy']['concurrent_ios_per_device'] is not None and \
                pool_params['rebalance_io_priority_policy']['concurrent_ios_per_device'] != pool_details['rebalanceIoPriorityNumOfConcurrentIosPerDevice']:
            policy_dict['concurrent_ios'] = str(pool_params['rebalance_io_priority_policy']['concurrent_ios_per_device'])

        if pool_params['rebalance_io_priority_policy']['bw_limit_per_device'] is not None and \
                pool_params['rebalance_io_priority_policy']['bw_limit_per_device'] != pool_details['rebalanceIoPriorityBwLimitPerDeviceInKbps']:
            policy_dict['bw_limit'] = str(pool_params['rebalance_io_priority_policy']['bw_limit_per_device'])

        if policy_dict['policy'] is None and (policy_dict['concurrent_ios'] is not None or policy_dict['bw_limit'] is not None):
            policy_dict['policy'] = pool_details['rebalanceIoPriorityPolicy']
            modify = True

        if modify is True:
            return policy_dict
        else:
            return None

    def to_modify_vtree_migration_io_priority_policy(self, pool_details, pool_params):
        policy_dict = {
            'policy': None,
            'concurrent_ios': None,
            'bw_limit': None
        }
        modify = False
        if pool_params['vtree_migration_io_priority_policy']['policy'] is not None and \
                pool_params['vtree_migration_io_priority_policy']['policy'] != pool_details['vtreeMigrationIoPriorityPolicy']:
            policy_dict['policy'] = pool_params['vtree_migration_io_priority_policy']['policy']
            modify = True

        if pool_params['vtree_migration_io_priority_policy']['concurrent_ios_per_device'] is not None and \
                pool_params['vtree_migration_io_priority_policy']['concurrent_ios_per_device'] != \
                pool_details['vtreeMigrationIoPriorityNumOfConcurrentIosPerDevice']:
            policy_dict['concurrent_ios'] = str(pool_params['vtree_migration_io_priority_policy']['concurrent_ios_per_device'])

        if pool_params['vtree_migration_io_priority_policy']['bw_limit_per_device'] is not None and \
                pool_params['vtree_migration_io_priority_policy']['bw_limit_per_device'] != \
                pool_details['vtreeMigrationIoPriorityBwLimitPerDeviceInKbps']:
            policy_dict['bw_limit'] = str(pool_params['vtree_migration_io_priority_policy']['bw_limit_per_device'])

        if policy_dict['policy'] is None and (policy_dict['concurrent_ios'] is not None or policy_dict['bw_limit'] is not None):
            policy_dict['policy'] = pool_details['vtreeMigrationIoPriorityPolicy']
            modify = True

        if modify is True:
            return policy_dict
        else:
            return None

    def to_modify_protected_maintenance_mode_io_priority_policy(self, pool_details, pool_params):

        policy_dict = {
            'policy': None,
            'concurrent_ios': None,
            'bw_limit': None
        }
        modify = False
        if pool_params['protected_maintenance_mode_io_priority_policy']['policy'] is not None and \
                pool_params['protected_maintenance_mode_io_priority_policy']['policy'] != pool_details['protectedMaintenanceModeIoPriorityPolicy']:
            policy_dict['policy'] = pool_params['protected_maintenance_mode_io_priority_policy']['policy']
            modify = True

        if pool_params['protected_maintenance_mode_io_priority_policy']['concurrent_ios_per_device'] is not None and \
                pool_params['protected_maintenance_mode_io_priority_policy']['concurrent_ios_per_device'] != \
                pool_details['protectedMaintenanceModeIoPriorityNumOfConcurrentIosPerDevice']:
            policy_dict['concurrent_ios'] = str(pool_params['protected_maintenance_mode_io_priority_policy']['concurrent_ios_per_device'])

        if pool_params['protected_maintenance_mode_io_priority_policy']['bw_limit_per_device'] is not None and \
                pool_params['protected_maintenance_mode_io_priority_policy']['bw_limit_per_device'] != \
                pool_details['protectedMaintenanceModeIoPriorityBwLimitPerDeviceInKbps']:
            policy_dict['bw_limit'] = str(pool_params['protected_maintenance_mode_io_priority_policy']['bw_limit_per_device'])

        if policy_dict['policy'] is None and (policy_dict['concurrent_ios'] is not None or policy_dict['bw_limit'] is not None):
            policy_dict['policy'] = pool_details['protectedMaintenanceModeIoPriorityPolicy']
            modify = True

        if modify is True:
            return policy_dict
        else:
            return None

    def to_modify_capacity_alert_thresholds(self, pool_details, pool_params, thresholds):
        modify = False
        threshold = dict()
        if pool_params['cap_alert_thresholds']['high_threshold'] is not None and pool_params['cap_alert_thresholds'][
                'high_threshold'] != pool_details['capacityAlertHighThreshold']:
            threshold['high'] = str(pool_params['cap_alert_thresholds']['high_threshold'])
            modify = True
        if pool_params['cap_alert_thresholds']['critical_threshold'] is not None and \
                pool_params['cap_alert_thresholds']['critical_threshold'] != pool_details[
                'capacityAlertCriticalThreshold']:
            threshold['critical'] = str(pool_params['cap_alert_thresholds']['critical_threshold'])
            modify = True
        if modify is True:
            if 'high' not in threshold:
                threshold['high'] = str(pool_details['capacityAlertHighThreshold'])
            if 'critical' not in threshold:
                threshold['critical'] = str(pool_details['capacityAlertCriticalThreshold'])

        return threshold


def get_powerflex_storagepool_parameters():
    """This method provides parameters required for the ansible
    Storage Pool module on powerflex"""
    return dict(
        storage_pool_name=dict(required=False, type='str'),
        storage_pool_id=dict(required=False, type='str'),
        protection_domain_name=dict(required=False, type='str'),
        protection_domain_id=dict(required=False, type='str'),
        media_type=dict(required=False, type='str',
                        choices=['HDD', 'SSD', 'TRANSITIONAL']),
        use_rfcache=dict(required=False, type='bool'),
        use_rmcache=dict(required=False, type='bool'),
        enable_zero_padding=dict(type='bool'),
        rep_cap_max_ratio=dict(type='int'),
        rmcache_write_handling_mode=dict(choices=['Cached', 'Passthrough'], default='Cached'),
        spare_percentage=dict(type='int'),
        enable_rebalance=dict(type='bool'),
        enable_fragmentation=dict(type='bool'),
        enable_rebuild=dict(type='bool'),
        storage_pool_new_name=dict(required=False, type='str'),
        parallel_rebuild_rebalance_limit=dict(type='int'),
        cap_alert_thresholds=dict(type='dict', options=dict(
            high_threshold=dict(type='int'),
            critical_threshold=dict(type='int'))),
        protected_maintenance_mode_io_priority_policy=dict(type='dict', options=dict(
            policy=dict(choices=['unlimited', 'limitNumOfConcurrentIos', 'favorAppIos'], default='limitNumOfConcurrentIos'),
            concurrent_ios_per_device=dict(type='int'),
            bw_limit_per_device=dict(type='int'))),
        rebalance_io_priority_policy=dict(type='dict', options=dict(
            policy=dict(choices=['unlimited', 'limitNumOfConcurrentIos', 'favorAppIos'], default='favorAppIos'),
            concurrent_ios_per_device=dict(type='int'),
            bw_limit_per_device=dict(type='int'))),
        vtree_migration_io_priority_policy=dict(type='dict', options=dict(
            policy=dict(choices=['limitNumOfConcurrentIos', 'favorAppIos']),
            concurrent_ios_per_device=dict(type='int'),
            bw_limit_per_device=dict(type='int'))),
        persistent_checksum=dict(type='dict', options=dict(
            enable=dict(type='bool'),
            validate_on_read=dict(type='bool'),
            builder_limit=dict(type='int', default=3072))),
        state=dict(required=True, type='str', choices=['present', 'absent']))


class StoragePoolExitHandler():
    def handle(self, pool_obj, pool_details):
        if pool_details:
            pool_details = pool_obj.get_storage_pool(storage_pool_id=pool_details['id'])
        pool_obj.result['storage_pool_details'] = pool_details

        pool_obj.module.exit_json(**pool_obj.result)


class StoragePoolDeleteHandler():
    def handle(self, pool_obj, pool_params, pool_details):
        if pool_params['state'] == 'absent' and pool_details:
            msg = "Deleting storage pool is not supported through" \
                  " ansible module."
            LOG.error(msg)
            pool_obj.module.fail_json(msg=msg)

        StoragePoolExitHandler().handle(pool_obj, pool_details)


class StoragePoolModifyPersistentChecksumHandler():
    def handle(self, pool_obj, pool_params, pool_details):
        try:
            if pool_params['state'] == 'present' and pool_details:
                if pool_params['persistent_checksum'] is not None:
                    checksum_dict = pool_obj.to_modify_persistent_checksum(
                        pool_details=pool_details,
                        pool_params=pool_params)
                    if checksum_dict != {}:
                        if not pool_obj.module.check_mode:
                            pool_details = pool_obj.set_persistent_checksum(
                                pool_details=pool_details,
                                pool_params=pool_params)
                        pool_obj.result['changed'] = True

            StoragePoolDeleteHandler().handle(pool_obj, pool_params, pool_details)

        except Exception as e:
            error_msg = (f"Modify Persistent Checksum failed "
                         f"with error {str(e)}")
            LOG.error(error_msg)
            pool_obj.module.fail_json(msg=error_msg)


class StoragePoolModifyRebalanceIOPriorityPolicyHandler():
    def handle(self, pool_obj, pool_params, pool_details):
        try:
            if pool_params['state'] == 'present' and pool_details:
                if pool_params['rebalance_io_priority_policy'] is not None:
                    policy_dict = pool_obj.to_modify_rebalance_io_priority_policy(
                        pool_details=pool_details,
                        pool_params=pool_params
                    )
                    if policy_dict is not None:
                        if not pool_obj.module.check_mode:
                            pool_details = pool_obj.powerflex_conn.storage_pool.rebalance_io_priority_policy(
                                storage_pool_id=pool_details['id'],
                                policy=policy_dict['policy'],
                                concurrent_ios_per_device=policy_dict['concurrent_ios'],
                                bw_limit_per_device=policy_dict['bw_limit'])
                        pool_obj.result['changed'] = True

            StoragePoolModifyPersistentChecksumHandler().handle(pool_obj, pool_params, pool_details)

        except Exception as e:
            error_msg = (f"Modify rebalance IO Priority Policy failed "
                         f"with error {str(e)}")
            LOG.error(error_msg)
            pool_obj.module.fail_json(msg=error_msg)


class StoragePoolSetVtreeMigrationIOPriorityPolicyHandler():
    def handle(self, pool_obj, pool_params, pool_details):
        try:
            if pool_params['state'] == 'present' and pool_details:
                if pool_params['vtree_migration_io_priority_policy'] is not None:
                    policy_dict = pool_obj.to_modify_vtree_migration_io_priority_policy(
                        pool_details=pool_details,
                        pool_params=pool_params
                    )
                    if policy_dict is not None:
                        if not pool_obj.module.check_mode:
                            pool_details = pool_obj.powerflex_conn.storage_pool.set_vtree_migration_io_priority_policy(
                                storage_pool_id=pool_details['id'],
                                policy=policy_dict['policy'],
                                concurrent_ios_per_device=policy_dict['concurrent_ios'],
                                bw_limit_per_device=policy_dict['bw_limit'])
                        pool_obj.result['changed'] = True

            StoragePoolModifyRebalanceIOPriorityPolicyHandler().handle(pool_obj, pool_params, pool_details)

        except Exception as e:
            error_msg = (f"Set Vtree Migration I/O Priority Policy operation failed "
                         f"with error {str(e)}")
            LOG.error(error_msg)
            pool_obj.module.fail_json(msg=error_msg)


class StoragePoolSetProtectedMaintenanceModeIOPriorityPolicyHandler():
    def handle(self, pool_obj, pool_params, pool_details):
        try:
            if pool_params['state'] == 'present' and pool_details:
                if pool_params['protected_maintenance_mode_io_priority_policy'] is not None:
                    policy_dict = pool_obj.to_modify_protected_maintenance_mode_io_priority_policy(
                        pool_details=pool_details,
                        pool_params=pool_params
                    )
                    if policy_dict is not None:
                        if not pool_obj.module.check_mode:
                            pool_details = pool_obj.powerflex_conn.storage_pool.set_protected_maintenance_mode_io_priority_policy(
                                storage_pool_id=pool_details['id'],
                                policy=policy_dict['policy'],
                                concurrent_ios_per_device=policy_dict['concurrent_ios'],
                                bw_limit_per_device=policy_dict['bw_limit'])
                        pool_obj.result['changed'] = True

            StoragePoolSetVtreeMigrationIOPriorityPolicyHandler().handle(pool_obj, pool_params, pool_details)

        except Exception as e:
            error_msg = (f"Set Protected Maintenance Mode IO Priority Policy operation failed "
                         f"with error {str(e)}")
            LOG.error(error_msg)
            pool_obj.module.fail_json(msg=error_msg)


class StoragePoolModifyCapacityAlertThresholdsHandler():
    def handle(self, pool_obj, pool_params, pool_details):
        try:
            if pool_params['state'] == 'present' and pool_details:
                if pool_params['cap_alert_thresholds'] is not None:
                    threshold = pool_obj.to_modify_capacity_alert_thresholds(pool_details=pool_details,
                                                                             pool_params=pool_params,
                                                                             thresholds=pool_params[
                                                                                 'cap_alert_thresholds'])
                    if threshold != {}:
                        if not pool_obj.module.check_mode:
                            pool_details = pool_obj.powerflex_conn.storage_pool.set_cap_alert_thresholds(
                                storage_pool_id=pool_details['id'],
                                cap_alert_high_threshold=threshold['high'],
                                cap_alert_critical_threshold=threshold['critical'])
                        pool_obj.result['changed'] = True

            StoragePoolSetProtectedMaintenanceModeIOPriorityPolicyHandler().handle(pool_obj, pool_params, pool_details)

        except Exception as e:
            error_msg = (f"Modify Capacity Alert Thresholds operation failed "
                         f"with error {str(e)}")
            LOG.error(error_msg)
            pool_obj.module.fail_json(msg=error_msg)


class StoragePoolModifyRebuildRebalanceParallelismLimitHandler():
    def handle(self, pool_obj, pool_params, pool_details):
        try:
            if pool_params['state'] == 'present' and pool_details:
                if pool_params['parallel_rebuild_rebalance_limit'] is not None and \
                        pool_params['parallel_rebuild_rebalance_limit'] != pool_details['numOfParallelRebuildRebalanceJobsPerDevice']:
                    if not pool_obj.module.check_mode:
                        pool_details = pool_obj.powerflex_conn.storage_pool.set_rebuild_rebalance_parallelism_limit(
                            pool_details['id'], str(pool_params['parallel_rebuild_rebalance_limit']))
                    pool_obj.result['changed'] = True

            StoragePoolModifyCapacityAlertThresholdsHandler().handle(pool_obj, pool_params, pool_details)

        except Exception as e:
            error_msg = (f"Modify Rebuild/Rebalance Parallelism Limit operation failed "
                         f"with error {str(e)}")
            LOG.error(error_msg)
            pool_obj.module.fail_json(msg=error_msg)


class StoragePoolModifyRMCacheWriteHandlingModeHandler():
    def handle(self, pool_obj, pool_params, pool_details):
        try:
            if pool_params['state'] == 'present' and pool_details:
                if pool_params['rmcache_write_handling_mode'] is not None and \
                        pool_params['rmcache_write_handling_mode'] != pool_details['rmcacheWriteHandlingMode']:
                    if not pool_obj.module.check_mode:
                        pool_details = pool_obj.powerflex_conn.storage_pool.set_rmcache_write_handling_mode(
                            pool_details['id'], pool_params['rmcache_write_handling_mode'])
                    pool_obj.result['changed'] = True

            StoragePoolModifyRebuildRebalanceParallelismLimitHandler().handle(pool_obj, pool_params, pool_details)

        except Exception as e:
            error_msg = (f"Modify RMCache Write Handling Mode failed "
                         f"with error {str(e)}")
            LOG.error(error_msg)
            pool_obj.module.fail_json(msg=error_msg)


class StoragePoolModifySparePercentageHandler():
    def handle(self, pool_obj, pool_params, pool_details):
        try:
            if pool_params['state'] == 'present' and pool_details:
                if pool_params['spare_percentage'] is not None and pool_params['spare_percentage'] != pool_details['sparePercentage']:
                    if not pool_obj.module.check_mode:
                        pool_details = pool_obj.powerflex_conn.storage_pool.set_spare_percentage(
                            pool_details['id'], str(pool_params['spare_percentage']))
                    pool_obj.result['changed'] = True

            StoragePoolModifyRMCacheWriteHandlingModeHandler().handle(pool_obj, pool_params, pool_details)

        except Exception as e:
            error_msg = (f"Modify Spare Percentage operation failed "
                         f"with error {str(e)}")
            LOG.error(error_msg)
            pool_obj.module.fail_json(msg=error_msg)


class StoragePoolEnableFragmentationHandler():
    def handle(self, pool_obj, pool_params, pool_details):
        try:
            if pool_params['state'] == 'present' and pool_details:
                if pool_params['enable_fragmentation'] is not None and pool_params['enable_fragmentation'] != pool_details['fragmentationEnabled']:
                    if not pool_obj.module.check_mode:
                        pool_details = pool_obj.powerflex_conn.storage_pool.set_fragmentation_enabled(
                            pool_details['id'], pool_params['enable_fragmentation'])
                    pool_obj.result['changed'] = True

            StoragePoolModifySparePercentageHandler().handle(pool_obj, pool_params, pool_details)

        except Exception as e:

            error_msg = (f"Enable/Disable Fragmentation operation failed "
                         f"with error {str(e)}")
            LOG.error(error_msg)
            pool_obj.module.fail_json(msg=error_msg)


class StoragePoolEnableRebuildHandler():
    def handle(self, pool_obj, pool_params, pool_details):
        try:
            if pool_params['state'] == 'present' and pool_details:
                if pool_params['enable_rebuild'] is not None and pool_params['enable_rebuild'] != pool_details['rebuildEnabled']:
                    if not pool_obj.module.check_mode:
                        pool_details = pool_obj.powerflex_conn.storage_pool.set_rebuild_enabled(
                            pool_details['id'], pool_params['enable_rebuild'])
                    pool_obj.result['changed'] = True

            StoragePoolEnableFragmentationHandler().handle(pool_obj, pool_params, pool_details)

        except Exception as e:
            error_msg = (f"Enable/Disable Rebuild operation failed "
                         f"with error {str(e)}")
            LOG.error(error_msg)
            pool_obj.module.fail_json(msg=error_msg)


class StoragePoolEnableRebalanceHandler():
    def handle(self, pool_obj, pool_params, pool_details):
        try:
            if pool_params['state'] == 'present' and pool_details:
                if pool_params['enable_rebalance'] is not None and pool_params['enable_rebalance'] != pool_details['rebalanceEnabled']:
                    if not pool_obj.module.check_mode:
                        pool_details = pool_obj.powerflex_conn.storage_pool.set_rebalance_enabled(
                            pool_details['id'], pool_params['enable_rebalance'])
                    pool_obj.result['changed'] = True

            StoragePoolEnableRebuildHandler().handle(pool_obj, pool_params, pool_details)

        except Exception as e:
            error_msg = (f"Enable/Disable Rebalance failed "
                         f"with error {str(e)}")
            LOG.error(error_msg)
            pool_obj.module.fail_json(msg=error_msg)


class StoragePoolModifyRepCapMaxRatioHandler():
    def handle(self, pool_obj, pool_params, pool_details):
        try:
            if pool_params['state'] == 'present' and pool_details:
                if pool_params['rep_cap_max_ratio'] is not None and pool_params['rep_cap_max_ratio'] != pool_details['replicationCapacityMaxRatio']:
                    if not pool_obj.module.check_mode:
                        pool_details = pool_obj.powerflex_conn.storage_pool.set_rep_cap_max_ratio(
                            pool_details['id'], str(pool_params['rep_cap_max_ratio']))
                    pool_obj.result['changed'] = True

            StoragePoolEnableRebalanceHandler().handle(pool_obj, pool_params, pool_details)

        except Exception as e:
            error_msg = (f"Modify Replication Capacity max ratio operation failed "
                         f"with error {str(e)}")
            LOG.error(error_msg)
            pool_obj.module.fail_json(msg=error_msg)


class StoragePoolEnableZeroPaddingHandler():
    def handle(self, pool_obj, pool_params, pool_details):
        try:
            if pool_params['state'] == 'present' and pool_details:
                if pool_params['enable_zero_padding'] is not None and pool_params['enable_zero_padding'] != pool_details['zeroPaddingEnabled']:
                    if not pool_obj.module.check_mode:
                        pool_details = pool_obj.powerflex_conn.storage_pool.set_zero_padding_policy(
                            pool_details['id'], pool_params['enable_zero_padding'])
                    pool_obj.result['changed'] = True

            StoragePoolModifyRepCapMaxRatioHandler().handle(pool_obj, pool_params, pool_details)

        except Exception as e:
            error_msg = (f"Enable/Disable zero padding operation failed "
                         f"with error {str(e)}")
            LOG.error(error_msg)
            pool_obj.module.fail_json(msg=error_msg)


class StoragePoolUseRFCacheHandler():
    def handle(self, pool_obj, pool_params, pool_details):
        try:
            if pool_params['state'] == 'present' and pool_details:
                if pool_params['use_rfcache'] is not None and pool_params['use_rfcache'] != pool_details['useRfcache']:
                    if not pool_obj.module.check_mode:
                        pool_details = pool_obj.powerflex_conn.storage_pool.set_use_rfcache(
                            pool_details['id'], pool_params['use_rfcache'])
                    pool_obj.result['changed'] = True

            StoragePoolEnableZeroPaddingHandler().handle(pool_obj, pool_params, pool_details)

        except Exception as e:
            error_msg = (f"Modify RF cache operation failed "
                         f"with error {str(e)}")
            LOG.error(error_msg)
            pool_obj.module.fail_json(msg=error_msg)


class StoragePoolUseRMCacheHandler():
    def handle(self, pool_obj, pool_params, pool_details):
        try:
            if pool_params['state'] == 'present' and pool_details:
                if pool_params['use_rmcache'] is not None and pool_params['use_rmcache'] != pool_details['useRmcache']:
                    if not pool_obj.module.check_mode:
                        pool_details = pool_obj.powerflex_conn.storage_pool.set_use_rmcache(
                            pool_details['id'], pool_params['use_rmcache'])
                    pool_obj.result['changed'] = True

            StoragePoolUseRFCacheHandler().handle(pool_obj, pool_params, pool_details)

        except Exception as e:
            error_msg = (f"Modify RM cache operation failed "
                         f"with error {str(e)}")
            LOG.error(error_msg)
            pool_obj.module.fail_json(msg=error_msg)


class StoragePoolRenameHandler():
    def handle(self, pool_obj, pool_params, pool_details):
        try:
            if pool_params['state'] == 'present' and pool_details:
                if pool_params['storage_pool_new_name'] is not None and pool_params['storage_pool_new_name'] != pool_details['name']:
                    if not pool_obj.module.check_mode:
                        pool_obj.powerflex_conn.storage_pool.rename(pool_details['id'], pool_params['storage_pool_new_name'])
                    pool_obj.result['changed'] = True

            StoragePoolUseRMCacheHandler().handle(pool_obj, pool_params, pool_details)

        except Exception as e:
            error_msg = (f"Modify storage pool name failed "
                         f"with error {str(e)}")
            LOG.error(error_msg)
            pool_obj.module.fail_json(msg=error_msg)


class StoragePoolModifyMediaTypeHandler():
    def handle(self, pool_obj, pool_params, pool_details, media_type):
        try:
            if pool_params['state'] == 'present' and pool_details:
                if media_type is not None and media_type != pool_details['mediaType']:
                    if not pool_obj.module.check_mode:
                        pool_details = pool_obj.powerflex_conn.storage_pool.set_media_type(
                            pool_details['id'], media_type)
                    pool_obj.result['changed'] = True

            StoragePoolRenameHandler().handle(pool_obj, pool_params, pool_details)

        except Exception as e:
            error_msg = (f"Modify Media Type failed "
                         f"with error {str(e)}")
            LOG.error(error_msg)
            pool_obj.module.fail_json(msg=error_msg)


class StoragePoolCreateHandler():
    def handle(self, pool_obj, pool_params, pool_details, pd_id, media_type):
        if pool_params['state'] == 'present' and pool_details is None:
            if not pool_obj.module.check_mode:
                LOG.info("Creating new storage pool")
                if pool_params['storage_pool_id']:
                    self.module.fail_json(
                        msg="storage_pool_name is missing & name required to "
                            "create a storage pool. Please enter a valid "
                            "storage_pool_name.")

                pool_details = pool_obj.create_storage_pool(
                    pool_name=pool_params['storage_pool_name'],
                    pd_id=pd_id,
                    media_type=media_type,
                    use_rfcache=pool_params['use_rfcache'],
                    use_rmcache=pool_params['use_rmcache'])

            pool_obj.result['changed'] = True

        StoragePoolModifyMediaTypeHandler().handle(pool_obj, pool_params, pool_details, media_type)


class StoragePoolHandler():
    def handle(self, pool_obj, pool_params):
        pool_obj.verify_storage_pool_name()
        media_type = pool_params['media_type']
        if media_type == "TRANSITIONAL":
            media_type = 'Transitional'
        pd_id = None
        if pool_params['protection_domain_id'] or pool_params['protection_domain_name']:
            pd_id = pool_obj.get_protection_domain(
                protection_domain_id=pool_params['protection_domain_id'],
                protection_domain_name=pool_params['protection_domain_name'])['id']
        pool_details = pool_obj.get_storage_pool(storage_pool_id=pool_params['storage_pool_id'],
                                                 storage_pool_name=pool_params['storage_pool_name'],
                                                 pd_id=pd_id)
        pool_obj.verify_protection_domain(pool_details=pool_details)
        StoragePoolCreateHandler().handle(pool_obj, pool_params, pool_details, pd_id, media_type)


def main():
    """ Create PowerFlex storage pool object and perform action on it
        based on user input from playbook"""
    obj = PowerFlexStoragePool()
    StoragePoolHandler().handle(obj, obj.module.params)


if __name__ == '__main__':
    main()
