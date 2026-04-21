# !/usr/bin/python

# Copyright: (c) 2024, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module for Gathering information about Dell Technologies (Dell) PowerFlex"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: info

version_added: '1.0.0'

short_description: Gathering information about Dell PowerFlex

description:
- Gathering information about Dell PowerFlex storage system includes
  getting the api details, list of volumes, SDSs, SDCs, storage pools,
  protection domains, snapshot policies, and devices.
- Gathering information about Dell PowerFlex Manager includes getting the
  list of managed devices, deployments, service templates and firmware repository.

extends_documentation_fragment:
  - dellemc.powerflex.powerflex

author:
- Arindam Datta (@dattaarindam) <ansible.team@dell.com>
- Trisha Datta (@trisha-dell) <ansible.team@dell.com>
- Jennifer John (@Jennifer-John) <ansible.team@dell.com>
- Felix Stephen (@felixs88) <ansible.team@dell.com>

options:
  gather_subset:
    description:
    - List of string variables to specify the PowerFlex storage system
      entities for which information is required.
    - Volumes - C(vol).
    - Storage pools - C(storage_pool).
    - Protection domains - C(protection_domain).
    - SDCs - C(sdc).
    - SDSs - C(sds).
    - Snapshot policies - C(snapshot_policy).
    - Devices - C(device).
    - Replication consistency groups - C(rcg).
    - Replication pairs - C(replication_pair).
    - Fault Sets - C(fault_set).
    - Service templates - C(service_template).
    - Managed devices - C(managed_device).
    - Deployments - C(deployment).
    - FirmwareRepository - C(firmware_repository).
    - NVMe host - C(nvme_host)
    - NVMe Storage Data Target  - C(sdt).
    choices: [vol, storage_pool, protection_domain, sdc, sds,
             snapshot_policy, device, rcg, replication_pair,
             fault_set, service_template, managed_device, deployment, firmware_repository,
             nvme_host, sdt]
    type: list
    elements: str
  filters:
    description:
    - List of filters to support filtered output for storage entities.
    - Each filter is a list of I(filter_key), I(filter_operator), I(filter_value).
    - Supports passing of multiple filters.
    type: list
    elements: dict
    suboptions:
      filter_key:
        description:
        - Name identifier of the filter.
        type: str
        required: true
      filter_operator:
        description:
        - Operation to be performed on filter key.
        - Choice C(contains) is supported for I(gather_subset) keys C(service_template), C(managed_device),
          C(deployment), C(firmware_repository).
        type: str
        choices: [equal, contains]
        required: true
      filter_value:
        description:
        - Value of the filter key.
        type: str
        required: true
  limit:
    description:
    - Page limit.
    - Supported for I(gather_subset) keys C(service_template), C(managed_device), C(deployment), C(firmware_repository).
    type: int
    default: 50
  offset:
    description:
    - Pagination offset.
    - Supported for I(gather_subset) keys C(service_template), C(managed_device), C(deployment), C(firmware_repository).
    type: int
    default: 0
  sort:
    description:
    - Sort the returned components based on specified field.
    - Supported for I(gather_subset) keys C(service_template), C(managed_device), C(deployment), C(firmware_repository).
    - The supported sort keys for the I(gather_subset) can be referred from PowerFlex Manager API documentation in U(https://developer.dell.com).
    type: str
  include_devices:
    description:
    - Include devices in response.
    - Applicable when I(gather_subset) is C(deployment).
    type: bool
    default: true
  include_template:
    description:
    - Include service templates in response.
    - Applicable when I(gather_subset) is C(deployment).
    type: bool
    default: true
  full:
    description:
    - Specify if response is full or brief.
    - Applicable when I(gather_subset) is C(deployment), C(service_template).
    - For C(deployment) specify to use full templates including resources in response.
    type: bool
    default: false
  include_attachments:
    description:
    - Include attachments.
    - Applicable when I(gather_subset) is C(service_template).
    type: bool
    default: true
  include_related:
    description:
    - Include related entities.
    - Applicable when I(gather_subset) is C(firmware_repository).
    type: bool
    default: false
    version_added: 2.3.0
  include_bundles:
    description:
    - Include software bundle entities.
    - Applicable when I(gather_subset) is C(firmware_repository).
    type: bool
    default: false
    version_added: 2.3.0
  include_components:
    description:
    - Include software component entities.
    - Applicable when I(gather_subset) is C(firmware_repository).
    type: bool
    default: false
    version_added: 2.3.0
notes:
  - The I(check_mode) is supported.
  - The supported filter keys for the I(gather_subset) can be referred from PowerFlex Manager API documentation in U(https://developer.dell.com).
  - The I(filter), I(sort), I(limit) and I(offset) options will be ignored when more than one I(gather_subset) is specified along with
    C(service_template), C(managed_device), C(deployment) or C(firmware_repository).
'''

EXAMPLES = r'''
- name: Get detailed list of PowerFlex entities
  dellemc.powerflex.info:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    gather_subset:
      - vol
      - storage_pool
      - protection_domain
      - sdc
      - sds
      - snapshot_policy
      - device
      - rcg
      - replication_pair
      - fault_set
      - nvme_host
      - sdt

- name: Get a subset list of PowerFlex volumes
  dellemc.powerflex.info:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    gather_subset:
      - vol
    filters:
      - filter_key: "name"
        filter_operator: "equal"
        filter_value: "ansible_test"

- name: Get deployment and resource provisioning info
  dellemc.powerflex.info:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    gather_subset:
      - managed_device
      - deployment
      - service_template

- name: Get deployment with filter, sort, pagination
  dellemc.powerflex.info:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    gather_subset:
      - deployment
    filters:
      - filter_key: "name"
        filter_operator: "contains"
        filter_value: "partial"
    sort: name
    limit: 10
    offset: 10
    include_devices: true
    include_template: true

- name: Get the list of firmware repository.
  dellemc.powerflex.info:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    gather_subset:
      - firmware_repository

- name: Get the list of firmware repository
  dellemc.powerflex.info:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    gather_subset:
      - firmware_repository
    include_related: true
    include_bundles: true
    include_components: true

- name: Get the list of firmware repository with filter
  dellemc.powerflex.info:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    gather_subset:
      - firmware_repository
    filters:
      - filter_key: "createdBy"
        filter_operator: "equal"
        filter_value: "admin"
    sort: createdDate
    limit: 10
    include_related: true
    include_bundles: true
    include_components: true
  register: result_repository_out

- name: Get the list of available firmware repository
  ansible.builtin.debug:
    msg: "{{ result_repository_out.FirmwareRepository | selectattr('state', 'equalto', 'available') }}"

- name: Get the list of software components in the firmware repository
  ansible.builtin.debug:
    msg: "{{ result_repository_out.FirmwareRepository |
        selectattr('id', 'equalto', '8aaa80788b7') | map(attribute='softwareComponents') | flatten }}"

- name: Get the list of software bundles in the firmware repository
  ansible.builtin.debug:
    msg: "{{ result_repository_out.FirmwareRepository |
        selectattr('id', 'equalto', '8aaa80788b7') | map(attribute='softwareBundles') | flatten }}"

- name: Get the list of NVMe hosts
  dellemc.powerflex.info:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    gather_subset:
      - nvme_host
    filters:
      - filter_key: "name"
        filter_operator: "equal"
        filter_value: "ansible_test"

- name: Get the list of NVMe Storage Data Target
  dellemc.powerflex.info:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    gather_subset:
      - sdt
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: 'false'
Array_Details:
    description: System entities of PowerFlex storage array.
    returned: always
    type: dict
    contains:
        addressSpaceUsage:
            description: Address space usage.
            type: str
        authenticationMethod:
            description: Authentication method.
            type: str
        capacityAlertCriticalThresholdPercent:
            description: Capacity alert critical threshold percentage.
            type: int
        capacityAlertHighThresholdPercent:
            description: Capacity alert high threshold percentage.
            type: int
        capacityTimeLeftInDays:
            description: Capacity time left in days.
            type: str
        cliPasswordAllowed:
            description: CLI password allowed.
            type: bool
        daysInstalled:
            description: Days installed.
            type: int
        defragmentationEnabled:
            description: Defragmentation enabled.
            type: bool
        enterpriseFeaturesEnabled:
            description: Enterprise features enabled.
            type: bool
        id:
            description: The ID of the system.
            type: str
        installId:
            description: installation Id.
            type: str
        isInitialLicense:
            description: Initial license.
            type: bool
        lastUpgradeTime:
            description: Last upgrade time.
            type: int
        managementClientSecureCommunicationEnabled:
            description: Management client secure communication enabled.
            type: bool
        maxCapacityInGb:
            description: Maximum capacity in GB.
            type: dict
        mdmCluster:
            description: MDM cluster details.
            type: dict
        mdmExternalPort:
            description: MDM external port.
            type: int
        mdmManagementPort:
            description: MDM management port.
            type: int
        mdmSecurityPolicy:
            description: MDM security policy.
            type: str
        showGuid:
            description: Show guid.
            type: bool
        swid:
            description: SWID.
            type: str
        systemVersionName:
            description: System version and name.
            type: str
        tlsVersion:
            description: TLS version.
            type: str
        upgradeState:
            description: Upgrade state.
            type: str
    sample: {
        "addressSpaceUsage": "Normal",
        "authenticationMethod": "Native",
        "capacityAlertCriticalThresholdPercent": 90,
        "capacityAlertHighThresholdPercent": 80,
        "capacityTimeLeftInDays": "24",
        "cliPasswordAllowed": true,
        "daysInstalled": 66,
        "defragmentationEnabled": true,
        "enterpriseFeaturesEnabled": true,
        "id": "4a54a8ba6df0690f",
        "installId": "38622771228e56db",
        "isInitialLicense": true,
        "lastUpgradeTime": 0,
        "managementClientSecureCommunicationEnabled": true,
        "maxCapacityInGb": "Unlimited",
        "mdmCluster": {
            "clusterMode": "ThreeNodes",
            "clusterState": "ClusteredNormal",
            "goodNodesNum": 3,
            "goodReplicasNum": 2,
            "id": "5356091375512217871",
            "master": {
                "id": "6101582c2ca8db00",
                "ips": [
                    "10.47.xxx.xxx"
                ],
                "managementIPs": [
                    "10.47.xxx.xxx"
                ],
                "name": "node0",
                "opensslVersion": "OpenSSL 1.0.2k-fips  26 Jan 2017",
                "port": 9011,
                "role": "Manager",
                "status": "Normal",
                "versionInfo": "R3_6.0.0",
                "virtualInterfaces": [
                    "ens160"
                ]
            },
            "slaves": [
                {
                    "id": "23fb724015661901",
                    "ips": [
                        "10.47.xxx.xxx"
                    ],
                    "managementIPs": [
                        "10.47.xxx.xxx"
                    ],
                    "opensslVersion": "OpenSSL 1.0.2k-fips  26 Jan 2017",
                    "port": 9011,
                    "role": "Manager",
                    "status": "Normal",
                    "versionInfo": "R3_6.0.0",
                    "virtualInterfaces": [
                        "ens160"
                    ]
                }
            ],
            "tieBreakers": [
                {
                    "id": "6ef27eb20d0c1202",
                    "ips": [
                        "10.47.xxx.xxx"
                    ],
                    "managementIPs": [
                        "10.47.xxx.xxx"
                    ],
                    "opensslVersion": "N/A",
                    "port": 9011,
                    "role": "TieBreaker",
                    "status": "Normal",
                    "versionInfo": "R3_6.0.0"
                }
            ]
        },
        "mdmExternalPort": 7611,
        "mdmManagementPort": 6611,
        "mdmSecurityPolicy": "None",
        "showGuid": true,
        "swid": "",
        "systemVersionName": "DellEMC PowerFlex Version: R3_6.0.354",
        "tlsVersion": "TLSv1.2",
        "upgradeState": "NoUpgrade"
    }
API_Version:
    description: API version of PowerFlex API Gateway.
    returned: always
    type: str
    sample: "3.5"
Protection_Domains:
    description: Details of all protection domains.
    returned: always
    type: list
    contains:
        id:
            description: protection domain id.
            type: str
        name:
            description: protection domain name.
            type: str
    sample: [
        {
            "id": "9300e90900000001",
            "name": "domain2"
        },
        {
            "id": "9300c1f900000000",
            "name": "domain1"
        }
    ]
SDCs:
    description: Details of storage data clients.
    returned: always
    type: list
    contains:
        id:
            description: storage data client id.
            type: str
        name:
            description: storage data client name.
            type: str
    sample: [
        {
            "id": "07335d3d00000006",
            "name": "LGLAP203"
        },
        {
            "id": "07335d3c00000005",
            "name": "LGLAP178"
        },
        {
            "id": "0733844a00000003"
        }
    ]
SDSs:
    description: Details of storage data servers.
    returned: always
    type: list
    contains:
        id:
            description: storage data server id.
            type: str
        name:
            description: storage data server name.
            type: str
    sample: [
        {
            "id": "8f3bb0cc00000002",
            "name": "node0"
        },
        {
            "id": "8f3bb0ce00000000",
            "name": "node1"
        },
        {
            "id": "8f3bb15300000001",
            "name": "node22"
        }
    ]
Snapshot_Policies:
    description: Details of snapshot policies.
    returned: always
    type: list
    contains:
        id:
            description: snapshot policy id.
            type: str
        name:
            description: snapshot policy name.
            type: str
    sample: [
        {
            "id": "2b380c5c00000000",
            "name": "sample_snap_policy"
        },
        {
            "id": "2b380c5d00000001",
            "name": "sample_snap_policy_1"
        }
    ]
Storage_Pools:
    description: Details of storage pools.
    returned: always
    type: list
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
        statistics:
            description: Statistics details of the storage pool.
            type: dict
            contains:
                capacityInUseInKb:
                    description: Total capacity of the storage pool.
                    type: str
                unusedCapacityInKb:
                    description: Unused capacity of the storage pool.
                    type: str
                deviceIds:
                    description: Device Ids of the storage pool.
                    type: list
    sample: [
        {
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
    ]
Volumes:
    description: Details of volumes.
    returned: always
    type: list
    contains:
        id:
            description: The ID of the volume.
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
                    description: mapping access mode for the specified volume.
                    type: str
                limitIops:
                    description: IOPS limit for the SDC.
                    type: int
                limitBwInMbps:
                    description: Bandwidth limit for the SDC.
                    type: int
        name:
            description: Name of the volume.
            type: str
        sizeInKb:
            description: Size of the volume in Kb.
            type: int
        sizeInGb:
            description: Size of the volume in Gb.
            type: int
        storagePoolId:
            description: ID of the storage pool in which volume resides.
            type: str
        storagePoolName:
            description: Name of the storage pool in which volume resides.
            type: str
        protectionDomainId:
            description: ID of the protection domain in which volume resides.
            type: str
        protectionDomainName:
            description: Name of the protection domain in which volume resides.
            type: str
        snapshotPolicyId:
            description: ID of the snapshot policy associated with volume.
            type: str
        snapshotPolicyName:
            description: Name of the snapshot policy associated with volume.
            type: str
        snapshotsList:
            description: List of snapshots associated with the volume.
            type: str
        "statistics":
            description: Statistics details of the storage pool.
            type: dict
            contains:
                "numOfChildVolumes":
                    description: Number of child volumes.
                    type: int
                "numOfMappedSdcs":
                    description: Number of mapped Sdcs of the volume.
                    type: int
    sample: [
        {
            "accessModeLimit": "ReadWrite",
            "ancestorVolumeId": null,
            "autoSnapshotGroupId": null,
            "compressionMethod": "Invalid",
            "consistencyGroupId": null,
            "creationTime": 1661234220,
            "dataLayout": "MediumGranularity",
            "id": "456afd7XXXXXXX",
            "lockedAutoSnapshot": false,
            "lockedAutoSnapshotMarkedForRemoval": false,
            "managedBy": "ScaleIO",
            "mappedSdcInfo": [
                {
                "accessMode": "ReadWrite",
                "isDirectBufferMapping": false,
                "limitBwInMbps": 0,
                "limitIops": 0,
                "sdcId": "c42425cbXXXXX",
                "sdcIp": "10.XXX.XX.XX",
                "sdcName": null
                }
            ],
            "name": "vol-1",
            "notGenuineSnapshot": false,
            "originalExpiryTime": 0,
            "pairIds": null,
            "replicationJournalVolume": false,
            "replicationTimeStamp": 0,
            "retentionLevels": [
            ],
            "secureSnapshotExpTime": 0,
            "sizeInKb": 8388608,
            "snplIdOfAutoSnapshot": null,
            "snplIdOfSourceVolume": null,
            "statistics": {
                "childVolumeIds": [
                ],
                "descendantVolumeIds": [
                ],
                "initiatorSdcId": null,
                "mappedSdcIds": [
                "c42425XXXXXX"
                ],
                "numOfChildVolumes": 0,
                "numOfDescendantVolumes": 0,
                "numOfMappedSdcs": 1,
                "registrationKey": null,
                "registrationKeys": [
                ],
                "replicationJournalVolume": false,
                "replicationState": "UnmarkedForReplication",
                "reservationType": "NotReserved",
                "rplTotalJournalCap": 0,
                "rplUsedJournalCap": 0,
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
                }
            },
            "storagePoolId": "7630a248XXXXXXX",
            "timeStampIsAccurate": false,
            "useRmcache": false,
            "volumeReplicationState": "UnmarkedForReplication",
            "volumeType": "ThinProvisioned",
            "vtreeId": "32b168bXXXXXX"
        }
    ]
Devices:
    description: Details of devices.
    returned: always
    type: list
    contains:
        id:
            description: device id.
            type: str
        name:
            description: device name.
            type: str
    sample:  [
        {
            "id": "b6efa59900000000",
            "name": "device230"
        },
        {
            "id": "b6efa5fa00020000",
            "name": "device_node0"
        },
        {
            "id": "b7f3a60900010000",
            "name": "device22"
        }
    ]
Replication_Consistency_Groups:
    description: Details of rcgs.
    returned: always
    type: list
    contains:
        id:
            description: The ID of the replication consistency group.
            type: str
        name:
            description: The name of the replication consistency group.
            type: str
        protectionDomainId:
            description: The Protection Domain ID of the replication consistency group.
            type: str
        peerMdmId:
            description: The ID of the peer MDM of the replication consistency group.
            type: str
        remoteId:
            description: The ID of the remote replication consistency group.
            type: str
        remoteMdmId:
            description: The ID of the remote MDM of the replication consistency group.
            type: str
        currConsistMode:
            description: The current consistency mode of the replication consistency group.
            type: str
        freezeState:
            description: The freeze state of the replication consistency group.
            type: str
        lifetimeState:
            description: The Lifetime state of the replication consistency group.
            type: str
        pauseMode:
            description: The Lifetime state of the replication consistency group.
            type: str
        snapCreationInProgress:
            description: Whether the process of snapshot creation of the replication consistency group is in progress or not.
            type: bool
        lastSnapGroupId:
            description: ID of the last snapshot of the replication consistency group.
            type: str
        lastSnapCreationRc:
            description: The return code of the last snapshot of the replication consistency group.
            type: int
        targetVolumeAccessMode:
            description: The access mode of the target volume of the replication consistency group.
            type: str
        remoteProtectionDomainId:
            description: The ID of the remote Protection Domain.
            type: str
        remoteProtectionDomainName:
            description: The Name of the remote Protection Domain.
            type: str
        failoverType:
            description: The type of failover of the replication consistency group.
            type: str
        failoverState:
            description: The state of failover of the replication consistency group.
            type: str
        activeLocal:
            description: Whether the local replication consistency group is active.
            type: bool
        activeRemote:
            description: Whether the remote replication consistency group is active
            type: bool
        abstractState:
            description: The abstract state of the replication consistency group.
            type: str
        localActivityState:
            description: The state of activity of the local replication consistency group.
            type: str
        remoteActivityState:
            description: The state of activity of the remote replication consistency group..
            type: str
        inactiveReason:
            description: The reason for the inactivity of the replication consistency group.
            type: int
        rpoInSeconds:
            description: The RPO value of the replication consistency group in seconds.
            type: int
        replicationDirection:
            description: The direction of the replication of the replication consistency group.
            type: str
        disasterRecoveryState:
            description: The state of disaster recovery of the local replication consistency group.
            type: str
        remoteDisasterRecoveryState:
            description: The state of disaster recovery of the remote replication consistency group.
            type: str
        error:
            description: The error code of the replication consistency group.
            type: int
        type:
            description: The type of the replication consistency group.
            type: str
    sample: {
        "protectionDomainId": "b969400500000000",
        "peerMdmId": "6c3d94f600000000",
        "remoteId": "2130961a00000000",
        "remoteMdmId": "0e7a082862fedf0f",
        "currConsistMode": "Consistent",
        "freezeState": "Unfrozen",
        "lifetimeState": "Normal",
        "pauseMode": "None",
        "snapCreationInProgress": false,
        "lastSnapGroupId": "e58280b300000001",
        "lastSnapCreationRc": "SUCCESS",
        "targetVolumeAccessMode": "NoAccess",
        "remoteProtectionDomainId": "4eeb304600000000",
        "remoteProtectionDomainName": "domain1",
        "failoverType": "None",
        "failoverState": "None",
        "activeLocal": true,
        "activeRemote": true,
        "abstractState": "Ok",
        "localActivityState": "Active",
        "remoteActivityState": "Active",
        "inactiveReason": 11,
        "rpoInSeconds": 30,
        "replicationDirection": "LocalToRemote",
        "disasterRecoveryState": "None",
        "remoteDisasterRecoveryState": "None",
        "error": 65,
        "name": "test_rcg",
        "type": "User",
        "id": "aadc17d500000000"
    }
Replication_pairs:
    description: Details of the replication pairs.
    returned: Always
    type: list
    contains:
        id:
            description: The ID of the replication pair.
            type: str
        name:
            description: The name of the replication pair.
            type: str
        remoteId:
            description: The ID of the remote replication pair.
            type: str
        localVolumeId:
            description: The ID of the local volume.
            type: str
        replicationConsistencyGroupId:
            description: The ID of the replication consistency group.
            type: str
        copyType:
            description: The copy type of the replication pair.
            type: str
        initialCopyState:
            description: The inital copy state of the replication pair.
            type: str
        localActivityState:
            description: The state of activity of the local replication pair.
            type: str
        remoteActivityState:
            description: The state of activity of the remote replication pair.
            type: str
    sample: {
        "copyType": "OnlineCopy",
        "id": "23aa0bc900000001",
        "initialCopyPriority": -1,
        "initialCopyState": "Done",
        "lifetimeState": "Normal",
        "localActivityState": "RplEnabled",
        "localVolumeId": "e2bc1fab00000008",
        "name": null,
        "peerSystemName": null,
        "remoteActivityState": "RplEnabled",
        "remoteCapacityInMB": 8192,
        "remoteId": "a058446700000001",
        "remoteVolumeId": "1cda7af20000000d",
        "remoteVolumeName": "vol",
        "replicationConsistencyGroupId": "e2ce036b00000002",
        "userRequestedPauseTransmitInitCopy": false
    }
Fault_Sets:
    description: Details of fault sets.
    returned: always
    type: list
    contains:
        protectionDomainId:
            description: The ID of the protection domain.
            type: str
        name:
            description: device name.
            type: str
        id:
            description: device id.
            type: str
    sample:  [
        {
            "protectionDomainId": "da721a8300000000",
            "protectionDomainName": "fault_set_1",
            "name": "at1zbs1t6cp2sds1d1fs1",
            "SDS": [],
            "id": "eb44b70500000000",
            "links": [
                { "rel": "self", "href": "/api/instances/FaultSet::eb44b70500000000" },
                {
                    "rel": "/api/FaultSet/relationship/Statistics",
                    "href": "/api/instances/FaultSet::eb44b70500000000/relationships/Statistics"
                },
                {
                    "rel": "/api/FaultSet/relationship/Sds",
                    "href": "/api/instances/FaultSet::eb44b70500000000/relationships/Sds"
                },
                {
                    "rel": "/api/parent/relationship/protectionDomainId",
                    "href": "/api/instances/ProtectionDomain::da721a8300000000"
                }
            ]
        },
        {
            "protectionDomainId": "da721a8300000000",
            "protectionDomainName": "fault_set_2",
            "name": "at1zbs1t6cp2sds1d1fs3",
            "SDS": [],
            "id": "eb44b70700000002",
            "links": [
                { "rel": "self", "href": "/api/instances/FaultSet::eb44b70700000002" },
                {
                    "rel": "/api/FaultSet/relationship/Statistics",
                    "href": "/api/instances/FaultSet::eb44b70700000002/relationships/Statistics"
                },
                {
                    "rel": "/api/FaultSet/relationship/Sds",
                    "href": "/api/instances/FaultSet::eb44b70700000002/relationships/Sds"
                },
                {
                    "rel": "/api/parent/relationship/protectionDomainId",
                    "href": "/api/instances/ProtectionDomain::da721a8300000000"
                }
            ]
        }
    ]
ManagedDevices:
    description: Details of all devices from inventory.
    returned: when I(gather_subset) is I(managed_device)
    type: list
    contains:
        deviceType:
            description: Device Type.
            type: str
        serviceTag:
            description: Service Tag.
            type: str
        serverTemplateId:
            description: The ID of the server template.
            type: str
        state:
            description: The state of the device.
            type: str
        managedState:
            description: The managed state of the device.
            type: str
        compliance:
            description: The compliance state of the device.
            type: str
        systemId:
            description: The system ID.
            type: str
    sample: [{
        "refId": "softwareOnlyServer-10.1.1.1",
        "refType": null,
        "ipAddress": "10.1.1.1",
        "currentIpAddress": "10.1.1.1",
        "serviceTag": "VMware-42 15 a5 f9 65 e6 63 0e-36 79 59 73 7b 3a 68 cd-SW",
        "model": "VMware Virtual Platform",
        "deviceType": "SoftwareOnlyServer",
        "discoverDeviceType": "SOFTWAREONLYSERVER_CENTOS",
        "displayName": "vpi1011-c1n1",
        "managedState": "UNMANAGED",
        "state": "READY",
        "inUse": false,
        "serviceReferences": [],
        "statusMessage": null,
        "firmwareName": "Default Catalog - PowerFlex 4.5.0.0",
        "customFirmware": false,
        "needsAttention": false,
        "manufacturer": "VMware, Inc.",
        "systemId": null,
        "health": "RED",
        "healthMessage": "Inventory run failed.",
        "operatingSystem": "N/A",
        "numberOfCPUs": 0,
        "cpuType": null,
        "nics": 0,
        "memoryInGB": 0,
        "infraTemplateDate": null,
        "infraTemplateId": null,
        "serverTemplateDate": null,
        "serverTemplateId": null,
        "inventoryDate": null,
        "complianceCheckDate": "2024-02-05T18:31:31.213+00:00",
        "discoveredDate": "2024-02-05T18:31:30.992+00:00",
        "deviceGroupList": {
            "paging": null,
            "deviceGroup": [
                {
                    "link": null,
                    "groupSeqId": -1,
                    "groupName": "Global",
                    "groupDescription": null,
                    "createdDate": null,
                    "createdBy": "admin",
                    "updatedDate": null,
                    "updatedBy": null,
                    "managedDeviceList": null,
                    "groupUserList": null
                }
            ]
        },
        "detailLink": {
            "title": "softwareOnlyServer-10.1.1.1",
            "href": "/AsmManager/ManagedDevice/softwareOnlyServer-10.1.1.1",
            "rel": "describedby",
            "type": null
        },
        "credId": "bc97cefb-5eb4-4c20-8e39-d1a2b809c9f5",
        "compliance": "NONCOMPLIANT",
        "failuresCount": 0,
        "chassisId": null,
        "parsedFacts": null,
        "config": null,
        "hostname": "vpi1011-c1n1",
        "osIpAddress": null,
        "osAdminCredential": null,
        "osImageType": null,
        "lastJobs": null,
        "puppetCertName": "red_hat-10.1.1.1",
        "svmAdminCredential": null,
        "svmName": null,
        "svmIpAddress": null,
        "svmImageType": null,
        "flexosMaintMode": 0,
        "esxiMaintMode": 0,
        "vmList": []
    }]
Deployments:
    description: Details of all deployments.
    returned: when I(gather_subset) is I(deployment)
    type: list
    contains:
        id:
            description: Deployment ID.
            type: str
        deploymentName:
            description: Deployment name.
            type: str
        status:
            description: The status of deployment.
            type: str
        firmwareRepository:
            description: The firmware repository.
            type: dict
            contains:
                signature:
                    description: The signature details.
                    type: str
                downloadStatus:
                    description: The download status.
                    type: str
                rcmapproved:
                    description: If RCM approved.
                    type: bool
    sample: [{
        "id": "8aaa80658cd602e0018cda8b257f78ce",
        "deploymentName": "Test-Update - K",
        "deploymentDescription": "Test-Update - K",
        "deploymentValid": null,
        "retry": false,
        "teardown": false,
        "teardownAfterCancel": false,
        "removeService": false,
        "createdDate": "2024-01-05T16:53:21.407+00:00",
        "createdBy": "admin",
        "updatedDate": "2024-02-11T17:00:05.657+00:00",
        "updatedBy": "system",
        "deploymentScheduledDate": null,
        "deploymentStartedDate": "2024-01-05T16:53:22.886+00:00",
        "deploymentFinishedDate": null,
        "serviceTemplate": {
            "id": "8aaa80658cd602e0018cda8b257f78ce",
            "templateName": "block-only (8aaa80658cd602e0018cda8b257f78ce)",
            "templateDescription": "Storage - Software Only deployment",
            "templateType": "VxRack FLEX",
            "templateVersion": "4.5.0.0",
            "templateValid": {
                "valid": true,
                "messages": []
            },
            "originalTemplateId": "c44cb500-020f-4562-9456-42ec1eb5f9b2",
            "templateLocked": false,
            "draft": false,
            "inConfiguration": false,
            "createdDate": "2024-01-05T16:53:22.083+00:00",
            "createdBy": null,
            "updatedDate": "2024-02-09T06:00:09.602+00:00",
            "lastDeployedDate": null,
            "updatedBy": null,
            "components": [
                {
                    "id": "6def7edd-bae2-4420-93bf-9ceb051bbb65",
                    "componentID": "component-scaleio-gateway-1",
                    "identifier": null,
                    "componentValid": {
                        "valid": true,
                        "messages": []
                    },
                    "puppetCertName": "scaleio-block-legacy-gateway",
                    "osPuppetCertName": null,
                    "name": "block-legacy-gateway",
                    "type": "SCALEIO",
                    "subType": "STORAGEONLY",
                    "teardown": false,
                    "helpText": null,
                    "managementIpAddress": null,
                    "configFile": null,
                    "serialNumber": null,
                    "asmGUID": "scaleio-block-legacy-gateway",
                    "relatedComponents": {
                        "625b0e17-9b91-4bc0-864c-d0111d42d8d0": "Node (Software Only)",
                        "961a59eb-80c3-4a3a-84b7-2101e9831527": "Node (Software Only)-2",
                        "bca710a5-7cdf-481e-b729-0b53e02873ee": "Node (Software Only)-3"
                    },
                    "resources": [],
                    "refId": null,
                    "cloned": false,
                    "clonedFromId": null,
                    "manageFirmware": false,
                    "brownfield": false,
                    "instances": 1,
                    "clonedFromAsmGuid": null,
                    "ip": null
                }
            ],
            "category": "block-only",
            "allUsersAllowed": true,
            "assignedUsers": [],
            "manageFirmware": true,
            "useDefaultCatalog": false,
            "firmwareRepository": null,
            "licenseRepository": null,
            "configuration": null,
            "serverCount": 3,
            "storageCount": 1,
            "clusterCount": 1,
            "serviceCount": 0,
            "switchCount": 0,
            "vmCount": 0,
            "sdnasCount": 0,
            "brownfieldTemplateType": "NONE",
            "networks": [
                {
                    "id": "8aaa80648cd5fb9b018cda46e4e50000",
                    "name": "mgmt",
                    "description": "",
                    "type": "SCALEIO_MANAGEMENT",
                    "vlanId": 850,
                    "static": true,
                    "staticNetworkConfiguration": {
                        "gateway": "10.1.1.1",
                        "subnet": "1.1.1.0",
                        "primaryDns": "10.1.1.1",
                        "secondaryDns": "10.1.1.1",
                        "dnsSuffix": null,
                        "ipRange": [
                            {
                                "id": "8aaa80648cd5fb9b018cda46e5080001",
                                "startingIp": "10.1.1.1",
                                "endingIp": "10.1.1.1",
                                "role": null
                            }
                        ],
                        "ipAddress": null,
                        "staticRoute": null
                    },
                    "destinationIpAddress": "10.1.1.1"
                }
            ],
            "blockServiceOperationsMap": {
                "scaleio-block-legacy-gateway": {
                    "blockServiceOperationsMap": {}
                }
            }
        },
        "scheduleDate": null,
        "status": "complete",
        "compliant": true,
        "deploymentDevice": [
            {
                "refId": "scaleio-block-legacy-gateway",
                "refType": null,
                "logDump": null,
                "status": null,
                "statusEndTime": null,
                "statusStartTime": null,
                "deviceHealth": "GREEN",
                "healthMessage": "OK",
                "compliantState": "COMPLIANT",
                "brownfieldStatus": "NOT_APPLICABLE",
                "deviceType": "scaleio",
                "deviceGroupName": null,
                "ipAddress": "block-legacy-gateway",
                "currentIpAddress": "10.1.1.1",
                "serviceTag": "block-legacy-gateway",
                "componentId": null,
                "statusMessage": null,
                "model": "PowerFlex Gateway",
                "cloudLink": false,
                "dasCache": false,
                "deviceState": "READY",
                "puppetCertName": "scaleio-block-legacy-gateway",
                "brownfield": false
            }
        ],
        "vms": null,
        "updateServerFirmware": true,
        "useDefaultCatalog": false,
        "firmwareRepository": {
            "id": "8aaa80658cd602e0018cd996a1c91bdc",
            "name": "Intelligent Catalog 45.373.00",
            "sourceLocation": null,
            "sourceType": null,
            "diskLocation": null,
            "filename": null,
            "md5Hash": null,
            "username": null,
            "password": null,
            "downloadStatus": null,
            "createdDate": null,
            "createdBy": null,
            "updatedDate": null,
            "updatedBy": null,
            "defaultCatalog": false,
            "embedded": false,
            "state": null,
            "softwareComponents": [],
            "softwareBundles": [],
            "deployments": [],
            "bundleCount": 0,
            "componentCount": 0,
            "userBundleCount": 0,
            "minimal": false,
            "downloadProgress": 0,
            "extractProgress": 0,
            "fileSizeInGigabytes": null,
            "signedKeySourceLocation": null,
            "signature": null,
            "custom": false,
            "needsAttention": false,
            "jobId": null,
            "rcmapproved": false
        },
        "firmwareRepositoryId": "8aaa80658cd602e0018cd996a1c91bdc",
        "licenseRepository": null,
        "licenseRepositoryId": null,
        "individualTeardown": false,
        "deploymentHealthStatusType": "green",
        "assignedUsers": [],
        "allUsersAllowed": true,
        "owner": "admin",
        "noOp": false,
        "firmwareInit": false,
        "disruptiveFirmware": false,
        "preconfigureSVM": false,
        "preconfigureSVMAndUpdate": false,
        "servicesDeployed": "NONE",
        "precalculatedDeviceHealth": null,
        "lifecycleModeReasons": [],
        "jobDetails": null,
        "numberOfDeployments": 0,
        "operationType": "NONE",
        "operationStatus": null,
        "operationData": null,
        "deploymentValidationResponse": null,
        "currentStepCount": null,
        "totalNumOfSteps": null,
        "currentStepMessage": null,
        "customImage": "os_sles",
        "originalDeploymentId": null,
        "currentBatchCount": null,
        "totalBatchCount": null,
        "templateValid": true,
        "lifecycleMode": false,
        "vds": false,
        "scaleUp": false,
        "brownfield": false,
        "configurationChange": false
    }]
ServiceTemplates:
    description: Details of all service templates.
    returned: when I(gather_subset) is I(service_template)
    type: list
    contains:
        templateName:
            description: Template name.
            type: str
        templateDescription:
            description: Template description.
            type: str
        templateType:
            description: Template type.
            type: str
        templateVersion:
            description: Template version.
            type: str
        category:
            description: The template category.
            type: str
        serverCount:
            description: Server count.
            type: int
    sample: [{
        "id": "2434144f-7795-4245-a04b-6fcb771697d7",
        "templateName": "Storage- 100Gb",
        "templateDescription": "Storage Only 4 Node deployment with 100Gb networking",
        "templateType": "VxRack FLEX",
        "templateVersion": "4.5-213",
        "templateValid": {
            "valid": true,
            "messages": []
        },
        "originalTemplateId": "ff80808177f880fc0177f883bf1e0027",
        "templateLocked": true,
        "draft": false,
        "inConfiguration": false,
        "createdDate": "2024-01-04T19:47:23.534+00:00",
        "createdBy": "system",
        "updatedDate": null,
        "lastDeployedDate": null,
        "updatedBy": null,
        "components": [
            {
                "id": "43dec024-85a9-4901-9e8e-fa0d3c417f7b",
                "componentID": "component-scaleio-gateway-1",
                "identifier": null,
                "componentValid": {
                    "valid": true,
                    "messages": []
                },
                "puppetCertName": null,
                "osPuppetCertName": null,
                "name": "PowerFlex Cluster",
                "type": "SCALEIO",
                "subType": "STORAGEONLY",
                "teardown": false,
                "helpText": null,
                "managementIpAddress": null,
                "configFile": null,
                "serialNumber": null,
                "asmGUID": null,
                "relatedComponents": {
                    "c5c46733-012c-4dca-af9b-af46d73d045a": "Storage Only Node"
                },
                "resources": [],
                "refId": null,
                "cloned": false,
                "clonedFromId": null,
                "manageFirmware": false,
                "brownfield": false,
                "instances": 1,
                "clonedFromAsmGuid": null,
                "ip": null
            }
        ],
        "category": "Sample Templates",
        "allUsersAllowed": false,
        "assignedUsers": [],
        "manageFirmware": true,
        "useDefaultCatalog": true,
        "firmwareRepository": null,
        "licenseRepository": null,
        "configuration": null,
        "serverCount": 4,
        "storageCount": 0,
        "clusterCount": 1,
        "serviceCount": 0,
        "switchCount": 0,
        "vmCount": 0,
        "sdnasCount": 0,
        "brownfieldTemplateType": "NONE",
        "networks": [
            {
                "id": "ff80808177f8823b0177f8bb82d80005",
                "name": "flex-data2",
                "description": "",
                "type": "SCALEIO_DATA",
                "vlanId": 105,
                "static": true,
                "staticNetworkConfiguration": {
                    "gateway": null,
                    "subnet": "1.1.1.0",
                    "primaryDns": null,
                    "secondaryDns": null,
                    "dnsSuffix": null,
                    "ipRange": null,
                    "ipAddress": null,
                    "staticRoute": null
                },
                "destinationIpAddress": "1.1.1.0"
            }
        ],
        "blockServiceOperationsMap": {}
    }]
FirmwareRepository:
    description: Details of all firmware repository.
    returned: when I(gather_subset) is C(firmware_repository)
    type: list
    contains:
        id:
            description: ID of the firmware repository.
            type: str
        name:
            description: Name of the firmware repository.
            type: str
        sourceLocation:
            description: Source location of the firmware repository.
            type: str
        state:
            description: State of the firmware repository.
            type: str
        softwareComponents:
            description: Software components of the firmware repository.
            type: list
        softwareBundles:
            description: Software bundles of the firmware repository.
            type: list
        deployments:
            description: Deployments of the firmware repository.
            type: list
    sample: [{
        "id": "8aaa03a78de4b2a5018de662818d000b",
        "name": "https://192.168.0.1/artifactory/path/pfxmlogs-bvt-pfmp-swo-upgrade-402-to-451-56.tar.gz",
        "sourceLocation": "https://192.168.0.2/artifactory/path/pfxmlogs-bvt-pfmp-swo-upgrade-402-to-451-56.tar.gz",
        "sourceType": null,
        "diskLocation": "",
        "filename": "",
        "md5Hash": null,
        "username": "",
        "password": "",
        "downloadStatus": "error",
        "createdDate": "2024-02-26T17:07:11.884+00:00",
        "createdBy": "admin",
        "updatedDate": "2024-03-01T06:21:10.917+00:00",
        "updatedBy": "system",
        "defaultCatalog": false,
        "embedded": false,
        "state": "errors",
        "softwareComponents": [],
        "softwareBundles": [],
        "deployments": [],
        "bundleCount": 0,
        "componentCount": 0,
        "userBundleCount": 0,
        "minimal": true,
        "downloadProgress": 100,
        "extractProgress": 0,
        "fileSizeInGigabytes": 0.0,
        "signedKeySourceLocation": null,
        "signature": "Unknown",
        "custom": false,
        "needsAttention": false,
        "jobId": "Job-10d75a23-d801-4fdb-a2d0-7f6389ab75cf",
        "rcmapproved": false
    }]
NVMe_Hosts:
    description: Details of all NVMe hosts.
    returned: always
    type: list
    contains:
        hostOsFullType:
            description: Full type of the host OS.
            type: str
        hostType:
            description: Type of the host.
            type: str
        id:
            description: ID of the NVMe host.
            type: str
        installedSoftwareVersionInfo:
            description: Installed software version information.
            type: str
        kernelBuildNumber:
            description: Kernel build number.
            type: str
        kernelVersion:
            description: Kernel version.
            type: str
        links:
            description: Links related to the NVMe host.
            type: list
            contains:
                href:
                    description: Hyperlink reference.
                    type: str
                rel:
                    description: Relation type.
                    type: str
        max_num_paths:
            description: Maximum number of paths per volume. Used to create or modify the NVMe host.
            type: int
        max_num_sys_ports:
            description: Maximum number of ports per protection domain. Used to create or modify the NVMe host.
            type: int
        mdmConnectionState:
            description: MDM connection state.
            type: str
        mdmIpAddressesCurrent:
            description: Current MDM IP addresses.
            type: list
        name:
            description: Name of the NVMe host.
            type: str
        nqn:
            description: NQN of the NVMe host. Used to create, get or modify the NVMe host.
            type: str
        osType:
            description: OS type.
            type: str
        peerMdmId:
            description: Peer MDM ID.
            type: str
        perfProfile:
            description: Performance profile.
            type: str
        sdcAgentActive:
            description: Whether the SDC agent is active.
            type: bool
        sdcApproved:
            description: Whether an SDC has approved access to the system.
            type: bool
        sdcApprovedIps:
            description: SDC approved IPs.
            type: list
        sdcGuid:
            description: SDC GUID.
            type: str
        sdcIp:
            description: SDC IP address.
            type: str
        sdcIps:
            description: SDC IP addresses.
            type: list
        sdcType:
            description: SDC type.
            type: str
        sdrId:
            description: SDR ID.
            type: str
        sdtId:
            description: SDT ID.
            type: str
        softwareVersionInfo:
            description: Software version information.
            type: str
        systemId:
            description: ID of the system.
            type: str
        versionInfo:
            description: Version information.
            type: str
    sample: [{
        "hostOsFullType": "Generic",
        "systemId": "f4c3b7f5c48cb00f",
        "sdcApproved": null,
        "sdcAgentActive": null,
        "mdmIpAddressesCurrent": null,
        "sdcIp": null,
        "sdcIps": null,
        "osType": null,
        "perfProfile": null,
        "peerMdmId": null,
        "sdtId": null,
        "mdmConnectionState": null,
        "softwareVersionInfo": null,
        "socketAllocationFailure": null,
        "memoryAllocationFailure": null,
        "versionInfo": null,
        "sdcType": null,
        "nqn": "nqn.org.nvmexpress:uuid",
        "maxNumPaths": 3,
        "maxNumSysPorts": 3,
        "sdcGuid": null,
        "installedSoftwareVersionInfo": null,
        "kernelVersion": null,
        "kernelBuildNumber": null,
        "sdcApprovedIps": null,
        "hostType": "NVMeHost",
        "sdrId": null,
        "name": "example_nvme_host",
        "id": "da8f60fd00010000",
        "links": [
            {
                "rel": "self",
                "href": "/api/instances/Host::da8f60fd00010000"
            },
            {
                "rel": "/api/Host/relationship/Volume",
                "href": "/api/instances/Host::da8f60fd00010000/relationships/Volume"
            },
            {
                "rel": "/api/Host/relationship/NvmeController",
                "href": "/api/instances/Host::da8f60fd00010000/relationships/NvmeController"
            },
            {
                "rel": "/api/parent/relationship/systemId",
                "href": "/api/instances/System::f4c3b7f5c48cb00f"
            }
        ]
    }]
sdt:
    description: Details of NVMe storage data targets.
    returned: when I(gather_subset) is C(sdt)
    type: list
    contains:
        authenticationError:
            description: The authentication error details of the SDT object.
            type: str
        certificateInfo:
            description: The certificate information of the SDT object.
            type: str
        discoveryPort:
            description: The discovery port number of the SDT object.
            type: int
        id:
            description: The unique identifier of the SDT object.
            type: str
        ipList:
            description: The list of IP addresses of the SDT object.
            type: list
            contains:
                ip:
                    description: The IP address of the SDT object.
                    type: str
                role:
                    description: The role associated with the IP address of the SDT object.
                    type: str
        maintenanceState:
            description: The maintenance state of the SDT object.
            type: str
        mdmConnectionState:
            description: The MDM connection state of the SDT object.
            type: str
        membershipState:
            description: The membership state of the SDT object.
            type: str
        name:
            description: The name of the SDT object.
            type: str
        nvmePort:
            description: The NVMe port number of the SDT object.
            type: int
        nvme_hosts:
            description: The list of NVMe hosts associated with the SDT object.
            type: list
            contains:
                controllerId:
                    description: The controller ID.
                    type: int
                hostId:
                    description: The host ID associated with the NVMe controller.
                    type: str
                hostIp:
                    description: The IP address of the host.
                    type: str
                id:
                    description: The unique identifier of the NVMe controller.
                    type: str
                isAssigned:
                    description: Indicates if the NVMe controller is assigned.
                    type: bool
                isConnected:
                    description: Indicates if the NVMe controller is connected.
                    type: bool
                links:
                    description: Hyperlinks related to the NVMe controller.
                    type: list
                    contains:
                        href:
                            description: The URL of the link.
                            type: str
                        rel:
                            description: The relation type of the link.
                            type: str
                name:
                    description: The name of the NVMe controller. Can be null.
                    type: str
                sdtId:
                    description: The SDT ID associated with the NVMe controller.
                    type: str
                subsystem:
                    description: The subsystem associated with the NVMe controller.
                    type: str
                sysPortId:
                    description: The system port ID.
                    type: int
                sysPortIp:
                    description: The IP address of the system port.
                    type: str
        protectionDomainId:
            description: The Protection Domain ID associated with the SDT object.
            type: str
        sdtState:
            description: The state of the SDT object.
            type: str
        softwareVersionInfo:
            description: The software version information of the SDT object.
            type: str
        storagePort:
            description: The storage port number of the SDT object.
            type: int
    sample: [{
        "authenticationError": "None",
        "certificateInfo": null,
        "discoveryPort": 8009,
        "faultSetId": null,
        "id": "8bddf18b00000000",
        "ipList": [
            {
                "ip": "10.1.1.1",
                "role": "HostOnly"
            },
            {
                "ip": "10.1.1.2",
                "role": "StorageOnly"
            }
        ],
        "links": [
            {
                "href": "/api/instances/Sdt::8bddf18b00000000",
                "rel": "self"
            },
            {
                "href": "/api/instances/Sdt::8bddf18b00000000/relationships/Statistics",
                "rel": "/api/Sdt/relationship/Statistics"
            },
            {
                "href": "/api/instances/ProtectionDomain::32a39aa600000000",
                "rel": "/api/parent/relationship/protectionDomainId"
            }
        ],
        "maintenanceState": "NoMaintenance",
        "mdmConnectionState": "Connected",
        "membershipState": "Joined",
        "name": "Sdt-yulan3-pf460-svm-1",
        "nvmePort": 4420,
        "nvme_hosts": [
            {
                "controllerId": 1,
                "hostId": "1040d69e00010001",
                "hostIp": "10.0.1.1",
                "id": "cc00010001000002",
                "isAssigned": false,
                "isConnected": true,
                "links": [
                    {
                        "href": "/api/instances/NvmeController::cc00010001000002",
                        "rel": "self"
                    }
                ],
                "name": null,
                "sdtId": "8bddf18b00000000",
                "subsystem": "Io",
                "sysPortId": 0,
                "sysPortIp": "10.1.1.1"
            }
        ],
        "persistentDiscoveryControllersNum": 0,
        "protectionDomainId": "32a39aa600000000",
        "sdtState": "Normal",
        "softwareVersionInfo": "R4_5.2100.0",
        "storagePort": 12200,
        "systemId": "264ec85b3855280f"
    }]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell \
    import utils
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell.libraries.configuration \
    import Configuration
import re

LOG = utils.get_logger('info')

UNSUPPORTED_SUBSET_FOR_VERSION = 'One or more specified subset is not supported for the PowerFlex version.'
POWERFLEX_MANAGER_GATHER_SUBSET = {'managed_device', 'deployment', 'service_template'}
MIN_SUPPORTED_POWERFLEX_MANAGER_VERSION = 4.0
ERROR_CODES = r'PARSE002|FILTER002|FILTER003'


class PowerFlexInfo(object):
    """Class with Info operations"""

    filter_mapping = {'equal': 'eq', 'contains': 'co'}

    def __init__(self):
        """ Define all parameters required by this module"""

        self.module_params = utils.get_powerflex_gateway_host_parameters()
        self.module_params.update(get_powerflex_info_parameters())

        self.filter_keys = sorted(
            [k for k in self.module_params['filters']['options'].keys()
             if 'filter' in k])

        """ initialize the ansible module """
        self.module = AnsibleModule(argument_spec=self.module_params,
                                    supports_check_mode=True)

        utils.ensure_required_libs(self.module)

        try:
            self.powerflex_conn = utils.get_powerflex_gateway_host_connection(
                self.module.params)
            LOG.info('Got the PowerFlex system connection object instance')
            LOG.info('The check_mode flag %s', self.module.check_mode)

        except Exception as e:
            LOG.error(str(e))
            self.module.fail_json(msg=str(e))

    def get_api_details(self):
        """ Get api details of the array """
        try:
            LOG.info('Getting API details ')
            api_version = self.powerflex_conn.system.api_version()
            return api_version

        except Exception as e:
            msg = 'Get API details from Powerflex array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_array_details(self):
        """ Get system details of a powerflex array """

        try:
            LOG.info('Getting array details ')
            entity_list = ['addressSpaceUsage', 'authenticationMethod',
                           'capacityAlertCriticalThresholdPercent',
                           'capacityAlertHighThresholdPercent',
                           'capacityTimeLeftInDays', 'cliPasswordAllowed',
                           'daysInstalled', 'defragmentationEnabled',
                           'enterpriseFeaturesEnabled', 'id', 'installId',
                           'isInitialLicense', 'lastUpgradeTime',
                           'managementClientSecureCommunicationEnabled',
                           'maxCapacityInGb', 'mdmCluster',
                           'mdmExternalPort', 'mdmManagementPort',
                           'mdmSecurityPolicy', 'showGuid', 'swid',
                           'systemVersionName', 'tlsVersion', 'upgradeState']

            sys_list = self.powerflex_conn.system.get()
            sys_details_list = []
            for sys in sys_list:
                sys_details = {}
                for entity in entity_list:
                    if entity in sys.keys():
                        sys_details.update({entity: sys[entity]})
                if sys_details:
                    sys_details_list.append(sys_details)

            return sys_details_list

        except Exception as e:
            msg = 'Get array details from Powerflex array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_sdc_list(self, filter_dict=None):
        """ Get the list of sdcs on a given PowerFlex storage system """

        try:
            LOG.info('Getting SDC list ')
            if filter_dict:
                sdc = self.powerflex_conn.sdc.get(filter_fields=filter_dict)
            else:
                sdc = self.powerflex_conn.sdc.get()
            # filter out NVMe host entities
            sdc = [obj for obj in sdc if obj.get('hostType') != 'NVMeHost']
            return result_list(sdc)

        except Exception as e:
            msg = 'Get SDC list from powerflex array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_nvme_host_list(self, filter_dict=None):
        """ Get the list of NVMe hosts on a given PowerFlex storage system """

        try:
            LOG.info('Getting NVMe hosts list ')
            sdc = self.powerflex_conn.sdc.get()
            # filter out NVMe host entities
            hosts = [obj for obj in sdc if obj.get('hostType') == 'NVMeHost']
            # Add name to NVMe hosts without giving name
            for host in hosts:
                if host.get("name") is None:
                    host["name"] = f"NVMeHost:{host['id']}"
            if filter_dict:
                hosts = utils.filter_response(hosts, filter_dict)
            return result_list(hosts)

        except Exception as e:
            msg = 'Get NVMe host list from powerflex array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_sds_list(self, filter_dict=None):
        """ Get the list of sdses on a given PowerFlex storage system """

        try:
            LOG.info('Getting SDS list ')
            if filter_dict:
                sds = self.powerflex_conn.sds.get(filter_fields=filter_dict)
            else:
                sds = self.powerflex_conn.sds.get()
            return result_list(sds)

        except Exception as e:
            msg = 'Get SDS list from powerflex array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_pd_list(self, filter_dict=None):
        """ Get the list of Protection Domains on a given PowerFlex
            storage system """

        try:
            LOG.info('Getting protection domain list ')

            if filter_dict:
                pd = self.powerflex_conn.protection_domain.get(filter_fields=filter_dict)
            else:
                pd = self.powerflex_conn.protection_domain.get()
            return result_list(pd)

        except Exception as e:
            msg = 'Get protection domain list from powerflex array failed ' \
                  'with error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_storage_pool_list(self, filter_dict=None):
        """ Get the list of storage pools on a given PowerFlex storage
            system """

        try:
            LOG.info('Getting storage pool list ')
            if filter_dict:
                pool = self.powerflex_conn.storage_pool.get(filter_fields=filter_dict)
            else:
                pool = self.powerflex_conn.storage_pool.get()

            if pool:
                statistics_map = self.powerflex_conn.utility.get_statistics_for_all_storagepools()
                list_of_pool_ids_in_statistics = statistics_map.keys()
                for item in pool:
                    item['statistics'] = statistics_map[item['id']] if item['id'] in list_of_pool_ids_in_statistics else {}
            return result_list(pool)

        except Exception as e:
            msg = 'Get storage pool list from powerflex array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_replication_consistency_group_list(self, filter_dict=None):
        """ Get the list of replication consistency group on a given PowerFlex storage
            system """

        try:
            LOG.info('Getting replication consistency group list ')
            if filter_dict:
                rcgs = self.powerflex_conn.replication_consistency_group.get(filter_fields=filter_dict)
            else:
                rcgs = self.powerflex_conn.replication_consistency_group.get()
            if rcgs:
                api_version = self.powerflex_conn.system.get()[0]['mdmCluster']['master']['versionInfo']
                statistics_map = \
                    self.powerflex_conn.replication_consistency_group.get_all_statistics(utils.is_version_less_than_3_6(api_version))
                list_of_rcg_ids_in_statistics = statistics_map.keys()
                for rcg in rcgs:
                    rcg.pop('links', None)
                    rcg['statistics'] = statistics_map[rcg['id']] if rcg['id'] in list_of_rcg_ids_in_statistics else {}
                return result_list(rcgs)

        except Exception as e:
            msg = 'Get replication consistency group list from powerflex array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_replication_pair_list(self, filter_dict=None):
        """ Get the list of replication pairs on a given PowerFlex storage
            system """

        try:
            LOG.info('Getting replication pair list ')
            if filter_dict:
                pairs = self.powerflex_conn.replication_pair.get(filter_fields=filter_dict)
            else:
                pairs = self.powerflex_conn.replication_pair.get()
            if pairs:
                for pair in pairs:
                    pair.pop('links', None)
                    local_volume = self.powerflex_conn.volume.get(filter_fields={'id': pair['localVolumeId']})
                    if local_volume:
                        pair['localVolumeName'] = local_volume[0]['name']
                    pair['replicationConsistencyGroupName'] = \
                        self.powerflex_conn.replication_consistency_group.get(filter_fields={'id': pair['replicationConsistencyGroupId']})[0]['name']
                    pair['statistics'] = self.powerflex_conn.replication_pair.get_statistics(pair['id'])
                return pairs

        except Exception as e:
            msg = 'Get replication pair list from powerflex array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_volumes_list(self, filter_dict=None):
        """ Get the list of volumes on a given PowerFlex storage
            system """

        try:
            LOG.info('Getting volumes list ')
            if filter_dict:
                volumes = self.powerflex_conn.volume.get(filter_fields=filter_dict)
            else:
                volumes = self.powerflex_conn.volume.get()

            if volumes:
                statistics_map = self.powerflex_conn.utility.get_statistics_for_all_volumes()
                list_of_vol_ids_in_statistics = statistics_map.keys()
                for item in volumes:
                    item['statistics'] = statistics_map[item['id']] if item['id'] in list_of_vol_ids_in_statistics else {}
            return result_list(volumes)

        except Exception as e:
            msg = 'Get volumes list from powerflex array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_snapshot_policy_list(self, filter_dict=None):
        """ Get the list of snapshot schedules on a given PowerFlex storage
            system """

        try:
            LOG.info('Getting snapshot policies list ')
            if filter_dict:
                snapshot_policies = \
                    self.powerflex_conn.snapshot_policy.get(
                        filter_fields=filter_dict)
            else:
                snapshot_policies = \
                    self.powerflex_conn.snapshot_policy.get()

            if snapshot_policies:
                statistics_map = self.powerflex_conn.utility.get_statistics_for_all_snapshot_policies()
                list_of_snap_pol_ids_in_statistics = statistics_map.keys()
                for item in snapshot_policies:
                    item['statistics'] = statistics_map[item['id']] if item['id'] in list_of_snap_pol_ids_in_statistics else {}
            return result_list(snapshot_policies)

        except Exception as e:
            msg = 'Get snapshot policies list from powerflex array failed ' \
                  'with error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_devices_list(self, filter_dict=None):
        """ Get the list of devices on a given PowerFlex storage
            system """

        try:
            LOG.info('Getting device list ')
            if filter_dict:
                devices = self.powerflex_conn.device.get(filter_fields=filter_dict)
            else:
                devices = self.powerflex_conn.device.get()

            return result_list(devices)

        except Exception as e:
            msg = 'Get device list from powerflex array failed ' \
                  'with error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_fault_sets_list(self, filter_dict=None):
        """ Get the list of fault sets on a given PowerFlex storage
            system """

        try:
            LOG.info('Getting fault set list ')
            filter_pd = []
            if filter_dict:
                if 'protectionDomainName' in filter_dict.keys():
                    filter_pd = filter_dict['protectionDomainName']
                    del filter_dict['protectionDomainName']
                fault_sets = self.powerflex_conn.fault_set.get(filter_fields=filter_dict)
            else:
                fault_sets = self.powerflex_conn.fault_set.get()

            fault_set_final = []
            if fault_sets:
                for fault_set in fault_sets:
                    fault_set['protectionDomainName'] = Configuration(self.powerflex_conn, self.module).get_protection_domain(
                        protection_domain_id=fault_set["protectionDomainId"])["name"]
                    fault_set["SDS"] = Configuration(self.powerflex_conn, self.module).get_associated_sds(
                        fault_set_id=fault_set['id'])
                    fault_set_final.append(fault_set)
            fault_sets = []
            for fault_set in fault_set_final:
                if fault_set['protectionDomainName'] in filter_pd:
                    fault_sets.append(fault_set)
            if len(filter_pd) != 0:
                return result_list(fault_sets)
            return result_list(fault_set_final)

        except Exception as e:
            msg = 'Get fault set list from powerflex array failed ' \
                  'with error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_managed_devices_list(self):
        """ Get the list of managed devices on a given PowerFlex Manager system """
        try:
            LOG.info('Getting managed devices list ')
            devices = self.powerflex_conn.managed_device.get(filters=self.populate_filter_list(),
                                                             limit=self.get_param_value('limit'),
                                                             offset=self.get_param_value('offset'),
                                                             sort=self.get_param_value('sort'))
            return devices
        except Exception as e:
            msg = f'Get managed devices from PowerFlex Manager failed with error {str(e)}'
            return self.handle_error_exit(msg)

    def get_deployments_list(self):
        """ Get the list of deployments on a given PowerFlex Manager system """
        try:
            LOG.info('Getting deployments list ')
            deployments = self.powerflex_conn.deployment.get(filters=self.populate_filter_list(),
                                                             sort=self.get_param_value('sort'),
                                                             limit=self.get_param_value('limit'),
                                                             offset=self.get_param_value('offset'),
                                                             include_devices=self.get_param_value('include_devices'),
                                                             include_template=self.get_param_value('include_template'),
                                                             full=self.get_param_value('full'))
            return deployments
        except Exception as e:
            msg = f'Get deployments from PowerFlex Manager failed with error {str(e)}'
            return self.handle_error_exit(msg)

    def get_sdt_list(self, filter_dict=None):
        """ Get the list of sdt on a given PowerFlex Manager system """
        try:
            LOG.info('Getting sdt list ')
            # Get the list of nvme hosts
            associated_hosts = []
            nvme_hosts = self.powerflex_conn.sdc.get(filter_fields={'hostType': "NVMeHost"})
            for nvme_host in nvme_hosts:
                controller = self.powerflex_conn.host.get_related(entity_id=nvme_host.get('id'), related='NvmeController')
                associated_hosts.extend(controller)
            associated_hosts_map = {controller.get('sdtId'): controller for controller in associated_hosts if controller.get('sdtId') is not None}
            if filter_dict:
                sdts = self.powerflex_conn.sdt.get(filter_fields=filter_dict)
            else:
                sdts = self.powerflex_conn.sdt.get()

            for sdt in sdts:
                sdt['nvme_hosts'] = []
                for host in associated_hosts_map.values():
                    if host.get('sdtId') == sdt.get('id'):
                        sdt['nvme_hosts'].append(host)

            return result_list(sdts)

        except Exception as e:
            msg = f'Get sdt from PowerFlex Manager failed with error {str(e)}'
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_pagination_params(self):
        """ Get the pagination parameters """
        return {'limit': self.get_param_value('limit'), 'offset': self.get_param_value('offset'),
                'sort': self.get_param_value('sort'), 'filters': self.populate_filter_list()}

    def get_firmware_repository_list(self):
        """ Get the list of firmware repository on a given PowerFlex Manager system """
        try:
            LOG.info('Getting firmware repository list ')
            firmware_repository = self.powerflex_conn.firmware_repository.get(
                **self.get_pagination_params(),
                related=self.get_param_value('include_related'),
                bundles=self.get_param_value('include_bundles'),
                components=self.get_param_value('include_components'))
            return firmware_repository
        except Exception as e:
            msg = f'Get firmware repository from PowerFlex Manager failed with error {str(e)}'
            return self.handle_error_exit(msg)

    def get_service_templates_list(self):
        """ Get the list of service templates on a given PowerFlex Manager system """
        try:
            LOG.info('Getting service templates list ')
            service_templates = self.powerflex_conn.service_template.get(filters=self.populate_filter_list(),
                                                                         sort=self.get_param_value('sort'),
                                                                         offset=self.get_param_value('offset'),
                                                                         limit=self.get_param_value('limit'),
                                                                         full=self.get_param_value('full'),
                                                                         include_attachments=self.get_param_value('include_attachments'))
            return service_templates
        except Exception as e:
            msg = f'Get service templates from PowerFlex Manager failed with error {str(e)}'
            return self.handle_error_exit(msg)

    def handle_error_exit(self, detailed_message):
        match = re.search(r"displayMessage=([^']+)", detailed_message)
        error_message = match.group(1) if match else detailed_message
        LOG.error(error_message)
        if re.search(ERROR_CODES, detailed_message):
            return []
        self.module.fail_json(msg=error_message)

    def get_param_value(self, param):
        """
        Get the value of the given parameter.
        Args:
            param (str): The parameter to get the value for.
        Returns:
            The value of the parameter if it is different from the default value,
            The value of the parameter if int and greater than 0
            otherwise None.
        """
        if param in ('sort', 'offset', 'limit') and len(self.module.params.get('gather_subset')) > 1:
            return None

        default_value = self.module_params.get(param).get('default')
        param_value = self.module.params.get(param)
        if (default_value != param_value) and (param_value >= 0 if isinstance(param_value, int) else True):
            return param_value
        return None

    def validate_filter(self, filter_dict):
        """ Validate given filter_dict """

        is_invalid_filter = self.filter_keys != sorted(list(filter_dict))
        if is_invalid_filter:
            msg = "Filter should have all keys: '{0}'".format(
                ", ".join(self.filter_keys))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

        is_invalid_filter = [filter_dict[i] is None for i in filter_dict]
        if True in is_invalid_filter:
            msg = "Filter keys: '{0}' cannot be None".format(self.filter_keys)
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def populate_filter_list(self):
        """Populate the filter list"""
        if len(self.module.params.get('gather_subset')) > 1:
            return []
        filters = self.module.params.get('filters') or []
        return [
            f'{self.filter_mapping.get(filter_dict["filter_operator"])},{filter_dict["filter_key"]},{filter_dict["filter_value"]}'
            for filter_dict in filters
        ]

    def get_filters(self, filters):
        """Get the filters to be applied"""

        filter_dict = {}
        for item in filters:
            self.validate_filter(item)
            f_op = item['filter_operator']
            if self.filter_mapping.get(f_op) == self.filter_mapping.get("equal"):
                f_key = item['filter_key']
                f_val = item['filter_value']
                if f_key in filter_dict:
                    # multiple filters on same key
                    if isinstance(filter_dict[f_key], list):
                        # prev_val is list, so append new f_val
                        filter_dict[f_key].append(f_val)
                    else:
                        # prev_val is not list,
                        # so create list with prev_val & f_val
                        filter_dict[f_key] = [filter_dict[f_key], f_val]
                else:
                    filter_dict[f_key] = f_val
        return filter_dict

    def validate_subset(self, api_version, subset):
        if float(api_version) < MIN_SUPPORTED_POWERFLEX_MANAGER_VERSION and subset and set(subset).issubset(POWERFLEX_MANAGER_GATHER_SUBSET):
            self.module.exit_json(msg=UNSUPPORTED_SUBSET_FOR_VERSION, skipped=True)

    def perform_module_operation(self):
        """ Perform different actions on info based on user input
            in the playbook """

        filters = self.module.params['filters']
        filter_dict = {}
        if filters:
            filter_dict = self.get_filters(filters)
            LOG.info('filters: %s', filter_dict)

        api_version = self.get_api_details()
        array_details = self.get_array_details()
        subset = self.module.params['gather_subset']
        subset_result_filter = {}
        subset_result_wo_param = {}
        self.validate_subset(api_version, subset)

        subset_dict_with_filter = {
            "sdc": self.get_sdc_list,
            "sds": self.get_sds_list,
            "protection_domain": self.get_pd_list,
            "storage_pool": self.get_storage_pool_list,
            "vol": self.get_volumes_list,
            "snapshot_policy": self.get_snapshot_policy_list,
            "device": self.get_devices_list,
            "rcg": self.get_replication_consistency_group_list,
            "replication_pair": self.get_replication_pair_list,
            "fault_set": self.get_fault_sets_list,
            "nvme_host": self.get_nvme_host_list,
            "sdt": self.get_sdt_list,
        }

        subset_wo_param = {
            "managed_device": self.get_managed_devices_list,
            "service_template": self.get_service_templates_list,
            "deployment": self.get_deployments_list,
            "firmware_repository": self.get_firmware_repository_list
        }
        if subset:
            subset_result_filter = {key: subset_dict_with_filter[key](
                filter_dict=filter_dict) for key in subset if key in subset_dict_with_filter}
            subset_result_wo_param = {key: subset_wo_param[key](
            ) for key in subset if key in subset_wo_param}

        self.module.exit_json(
            Array_Details=array_details,
            API_Version=api_version,
            SDCs=subset_result_filter.get("sdc", []),
            SDSs=subset_result_filter.get("sds", []),
            Storage_Pools=subset_result_filter.get("storage_pool", []),
            Volumes=subset_result_filter.get("vol", []),
            Snapshot_Policies=subset_result_filter.get("snapshot_policy", []),
            Protection_Domains=subset_result_filter.get(
                "protection_domain", []),
            Devices=subset_result_filter.get("device", []),
            Replication_Consistency_Groups=subset_result_filter.get("rcg", []),
            Replication_Pairs=subset_result_filter.get("replication_pair", []),
            Fault_Sets=subset_result_filter.get("fault_set", []),
            SDTs=subset_result_filter.get("sdt", []),
            ManagedDevices=subset_result_wo_param.get("managed_device", []),
            ServiceTemplates=subset_result_wo_param.get(
                "service_template", []),
            Deployments=subset_result_wo_param.get("deployment", []),
            FirmwareRepository=subset_result_wo_param.get(
                "firmware_repository", []),
            NVMeHosts=subset_result_filter.get("nvme_host", [])
        )


def result_list(entity):
    """ Get the name and id associated with the PowerFlex entities """
    result = []
    if entity:
        LOG.info('Successfully listed.')
        for item in entity:
            if item['name']:
                result.append(item)
            else:
                result.append({"id": item['id']})
        return result
    else:
        return None


def get_powerflex_info_parameters():
    """This method provides parameters required for the ansible
    info module on powerflex"""
    return dict(
        gather_subset=dict(type='list', required=False, elements='str',
                           choices=['vol', 'storage_pool',
                                    'protection_domain', 'sdc', 'sds', 'snapshot_policy',
                                    'device', 'rcg', 'replication_pair', 'fault_set',
                                    'service_template', 'managed_device', 'deployment', 'firmware_repository', 'nvme_host', 'sdt']),
        filters=dict(type='list', required=False, elements='dict',
                     options=dict(filter_key=dict(type='str', required=True, no_log=False),
                                  filter_operator=dict(
                                      type='str', required=True,
                                      choices=['equal', 'contains']),
                                  filter_value=dict(type='str', required=True)
                                  )),
        sort=dict(type='str'),
        limit=dict(type='int', default=50),
        offset=dict(type='int', default=0),
        include_devices=dict(type='bool', default=True),
        include_template=dict(type='bool', default=True),
        full=dict(type='bool', default=False),
        include_attachments=dict(type='bool', default=True),
        include_related=dict(type='bool', default=False),
        include_bundles=dict(type='bool', default=False),
        include_components=dict(type='bool', default=False),
    )


def main():
    """ Create PowerFlex info object and perform action on it
        based on user input from playbook"""
    obj = PowerFlexInfo()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
