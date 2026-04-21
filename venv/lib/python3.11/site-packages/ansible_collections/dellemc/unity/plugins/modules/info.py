#!/usr/bin/python
# Copyright: (c) 2020-2025, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module for Gathering information about Unity"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: info

version_added: '1.1.0'

short_description: Gathering information about Unity

description:
- Gathering information about Unity storage system includes
  Get the details of Unity array,
  Get list of Hosts in Unity array,
  Get list of FC initiators in Unity array,
  Get list of iSCSI initiators in Unity array,
  Get list of Consistency groups in Unity array,
  Get list of Storage pools in Unity array,
  Get list of Volumes in Unity array,
  Get list of Snapshot schedules in Unity array,
  Get list of NAS servers in Unity array,
  Get list of File systems in Unity array,
  Get list of Snapshots in Unity array,
  Get list of SMB shares in Unity array,
  Get list of NFS exports in Unity array,
  Get list of User quotas in Unity array,
  Get list of Quota tree in Unity array,
  Get list of NFS Servers in Unity array,
  Get list of CIFS Servers in Unity array.
  Get list of Ethernet ports in Unity array.
  Get list of File interfaces used in Unity array.
  Get list of Replication sessions in Unity array.

extends_documentation_fragment:
  - dellemc.unity.unity

author:
- Rajshree Khare (@kharer5) <ansible.team@dell.com>
- Akash Shendge (@shenda1) <ansible.team@dell.com>
- Meenakshi Dembi (@dembim) <ansible.team@dell.com>

options:
  gather_subset:
    description:
    - List of string variables to specify the Unity storage system entities
      for which information is required.
    choices: [host, fc_initiator, iscsi_initiator, cg, storage_pool, vol,
    snapshot_schedule, nas_server, file_system, snapshot, nfs_export,
    smb_share, user_quota, tree_quota, disk_group, nfs_server, cifs_server, ethernet_port, file_interface, replication_session]
    type: list
    elements: str

notes:
  - The I(check_mode) is supported.
'''

EXAMPLES = r'''
- name: Get detailed list of Unity entities
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - host
      - fc_initiator
      - iscsi_initiator
      - cg
      - storage_pool
      - vol
      - snapshot_schedule
      - nas_server
      - file_system
      - snapshot
      - nfs_export
      - smb_share
      - user_quota
      - tree_quota
      - disk_group
      - nfs_server
      - cifs_server
      - ethernet_port
      - file_interface
      - replication_session

- name: Get information of Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"

- name: Get list of hosts on Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - host

- name: Get list of FC initiators on Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - fc_initiator

- name: Get list of ISCSI initiators on Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - iscsi_initiator

- name: Get list of consistency groups on Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - cg

- name: Get list of storage pools on Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - storage_pool

- name: Get list of volumes on Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - vol

- name: Get list of snapshot schedules on Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - snapshot_schedule

- name: Get list of NAS Servers on Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - nas_server

- name: Get list of File Systems on Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - file_system

- name: Get list of Snapshots on Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - snapshot

- name: Get list of NFS exports on Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - nfs_export

- name: Get list of SMB shares on Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - smb_share

- name: Get list of user quotas on Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - user_quota

- name: Get list of quota trees on Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - tree_quota

- name: Get list of disk groups on Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - disk_group

- name: Get list of NFS Servers on Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - nfs_server

- name: Get list of CIFS Servers on Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - cifs_server

- name: Get list of ethernet ports on Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - ethernet_port

- name: Get list of file interfaces on Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - file_interface

- name: Get list of replication sessions on Unity array
  info:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - replication_session
'''

RETURN = r'''
Array_Details:
    description: Details of the Unity Array.
    returned: always
    type: dict
    contains:
        api_version:
            description: The current api version of the Unity Array.
            type: str
        earliest_api_version:
            description: The earliest api version of the Unity Array.
            type: str
        model:
            description: The model of the Unity Array.
            type: str
        name:
            description: The name of the Unity Array.
            type: str
        software_version:
            description: The software version of the Unity Array.
            type: str
    sample: {
        "api_version": "12.0",
        "earliest_api_version": "4.0",
        "existed": true,
        "hash": 8766644083532,
        "id": "0",
        "model": "Unity 480",
        "name": "APM00213404195",
        "software_version": "5.2.1"
    }

Hosts:
    description: Details of the hosts.
    returned: When hosts exist.
    type: list
    contains:
        id:
            description: The ID of the host.
            type: str
        name:
            description: The name of the host.
            type: str
    sample: [
        {
            "auto_manage_type": "HostManageEnum.UNKNOWN",
            "datastores": null,
            "description": "",
            "existed": true,
            "fc_host_initiators": null,
            "hash": 8762200072289,
            "health": {
                "UnityHealth": {
                    "hash": 8762200072352
                }
            },
            "host_container": null,
            "host_ip_ports": {
                "UnityHostIpPortList": [
                    {
                        "UnityHostIpPort": {
                            "hash": 8762200072361
                        }
                    }
                ]
            },
            "host_luns": null,
            "host_polled_uuid": null,
            "host_pushed_uuid": null,
            "host_uuid": null,
            "host_v_vol_datastore": null,
            "id": "Host_2191",
            "iscsi_host_initiators": null,
            "last_poll_time": null,
            "name": "10.225.2.153",
            "os_type": "Linux",
            "registration_type": null,
            "storage_resources": null,
            "tenant": null,
            "type": "HostTypeEnum.HOST_MANUAL",
            "vms": null
        }
    ]

FC_initiators:
    description: Details of the FC initiators.
    returned: When FC initiator exist.
    type: list
    contains:
        WWN:
            description: The WWN of the FC initiator.
            type: str
        id:
            description: The id of the FC initiator.
            type: str
    sample: [
        {
            "WWN": "20:00:00:0E:1E:E9:B8:FC:21:00:00:0E:1E:E9:B8:FC",
            "id": "HostInitiator_3"
        },
        {
            "WWN": "20:00:00:0E:1E:E9:B8:F7:21:00:00:0E:1E:E9:B8:F7",
            "id": "HostInitiator_4"
        }
    ]

ISCSI_initiators:
    description: Details of the ISCSI initiators.
    returned: When ISCSI initiators exist.
    type: list
    contains:
        IQN:
            description: The IQN of the ISCSI initiator.
            type: str
        id:
            description: The id of the ISCSI initiator.
            type: str
    sample: [
        {
            "IQN": "iqn.1994-05.com.redhat:634d768090f",
            "id": "HostInitiator_1"
        },
        {
            "IQN": "iqn.1994-05.com.redhat:2835ba62cc6d",
            "id": "HostInitiator_2"
        }
    ]

Consistency_Groups:
    description: Details of the Consistency Groups.
    returned: When Consistency Groups exist.
    type: list
    contains:
        id:
            description: The ID of the Consistency Group.
            type: str
        name:
            description: The name of the Consistency Group.
            type: str
    sample: [
        {
            "advanced_dedup_status": "DedupStatusEnum.DISABLED",
            "block_host_access": {
                "UnityBlockHostAccessList": [
                    {
                        "UnityBlockHostAccess": {
                            "hash": 8745385821206
                        }
                    },
                    {
                        "UnityBlockHostAccess": {
                            "hash": 8745386530115
                        }
                    },
                    {
                        "UnityBlockHostAccess": {
                            "hash": 8745386530124
                        }
                    }
                ]
            },
            "data_reduction_percent": 0,
            "data_reduction_ratio": 1.0,
            "data_reduction_size_saved": 0,
            "data_reduction_status": "DataReductionStatusEnum.DISABLED",
            "datastores": null,
            "dedup_status": null,
            "description": "CG has created with all parametres.",
            "esx_filesystem_block_size": null,
            "esx_filesystem_major_version": null,
            "existed": true,
            "filesystem": null,
            "hash": 8745385801328,
            "health": {
                "UnityHealth": {
                    "hash": 8745386647098
                }
            },
            "host_v_vol_datastore": null,
            "id": "res_93",
            "is_replication_destination": false,
            "is_snap_schedule_paused": false,
            "luns": {
                "UnityLunList": [
                    {
                        "UnityLun": {
                            "hash": 8745389830024,
                            "id": "sv_64"
                        }
                    },
                    {
                        "UnityLun": {
                            "hash": 8745386526751,
                            "id": "sv_63"
                        }
                    }
                ]
            },
            "metadata_size": 8858370048,
            "metadata_size_allocated": 7516192768,
            "name": "CG1_Ansible_Test_SS",
            "per_tier_size_used": [
                11811160064,
                0,
                0
            ],
            "pools": {
                "UnityPoolList": [
                    {
                        "UnityPool": {
                            "hash": 8745386552375,
                            "id": "pool_3"
                        }
                    }
                ]
            },
            "relocation_policy": "TieringPolicyEnum.AUTOTIER",
            "replication_type": "ReplicationTypeEnum.NONE",
            "size_allocated": 99418112,
            "size_total": 268435456000,
            "size_used": null,
            "snap_count": 1,
            "snap_schedule": {
                "UnitySnapSchedule": {
                    "hash": 8745386550224,
                    "id": "snapSch_66"
                }
            },
            "snaps_size_allocated": 8888320,
            "snaps_size_total": 108675072,
            "thin_status": "ThinStatusEnum.TRUE",
            "type": "StorageResourceTypeEnum.CONSISTENCY_GROUP",
            "virtual_volumes": null,
            "vmware_uuid": null
        },
    ]

Storage_Pools:
    description: Details of the Storage Pools.
    returned: When Storage Pools exist.
    type: list
    contains:
        id:
            description: The ID of the Storage Pool.
            type: str
        name:
            description: The name of the Storage Pool.
            type: str
    sample: [
        {
            "alert_threshold": 70,
            "creation_time": "2021-10-18 12:45:12+00:00",
            "description": "",
            "existed": true,
            "harvest_state": "UsageHarvestStateEnum.PAUSED_COULD_NOT_REACH_HWM",
            "hash": 8741501012399,
            "health": {
                "UnityHealth": {
                    "hash": 8741501012363
                }
            },
            "id": "pool_2",
            "is_all_flash": false,
            "is_empty": false,
            "is_fast_cache_enabled": false,
            "is_harvest_enabled": true,
            "is_snap_harvest_enabled": false,
            "metadata_size_subscribed": 312458870784,
            "metadata_size_used": 244544700416,
            "name": "fastVP_pool",
            "object_id": 12884901891,
            "pool_fast_vp": {
                "UnityPoolFastVp": {
                    "hash": 8741501228023
                }
            },
            "pool_space_harvest_high_threshold": 95.0,
            "pool_space_harvest_low_threshold": 85.0,
            "pool_type": "StoragePoolTypeEnum.TRADITIONAL",
            "raid_type": "RaidTypeEnum.RAID5",
            "rebalance_progress": null,
            "size_free": 2709855928320,
            "size_subscribed": 2499805044736,
            "size_total": 3291018690560,
            "size_used": 455513956352,
            "snap_size_subscribed": 139720515584,
            "snap_size_used": 66002944,
            "snap_space_harvest_high_threshold": 25.0,
            "snap_space_harvest_low_threshold": 20.0,
            "tiers": {
                "UnityPoolTierList": [
                    {
                        "UnityPoolTier": {
                            "hash": 8741500996410
                        }
                    },
                    {
                        "UnityPoolTier": {
                            "hash": 8741501009430
                        }
                    },
                    {
                        "UnityPoolTier": {
                            "hash": 8741501009508
                        }
                    }
                ]
            }
        },
    ]

Volumes:
    description: Details of the Volumes.
    returned: When Volumes exist.
    type: list
    contains:
        id:
            description: The ID of the Volume.
            type: str
        name:
            description: The name of the Volume.
            type: str
    sample: [
        {
            "current_node": "NodeEnum.SPB",
            "data_reduction_percent": 0,
            "data_reduction_ratio": 1.0,
            "data_reduction_size_saved": 0,
            "default_node": "NodeEnum.SPB",
            "description": null,
            "effective_io_limit_max_iops": null,
            "effective_io_limit_max_kbps": null,
            "existed": true,
            "family_base_lun": {
                "UnityLun": {
                    "hash": 8774260820794,
                    "id": "sv_27"
                }
            },
            "family_clone_count": 0,
            "hash": 8774260854260,
            "health": {
                "UnityHealth": {
                    "hash": 8774260812499
                }
            },
            "host_access": {
                "UnityBlockHostAccessList": [
                    {
                        "UnityBlockHostAccess": {
                            "hash": 8774260826387
                        }
                    }
                ]
            },
            "id": "sv_27",
            "io_limit_policy": null,
            "is_advanced_dedup_enabled": false,
            "is_compression_enabled": null,
            "is_data_reduction_enabled": false,
            "is_replication_destination": false,
            "is_snap_schedule_paused": false,
            "is_thin_clone": false,
            "is_thin_enabled": false,
            "metadata_size": 4294967296,
            "metadata_size_allocated": 4026531840,
            "name": "VSI-UNITY-test-task",
            "per_tier_size_used": [
                111400714240,
                0,
                0
            ],
            "pool": {
                "UnityPool": {
                    "hash": 8774260811427
                }
            },
            "size_allocated": 107374182400,
            "size_total": 107374182400,
            "size_used": null,
            "snap_count": 0,
            "snap_schedule": null,
            "snap_wwn": "60:06:01:60:5C:F0:50:00:94:3E:91:4D:51:5A:4F:97",
            "snaps_size": 0,
            "snaps_size_allocated": 0,
            "storage_resource": {
                "UnityStorageResource": {
                    "hash": 8774267822228
                }
            },
            "tiering_policy": "TieringPolicyEnum.AUTOTIER_HIGH",
            "type": "LUNTypeEnum.VMWARE_ISCSI",
            "wwn": "60:06:01:60:5C:F0:50:00:00:B5:95:61:2E:34:DB:B2"
        },
    ]

Snapshot_Schedules:
    description: Details of the Snapshot Schedules.
    returned: When Snapshot Schedules exist.
    type: list
    contains:
        id:
            description: The ID of the Snapshot Schedule.
            type: str
        name:
            description: The name of the Snapshot Schedule.
            type: str
    sample: [
        {
            "existed": true,
            "hash": 8775599492651,
            "id": "snapSch_1",
            "is_default": true,
            "is_modified": null,
            "is_sync_replicated": false,
            "luns": null,
            "modification_time": "2021-08-18 19:10:33.774000+00:00",
            "name": "CEM_DEFAULT_SCHEDULE_DEFAULT_PROTECTION",
            "rules": {
                "UnitySnapScheduleRuleList": [
                    {
                        "UnitySnapScheduleRule": {
                            "hash": 8775599498593
                        }
                    }
                ]
            },
            "storage_resources": {
                "UnityStorageResourceList": [
                    {
                        "UnityStorageResource": {
                            "hash": 8775599711597,
                            "id": "res_88"
                        }
                    },
                    {
                        "UnityStorageResource": {
                            "hash": 8775599711528,
                            "id": "res_3099"
                        }
                    }
                ]
            },
            "version": "ScheduleVersionEnum.LEGACY"
        },
    ]

NAS_Servers:
    description: Details of the NAS Servers.
    returned: When NAS Servers exist.
    type: list
    contains:
        id:
            description: The ID of the NAS Server.
            type: str
        name:
            description: The name of the NAS Server.
            type: str
    sample: [
        {
            "allow_unmapped_user": null,
            "cifs_server": null,
            "current_sp": {
                "UnityStorageProcessor": {
                    "hash": 8747629920422,
                    "id": "spb"
                }
            },
            "current_unix_directory_service": "NasServerUnixDirectoryServiceEnum.NONE",
            "default_unix_user": null,
            "default_windows_user": null,
            "existed": true,
            "file_dns_server": null,
            "file_interface": {
                "UnityFileInterfaceList": [
                    {
                        "UnityFileInterface": {
                            "hash": 8747626606870,
                            "id": "if_6"
                        }
                    }
                ]
            },
            "filesystems": {
                "UnityFileSystemList": [
                    {
                        "UnityFileSystem": {
                            "hash": 8747625901355,
                            "id": "fs_6892"
                        }
                    },
                ]
            },
            "hash": 8747625900370,
            "health": {
                "UnityHealth": {
                    "hash": 8747625900493
                }
            },
            "home_sp": {
                "UnityStorageProcessor": {
                    "hash": 8747625877420,
                    "id": "spb"
                }
            },
            "id": "nas_1",
            "is_backup_only": false,
            "is_multi_protocol_enabled": false,
            "is_packet_reflect_enabled": false,
            "is_replication_destination": false,
            "is_replication_enabled": false,
            "is_windows_to_unix_username_mapping_enabled": null,
            "name": "lglad072",
            "pool": {
                "UnityPool": {
                    "hash": 8747629920479,
                    "id": "pool_3"
                }
            },
            "preferred_interface_settings": {
                "UnityPreferredInterfaceSettings": {
                    "hash": 8747626625166,
                    "id": "preferred_if_1"
                }
            },
            "replication_type": "ReplicationTypeEnum.NONE",
            "size_allocated": 2952790016,
            "tenant": null,
            "virus_checker": {
                "UnityVirusChecker": {
                    "hash": 8747626604144,
                    "id": "cava_1"
                }
            }
        },
    ]

File_Systems:
    description: Details of the File Systems.
    returned: When File Systems exist.
    type: list
    contains:
        id:
            description: The ID of the File System.
            type: str
        name:
            description: The name of the File System.
            type: str
    sample: [
        {
            "access_policy": "AccessPolicyEnum.UNIX",
            "cifs_notify_on_change_dir_depth": 512,
            "cifs_share": null,
            "data_reduction_percent": 0,
            "data_reduction_ratio": 1.0,
            "data_reduction_size_saved": 0,
            "description": "",
            "existed": true,
            "folder_rename_policy": "FSRenamePolicyEnum.SMB_RENAME_FORBIDDEN",
            "format": "FSFormatEnum.UFS64",
            "hash": 8786518053735,
            "health": {
                "UnityHealth": {
                    "hash": 8786518049091
                }
            },
            "host_io_size": "HostIOSizeEnum.GENERAL_8K",
            "id": "fs_12",
            "is_advanced_dedup_enabled": false,
            "is_cifs_notify_on_access_enabled": false,
            "is_cifs_notify_on_write_enabled": false,
            "is_cifs_op_locks_enabled": true,
            "is_cifs_sync_writes_enabled": false,
            "is_data_reduction_enabled": false,
            "is_read_only": false,
            "is_smbca": false,
            "is_thin_enabled": true,
            "locking_policy": "FSLockingPolicyEnum.MANDATORY",
            "metadata_size": 4294967296,
            "metadata_size_allocated": 3758096384,
            "min_size_allocated": 0,
            "name": "vro-daniel-test",
            "nas_server": {
                "UnityNasServer": {
                    "hash": 8786517296113,
                    "id": "nas_1"
                }
            },
            "nfs_share": null,
            "per_tier_size_used": [
                6442450944,
                0,
                0
            ],
            "pool": {
                "UnityPool": {
                    "hash": 8786518259493,
                    "id": "pool_3"
                }
            },
            "pool_full_policy": "ResourcePoolFullPolicyEnum.FAIL_WRITES",
            "size_allocated": 283148288,
            "size_allocated_total": 4041244672,
            "size_preallocated": 2401206272,
            "size_total": 107374182400,
            "size_used": 1620312064,
            "snap_count": 0,
            "snaps_size": 0,
            "snaps_size_allocated": 0,
            "storage_resource": {
                "UnityStorageResource": {
                    "hash": 8786518044167,
                    "id": "res_20"
                }
            },
            "supported_protocols": "FSSupportedProtocolEnum.NFS",
            "tiering_policy": "TieringPolicyEnum.AUTOTIER_HIGH",
            "type": "FilesystemTypeEnum.FILESYSTEM"
        },
    ]

Snapshots:
    description: Details of the Snapshots.
    returned: When Snapshots exist.
    type: list
    contains:
        id:
            description: The ID of the Snapshot.
            type: str
        name:
            description: The name of the Snapshot.
            type: str
    sample: [
        {
            "access_type": "FilesystemSnapAccessTypeEnum.CHECKPOINT",
            "attached_wwn": null,
            "creation_time": "2022-04-06 11:19:26.818000+00:00",
            "creator_schedule": null,
            "creator_type": "SnapCreatorTypeEnum.REP_V2",
            "creator_user": null,
            "description": "",
            "existed": true,
            "expiration_time": null,
            "hash": 8739100256648,
            "host_access": null,
            "id": "38654716464",
            "io_limit_policy": null,
            "is_auto_delete": false,
            "is_modifiable": false,
            "is_modified": false,
            "is_read_only": true,
            "is_system_snap": true,
            "last_writable_time": null,
            "lun": {
                "UnityLun": {
                    "hash": 8739100148962,
                    "id": "sv_301"
                }
            },
            "name": "42949677504_APM00213404195_0000.ckpt000_9508038064690266.2_238",
            "parent_snap": null,
            "size": 3221225472,
            "snap_group": null,
            "state": "SnapStateEnum.READY",
            "storage_resource": {
                "UnityStorageResource": {
                    "hash": 8739100173002,
                    "id": "sv_301"
                }
            }
        },
    ]

NFS_Exports:
    description: Details of the NFS Exports.
    returned: When NFS Exports exist.
    type: list
    contains:
        id:
            description: The ID of the NFS Export.
            type: str
        name:
            description: The name of the NFS Export.
            type: str
    sample: [
        {
            "anonymous_gid": 4294967294,
            "anonymous_uid": 4294967294,
            "creation_time": "2021-12-01 06:21:48.381000+00:00",
            "default_access": "NFSShareDefaultAccessEnum.NO_ACCESS",
            "description": "",
            "existed": true,
            "export_option": 1,
            "export_paths": [
                "10.230.24.20:/zack_nfs_01"
            ],
            "filesystem": {
                "UnityFileSystem": {
                    "hash": 8747298565566,
                    "id": "fs_67"
                }
            },
            "hash": 8747298565548,
            "host_accesses": null,
            "id": "NFSShare_29",
            "is_read_only": null,
            "min_security": "NFSShareSecurityEnum.SYS",
            "modification_time": "2022-04-01 11:44:17.553000+00:00",
            "name": "zack_nfs_01",
            "nfs_owner_username": null,
            "no_access_hosts": null,
            "no_access_hosts_string": "10.226.198.207,10.226.198.25,10.226.198.44,10.226.198.85,Host1,
Host2,Host4,Host5,Host6,10.10.0.0/255.255.240.0",
            "path": "/",
            "read_only_hosts": null,
            "read_only_hosts_string": "",
            "read_only_root_access_hosts": null,
            "read_only_root_hosts_string": "",
            "read_write_hosts": null,
            "read_write_hosts_string": "",
            "read_write_root_hosts_string": "",
            "role": "NFSShareRoleEnum.PRODUCTION",
            "root_access_hosts": null,
            "snap": null,
            "type": "NFSTypeEnum.NFS_SHARE"
        },
    ]

SMB_Shares:
    description: Details of the SMB Shares.
    returned: When SMB Shares exist.
    type: list
    contains:
        id:
            description: The ID of the SMB Share.
            type: str
        name:
            description: The name of the SMB Share.
            type: str
    sample: [
        {
            "creation_time": "2022-03-17 11:56:54.867000+00:00",
            "description": "",
            "existed": true,
            "export_paths": [
                "\\\\multi-prot-pie.extreme1.com\\multi-prot-hui",
                "\\\\10.230.24.26\\multi-prot-hui"
            ],
            "filesystem": {
                "UnityFileSystem": {
                    "hash": 8741295638110,
                    "id": "fs_140"
                }
            },
            "hash": 8741295638227,
            "id": "SMBShare_20",
            "is_abe_enabled": false,
            "is_ace_enabled": false,
            "is_branch_cache_enabled": false,
            "is_continuous_availability_enabled": false,
            "is_dfs_enabled": false,
            "is_encryption_enabled": false,
            "is_read_only": null,
            "modified_time": "2022-03-17 11:56:54.867000+00:00",
            "name": "multi-prot-hui",
            "offline_availability": "CifsShareOfflineAvailabilityEnum.NONE",
            "path": "/",
            "snap": null,
            "type": "CIFSTypeEnum.CIFS_SHARE",
            "umask": "022"
        },
    ]

User_Quotas:
    description: Details of the user quotas.
    returned: When user quotas exist.
    type: list
    contains:
        id:
            description: The ID of the user quota.
            type: str
        uid:
            description: The UID of the user quota.
            type: str
    sample: [
        {
            "id": "userquota_171798694698_0_60000",
            "uid": 60000
        },
        {
            "id": "userquota_171798694939_0_5001",
            "uid": 5001
        }
    ]

Tree_Quotas:
    description: Details of the quota trees.
    returned: When quota trees exist.
    type: list
    contains:
        id:
            description: The ID of the quota tree.
            type: str
        path:
            description: The path of the quota tree.
            type: str
    sample: [
        {
            "id": "treequota_171798709589_1",
            "path": "/vro-ui-fs-rkKfimmN"
        },
        {
            "id": "treequota_171798709590_1",
            "path": "/vro-ui-fs-mGYXAMqk"
        }
    ]

Disk_Groups:
    description: Details of the disk groups.
    returned: When disk groups exist.
    type: list
    contains:
        id:
            description: The ID of the disk group.
            type: str
        name:
            description: The name of the disk group.
            type: str
        tier_type:
            description: The tier type of the disk group.
            type: str
    sample: [
        {
            "id": "dg_3",
            "name": "400 GB SAS Flash 2",
            "tier_type": "EXTREME_PERFORMANCE"
        },
        {
            "id": "dg_16",
            "name": "600 GB SAS 10K",
            "tier_type": "PERFORMANCE"
        }
    ]

NFS_Servers:
    description: Details of the NFS Servers.
    returned: When NFS Servers exist.
    type: list
    contains:
        id:
            description: The ID of the NFS Servers.
            type: str
    sample: [
        {
            "id": "nfs_3",
        },
        {
            "id": "nfs_4",
        },
        {
            "id": "nfs_9",
        }
    ]
CIFS_Servers:
    description: Details of the CIFS Servers.
    returned: When CIFS Servers exist.
    type: list
    contains:
        id:
            description: The ID of the CIFS Servers.
            type: str
        name:
            description: The name of the CIFS server.
            type: str
    sample: [
        {
            "id": "cifs_3",
            "name": "test_cifs_1"
        },
        {
            "id": "cifs_4",
            "name": "test_cifs_2"
        },
        {
            "id": "cifs_9",
            "name": "test_cifs_3"
        }
    ]
Ethernet_ports:
    description: Details of the ethernet ports.
    returned: When ethernet ports exist.
    type: list
    contains:
        id:
            description: The ID of the ethernet port.
            type: str
        name:
            description: The name of the ethernet port.
            type: str
    sample: [
        {
            "id": "spa_mgmt",
            "name": "SP A Management Port"
        },
        {
            "id": "spa_ocp_0_eth0",
            "name": "SP A 4-Port Card Ethernet Port 0"
        },
        {
            "id": "spa_ocp_0_eth1",
            "name": "SP A 4-Port Card Ethernet Port 1"
        }
    ]
File_interfaces:
    description: Details of the file inetrfaces.
    returned: When file inetrface exist.
    type: list
    contains:
        id:
            description: The ID of the file inetrface.
            type: str
        name:
            description: The name of the file inetrface.
            type: str
        ip_address:
            description: IP address of the file inetrface.
            type: str
    sample: [
        {
            "id": "if_3",
            "ip_address": "xx.xx.xx.xx",
            "name": "1_APMXXXXXXXXXX"
        },
        {
            "id": "if_3",
            "ip_address": "xx.xx.xx.xx",
            "name": "2_APMXXXXXXXXXX"
        },
        {
            "id": "if_3",
            "ip_address": "xx.xx.xx.xx",
            "name": "3_APMXXXXXXXXXX"
        }
    ]
Replication_sessions:
    description: Details of the Replication sessions.
    returned: When Replication sessions exist.
    type: list
    contains:
        id:
            description: The ID of the Replication session.
            type: str
        name:
            description: The name of the Replication session.
            type: str
    sample: [
        {
            "current_transfer_est_remain_time": 0,
            "daily_snap_replication_policy": null,
            "dst_resource_id": "nas_8",
            "dst_spa_interface": {
                "UnityRemoteInterface": {
                    "hash": 8771253398547,
                    "id": "APM00213404195:if_181"
                }
            },
            "dst_spb_interface": {
               "UnityRemoteInterface": {
                   "hash": 8771253424144,
                   "id": "APM00213404195:if_180"
              }
            },
            "dst_status": "ReplicationSessionStatusEnum.OK",
            "existed": true,
            "hash": 8771259012271,
            "health": {
                "UnityHealth": {
                    "hash": 8771253424168
                }
            },
            "hourly_snap_replication_policy": null,
            "id": "103079215114_APM00213404195_0000_103079215274_APM00213404194_0000",
            "last_sync_time": "2023-04-18 10:35:25+00:00",
            "local_role": "ReplicationSessionReplicationRoleEnum.DESTINATION",
            "max_time_out_of_sync": 0,
            "members": null,
            "name": "rep_sess_nas",
            "network_status": "ReplicationSessionNetworkStatusEnum.OK",
            "remote_system": {
                "UnityRemoteSystem": {
                    "hash": 8771253380142
                }
            },
            "replication_resource_type": "ReplicationEndpointResourceTypeEnum.NASSERVER",
            "src_resource_id": "nas_213",
            "src_spa_interface": {
                "UnityRemoteInterface": {
                    "hash": 8771253475010,
                    "id": "APM00213404194:if_195"
                }
            },
            "src_spb_interface": {
                "UnityRemoteInterface": {
                    "hash": 8771253374169,
                    "id": "APM00213404194:if_194"
                }
            },
            "src_status": "ReplicationSessionStatusEnum.OK",
            "status": "ReplicationOpStatusEnum.ACTIVE",
            "sync_progress": 0,
            "sync_state": "ReplicationSessionSyncStateEnum.IN_SYNC"
        },
    ]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.unity.plugins.module_utils.storage.dell \
    import utils

LOG = utils.get_logger('info')
SUCCESSFULL_LISTED_MSG = 'Successfully listed.'

application_type = "Ansible/1.7.1"


class Info(object):
    """Class with Info operations"""

    def __init__(self):
        """ Define all parameters required by this module"""

        self.module_params = utils.get_unity_management_host_parameters()
        self.module_params.update(get_info_parameters())

        """ initialize the ansible module """
        self.module = AnsibleModule(argument_spec=self.module_params,
                                    supports_check_mode=True)
        utils.ensure_required_libs(self.module)

        self.unity = utils.get_unity_unisphere_connection(self.module.params,
                                                          application_type)
        LOG.info('Got the unity instance for provisioning on Unity')

    def get_array_details(self):
        """ Get the list of snapshot schedules on a given Unity storage
            system """

        try:
            LOG.info('Getting array details ')
            array_details = self.unity.info
            return array_details._get_properties()

        except utils.HttpError as e:
            if e.http_status == 401:
                msg = 'Incorrect username or password provided.'
                LOG.error(msg)
                self.module.fail_json(msg=msg)
            else:
                msg = str(e)
                LOG.error(msg)
                self.module.fail_json(msg=msg)
        except Exception as e:
            msg = 'Get array details from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_hosts_list(self):
        """ Get the list of hosts on a given Unity storage system """

        try:
            LOG.info('Getting hosts list ')
            hosts = self.unity.get_host()
            return result_list(hosts)

        except Exception as e:
            msg = 'Get hosts list from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_fc_initiators_list(self):
        """ Get the list of FC Initiators on a given Unity storage system """

        try:
            LOG.info('Getting FC initiators list ')
            fc_initiator = utils.host.UnityHostInitiatorList \
                .get(cli=self.unity._cli, type=utils.HostInitiatorTypeEnum.FC)
            return fc_initiators_result_list(fc_initiator)

        except Exception as e:
            msg = 'Get FC initiators list from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_iscsi_initiators_list(self):
        """ Get the list of ISCSI initiators on a given Unity storage
            system """

        try:
            LOG.info('Getting ISCSI initiators list ')
            iscsi_initiator = utils.host.UnityHostInitiatorList \
                .get(cli=self.unity._cli, type=utils.HostInitiatorTypeEnum.
                     ISCSI)
            return iscsi_initiators_result_list(iscsi_initiator)

        except Exception as e:
            msg = 'Get ISCSI initiators list from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_consistency_groups_list(self):
        """ Get the list of consistency groups on a given Unity storage
            system """

        try:
            LOG.info('Getting consistency groups list ')
            consistency_groups = utils.cg.UnityConsistencyGroupList \
                .get(self.unity._cli)
            return result_list(consistency_groups)

        except Exception as e:
            msg = 'Get consistency groups list from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_storage_pools_list(self):
        """ Get the list of storage pools on a given Unity storage
            system """

        try:
            LOG.info('Getting storage pools list ')
            storage_pools = self.unity.get_pool()
            return result_list(storage_pools)

        except Exception as e:
            msg = 'Get storage pools list from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_volumes_list(self):
        """ Get the list of volumes on a given Unity storage
            system """

        try:
            LOG.info('Getting volumes list ')
            volumes = self.unity.get_lun()
            return result_list(volumes)

        except Exception as e:
            msg = 'Get volumes list from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_snapshot_schedules_list(self):
        """ Get the list of snapshot schedules on a given Unity storage
            system """

        try:
            LOG.info('Getting snapshot schedules list ')
            snapshot_schedules = utils.snap_schedule.UnitySnapScheduleList \
                .get(cli=self.unity._cli)
            return result_list(snapshot_schedules)

        except Exception as e:
            msg = 'Get snapshot schedules list from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_nas_servers_list(self):
        """Get the list of NAS servers on a given Unity storage system"""

        try:
            LOG.info("Getting NAS servers list")
            nas_servers = self.unity.get_nas_server()
            return result_list(nas_servers)

        except Exception as e:
            msg = 'Get NAS servers list from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_file_systems_list(self):
        """Get the list of file systems on a given Unity storage system"""

        try:
            LOG.info("Getting file systems list")
            file_systems = self.unity.get_filesystem()
            return result_list(file_systems)

        except Exception as e:
            msg = 'Get file systems list from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_snapshots_list(self):
        """Get the list of snapshots on a given Unity storage system"""

        try:
            LOG.info("Getting snapshots list")
            snapshots = self.unity.get_snap()
            return result_list(snapshots)

        except Exception as e:
            msg = 'Get snapshots from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_nfs_exports_list(self):
        """Get the list of NFS exports on a given Unity storage system"""

        try:
            LOG.info("Getting NFS exports list")
            nfs_exports = self.unity.get_nfs_share()
            return result_list(nfs_exports)

        except Exception as e:
            msg = 'Get NFS exports from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_smb_shares_list(self):
        """Get the list of SMB shares on a given Unity storage system"""

        try:
            LOG.info("Getting SMB shares list")
            smb_shares = self.unity.get_cifs_share()
            return result_list(smb_shares)

        except Exception as e:
            msg = 'Get SMB shares from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_user_quota_list(self):
        """Get the list of user quotas on a given Unity storage system"""

        try:
            LOG.info("Getting user quota list")
            user_quotas = self.unity.get_user_quota()
            return user_quota_result_list(user_quotas)

        except Exception as e:
            msg = 'Get user quotas from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_tree_quota_list(self):
        """Get the list of quota trees on a given Unity storage system"""

        try:
            LOG.info("Getting quota tree list")
            tree_quotas = self.unity.get_tree_quota()
            return tree_quota_result_list(tree_quotas)

        except Exception as e:
            msg = 'Get quota trees from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_disk_groups_list(self):
        """Get the list of disk group details on a given Unity storage system"""

        try:
            LOG.info("Getting disk group list")
            pool_disk_list = []
            disk_instances = utils.UnityDiskGroupList(cli=self.unity._cli)
            if disk_instances:
                for disk in disk_instances:
                    pool_disk = {"id": disk.id, "name": disk.name,
                                 "tier_type": disk.tier_type.name}
                    pool_disk_list.append(pool_disk)
            return pool_disk_list
        except Exception as e:
            msg = 'Get disk group from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_nfs_server_list(self):
        """Get the list of NFS servers on a given Unity storage system"""

        try:
            LOG.info("Getting NFS servers list")
            nfs_servers = self.unity.get_nfs_server()
            return nfs_server_result_list(nfs_servers)

        except Exception as e:
            msg = 'Get NFS servers list from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_cifs_server_list(self):
        """Get the list of CIFS servers on a given Unity storage system"""

        try:
            LOG.info("Getting CIFS servers list")
            cifs_servers = self.unity.get_cifs_server()
            return result_list(cifs_servers)

        except Exception as e:
            msg = 'Get CIFS servers list from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_ethernet_port_list(self):
        """Get the list of ethernet ports on a given Unity storage system"""

        try:
            LOG.info("Getting ethernet ports list")
            ethernet_port = self.unity.get_ethernet_port()
            return result_list(ethernet_port)

        except Exception as e:
            msg = 'Get ethernet port list from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_file_interface_list(self):
        """Get the list of file interfaces on a given Unity storage system"""

        try:
            LOG.info("Getting file interfaces list")
            file_interface = self.unity.get_file_interface()
            return file_interface_result_list(file_interface)

        except Exception as e:
            msg = 'Get file interface list from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_replication_session_list(self):
        """Get the list of replication sessions on a given Unity storage system"""

        try:
            LOG.info("Getting replication sessions list")
            replication_sessions = self.unity.get_replication_session()
            return result_list(replication_sessions)

        except Exception as e:
            msg = 'Get replication session list from unity array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def perform_module_operation(self):
        """ Perform different actions on Info based on user parameter
            chosen in playbook """

        """ Get the array details a given Unity storage system """

        array_details = self.get_array_details()
        host = []
        fc_initiator = []
        iscsi_initiator = []
        cg = []
        storage_pool = []
        vol = []
        snapshot_schedule = []
        nas_server = []
        file_system = []
        snapshot = []
        nfs_export = []
        smb_share = []
        user_quota = []
        tree_quota = []
        disk_group = []
        nfs_server = []
        cifs_server = []
        ethernet_port = []
        file_interface = []
        replication_session = []

        subset = self.module.params['gather_subset']
        if subset is not None:
            if 'host' in subset:
                host = self.get_hosts_list()
            if 'fc_initiator' in subset:
                fc_initiator = self.get_fc_initiators_list()
            if 'iscsi_initiator' in subset:
                iscsi_initiator = self.get_iscsi_initiators_list()
            if 'cg' in subset:
                cg = self.get_consistency_groups_list()
            if 'storage_pool' in subset:
                storage_pool = self.get_storage_pools_list()
            if 'vol' in subset:
                vol = self.get_volumes_list()
            if 'snapshot_schedule' in subset:
                snapshot_schedule = self.get_snapshot_schedules_list()
            if 'nas_server' in subset:
                nas_server = self.get_nas_servers_list()
            if 'file_system' in subset:
                file_system = self.get_file_systems_list()
            if 'snapshot' in subset:
                snapshot = self.get_snapshots_list()
            if 'nfs_export' in subset:
                nfs_export = self.get_nfs_exports_list()
            if 'smb_share' in subset:
                smb_share = self.get_smb_shares_list()
            if 'user_quota' in subset:
                user_quota = self.get_user_quota_list()
            if 'tree_quota' in subset:
                tree_quota = self.get_tree_quota_list()
            if 'disk_group' in subset:
                disk_group = self.get_disk_groups_list()
            if 'nfs_server' in subset:
                nfs_server = self.get_nfs_server_list()
            if 'cifs_server' in subset:
                cifs_server = self.get_cifs_server_list()
            if 'ethernet_port' in subset:
                ethernet_port = self.get_ethernet_port_list()
            if 'file_interface' in subset:
                file_interface = self.get_file_interface_list()
            if 'replication_session' in subset:
                replication_session = self.get_replication_session_list()

        self.module.exit_json(
            Array_Details=array_details,
            Hosts=host,
            FC_initiators=fc_initiator,
            ISCSI_initiators=iscsi_initiator,
            Consistency_Groups=cg,
            Storage_Pools=storage_pool,
            Volumes=vol,
            Snapshot_Schedules=snapshot_schedule,
            NAS_Servers=nas_server,
            File_Systems=file_system,
            Snapshots=snapshot,
            NFS_Exports=nfs_export,
            SMB_Shares=smb_share,
            User_Quotas=user_quota,
            Tree_Quotas=tree_quota,
            Disk_Groups=disk_group,
            NFS_Servers=nfs_server,
            CIFS_Servers=cifs_server,
            Ethernet_ports=ethernet_port,
            File_interfaces=file_interface,
            Replication_sessions=replication_session
        )


def result_list(entity):
    """ Get the name and id associated with the Unity entities """
    result = []

    if entity:
        LOG.info(SUCCESSFULL_LISTED_MSG)
        for item in entity:
            result.append(
                item._get_properties()
            )
        return result
    else:
        return None


def fc_initiators_result_list(entity):
    """ Get the WWN and id associated with the Unity FC initiators """
    result = []

    if entity:
        LOG.info(SUCCESSFULL_LISTED_MSG)
        for item in entity:
            result.append(
                {
                    "WWN": item.initiator_id,
                    "id": item.id
                }
            )
        return result
    else:
        return None


def iscsi_initiators_result_list(entity):
    """ Get the IQN and id associated with the Unity ISCSI initiators """
    result = []

    if entity:
        LOG.info(SUCCESSFULL_LISTED_MSG)
        for item in entity:
            result.append(
                {
                    "IQN": item.initiator_id,
                    "id": item.id
                }
            )
        return result
    else:
        return None


def user_quota_result_list(entity):
    """ Get the id and uid associated with the Unity user quotas """
    result = []

    if entity:
        LOG.info(SUCCESSFULL_LISTED_MSG)
        for item in entity:
            result.append(
                {
                    "uid": item.uid,
                    "id": item.id
                }
            )
        return result
    else:
        return None


def tree_quota_result_list(entity):
    """ Get the id and path associated with the Unity quota trees """
    result = []

    if entity:
        LOG.info(SUCCESSFULL_LISTED_MSG)
        for item in entity:
            result.append(
                {
                    "path": item.path,
                    "id": item.id
                }
            )
        return result
    else:
        return None


def nfs_server_result_list(entity):
    """ Get the id of NFS Server """
    result = []

    if entity:
        LOG.info(SUCCESSFULL_LISTED_MSG)
        for item in entity:
            result.append(
                item._get_properties()
            )
        return result
    else:
        return None


def file_interface_result_list(entity):
    """ Get the id, name and IP of File Interfaces """
    result = []

    if entity:
        LOG.info(SUCCESSFULL_LISTED_MSG)
        for item in entity:
            result.append(
                item._get_properties()
            )
        return result
    else:
        return None


def get_info_parameters():
    """This method provides parameters required for the ansible
    info module on Unity"""
    return dict(gather_subset=dict(type='list', required=False,
                                   elements='str',
                                   choices=['host', 'fc_initiator',
                                            'iscsi_initiator', 'cg',
                                            'storage_pool', 'vol',
                                            'snapshot_schedule', 'nas_server',
                                            'file_system', 'snapshot',
                                            'nfs_export', 'smb_share',
                                            'user_quota', 'tree_quota', 'disk_group', 'nfs_server', 'cifs_server',
                                            'ethernet_port', 'file_interface', 'replication_session']))


def main():
    """ Create Unity Info object and perform action on it
        based on user input from playbook"""
    obj = Info()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
