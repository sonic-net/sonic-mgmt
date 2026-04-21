#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
module: na_ontap_volume
short_description: NetApp ONTAP manage volumes.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.6.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
  - Create or destroy or modify volumes on NetApp ONTAP.

options:

  state:
    description:
      - Whether the specified volume should exist or not.
    choices: ['present', 'absent']
    type: str
    default: 'present'

  name:
    description:
      - The name of the volume to manage.
    type: str
    required: true

  vserver:
    description:
      - Name of the vserver to use.
    type: str
    required: true

  from_name:
    description:
      - Name of the existing volume to be renamed to name.
    type: str
    version_added: 2.7.0

  is_infinite:
    type: bool
    description:
      - Set True if the volume is an Infinite Volume.
      - Deleting an infinite volume is asynchronous.
    default: false

  is_online:
    type: bool
    description:
    - Whether the specified volume is online, or not.
    default: True

  aggregate_name:
    description:
      - The name of the aggregate the flexvol should exist on.
      - Cannot be set when using the C(nas_application_template) option.
    type: str

  tags:
    description:
      - Tags are an optional way to track the uses of a resource.
      - Tag values must be formatted as key:value strings, example ["team:csi", "environment:test"]
    type: list
    elements: str
    version_added: 22.6.0

  nas_application_template:
    description:
      - additional options when using the application/applications REST API to create a volume.
      - the module is using ZAPI by default, and switches to REST if any suboption is present.
      - create a FlexVol by default.
      - create a FlexGroup if C(auto_provision_as) is set and C(FlexCache) option is not present.
      - create a FlexCache if C(flexcache) option is present.
    type: dict
    version_added: 20.12.0
    suboptions:
      flexcache:
        description: whether to create a flexcache.  If absent, a FlexVol or FlexGroup is created.
        type: dict
        suboptions:
          dr_cache:
            description:
               - whether to use the same flexgroup msid as the origin.
               - requires ONTAP 9.9 and REST.
               - create only option, ignored if the flexcache already exists.
            type: bool
            version_added: 21.3.0
          origin_svm_name:
            description: the remote SVM for the flexcache.
            type: str
            required: true
          origin_component_name:
            description: the remote component for the flexcache.
            type: str
            required: true
      cifs_access:
        description:
          - The list of CIFS access controls.  You must provide I(user_or_group) or I(access) to enable CIFS access.
        type: list
        elements: dict
        suboptions:
          access:
            description: The CIFS access granted to the user or group.  Default is full_control.
            type: str
            choices: [change, full_control, no_access, read]
          user_or_group:
            description: The name of the CIFS user or group that will be granted access.  Default is Everyone.
            type: str
      nfs_access:
        description:
          - The list of NFS access controls.  You must provide I(host) or I(access) to enable NFS access.
          - Mutually exclusive with export_policy option.
        type: list
        elements: dict
        suboptions:
          access:
            description: The NFS access granted.  Default is rw.
            type: str
            choices: [none, ro, rw]
          host:
            description: The name of the NFS entity granted access.  Default is 0.0.0.0/0.
            type: str
      storage_service:
        description:
          - The performance service level (PSL) for this volume
        type: str
        choices: ['value', 'performance', 'extreme']
      tiering:
        description:
          - Cloud tiering policy (see C(tiering_policy) for a more complete description).
        type: dict
        suboptions:
          control:
            description: Storage tiering placement rules for the container.
            choices: ['required', 'best_effort', 'disallowed']
            type: str
          policy:
            description:
              - Cloud tiering policy (see C(tiering_policy)).
              - Must match C(tiering_policy) if both are present.
            choices: ['all', 'auto', 'none', 'snapshot-only']
            type: str
          object_stores:
            description: list of object store names for tiering.
            type: list
            elements: str
      exclude_aggregates:
        description:
          - The list of aggregate names to exclude when creating a volume.
          - Requires ONTAP 9.9.1 GA or later.
        type: list
        elements: str
        version_added: 21.7.0
      use_nas_application:
        description:
          - Whether to use the application/applications REST/API to create a volume.
          - This will default to true if any other suboption is present.
        type: bool
        default: true
      cifs_share_name:
        description:
          - The name of the CIFS share.
          - Requires ONTAP 9.11 or later.
        type: str
        version_added: 22.13.0
      snapshot_locking_enabled:
        description:
          - Indicates whether Snapshot copy locking is enabled on the volume.
          - Requires ONTAP 9.13.1 or later.
        type: bool
        version_added: 22.13.0
      snaplock:
        description: Requires ONTAP 9.12 or later.
        type: dict
        version_added: 22.13.0
        suboptions:
          snaplock_type:
            description: The SnapLock type of the smart container.
            choices: ['compliance', 'enterprise', 'non_snaplock']
            type: str
          autocommit_period:
            description:
              - Specifies the autocommit period for SnapLock volume.
              - Duration is in the ISO-8601 duration format (eg PY, PM, PD, PTH, PTM).
              - Examples are P30M, P10Y, PT1H, none. A duration that combines different periods is not supported.
            type: str
          append_mode_enabled:
            description: Specifies if the volume append mode is enabled or disabled.
            type: bool
          retention:
            description:
              - Default, maximum, and minumum retention periods for files committed to the WORM state on the volume.
              - Durations are in the ISO-8601 duration format, see autocommit_period.
            type: dict
            suboptions:
              default:
                description: Default retention period that is applied to files while committing them to the WORM state without an associated retention period.
                type: str
              maximum:
                description: Maximum allowed retention period for files committed to the WORM state on the volume.
                type: str
              minimum:
                description: Minimum allowed retention period for files committed to the WORM state on the volume.
                type: str

  size:
    description:
      - The size of the volume in (size_unit). Required when C(state=present).
    type: int

  size_unit:
    description:
      - The unit used to interpret the size parameter.
    choices: ['bytes', 'b', 'kb', 'mb', 'gb', 'tb', 'pb', 'eb', 'zb', 'yb']
    type: str
    default: 'gb'

  size_change_threshold:
    description:
      - Percentage in size change to trigger a resize.
      - When this parameter is greater than 0, a difference in size between what is expected and what is configured is ignored if it is below the threshold.
      - For instance, the nas application allocates a larger size than specified to account for overhead.
      - When using C(nas_application_template), if the overhead size difference is within the threshold,
        the module updates the size parameter to match the allocated size for idempotency in subsequent runs.
      - If the difference exceeds the threshold, the volume will be resized to the requested size.
      - For regular volumes (without nas_application_template), size differences within the threshold are ignored without parameter updates.
      - Set this to 0 for an exact match.
    type: int
    default: 10
    version_added: 20.12.0

  sizing_method:
    description:
      - Represents the method to modify the size of a FlexGroup.
      - use_existing_resources - Increases or decreases the size of the FlexGroup by increasing or decreasing the size of the current FlexGroup resources.
      - add_new_resources - Increases the size of the FlexGroup by adding new resources. This is limited to two new resources per available aggregate.
      - This is only supported if REST is enabled (ONTAP 9.6 or later) and only for FlexGroups.  ONTAP defaults to use_existing_resources.
    type: str
    choices: ['add_new_resources', 'use_existing_resources']
    version_added: 20.12.0

  type:
    description:
      - The volume type, either read-write (RW) or data-protection (DP).
    type: str

  export_policy:
    description:
      - Name of the export policy.
      - Mutually exclusive with nfs_access suboption in nas_application_template.
    type: str
    aliases: ['policy']

  junction_path:
    description:
      - Junction path of the volume.
      - To unmount, use junction path C('').
    type: str

  space_guarantee:
    description:
      - Space guarantee style for the volume.
      - The file setting is no longer supported.
    choices: ['none', 'file', 'volume']
    type: str

  percent_snapshot_space:
    description:
      - Amount of space reserved for snapshot copies of the volume.
    type: int

  volume_security_style:
    description:
      - The security style associated with this volume.
    choices: ['mixed', 'ntfs', 'unified', 'unix']
    type: str

  encrypt:
    type: bool
    description:
      - Whether or not to enable Volume Encryption.
      - If not present, ONTAP defaults to false at volume creation.
      - Changing encrypt value after creation requires ONTAP 9.3 or later.
    version_added: 2.7.0

  efficiency_policy:
    description:
      - Allows a storage efficiency policy to be set on volume creation.
    type: str
    version_added: 2.7.0

  unix_permissions:
    description:
      - Unix permission bits in octal or symbolic format.
      - For example, 0 is equivalent to ------------, 777 is equivalent to ---rwxrwxrwx,both formats are accepted.
      - The valid octal value ranges between 0 and 777 inclusive.
    type: str
    version_added: 2.8.0

  group_id:
    description:
      - The UNIX group ID for the volume. The default value is 0 ('root').
    type: int
    version_added: '20.1.0'

  user_id:
    description:
      - The UNIX user ID for the volume. The default value is 0 ('root').
    type: int
    version_added: '20.1.0'

  snapshot_policy:
    description:
      - The name of the snapshot policy.
      - The default policy name is 'default'.
      - If present, this will set the protection_type when using C(nas_application_template).
    type: str
    version_added: 2.8.0

  aggr_list:
    description:
      - an array of names of aggregates to be used for FlexGroup constituents.
    type: list
    elements: str
    version_added: 2.8.0

  aggr_list_multiplier:
    description:
      - The number of times to iterate over the aggregates listed with the aggr_list parameter when creating a FlexGroup.
    type: int
    version_added: 2.8.0

  auto_provision_as:
    description:
      - Automatically provision a FlexGroup volume.
    version_added: 2.8.0
    choices: ['flexgroup']
    type: str

  snapdir_access:
    description:
      - This is an advanced option, the default is False.
      - Enable the visible '.snapshot' directory that is normally present at system internal mount points.
      - This value also turns on access to all other '.snapshot' directories in the volume.
      - This option is supported in REST for ONTAP 9.13.1 or later with ONTAP collection version 22.8.0 or later.
    type: bool
    version_added: 2.8.0

  atime_update:
    description:
      - This is an advanced option, the default is True.
      - If false, prevent the update of inode access times when a file is read.
      - This value is useful for volumes with extremely high read traffic,
        since it prevents writes to the inode file for the volume from contending with reads from other files.
      - This field should be used carefully.
      - That is, use this field when you know in advance that the correct access time for inodes will not be needed for files on that volume.
      - This option is supported in REST for ONTAP 9.8 or later with ONTAP collection version 22.8.0 or later.
    type: bool
    version_added: 2.8.0

  vol_nearly_full_threshold_percent:
    description:
      - Specifies the percentage at which the volume is considered nearly full, and above which an EMS warning will be generated.
      - The default value is 95%. The maximum value for this option is 99%.
      - Setting this threshold to 0 disables the volume nearly full space alerts.
      - Supported only with REST and requires ONTAP 9.9 or later.
    type: int
    version_added: 22.8.0

  vol_full_threshold_percent:
    description:
      - Specifies the percentage at which the volume is considered full, and above which a critical EMS error will be generated.
      - The default value is 98%. The maximum value for this option is 100%.
      - Setting this threshold to 0 disables the volume full space alerts.
      - Supported only with REST and requires ONTAP 9.9 or later.
    type: int
    version_added: 22.8.0

  large_size_enabled:
    description:
      - Indicates if the support for large FlexVol volumes and large files is enabled on this volume.
    type: bool
    version_added: 22.14.0

  wait_for_completion:
    description:
      - Set this parameter to 'true' for synchronous execution during create (wait until volume status is online)
      - Set this parameter to 'false' for asynchronous execution
      - For asynchronous, execution exits as soon as the request is sent, without checking volume status
    type: bool
    default: false
    version_added: 2.8.0

  time_out:
    description:
      - With ZAPI - time to wait for Flexgroup creation, modification, or deletion in seconds.
      - With REST - time to wait for any volume creation, modification, or deletion in seconds.
      - Error out if task is not completed in defined time.
      - With ZAPI - if 0, the request is asynchronous.
      - Default is set to 3 minutes.
      - Use C(max_wait_time) and C(wait_for_completion) for volume move and encryption operations.
    default: 180
    type: int
    version_added: 2.8.0

  max_wait_time:
    description:
      - Volume move and encryption operations might take longer time to complete.
      - With C(wait_for_completion) set, module will wait for time set in this option for volume move and encryption to complete.
      - If time exipres, module exit and the operation may still be running.
      - Default is set to 10 minutes.
    default: 600
    type: int
    version_added: 22.0.0

  language:
    description:
      - Language to use for Volume
      - Default uses SVM language
      - Possible values   Language
      - c                 POSIX
      - ar                Arabic
      - cs                Czech
      - da                Danish
      - de                German
      - en                English
      - en_us             English (US)
      - es                Spanish
      - fi                Finnish
      - fr                French
      - he                Hebrew
      - hr                Croatian
      - hu                Hungarian
      - it                Italian
      - ja                Japanese euc-j
      - ja_v1             Japanese euc-j
      - ja_jp.pck         Japanese PCK (sjis)
      - ja_jp.932         Japanese cp932
      - ja_jp.pck_v2      Japanese PCK (sjis)
      - ko                Korean
      - no                Norwegian
      - nl                Dutch
      - pl                Polish
      - pt                Portuguese
      - ro                Romanian
      - ru                Russian
      - sk                Slovak
      - sl                Slovenian
      - sv                Swedish
      - tr                Turkish
      - zh                Simplified Chinese
      - zh.gbk            Simplified Chinese (GBK)
      - zh_tw             Traditional Chinese euc-tw
      - zh_tw.big5        Traditional Chinese Big 5
      - To use UTF-8 as the NFS character set, append '.UTF-8' to the language code
    type: str
    version_added: 2.8.0

  qos_policy_group:
    description:
      - Specifies a QoS policy group to be set on volume.
    type: str
    version_added: 2.9.0

  qos_adaptive_policy_group:
    description:
      - Specifies a QoS adaptive policy group to be set on volume.
    type: str
    version_added: 2.9.0

  tiering_policy:
    description:
      - The tiering policy that is to be associated with the volume.
      - This policy decides whether the blocks of a volume will be tiered to the capacity tier.
      - snapshot-only policy allows tiering of only the volume snapshot copies not associated with the active file system.
      - auto policy allows tiering of both snapshot and active file system user data to the capacity tier.
      - backup policy on DP volumes allows all transferred user data blocks to start in the capacity tier.
      - all is the REST equivalent for backup.
      - When set to none, the Volume blocks will not be tiered to the capacity tier.
      - If no value specified, the volume is assigned snapshot only by default.
      - Requires ONTAP 9.4 or later.
    choices: ['snapshot-only', 'auto', 'backup', 'none', 'all']
    type: str
    version_added: 2.9.0

  tiering_object_tags:
    description:
      - This parameter specifies tags of a volume for objects stored on a FabricPool-enabled aggregate.
      - Each tag is a key,value pair and should be in the format "key=value".
      - A maximum of 4 tags are allowed per volume.
      - To remove all existing tiering object tags, specify an empty list as the parameter value.
    type: list
    elements: str
    version_added: 23.1.0

  space_slo:
    description:
      - Specifies the space SLO type for the volume. The space SLO type is the Service Level Objective for space management for the volume.
      - The space SLO value is used to enforce existing volume settings so that sufficient space is set aside on the aggregate to meet the space SLO.
      - This parameter is not supported on Infinite Volumes.
    choices: ['none', 'thick', 'semi-thick']
    type: str
    version_added: 2.9.0

  nvfail_enabled:
    description:
      - If true, the controller performs additional work at boot and takeover times if it finds that there has been any potential data loss in the volume's
        constituents due to an NVRAM failure.
      - The volume's constituents would be put in a special state called 'in-nvfailed-state' such that protocol access is blocked.
      - This will cause the client applications to crash and thus prevent access to stale data.
      - To get out of this situation, the admin needs to manually clear the 'in-nvfailed-state' on the volume's constituents.
    type: bool
    version_added: 2.9.0

  vserver_dr_protection:
    description:
      - Specifies the protection type for the volume in a Vserver DR setup.
    choices: ['protected', 'unprotected']
    type: str
    version_added: 2.9.0

  comment:
    description:
      - Sets a comment associated with the volume.
    type: str
    version_added: 2.9.0

  snapshot_auto_delete:
    description:
      - A dictionary for the auto delete options and values.
      - All the above mentioned options except 'destroy_list' are supported in REST for ONTAP 9.13.1 or later with ONTAP collection version 22.8.0 or later.
    type: dict
    version_added: '20.4.0'
    suboptions:
      state:
        description: Determines if the snapshot autodelete is currently enabled for the volume.
        type: str
        choices: ['on', 'off']
      commitment:
        description: Determines the snapshots that the snapshot autodelete is allowed to delete to get back space.
        type: str
        choices: [try, disrupt, destroy]
      trigger:
        description:
          - Determines the condition which starts the automatic deletion of snapshots.
          - Note - C(space_reserve) option is deprecated and may be removed in the future.
        type: str
        choices: [volume, snap_reserve, space_reserve]
      target_free_space:
        description:
          - Determines when snapshot autodelete should stop deleting snapshots.
          - Depending on the trigger, snapshots are deleted until the target free space percentage is reached.
        type: int
      delete_order:
        description: Determines if the oldest or newest snapshot is deleted first.
        type: str
        choices: [newest_first, oldest_first]
      defer_delete:
        description: Determines what kind of snapshot to delete in the end.
        type: str
        choices: [scheduled, user_created, prefix, 'none']
      prefix:
        description:
          - Can be set to provide the prefix string for the 'prefix' value of the 'defer_delete' option.
          - The prefix string can be 15 characters long.
        type: str
      destroy_list:
        description:
          - A comma seperated list of services which can be destroyed if the snapshot backing that service is deleted.
          - For 7-mode, the possible values for this option are a combination of 'lun_clone', 'vol_clone', 'cifs_share', 'file_clone' or 'none'.
          - For cluster-mode, the possible values for this option are a combination of 'lun_clone,file_clone' (for LUN clone and/or file clone),
            'lun_clone,sfsr' (for LUN clone and/or sfsr), 'vol_clone', 'cifs_share', or 'none'.
        type: str

  cutover_action:
    description:
      - Specifies the action to be taken for cutover.
      - Possible values are 'abort_on_failure', 'defer_on_failure', 'force' and 'wait'. Default is 'defer_on_failure'.
    choices: ['abort_on_failure', 'defer_on_failure', 'force', 'wait']
    type: str
    version_added: '20.5.0'

  check_interval:
    description:
      - The amount of time in seconds to wait between checks of a volume to see if it has moved successfully.
    default: 30
    type: int
    version_added: '20.6.0'

  from_vserver:
    description:
      - The source vserver of the volume is rehosted.
    type: str
    version_added: '20.6.0'

  auto_remap_luns:
    description:
      - Flag to control automatic map of LUNs.
    type: bool
    version_added: '20.6.0'

  force_unmap_luns:
    description:
      - Flag to control automatic unmap of LUNs.
    type: bool
    version_added: '20.6.0'

  force_restore:
    description:
      - If this field is set to "true", the Snapshot copy is restored even if the volume has one or more newer Snapshot
        copies which are currently used as reference Snapshot copy by SnapMirror. If a restore is done in this
        situation, this will cause future SnapMirror transfers to fail.
      - Option should only be used along with snapshot_restore.
    type: bool
    version_added: '20.6.0'

  preserve_lun_ids:
    description:
      - If this field is set to "true", LUNs in the volume being restored will remain mapped and their identities
        preserved such that host connectivity will not be disrupted during the restore operation. I/O's to the LUN will
        be fenced during the restore operation by placing the LUNs in an unavailable state. Once the restore operation
        has completed, hosts will be able to resume I/O access to the LUNs.
      - Option should only be used along with snapshot_restore.
    type: bool
    version_added: '20.6.0'

  snapshot_restore:
    description:
      - Name of snapshot to restore from.
      - Not supported on Infinite Volume.
    type: str
    version_added: '20.6.0'

  compression:
    description:
      - Whether to enable compression for the volume (HDD and Flash Pool aggregates).
      - If this option is not present, it is automatically set to true if inline_compression is true.
    type: bool
    version_added: '20.12.0'

  inline_compression:
    description:
      - Whether to enable inline compression for the volume (HDD and Flash Pool aggregates, AFF platforms).
    type: bool
    version_added: '20.12.0'

  tiering_minimum_cooling_days:
    description:
      - Determines how many days must pass before inactive data in a volume using the Auto or Snapshot-Only policy is
        considered cold and eligible for tiering.
      - This option is only supported in REST 9.8 or later.
    type: int
    version_added: '21.16.0'

  logical_space_enforcement:
    description:
      - This optionally specifies whether to perform logical space accounting on the volume. When space is enforced
        logically, ONTAP enforces volume settings such that all the physical space saved by the storage efficiency
        features will be calculated as used.
      - This is only supported with REST.
    type: bool
    version_added: '21.16.0'

  logical_space_reporting:
    description:
      - This optionally specifies whether to report space logically on the volume. When space is reported logically,
        ONTAP reports the volume space such that all the physical space saved by the storage efficiency features are also
        reported as used.
      - This is only supported with REST.
    type: bool
    version_added: '21.16.0'

  snaplock:
    description:
      - Starting with ONTAP 9.10.1, snaplock.type is set at the volume level.
      - The other suboptions can be set or modified when using REST on earlier versions of ONTAP.
      - These option and suboptions are only supported with REST.
    type: dict
    version_added: 21.18.0
    suboptions:
      append_mode_enabled:
        description:
          - when enabled, all the files created with write permissions on the volume are, by default,
            WORM appendable files. The user can append the data to a WORM appendable file but cannot modify
            the existing contents of the file nor delete the file until it expires.
        type: bool
      autocommit_period:
        description:
          - autocommit period for SnapLock volume. All files which are not modified for a period greater than
            the autocommit period of the volume are committed to the WORM state.
          - duration is in the ISO-8601 duration format (eg PY, PM, PD, PTH, PTM).
          - examples P30M, P10Y, PT1H, "none".  A duration that combines different periods is not supported.
        type: str
      privileged_delete:
        description:
          - privileged-delete attribute of a SnapLock volume.
          - On a SnapLock Enterprise (SLE) volume, a designated privileged user can selectively delete files irrespective of the retention time of the file.
          - On a SnapLock Compliance (SLC) volume, it is always permanently_disabled.
        type: str
        choices: [disabled, enabled, permanently_disabled]
      retention:
        description:
          - default, maximum, and minumum retention periods for files committed to the WORM state on the volume.
          - durations are in the ISO-8601 duration format, see autocommit_period.
        type: dict
        suboptions:
          default:
            description:
              - default retention period that is applied to files while committing them to the WORM state without an associated retention period.
            type: str
          maximum:
            description:
              - maximum allowed retention period for files committed to the WORM state on the volume.
            type: str
          minimum:
            description:
              - minimum allowed retention period for files committed to the WORM state on the volume.
            type: str
      type:
        description:
          - The SnapLock type of the volume.
          - compliance - A SnapLock Compliance (SLC) volume provides the highest level of WORM protection and
            an administrator cannot destroy a SLC volume if it contains unexpired WORM files.
          - enterprise - An administrator can delete a SnapLock Enterprise (SLE) volume.
          - non_snaplock - Indicates the volume is non-snaplock.
        type: str
        choices: [compliance, enterprise, non_snaplock]

  max_files:
    description:
      - The maximum number of files (inodes) for user-visible data allowed on the volume.
      - Note - ONTAP allocates a slightly different value, for instance 3990 when asking for 4000.
        Tp preserve idempotency, small variations in size are ignored.
    type: int
    version_added: '21.18.0'

  analytics:
    description:
      - Sets file system analytics state of the volume.
      - Only supported with REST and requires ONTAP 9.8 or later version.
      - Cannot enable analytics for volume that contains luns.
    type: str
    version_added: '22.0.0'
    choices: ['on', 'off']

  activity_tracking:
    description:
      - Sets activity tracking state of the volume.
      - Only supported with REST and requires ONTAP 9.10 or later version.
    type: str
    version_added: '22.12.0'
    choices: ['on', 'off']

  snapshot_locking:
    description:
      - Specifies whether or not snapshot copy locking is enabled on the volume.
      - Only supported with REST and requires ONTAP 9.12 or later.
    type: bool
    version_added: '22.12.0'

  granular_data:
    description:
      - State of granular data on the volume.
      - Only FlexGroup volumes support this feature. Once enabled, this setting can only be disabled by restoring a Snapshot copy.
      - Only supported with REST and requires ONTAP 9.12 or later.
    type: bool
    version_added: 22.13.0

  lambda_config:
    description:
      - Configuration parameters for AWS Lambda proxy functionality.
      - These option and suboptions are only supported with REST.
    type: dict
    version_added: 23.2.0
    suboptions:
      function_name:
        description:
          - The name of the AWS Lambda function to invoke.
        type: str
        required: true
      aws_region:
        description:
          - The name of the AWS region.
        type: str
        required: true
      aws_profile:
        description:
          - The name of the AWS profile to use for authentication.
        type: str

notes:
  - supports REST and ZAPI.  REST requires ONTAP 9.6 or later.  Efficiency with REST requires ONTAP 9.7 or later.
  - REST is enabled when C(use_rest) is set to always.
  - The feature_flag C(warn_or_fail_on_fabricpool_backend_change) controls whether an error is reported when
    tiering control would require or disallow FabricPool for an existing volume with a different backend.
    Allowed values are fail, warn, and ignore, and the default is set to fail.
  - snapshot_restore is not idempotent, it always restores.
  - Supports AWS Lambda proxy functionality when using REST.

'''

EXAMPLES = """
- name: Create FlexVol
  netapp.ontap.na_ontap_volume:
    state: present
    name: ansibleVolume12
    is_infinite: false
    aggregate_name: ansible_aggr
    size: 100
    size_unit: mb
    user_id: 1001
    group_id: 2002
    space_guarantee: none
    tiering_policy: auto
    export_policy: default
    percent_snapshot_space: 60
    qos_policy_group: max_performance_gold
    vserver: ansibleVServer
    wait_for_completion: true
    space_slo: none
    nvfail_enabled: false
    comment: ansible created volume
    tiering_object_tags: ['tag1=one', 'tag2=two', 'tag3=3', 'tag4=4']
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Volume Delete
  netapp.ontap.na_ontap_volume:
    state: absent
    name: ansibleVolume12
    aggregate_name: ansible_aggr
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Make FlexVol offline
  netapp.ontap.na_ontap_volume:
    state: present
    name: ansibleVolume
    is_infinite: false
    is_online: false
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Create Flexgroup volume manually
  netapp.ontap.na_ontap_volume:
    state: present
    name: ansibleVolume
    is_infinite: false
    aggr_list: "{{ aggr_list }}"
    aggr_list_multiplier: 2
    size: 200
    size_unit: mb
    space_guarantee: none
    export_policy: default
    vserver: "{{ vserver }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: false
    unix_permissions: 777
    snapshot_policy: default
    time_out: 0

- name: Create Flexgroup volume auto provsion as flex group
  netapp.ontap.na_ontap_volume:
    state: present
    name: ansibleVolume
    is_infinite: false
    auto_provision_as: flexgroup
    size: 200
    size_unit: mb
    space_guarantee: none
    export_policy: default
    vserver: "{{ vserver }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: false
    unix_permissions: 777
    snapshot_policy: default
    time_out: 0

- name: Create FlexVol with QoS adaptive
  netapp.ontap.na_ontap_volume:
    state: present
    name: ansibleVolume15
    is_infinite: false
    aggregate_name: ansible_aggr
    size: 100
    size_unit: gb
    space_guarantee: none
    export_policy: default
    percent_snapshot_space: 10
    qos_adaptive_policy_group: extreme
    vserver: ansibleVServer
    wait_for_completion: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify volume dr protection (vserver of the volume must be in a snapmirror relationship)
  netapp.ontap.na_ontap_volume:
    state: present
    name: ansibleVolume
    vserver_dr_protection: protected
    vserver: "{{ vserver }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: false

- name: Modify volume with snapshot auto delete options
  netapp.ontap.na_ontap_volume:
    state: present
    name: vol_auto_delete
    snapshot_auto_delete:
      state: "on"
      commitment: try
      defer_delete: scheduled
      target_free_space: 30
      destroy_list: lun_clone,vol_clone
      delete_order: newest_first
    aggregate_name: "{{ aggr }}"
    vserver: "{{ vserver }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: false

- name: Move volume with force cutover action
  netapp.ontap.na_ontap_volume:
    name: ansible_vol
    aggregate_name: aggr_ansible
    cutover_action: force
    vserver: "{{ vserver }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: false

- name: Rehost volume to another vserver auto remap luns
  netapp.ontap.na_ontap_volume:
    name: ansible_vol
    from_vserver: ansible
    auto_remap_luns: true
    vserver: "{{ vserver }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: false

- name: Rehost volume to another vserver force unmap luns
  netapp.ontap.na_ontap_volume:
    name: ansible_vol
    from_vserver: ansible
    force_unmap_luns: true
    vserver: "{{ vserver }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: false

- name: Snapshot restore volume
  netapp.ontap.na_ontap_volume:
    name: ansible_vol
    vserver: ansible
    snapshot_restore: 2020-05-24-weekly
    force_restore: true
    preserve_lun_ids: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false

- name: Volume create using application/applications nas template
  netapp.ontap.na_ontap_volume:
    state: present
    name: ansibleVolume12
    vserver: ansibleSVM
    size: 100000000
    size_unit: b
    space_guarantee: none
    language: es
    percent_snapshot_space: 60
    unix_permissions: ---rwxrwxrwx
    snapshot_policy: default
    efficiency_policy: default
    comment: testing
    nas_application_template:
      nfs_access:   # the mere presence of a suboption is enough to enable this new feature
        - access: ro
        - access: rw
          host: 10.0.0.0/8
      exclude_aggregates: aggr0
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false

# requires Ontap collection version - 21.24.0 to use iso filter plugin.
- name: volume create with snaplock set.
  netapp.ontap.na_ontap_volume:
    state: present
    name: "{{ snaplock_volume }}"
    aggregate_name: "{{ aggregate }}"
    size: 20
    size_unit: mb
    space_guarantee: none
    policy: default
    type: rw
    snaplock:
      type: enterprise
      retention:
        default: "{{ 60 | netapp.ontap.iso8601_duration_from_seconds }}"

- name: Create volume with snapshot-auto-delete options - REST
  netapp.ontap.na_ontap_volume:
    state: present
    name: test_vol
    aggregate_name: "{{ aggr }}"
    size: 20
    size_unit: mb
    snapshot_auto_delete:
      state: 'on'
      trigger: volume
      delete_order: "oldest_first"
      defer_delete: "user_created"
      commitment: "try"
      target_free_space: 30
      prefix: "my_prefix"
    wait_for_completion: true

- name: Modify volume - REST
  netapp.ontap.na_ontap_volume:
    state: present
    name: test_vol
    aggregate_name: "{{ aggr }}"
    snapdir_access: false
    snapshot_auto_delete:
      state: 'on'
      target_free_space: 25

- name: Modify volume tiering onject_tags - REST
  netapp.ontap.na_ontap_volume:
    state: present
    name: test_vol
    aggregate_name: "{{ aggr }}"
    tiering_object_tags: ['tag1=one', 'tag2=two']
"""

RETURN = """
"""

import time
import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.rest_application import RestApplication
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic
from ansible_collections.netapp.ontap.plugins.module_utils import rest_vserver


class NetAppOntapVolume:
    '''Class with volume operations'''

    def __init__(self):
        '''Initialize module parameters'''
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            vserver=dict(required=True, type='str'),
            from_name=dict(required=False, type='str'),
            is_infinite=dict(required=False, type='bool', default=False),
            is_online=dict(required=False, type='bool', default=True),
            size=dict(type='int', default=None),
            size_unit=dict(default='gb', choices=['bytes', 'b', 'kb', 'mb', 'gb', 'tb', 'pb', 'eb', 'zb', 'yb'], type='str'),
            sizing_method=dict(choices=['add_new_resources', 'use_existing_resources'], type='str'),
            aggregate_name=dict(type='str', default=None),
            type=dict(type='str', default=None),
            export_policy=dict(type='str', default=None, aliases=['policy']),
            junction_path=dict(type='str', default=None),
            space_guarantee=dict(choices=['none', 'file', 'volume'], default=None),
            percent_snapshot_space=dict(type='int', default=None),
            volume_security_style=dict(choices=['mixed', 'ntfs', 'unified', 'unix']),
            encrypt=dict(required=False, type='bool'),
            efficiency_policy=dict(required=False, type='str'),
            unix_permissions=dict(required=False, type='str'),
            group_id=dict(required=False, type='int'),
            user_id=dict(required=False, type='int'),
            snapshot_policy=dict(required=False, type='str'),
            aggr_list=dict(required=False, type='list', elements='str'),
            aggr_list_multiplier=dict(required=False, type='int'),
            snapdir_access=dict(required=False, type='bool'),
            atime_update=dict(required=False, type='bool'),
            vol_nearly_full_threshold_percent=dict(required=False, type='int'),
            vol_full_threshold_percent=dict(required=False, type='int'),
            large_size_enabled=dict(required=False, type='bool'),
            auto_provision_as=dict(choices=['flexgroup'], required=False, type='str'),
            wait_for_completion=dict(required=False, type='bool', default=False),
            time_out=dict(required=False, type='int', default=180),
            max_wait_time=dict(required=False, type='int', default=600),
            language=dict(type='str', required=False),
            qos_policy_group=dict(required=False, type='str'),
            qos_adaptive_policy_group=dict(required=False, type='str'),
            nvfail_enabled=dict(type='bool', required=False),
            space_slo=dict(type='str', required=False, choices=['none', 'thick', 'semi-thick']),
            tiering_policy=dict(type='str', required=False, choices=['snapshot-only', 'auto', 'backup', 'none', 'all']),
            tiering_object_tags=dict(type='list', elements='str', required=False),
            vserver_dr_protection=dict(type='str', required=False, choices=['protected', 'unprotected']),
            comment=dict(type='str', required=False),
            snapshot_auto_delete=dict(type='dict', required=False),
            cutover_action=dict(required=False, type='str', choices=['abort_on_failure', 'defer_on_failure', 'force', 'wait']),
            check_interval=dict(required=False, type='int', default=30),
            from_vserver=dict(required=False, type='str'),
            auto_remap_luns=dict(required=False, type='bool'),
            force_unmap_luns=dict(required=False, type='bool'),
            force_restore=dict(required=False, type='bool'),
            compression=dict(required=False, type='bool'),
            inline_compression=dict(required=False, type='bool'),
            preserve_lun_ids=dict(required=False, type='bool'),
            snapshot_restore=dict(required=False, type='str'),
            nas_application_template=dict(type='dict', options=dict(
                use_nas_application=dict(type='bool', default=True),
                exclude_aggregates=dict(type='list', elements='str'),
                flexcache=dict(type='dict', options=dict(
                    dr_cache=dict(type='bool'),
                    origin_svm_name=dict(required=True, type='str'),
                    origin_component_name=dict(required=True, type='str')
                )),
                cifs_access=dict(type='list', elements='dict', options=dict(
                    access=dict(type='str', choices=['change', 'full_control', 'no_access', 'read']),
                    user_or_group=dict(type='str')
                )),
                nfs_access=dict(type='list', elements='dict', options=dict(
                    access=dict(type='str', choices=['none', 'ro', 'rw']),
                    host=dict(type='str')
                )),
                storage_service=dict(type='str', choices=['value', 'performance', 'extreme']),
                tiering=dict(type='dict', options=dict(
                    control=dict(type='str', choices=['required', 'best_effort', 'disallowed']),
                    policy=dict(type='str', choices=['all', 'auto', 'none', 'snapshot-only']),
                    object_stores=dict(type='list', elements='str')     # create only
                )),
                cifs_share_name=dict(required=False, type='str'),
                snapshot_locking_enabled=dict(required=False, type='bool'),
                snaplock=dict(type='dict', options=dict(
                    append_mode_enabled=dict(required=False, type='bool'),
                    autocommit_period=dict(required=False, type='str'),
                    retention=dict(type='dict', options=dict(
                        default=dict(required=False, type='str'),
                        maximum=dict(required=False, type='str'),
                        minimum=dict(required=False, type='str')
                    )),
                    snaplock_type=dict(required=False, type='str', choices=['compliance', 'enterprise', 'non_snaplock'])
                )),
            )),
            size_change_threshold=dict(type='int', default=10),
            tiering_minimum_cooling_days=dict(required=False, type='int'),
            logical_space_enforcement=dict(required=False, type='bool'),
            logical_space_reporting=dict(required=False, type='bool'),
            snaplock=dict(type='dict', options=dict(
                append_mode_enabled=dict(required=False, type='bool'),
                autocommit_period=dict(required=False, type='str'),
                privileged_delete=dict(required=False, type='str', choices=['disabled', 'enabled', 'permanently_disabled']),
                retention=dict(type='dict', options=dict(
                    default=dict(required=False, type='str'),
                    maximum=dict(required=False, type='str'),
                    minimum=dict(required=False, type='str')
                )),
                type=dict(required=False, type='str', choices=['compliance', 'enterprise', 'non_snaplock'])
            )),
            max_files=dict(required=False, type='int'),
            analytics=dict(required=False, type='str', choices=['on', 'off']),
            activity_tracking=dict(required=False, type='str', choices=['on', 'off']),
            tags=dict(required=False, type='list', elements='str'),
            snapshot_locking=dict(required=False, type='bool'),
            granular_data=dict(required=False, type='bool'),
        ))
        self.argument_spec.update(netapp_utils.na_ontap_lambda_argument_spec())
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            mutually_exclusive=[
                ['space_guarantee', 'space_slo'], ['auto_remap_luns', 'force_unmap_luns']
            ],
            required_if=[
                ['use_lambda', True, ('lambda_config',)]
            ],
            supports_check_mode=True
        )
        self.na_helper = NetAppModule(self)
        self.parameters = self.na_helper.check_and_set_parameters(self.module)
        self.volume_style = None
        self.volume_created = False
        self.issues = []
        self.sis_keys2zapi_get = dict(
            efficiency_policy='policy',
            compression='is-compression-enabled',
            inline_compression='is-inline-compression-enabled')
        self.sis_keys2zapi_set = dict(
            efficiency_policy='policy-name',
            compression='enable-compression',
            inline_compression='enable-inline-compression')

        if self.parameters.get('size'):
            self.parameters['size'] = self.parameters['size'] * \
                netapp_utils.POW2_BYTE_MAP[self.parameters['size_unit']]
        self.validate_snapshot_auto_delete()
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        unsupported_rest_properties = ['cutover_action',
                                       'encrypt-destination',
                                       'force_restore',
                                       'nvfail_enabled',
                                       'preserve_lun_ids',
                                       'destroy_list',
                                       'space_slo',
                                       'vserver_dr_protection']
        partially_supported_rest_properties = [['efficiency_policy', (9, 7)], ['tiering_minimum_cooling_days', (9, 8)],
                                               ['analytics', (9, 8)], ['atime_update', (9, 8)], ['tiering_object_tags', (9, 8)],
                                               ['vol_nearly_full_threshold_percent', (9, 9)], ['vol_full_threshold_percent', (9, 9)],
                                               ['activity_tracking', (9, 10, 1)], ['snapshot_locking', (9, 12, 1)],
                                               ['granular_data', (9, 12, 1)], ['large_size_enabled', (9, 12, 1)],
                                               ['tags', (9, 13, 1)], ['snapdir_access', (9, 13, 1)], ['snapshot_auto_delete', (9, 13, 1)]]
        self.unsupported_zapi_properties = ['sizing_method', 'logical_space_enforcement', 'logical_space_reporting', 'snaplock',
                                            'analytics', 'activity_tracking', 'tags', 'vol_nearly_full_threshold_percent',
                                            'vol_full_threshold_percent', 'large_size_enabled', 'snapshot_locking', 'granular_data', 'tiering_object_tags']
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, unsupported_rest_properties, partially_supported_rest_properties)

        if not self.use_rest:
            if self.parameters.get('use_lambda'):
                self.module.fail_json(msg="Error: AWS Lambda proxy for ONTAP APIs is only supported with REST.")
            self.setup_zapi()
        if self.use_rest:
            self.rest_errors()

        # REST API for application/applications if needed - will report an error when REST is not supported
        self.rest_app = self.setup_rest_application()

    def setup_zapi(self):
        if netapp_utils.has_netapp_lib() is False:
            self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())

        for unsupported_zapi_property in self.unsupported_zapi_properties:
            if self.parameters.get(unsupported_zapi_property) is not None:
                msg = "Error: %s option is not supported with ZAPI.  It can only be used with REST." % unsupported_zapi_property
                msg += '  use_rest: %s.' % self.parameters['use_rest']
                if self.rest_api.fallback_to_zapi_reason:
                    msg += '  Conflict %s.' % self.rest_api.fallback_to_zapi_reason
                self.module.fail_json(msg=msg)
        self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])
        self.cluster = netapp_utils.setup_na_ontap_zapi(module=self.module)

    def validate_snapshot_auto_delete(self):
        if 'snapshot_auto_delete' in self.parameters:
            for key in self.parameters['snapshot_auto_delete']:
                if key not in ['commitment', 'trigger', 'target_free_space', 'delete_order', 'defer_delete',
                               'prefix', 'destroy_list', 'state']:
                    self.module.fail_json(msg="snapshot_auto_delete option '%s' is not valid." % key)

    def setup_rest_application(self):
        rest_app = None
        if self.na_helper.safe_get(self.parameters, ['nas_application_template', 'use_nas_application']):
            if not self.use_rest:
                msg = 'Error: nas_application_template requires REST support.'
                msg += '  use_rest: %s.' % self.parameters['use_rest']
                if self.rest_api.fallback_to_zapi_reason:
                    msg += '  Conflict %s.' % self.rest_api.fallback_to_zapi_reason
                self.module.fail_json(msg=msg)
            # consistency checks
            # tiering policy is duplicated, make sure values are matching
            tiering_policy_nas = self.na_helper.safe_get(self.parameters, ['nas_application_template', 'tiering', 'policy'])
            tiering_policy = self.na_helper.safe_get(self.parameters, ['tiering_policy'])
            if tiering_policy_nas is not None and tiering_policy is not None and tiering_policy_nas != tiering_policy:
                msg = 'Conflict: if tiering_policy and nas_application_template tiering policy are both set, they must match.'
                msg += '  Found "%s" and "%s".' % (tiering_policy, tiering_policy_nas)
                self.module.fail_json(msg=msg)
            # aggregate_name will force a move if present
            if self.parameters.get('aggregate_name') is not None:
                msg = 'Conflict: aggregate_name is not supported when application template is enabled.'\
                      '  Found: aggregate_name: %s' % self.parameters['aggregate_name']
                self.module.fail_json(msg=msg)
            nfs_access = self.na_helper.safe_get(self.parameters, ['nas_application_template', 'nfs_access'])
            if nfs_access is not None and self.na_helper.safe_get(self.parameters, ['export_policy']) is not None:
                msg = 'Conflict: export_policy option and nfs_access suboption in nas_application_template are mutually exclusive.'
                self.module.fail_json(msg=msg)
            rest_app = RestApplication(self.rest_api, self.parameters['vserver'], self.parameters['name'])
        return rest_app

    def volume_get_iter(self, vol_name=None):
        """
        Return volume-get-iter query results
        :param vol_name: name of the volume
        :return: NaElement
        """
        volume_info = netapp_utils.zapi.NaElement('volume-get-iter')
        volume_attributes = netapp_utils.zapi.NaElement('volume-attributes')
        volume_id_attributes = netapp_utils.zapi.NaElement('volume-id-attributes')
        volume_id_attributes.add_new_child('name', vol_name)
        volume_id_attributes.add_new_child('vserver', self.parameters['vserver'])
        volume_attributes.add_child_elem(volume_id_attributes)
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(volume_attributes)
        volume_info.add_child_elem(query)

        try:
            result = self.server.invoke_successfully(volume_info, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching volume %s : %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        return result

    def get_application(self, template):
        if self.rest_app:
            app, error = self.rest_app.get_application_details(template=template)
            self.na_helper.fail_on_error(error)
            # flatten component list
            comps = self.na_helper.safe_get(app, [template, 'application_components'])
            if comps:
                comp = comps[0]
                app[template].pop('application_components')
                app[template].update(comp)
                return app[template]
        return None

    def get_volume_attributes(self, volume_attributes, result):
        # extract values from volume record
        attrs = dict(
            # The keys are used to index a result dictionary, values are read from a ZAPI object indexed by key_list.
            # If required is True, an error is reported if a key in key_list is not found.
            # We may have observed cases where the record is incomplete as the volume is being created, so it may be better to ignore missing keys
            # I'm not sure there is much value in omitnone, but it preserves backward compatibility
            # If omitnone is absent or False, a None value is recorded, if True, the key is not set
            encrypt=dict(key_list=['encrypt'], convert_to=bool, omitnone=True),
            tiering_policy=dict(key_list=['volume-comp-aggr-attributes', 'tiering-policy'], omitnone=True),
            export_policy=dict(key_list=['volume-export-attributes', 'policy']),
            aggregate_name=dict(key_list=['volume-id-attributes', 'containing-aggregate-name']),
            flexgroup_uuid=dict(key_list=['volume-id-attributes', 'flexgroup-uuid']),
            instance_uuid=dict(key_list=['volume-id-attributes', 'instance-uuid']),
            junction_path=dict(key_list=['volume-id-attributes', 'junction-path'], default=''),
            style_extended=dict(key_list=['volume-id-attributes', 'style-extended']),
            type=dict(key_list=['volume-id-attributes', 'type'], omitnone=True),
            comment=dict(key_list=['volume-id-attributes', 'comment']),
            max_files=dict(key_list=['volume-inode-attributes', 'files-total'], convert_to=int),
            atime_update=dict(key_list=['volume-performance-attributes', 'is-atime-update-enabled'], convert_to=bool),
            qos_policy_group=dict(key_list=['volume-qos-attributes', 'policy-group-name']),
            qos_adaptive_policy_group=dict(key_list=['volume-qos-attributes', 'adaptive-policy-group-name']),
            # style is not present if the volume is still offline or of type: dp
            volume_security_style=dict(key_list=['volume-security-attributes', 'style'], omitnone=True),
            group_id=dict(key_list=['volume-security-attributes', 'volume-security-unix-attributes', 'group-id'], convert_to=int, omitnone=True),
            unix_permissions=dict(key_list=['volume-security-attributes', 'volume-security-unix-attributes', 'permissions'], required=True),
            user_id=dict(key_list=['volume-security-attributes', 'volume-security-unix-attributes', 'user-id'], convert_to=int, omitnone=True),
            snapdir_access=dict(key_list=['volume-snapshot-attributes', 'snapdir-access-enabled'], convert_to=bool),
            snapshot_policy=dict(key_list=['volume-snapshot-attributes', 'snapshot-policy'], omitnone=True),
            percent_snapshot_space=dict(key_list=['volume-space-attributes', 'percentage-snapshot-reserve'], convert_to=int, omitnone=True),
            size=dict(key_list=['volume-space-attributes', 'size'], convert_to=int),
            space_guarantee=dict(key_list=['volume-space-attributes', 'space-guarantee']),
            space_slo=dict(key_list=['volume-space-attributes', 'space-slo']),
            nvfail_enabled=dict(key_list=['volume-state-attributes', 'is-nvfail-enabled'], convert_to=bool),
            is_online=dict(key_list=['volume-state-attributes', 'state'], convert_to='bool_online', omitnone=True),
            vserver_dr_protection=dict(key_list=['volume-vserver-dr-protection-attributes', 'vserver-dr-protection']),
        )

        self.na_helper.zapi_get_attrs(volume_attributes, attrs, result)

    def get_snapshot_auto_delete_attributes(self, volume_attributes, result):
        attrs = dict(
            commitment=dict(key_list=['volume-snapshot-autodelete-attributes', 'commitment']),
            defer_delete=dict(key_list=['volume-snapshot-autodelete-attributes', 'defer-delete']),
            delete_order=dict(key_list=['volume-snapshot-autodelete-attributes', 'delete-order']),
            destroy_list=dict(key_list=['volume-snapshot-autodelete-attributes', 'destroy-list']),
            is_autodelete_enabled=dict(key_list=['volume-snapshot-autodelete-attributes', 'is-autodelete-enabled'], convert_to=bool),
            prefix=dict(key_list=['volume-snapshot-autodelete-attributes', 'prefix']),
            target_free_space=dict(key_list=['volume-snapshot-autodelete-attributes', 'target-free-space'], convert_to=int),
            trigger=dict(key_list=['volume-snapshot-autodelete-attributes', 'trigger']),
        )
        self.na_helper.zapi_get_attrs(volume_attributes, attrs, result)
        if result['is_autodelete_enabled'] is not None:
            result['state'] = 'on' if result['is_autodelete_enabled'] else 'off'
            del result['is_autodelete_enabled']

    def get_volume(self, vol_name=None):
        """
        Return details about the volume
        :param:
            name : Name of the volume
        :return: Details about the volume. None if not found.
        :rtype: dict
        """
        result = None
        if vol_name is None:
            vol_name = self.parameters['name']
        if self.use_rest:
            return self.get_volume_rest(vol_name)
        volume_info = self.volume_get_iter(vol_name)
        if self.na_helper.zapi_get_value(volume_info, ['num-records'], convert_to=int, default=0) > 0:
            result = self.get_volume_record_from_zapi(volume_info, vol_name)
        return result

    def get_volume_record_from_zapi(self, volume_info, vol_name):
        volume_attributes = self.na_helper.zapi_get_value(volume_info, ['attributes-list', 'volume-attributes'], required=True)
        result = dict(name=vol_name)
        self.get_volume_attributes(volume_attributes, result)
        result['uuid'] = (result['instance_uuid'] if result['style_extended'] == 'flexvol'
                          else result['flexgroup_uuid'] if result['style_extended'] is not None and result['style_extended'].startswith('flexgroup')
                          else None)

        # snapshot_auto_delete options
        auto_delete = {}
        self. get_snapshot_auto_delete_attributes(volume_attributes, auto_delete)
        result['snapshot_auto_delete'] = auto_delete

        self.get_efficiency_info(result)

        return result

    def wrap_fail_json(self, msg, exception=None):
        for issue in self.issues:
            self.module.warn(issue)
        if self.volume_created:
            msg = 'Volume created with success, with missing attributes: %s' % msg
        self.module.fail_json(msg=msg, exception=exception)

    def create_nas_application_component(self):
        '''Create application component for nas template'''
        required_options = ('name', 'size')
        for option in required_options:
            if self.parameters.get(option) is None:
                self.module.fail_json(msg='Error: "%s" is required to create nas application.' % option)

        application_component = dict(
            name=self.parameters['name'],
            total_size=self.parameters['size'],
            share_count=1,      # 1 is the maximum value for nas
            scale_out=(self.volume_style == 'flexgroup'),
        )
        name = self.na_helper.safe_get(self.parameters, ['nas_application_template', 'storage_service'])
        if name is not None:
            application_component['storage_service'] = dict(name=name)

        flexcache = self.na_helper.safe_get(self.parameters, ['nas_application_template', 'flexcache'])
        if flexcache is not None:
            application_component['flexcache'] = dict(
                origin=dict(
                    svm=dict(name=flexcache['origin_svm_name']),
                    component=dict(name=flexcache['origin_component_name'])
                )
            )
            # scale_out should be absent or set to True for FlexCache
            del application_component['scale_out']
            dr_cache = self.na_helper.safe_get(self.parameters, ['nas_application_template', 'flexcache', 'dr_cache'])
            if dr_cache is not None:
                application_component['flexcache']['dr_cache'] = dr_cache

        tiering = self.na_helper.safe_get(self.parameters, ['nas_application_template', 'tiering'])
        if tiering is not None or self.parameters.get('tiering_policy') is not None:
            application_component['tiering'] = {}
            if tiering is None:
                tiering = {}
            if 'policy' not in tiering:
                tiering['policy'] = self.parameters.get('tiering_policy')
            for attr in ('control', 'policy', 'object_stores'):
                value = tiering.get(attr)
                if attr == 'object_stores' and value is not None:
                    value = [dict(name=x) for x in value]
                if value is not None:
                    application_component['tiering'][attr] = value

        snapshot_locking_enabled = self.na_helper.safe_get(self.parameters, ['nas_application_template', 'snapshot_locking_enabled'])
        if snapshot_locking_enabled is not None:
            application_component['snapshot_locking_enabled'] = snapshot_locking_enabled

        snaplock = self.na_helper.safe_get(self.parameters, ['nas_application_template', 'snaplock'])
        if snaplock is not None:
            value = self.na_helper.filter_out_none_entries(snaplock)
            if value:
                application_component['snaplock'] = value

        if self.get_qos_policy_group() is not None:
            application_component['qos'] = {
                "policy": {
                    "name": self.get_qos_policy_group(),
                }
            }
        if self.parameters.get('export_policy') is not None:
            application_component['export_policy'] = {
                "name": self.parameters['export_policy'],
            }
        return application_component

    def create_volume_body(self):
        '''Create body for application template'''
        if self.parameters.get('nas_application_template') is not None:
            nas = dict(application_components=[self.create_nas_application_component()])
            value = self.na_helper.safe_get(self.parameters, ['snapshot_policy'])
            if value is not None:
                nas['protection_type'] = {'local_policy': value}
            for attr in ('nfs_access', 'cifs_access'):
                value = self.na_helper.safe_get(self.parameters, ['nas_application_template', attr])
                if value is not None:
                    # we expect value to be a list of dicts, with maybe some empty entries
                    value = self.na_helper.filter_out_none_entries(value)
                    if value:
                        nas[attr] = value
            for attr in ('exclude_aggregates',):
                values = self.na_helper.safe_get(self.parameters, ['nas_application_template', attr])
                if values:
                    nas[attr] = [dict(name=name) for name in values]
            for attr in ('cifs_share_name',):
                value = self.na_helper.safe_get(self.parameters, ['nas_application_template', attr])
                if value is not None:
                    nas[attr] = value
            return self.rest_app.create_application_body("nas", nas, smart_container=True)

    def create_application_template(self):
        '''Use REST application/applications template to create a volume'''
        body, error = self.create_volume_body()
        self.na_helper.fail_on_error(error)
        response, error = self.rest_app.create_application(body)
        self.na_helper.fail_on_error(error)
        return response

    def wait_for_volume_online(self, sleep_time=10):
        # round off time_out
        retries = (self.parameters['time_out'] + 5) // 10
        is_online = None
        errors = []
        while not is_online and retries > 0:
            try:
                current = self.get_volume()
                is_online = None if current is None else current['is_online']
            except KeyError as err:
                # get_volume may receive incomplete data as the volume is being created
                errors.append(repr(err))
            if not is_online:
                time.sleep(sleep_time)
            retries -= 1
        if not is_online:
            errors.append("Timeout after %s seconds" % self.parameters['time_out'])
            self.module.fail_json(msg='Error waiting for volume %s to come online: %s' % (self.parameters['name'], str(errors)))

    def create_volume(self):
        '''Create ONTAP volume'''
        if self.rest_app:
            return self.create_application_template()
        if self.use_rest:
            return self.create_volume_rest()
        if self.volume_style == 'flexgroup':
            return self.create_volume_async()

        options = self.create_volume_options()
        volume_create = netapp_utils.zapi.NaElement.create_node_with_children('volume-create', **options)
        try:
            self.server.invoke_successfully(volume_create, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            size_msg = ' of size %s' % self.parameters['size'] if self.parameters.get('size') is not None else ''
            self.module.fail_json(msg='Error provisioning volume %s%s: %s'
                                  % (self.parameters['name'], size_msg, to_native(error)),
                                  exception=traceback.format_exc())

        if self.parameters.get('wait_for_completion'):
            self.wait_for_volume_online()
        return None

    def create_volume_async(self):
        '''
        create volume async.
        '''
        options = self.create_volume_options()
        volume_create = netapp_utils.zapi.NaElement.create_node_with_children('volume-create-async', **options)
        if self.parameters.get('aggr_list'):
            aggr_list_obj = netapp_utils.zapi.NaElement('aggr-list')
            volume_create.add_child_elem(aggr_list_obj)
            for aggr in self.parameters['aggr_list']:
                aggr_list_obj.add_new_child('aggr-name', aggr)
        try:
            result = self.server.invoke_successfully(volume_create, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            size_msg = ' of size %s' % self.parameters['size'] if self.parameters.get('size') is not None else ''
            self.module.fail_json(msg='Error provisioning volume %s%s: %s'
                                  % (self.parameters['name'], size_msg, to_native(error)),
                                  exception=traceback.format_exc())
        self.check_invoke_result(result, 'create')
        return None

    def create_volume_options(self):
        '''Set volume options for create operation'''
        options = {}
        if self.volume_style == 'flexgroup':
            options['volume-name'] = self.parameters['name']
            if self.parameters.get('aggr_list_multiplier') is not None:
                options['aggr-list-multiplier'] = str(self.parameters['aggr_list_multiplier'])
            if self.parameters.get('auto_provision_as') is not None:
                options['auto-provision-as'] = self.parameters['auto_provision_as']
            if self.parameters.get('space_guarantee') is not None:
                options['space-guarantee'] = self.parameters['space_guarantee']
        else:
            options['volume'] = self.parameters['name']
            if self.parameters.get('aggregate_name') is None:
                self.module.fail_json(msg='Error provisioning volume %s: aggregate_name is required'
                                      % self.parameters['name'])
            options['containing-aggr-name'] = self.parameters['aggregate_name']
            if self.parameters.get('space_guarantee') is not None:
                options['space-reserve'] = self.parameters['space_guarantee']

        if self.parameters.get('size') is not None:
            options['size'] = str(self.parameters['size'])
        if self.parameters.get('snapshot_policy') is not None:
            options['snapshot-policy'] = self.parameters['snapshot_policy']
        if self.parameters.get('unix_permissions') is not None:
            options['unix-permissions'] = self.parameters['unix_permissions']
        if self.parameters.get('group_id') is not None:
            options['group-id'] = str(self.parameters['group_id'])
        if self.parameters.get('user_id') is not None:
            options['user-id'] = str(self.parameters['user_id'])
        if self.parameters.get('volume_security_style') is not None:
            options['volume-security-style'] = self.parameters['volume_security_style']
        if self.parameters.get('export_policy') is not None:
            options['export-policy'] = self.parameters['export_policy']
        if self.parameters.get('junction_path') is not None:
            options['junction-path'] = self.parameters['junction_path']
        if self.parameters.get('comment') is not None:
            options['volume-comment'] = self.parameters['comment']
        if self.parameters.get('type') is not None:
            options['volume-type'] = self.parameters['type']
        if self.parameters.get('percent_snapshot_space') is not None:
            options['percentage-snapshot-reserve'] = str(self.parameters['percent_snapshot_space'])
        if self.parameters.get('language') is not None:
            options['language-code'] = self.parameters['language']
        if self.parameters.get('qos_policy_group') is not None:
            options['qos-policy-group-name'] = self.parameters['qos_policy_group']
        if self.parameters.get('qos_adaptive_policy_group') is not None:
            options['qos-adaptive-policy-group-name'] = self.parameters['qos_adaptive_policy_group']
        if self.parameters.get('nvfail_enabled') is not None:
            options['is-nvfail-enabled'] = str(self.parameters['nvfail_enabled'])
        if self.parameters.get('space_slo') is not None:
            options['space-slo'] = self.parameters['space_slo']
        if self.parameters.get('tiering_policy') is not None:
            options['tiering-policy'] = self.parameters['tiering_policy']
        if self.parameters.get('encrypt') is not None:
            options['encrypt'] = self.na_helper.get_value_for_bool(False, self.parameters['encrypt'], 'encrypt')
        if self.parameters.get('vserver_dr_protection') is not None:
            options['vserver-dr-protection'] = self.parameters['vserver_dr_protection']
        if self.parameters['is_online']:
            options['volume-state'] = 'online'
        else:
            options['volume-state'] = 'offline'
        return options

    def rest_delete_volume(self, current):
        """
        Delete the volume using REST DELETE method (it scrubs better than ZAPI).
        """
        uuid = self.parameters['uuid']
        if uuid is None:
            self.module.fail_json(msg='Could not read UUID for volume %s in delete.' % self.parameters['name'])
        unmount_error = self.volume_unmount_rest(fail_on_error=False) if current.get('junction_path') else None
        dummy, error = rest_generic.delete_async(self.rest_api, 'storage/volumes', uuid, job_timeout=self.parameters['time_out'])
        self.na_helper.fail_on_error(error, previous_errors=(['Error unmounting volume: %s' % unmount_error] if unmount_error else None))
        if unmount_error:
            self.module.warn('Volume was successfully deleted though unmount failed with: %s' % unmount_error)

    def delete_volume_async(self, current):
        '''Delete ONTAP volume for infinite or flexgroup types '''
        errors = None
        if current['is_online']:
            dummy, errors = self.change_volume_state(call_from_delete_vol=True)
        volume_delete = netapp_utils.zapi.NaElement.create_node_with_children(
            'volume-destroy-async', **{'volume-name': self.parameters['name']})
        try:
            result = self.server.invoke_successfully(volume_delete, enable_tunneling=True)
            self.check_invoke_result(result, 'delete')
        except netapp_utils.zapi.NaApiError as error:
            msg = 'Error deleting volume %s: %s.' % (self.parameters['name'], to_native(error))
            if errors:
                msg += '  Previous errors when offlining/unmounting volume: %s' % ' - '.join(errors)
            self.module.fail_json(msg=msg)

    def delete_volume_sync(self, current, unmount_offline):
        '''Delete ONTAP volume for flexvol types '''
        options = {'name': self.parameters['name']}
        if unmount_offline:
            options['unmount-and-offline'] = 'true'
        volume_delete = netapp_utils.zapi.NaElement.create_node_with_children(
            'volume-destroy', **options)
        try:
            self.server.invoke_successfully(volume_delete, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            return error
        return None

    def delete_volume(self, current):
        '''Delete ONTAP volume'''
        if self.use_rest and self.parameters['uuid'] is not None:
            return self.rest_delete_volume(current)
        if self.parameters.get('is_infinite') or self.volume_style == 'flexgroup':
            return self.delete_volume_async(current)
        errors = []
        error = self.delete_volume_sync(current, True)
        if error:
            errors.append('volume delete failed with unmount-and-offline option: %s' % to_native(error))
            error = self.delete_volume_sync(current, False)
        if error:
            errors.append('volume delete failed without unmount-and-offline option: %s' % to_native(error))
        if errors:
            self.module.fail_json(msg='Error deleting volume %s: %s'
                                  % (self.parameters['name'], ' - '.join(errors)),
                                  exception=traceback.format_exc())

    def move_volume(self, encrypt_destination=None):
        '''Move volume from source aggregate to destination aggregate'''
        if self.use_rest:
            return self.move_volume_rest(encrypt_destination)
        volume_move = netapp_utils.zapi.NaElement.create_node_with_children(
            'volume-move-start', **{'source-volume': self.parameters['name'],
                                    'vserver': self.parameters['vserver'],
                                    'dest-aggr': self.parameters['aggregate_name']})
        if self.parameters.get('cutover_action'):
            volume_move.add_new_child('cutover-action', self.parameters['cutover_action'])
        if encrypt_destination is not None:
            volume_move.add_new_child('encrypt-destination', self.na_helper.get_value_for_bool(False, encrypt_destination))
        try:
            self.cluster.invoke_successfully(volume_move,
                                             enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            rest_error = self.move_volume_with_rest_passthrough(encrypt_destination)
            if rest_error is not None:
                self.module.fail_json(msg='Error moving volume %s: %s -  Retry failed with REST error: %s'
                                      % (self.parameters['name'], to_native(error), rest_error),
                                      exception=traceback.format_exc())
        if self.parameters.get('wait_for_completion'):
            self.wait_for_volume_move()

    def move_volume_with_rest_passthrough(self, encrypt_destination=None):
        # MDV volume will fail on a move, but will work using the REST CLI pass through
        # vol move start -volume MDV_CRS_d6b0b313ff5611e9837100a098544e51_A -destination-aggregate data_a3 -vserver wmc66-a
        # if REST isn't available fail with the original error
        if not self.use_rest:
            return False
        # if REST exists let's try moving using the passthrough CLI
        api = 'private/cli/volume/move/start'
        body = {'destination-aggregate': self.parameters['aggregate_name'],
                }
        if encrypt_destination is not None:
            body['encrypt-destination'] = encrypt_destination
        query = {'volume': self.parameters['name'],
                 'vserver': self.parameters['vserver']
                 }
        dummy, error = self.rest_api.patch(api, body, query)
        return error

    def check_volume_move_state(self, result):
        if self.use_rest:
            volume_move_status = self.na_helper.safe_get(result, ['movement', 'state'])
        else:
            volume_move_status = result.get_child_by_name('attributes-list').get_child_by_name('volume-move-info').get_child_content('state')
        # We have 5 states that can be returned.
        # warning and healthy are state where the move is still going so we don't need to do anything for thouse.
        # success - volume move is completed in REST.
        if volume_move_status in ['success', 'done']:
            return False
        # ZAPI returns failed or alert, REST returns failed or aborted.
        if volume_move_status in ['failed', 'alert', 'aborted']:
            self.module.fail_json(msg='Error moving volume %s: %s' %
                                  (self.parameters['name'], result.get_child_by_name('attributes-list').get_child_by_name('volume-move-info')
                                   .get_child_content('details')))
        return True

    def wait_for_volume_move(self):
        volume_move_iter = netapp_utils.zapi.NaElement('volume-move-get-iter')
        volume_move_info = netapp_utils.zapi.NaElement('volume-move-info')
        volume_move_info.add_new_child('volume', self.parameters['name'])
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(volume_move_info)
        volume_move_iter.add_child_elem(query)
        error = self.wait_for_task_completion(volume_move_iter, self.check_volume_move_state)
        if error:
            self.module.fail_json(msg='Error getting volume move status: %s' % (to_native(error)),
                                  exception=traceback.format_exc())

    def wait_for_volume_move_rest(self):
        api = "storage/volumes"
        query = {
            'name': self.parameters['name'],
            'movement.destination_aggregate.name': self.parameters['aggregate_name'],
            'fields': 'movement.state'
        }
        error = self.wait_for_task_completion_rest(api, query, self.check_volume_move_state)
        if error:
            self.module.fail_json(msg='Error getting volume move status: %s' % (to_native(error)),
                                  exception=traceback.format_exc())

    def check_volume_encryption_conversion_state(self, result):
        if self.use_rest:
            volume_encryption_conversion_status = self.na_helper.safe_get(result, ['encryption', 'status', 'message'])
        else:
            volume_encryption_conversion_status = result.get_child_by_name('attributes-list').get_child_by_name('volume-encryption-conversion-info')\
                                                        .get_child_content('status')
        # REST returns running or initializing, ZAPI returns running if encryption in progress.
        if volume_encryption_conversion_status in ['running', 'initializing']:
            return True
        # If encryprion is completed, REST do have encryption status message.
        if volume_encryption_conversion_status in ['Not currently going on.', None]:
            return False
        self.module.fail_json(msg='Error converting encryption for volume %s: %s' %
                              (self.parameters['name'], volume_encryption_conversion_status))

    def wait_for_volume_encryption_conversion(self):
        if self.use_rest:
            return self.wait_for_volume_encryption_conversion_rest()
        volume_encryption_conversion_iter = netapp_utils.zapi.NaElement('volume-encryption-conversion-get-iter')
        volume_encryption_conversion_info = netapp_utils.zapi.NaElement('volume-encryption-conversion-info')
        volume_encryption_conversion_info.add_new_child('volume', self.parameters['name'])
        volume_encryption_conversion_info.add_new_child('vserver', self.parameters['vserver'])
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(volume_encryption_conversion_info)
        volume_encryption_conversion_iter.add_child_elem(query)
        error = self.wait_for_task_completion(volume_encryption_conversion_iter, self.check_volume_encryption_conversion_state)
        if error:
            self.module.fail_json(msg='Error getting volume encryption_conversion status: %s' % (to_native(error)),
                                  exception=traceback.format_exc())

    def wait_for_volume_encryption_conversion_rest(self):
        api = "storage/volumes"
        query = {
            'name': self.parameters['name'],
            'fields': 'encryption'
        }
        error = self.wait_for_task_completion_rest(api, query, self.check_volume_encryption_conversion_state)
        if error:
            self.module.fail_json(msg='Error getting volume encryption_conversion status: %s' % (to_native(error)),
                                  exception=traceback.format_exc())

    def wait_for_task_completion(self, zapi_iter, check_state):
        retries = self.parameters['max_wait_time'] // (self.parameters['check_interval'] + 1)
        fail_count = 0
        while retries > 0:
            try:
                result = self.cluster.invoke_successfully(zapi_iter, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                if fail_count < 3:
                    fail_count += 1
                    retries -= 1
                    time.sleep(self.parameters['check_interval'])
                    continue
                return error
            if int(result.get_child_content('num-records')) == 0:
                return None
            # reset fail count to 0
            fail_count = 0
            retry_required = check_state(result)
            if not retry_required:
                return None
            time.sleep(self.parameters['check_interval'])
            retries -= 1

    def wait_for_task_completion_rest(self, api, query, check_state):
        retries = self.parameters['max_wait_time'] // (self.parameters['check_interval'] + 1)
        fail_count = 0
        while retries > 0:
            record, error = rest_generic.get_one_record(self.rest_api, api, query)
            if error:
                if fail_count < 3:
                    fail_count += 1
                    retries -= 1
                    time.sleep(self.parameters['check_interval'])
                    continue
                return error
            if record is None:
                return None
            # reset fail count to 0
            fail_count = 0
            retry_required = check_state(record)
            if not retry_required:
                return None
            time.sleep(self.parameters['check_interval'])
            retries -= 1

    def rename_volume(self):
        """
        Rename the volume.

        Note: 'is_infinite' needs to be set to True in order to rename an
        Infinite Volume. Use time_out parameter to set wait time for rename completion.
        """
        if self.use_rest:
            return self.rename_volume_rest()
        vol_rename_zapi, vol_name_zapi = ['volume-rename-async', 'volume-name'] if self.parameters['is_infinite']\
            else ['volume-rename', 'volume']
        volume_rename = netapp_utils.zapi.NaElement.create_node_with_children(
            vol_rename_zapi, **{vol_name_zapi: self.parameters['from_name'],
                                'new-volume-name': str(self.parameters['name'])})
        try:
            result = self.server.invoke_successfully(volume_rename, enable_tunneling=True)
            if vol_rename_zapi == 'volume-rename-async':
                self.check_invoke_result(result, 'rename')
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error renaming volume %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def resize_volume(self):
        """
        Re-size the volume.

        Note: 'is_infinite' needs to be set to True in order to resize an
        Infinite Volume.
        """
        if self.use_rest:
            return self.resize_volume_rest()

        vol_size_zapi, vol_name_zapi = ['volume-size-async', 'volume-name']\
            if (self.parameters['is_infinite'] or self.volume_style == 'flexgroup')\
            else ['volume-size', 'volume']
        volume_resize = netapp_utils.zapi.NaElement.create_node_with_children(
            vol_size_zapi, **{vol_name_zapi: self.parameters['name'],
                              'new-size': str(self.parameters['size'])})
        try:
            result = self.server.invoke_successfully(volume_resize, enable_tunneling=True)
            if vol_size_zapi == 'volume-size-async':
                self.check_invoke_result(result, 'resize')
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error re-sizing volume %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        return None

    def start_encryption_conversion(self, encrypt_destination):
        if encrypt_destination:
            if self.use_rest:
                return self.encryption_conversion_rest()
            zapi = netapp_utils.zapi.NaElement.create_node_with_children(
                'volume-encryption-conversion-start', **{'volume': self.parameters['name']})
            try:
                self.server.invoke_successfully(zapi, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error enabling encryption for volume %s: %s'
                                      % (self.parameters['name'], to_native(error)),
                                      exception=traceback.format_exc())
            if self.parameters.get('wait_for_completion'):
                self.wait_for_volume_encryption_conversion()
        else:
            self.module.warn('disabling encryption requires cluster admin permissions.')
            self.move_volume(encrypt_destination)

    def change_volume_state(self, call_from_delete_vol=False):
        """
        Change volume's state (offline/online).
        """
        if self.use_rest:
            return self.change_volume_state_rest()
        if self.parameters['is_online'] and not call_from_delete_vol:    # Desired state is online, setup zapi APIs respectively
            vol_state_zapi, vol_name_zapi, action = ['volume-online-async', 'volume-name', 'online']\
                if (self.parameters['is_infinite'] or self.volume_style == 'flexgroup')\
                else ['volume-online', 'name', 'online']
        else:   # Desired state is offline, setup zapi APIs respectively
            vol_state_zapi, vol_name_zapi, action = ['volume-offline-async', 'volume-name', 'offline']\
                if (self.parameters['is_infinite'] or self.volume_style == 'flexgroup')\
                else ['volume-offline', 'name', 'offline']
            volume_unmount = netapp_utils.zapi.NaElement.create_node_with_children(
                'volume-unmount', **{'volume-name': self.parameters['name']})
        volume_change_state = netapp_utils.zapi.NaElement.create_node_with_children(
            vol_state_zapi, **{vol_name_zapi: self.parameters['name']})

        errors = []
        if not self.parameters['is_online'] or call_from_delete_vol:  # Unmount before offline
            try:
                self.server.invoke_successfully(volume_unmount, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                errors.append('Error unmounting volume %s: %s' % (self.parameters['name'], to_native(error)))
        state = "online" if self.parameters['is_online'] and not call_from_delete_vol else "offline"
        try:
            result = self.server.invoke_successfully(volume_change_state, enable_tunneling=True)
            if self.volume_style == 'flexgroup' or self.parameters['is_infinite']:
                self.check_invoke_result(result, action)
        except netapp_utils.zapi.NaApiError as error:
            errors.append('Error changing the state of volume %s to %s: %s' % (self.parameters['name'], state, to_native(error)))
        if errors and not call_from_delete_vol:
            self.module.fail_json(msg=', '.join(errors), exception=traceback.format_exc())
        return state, errors

    def create_volume_attribute(self, zapi_object, parent_attribute, attribute, option_name, convert_from=None):
        """

        :param parent_attribute:
        :param child_attribute:
        :param value:
        :return:
        """
        value = self.parameters.get(option_name)
        if value is None:
            return
        if convert_from == int:
            value = str(value)
        elif convert_from == bool:
            value = self.na_helper.get_value_for_bool(False, value, option_name)

        if zapi_object is None:
            parent_attribute.add_new_child(attribute, value)
            return
        if isinstance(zapi_object, str):
            # retrieve existing in parent, or create a new one
            element = parent_attribute.get_child_by_name(zapi_object)
            zapi_object = netapp_utils.zapi.NaElement(zapi_object) if element is None else element
        zapi_object.add_new_child(attribute, value)
        parent_attribute.add_child_elem(zapi_object)

    def build_zapi_volume_modify_iter(self, params):
        vol_mod_iter = netapp_utils.zapi.NaElement('volume-modify-iter-async' if self.volume_style == 'flexgroup' or self.parameters['is_infinite']
                                                   else 'volume-modify-iter')

        attributes = netapp_utils.zapi.NaElement('attributes')
        vol_mod_attributes = netapp_utils.zapi.NaElement('volume-attributes')
        # Volume-attributes is split in to 25 sub categories
        # volume-inode-attributes
        vol_inode_attributes = netapp_utils.zapi.NaElement('volume-inode-attributes')
        self.create_volume_attribute(vol_inode_attributes, vol_mod_attributes, 'files-total', 'max_files', int)
        # volume-space-attributes
        vol_space_attributes = netapp_utils.zapi.NaElement('volume-space-attributes')
        self.create_volume_attribute(vol_space_attributes, vol_mod_attributes, 'space-guarantee', 'space_guarantee')
        self.create_volume_attribute(vol_space_attributes, vol_mod_attributes, 'percentage-snapshot-reserve', 'percent_snapshot_space', int)
        self.create_volume_attribute(vol_space_attributes, vol_mod_attributes, 'space-slo', 'space_slo')
        # volume-snapshot-attributes
        vol_snapshot_attributes = netapp_utils.zapi.NaElement('volume-snapshot-attributes')
        self.create_volume_attribute(vol_snapshot_attributes, vol_mod_attributes, 'snapshot-policy', 'snapshot_policy')
        self.create_volume_attribute(vol_snapshot_attributes, vol_mod_attributes, 'snapdir-access-enabled', 'snapdir_access', bool)
        # volume-export-attributes
        self.create_volume_attribute('volume-export-attributes', vol_mod_attributes, 'policy', 'export_policy')
        # volume-security-attributes
        if self.parameters.get('unix_permissions') is not None or self.parameters.get('group_id') is not None or self.parameters.get('user_id') is not None:
            vol_security_attributes = netapp_utils.zapi.NaElement('volume-security-attributes')
            vol_security_unix_attributes = netapp_utils.zapi.NaElement('volume-security-unix-attributes')
            self.create_volume_attribute(vol_security_unix_attributes, vol_security_attributes, 'permissions', 'unix_permissions')
            self.create_volume_attribute(vol_security_unix_attributes, vol_security_attributes, 'group-id', 'group_id', int)
            self.create_volume_attribute(vol_security_unix_attributes, vol_security_attributes, 'user-id', 'user_id', int)
            vol_mod_attributes.add_child_elem(vol_security_attributes)
        if params and params.get('volume_security_style') is not None:
            self.create_volume_attribute('volume-security-attributes', vol_mod_attributes, 'style', 'volume_security_style')

        # volume-performance-attributes
        self.create_volume_attribute('volume-performance-attributes', vol_mod_attributes, 'is-atime-update-enabled', 'atime_update', bool)
        # volume-qos-attributes
        self.create_volume_attribute('volume-qos-attributes', vol_mod_attributes, 'policy-group-name', 'qos_policy_group')
        self.create_volume_attribute('volume-qos-attributes', vol_mod_attributes, 'adaptive-policy-group-name', 'qos_adaptive_policy_group')
        # volume-comp-aggr-attributes
        if params and params.get('tiering_policy') is not None:
            self.create_volume_attribute('volume-comp-aggr-attributes', vol_mod_attributes, 'tiering-policy', 'tiering_policy')
        # volume-state-attributes
        self.create_volume_attribute('volume-state-attributes', vol_mod_attributes, 'is-nvfail-enabled', 'nvfail_enabled', bool)
        # volume-dr-protection-attributes
        self.create_volume_attribute('volume-vserver-dr-protection-attributes', vol_mod_attributes, 'vserver-dr-protection', 'vserver_dr_protection')
        # volume-id-attributes
        self.create_volume_attribute('volume-id-attributes', vol_mod_attributes, 'comment', 'comment')
        # End of Volume-attributes sub attributes
        attributes.add_child_elem(vol_mod_attributes)

        query = netapp_utils.zapi.NaElement('query')
        vol_query_attributes = netapp_utils.zapi.NaElement('volume-attributes')
        self.create_volume_attribute('volume-id-attributes', vol_query_attributes, 'name', 'name')
        query.add_child_elem(vol_query_attributes)
        vol_mod_iter.add_child_elem(attributes)
        vol_mod_iter.add_child_elem(query)
        return vol_mod_iter

    def volume_modify_attributes(self, params):
        """
        modify volume parameter 'export_policy','unix_permissions','snapshot_policy','space_guarantee', 'percent_snapshot_space',
                                'qos_policy_group', 'qos_adaptive_policy_group'
        """
        if self.use_rest:
            return self.volume_modify_attributes_rest(params)
        vol_mod_iter = self.build_zapi_volume_modify_iter(params)
        try:
            result = self.server.invoke_successfully(vol_mod_iter, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            error_msg = to_native(error)
            if 'volume-comp-aggr-attributes' in error_msg:
                error_msg += ". Added info: tiering option requires 9.4 or later."
            self.wrap_fail_json(msg='Error modifying volume %s: %s'
                                % (self.parameters['name'], error_msg),
                                exception=traceback.format_exc())

        failures = result.get_child_by_name('failure-list')
        # handle error if modify space, policy, or unix-permissions parameter fails
        if failures is not None:
            error_msgs = [
                failures.get_child_by_name(return_info).get_child_content(
                    'error-message'
                )
                for return_info in (
                    'volume-modify-iter-info',
                    'volume-modify-iter-async-info',
                )
                if failures.get_child_by_name(return_info) is not None
            ]
            if error_msgs and any(x is not None for x in error_msgs):
                self.wrap_fail_json(msg="Error modifying volume %s: %s"
                                    % (self.parameters['name'], ' --- '.join(error_msgs)),
                                    exception=traceback.format_exc())
        if self.volume_style == 'flexgroup' or self.parameters['is_infinite']:
            success = self.na_helper.safe_get(result, ['success-list', 'volume-modify-iter-async-info'])
            results = {}
            for key in ('status', 'jobid'):
                if success and success.get_child_by_name(key):
                    results[key] = success[key]

            status = results.get('status')
            if status == 'in_progress' and 'jobid' in results:
                if self.parameters['time_out'] == 0:
                    return
                error = self.check_job_status(results['jobid'])
                if error is None:
                    return
                self.wrap_fail_json(msg='Error when modifying volume: %s' % error)
            self.wrap_fail_json(msg='Unexpected error when modifying volume: result is: %s' % str(result.to_string()))

    def volume_mount(self):
        """
        Mount an existing volume in specified junction_path
        :return: None
        """
        if self.use_rest:
            return self.volume_mount_rest()
        vol_mount = netapp_utils.zapi.NaElement('volume-mount')
        vol_mount.add_new_child('volume-name', self.parameters['name'])
        vol_mount.add_new_child('junction-path', self.parameters['junction_path'])
        try:
            self.server.invoke_successfully(vol_mount, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error mounting volume %s on path %s: %s'
                                  % (self.parameters['name'], self.parameters['junction_path'],
                                     to_native(error)), exception=traceback.format_exc())

    def volume_unmount(self):
        """
        Unmount an existing volume
        :return: None
        """
        if self.use_rest:
            return self.volume_unmount_rest()
        vol_unmount = netapp_utils.zapi.NaElement.create_node_with_children(
            'volume-unmount', **{'volume-name': self.parameters['name']})
        try:
            self.server.invoke_successfully(vol_unmount, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error unmounting volume %s: %s'
                                  % (self.parameters['name'], to_native(error)), exception=traceback.format_exc())

    def modify_volume(self, modify):
        '''Modify volume action'''
        # snaplock requires volume in unmount state.
        if modify.get('junction_path') == '':
            self.volume_unmount()
        attributes = modify.keys()
        for attribute in attributes:
            if attribute in ['space_guarantee', 'export_policy', 'unix_permissions', 'group_id', 'user_id', 'tiering_policy', 'tiering_object_tags',
                             'snapshot_policy', 'percent_snapshot_space', 'snapdir_access', 'atime_update', 'volume_security_style',
                             'nvfail_enabled', 'space_slo', 'qos_policy_group', 'qos_adaptive_policy_group', 'vserver_dr_protection',
                             'comment', 'logical_space_enforcement', 'logical_space_reporting', 'tiering_minimum_cooling_days',
                             'snaplock', 'max_files', 'analytics', 'activity_tracking', 'tags', 'snapshot_auto_delete',
                             'vol_nearly_full_threshold_percent', 'vol_full_threshold_percent', 'large_size_enabled', 'snapshot_locking', 'granular_data']:
                self.volume_modify_attributes(modify)
                break
        if 'snapshot_auto_delete' in attributes and not self.use_rest:
            # Rest didn't support snapshot_auto_delete prior to ONTAP 9.13.1; for supported ONTAP versions,
            # modification for this parameter is handled by calling volume_modify_attributes function.
            self.set_snapshot_auto_delete()
        # don't mount or unmount when offline
        if modify.get('junction_path'):
            self.volume_mount()
        if 'size' in attributes:
            self.resize_volume()
        if 'aggregate_name' in attributes:
            # keep it last, as it may take some time
            # handle change in encryption as part of the move
            # allow for encrypt/decrypt only if encrypt present in attributes.
            self.move_volume(modify.get('encrypt'))
        elif 'encrypt' in attributes:
            self.start_encryption_conversion(self.parameters['encrypt'])

    def get_volume_style(self, current):
        '''Get volume style, infinite or standard flexvol'''
        if current is not None:
            return current.get('style_extended')
        if self.parameters.get('aggr_list') or self.parameters.get('aggr_list_multiplier') or self.parameters.get('auto_provision_as'):
            if self.use_rest and self.parameters.get('auto_provision_as') and self.parameters.get('aggr_list_multiplier') is None:
                self.parameters['aggr_list_multiplier'] = 1
            return 'flexgroup'
        return None

    def get_job(self, jobid, server):
        """
        Get job details by id
        """
        job_get = netapp_utils.zapi.NaElement('job-get')
        job_get.add_new_child('job-id', jobid)
        try:
            result = server.invoke_successfully(job_get, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            if to_native(error.code) == "15661":
                # Not found
                return None
            self.wrap_fail_json(msg='Error fetching job info: %s' % to_native(error),
                                exception=traceback.format_exc())
        job_info = result.get_child_by_name('attributes').get_child_by_name('job-info')
        return {
            'job-progress': job_info['job-progress'],
            'job-state': job_info['job-state'],
            'job-completion': job_info['job-completion'] if job_info.get_child_by_name('job-completion') is not None else None
        }

    def check_job_status(self, jobid):
        """
        Loop until job is complete
        """
        server = self.server
        sleep_time = 5
        time_out = self.parameters['time_out']
        error = 'timeout'

        if time_out <= 0:
            results = self.get_job(jobid, server)

        while time_out > 0:
            results = self.get_job(jobid, server)
            # If running as cluster admin, the job is owned by cluster vserver
            # rather than the target vserver.
            if results is None and server == self.server:
                results = netapp_utils.get_cserver(self.server)
                server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=results)
                continue
            if results is None:
                error = 'cannot locate job with id: %d' % int(jobid)
                break
            if results['job-state'] in ('queued', 'running'):
                time.sleep(sleep_time)
                time_out -= sleep_time
                continue
            if results['job-state'] in ('success', 'failure'):
                break
            else:
                self.wrap_fail_json(msg='Unexpected job status in: %s' % repr(results))

        if results is not None:
            if results['job-state'] == 'success':
                error = None
            elif results['job-state'] in ('queued', 'running'):
                error = 'job completion exceeded expected timer of: %s seconds' % \
                        self.parameters['time_out']
            elif results['job-completion'] is not None:
                error = results['job-completion']
            else:
                error = results['job-progress']
        return error

    def check_invoke_result(self, result, action):
        '''
        check invoked api call back result.
        '''
        results = {}
        for key in ('result-status', 'result-jobid'):
            if result.get_child_by_name(key):
                results[key] = result[key]

        status = results.get('result-status')
        if status == 'in_progress' and 'result-jobid' in results:
            if self.parameters['time_out'] == 0:
                return
            error = self.check_job_status(results['result-jobid'])
            if error is None:
                return
            else:
                self.wrap_fail_json(msg='Error when %s volume: %s' % (action, error))
        if status == 'failed':
            self.wrap_fail_json(msg='Operation failed when %s volume.' % action)

    def set_efficiency_attributes(self, options):
        for key, attr in self.sis_keys2zapi_set.items():
            value = self.parameters.get(key)
            if value is not None:
                if self.argument_spec[key]['type'] == 'bool':
                    value = self.na_helper.get_value_for_bool(False, value)
                options[attr] = value
        # ZAPI requires compression to be set for inline-compression
        if options.get('enable-inline-compression') == 'true' and 'enable-compression' not in options:
            options['enable-compression'] = 'true'

    def set_efficiency_config(self):
        '''Set efficiency policy and compression attributes'''
        options = {'path': '/vol/' + self.parameters['name']}
        efficiency_enable = netapp_utils.zapi.NaElement.create_node_with_children('sis-enable', **options)
        try:
            self.server.invoke_successfully(efficiency_enable, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            # Error 40043 denotes an Operation has already been enabled.
            if to_native(error.code) != "40043":
                self.wrap_fail_json(msg='Error enable efficiency on volume %s: %s'
                                    % (self.parameters['name'], to_native(error)),
                                    exception=traceback.format_exc())

        self.set_efficiency_attributes(options)
        efficiency_start = netapp_utils.zapi.NaElement.create_node_with_children('sis-set-config', **options)
        try:
            self.server.invoke_successfully(efficiency_start, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.wrap_fail_json(msg='Error setting up efficiency attributes on volume %s: %s'
                                % (self.parameters['name'], to_native(error)),
                                exception=traceback.format_exc())

    def set_efficiency_config_async(self):
        """Set efficiency policy and compression attributes in asynchronous mode"""
        options = {'volume-name': self.parameters['name']}
        efficiency_enable = netapp_utils.zapi.NaElement.create_node_with_children('sis-enable-async', **options)
        try:
            result = self.server.invoke_successfully(efficiency_enable, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.wrap_fail_json(msg='Error enable efficiency on volume %s: %s'
                                % (self.parameters['name'], to_native(error)),
                                exception=traceback.format_exc())
        self.check_invoke_result(result, 'enable efficiency on')

        self.set_efficiency_attributes(options)
        efficiency_start = netapp_utils.zapi.NaElement.create_node_with_children('sis-set-config-async', **options)
        try:
            result = self.server.invoke_successfully(efficiency_start, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.wrap_fail_json(msg='Error setting up efficiency attributes on volume %s: %s'
                                % (self.parameters['name'], to_native(error)),
                                exception=traceback.format_exc())
        self.check_invoke_result(result, 'set efficiency policy on')

    def get_efficiency_info(self, return_value):
        """
        get the name of the efficiency policy assigned to volume, as well as compression values
        if attribute does not exist, set its value to None
        :return: update return_value dict.
        """
        sis_info = netapp_utils.zapi.NaElement('sis-get-iter')
        sis_status_info = netapp_utils.zapi.NaElement('sis-status-info')
        sis_status_info.add_new_child('path', '/vol/' + self.parameters['name'])
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(sis_status_info)
        sis_info.add_child_elem(query)
        try:
            result = self.server.invoke_successfully(sis_info, True)
        except netapp_utils.zapi.NaApiError as error:
            # Don't error out if efficiency settings cannot be read.  We'll fail if they need to be set.
            if error.message.startswith('Insufficient privileges: user ') and error.message.endswith(' does not have read access to this resource'):
                self.issues.append('cannot read volume efficiency options (as expected when running as vserver): %s' % to_native(error))
                return
            self.wrap_fail_json(msg='Error fetching efficiency policy for volume %s: %s'
                                % (self.parameters['name'], to_native(error)),
                                exception=traceback.format_exc())
        for key in self.sis_keys2zapi_get:
            return_value[key] = None
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
            sis_attributes = result.get_child_by_name('attributes-list'). get_child_by_name('sis-status-info')
            for key, attr in self.sis_keys2zapi_get.items():
                value = sis_attributes.get_child_content(attr)
                if self.argument_spec[key]['type'] == 'bool':
                    value = self.na_helper.get_value_for_bool(True, value)
                return_value[key] = value

    def modify_volume_efficiency_config(self, efficiency_config_modify_value):
        if self.use_rest:
            return self.set_efficiency_rest()
        if efficiency_config_modify_value == 'async':
            self.set_efficiency_config_async()
        else:
            self.set_efficiency_config()

    def set_snapshot_auto_delete(self):
        options = {'volume': self.parameters['name']}
        desired_options = self.parameters['snapshot_auto_delete']
        for key, value in desired_options.items():
            options['option-name'] = key
            options['option-value'] = str(value)
            snapshot_auto_delete = netapp_utils.zapi.NaElement.create_node_with_children('snapshot-autodelete-set-option', **options)
            try:
                self.server.invoke_successfully(snapshot_auto_delete, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                self.wrap_fail_json(msg='Error setting snapshot auto delete options for volume %s: %s'
                                    % (self.parameters['name'], to_native(error)),
                                    exception=traceback.format_exc())

    def rehost_volume(self):
        volume_rehost = netapp_utils.zapi.NaElement.create_node_with_children(
            'volume-rehost', **{'vserver': self.parameters['from_vserver'],
                                'destination-vserver': self.parameters['vserver'],
                                'volume': self.parameters['name']})
        if self.parameters.get('auto_remap_luns') is not None:
            volume_rehost.add_new_child('auto-remap-luns', str(self.parameters['auto_remap_luns']))
        if self.parameters.get('force_unmap_luns') is not None:
            volume_rehost.add_new_child('force-unmap-luns', str(self.parameters['force_unmap_luns']))
        try:
            self.cluster.invoke_successfully(volume_rehost, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error rehosting volume %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def snapshot_restore_volume(self):
        if self.use_rest:
            return self.snapshot_restore_volume_rest()
        snapshot_restore = netapp_utils.zapi.NaElement.create_node_with_children(
            'snapshot-restore-volume', **{'snapshot': self.parameters['snapshot_restore'],
                                          'volume': self.parameters['name']})
        if self.parameters.get('force_restore') is not None:
            snapshot_restore.add_new_child('force', str(self.parameters['force_restore']))
        if self.parameters.get('preserve_lun_ids') is not None:
            snapshot_restore.add_new_child('preserve-lun-ids', str(self.parameters['preserve_lun_ids']))
        try:
            self.server.invoke_successfully(snapshot_restore, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error restoring volume %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def ignore_small_change(self, current, attribute, threshold):
        if attribute in current and current[attribute] != 0 and self.parameters.get(attribute) is not None:
            # ignore a less than XX% difference
            change = abs(current[attribute] - self.parameters[attribute]) * 100.0 / current[attribute]
            if change < threshold:
                self.parameters[attribute] = current[attribute]
                if change > 0.1:
                    self.module.warn('resize request for %s ignored: %.1f%% is below the threshold: %.1f%%' % (attribute, change, threshold))

    def adjust_sizes(self, current, after_create):
        """
        ignore small change in size by resetting expectations
        """
        if after_create:
            # For NAS application templates, apply size threshold logic instead of blindly accepting current size
            if self.parameters.get('nas_application_template') is not None:
                # Check if size change is within threshold for NAS templates
                if current.get('size') and self.parameters.get('size'):
                    change = abs(current['size'] - self.parameters['size']) * 100.0 / current['size']
                    threshold = self.parameters.get('size_change_threshold', 10)

                    if change < threshold:
                        # Size difference is within threshold - update parameters for idempotency
                        original_size = self.parameters['size']
                        self.parameters['size'] = current['size']
                        self.module.warn('NAS template overhead detected: volume size adjusted from %s to %s (%.1f%% difference, below %.1f%% threshold)'
                                         % (original_size, current['size'], change, threshold))
                    # If change >= threshold, keep original size to trigger a resize operation
            else:
                # For regular volumes (non-NAS templates), ignore change in size immediately after create
                self.parameters['size'] = current['size']
            # inodes are not set in create
            return
        self.ignore_small_change(current, 'size', self.parameters['size_change_threshold'])
        self.ignore_small_change(current, 'max_files', netapp_utils.get_feature(self.module, 'max_files_change_threshold'))

    def validate_snaplock_changes(self, current, modify=None, after_create=False):
        if not self.use_rest:
            return
        msg = None
        if modify:
            # prechecks when computing modify
            if 'type' in modify['snaplock']:
                msg = "Error: volume snaplock type was not set properly at creation time." if after_create else \
                      "Error: changing a volume snaplock type after creation is not allowed."
                msg += '  Current: %s, desired: %s.' % (current['snaplock']['type'], self.parameters['snaplock']['type'])
        elif self.parameters['state'] == 'present':
            # prechecks before computing modify
            sl_dict = self.na_helper.filter_out_none_entries(self.parameters.get('snaplock', {}))
            sl_type = sl_dict.pop('type', 'non_snaplock')
            # verify type is the only option when not enabling snaplock compliance or enterprise
            if sl_dict and (
               (current is None and sl_type == 'non_snaplock') or (current and current['snaplock']['type'] == 'non_snaplock')):
                msg = "Error: snaplock options are not supported for non_snaplock volume, found: %s." % sl_dict
            # verify type is not used before 9.10.1, or allow non_snaplock as this is the default
            if not self.rest_api.meets_rest_minimum_version(True, 9, 10, 1):
                if sl_type == 'non_snaplock':
                    self.parameters.pop('snaplock', None)
                else:
                    msg = "Error: %s" % self.rest_api.options_require_ontap_version('snaplock type', '9.10.1', True)
        if msg:
            self.module.fail_json(msg=msg)

    def set_modify_dict(self, current, after_create=False):
        '''Fill modify dict with changes'''
        octal_value = current.get('unix_permissions') if current else None
        if self.parameters.get('unix_permissions') is not None and self.na_helper.compare_chmod_value(octal_value, self.parameters['unix_permissions']):
            # don't change if the values are the same
            # can't change permissions if not online
            del self.parameters['unix_permissions']
        # snapshot_auto_delete's value is a dict, get_modified_attributes function doesn't support dict as value.
        auto_delete_info = current.pop('snapshot_auto_delete', None)
        # ignore small changes in volume size or inode maximum by adjusting self.parameters['size'] or self.parameters['max_files']
        self.adjust_sizes(current, after_create)
        if 'type' in self.parameters:
            self.parameters['type'] = self.parameters['type'].lower()
        modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if modify is not None and 'type' in modify:
            msg = "Error: volume type was not set properly at creation time." if after_create else \
                  "Error: changing a volume from one type to another is not allowed."
            msg += '  Current: %s, desired: %s.' % (current['type'], self.parameters['type'])
            self.module.fail_json(msg=msg)
        if modify is not None and 'snaplock' in modify:
            self.validate_snaplock_changes(current, modify, after_create)
        desired_style = self.get_volume_style(None)
        if desired_style is not None and desired_style != self.volume_style:
            msg = "Error: volume backend was not set properly at creation time." if after_create else \
                  "Error: changing a volume from one backend to another is not allowed."
            msg += '  Current: %s, desired: %s.' % (self.volume_style, desired_style)
            self.module.fail_json(msg=msg)
        desired_tcontrol = self.na_helper.safe_get(self.parameters, ['nas_application_template', 'tiering', 'control'])
        if desired_tcontrol in ('required', 'disallowed'):
            warn_or_fail = netapp_utils.get_feature(self.module, 'warn_or_fail_on_fabricpool_backend_change')
            if warn_or_fail in ('warn', 'fail'):
                current_tcontrol = self.tiering_control(current)
                if desired_tcontrol != current_tcontrol:
                    msg = "Error: volume tiering control was not set properly at creation time." if after_create else \
                          "Error: changing a volume from one backend to another is not allowed."
                    msg += '  Current tiering control: %s, desired: %s.' % (current_tcontrol, desired_tcontrol)
                    if warn_or_fail == 'fail':
                        self.module.fail_json(msg=msg)
                    self.module.warn("Ignored " + msg)
            elif warn_or_fail not in (None, 'ignore'):
                self.module.warn("Unexpected value '%s' for warn_or_fail_on_fabricpool_backend_change, expecting: None, 'ignore', 'fail', 'warn'"
                                 % warn_or_fail)
        if self.parameters.get('snapshot_auto_delete') is not None:
            auto_delete_modify = self.na_helper.get_modified_attributes(auto_delete_info,
                                                                        self.parameters['snapshot_auto_delete'])
            if len(auto_delete_modify) > 0:
                modify['snapshot_auto_delete'] = auto_delete_modify
        return modify

    def take_modify_actions(self, modify):
        self.modify_volume(modify)

        if any(modify.get(key) is not None for key in self.sis_keys2zapi_get):
            if self.parameters.get('is_infinite') or self.volume_style == 'flexgroup':
                efficiency_config_modify = 'async'
            else:
                efficiency_config_modify = 'sync'
            self.modify_volume_efficiency_config(efficiency_config_modify)

        # offline volume last
        if modify.get('is_online') is False:
            self.change_volume_state()

    """ MAPPING OF VOLUME FIELDS FROM ZAPI TO REST
    ZAPI = REST
    encrypt = encryption.enabled
    volume-comp-aggr-attributes.tiering-policy = tiering.policy
    'volume-export-attributes.policy' = nas.export_policy.name
    'volume-id-attributes.containing-aggregate-name' = aggregates.name
    'volume-id-attributes.flexgroup-uuid' = uuid (Only for FlexGroup volumes)
    'volume-id-attributes.instance-uuid' = uuid (Only for FlexVols)
    'volume-id-attributes.junction-path' = nas.path
    'volume-id-attributes.style-extended' = style
    'volume-id-attributes.type' = type
    'volume-id-attributes.comment' = comment
    'volume-performance-attributes.is-atime-update-enabled' == NO REST VERSION
    volume-qos-attributes.policy-group-name' = qos.policy.name
    'volume-qos-attributes.adaptive-policy-group-name' = qos.policy.name
    'volume-security-attributes.style = nas.security_style
    volume-security-attributes.volume-security-unix-attributes.group-id' = nas.gid
    'volume-security-attributes.volume-security-unix-attributes.permissions' =  nas.unix_permissions
    'volume-security-attributes.volume-security-unix-attributes.user-id' = nas.uid
    'volume-snapshot-attributes.snapdir-access-enabled' == NO REST VERSION
    'volume-snapshot-attributes,snapshot-policy' = snapshot_policy
    volume-space-attributes.percentage-snapshot-reserve = space.snapshot.reserve_percent
    volume-space-attributes.size' = space.size
    'volume-space-attributes.space-guarantee' = guarantee.type
    volume-space-attributes.space-slo' == NO REST VERSION
    'volume-state-attributes.is-nvfail-enabled' == NO REST Version
    'volume-state-attributes.state' = state
    'volume-vserver-dr-protection-attributes.vserver-dr-protection' = == NO REST Version
    volume-snapshot-autodelete-attributes.* None exist other than space.snapshot.autodelete_enabled
    From get_efficiency_info function
    efficiency_policy = efficiency.policy.name
    compression = efficiency.compression
    inline_compression = efficiency.compression
    """

    def get_volume_rest(self, vol_name):
        """
        This covers the zapi functions
        get_volume
         - volume_get_iter
         - get_efficiency_info
        """
        api = 'storage/volumes'
        params = {'name': vol_name,
                  'svm.name': self.parameters['vserver'],
                  'fields': 'encryption.enabled,'
                            'tiering.policy,'
                            'tiering.object_tags,'
                            'nas.export_policy.name,'
                            'aggregates.name,'
                            'aggregates.uuid,'
                            'uuid,'
                            'nas.path,'
                            'style,'
                            'type,'
                            'comment,'
                            'qos.policy.name,'
                            'nas.security_style,'
                            'nas.gid,'
                            'nas.unix_permissions,'
                            'nas.uid,'
                            'snapshot_policy,'
                            'space.snapshot.reserve_percent,'
                            'space.size,'
                            'guarantee.type,'
                            'state,'
                            'efficiency.compression,'
                            'snaplock,'
                            'files.maximum,'
                            'space.logical_space.enforcement,'
                            'space.logical_space.reporting,'}
        if self.parameters.get('efficiency_policy'):
            params['fields'] += 'efficiency.policy.name,'
        if self.parameters.get('tiering_minimum_cooling_days'):
            params['fields'] += 'tiering.min_cooling_days,'
        if self.parameters.get('analytics'):
            params['fields'] += 'analytics,'
        if self.parameters.get('activity_tracking'):
            params['fields'] += 'activity_tracking,'
        if self.parameters.get('tags'):
            params['fields'] += '_tags,'
        if self.parameters.get('atime_update') is not None:
            params['fields'] += 'access_time_enabled,'
        if self.parameters.get('snapdir_access') is not None:
            params['fields'] += 'snapshot_directory_access_enabled,'
        if self.parameters.get('snapshot_auto_delete') is not None:
            params['fields'] += 'space.snapshot.autodelete,'
        if self.parameters.get('vol_nearly_full_threshold_percent') is not None:
            params['fields'] += 'space.nearly_full_threshold_percent,'
        if self.parameters.get('vol_full_threshold_percent') is not None:
            params['fields'] += 'space.full_threshold_percent,'
        if self.parameters.get('large_size_enabled') is not None:
            params['fields'] += 'space.large_size_enabled,'
        if self.parameters.get('snapshot_locking') is not None:
            params['fields'] += 'snapshot_locking_enabled,'
        if self.parameters.get('granular_data') is not None:
            params['fields'] += 'granular_data,'

        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg=error)
        return self.format_get_volume_rest(record) if record else None

    def rename_volume_rest(self):
        # volume-rename-async and volume-rename are the same in rest
        # Zapi you had to give the old and new name to change a volume.
        # Rest you need the old UUID, and the new name only
        current = self.get_volume_rest(self.parameters['from_name'])
        body = {
            'name': self.parameters['name']
        }
        dummy, error = self.volume_rest_patch(body, uuid=current['uuid'])
        if error:
            self.module.fail_json(msg='Error changing name of volume %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def snapshot_restore_volume_rest(self):
        # Rest does not have force_restore or preserve_lun_id
        current = self.get_volume()
        self.parameters['uuid'] = current['uuid']
        body = {
            'restore_to.snapshot.name': self.parameters['snapshot_restore']
        }
        dummy, error = self.volume_rest_patch(body)
        if error:
            self.module.fail_json(msg='Error restoring snapshot %s in volume %s: %s' % (
                self.parameters['snapshot_restore'],
                self.parameters['name'],
                to_native(error)), exception=traceback.format_exc())

    def create_volume_rest(self):
        body = self.create_volume_body_rest()
        dummy, error = rest_generic.post_async(self.rest_api, 'storage/volumes', body, job_timeout=self.parameters['time_out'])
        if error:
            self.module.fail_json(msg='Error creating volume %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        if self.parameters.get('wait_for_completion'):
            self.wait_for_volume_online(sleep_time=5)

    def create_volume_body_rest(self):
        body = {
            'name': self.parameters['name'],
            'svm.name': self.parameters['vserver']
        }
        # Zapi's Space-guarantee and space-reserve are the same thing in Rest
        if self.parameters.get('space_guarantee') is not None:
            body['guarantee.type'] = self.parameters['space_guarantee']
        # TODO: Check to see if there a difference in rest between flexgroup or not. might need to throw error
        body = self.aggregates_rest(body)
        if self.parameters.get('tags') is not None:
            body['_tags'] = self.parameters['tags']
        if self.parameters.get('size') is not None:
            body['size'] = self.parameters['size']
        if self.parameters.get('snapshot_policy') is not None:
            body['snapshot_policy.name'] = self.parameters['snapshot_policy']
        if self.parameters.get('unix_permissions') is not None:
            body['nas.unix_permissions'] = self.parameters['unix_permissions']
        if self.parameters.get('group_id') is not None:
            body['nas.gid'] = self.parameters['group_id']
        if self.parameters.get('user_id') is not None:
            body['nas.uid'] = self.parameters['user_id']
        if self.parameters.get('volume_security_style') is not None:
            body['nas.security_style'] = self.parameters['volume_security_style']
        if self.parameters.get('export_policy') is not None:
            body['nas.export_policy.name'] = self.parameters['export_policy']
        if self.parameters.get('junction_path') is not None:
            body['nas.path'] = self.parameters['junction_path']
        if self.parameters.get('comment') is not None:
            body['comment'] = self.parameters['comment']
        if self.parameters.get('type') is not None:
            body['type'] = self.parameters['type'].lower()
        if self.parameters.get('percent_snapshot_space') is not None:
            body['space.snapshot.reserve_percent'] = self.parameters['percent_snapshot_space']
        if self.parameters.get('language') is not None:
            body['language'] = self.parameters['language']
        if self.get_qos_policy_group() is not None:
            body['qos.policy.name'] = self.get_qos_policy_group()
        if self.parameters.get('tiering_policy') is not None:
            body['tiering.policy'] = self.parameters['tiering_policy']
        if self.parameters.get('tiering_object_tags') is not None:
            body['tiering.object_tags'] = self.parameters['tiering_object_tags']
        if self.parameters.get('encrypt') is not None:
            body['encryption.enabled'] = self.parameters['encrypt']
        if self.parameters.get('logical_space_enforcement') is not None:
            body['space.logical_space.enforcement'] = self.parameters['logical_space_enforcement']
        if self.parameters.get('logical_space_reporting') is not None:
            body['space.logical_space.reporting'] = self.parameters['logical_space_reporting']
        if self.parameters.get('tiering_minimum_cooling_days') is not None:
            body['tiering.min_cooling_days'] = self.parameters['tiering_minimum_cooling_days']
        if self.parameters.get('snaplock') is not None:
            body['snaplock'] = self.na_helper.filter_out_none_entries(self.parameters['snaplock'])
        if self.volume_style:
            body['style'] = self.volume_style
        if self.parameters.get('efficiency_policy') is not None:
            body['efficiency.policy.name'] = self.parameters['efficiency_policy']
        if self.get_compression():
            body['efficiency.compression'] = self.get_compression()
        if self.parameters.get('analytics'):
            body['analytics.state'] = self.parameters['analytics']
        if self.parameters.get('activity_tracking'):
            body['activity_tracking.state'] = self.parameters['activity_tracking']
        body['state'] = self.bool_to_online(self.parameters['is_online'])
        return body

    def aggregates_rest(self, body):
        if self.parameters.get('aggregate_name') is not None:
            body['aggregates'] = [{'name': self.parameters['aggregate_name']}]
        if self.parameters.get('aggr_list') is not None:
            body['aggregates'] = [{'name': name} for name in self.parameters['aggr_list']]
        if self.parameters.get('aggr_list_multiplier') is not None:
            body['constituents_per_aggregate'] = self.parameters['aggr_list_multiplier']
        return body

    def volume_modify_attributes_rest(self, params):
        body = self.modify_volume_body_rest(params)
        dummy, error = self.volume_rest_patch(body)
        if error:
            self.module.fail_json(msg='Error modifying volume %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    @staticmethod
    def bool_to_online(item):
        return 'online' if item else 'offline'

    @staticmethod
    def enabled_to_bool(item, reverse=False):
        """ convertes on/off to true/false or vice versa """
        if reverse:
            return 'on' if item else 'off'
        return True if item == 'on' else False

    def modify_volume_body_rest(self, params):
        body = {}
        for key, option, transform in [
            ('analytics.state', 'analytics', None),
            ('activity_tracking.state', 'activity_tracking', None),
            ('guarantee.type', 'space_guarantee', None),
            ('space.snapshot.reserve_percent', 'percent_snapshot_space', None),
            ('snapshot_policy.name', 'snapshot_policy', None),
            ('nas.export_policy.name', 'export_policy', None),
            ('nas.unix_permissions', 'unix_permissions', None),
            ('nas.gid', 'group_id', None),
            ('nas.uid', 'user_id', None),
            # only one of these 2 options for QOS policy can be defined at most
            ('qos.policy.name', 'qos_policy_group', None),
            ('qos.policy.name', 'qos_adaptive_policy_group', None),
            ('comment', 'comment', None),
            ('space.logical_space.enforcement', 'logical_space_enforcement', None),
            ('space.logical_space.reporting', 'logical_space_reporting', None),
            ('tiering.min_cooling_days', 'tiering_minimum_cooling_days', None),
            ('state', 'is_online', self.bool_to_online),
            ('_tags', 'tags', None),
            ('snapshot_directory_access_enabled', 'snapdir_access', None),
            ('access_time_enabled', 'atime_update', None),
            ('space.nearly_full_threshold_percent', 'vol_nearly_full_threshold_percent', None),
            ('space.full_threshold_percent', 'vol_full_threshold_percent', None),
            ('space.large_size_enabled', 'large_size_enabled', None),
            ('snapshot_locking_enabled', 'snapshot_locking', None),
            ('granular_data', 'granular_data', None),
        ]:
            value = self.parameters.get(option)
            if value is not None and transform:
                value = transform(value)
            if value is not None:
                body[key] = value

        # not too sure why we don't always set them
        # one good reason are fields that are not supported on all releases
        for key, option, transform in [
            ('nas.security_style', 'volume_security_style', None),
            ('tiering.policy', 'tiering_policy', None),
            ('tiering.object_tags', 'tiering_object_tags', None),
            ('files.maximum', 'max_files', None),
        ]:
            if params and params.get(option) is not None:
                body[key] = self.parameters[option]

        if params and params.get('snaplock') is not None:
            sl_dict = self.na_helper.filter_out_none_entries(self.parameters['snaplock']) or {}
            # type is not allowed in patch, and we already prevented any change in type
            sl_dict.pop('type', None)
            if sl_dict:
                body['snaplock'] = sl_dict

        if params and params.get('snapshot_auto_delete') is not None:
            for key, option, transform in [
                ('space.snapshot.autodelete.trigger', 'trigger', None),
                ('space.snapshot.autodelete.target_free_space', 'target_free_space', None),
                ('space.snapshot.autodelete.delete_order', 'delete_order', None),
                ('space.snapshot.autodelete.commitment', 'commitment', None),
                ('space.snapshot.autodelete.defer_delete', 'defer_delete', None),
                ('space.snapshot.autodelete.prefix', 'prefix', None),
                ('space.snapshot.autodelete.enabled', 'state', self.enabled_to_bool),
            ]:
                if params and params['snapshot_auto_delete'].get(option) is not None:
                    if transform:
                        body[key] = transform(self.parameters['snapshot_auto_delete'][option])
                    else:
                        body[key] = self.parameters['snapshot_auto_delete'][option]
        return body

    def change_volume_state_rest(self):
        body = {
            'state': self.bool_to_online(self.parameters['is_online']),
        }
        dummy, error = self.volume_rest_patch(body)
        if error:
            self.module.fail_json(msg='Error changing state of volume %s: %s' % (self.parameters['name'],
                                                                                 to_native(error)),
                                  exception=traceback.format_exc())
        return body['state'], None

    def volume_unmount_rest(self, fail_on_error=True):
        body = {
            'nas.path': '',
        }
        dummy, error = self.volume_rest_patch(body)
        if error and fail_on_error:
            self.module.fail_json(msg='Error unmounting volume %s with path "%s": %s' % (self.parameters['name'],
                                                                                         self.parameters.get('junction_path'),
                                                                                         to_native(error)),
                                  exception=traceback.format_exc())
        return error

    def volume_mount_rest(self):
        body = {
            'nas.path': self.parameters['junction_path']
        }
        dummy, error = self.volume_rest_patch(body)
        if error:
            self.module.fail_json(msg='Error mounting volume %s with path "%s": %s' % (self.parameters['name'],
                                                                                       self.parameters['junction_path'],
                                                                                       to_native(error)),
                                  exception=traceback.format_exc())

    def set_efficiency_rest(self):
        body = {}
        if self.parameters.get('efficiency_policy') is not None:
            body['efficiency.policy.name'] = self.parameters['efficiency_policy']
        if self.get_compression():
            body['efficiency.compression'] = self.get_compression()
        if not body:
            return
        dummy, error = self.volume_rest_patch(body)
        if error:
            if "Failed to modify efficiency configuration for volume" in error and "Operation is not enabled" in error \
                    and "'code': '6881332'" in error:
                self.module.fail_json(msg=('You are trying to set the efficiency configuration for the volume, where efficiency is disabled. '
                                           'Please refer to module na_ontap_volume_efficiency to enable efficiency on the volume first.'))
            self.module.fail_json(msg='Error setting efficiency for volume %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def encryption_conversion_rest(self):
        # volume-encryption-conversion-start
        # Set the "encryption.enabled" field to "true" to start the encryption conversion operation.
        body = {
            'encryption.enabled': True
        }
        dummy, error = self.volume_rest_patch(body)
        if error:
            self.module.fail_json(msg='Error enabling encryption for volume %s: %s' % (self.parameters['name'],
                                                                                       to_native(error)),
                                  exception=traceback.format_exc())
        if self.parameters.get('wait_for_completion'):
            self.wait_for_volume_encryption_conversion_rest()

    def resize_volume_rest(self):
        query = None
        if self.parameters.get('sizing_method') is not None:
            query = dict(sizing_method=self.parameters['sizing_method'])
        body = {
            'size': self.parameters['size']
        }
        dummy, error = self.volume_rest_patch(body, query)
        if error:
            self.module.fail_json(msg='Error resizing volume %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def move_volume_rest(self, encrypt_destination):
        body = {
            'movement.destination_aggregate.name': self.parameters['aggregate_name'],
        }
        if encrypt_destination is not None:
            body['encryption.enabled'] = encrypt_destination
        dummy, error = self.volume_rest_patch(body)
        if error:
            self.module.fail_json(msg='Error moving volume %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        if self.parameters.get('wait_for_completion'):
            self.wait_for_volume_move_rest()

    def volume_rest_patch(self, body, query=None, uuid=None):
        if not uuid:
            uuid = self.parameters['uuid']
        if not uuid:
            self.module.fail_json(msg='Could not read UUID for volume %s in patch.' % self.parameters['name'])
        return rest_generic.patch_async(self.rest_api, 'storage/volumes', uuid, body, query=query, job_timeout=self.parameters['time_out'])

    def get_qos_policy_group(self):
        if self.parameters.get('qos_policy_group') is not None:
            return self.parameters['qos_policy_group']
        if self.parameters.get('qos_adaptive_policy_group') is not None:
            return self.parameters['qos_adaptive_policy_group']
        return None

    def get_compression(self):
        if self.parameters.get('compression') and self.parameters.get('inline_compression'):
            return 'both'
        if self.parameters.get('compression'):
            return 'background'
        if self.parameters.get('inline_compression'):
            return 'inline'
        if self.parameters.get('compression') is False and self.parameters.get('inline_compression') is False:
            return 'none'
        return None

    def rest_errors(self):
        # For variable that have been merged together we should fail before we do anything
        if self.parameters.get('qos_policy_group') and self.parameters.get('qos_adaptive_policy_group'):
            self.module.fail_json(msg='Error: With Rest API qos_policy_group and qos_adaptive_policy_group are now '
                                      'the same thing, and cannot be set at the same time')

        ontap_97_options = ['nas_application_template']
        if not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 7) and any(x in self.parameters for x in ontap_97_options):
            self.module.fail_json(msg='Error: %s' % self.rest_api.options_require_ontap_version(ontap_97_options, version='9.7'))

        if not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 9) and\
           self.na_helper.safe_get(self.parameters, ['nas_application_template', 'flexcache', 'dr_cache']) is not None:
            self.module.fail_json(msg='Error: %s' % self.rest_api.options_require_ontap_version('flexcache: dr_cache', version='9.9'))
        if not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 11) and\
           self.na_helper.safe_get(self.parameters, ['nas_application_template', 'cifs_share_name']) is not None:
            self.module.fail_json(msg='Error: %s' % self.rest_api.options_require_ontap_version('nas_application_template: cifs_share_name', version='9.11'))
        if not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 12) and\
           self.na_helper.safe_get(self.parameters, ['nas_application_template', 'snaplock']) is not None:
            self.module.fail_json(msg='Error: %s' % self.rest_api.options_require_ontap_version('nas_application_template: snaplock', version='9.12'))
        if not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 13, 1) and\
           self.na_helper.safe_get(self.parameters, ['nas_application_template', 'snapshot_locking_enabled']) is not None:
            self.module.fail_json(msg='Error: %s' % self.rest_api.options_require_ontap_version('nas_application_template: \
                                                                                                 snapshot_locking_enabled', version='9.13.1'))

        if self.na_helper.safe_get(self.parameters, ['nas_application_template', 'cifs_share_name']) is not None and\
           self.na_helper.safe_get(self.parameters, ['nas_application_template', 'cifs_access']) is None:
            self.module.fail_json(msg='Must provide CIFS access information when providing CIFS share name.')

        if 'snapshot_auto_delete' in self.parameters:
            if 'destroy_list' in self.parameters['snapshot_auto_delete']:
                self.module.fail_json(msg="snapshot_auto_delete option 'destroy_list' is currently not supported with REST.")

    def format_get_volume_rest(self, record):
        is_online = record.get('state') == 'online'
        # TODO FIX THIS!!!! ZAPI would only return a single aggr, REST can return more than 1.
        # For now i'm going to hard code this, but we need a way to show all aggrs
        aggregates = record.get('aggregates', None)
        aggr_name = aggregates[0].get('name', None) if aggregates else None
        rest_compression = self.na_helper.safe_get(record, ['efficiency', 'compression'])
        junction_path = self.na_helper.safe_get(record, ['nas', 'path'])
        if junction_path is None:
            junction_path = ''
        # if analytics.state is initializing it will be ON once completed.
        state = self.na_helper.safe_get(record, ['analytics', 'state'])
        analytics = 'on' if state == 'initializing' else state
        auto_delete_info = self.na_helper.safe_get(record, ['space', 'snapshot', 'autodelete'])
        if auto_delete_info is not None:
            auto_delete_info['state'] = self.enabled_to_bool(self.na_helper.safe_get(record, ['space', 'snapshot', 'autodelete', 'enabled']), reverse=True)
            del auto_delete_info['enabled']
        return {
            'tags': record.get('_tags', []),
            'name': record.get('name', None),
            'analytics': analytics,
            'activity_tracking': self.na_helper.safe_get(record, ['activity_tracking', 'state']),
            'encrypt': self.na_helper.safe_get(record, ['encryption', 'enabled']),
            'tiering_policy': self.na_helper.safe_get(record, ['tiering', 'policy']),
            'tiering_object_tags': self.na_helper.safe_get(record, ['tiering', 'object_tags']),
            'export_policy': self.na_helper.safe_get(record, ['nas', 'export_policy', 'name']),
            'aggregate_name': aggr_name,
            'aggregates': aggregates,
            'flexgroup_uuid': record.get('uuid', None),  # this might need some additional logic
            'instance_uuid': record.get('uuid', None),  # this might need some additional logic
            'junction_path': junction_path,
            'style_extended': record.get('style', None),
            'type': record.get('type', None),
            'comment': record.get('comment', None),
            'qos_policy_group': self.na_helper.safe_get(record, ['qos', 'policy', 'name']),
            'qos_adaptive_policy_group': self.na_helper.safe_get(record, ['qos', 'policy', 'name']),
            'volume_security_style': self.na_helper.safe_get(record, ['nas', 'security_style']),
            'group_id': self.na_helper.safe_get(record, ['nas', 'gid']),
            # Rest return an Int while Zapi return a string, force Rest to be an String
            'unix_permissions': str(self.na_helper.safe_get(record, ['nas', 'unix_permissions'])),
            'user_id': self.na_helper.safe_get(record, ['nas', 'uid']),
            'snapshot_policy': self.na_helper.safe_get(record, ['snapshot_policy', 'name']),
            'percent_snapshot_space': self.na_helper.safe_get(record, ['space', 'snapshot', 'reserve_percent']),
            'size': self.na_helper.safe_get(record, ['space', 'size']),
            'space_guarantee': self.na_helper.safe_get(record, ['guarantee', 'type']),
            'is_online': is_online,
            'uuid': record.get('uuid', None),
            'efficiency_policy': self.na_helper.safe_get(record, ['efficiency', 'policy', 'name']),
            'compression': rest_compression in ('both', 'background'),
            'inline_compression': rest_compression in ('both', 'inline'),
            'logical_space_enforcement': self.na_helper.safe_get(record, ['space', 'logical_space', 'enforcement']),
            'logical_space_reporting': self.na_helper.safe_get(record, ['space', 'logical_space', 'reporting']),
            'tiering_minimum_cooling_days': self.na_helper.safe_get(record, ['tiering', 'min_cooling_days']),
            'snaplock': self.na_helper.safe_get(record, ['snaplock']),
            'max_files': self.na_helper.safe_get(record, ['files', 'maximum']),
            # The default setting for access_time_enabled and snapshot_directory_access_enabled is true
            'atime_update': record.get('access_time_enabled', True),
            'snapdir_access': record.get('snapshot_directory_access_enabled', True),
            'snapshot_auto_delete': auto_delete_info,
            'vol_nearly_full_threshold_percent': self.na_helper.safe_get(record, ['space', 'nearly_full_threshold_percent']),
            'vol_full_threshold_percent': self.na_helper.safe_get(record, ['space', 'full_threshold_percent']),
            'large_size_enabled': self.na_helper.safe_get(record, ['space', 'large_size_enabled']),
            'snapshot_locking': self.na_helper.safe_get(record, ['snapshot_locking_enabled']),
            'granular_data': self.na_helper.safe_get(record, ['granular_data']),
        }

    def is_fabricpool(self, name, aggregate_uuid):
        '''whether the aggregate is associated with one or more object stores'''
        api = 'storage/aggregates/%s/cloud-stores' % aggregate_uuid
        records, error = rest_generic.get_0_or_more_records(self.rest_api, api)
        if error:
            self.module.fail_json(msg="Error getting object store for aggregate: %s: %s" % (name, error))
        return records is not None and len(records) > 0

    def tiering_control(self, current):
        '''return whether the backend meets FabricPool requirements:
            required: all aggregates are in a FabricPool
            disallowed: all aggregates are not in a FabricPool
            best_effort: mixed
        '''
        fabricpools = [self.is_fabricpool(aggregate['name'], aggregate['uuid'])
                       for aggregate in current.get('aggregates', [])]
        if not fabricpools:
            return None
        if all(fabricpools):
            return 'required'
        if any(fabricpools):
            return 'best_effort'
        return 'disallowed'

    def set_actions(self):
        """define what needs to be done"""
        actions = []
        modify = {}

        current = self.get_volume()
        if current:
            if 'tiering_object_tags' in current and current['tiering_object_tags'] is None:
                current['tiering_object_tags'] = []
        self.volume_style = self.get_volume_style(current)
        if self.volume_style == 'flexgroup' and self.parameters.get('aggregate_name') is not None:
            self.module.fail_json(msg='Error: aggregate_name option cannot be used with FlexGroups.')

        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action == 'delete' or self.parameters['state'] == 'absent':
            return ['delete'] if cd_action == 'delete' else [], current, modify
        if cd_action == 'create':
            # report an error if the vserver does not exist (it can be also be a cluster or node vserver with REST)
            if self.use_rest:
                rest_vserver.get_vserver_uuid(self.rest_api, self.parameters['vserver'], self.module, True)
            actions = ['create']
            if self.parameters.get('from_name'):
                # create by renaming
                current = self.get_volume(self.parameters['from_name'])
                rename = self.na_helper.is_rename_action(current, None)
                if rename is None:
                    self.module.fail_json(msg="Error renaming volume: cannot find %s" % self.parameters['from_name'])
                if rename:
                    cd_action = None
                    actions = ['rename']
            elif self.parameters.get('from_vserver'):
                # create by rehosting
                if self.use_rest:
                    self.module.fail_json(msg='Error: ONTAP REST API does not support Rehosting Volumes')
                actions = ['rehost']
                self.na_helper.changed = True
        if self.parameters.get('snapshot_restore'):
            # update by restoring
            if 'create' in actions:
                self.module.fail_json(msg="Error restoring volume: cannot find parent: %s" % self.parameters['name'])
            # let's allow restoring after a rename or rehost
            actions.append('snapshot_restore')
            self.na_helper.changed = True
        self.validate_snaplock_changes(current)
        if cd_action is None and 'rehost' not in actions:
            # Ignoring modify after a rehost, as we can't read the volume properties on the remote volume
            # or maybe we could, using a cluster ZAPI, but since ZAPI is going away, is it worth it?
            modify = self.set_modify_dict(current)
            if modify:
                # ZAPI decrypts volume using volume move api and aggregate name is required.
                if not self.use_rest and modify.get('encrypt') is False and not self.parameters.get('aggregate_name'):
                    self.parameters['aggregate_name'] = current['aggregate_name']
                if self.use_rest and modify.get('encrypt') is False and not modify.get('aggregate_name'):
                    self.module.fail_json(msg="Error: unencrypting volume is only supported when moving the volume to another aggregate in REST.")
                actions.append('modify')
        if self.parameters.get('nas_application_template') is not None:
            application = self.get_application('nas')
            changed = self.na_helper.changed
            app_component = self.create_nas_application_component() if self.parameters['state'] == 'present' else None
            modify_app = self.na_helper.get_modified_attributes(application, app_component)
            # restore current change state, as we ignore this
            if modify_app:
                self.na_helper.changed = changed
        return actions, current, modify

    def apply(self):
        '''Call create/modify/delete operations'''
        actions, current, modify = self.set_actions()
        is_online = current.get('is_online') if current else None
        response = None

        # rehost, snapshot_restore and modify actions requires volume state to be online.
        online_modify_options = [x for x in actions if x in ['rehost', 'snapshot_restore', 'modify']]
        # ignore options that requires volume shoule be online.
        if not modify.get('is_online') and is_online is False and online_modify_options:
            modify_keys = []
            if 'modify' in online_modify_options:
                online_modify_options.remove('modify')
                modify_keys = [key for key in modify if key != 'is_online']
            action_msg = 'perform action(s): %s' % online_modify_options if online_modify_options else ''
            modify_msg = ' and modify: %s' % modify_keys if action_msg else 'modify: %s' % modify_keys
            self.module.warn("Cannot %s%s when volume is offline." % (action_msg, modify_msg))
            modify, actions = {}, []
            if 'rename' in actions:
                # rename can be done if volume is offline.
                actions = ['rename']
            else:
                self.na_helper.changed = False

        if self.na_helper.changed and not self.module.check_mode:
            # always online volume first before other changes.
            # rehost, snapshot_restore and modify requires volume in online state.
            if modify.get('is_online'):
                self.parameters['uuid'] = current['uuid']
                # when moving to online, include parameters that get does not return when volume is offline
                for field in ['volume_security_style', 'group_id', 'user_id', 'percent_snapshot_space']:
                    if self.parameters.get(field) is not None:
                        modify[field] = self.parameters[field]
                self.change_volume_state()
            if 'rename' in actions:
                self.rename_volume()
            if 'rehost' in actions:
                # REST DOES NOT have a volume-rehost equivalent
                self.rehost_volume()
            if 'snapshot_restore' in actions:
                self.snapshot_restore_volume()
            if 'create' in actions:
                response = self.create_volume()
                # if we create using ZAPI and modify only options are set (snapdir_access or atime_update), we need to run a modify.
                # The modify also takes care of efficiency (sis) parameters and snapshot_auto_delete.
                # If we create using REST application, some options are not available, we may need to run a modify.
                # If we create using REST and modify only options are set (snapdir_access or atime_update or snapshot_auto_delete), we need to run a modify.
                # For modify only options to be set after creation wait_for_completion needs to be set.
                # volume should be online for modify.
                current = self.get_volume()
                if current:
                    self.volume_created = True
                    modify = self.set_modify_dict(current, after_create=True)
                    is_online = current.get('is_online')
                    if modify:
                        if is_online:
                            actions.append('modify')
                        else:
                            self.module.warn("Cannot perform actions: modify when volume is offline.")
                # restore this, as set_modify_dict could set it to False
                self.na_helper.changed = True
            if 'delete' in actions:
                self.parameters['uuid'] = current['uuid']
                self.delete_volume(current)
            if 'modify' in actions:
                self.parameters['uuid'] = current['uuid']
                self.take_modify_actions(modify)

        result = netapp_utils.generate_result(self.na_helper.changed, actions, modify, response)
        self.module.exit_json(**result)


def main():
    '''Apply volume operations from playbook'''
    obj = NetAppOntapVolume()
    obj.apply()


if __name__ == '__main__':
    main()
