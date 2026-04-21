====================================
Purestorage.Flasharray Release Notes
====================================

.. contents:: Topics

v1.40.0
=======

Minor Changes
-------------

- purefa_connection - Add new parameters for key refresh and connection refresh, as well as ability to update existing connection
- purefa_info - Added more data to hostgroup volume information to support NVMe connections
- purefa_info - Added tags info to entities that support them
- purefa_network - Addressed issues found in update_interface
- purefa_phonehome - Added ``excludes`` parameter, supported from Purity//FA 6.10.0
- purefa_pod - Fixed pydantic issue from lastest SDK version
- purefa_policy - Added Continuous Availability support for SMB policies

Bugfixes
--------

- purefa_info - Resolves issue with hostgroup info when NVMe connected volumes are in a hostgroup

v1.39.0
=======

Minor Changes
-------------

- purefa_arrayname - Added Fusion support
- purefa_audits - Added Fusion support
- purefa_banner - Added Fusion support
- purefa_connect - Added Fusion support
- purefa_console - Added Fusion support
- purefa_directory - Added Fusion support
- purefa_dirsnap - Added Fusion support
- purefa_ds - Added Fusion support
- purefa_dsrole - Added Fusion support
- purefa_endpoint - Added Fusion support
- purefa_eradication - Added Fusion support
- purefa_export - Added Fusion support
- purefa_fs - Added Fusion support
- purefa_maintenance - Timeout window updated
- purefa_messages - Added Fusion support
- purefa_offload - Added Fusion support
- purefa_policy - Added Fusion support
- purefa_syslog_settings - Added Fusion support
- purefa_timeout - Added Fusion support

Bugfixes
--------

- purefa_eradication - Idempotency fix
- purefa_info - Fixed AttributeError for hgroups subset
- purefa_pg - Fixed AttributeError adding target to PG

v1.38.0
=======

Minor Changes
-------------

- plugins/module_utils/purefa.py - Removed ``get_system`` function as REST v1 no longer supported by Collection
- purefa_dsrole_old - Upgraded to REST v2
- purefa_policy - Upgraded to REST v2
- purefa_volume_tags - Add `tag` parameter to specify tag to be deleted by key name
- purefa_volume_tags - Upgraded to REST v2 and added Fusion support

Bugfixes
--------

- purefa_certs - Resolved error with incorrect use of ``key_size`` for imported certificates
- purefa_host - Fixed Pydantic error when updating preferred_arrays
- purefa_info - Ensured that volumes, hosts, host_groups and transfers are correctly listed for protection groups
- purefa_info - Fixed AttributeError in config section related to SSO SAML2
- purefa_info - Fixed issue with replication connection throttle reporting
- purefa_info - Fixed issue with undo-demote pods not reporting correctly
- purefa_info - Resolved AttributeError in volume subset
- purefa_subnet - Fixed failure when trying to update a subnet with no gateway defined

v1.37.1
=======

Bugfixes
--------

- purefa_network - Resolve typo that causes network updates to not apply correctly

v1.37.0
=======

Minor Changes
-------------

- purefa_connect - Allow asynchronous FC-based replication
- purefa_default_protection - Added Fusion support.
- purefa_info - Added new subsets ``workloads`` and ``presets``
- purefa_info - Converted to use REST 2
- purefa_network - Converted to REST v2
- purefa_ntp - Added Fusion support.
- purefa_pod - Added support for SafeMode protection group configuration
- purefa_syslog - Added Fusion support.
- purefa_user - All AD users to have SSH keys and/or API tokens assigned, even if they have never accessed the FlashArray before. AD users must have ``ad_user`` set as ``true``.

Deprecated Features
-------------------

- purefa_volume_tags - Deprecated due to removal of REST 1.x support. Will be removed in Collection 2.0.0

Bugfixes
--------

- purefa_connect - Ensured that encrypted connections use encrypted connection keys
- purefa_eradication - Fixed idempotency issue
- purefa_eula - Fix AttributeError when first sogning EULA
- purefa_pg - Changing target for PG no longer requires a ``FixedReference``

v1.36.0
=======

Minor Changes
-------------

- purefa_user - No longer tries to expose API tokens as these are not required in the module

Bugfixes
--------

- purefa_vg - Fixed issue where VG QoS updates were being ignored

v1.35.1
=======

Bugfixes
--------

- purefa_ds - Fixed issue with updaing a LDAP configuration fails with a list error.
- purefa_proxy - Fixed issue with incorrect string comparison

v1.35.0
=======

Minor Changes
-------------

- purefa_endpoint - Converted to REST v2
- purefa_fleet - Allows FlashBlades to be added to Fusion fleets if FlashArray is Purity//FA 6.8.5 or higher
- purefa_host - Hosts can be created in realms and renamed within the same realm
- purefa_host - Move function added to allow movement of host to/from realms
- purefa_inventory - Added support for capacity down licensing
- purefa_policy - Added support change a specific quota rule by name
- purefa_subnet - Converted to use REST 2
- purefa_volume - Added support for creating volumes in Realms

Bugfixes
--------

- purefa_volume - Fixed issue for error on volume delete w/o eradicate

v1.34.1
=======

Bugfixes
--------

- purefa_vg - Fixed idempotency issue when clearing volume group QoS settings
- purefa_vg - Fixed issue with creating non-QoS volume groups

v1.34.0
=======

Minor Changes
-------------

- purefa_timeout - Convert to REST v2
- purefa_user - Added parameter for SSH public keys and API token timeout
- purefa_user - Converted to use REST v2
- purefa_user - When changing API token or timout for an existing user, the user role must be provided or it will revert to ``readonly``

Bugfixes
--------

- purefa_dsrole - Fixed bug with DS role having no group or group base cannot be updated
- purefa_pgsnap - Fixed issue with overwrite failing
- purefa_vlan - Allow LACP bonds to be subnet interfaces

v1.33.1
=======

Bugfixes
--------

- purefa_host - Fix issue with no VLAN provided when Purity//FA is a recent version.
- purefa_host - Fix issue with setting preferred_arrays for a host.

v1.33.0
=======

Minor Changes
-------------

- all - Minimum ``py-pure-client`` version increased to 1.57.0 due to release of Realms feature
- purefa_hg - Added support for Fusion
- purefa_host - Added Fusion support
- purefa_info - Add performance data for network interfaces
- purefa_info - Added new section ``realms``.
- purefa_info - Added new subset ``fleet``
- purefa_info - Deprecate ``network.<interface>.hwaddr`` - replaced by ``network.<interface>.mac_address``
- purefa_info - Deprecate ``network.<interface>.slaves`` - replaced by ``network.<interface>.subinterfaces``
- purefa_info - VNC feature deprecated from Purity//FA 6.8.0.
- purefa_pg - Added Fusion support.
- purefa_pgsched - Added support for Fusion.
- purefa_pgsnap - Added support for Fusion.
- purefa_pod_replica - Added Fusion support.
- purefa_pods - Added support for Fusion with ``context`` parameter.
- purefa_smtp - Added support for additional parameters, including encryption mode and email prefixs and email sender name.
- purefa_snap - Added Fusion support.
- purefa_vg - Added support for Fusion
- purefa_vlan - Convert to REST v2
- purefa_vnc - VNC feature deprecated from Purity//FA 6.8.0.
- purefa_volume - Added ``context`` parameter to support fleet operations

Bugfixes
--------

- purefa_ds - Fixed issue with trying to create a pre-existing system-defined role
- purefa_hg - Fixed issue when ``check_mode = true`` not reporting correct status when adding new hosts to hostgroup.
- purefa_pod - Errored out when setting failover preference for pod
- purefa_ra - Fixed duration check logic
- purefa_volume - Fixes issue of moving protected volume into volume group

Known Issues
------------

- All Fusion fleet members will be assumed to be at the same Purity//FA version level as the array connected to by Ansible.
- FlashArray//CBS is not currently supported as a member of a Fusion fleet

New Modules
-----------

- purestorage.flasharray.purefa_fleet - Manage Fusion Fleet
- purestorage.flasharray.purefa_realm - Manage realms on Pure Storage FlashArrays

v1.32.0
=======

Minor Changes
-------------

- purefa_dsrole - Add support for non-system-defined directory service roles with new parameter `name`
- purefa_info - Add ``enabled`` value for network subnets
- purefa_info - Add ``policies` list of dicts to ``filesystem`` subset for each share.
- purefa_info - Add ``time_remaining`` field for non-deleted directory snapshots
- purefa_info - Expose directory service role management access policies if they exist
- purefa_info - Exposed password policy information
- purefa_info - SnaptoNFS support removed from Purity//FA 6.6.0 and higher.
- purefa_info - Update KMIP information collection to use REST v2, exposing full certifcate content
- purefa_offload - Add support for S3 Offload ``uri`` and ``auth_region`` parameters
- purefa_pgsnap - Expose created protection group snapshot data in the module return dict
- purefa_policy - New policy type of ``password`` added. Currently the only default management policy can be updated
- purefa_subnet - Remove default value for MTU t ostop restting to default on enable/disable of subnet. Creation will still default to 1500 if not provided.

Bugfixes
--------

- purefa_alert - Fix unreferenced variable error
- purefa_audits - Fix issue when ``start`` parameter not supplied
- purefa_dirsnap - Fixed issues with ``keep_for`` setting and issues related to recovery of deleted snapshots
- purefa_dsrole - Fixed bug in role creation.
- purefa_eradication - Fix incorrect timer settings
- purefa_info - Cater for zero used space in NFS offloads
- purefa_info - ``exports`` dict for each share changed to a list of dicts in ``filesystm`` subset
- purefa_inventory - Fixed quiet failures due to attribute errors
- purefa_network - Allow LACP bonds to be children of a VIF
- purefa_network - Fix compatability issue with ``netaddr>=1.2.0``
- purefa_ntp - Fix issue with deletion of NTP servers
- purefa_offload - Corrected version check logic
- purefa_pod - Allow pd to be deleted with contents if ``delete_contents`` specified
- purefa_sessions - Correctly report sessions with no start or end time
- purefa_smtp - Fixed SMTP deletion issue
- purefa_snmp - Fix issues with deleting SNMP entries
- purefa_snmp_agent - Fix issues with deleting v3 agent
- purefa_volume - Added error message to warn about moving protected volume
- purefa_volume - Errors out when pgroup and add_to_pgs used incorrectly
- purefa_volume - Fixed issue of unable to move volume from pod to vgroup

v1.31.1
=======

Bugfixes
--------

- purefa_dsrole - Fix version check logic

v1.31.0
=======

Release Summary
---------------

| NOTE: ``purefa_ds`` module has been determined to require a minimum Purity//FA version
| of 6.6.0
| To facilitate this functionality in versions 6.1.x - 6.5.x please use the module
| ``purefa_dsrole_old`` 

Minor Changes
-------------

- purefa_token - Add ``disable_warnings`` support

Bugfixes
--------

- purefa_pod - Fix issue with pod not creating correctly
- purefa_subnet - Initialize varaible correctly
- purefa_syslog_settings - Initialize varaible correctly
- purefa_volume - Fixes ``eradicate`` so it doesn't report success when it hasn't actually eradicated
- purefa_volume - Fixes ``volfact`` response when in ``check_mode``
- purefa_volume - Fixes issue where malformed ``volfact`` will cause the ``move`` to apparently fail.

New Modules
-----------

- purestorage.flasharray.purefa_dsrole_old - Configure FlashArray Directory Service Roles (pre-6.6.3)

v1.30.2
=======

Bugfixes
--------

- purefa_info - Fixed issue trying to collect deleted volumes perfomance stats
- purefa_volume - Fix issue with creating volume using old Purity version (6.1.19)

v1.30.1
=======

Bugfixes
--------

- purefa_dsrole - Fix function name typo
- purefa_pg - Fix parameter name typo

v1.30.0
=======

Minor Changes
-------------

- purefa_connect - Add support for TLS encrypted array connections
- purefa_info - Fix regression of code that caused volume host connectivity info to be lost
- purefa_info - Provide array connection path information

Bugfixes
--------

- purefa_hg - Fix edge case with incorrectly deleted hostgroup when empty array sent for volumes or hosts

v1.29.1
=======

Bugfixes
--------

- purefa_info - Fix typo from PR

v1.29.0
=======

Minor Changes
-------------

- all - add ``disable_warnings`` parameters
- purefa_alert - Add new ``state`` of ``test`` to check alert manager configuration
- purefa_alert - Converted to REST v2
- purefa_connect - Convert to REST v2
- purefa_console - Convert to REST v2
- purefa_dns - Convert to REST v2
- purefa_ds - Add new ``state`` of ``test`` to check directory services configuration
- purefa_ds - Convert to REST v2 removing all parameters used unsupported Purity versions
- purefa_dsrole - Convert to REST v2
- purefa_info - Add SMTP server information
- purefa_kmip - Add new ``state`` of ``test`` to check KMIP object configuration
- purefa_ntp - Add new ``state`` of ``test`` to check NTP configuration
- purefa_phonehome - Convert to REST v2
- purefa_pod - Add ``delete_contents`` parameter for eradication of pods.
- purefa_pod - Add support for ``throttle`` parameter from REST 2.31.
- purefa_pod - Convert to REST v2.
- purefa_ra - Add new ``state`` of ``test`` to check remote support configuration
- purefa_saml - Add new ``state`` of ``test`` to check SAML2 IdP configuration
- purefa_snmp - Add new ``state`` of ``test`` to check SNMP manager configuration
- purefa_syslog - Add new ``state`` of ``test`` to check syslog server configuration

Bugfixes
--------

- purefa_info - Resolve issue with performance stats trying to report for remote hosts

New Modules
-----------

- purestorage.flasharray.purefa_audits - List FlashArray Audit Events
- purestorage.flasharray.purefa_sessions - List FlashArray Sessions

v1.28.1
=======

Bugfixes
--------

- purefa_network - Fix issue with clearing network interface addresses
- purefa_network - Resolve issue when setting a network port on a new array
- purefa_policy - Enhanced idempotency for snapshot policy rules

v1.28.0
=======

Minor Changes
-------------

- purefa_hg - Add support to rename existing hostgroup
- purefa_info - Add ``is_local`` parameter for snapshots
- purefa_info - Add performance data for some subsets
- purefa_info - Add service_mode to identify if array is Evergreen//One or standard FlashArray
- purefa_pg - Enhance ``state absent`` to work on volumes, hosts and hostgroups
- purefa_snap - Add ``created_epoch`` parameter in response

Bugfixes
--------

- purefa_host - Allows all current host inititators to be correctly removed
- purefa_host - Fix idempotency issue with connected volume
- purefa_volume - Ensure module response for creation of volume and rerun are the same
- purefa_volume - Fix idempotency issue with delete volume

v1.27.0
=======

Release Summary
---------------

| This release changes the minimum supported Purity//FA version.
|
| The minimum supported Purity//FA version increases to 6.1.0.
| All previous versions are classed as EOL by Pure Storage support.
|
| This change is to support the full integration to Purity//FA REST v2.x

Minor Changes
-------------

- purefa_arrayname - Convert to REST v2
- purefa_eula - Only sign if not previously signed. From REST 2.30 name, title and company are no longer required
- purefa_info - Add support for controller uptime from Purity//FA 6.6.3
- purefa_inventory - Convert to REST v2
- purefa_ntp - Convert to REST v2
- purefa_offload - Convert to REST v2
- purefa_pgsnap - Module now requires minimum FlashArray Purity//FA 6.1.0
- purefa_ra - Add ``present`` and ``absent`` as valid ``state`` options
- purefa_ra - Add connecting as valid status of RA to perform operations on
- purefa_ra - Convert to REST v2
- purefa_syslog - ``name`` becomes a required parameter as module converts to full REST 2 support
- purefa_vnc - Convert to REST v2

Bugfixes
--------

- purefa_certs - Allow certificates of over 3000 characters to be imported.
- purefa_info - Resolved issue with KeyError when LACP bonds are in use
- purefa_inventory - Fix issue with iSCSI-only FlashArrays
- purefa_pgsnap - Add support for restoring volumes connected to hosts in a host-based protection group and hosts in a hostgroup-based protection group.

v1.26.0
=======

Minor Changes
-------------

- purefa_policy - Add SMB user based enumeration parameter
- purefa_policy - Remove default setting for nfs_version to allow for change of version at policy level

Bugfixes
--------

- purefa_ds - Fix issue with SDK returning empty data for data directory services even when it does exist
- purefa_policy - Fix incorrect call of psot instead of patch for NFS policies

v1.25.0
=======

Minor Changes
-------------

- all - ``distro`` package added as a pre-requisite
- multiple - Remove packaging pre-requisite.
- multiple - Where only REST 2.x endpoints are used, convert to REST 2.x methodology.
- purefa_info - Expose NFS security flavor for policies
- purefa_info - Expose cloud capacity details if array is a Cloud Block Store.
- purefa_policy - Added NFS security flavors for accessing files in the mount point.

v1.24.0
=======

Minor Changes
-------------

- purefa_dns - Added facility to add a CA certifcate to management DNS and check peer.
- purefa_snap - Add support for suffix on remote offload snapshots

Bugfixes
--------

- purefa_dns - Fixed attribute error on deletion of management DNS
- purefa_pgsched - Fixed issue with disabling schedules
- purefa_pgsnap - Fixed incorrect parameter name

New Modules
-----------

- purestorage.flasharray.purefa_hardware - Manage FlashArray Hardware Identification

v1.23.0
=======

Minor Changes
-------------

- purefa_info - Add NSID value for NVMe namespace in `hosts` response
- purefa_info - Subset `pgroups` now also provides a new dict called `deleted_pgroups`
- purefa_offload - Remove `nfs` as an option when Purity//FA 6.6.0 or higher is detected

Bugfixes
--------

- purefa_cert - Fixed issue where parts of the subject where not included in the CSR if they did not exist in the currently used cert.
- purefa_pg - Allows a protection group to be correctly created when `target` is specified as well as other objects, such as `volumes` or `hosts`

v1.22.0
=======

Minor Changes
-------------

- purefa_eradication - Added support for disabled and enabled timers from Purity//FA 6.4.10
- purefa_info - Add array subscription data
- purefa_info - Added `nfs_version` to policies and rules from Purity//FA 6.4.10
- purefa_info - Added `total_used` to multiple sections from Purity//FA 6.4.10
- purefa_info - Prive array timezone from Purity//FA 6.4.10
- purefa_info - Report NTP Symmetric key presence from Purity//FA 6.4.10
- purefa_network - Add support for creating/modifying VIF and LACP_BOND interfaces
- purefa_network - `enabled` option added. This must now be used instead of state=absent to disable a physical interface as state=absent can now fully delete a non-physical interface
- purefa_ntp - Added support for NTP Symmetric Key from Purity//FA 6.4.10s
- purefa_pgsched - Change `snap_at` and `replicate_at` to be AM or PM hourly
- purefa_pgsnap - Add protection group snapshot rename functionality
- purefa_policy - Added support for multiple NFS versions from Purity//FA 6.4.10
- purefa_vg - Add rename parameter

Bugfixes
--------

- purefa_ds - Fixes error when enabling directory services while a bind_user is set on the array and a bind_password is not.
- purefa_ds - Fixes issue with creating a new ds configuration while setting force_bind_password as "false".
- purefa_host - Fix incorrect calling of "module.params".
- purefa_info - Added missing alerts subset name
- purefa_info - Fixed attribute errors after EUC changes
- purefa_info - Fixed issue with replica links in unknown state
- purefa_info - Fixed parameter error when enabled and disabled timers are different values on purity 6.4.10+ arrays.
- purefa_info - Fixed py39 specific bug with multiple DNS entries
- purefa_network - Allow `gateway` to be set as `0.0.0.0` to remove an existing gateway address
- purefa_network - Fixed IPv6 support issues
- purefa_network - Fixed idempotency issue when gateway not modified
- purefa_pgsched - Fixed bug with an unnecessary substitution
- purefa_pgsnap - Enabled to eradicate destroyed snapshots.
- purefa_pgsnap - Ensure that `now` and `remote` are mutually exclusive.
- purefa_snap - Fixed incorrect calling logic causing failure on remote snapshot creation
- purefa_subnet - Fixed IPv4 gateway removal issue.
- purefa_subnet - Fixed IPv6 support issues.

New Modules
-----------

- purestorage.flasharray.purefa_file - Manage FlashArray File Copies

v1.21.0
=======

Minor Changes
-------------

- purefa_info - Add `port_connectivity` information for hosts
- purefa_info - Add promotion status information for volumes
- purefa_offload - Added a new profile parameter.
- purefa_pgsnap - Added new parameter to support snapshot throttling
- purefa_snap - Added new parameter to support snapshot throttling

Bugfixes
--------

- purefa_certs - Resolved CSR issue and require export_file for state sign.
- purefa_info - Fix serial number generation issue for vVols
- purefa_snap - Fixed issue with remote snapshot retrieve. Mainly a workaround to an issue with Purity REST 1.x when remote snapshots are searched.
- purefa_volume - Fixed bug with NULL suffix for multiple volume creation.

v1.20.0
=======

Minor Changes
-------------

- purefa_info - Added support for autodir policies
- purefa_policy - Added support for autodir policies
- purefa_proxy - Add new protocol parameter, defaults to https

Bugfixes
--------

- purefa_pgsched - Resolved idempotency issue with snap and replication enabled flags
- purefa_pgsnap - Fixed issue with eradicating deleted pgsnapshot
- purefa_pgsnap - Update the accepted suffixes to include also numbers only. Fixed the logic to retrieve the latest completed snapshot
- purefa_policy - Set user_mapping parameter default to True

v1.19.1
=======

Bugfixes
--------

- purefa_info - Fixed missing arguments for google_offload and pods

v1.19.0
=======

New Modules
-----------

- purestorage.flasharray.purefa_logging - Manage Pure Storage FlashArray Audit and Session logs

v1.18.0
=======

Release Summary
---------------

| FlashArray Collection v1.18 removes module-side support for Python 2.7.
| The minimum required Python version for the FlashArray Collection is Python 3.6.

Minor Changes
-------------

- purefa_hg - Changed parameter hostgroup to name for consistency. Added hostgroup as an alias for backwards compatability.
- purefa_hg - Exit gracefully, rather than failing when a specified volume does not exist
- purefa_host - Exit gracefully, rather than failing when a specified volume does not exist
- purefa_info - Added network neighbors info to `network` subset
- purefa_pod - Added support for pod quotas (from REST 2.23)
- purefa_snap - New response of 'suffix' when snapshot has been created.
- purefa_volume - Added additional volume facts for volume update, or for no change

Bugfixes
--------

- purefa_network - Resolves network port setting idempotency issue
- purefa_pg - Fixed issue where volumes could not be added to a PG when one of the arrays was undergoing a failover.
- purefa_snap - Fixed issue system generated suffixes not being allowed and removed unnecessary warning message.

v1.17.2
=======

v1.17.1
=======

Bugfixes
--------

- purefa_info - Fix REST response backwards compatibility issue for array capacity REST response
- purefa_info - Resolves issue in AC environment where REST v2 host list mismatches REST v1 due to remote hosts.
- purefa_info - Resolves issue with destroyed pgroup snapshot on an offload target not have a time remaining value
- purefa_pg - Resolves issue with destroyed pgroup snapshot on an offload target not have a time remaining value

v1.17.0
=======

Minor Changes
-------------

- purefa_network - Added support for NVMe-RoCE and NVMe-TCP service types
- purefa_user - Added Ops Admin role to choices
- purefa_vlan - Added support for NVMe-TCP service type

Bugfixes
--------

- purefa_host - Fixed parameter name
- purefa_info - Fix missing FC target ports for host
- purefa_pgsched - Fix error when setting schedule for pod based protection group
- purefa_vg - Fix issue with VG creation on newer Purity versions
- purefa_volume - Ensure promotion_stateus is returned correctly on creation
- purefa_volume - Fix bug when overwriting volume using invalid parmaeters
- purefa_volume - Fixed idempotency bug when creating volumes with QoS

v1.16.2
=======

v1.16.1
=======

Bugfixes
--------

- purefa_volume - Fixed issue with promotion status not being called correctly

v1.16.0
=======

Minor Changes
-------------

- purefa_host - Add support for VLAN ID tagging for a host (Requires Purity//FA 6.3.5)
- purefa_info - Add new subset alerts
- purefa_info - Added default protection information to `config` section
- purefa_volume - Added support for volume promotion/demotion

Bugfixes
--------

- purefa - Remove unneeded REST version check as causes issues with REST mismatches
- purefa_ds - Fixed dict syntax error
- purefa_info - Fiexed issue with DNS reporting in Purity//FA 6.4.0 with non-FA-File system
- purefa_info - Fixed error in policies subsection due to API issue
- purefa_info - Fixed race condition with protection groups
- purefa_smtp - Fix parameter name

New Modules
-----------

- purestorage.flasharray.purefa_snmp_agent - Configure the FlashArray SNMP Agent

v1.15.0
=======

Minor Changes
-------------

- purefa_network - Added support for servicelist updates
- purefa_vlan - Extend VLAN support to cover NVMe-RoCE and file interfaces

Bugfixes
--------

- purefa.py - Fix issue in Purity versions numbers that are for development versions
- purefa_policy - Fixed missing parameters in function calls
- purefa_vg - Fix typeerror when using newer Purity versions and setting VG QoS

v1.14.0
=======

Minor Changes
-------------

- purefa_ad - Add support for TLS and joining existing AD account
- purefa_dns - Support multiple DNS configurations from Puritry//FA 6.3.3
- purefa_info - Add NFS policy user mapping status
- purefa_info - Add support for Virtual Machines and Snapshots
- purefa_info - Ensure global admin lockout duration is measured in seconds
- purefa_info - Support multiple DNS configurations
- purefa_inventory - Add REST 2.x support and SFP details for Purity//FA 6.3.4 and higher
- purefa_inventory - Change response dict name to `purefa_inv` so doesn't clash with info module response dict
- purefa_inventory - add chassis information to inventory
- purefa_pg - Changed parameter `pgroup` to `name`. Allow `pgroup` as alias for backwards compatability.
- purefa_policy - Add ``all_squash``, ``anonuid`` and ``anongid`` to NFS client rules options
- purefa_policy - Add support for NFS policy user mapping
- purefa_volume - Default Protection Group support added for volume creation and copying from Purity//FA 6.3.4

Bugfixes
--------

- purefa_dns - Corrects logic where API responds with an empty list rather than a list with a single empty string in it.
- purefa_ds - Add new parameter `force_bind_password` (default = True) to allow idempotency for module
- purefa_hg - Ensure volume disconnection from a hostgroup is idempotent
- purefa_ntp - Corrects workflow so that the state between desired and current are checked before marking the changed flag to true during an absent run
- purefa_pg - Corredt issue when target for protection group is not correctly amended
- purefa_pg - Ensure deleted protection group can be correctly recovered
- purefa_pg - Fix idempotency issue for protection group targets
- purefa_pgsched - Allow zero as a valid value for appropriate schedule parameters
- purefa_pgsched - Fix issue where 0 was not correctly handled for replication schedule
- purefa_pgsnap - Resolved intermittent error where `latest` snapshot is not complete and can fail. Only select latest completed snapshot to restore from.

New Modules
-----------

- purestorage.flasharray.purefa_default_protection - Manage SafeMode default protection for a Pure Storage FlashArray
- purestorage.flasharray.purefa_messages - List FlashArray Alert Messages

v1.13.0
=======

Minor Changes
-------------

- purefa_fs - Add support for replicated file systems
- purefa_info - Add QoS information for volume groups
- purefa_info - Add info for protection group safe mode setting (Requires Purity//FA 6.3.0 or higher)
- purefa_info - Add info for protection group snapshots
- purefa_info - Add priority adjustment information for volumes and volume groups
- purefa_info - Split volume groups into live and deleted dicts
- purefa_pg - Add support for protection group SafeMode. Requires Purity//FA 6.3.0 or higher
- purefa_policy - Allow directories in snapshot policies to be managed
- purefa_vg - Add DMM Priority Adjustment support
- purefa_volume - Add support for DMM Priority Adjustment
- purefa_volume - Provide volume facts for volume after recovery

Bugfixes
--------

- purefa_host - Allow multi-host creation without requiring a suffix string
- purefa_info - Fix issue where remote arrays are not in a valid connected state
- purefa_policy - Fix idempotency issue with quota policy rules
- purefa_policy - Fix issue when creating multiple rules in an NFS policy

v1.12.1
=======

Minor Changes
-------------

- All modules - Change examples to use FQCN for module

Bugfixes
--------

- purefa_info - Fix space reporting issue
- purefa_subnet - Fix subnet update checks when no gateway in existing subnet configuration

v1.12.0
=======

Minor Changes
-------------

- purefa_admin - New module to set global admin settings, inclusing SSO
- purefa_dirsnap - Add support to rename directory snapshots not managed by a snapshot policy
- purefa_info - Add SAML2SSO configutration information
- purefa_info - Add Safe Mode status
- purefa_info - Fix Active Directory configuration details
- purefa_network - Resolve bug stopping management IP address being changed correctly
- purefa_offload - Add support for multiple, homogeneous, offload targets
- purefa_saml - Add support for SAML2 SSO IdPs
- purefa_volume - Provide volume facts in all cases, including when no change has occured.

Deprecated Features
-------------------

- purefa_sso - Deprecated in favor of M(purefa_admin). Will be removed in Collection 2.0

Bugfixes
--------

- purefa_certs - Allow a certificate to be imported over an existing SSL certificate
- purefa_eula - Reolve EULA signing issue
- purefa_network - Fix bug introduced with management of FC ports
- purefa_policy - Fix issue with SMB Policy creation

Known Issues
------------

- purefa_admin - Once `max_login` and `lockout` have been set there is currently no way to rest these to zero except through the FlashArray GUI

New Modules
-----------

- purestorage.flasharray.purefa_admin - Configure Pure Storage FlashArray Global Admin settings
- purestorage.flasharray.purefa_saml - Manage FlashArray SAML2 service and identity providers

v1.11.0
=======

Minor Changes
-------------

- purefa_host - Deprecate ``protocol`` parameter. No longer required.
- purefa_info - Add NVMe NGUID value for volumes
- purefa_info - Add array, volume and snapshot detailed capacity information
- purefa_info - Add deleted members to volume protection group info
- purefa_info - Add snapshot policy rules suffix support
- purefa_info - Remove directory_services field. Deprecated in Collections 1.6
- purefa_policy - Add snapshot policy rules suffix support
- purefa_syslog_settings - Add support to manage global syslog server settings
- purefa_volume - Add NVMe NGUID to response dict

Bugfixes
--------

- purefa_subnet - Add regex to check for correct dsubnet name
- purefa_user - Add regex to check for correct username

v1.10.0
=======

Minor Changes
-------------

- purefa_ds - Add ``join_ou`` parameter for AD account creation
- purefa_kmip - Add support for KMIP server management

New Modules
-----------

- purestorage.flasharray.purefa_kmip - Manage FlashArray KMIP server objects

v1.9.0
======

Minor Changes
-------------

- purefa_ad - Increase number of kerberos and directory servers to be 3 for each.
- purefa_ad - New module to manage Active Directory accounts
- purefa_dirsnap - New modules to manage FA-Files directory snapshots
- purefa_eradication - New module to set deleted items eradication timer
- purefa_info - Add data-at-rest and eradication timer information to default dict
- purefa_info - Add high-level count for directory quotas and details for all FA-Files policies
- purefa_info - Add volume Page 83 NAA information for volume details
- purefa_network - Add support for enable/diable FC ports
- purefa_policy - Add support for FA-files Directory Quotas and associated rules and members
- purefa_sso - Add support for setting FlashArray Single Sign-On from Pure1 Manage
- purefa_volume - Add volume Page 83 NAA information to response dict

Bugfixes
--------

- purefa_host - Rollback host creation if initiators already used by another host
- purefa_policy - Fix incorrect protocol endpoint invocation
- purefa_ra - fix disable feature for remote assist, this didn't work due to error in check logic
- purefa_vg - Correct issue when setting or changing Volume Group QoS
- purefa_volume - Fix incorrect API version check for ActiveDR support

New Modules
-----------

- purestorage.flasharray.purefa_ad - Manage FlashArray Active Directory Account
- purestorage.flasharray.purefa_dirsnap - Manage FlashArray File System Directory Snapshots
- purestorage.flasharray.purefa_eradication - Configure Pure Storage FlashArray Eradication Timer
- purestorage.flasharray.purefa_sso - Configure Pure Storage FlashArray Single Sign-On

v1.8.0
======

Minor Changes
-------------

- purefa_certs - New module for managing SSL certificates
- purefa_volume - New parameter pgroup to specify an existing protection group to put crwated volume(s) in.

Bugfixes
--------

- purefa_dsrole - If using None for group or group_base incorrect change state applied
- purefa_network - Allow gateway paremeter to be set as None - needed for non-routing iSCSI ports
- purefa_pg - Check to ensure protection group name meets naming convention
- purefa_pgsnap - Fail with warning if trying to restore to a stretched ActiveCluster pod
- purefa_volume - Ensure REST version is high enough to support promotion_status

New Modules
-----------

- purestorage.flasharray.purefa_certs - Manage FlashArray SSL Certificates

v1.7.0
======

Minor Changes
-------------

- purefa_maintenance - New module to set maintenance windows
- purefa_pg - Add support to rename protection groups
- purefa_syslog - Add support for naming SYSLOG servers for Purity//FA 6.1 or higher

Bugfixes
--------

- purefa_info - Fix missing protection group snapshot info for local snapshots
- purefa_info - Resolve crash when an offload target is offline
- purefa_pgsnap - Ensure suffix rules only implemented for state=present
- purefa_user - Do not allow role changed for breakglass user (pureuser)
- purefa_user - Do not change role for existing user unless requested

New Modules
-----------

- purestorage.flasharray.purefa_maintenance - Configure Pure Storage FlashArray Maintence Windows

v1.6.2
======

Bugfixes
--------

- purefa_volume - Fix issues with moving volumes into demoted or linked pods

v1.6.0
======

Minor Changes
-------------

- purefa_connect - Add support for FC-based array replication
- purefa_ds - Add Purity v6 support for Directory Services, including Data DS and updating services
- purefa_info - Add support for FC Replication
- purefa_info - Add support for Remote Volume Snapshots
- purefa_info - Update directory_services dictionary to cater for FA-Files data DS. Change DS dict forward. Add deprecation warning.
- purefa_ntp - Ignore NTP configuration for CBS-based arrays
- purefa_pg - Add support for Protection Groups in AC pods
- purefa_snap - Add support for remote snapshot of individual volumes to offload targets

Bugfixes
--------

- purefa_hg - Ensure all hostname chacks are lowercase for consistency
- purefa_pgsnap - Add check to ensure suffix name meets naming conventions
- purefa_pgsnap - Ensure pgsnap restores work for AC PGs
- purefa_pod - Ensure all pod names are lowercase for consistency
- purefa_snap - Update suffix regex pattern
- purefa_volume - Add missing variable initialization

v1.5.1
======

Minor Changes
-------------

- purefa_host - Add host rename function
- purefa_host - Add support for multi-host creation
- purefa_vg - Add support for multiple vgroup creation
- purefa_volume - Add support for multi-volume creation

Bugfixes
--------

- purefa.py - Resolve issue when pypureclient doesn't handshake array correctly
- purefa_dns - Fix idempotency
- purefa_volume - Alert when volume selected for move does not exist

v1.5.0
======

Minor Changes
-------------

- purefa_apiclient - New module to support API Client management
- purefa_directory - Add support for managed directories
- purefa_export - Add support for filesystem exports
- purefa_fs - Add filesystem management support
- purefa_hg - Enforce case-sensitivity rules for hostgroup objects
- purefa_host - Enforce hostname case-sensitivity rules
- purefa_info - Add support for FA Files features
- purefa_offload - Add support for Google Cloud offload target
- purefa_pg - Enforce case-sensitivity rules for protection group objects
- purefa_policy - Add support for NFS, SMB and Snapshot policy management

Bugfixes
--------

- purefa_host - Correctly remove host that is in a hostgroup
- purefa_volume - Fix failing idempotency on eradicate volume

New Modules
-----------

- purestorage.flasharray.purefa_apiclient - Manage FlashArray API Clients
- purestorage.flasharray.purefa_directory - Manage FlashArray File System Directories
- purestorage.flasharray.purefa_export - Manage FlashArray File System Exports
- purestorage.flasharray.purefa_fs - Manage FlashArray File Systems
- purestorage.flasharray.purefa_policy - Manage FlashArray File System Policies

v1.4.0
======

Release Summary
---------------

| Release Date: 2020-08-08
| This changlelog describes all changes made to the modules and plugins included in this collection since Ansible 2.9.0

Major Changes
-------------

- purefa_console - manage Console Lock setting for the FlashArray
- purefa_endpoint - manage VMware protocol-endpoints on the FlashArray
- purefa_eula - sign, or resign, FlashArray EULA
- purefa_inventory - get hardware inventory information from a FlashArray
- purefa_network - manage the physical and virtual network settings on the FlashArray
- purefa_pgsched - manage protection group snapshot and replication schedules on the FlashArray
- purefa_pod - manage ActiveCluster pods in FlashArrays
- purefa_pod_replica - manage ActiveDR pod replica links in FlashArrays
- purefa_proxy - manage the phonehome HTTPS proxy setting for the FlashArray
- purefa_smis - manage SMI-S settings on the FlashArray
- purefa_subnet - manage network subnets on the FlashArray
- purefa_timeout - manage the GUI idle timeout on the FlashArray
- purefa_vlan - manage VLAN interfaces on the FlashArray
- purefa_vnc - manage VNC for installed applications on the FlashArray
- purefa_volume_tags - manage volume tags on the FlashArray

Minor Changes
-------------

- purefa_hg - All LUN ID to be set for single volume
- purefa_host - Add CHAP support
- purefa_host - Add support for Cloud Block Store
- purefa_host - Add volume disconnection support
- purefa_info - Certificate times changed to human readable rather than time since epoch
- purefa_info - new options added for information collection
- purefa_info - return dict names changed from ``ansible_facts`` to ``ra_info`` and ``user_info`` in approproate sections
- purefa_offload - Add support for Azure
- purefa_pgsnap - Add offload support
- purefa_snap - Allow recovery of deleted snapshot
- purefa_vg - Add QoS support

Bugfixes
--------

- purefa_host - resolve hostname case inconsistencies
- purefa_host - resolve issue found when using in Pure Storage Test Drive
