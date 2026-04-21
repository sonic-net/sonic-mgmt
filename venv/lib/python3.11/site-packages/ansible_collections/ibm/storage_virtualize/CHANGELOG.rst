====================================
IBM Storage Virtualize Release Notes
====================================

.. contents:: Topics

v2.7.4
======

Release Summary
---------------

Added fix for nginx timeout, playbooks for host rescan during partition migration, changed requirements as per ansible collection guidlelines and converted README files to README.md format.

Minor Changes
-------------

- ibm_svc_host.py - Added support for adding and removing preferred location, and IO Groups
- ibm_svc_hostcluster.py - Added support for adding site
- ibm_svc_manage_volume - Added support for warning parameter

Bugfixes
--------

- ibm_svc_ssh - Added fix for nginx timeout
- ibm_svc_utils - Added fix for nginx timeout

v2.7.3
======

Release Summary
---------------

Introduced new module ibm_sv_manage_flashsystem_grid and added support for highly-available snapshots, restoring highly-available volumes and volumegroups from local snapshots, vdisk protection settings, managing host with different options, and truststore for flashsystem grid and other volume-related tasks.

Minor Changes
-------------

- ibm_sv_manage_replication_policy - Added support for highly-available snapshots
- ibm_sv_manage_snapshot- Add support for restoring highly-available volumes and volumegroups from local snapshots
- ibm_sv_manage_truststore_for_replication - Added support for creating truststore for flashsystem grid
- ibm_svc_host - Added support for specifying host location in PBHA, support for FDMI discovery, suppressing offline alert, updating IO groups, and for specifying fcscsi and iscsi protocols during host creation
- ibm_svc_info - Added support for flashsystem grid
- ibm_svc_initial_setup - Added support for vdisk protection settings, iscsiauthmethod and improved REST API calls
- ibm_svc_manage_flashcopy - Added support for enabling cleanrate during flashcopy creation and update
- ibm_svc_manage_replication - Added support for highly-available snapshots
- ibm_svc_manage_volume - Added support for unmapping hosts, remote-copy and flashcopy during volume deletion
- ibm_svc_mdisk - Added support for updating tier
- ibm_svc_mdiskgrp - Improved probe function for storage pools

Bugfixes
--------

- ibm_svc_manage_replication - Added checks for mutually-exclusive parameters and policing for updating remote-copy relationship

New Modules
-----------

- ibm_sv_manage_flashsystem_grid - Manages operations of Flashsystem grid containing multiple Storage Virtualize systems

v2.6.0
======

Release Summary
---------------

Added support for partition migration, PBRHA (3-site), portset linking for PBHA, truststore properties changes, added playbooks for migrating GMCV (Global Mirror with Change Volumes) and GM (Global Mirror) to PBR (Policy-Based Replication), migrating HyperSwap to PBHA (Policy-Based High Availability) setup, deleting objects from PBHA partition and for PBRHA (3-site) setup and cleanup.

Minor Changes
-------------

- ibm_sv_manage_replication_policy - Added support for disaster recovery
- ibm_sv_manage_storage_partition - Added support for partition migration and disaster recovery
- ibm_sv_manage_truststore_for_replication - Added support for enabling various options (syslog, RESTAPI, vasa, ipsec, snmp and email) for existing truststore
- ibm_svc_initial_setup - Added support for flashcopy default grain size and SI (Storage Insights) to be able to control partition migration
- ibm_svc_manage_portset - Added support for linking portset of 2 clusters for PBHA
- ibm_svc_manage_volume - Added support for converting thinclone volume(s) to clone
- ibm_svc_manage_volumegroup - Added support for disaster recovery and converting thinclone volumegroup to clone

Bugfixes
--------

- ibm_svc_manage_flashcopy - Added support for creating flashcopy with existing target volume

v2.5.0
======

Release Summary
---------------

Added support for syslog server, high-speed replication portset, NNMeFC host, satask and sainfo commands, for moving existing objects into Policy-Based High Availability (PBHA), added playbook for setting up new PBHA environment, and improved policy-based replication playbook.

Minor Changes
-------------

- ibm_sv_manage_storage_partition - Added support for creating draft partition, publishing a draft partition, and merging 2 partitions
- ibm_sv_manage_syslog_server - Added support for creating TLS syslog server, and modifying existing UDP or TCP servers to TLS server
- ibm_sv_manage_truststore_for_replication - Added support for enabling various options (syslog, RESTAPI, vasa, ipsec, snmp and email) during truststore creation
- ibm_svc_host - Added support to add host into draft partition and to create an NVMeFC host
- ibm_svc_manage_portset - Added support to create a high-speed replication portset
- ibm_svc_manage_volumegroup - Added support to add existing volumegroups into draft partition
- ibm_svcinfo_command - Added support for sainfo commands
- ibm_svctask_command - Added support for satask commands

Bugfixes
--------

- ibm_svc_manage_callhome - Added support to change a subset of proxy settings

v2.4.1
======

Release Summary
---------------

Added support for drive state and task management, auto-download of security patches, and info enhancements.

Minor Changes
-------------

- ibm_sv_manage_security - Added support to allow automatic download of security patches
- ibm_svc_info - Added support to display concise view of all SVC objects not covered by I(gather_subset), detailed view for all SVC objects, concise view of a subset of objects allowing a I(filtervalue)

Bugfixes
--------

- ibm_svc_manage_callhome - Setting censorcallhome does not work
- ibm_svc_utils - REST API timeout due to slow response
- ibm_svc_utils - Return correct error in case of error code 500

v2.3.1
======

Release Summary
---------------

Added support for restoring set of volumes from snapshot, clone and thinclone management, and feature to release mapping for SVC entities.

Minor Changes
-------------

- ibm_sv_manage_snapshot - Added support to restore subset of volumes of a volumegroup from a snapshot
- ibm_svc_info - Added support to display information about partition, quorum, IO group, VG replication and enclosure, snmp server and ldap server
- ibm_svc_manage_volume - Added support to create clone or thinclone from snapshot
- ibm_svc_manage_volumgroup - Added support to create clone or thinkclone volumegroup from snapshot from a subset of volumes

Bugfixes
--------

- ibm_svc_info - Command and release mapping to remove errors in gather_subset=all
- ibm_svc_info - Return error in listing entities that require object name

v2.2.0
======

Release Summary
---------------

Added support for restoring volumegroups from snapshot, creating NVMeTCP host, features (evictvolumes, retentionminutes, volume and volumegroup information) for thincloned/cloned volume and volumegroups)

Minor Changes
-------------

- ibm_sv_manage_replication_policy - Added support to configure a 2-site-ha policy.
- ibm_sv_manage_snapshot - Added support to restore entire volumegroup from a snapshot of that volumegroup.
- ibm_svc_host - Added support to create nvmetcp host.
- ibm_svc_info - Added support to display information about thinclone/clone volumes and volumegroups.
- ibm_svc_manage_volumgroup - Added support to delete volumegroups keeping volumes via 'evictvolumes'.

Bugfixes
--------

v2.1.0
======

Release Summary
---------------

Introduced two new modules. Added support for syslog server management and storage partition.

Minor Changes
-------------

- ibm_sv_manage_replication_policy - Added support to configure a 2-site-ha policy.
- ibm_svc_host - Added support to associate/deassociate volume group with a storage partition.
- ibm_svc_info - Added support to display current security settings.
- ibm_svc_manage_volumgroup - Added support to associate/deassociate volume group with a storage partition.

Bugfixes
--------

New Modules
-----------

- ibm_sv_manage_security - Manages security settings on Storage Virtualize system related to SSH protocol and password-related configuration
- ibm_sv_manage_storage_partition - Manages storage partition on Storage Virtualize system used for policy based High Availability
- ibm_sv_manage_syslog_server - Manages syslog server configuration on Storage Virtualize system

v2.0.0
======

Minor Changes
-------------

- ibm_svc_manage_flashcopy - Added support for backup type snapshots.
- ibm_svc_manage_volumegroup - Added support to rename an existing volume group.
- ibm_svc_mdisk - Added support for Distributed Arrays (DRAID).

Bugfixes
--------

- ibm_svc_manage_volume - Allow adding hyperswap volume to a volume group.
