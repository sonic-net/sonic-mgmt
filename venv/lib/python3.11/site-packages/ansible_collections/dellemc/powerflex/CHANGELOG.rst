===============================
Dellemc.PowerFlex Change Logs
===============================

.. contents:: Topics

v2.6.1
======

Release Summary
---------------

This release brings several bug fixes and minor changes to the PowerFlex Ansible Modules.

Minor Changes
-------------

- Added none check for mdm cluster id in mdm_cluster module.
- Updated minimum SDK version to 2.6.1.

Bugfixes
--------

- snapshot_policy - Renamed snapshotAccessMode and secureSnapshots to snapshot_access_mode and secure_snapshots respectively.

v2.6.0
======

Minor Changes
-------------

- Added Ansible role to support installation and uninstallation of SDT.
- Info module is enhanced to support the listing of SDTs and NVMe hosts.

New Modules
-----------

- dellemc.powerflex.nvme_host - Manage NVMe Hosts on Dell PowerFlex
- dellemc.powerflex.sdt - Manage SDTs on Dell PowerFlex

v2.5.0
======

Minor Changes
-------------

- Added support for PowerFlex Onyx version(4.6.x).
- Fixed the roles to support attaching the MDM cluster to the gateway.
- The storage pool module has been enhanced to support more features.

v2.4.0
======

Minor Changes
-------------

- Added support for executing Ansible PowerFlex modules and roles on AWS environment.

v2.3.0
======

Minor Changes
-------------

- Added support for PowerFlex ansible modules and roles on Azure.
- Added support for resource group provisioning to validate, deploy, edit, add nodes and delete a resource group.
- The Info module is enhanced to list the firmware repositories.

New Modules
-----------

- dellemc.powerflex.resource_group - Manage resource group deployments on Dell PowerFlex

v2.2.0
======

Minor Changes
-------------

- The Info module is enhanced to retrieve lists related to fault sets, service templates, deployments, and managed devices.
- The SDS module has been enhanced to facilitate SDS creation within a fault set.

New Modules
-----------

- dellemc.powerflex.fault_set - Manage Fault Sets on Dell PowerFlex

v2.1.0
======

Minor Changes
-------------

- Added support for PowerFlex Denver version(4.5.x) to TB and Config role.

v2.0.1
======

Minor Changes
-------------

- Added Ansible role to support creation and deletion of protection domain, storage pool and fault set.
- Added Ansible role to support installation and uninstallation of Active MQ.
- Added support for PowerFlex Denver version(4.5.x)
- Added support for SDC installation on ESXi, Rocky Linux and Windows OS.

v1.9.0
======

Minor Changes
-------------

- Added Ansible role to support installation and uninstallation of Gateway.
- Added Ansible role to support installation and uninstallation of SDR.
- Added Ansible role to support installation and uninstallation of Web UI.

v1.8.0
======

Minor Changes
-------------

- Added Ansible role to support installation and uninstallation of LIA.
- Added Ansible role to support installation and uninstallation of MDM.
- Added Ansible role to support installation and uninstallation of SDS.
- Added Ansible role to support installation and uninstallation of TB.

v1.7.0
======

Minor Changes
-------------

- Added Ansible role to support installation and uninstallation of SDC.
- Added sample playbooks for the modules.
- Device module is enhanced to support force addition of device to the SDS.
- Info module is enhanced to list statistics in snapshot policies.
- Replication consistency group module is enhanced to support failover, restore, reverse, switchover, and sync operations.
- SDC module is enhanced to configure performance profile and to remove SDC.
- Updated modules to adhere with ansible community guidelines.

New Modules
-----------

- dellemc.powerflex.snapshot_policy - Manage snapshot policies on Dell PowerFlex

v1.6.0
======

Minor Changes
-------------

- Info module is enhanced to support the listing of replication pairs.

New Modules
-----------

- dellemc.powerflex.replication_pair - Manage replication pairs on Dell PowerFlex

v1.5.0
======

Minor Changes
-------------

- Info module is enhanced to support the listing replication consistency groups.
- Renamed gateway_host to hostname
- Renamed verifycert to validate_certs.
- Updated modules to adhere with ansible community guidelines.

New Modules
-----------

- dellemc.powerflex.replication_consistency_group - Manage replication consistency groups on Dell PowerFlex

v1.4.0
======

Minor Changes
-------------

- Added support for 4.0.x release of PowerFlex OS.
- Info module is enhanced to support the listing volumes and storage pools with statistics data.
- Storage pool module is enhanced to get the details with statistics data.
- Volume module is enhanced to get the details with statistics data.

v1.3.0
======

Minor Changes
-------------

- Added execution environment manifest file to support building an execution environment with ansible-builder.
- Enabled the check_mode support for info module

New Modules
-----------

- dellemc.powerflex.mdm_cluster - Manage MDM cluster on Dell PowerFlex

v1.2.0
======

Minor Changes
-------------

- Names of previously released modules have been changed from dellemc_powerflex_\<module name> to \<module name>.

New Modules
-----------

- dellemc.powerflex.protection_domain - Manage Protection Domain on Dell PowerFlex

v1.1.1
======

Deprecated Features
-------------------

- The dellemc_powerflex_gatherfacts module is deprecated and replaced with dellemc_powerflex_info

v1.1.0
======

Minor Changes
-------------

- Added dual licensing.
- Gatherfacts module is enhanced to list devices.

New Modules
-----------

- dellemc.powerflex.device - Manage device on Dell PowerFlex
- dellemc.powerflex.sds - Manage SDS on Dell PowerFlex

v1.0.0
======

New Modules
-----------

- dellemc.powerflex.info - Gathering information about Dell PowerFlex
- dellemc.powerflex.sdc - Manage SDCs on Dell PowerFlex
- dellemc.powerflex.snapshot - Manage Snapshots on Dell PowerFlex
- dellemc.powerflex.storagepool - Managing Dell PowerFlex storage pool
- dellemc.powerflex.volume - Manage volumes on Dell PowerFlex
