==========================================
Community Proxmox Collection Release Notes
==========================================

.. contents:: Topics

v1.4.0
======

Release Summary
---------------

This is the minor release of the ``community.proxmox`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- proxmox - Add delete parameter to delete settings (https://github.com/ansible-collections/community.proxmox/pull/195).
- proxmox_cluster -  Add master_api_password for authentication against master node (https://github.com/ansible-collections/community.proxmox/pull/140).
- proxmox_cluster - added link0 and link1 to join command (https://github.com/ansible-collections/community.proxmox/issues/168, https://github.com/ansible-collections/community.proxmox/pull/172).
- proxmox_kvm - update description of machine parameter in proxmox_kvm.py (https://github.com/ansible-collections/community.proxmox/pull/186)
- proxmox_storage - added `dir` and `zfspool` storage types (https://github.com/ansible-collections/community.proxmox/pull/184)
- proxmox_tasks_info - add source option to specify tasks to consider (https://github.com/ansible-collections/community.proxmox/pull/179)
- proxmox_template -  Add 'import' to allowed content types of proxmox_template, so disk images and can be used as disk images on VM creation (https://github.com/ansible-collections/community.proxmox/pull/162).

Bugfixes
--------

- proxmox inventory plugin and proxmox module utils - avoid Python 2 compatibility imports (https://github.com/ansible-collections/community.proxmox/pull/175).
- proxmox_kvm - remove limited choice for vga option in proxmox_kvm (https://github.com/ansible-collections/community.proxmox/pull/185)
- proxmox_kvm, proxmox_template - remove ``ansible.module_utils.six`` dependency (https://github.com/ansible-collections/community.proxmox/pull/201).
- proxmox_storage - fixed adding PBS-type storage by ensuring its parameters (server, datastore, etc.) are correctly sent to the Proxmox API (https://github.com/ansible-collections/community.proxmox/pull/171).
- proxmox_user - added a third case when testing for not-yet-existant user (https://github.com/ansible-collections/community.proxmox/issues/163)
- proxmox_vm_info - do not throw exception when iterating through machines and optional api results are missing (https://github.com/ansible-collections/community.proxmox/pull/191)

New Modules
-----------

- community.proxmox.proxmox_cluster_ha_rules - Management of HA rules.
- community.proxmox.proxmox_firewall - Manage firewall rules in Proxmox.
- community.proxmox.proxmox_firewall_info - Manage firewall rules in Proxmox.
- community.proxmox.proxmox_ipam_info - Retrieve information about IPAMs.
- community.proxmox.proxmox_subnet - Create/Update/Delete subnets from SDN.
- community.proxmox.proxmox_vnet - Manage virtual networks in Proxmox SDN.
- community.proxmox.proxmox_vnet_info - Retrieve information about one or more Proxmox VE SDN vnets.
- community.proxmox.proxmox_zone - Manage Proxmox zone configurations.
- community.proxmox.proxmox_zone_info - Get Proxmox zone info.

v1.3.0
======

Release Summary
---------------

This is the minor release of the ``community.proxmox`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- proxmox* modules - added fallback environment variables for ``api_token``, ``api_secret``, and ``validate_certs`` (https://github.com/ansible-collections/community.proxmox/issues/63, https://github.com/ansible-collections/community.proxmox/pull/136).
- proxmox_cluster_ha_groups - fix idempotency in proxmox_cluster_ha_groups module (https://github.com/ansible-collections/community.proxmox/issues/138, https://github.com/ansible-collections/community.proxmox/pull/139).
- proxmox_cluster_ha_resources -  Fix idempotency proxmox_cluster_ha_resources (https://github.com/ansible-collections/community.proxmox/pull/135).
- proxmox_kvm - Add missing 'storage' parameter to create_vm()-call.
- proxmox_kvm - add new purge parameter to proxmox_kvm module (https://github.com/ansible-collections/community.proxmox/issues/60, https://github.com/ansible-collections/community.proxmox/pull/148).

Bugfixes
--------

- proxmox_pct_remote connection plugin - avoid deprecated ansible-core paramiko import helper, import paramiko directly instead (https://github.com/ansible-collections/community.proxmox/issues/146, https://github.com/ansible-collections/community.proxmox/pull/151).

New Modules
-----------

- community.proxmox.proxmox_storage - Manage storage in PVE clusters and nodes.

v1.2.0
======

Release Summary
---------------

This is the minor release of the ``community.proxmox`` collection.
This changelog contains all changes to the modules and plugins in this collection that have been made after the previous release.

Minor Changes
-------------

- proxmox inventory plugin - always provide basic information regardless of want_facts (https://github.com/ansible-collections/community.proxmox/pull/124).
- proxmox_cluster - cluster creation has been made idempotent (https://github.com/ansible-collections/community.proxmox/pull/125).
- proxmox_pct_remote - allow forward agent with paramiko (https://github.com/ansible-collections/community.proxmox/pull/130).

New Modules
-----------

- community.proxmox.proxmox_group - Group management for Proxmox VE cluster.
- community.proxmox.proxmox_node - Manage Proxmox VE nodes.
- community.proxmox.proxmox_user - User management for Proxmox VE cluster.

v1.1.0
======

Release Summary
---------------

This is the minor release of the ``community.proxmox`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- proxmox - allow force deletion of LXC containers (https://github.com/ansible-collections/community.proxmox/pull/105).
- proxmox - validate the cluster name length (https://github.com/ansible-collections/community.proxmox/pull/119).

Bugfixes
--------

- proxmox inventory plugin - avoid using deprecated option when templating options (https://github.com/ansible-collections/community.proxmox/pull/108).

New Modules
-----------

- community.proxmox.proxmox_access_acl - Management of ACLs for objects in Proxmox VE Cluster.
- community.proxmox.proxmox_cluster_ha_groups - Management of HA groups in Proxmox VE Cluster.
- community.proxmox.proxmox_cluster_ha_resources - Management of HA groups in Proxmox VE Cluster.

v1.0.1
======

Release Summary
---------------

This is a minor bugfix release for the ``community.proxmox`` collections.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- proxmox module utils - fix handling warnings in LXC tasks (https://github.com/ansible-collections/community.proxmox/pull/104).

v1.0.0
======

Release Summary
---------------

This is the first stable release of the ``community.proxmox`` collection since moving from ``community.general``, released on 2025-06-08.

Minor Changes
-------------

- proxmox - add support for creating and updating containers in the same task (https://github.com/ansible-collections/community.proxmox/pull/92).
- proxmox module util - do not hang on tasks that throw warnings (https://github.com/ansible-collections/community.proxmox/issues/96, https://github.com/ansible-collections/community.proxmox/pull/100).
- proxmox_kvm - add ``rng0`` option to specify an RNG device (https://github.com/ansible-collections/community.proxmox/pull/18).
- proxmox_kvm - remove redundant check for duplicate names as this is allowed by PVE API (https://github.com/ansible-collections/community.proxmox/issues/97, https://github.com/ansible-collections/community.proxmox/pull/99).
- proxmox_snap - correctly handle proxmox_snap timeout parameter (https://github.com/ansible-collections/community.proxmox/issues/73, https://github.com/ansible-collections/community.proxmox/issues/95, https://github.com/ansible-collections/community.proxmox/pull/101).

Breaking Changes / Porting Guide
--------------------------------

- proxmox - ``update`` and ``force`` are now mutually exclusive (https://github.com/ansible-collections/community.proxmox/pull/92).
- proxmox - the default of ``update`` changed from ``false`` to ``true`` (https://github.com/ansible-collections/community.proxmox/pull/92).

Bugfixes
--------

- proxmox - fix crash in module when the used on an existing LXC container with ``state=present`` and ``force=true`` (https://github.com/ansible-collections/community.proxmox/pull/91).

New Modules
-----------

- community.proxmox.proxmox_backup_schedule - Schedule VM backups and removing them.
- community.proxmox.proxmox_cluster - Create and join Proxmox VE clusters.
- community.proxmox.proxmox_cluster_join_info - Retrieve the join information of the Proxmox VE cluster.

v0.1.0
======

Release Summary
---------------

This is the first community.proxmox release. It contains mainly the state of the Proxmox content in community.general 10.6.0.
The minimum required ansible-core version for community.proxmox is ansible-core 2.17, which implies Python 3.7+.
The minimum required proxmoxer version is 2.0.0.
