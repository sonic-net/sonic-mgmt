===========================================
NetApp StorageGRID Collection Release Notes
===========================================

.. contents:: Topics


v21.15.0
========

Minor Changes
-------------

- na_sg_grid_ha_group - added check mode support in the module.
- na_sg_org_container - Enhanced the Consistency setting.
- na_sg_org_container - new option `capacity_limit` added for bucket, requires storageGRID 11.9 or later.

Bugfixes
--------

- na_sg_org_user - fix where existing users with no groups attached were not getting any groups added.

New Modules
-----------

- netapp.storagegrid.na_sg_grid_alert_receiver - NetApp StorageGRID manage alert receiver.
- netapp.storagegrid.na_sg_grid_audit_destination - Configure audit log destinations on StorageGRID.
- netapp.storagegrid.na_sg_grid_autosupport - Configure autosupport on StorageGRID.
- netapp.storagegrid.na_sg_grid_domain_name - Configure endpoint domain name on StorageGRID.
- netapp.storagegrid.na_sg_grid_hotfix - Apply hotfixes on StorageGRID.
- netapp.storagegrid.na_sg_grid_proxy_settings - NetApp StorageGRID manage proxy settings for the grid.
- netapp.storagegrid.na_sg_grid_snmp - Configure SNMP agent on StorageGRID.
- netapp.storagegrid.na_sg_grid_tenant - NetApp StorageGRID manage tenant accounts.
- netapp.storagegrid.na_sg_grid_vlan_interface - Configure VLAN interface on StorageGRID.
- netapp.storagegrid.na_sg_org_bucket - Manage buckets on StorageGRID.

v21.14.0
========

Minor Changes
-------------

- na_sg_grid_account - new option `allow_compliance_mode` and `max_retention_days` added for tenant account, requires storageGRID 11.9 or later.
- na_sg_grid_gateway - new option `enable_tenant_manager`, `enable_grid_manager` and `node_type` added to support management interfaces.
- na_sg_grid_group - new option `read_only` added for grid groups.
- na_sg_grid_info - LB endpoints and HA group in info module.
- na_sg_org_group - new option `read_only` added for tenant groups.

New Modules
-----------

- netapp.storagegrid.na_sg_grid_ec_profile - Manage EC profiles on StorageGRID.
- netapp.storagegrid.na_sg_grid_ilm_policy - Manage ILM policies on StorageGRID.
- netapp.storagegrid.na_sg_grid_ilm_policy_tag - Manage ILM policy tags on StorageGRID.
- netapp.storagegrid.na_sg_grid_ilm_pool - Manage ILM pools on StorageGRID.
- netapp.storagegrid.na_sg_grid_ilm_rule - Manage ILM rules on StorageGRID.

v21.13.0
========

v21.12.0
========

Minor Changes
-------------

- na_sg_grid_account - New option ``allow_select_object_content`` for enabling use of the S3 SelectObjectContent API.
- na_sg_grid_account - New option ``description`` for setting additional identifying information for the tenant account.

Bugfixes
--------

- Removed fetch limit in API request and implemented pagination.

v21.11.1
========

Bugfixes
--------

- na_sg_org_container - fix versioning not enabled on initial bucket creation.

v21.11.0
========

Minor Changes
-------------

- na_sg_org_container - supports versioning configuration for S3 buckets available in StorageGRID 11.6+.

New Modules
-----------

- netapp.storagegrid.na_sg_grid_client_certificate - Manage Client Certificates on StorageGRID.

v21.10.0
========

Minor Changes
-------------

- na_sg_grid_gateway - supports specifying HA Groups by name or UUID.

Bugfixes
--------

- na_sg_org_group - fixed behaviour where update to ``s3_policy`` is ignored if ``management_policy`` is set.

New Modules
-----------

- netapp.storagegrid.na_sg_grid_ha_group - Manage high availability (HA) group configuration on StorageGRID.
- netapp.storagegrid.na_sg_grid_traffic_classes - Manage Traffic Classification Policy configuration on StorageGRID.

v21.9.0
=======

Minor Changes
-------------

- PR2 - allow usage of Ansible module group defaults - for Ansible 2.12+.
- na_sg_grid_gateway - supports load balancer endpoint binding available in StorageGRID 11.5+.
- na_sg_org_container - supports creation of S3 Object Lock buckets available in StorageGRID 11.5+.

Bugfixes
--------

- na_sg_grid_account - minor documentation fix.
- na_sg_grid_gateway - existing endpoints matched by ``name`` and ``port``.

v21.8.0
=======

Minor Changes
-------------

- PR2 - allow usage of Ansible module group defaults - for Ansible 2.12+.

v21.7.0
=======

Minor Changes
-------------

- Updated documentation - added RETURN block for each module

New Modules
-----------

- netapp.storagegrid.na_sg_grid_gateway - Manage Load balancer (gateway) endpoints on StorageGRID.

v21.6.0
=======

Minor Changes
-------------

- na_sg_org_container - supports deletion of buckets when ``state`` is set to ``absent``.

Bugfixes
--------

- na_sg_org_container - fix issue with applying compliance settings on buckets.

New Modules
-----------

- netapp.storagegrid.na_sg_grid_certificate - Manage the Storage API and Grid Management certificates on StorageGRID.
- netapp.storagegrid.na_sg_grid_identity_federation - NetApp StorageGRID manage Grid identity federation.
- netapp.storagegrid.na_sg_org_identity_federation - NetApp StorageGRID manage Tenant identity federation.

v20.11.0
========

Minor Changes
-------------

- na_sg_grid_account - New option ``root_access_account`` for granting initial root access permissions for the tenant to an existing federated group

New Modules
-----------

- netapp.storagegrid.na_sg_grid_info - NetApp StorageGRID Grid information gatherer
- netapp.storagegrid.na_sg_org_info - NetApp StorageGRID Org information gatherer

v20.10.0
========

Minor Changes
-------------

- na_sg_grid_account - new option ``update_password`` for managing Tenant Account root password changes.
- na_sg_grid_user - new option ``password`` and ``update_password`` for setting or updating Grid Admin User passwords.
- na_sg_org_user - new option ``password`` and ``update_password`` for setting or updating Tenant User passwords.

Breaking Changes / Porting Guide
--------------------------------

- This version introduces a breaking change.
  All modules have been renamed from ``nac_sg_*`` to ``na_sg_*``.
  Playbooks and Roles must be updated to match.

Bugfixes
--------

- na_sg_grid_account - added ``no_log`` flag to password fields.
- na_sg_grid_account - fixed documentation issue.
- na_sg_grid_group - fixed group name parsing.
- na_sg_org_group - fixed group name parsing.

v20.6.1
=======

Minor Changes
-------------

- Fixed documentation issue in README.md

Bugfixes
--------

- nac_sg_org_container - fixed documentation issue.

v20.6.0
=======

New Modules
-----------

- netapp.storagegrid.nac_sg_grid_account - NetApp StorageGRID Manage Tenant account.
- netapp.storagegrid.nac_sg_grid_dns - NetApp StorageGRID Manage Grid DNS servers.
- netapp.storagegrid.nac_sg_grid_group - NetApp StorageGRID Manage Grid admin group.
- netapp.storagegrid.nac_sg_grid_ntp - NetApp StorageGRID Manage Grid NTP servers.
- netapp.storagegrid.nac_sg_grid_regions - NetApp StorageGRID Manage Grid Regions.
- netapp.storagegrid.nac_sg_grid_user - NetApp StorageGRID Manage Grid admin user.
- netapp.storagegrid.nac_sg_org_container - NetApp StorageGRID Manage S3 bucket.
- netapp.storagegrid.nac_sg_org_group - NetApp StorageGRID Manage Tenant group.
- netapp.storagegrid.nac_sg_org_user - NetApp StorageGRID Manage Tenant user.
- netapp.storagegrid.nac_sg_org_user_s3_key - NetApp StorageGRID Manage S3 key.
