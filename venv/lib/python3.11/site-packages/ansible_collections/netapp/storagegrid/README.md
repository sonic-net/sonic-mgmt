![example workflow](https://github.com/ansible-collections/netapp.storagegrid/actions/workflows/main.yml/badge.svg)
[![codecov](https://codecov.io/gh/ansible-collections/netapp.storagegrid/branch/main/graph/badge.svg?token=weBYkksxSi)](https://codecov.io/gh/ansible-collections/netapp.storagegrid)
[![Discord](https://img.shields.io/discord/855068651522490400)](https://discord.gg/NetApp)


=============================================================

 netapp.storagegrid

 NetApp StorageGRID Collection

 Copyright (c) 2020 NetApp, Inc. All rights reserved.
 Specifications subject to change without notice.

=============================================================

# Installation

```bash
ansible-galaxy collection install netapp.storagegrid
```
To use this collection add the following to the top of your playbook.
```
collections:
  - netapp.storagegrid
```

# Requirements
  - ansible-core >= 2.17

# Usage

Each of the StorageGRID modules require an `auth_token` parameter to be specified. This can be obtained by executing a `uri` task against the StorageGRID Authorization API endpoint and registering the output as the first item in a Playbook.

If you are performing a Tenant operation, ensure that the `accountId` parameter is also specified in the URI body and set to the Tenant Account ID. For example, `"accountId": "01234567890123456789"`

```yaml
- name: Get Grid Authorization token
  uri:
    url: "https://sgadmin.example.com/api/v3/authorize"
    method: POST
    body: {
      "username": "root",
      "password": "storagegrid123",
      "cookie": false,
      "csrfToken": false
    }
    body_format: json
    validate_certs: false
  register: auth
```

Subsequent tasks can leverage the registered auth token.

```yaml
- name: Create a StorageGRID Tenant Account
  netapp.storagegrid.na_sg_grid_account:
    api_url: "https://sgadmin.example.com"
    auth_token: "{{ auth.json.data }}"
    validate_certs: false
    state: present
    name: AnsibleTenant
    protocol: s3
    management: true
    use_own_identity_source: true
    allow_platform_services: true
    password: "mytenantrootpassword"
    quota_size: 10
```

# Module documentation

[https://docs.ansible.com/ansible/latest/collections/netapp/storagegrid](https://docs.ansible.com/ansible/latest/collections/netapp/storagegrid/index.html)

# Versioning

[Releasing, Versioning and Deprecation](https://github.com/ansible-collections/netapp/issues/93)

# Need help

Join our [Discord](https://discord.gg/NetApp) and look for our #ansible channel.

# Code of Conduct

This collection follows the [Ansible project's Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).

# Release Notes

## 21.15.0

### New Modules
  - na_sg_grid_proxy_settings - configure proxy settings on StorageGRID.
  - na_sg_grid_domain_name - configure endpoint domain names on StorageGRID.
  - na_sg_grid_vlan_interface - configure VLAN interfaces on StorageGRID.
  - na_sg_grid_audit_destination - configure audit log destinations on StorageGRID.
  - na_sg_grid_autosupport - configure autosupport settings on StorageGRID.
  - na_sg_grid_snmp - configure SNMP agent for monitoring on StorageGRID.
  - na_sg_org_bucket - duplicate of `na_sg_org_container` module to manage bucket.
  - na_sg_grid_tenant - duplicate of `na_sg_grid_account` module to manage tenant account.
  - na_sg_grid_hotfix - apply hotfix on StorageGRID.
  - na_sg_grid_alert_receiver - configure alert receiver on StorageGRID.

### Minor Changes
  - na_sg_org_container - new option `capacity_limit` added for bucket, requires storageGRID 11.9 or later.
  - na_sg_grid_ha_group - added check mode support in the module.
  - na_sg_org_container - Enhanced the Consistency setting.

### Bug Fixes
  - na_sg_org_user - fix where existing users with no groups attached were not getting any groups added.

## 21.14.0

### New Modules
  - na_sg_grid_ilm_policy - Added new module for ILM policy management.
  - na_sg_grid_ilm_policy_tag - Added new module for ILM policy tag management.
  - na_sg_grid_ilm_rule - Added new module for ILM rule management.
  - na_sg_grid_ilm_pool - Added new module for ILM pool management.
  - na_sg_grid_ec_profile - Added new module for Erasure coding profile management.

### Minor Changes
  - na_sg_grid_info - LB endpoints and HA group in info module.
  - na_sg_grid_account - new option `allow_compliance_mode` and `max_retention_days` added for tenant account, requires storageGRID 11.9 or later.
  - na_sg_grid_group - new option `read_only` added for grid groups.
  - na_sg_org_group - new option `read_only` added for tenant groups.
  - na_sg_grid_gateway - new option `enable_tenant_manager`, `enable_grid_manager` and `node_type` added to support management interfaces.


## 21.13.0


### Minor Changes
- updated pipleine.

## 21.12.0

### Minor Changes
  - na_sg_grid_account - New option ``description`` for setting additional identifying information for the tenant account.
  - na_sg_grid_account - New option ``allow_select_object_content`` for enabling use of the S3 SelectObjectContent API.

### Bug Fixes
  - Removed fetch limit in API request and implemented pagination.

## 21.11.1

### Bug Fixes
  - na_sg_org_container - fix versioning not enabled on initial bucket creation.

## 21.11.0

### Minor Changes
  - na_sg_org_container - supports versioning configuration for S3 buckets available in StorageGRID 11.6+.

### New Modules
  - na_sg_grid_client_certificate - Manage Client Certificates on StorageGRID.

## 21.10.0

### Minor Changes
  - na_sg_grid_gateway - supports specifying HA Groups by name or UUID.

### Bug Fixes
  - na_sg_org_group - fixed behaviour where update to ``s3_policy`` is ignored if ``management_policy`` is set.

### New Modules
  - na_sg_grid_ha_group - Manage high availability (HA) group configuration on StorageGRID.
  - na_sg_grid_traffic_classes - Manage Traffic Classification Policy configuration on StorageGRID.

## 21.9.0

### Minor Changes
  - na_sg_grid_gateway - supports load balancer endpoint binding available in StorageGRID 11.5+.
  - na_sg_org_container - supports creation of S3 Object Lock buckets available in StorageGRID 11.5+.

### Bug Fixes
  - na_sg_grid_gateway - existing endpoints matched by ``name`` and ``port``.
  - na_sg_grid_account - minor documentation fix.

## 21.8.0

### Minor Changes
  - all modules - enable usage of Ansible module group defaults - for Ansible 2.12+.

## 21.7.0

### New Modules

- na_sg_grid_gateway: Manage Load balancer (gateway) endpoints

### Minor Changes
- Updated documentation - added RETURN block for each module

## 21.6.0

### New Modules

- na_sg_grid_certificate: Manage the Storage API and Grid Management certificates on StorageGRID.
- na_sg_grid_identity_federation: Manage Grid identity federation.
- na_sg_org_identity_federation: Manage Tenant identity federation.

### Minor Changes
- na_sg_org_container - supports deletion of buckets when `state` is set to `absent`.

### Bug Fixes
- na_sg_org_container - fix issue with applying compliance settings on buckets.

## 20.11.0

### New Modules

- na_sg_grid_info: Gather StorageGRID Grig subset information
- na_sg_org_info: Gather StorageGRID Org subset information

### Minor Changes

- na_sg_grid_account: new option `root_access_account` for granting initial root access permissions for the tenant to an existing federated group

## 20.10.0

### Breaking Changes

This version introduces a breaking change. All modules have been renamed from `nac_sg_*` to `na_sg_*`. Playbooks and Roles must be updated to match.

### Bug Fixes

- na_sg_grid_account: fixed documentation issue.
- na_sg_grid_account: added `no_log` flag to password fields
- na_sg_grid_group: fixed group name parsing
- na_sg_org_group: fixed group name parsing

### New Options

- na_sg_grid_account: new option `update_password` for managing Tenant Account root password changes
- na_sg_org_user: new option `password` and `update_password` for setting or updating Tenant User passwords
- na_sg_grid_user: new option `password` and `update_password` for setting or updating Grid Admin User passwords

## 20.6.1

### Minor Changes
- Fixed documentation issue in README.md

### Bug Fixes
- nac_sg_org_container: fixed documentation issue.

## 20.6.0

Initial release of NetApp StorageGRID Ansible modules

### New Modules

- nac_sg_grid_account: create/modify/delete Tenant account
- nac_sg_grid_dns: set Grid DNS servers
- nac_sg_grid_group: create/modify/delete Grid admin group
- nac_sg_grid_ntp: set Grid NTP servers
- nac_sg_grid_regions: set Grid Regions
- nac_sg_grid_user: create/modify/delete Grid admin user
- nac_sg_org_container: create S3 bucket
- nac_sg_org_group: create/modify/delete Tenant group
- nac_sg_org_user: create/modify/delete Tenant user
- nac_sg_org_user_s3_key: create/delete S3 key

## License
GNU General Public License v3.0
See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.