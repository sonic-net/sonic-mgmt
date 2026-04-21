[![Documentation](https://img.shields.io/badge/docs-brightgreen.svg)](https://docs.ansible.com/ansible/devel/collections/netapp/cloudmanager/index.html)
![example workflow](https://github.com/ansible-collections/netapp.cloudmanager/actions/workflows/main.yml/badge.svg)
[![codecov](https://codecov.io/gh/ansible-collections/netapp.cloudmanager/branch/main/graph/badge.svg?token=weBYkksxSi)](https://codecov.io/gh/ansible-collections/netapp.cloudmanager)
[![Discord](https://img.shields.io/discord/855068651522490400)](https://discord.gg/NetApp)
# Ansible Collection - netapp.cloudmanager

Copyright (c) 2022 NetApp, Inc. All rights reserved.
Specifications subject to change without notice.

This collection requires python 3.5 or better.

# Installation
```bash
ansible-galaxy collection install netapp.cloudmanager
```
To use this collection, add the following to the top of your playbook:
```
collections:
  - netapp.cloudmanager
```
# Requirements
- ansible version >= 2.9
- requests >= 2.20
- python version >= '3.5'

# Module documentation
https://docs.ansible.com/ansible/devel/collections/netapp/cloudmanager/

# Need help
Join our [Discord](https://discord.gg/NetApp) and look for our #ansible channel.

# Code of Conduct
This collection follows the [Ansible project's Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).

# Documentation
https://github.com/ansible-collections/netapp/wiki

# Release Notes

## 21.24.0

### Minor Changes
  - Requires Ansible 2.16 or higher.
  - updated pipleine.

## 21.22.1

### Minor Changes
  - na_cloudmanager_cvo_azure - increase timeout for creating cvo to 90 mins.
  - na_cloudmanager_cvo_aws - increase timeout for creating cvo to 90 mins.
  - na_cloudmanager_cvo_gcp - increase timeout for creating cvo to 90 mins.
  - Requires Ansible 2.14 or higher

## 21.22.0
  - Add `svm_name` option in AWS, AZURE and GCP CVO for creation and update.

## 21.21.0

### Minor Changes
  - na_cloudmanager_connector_azure - expose connector managed system identity principal_id tp perform role assignment.

### New Options
  - Add `availability_zone_node1` and `availability_zone_node2` options in CVO Azure HA on the location configuration.
  - Add new `storage_type` value Premium_ZRS

## 21.20.1

### Bug Fixes
  - new meta/execution-environment.yml is failing ansible-builder sanitize step.

## 21.20.0

### New Options
  - Add `availability_zone` option in CVO Azure on the location configuration.
  - Add `cluster_key_pair_name` option in CVO AWS for SSH authentication key pair method.
  - Add `subnet_path` option in CVO GCP.

### Bug Fixes
  - Fix the `machine_type` default value in the connector GCP.

### Minor Changes
  - na_cloudmanager_volume - Support AWS FsxN working environment

## 21.19.0

### Minor Changes
  - Support writing_speed_state modification for AWS, AZURE and GCP CVOs.

## 21.18.0
  - na_cloudmanager_connector_azure - support full subnet_id and vnet_id
  - Support ``writing_speed_state`` modification for AWS, AZURE and GCP CVOs.

## 21.17.0

### Minor Changes
  - na_cloudmanager_aws_fsx - Import AWS FSX to CloudManager.
  - Support ``license_type`` modification for AWS, AZURE and GCP CVOs.

### New Options
  - na_cloudmanager_connector_azure - Support user defined ``storage_account``. The storage account can be created automatically. When ``storage_account`` is not set, the name is constructed by appending 'sa' to the connector ``name``.
  - na_cloudmanager_aws_fsx - Import AWS FSX to CloudManager by adding new parameters ``import_file_system`` and ``file_system_id``.

## 21.16.0

### Bug Fixes
  - na_cloudmanager_volume - Add check when volume is capacity tiered.
  - na_cloudmanager_connector_azure - Fix string formatting error when deleting the connector.

### Minor Changes
  - na_cloudmanager_connector_gcp - when using the user application default credential authentication by running the command gcloud auth application-default login, ``gcp_service_account_path`` is not needed.

## 21.15.0

### Minor Changes
  - Add the description of the client_id based on the cloudmanager UI.
  - Update ``license_type`` and ``capacity_package_name`` default values on capacity based license.
 
## 21.14.0

### Minor Changes
  - na_cloudmanager_snapmirror - add AWS FSx to snapmirror.

### Bug Fixes
  - CVO working environment clusterProperties is deprecated. Make changes accordingly. Add CVO update status check on `instance_type` change.

## 21.13.0

### New Modules
  - na_cloudmanager_aws_fsx - NetApp AWS FSX

### Minor Changes
  - na_cloudmanager_connector_aws - make the module idempotent for create and delete.
  - na_cloudmanager_connector_aws - automatically fetch client_id and instance_id for delete.
  - na_cloudmanager_connector_aws - report client_id if connector already exists.
  - na_cloudmanager_info - new subsets - account_info, agents_info, active_agents_info.
  - Add ONTAP image upgrade feature for AWS, AZURE and GCP CVOs. Add ``upgrade_ontap_version`` to indicate if upgrade ONTAP is needed. It only can be used when ``use_latest_version`` is false and ``ontap_version`` is a specific version.
  - Add instance_type update feature for AWS, AZURE and GCP CVOs.
  - na_cloudmanager_volume - Add ``tiering_policy`` and ``snapshot_policy_name`` modification, and report error if the properties cannot be changed.

### Bug Fixes
  - na_cloudmanager_cvo_gcp - handle extra auto-gen GCP labels to fix `gcp_labels` update failure.
  - Add ``update_svm_password`` for ``svm_password`` update on AWS, AZURE and GCP CVOs. Update ``svm_password`` if ``update_svm_password`` is true.

## 21.12.1

### Bug Fixes
  - na_cloudmanager_connector_aws - fix default ami not found in the region on resource file.
  - na_cloudmanager_snapmirror - report actual error rather than None with "Error getting destination info".

## 21.12.0

### Minor Changes
  - Handle extra azure_tag on AZURE CVO and extra gcp_labels on GCP CVO HA on modification. gcp_labels modification on GCP CVO does not support remove labels.
  - PR1 - allow usage of Ansible module group defaults - for Ansible 2.12+.

### Bug Fixes
  - na_cloudmanager_snapmirror - working environment get information api not working for onprem is fixed.
  - Fix cannot find working environment if `working_environment_name` is provided.

## 21.11.0

## New Options
  - Adding new parameter `capacity_package_name` for all CVOs creation with capacity based license type capacity-paygo or ha-capacity-paygo for HA.

### Minor Changes
  - na_cloudmanager_connector_gcp - make the module idempotent for create and delete.
  - na_cloudmanager_connector_gcp - automatically fetch client_id for delete.
  - na_cloudmanager_connector_gcp - report client_id if connector already exists.
  - all modules - better error reporting if ``refresh_token`` is not valid.

### Bug Fixes
  - na_cloudmanager_connector_gcp - typeError when using proxy certificates.

## 21.10.0

### Minor Changes
  - Adding support update on `svm_password`, `tier_level`, `aws_tag`, `azure_tag` and `gcp_labels` for all CVOs. Only these parameters will be modified on the existing CVOs.

### Bug Fixes
  - na_cloudmanager_snapmirror - key error CloudProviderName for ONPREM operation.

## New Options
  - Adding new parameter `ha_enable_https` for HA CVO to enable the HTTPS connection from CVO to storage accounts. This can impact write performance. The default is false.
  - Adding new parameters `kms_key_id` and `kms_key_arn` as AWS encryption parameters for AWS CVO encryption.
  - Adding new parameter `azure_encryption_parameters` for AZURE CVO encryption.
  - Adding new parameter `gcp_encryption_parameters` for GCP CVO encryption.

## 21.9.0

### New Options
  - Adding selflink support on CVO GCP params: `subnet_id`, `vpc0_node_and_data_connectivity`, `vpc1_cluster_connectivity`, `vpc2_ha_connectivity`, `vpc3_data_replication`, `subnet0_node_and_data_connectivity`, `subnet1_cluster_connectivity`, `subnet2_ha_connectivity`, and `subnet3_data_replication`.
  - Adding pd-balanced support on ``gcp_volume_type`` CVO GCP and ``provider_volume_type`` for na_cloudmanager_snapmirror and na_cloudmanager_volume.

### Bug Fixes
  - Change `virtual_machine_size` default value to Standard_DS3_v2.

## 21.8.0

### New Options
  - Adding stage environment to all modules in cloudmanager.
  - Adding service account support on API operations in cloudmanager: `sa_client_id` and `sa_secret_key`. `refresh_token` will be ignored if service account information is provided.

### Bug Fixes
  - Accept client_id end with or without 'clients'.

## 21.7.0

### New Options
  - na_cloudmanager_cvo_aws: Support one new ebs_volume_type gp3.
  - Adding stage environemt to all modules in cloudmanager.
  - na_cloudmanager_volume: Add `aggregate_name` support on volume creation.
  - na_cloudmanager_cvo_aws: Support one new `ebs_volume_type` gp3.
  - na_cloudmanager_connector_azure: Add `subnet_name` as aliases of `subnet_id`, `vnet_name` as aliases of `vnet_id`.
  - na_cloudmanager_aggregate - Add ``provider_volume_type`` gp3 support.
  - na_cloudmanager_volume - Add ``provider_volume_type`` gp3 support.
  - na_cloudmanager_snapmirror - Add ``provider_volume_type`` gp3 support.
   
### Bug Fixes
  - na_cloudmanager_aggregate: Improve error message.
  - na_cloudmanager_cvo_gcp: Apply `network_project_id` on vpc1_cluster_connectivity, vpc2_ha_connectivity, vpc3_data_replication, subnet1_cluster_connectivity, subnet2_ha_connectivity, subnet3_data_replication.
  - na_cloudmanager_connector_gcp: rename option `service_account_email` and `service_account_path` to `gcp_service_account_email` and `gcp_service_account_path` respectively.
  - na_cloudmanager_connector_azure: Fix KeyError client_id.
  - na_cloudmanager_nss_account: Improve error message.
  - na_cloudmanager_volume: Improve error message.

## 21.6.0

### New Modules
  - na_cloudmanager_snapmirror: Create or Delete snapmirror on Cloud Manager.

### Bug Fixes
  - na_cloudmanager_connector_gcp: Make client_id as optional.
  - na_cloudmanager_cvo_gcp: Change ``vpc_id`` from optional to required.

## 21.5.1

### Bug fixes
  - na_cloudmanager_cifs_server: Fix incorrect API call when is_workgroup is true.
  - na_cloudmanager_connector_azure: Fix python error - msrest.exceptions.ValidationError. Parameter 'Deployment.properties' can not be None.
  - na_cloudmanager_connector_azure: Fix wrong example on the document and update account_id is required field on deletion.

## 21.5.0

### New Options
  - na_cloudmanager_connector_aws: Return newly created Azure client ID in cloud manager, instance ID and account ID. New option `proxy_certificates`.
  - na_cloudmanager_cvo_aws: Return newly created AWS working_environment_id.
  - na_cloudmanager_cvo_azure: Return newly created AZURE working_environment_id.
  - na_cloudmanager_cvo_gcp: Return newly created GCP working_environment_id.

## Bug Fixes
  - na_cloudmanager_cvo_aws: Fix incorrect placement of platformSerialNumber in the resulting json structure.

## 21.4.0

### Module documentation changes
  - Remove the period at the end of the line on short_description.
  - Add period at the end of the names in examples.
  - Add notes mentioning support check_mode.

### New Modules
  - na_cloudmanager_connector_azure: Create or delete Cloud Manager connector for Azure.
  - na_cloudmanager_cvo_azure: Create or delete Cloud Manager CVO for AZURE for both single and HA.
  - na_cloudmanager_info: Gather Cloud Manager subset information using REST APIs. Support for subsets `working_environments_info`, `aggregates_info`, `accounts_info`.
  - na_cloudmanager_connector_gcp: Create or delete Cloud Manager connector for GCP.
  - na_cloudmanager_cvo_gcp: Create or delete Cloud Manager CVO for GCP for both single and HA.

## 21.3.0

### New Modules
  - na_cloudmanager_aggregate: Create or delete an aggregate on Cloud Volumes ONTAP, or add disks on an aggregate.
  - na_cloudmanager_cifs_server: Create or delete CIFS server for Cloud Volumes ONTAP.
  - na_cloudmanager_connector_aws: Create or delete Cloud Manager connector for AWS.
  - na_cloudmanager_cvo_aws: Create or delete Cloud Manager CVO for AWS for both single and HA.
  - na_cloudmanager_nss_account: Create or delete a nss account on Cloud Manager.
  - na_cloudmanager_volume: Create, modify or delete a volume on Cloud Volumes ONTAP.
