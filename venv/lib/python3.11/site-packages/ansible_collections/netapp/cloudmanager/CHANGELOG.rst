============================================
NetApp CloudManager Collection Release Notes
============================================

.. contents:: Topics


v21.24.0
========

Minor Changes
-------------

- na_cloudmanager_cvo_aws - increase timeout for creating cvo to 90 mins.
- na_cloudmanager_cvo_azure - increase timeout for creating cvo to 90 mins.
- na_cloudmanager_cvo_gcp - increase timeout for creating cvo to 90 mins.

v21.22.0
========

Minor Changes
-------------

- Add ``svm_name`` option in CVO for AWS, AZURE and GCP creation and update.

v21.21.0
========

Minor Changes
-------------

- na_cloudmanager_connector_azure - expose connector managed system identity principal_id to perform role assignment
- na_cloudmanager_cvo_azure - Add new ``storage_type`` value Premium_ZRS
- na_cloudmanager_cvo_azure - Add parameter ``availability_zone_node1`` and ``availability_zone_node2`` for CVO Azure HA location

v21.20.1
========

Bugfixes
--------

- new meta/execution-environment.yml is failing ansible-builder sanitize step.

v21.20.0
========

Minor Changes
-------------

- Add ``availability_zone`` option in CVO Azure on the location configuration.
- Add ``subnet_path`` option in CVO GCP.
- na_cloudmanager_cvo_aws - Add new parameter ``cluster_key_pair_name`` to support SSH authentication method key pair.
- na_cloudmanager_volume - Support AWS FsxN working environment.

Bugfixes
--------

- na_cloudmanager_connector_gcp - Fix default machine_type value on the GCP connector.

v21.19.0
========

Minor Changes
-------------

- Support ``writing_speed_state`` modification on AWS, AZURE and GCP CVOs.

v21.18.0
========

Minor Changes
-------------

- na_cloudmanager_connector_azure - Support full ``subnet_id`` and ``vnet_id``.

v21.17.0
========

Minor Changes
-------------

- na_cloudmanager_aws_fsx - Import AWS FSX to CloudManager by adding new parameters ``import_file_system`` and ``file_system_id``.
- na_cloudmanager_connector_azure - Support user defined ``storage_account`` name. The ``storage_account`` can be created automatically. When ``storage_account`` is not set, the name is constructed by appending 'sa' to the connector ``name``.
- na_cloudmanager_cvo_aws - Support license_type update
- na_cloudmanager_cvo_azure - Support license_type update
- na_cloudmanager_cvo_gcp - Support license_type update

v21.16.0
========

Minor Changes
-------------

- na_cloudmanager_connector_gcp - when using the user application default credential authentication by running the command gcloud auth application-default login, ``gcp_service_account_path`` is not needed.

Bugfixes
--------

- Add check when volume is capacity tiered.
- na_cloudmanager_connector_azure - Fix string formatting error when deleting the connector.

v21.15.0
========

Minor Changes
-------------

- Add the description of client_id based on the cloudmanager UI.
- Set license_type default value 'capacity-paygo' for single node 'ha-capacity-paygo' for HA and 'capacity_package_name' value 'Essential'

v21.14.0
========

Minor Changes
-------------

- na_cloudmanager_snapmirror - Add FSX to snapmirror.

Bugfixes
--------

- CVO working environment clusterProperties is deprecated. Make changes accordingly. Add CVO update status check on ``instance_type`` change.

v21.13.0
========

Minor Changes
-------------

- Add ``update_svm_password`` for ``svm_password`` update on AWS, AZURE and GCP CVOs. Update ``svm_password`` if ``update_svm_password`` is true.
- Add ontap image upgrade on AWS, AZURE and GCP CVOs if ``upgrade_ontap_version`` is true and ``ontap_version`` is provided with a specific version. ``use_latest_version`` has to be false.
- na_cloudmanager_connector_aws - automatically fetch client_id and instance_id for delete.
- na_cloudmanager_connector_aws - make the module idempotent for create and delete.
- na_cloudmanager_connector_aws - report client_id and instance_id if connector already exists.
- na_cloudmanager_cvo_aws - Support instance_type update
- na_cloudmanager_cvo_azure - Support instance_type update
- na_cloudmanager_cvo_gcp - Support instance_type update
- na_cloudmanager_info - new subsets - account_info, agents_info, active_agents_info
- na_cloudmanager_volume - Report error if the volume properties cannot be modified. Add support ``tiering_policy`` and ``snapshot_policy_name`` modification.

Bugfixes
--------

- na_cloudmanager_cvo_gcp - handle extra two auto-gen GCP labels to prevent update ``gcp_labels`` failure.

New Modules
-----------

- netapp.cloudmanager.na_cloudmanager_aws_fsx - Cloud ONTAP file system(FSX) in AWS

v21.12.1
========

Bugfixes
--------

- na_cloudmanager_connector_aws - Fix default ami not based on the region in resource file
- na_cloudmanager_snapmirror - report actual error rather than None with "Error getting destination info".

v21.12.0
========

Minor Changes
-------------

- PR1 - allow usage of Ansible module group defaults - for Ansible 2.12+.
- na_cloudmanager_cvo_azure - Add extra tag handling on azure_tag maintenance
- na_cloudmanager_cvo_gcp - Add extra label hendling for HA and only allow add new labels on gcp_labels
- na_cloudmanager_snapmirror - working environment get information api not working for onprem is fixed

Bugfixes
--------

- Fix cannot find working environment if ``working_environment_name`` is provided

v21.11.0
========

Minor Changes
-------------

- Add CVO modification unit tests
- Adding new parameter ``capacity_package_name`` for all CVOs creation with capacity based ``license_type`` capacity-paygo or ha-capacity-paygo for HA.
- all modules - better error reporting if refresh_token is not valid.
- na_cloudmanager_connector_gcp - automatically fetch client_id for delete.
- na_cloudmanager_connector_gcp - make the module idempotent for create and delete.
- na_cloudmanager_connector_gcp - report client_id if connector already exists.
- na_cloudmanager_cvo_aws - Add unit tests for capacity based license support.
- na_cloudmanager_cvo_azure - Add unit tests for capacity based license support.
- na_cloudmanager_cvo_gcp - Add unit tests for capacity based license support and delete cvo.
- netapp.py - improve error handling with error content.

Bugfixes
--------

- na_cloudmanager_connector_gcp - typeError when using proxy certificates.

v21.10.0
========

Minor Changes
-------------

- Only these parameters will be modified on the existing CVOs. svm_passowrd will be updated on each run.
- na_cloudmanager_cvo_aws - Support update on svm_password, tier_level, and aws_tag.
- na_cloudmanager_cvo_aws - add new parameter ``kms_key_id`` and ``kms_key_arn`` as AWS encryption parameters to support AWS CVO encryption
- na_cloudmanager_cvo_azure - Add new parameter ``ha_enable_https`` for HA CVO to enable the HTTPS connection from CVO to storage accounts. This can impact write performance. The default is false.
- na_cloudmanager_cvo_azure - Support update on svm_password, tier_level, and azure_tag.
- na_cloudmanager_cvo_azure - add new parameter ``azure_encryption_parameters`` to support AZURE CVO encryption
- na_cloudmanager_cvo_gcp - Support update on svm_password, tier_level, and gcp_labels.
- na_cloudmanager_cvo_gcp - add new parameter ``gcp_encryption_parameters`` to support GCP CVO encryption

Bugfixes
--------

- na_cloudmanager_snapmirror - key error CloudProviderName for ONPREM operation

v21.9.0
=======

Minor Changes
-------------

- na_cloudmanager - Support pd-balanced in ``gcp_volume_type`` for CVO GCP, ``provider_volume_type`` in na_cloudmanager_snapmirror and na_cloudmanager_volume.
- na_cloudmanager_connector_azure - Change default value of ``virtual_machine_size`` to Standard_DS3_v2.
- na_cloudmanager_cvo_gcp - Add selflink support on subnet_id, vpc0_node_and_data_connectivity, vpc1_cluster_connectivity, vpc2_ha_connectivity, vpc3_data_replication, subnet0_node_and_data_connectivity, subnet1_cluster_connectivity, subnet2_ha_connectivity, and subnet3_data_replication.

v21.8.0
=======

Major Changes
-------------

- Adding stage environment to all modules in cloudmanager

Minor Changes
-------------

- na_cloudmanager - Support service account with new options ``sa_client_id`` and ``sa_secret_key`` to use for API operations.

Bugfixes
--------

- na_cloudmanager_aggregate - accept client_id end with or without 'clients'
- na_cloudmanager_cifs_server - accept client_id end with or without 'clients'
- na_cloudmanager_connector_aws - accept client_id end with or without 'clients'
- na_cloudmanager_connector_azure - accept client_id end with or without 'clients'
- na_cloudmanager_connector_gcp - accept client_id end with or without 'clients'
- na_cloudmanager_cvo_aws - accept client_id end with or without 'clients'
- na_cloudmanager_cvo_azure - accept client_id end with or without 'clients'
- na_cloudmanager_cvo_gcp - accept client_id end with or without 'clients'
- na_cloudmanager_info - accept client_id end with or without 'clients'
- na_cloudmanager_nss_account - accept client_id end with or without 'clients'
- na_cloudmanager_snapmirror - accept client_id end with or without 'clients'
- na_cloudmanager_volume - accept client_id end with or without 'clients'

v21.7.0
=======

Minor Changes
-------------

- na_cloudmanager_aggregate - Add provider_volume_type gp3 support.
- na_cloudmanager_connector_gcp - rename option ``service_account_email`` and ``service_account_path`` to ``gcp_service_account_email`` and ``gcp_service_account_path`` respectively.
- na_cloudmanager_cvo_aws - Add ebs_volume_type gp3 support.
- na_cloudmanager_snapmirror - Add provider_volume_type gp3 support.
- na_cloudmanager_volume - Add aggregate_name support on volume creation.
- na_cloudmanager_volume - Add provider_volume_type gp3 support.

Bugfixes
--------

- na_cloudmanager_aggregate - Improve error message
- na_cloudmanager_connector_azure - Add subnet_name as aliases of subnet_id, vnet_name as aliases of vnet_id.
- na_cloudmanager_connector_azure - Fix KeyError client_id
- na_cloudmanager_cvo_gcp - Apply network_project_id check on vpc1_cluster_connectivity, vpc2_ha_connectivity, vpc3_data_replication, subnet1_cluster_connectivity, subnet2_ha_connectivity, subnet3_data_replication
- na_cloudmanager_nss_account - Improve error message
- na_cloudmanager_volume - Improve error message

v21.6.0
=======

Bugfixes
--------

- na_cloudmanager_cifs_server - Fix incorrect API call when is_workgroup is true
- na_cloudmanager_connector_azure - Change client_id as optional
- na_cloudmanager_connector_azure - Fix python error - msrest.exceptions.ValidationError. Parameter 'Deployment.properties' can not be None.
- na_cloudmanager_connector_azure - Fix wrong example on the document and update account_id is required field on deletion.
- na_cloudmanager_cvo_gcp - Change vpc_id from optional to required.

New Modules
-----------

- netapp.cloudmanager.na_cloudmanager_snapmirror - NetApp Cloud Manager SnapMirror

v21.5.0
=======

Minor Changes
-------------

- na_cloudmanager_connector_aws - Return newly created Azure client ID in cloud manager, instance ID and account ID. New option ``proxy_certificates``.
- na_cloudmanager_cvo_aws - Return newly created AWS working_environment_id.
- na_cloudmanager_cvo_azure - Return newly created AZURE working_environment_id.
- na_cloudmanager_cvo_gcp - Return newly created GCP working_environment_id.

Bugfixes
--------

- na_cloudmanager_cvo_aws - Fix incorrect placement of platformSerialNumber in the resulting json structure

v21.4.0
=======

New Modules
-----------

- netapp.cloudmanager.na_cloudmanager_connector_azure - NetApp Cloud Manager connector for Azure.
- netapp.cloudmanager.na_cloudmanager_connector_gcp - NetApp Cloud Manager connector for GCP.
- netapp.cloudmanager.na_cloudmanager_cvo_azure - NetApp Cloud Manager CVO/working environment in single or HA mode for Azure.
- netapp.cloudmanager.na_cloudmanager_info - NetApp Cloud Manager info

v21.3.0
=======

New Modules
-----------

- netapp.cloudmanager.na_cloudmanager_aggregate - NetApp Cloud Manager Aggregate
- netapp.cloudmanager.na_cloudmanager_cifs_server - NetApp Cloud Manager cifs server
- netapp.cloudmanager.na_cloudmanager_connector_aws - NetApp Cloud Manager connector for AWS
- netapp.cloudmanager.na_cloudmanager_cvo_aws - NetApp Cloud Manager CVO for AWS
- netapp.cloudmanager.na_cloudmanager_nss_account - NetApp Cloud Manager nss account
- netapp.cloudmanager.na_cloudmanager_volume - NetApp Cloud Manager volume
