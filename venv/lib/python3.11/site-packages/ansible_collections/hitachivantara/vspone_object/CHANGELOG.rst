===========================================
Hitachivantara.Vspone\_Object Release Notes
===========================================

.. contents:: Topics

v1.1.1
======

Release Summary
---------------

This patch release provides minor documentation improvements.

v1.1.0
======

Release Summary
---------------

This minor release of `hitachivantara.vspone_object` enhances the storage component module with initial support for VSP One B20 series storage systems.

Minor Changes
-------------

- Enhanced `hv_storage_component` module to support storage components of type ARRAY for VSP One B20 series storage systems.

v1.0.0
======

Release Summary
---------------

This minor release of `hitachivantara.vspone_object` introduces new modules for VSP One Object management.

Minor Changes
-------------

- Added new facts module `hv_certificates_facts`.
- Added new facts module `hv_events_facts`.
- Added new facts module `hv_galaxy_facts`.
- Added new facts module `hv_kmip_server_facts`.
- Added new facts module `hv_licenses_facts`.
- Added new facts module `hv_region_facts`.
- Added new facts module `hv_s3_encryption_facts`.
- Added new facts module `hv_serial_number_facts`.
- Added new facts module `hv_storage_class_facts`.
- Added new facts module `hv_storage_components_facts`.
- Added new facts module `hv_storage_fault_domain_facts`.
- Added new facts module `hv_troubleshooting_facts`.
- Added new facts module `hv_user_buckets_facts`.
- Added new facts module `hv_user_id_facts`.
- Added new facts module `hv_users_facts`.
- Added new module `hv_certificates`.
- Added new module `hv_csrf`.
- Added new module `hv_job`.
- Added new module `hv_jobs_facts`.
- Added new module `hv_kmip`.
- Added new module `hv_license`.
- Added new module `hv_s3_encryption`.
- Added new module `hv_s3_user_credentials`.
- Added new module `hv_serial_number`.
- Added new module `hv_storage_class`.
- Added new module `hv_storage_component_state_update`.
- Added new module `hv_storage_component`.
- Added new module `hv_storage_fault_domain`.

New Modules
-----------

Oneobject Node
~~~~~~~~~~~~~~

- hitachivantara.vspone_object.oneobject_node.hv_certificates - Manage certificates in Hitachi VSP One Object.
- hitachivantara.vspone_object.oneobject_node.hv_certificates_facts - Get all the certificates of VSP One Object.
- hitachivantara.vspone_object.oneobject_node.hv_csrf - Fetch CSRF tokens from Hitachi VSP One Object.
- hitachivantara.vspone_object.oneobject_node.hv_events_facts - Get events from VSP One Object.
- hitachivantara.vspone_object.oneobject_node.hv_galaxy_facts - Get the galaxy information of VSP One Object.
- hitachivantara.vspone_object.oneobject_node.hv_job - Manage jobs in Hitachi VSP One Object.
- hitachivantara.vspone_object.oneobject_node.hv_jobs_facts - Get job information from VSP One Object.
- hitachivantara.vspone_object.oneobject_node.hv_kmip - Manage KMIP servers on VSP One Object.
- hitachivantara.vspone_object.oneobject_node.hv_kmip_server_facts - Get a list of KMIP servers.
- hitachivantara.vspone_object.oneobject_node.hv_license - Manage License in Hitachi VSP One Object.
- hitachivantara.vspone_object.oneobject_node.hv_licenses_facts - Get all the licenses of VSP One Object.
- hitachivantara.vspone_object.oneobject_node.hv_region_facts - Get the region info of VSP One Object.
- hitachivantara.vspone_object.oneobject_node.hv_s3_encryption - Set S3 Encryption.
- hitachivantara.vspone_object.oneobject_node.hv_s3_encryption_facts - Get the S3 encryption of VSP One Object.
- hitachivantara.vspone_object.oneobject_node.hv_s3_user_credentials - Generate S3 user credentials.
- hitachivantara.vspone_object.oneobject_node.hv_serial_number - Set serial number for VSP One Object.
- hitachivantara.vspone_object.oneobject_node.hv_serial_number_facts - Get the serialnumber of VSP One Object.
- hitachivantara.vspone_object.oneobject_node.hv_storage_class - Create or update a storage class.
- hitachivantara.vspone_object.oneobject_node.hv_storage_class_facts - Get storage classes from VSP One Object.
- hitachivantara.vspone_object.oneobject_node.hv_storage_component - Create or update a storage component.
- hitachivantara.vspone_object.oneobject_node.hv_storage_component_state_update - Update state of a storage component.
- hitachivantara.vspone_object.oneobject_node.hv_storage_components_facts - Get storage components from VSP One Object.
- hitachivantara.vspone_object.oneobject_node.hv_storage_fault_domain - Create or update a storage fault domain.
- hitachivantara.vspone_object.oneobject_node.hv_storage_fault_domain_facts - Get storage fault domains from VSP One Object.
- hitachivantara.vspone_object.oneobject_node.hv_troubleshooting_facts - Create a log bundle for troubleshooting.
- hitachivantara.vspone_object.oneobject_node.hv_user_buckets_facts - Get a list of user buckets.
- hitachivantara.vspone_object.oneobject_node.hv_user_id_facts - Get all the users's ids of VSP One Object.
- hitachivantara.vspone_object.oneobject_node.hv_users_facts - Get all the users of VSP One Object.
