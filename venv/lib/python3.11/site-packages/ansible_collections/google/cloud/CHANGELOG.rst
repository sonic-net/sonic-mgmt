==========================
Google.Cloud Release Notes
==========================

.. contents:: Topics

v1.10.2
=======

Bugfixes
--------

- Revert removal of Ansible 2.16 support (https://github.com/ansible-collections/google.cloud/pull/734)

v1.10.1
=======

Bugfixes
--------

- Fix runtime.yml to correctly note Ansible 2.17 minimum version (https://github.com/ansible-collections/google.cloud/pull/730)

v1.10.0
=======

Minor Changes
-------------

- gcp_alloydb_* - added gcp_alloydb_cluster, gcp_alloydb_instance, gcp_alloydb_backup, and gcp_alloydb_user modules (https://github.com/ansible-collections/google.cloud/pull/722)

Bugfixes
--------

- gcp_secret_manager - return the secret value as type `str` rather than `bytes` (https://github.com/ansible-collections/google.cloud/pull/721)

v1.9.0
======

Minor Changes
-------------

- iap - added scp_if_ssh option (https://github.com/ansible-collections/google.cloud/pull/716).

v1.8.0
======

Minor Changes
-------------

- iap - enable use of Identity Aware Proxy ssh connections to compute instances (https://github.com/ansible-collections/google.cloud/pull/709).

Bugfixes
--------

- gcp_compute_instance - add suppport for attaching disks to compute instances (https://github.com/ansible-collections/google.cloud/pull/711).
- gcp_secret_manager - use service_account_contents instead of service_account_info (https://github.com/ansible-collections/google.cloud/pull/703).

v1.7.0
======

Minor Changes
-------------

- gcp_parameter_manager - added module support for managing parameters and versions (https://github.com/ansible-collections/google.cloud/pull/684).
- gcp_storage_bucket - added support for iam_configuration (https://github.com/ansible-collections/google.cloud/pull/693).
- lookup - added lookup via gcp_parameter_manager (https://github.com/ansible-collections/google.cloud/pull/684).

Bugfixes
--------

- gcp_bigquery_table - fixed nested schema definitions (https://github.com/ansible-collections/google.cloud/issues/637).

v1.6.0
======

Minor Changes
-------------

- gcp_compute - added GVNIC support to compute instance (https://github.com/ansible-collections/google.cloud/pull/688).
- gcp_compute - added ``discard_local_ssd`` flag to compute instance (https://github.com/ansible-collections/google.cloud/pull/686).
- gcp_compute - added hostname support to dynamic inventory (https://github.com/ansible-collections/google.cloud/pull/689).
- gcp_secret_manager - added support for regional secret manager (https://github.com/ansible-collections/google.cloud/pull/685).

Bugfixes
--------

- gcp_secret_manager - cleaned up error responses (https://github.com/ansible-collections/google.cloud/pull/690).
- gcp_serviceusage_service - updated documentation (https://github.com/ansible-collections/google.cloud/pull/691).

v1.5.3
======

Bugfixes
--------

- updated README to match required format (https://github.com/ansible-collections/google.cloud/pull/682).

v1.5.2
======

Bugfixes
--------

- gcp_compute - fixed get_project_disks to process all responses (https://github.com/ansible-collections/google.cloud/pull/677).

v1.5.1
======

Bugfixes
--------

- run integration test with Ansible 2.16 to match `requires_ansible` version

v1.5.0
======

Major Changes
-------------

- google_cloud_ops_agents - role submodule removed because it prevents the collection from passing sanity and lint tests

Minor Changes
-------------

- gcp_pubsub_subscription - allows to create GCS subscription

Bugfixes
--------

- ansible - 2.17 is now the minimum version supported
- ansible - 3.11 is now the minimum Python version
- ansible-test - fixed sanity tests
- ansible-test - integration tests are now run against 2.17 and 2.18
- gcp_bigquery_table - properly handle BigQuery table clustering fields
- gcp_pubsub_subscription - fixed improper subscription uprade PATCH request

v1.4.1
======

Bugfixes
--------

- gcp_kms_filters - add DOCUMENTATION string
- gcp_secret_manager - make an f-string usage backward compatible

v1.4.0
======

Minor Changes
-------------

- ansible - 2.16.0 is now the minimum version supported
- ansible - 3.10 is now the minimum Python version
- ansible-test - integration tests are now run against 2.16.0 and 2.17.0
- gcloud role - use dnf instead of yum on RHEL
- gcp_secret_manager - add as a module and lookup plugin (https://github.com/ansible-collections/google.cloud/pull/578)
- gcp_secret_manager - support more than 10 versions (https://github.com/ansible-collections/google.cloud/pull/634)
- restore google_cloud_ops_agents submodule (https://github.com/ansible-collections/google.cloud/pull/594)

Bugfixes
--------

- ansible-lint - remove jinja templates from test assertions

v1.3.0
======

Minor Changes
-------------

- anisble-test - integration tests are now run against 2.14.0 and 2.15.0
- ansible - 2.14.0 is now the minimum version supported
- ansible-lint - fixed over a thousand reported errors
- ansible-lint - upgraded to 6.22
- ansible-test - add support for GCP application default credentials (https://github.com/ansible-collections/google.cloud/issues/359).
- gcp_serviceusage_service - added backoff when checking for operation completion.
- gcp_serviceusage_service - use alloyb API for the integration test as spanner conflicts with other tests
- gcp_sql_ssl_cert - made sha1_fingerprint optional, which enables resource creation
- gcp_storage_default_object_acl - removed non-existent fields; the resource is not usable.

v1.2.0
======

Minor Changes
-------------

- Add DataPlane V2 Support.
- Add auth support for GCP access tokens (#574).
- Add support for ip_allocation_policy->stack_type.

Bugfixes
--------

- Use default service account if `service_account_email` is unset.

v1.1.3
======

Bugfixes
--------

- gcp_compute_instance_info: fix incorrect documentation for filter which incorrectly pointed to the gcloud filter logic rather than the API (fixes #549)

v1.1.2
======

Bugfixes
--------

- fix `gcp_compute` no longer being a valid name of the inventory plugin

v1.1.1
======

Bugfixes
--------

- fix collection to work with Python 2.7

v1.1.0
======

Minor Changes
-------------

- GCE inventory plugin - a new option ``name_suffix``, to add a suffix to the name parameter.

Bugfixes
--------

- Disk has been fixed to send the sourceSnapshot parameter.
- gcp_cloudtasks_queue - was not functional before, and is now functional.
- gcp_compute_* - these resources use the correct selflink (www.googleapis.com) as the domain, no longer erroneously reporting changes after an execution.
- gcp_compute_backend_service - no longer erroneously reports changes after an execution for ``capacity_scaler``.
- gcp_container_cluster - support GKE clusters greater than 1.19+, which cannot use basic-auth.
- gcp_crypto_key - skip_initial_version_creation defaults to the correct value.
- gcp_iam_role - now properly undeletes and recognizes soft deleted roles as absent.
- gcp_iam_role - update of a role is functional (GitHub
- gcp_spanner_database - recognize a non-existent resource as absent.
- gcp_storage_object - fix for correct version of dependency requirement.
