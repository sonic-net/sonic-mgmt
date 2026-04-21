# Google Cloud Platform Ansible Collection

This collection provides a series of Ansible modules and plugins for
interacting with the [Google Cloud Platform](https://cloud.google.com)

## Description

The google.cloud collection provides a way to automate provisioning,
configuration, and management of Google Cloud resources using Ansible
playbooks. This collection includes modules for managing various
Google Cloud services such as Compute Engine instances, Cloud Storage
buckets, Cloud SQL instances, and more.

### Resources Supported

* AlloyDB Backup (gcp_alloydb_cluster)
* AlloyDB Cluster (gcp_alloydb_cluster)
* AlloyDB Instance (gcp_alloydb_instance)
* AlloyDB User (gcp_alloydb_user)
* App Engine FirewallRule (gcp_appengine_firewall_rule, gcp_appengine_firewall_rule_info)
* BigQuery Dataset (gcp_bigquery_dataset, gcp_bigquery_dataset_info)
* BigQuery Table (gcp_bigquery_table, gcp_bigquery_table_info)
* Cloud Bigtable Instance (gcp_bigtable_instance, gcp_bigtable_instance_info)
* Cloud Build Trigger (gcp_cloudbuild_trigger, gcp_cloudbuild_trigger_info)
* Cloud Functions CloudFunction (gcp_cloudfunctions_cloud_function, gcp_cloudfunctions_cloud_function_info)
* Cloud Scheduler Job (gcp_cloudscheduler_job, gcp_cloudscheduler_job_info)
* Cloud Tasks Queue (gcp_cloudtasks_queue, gcp_cloudtasks_queue_info)
* Compute Engine Address (gcp_compute_address, gcp_compute_address_info)
* Compute Engine Autoscaler (gcp_compute_autoscaler, gcp_compute_autoscaler_info)
* Compute Engine BackendBucket (gcp_compute_backend_bucket, gcp_compute_backend_bucket_info)
* Compute Engine BackendService (gcp_compute_backend_service, gcp_compute_backend_service_info)
* Compute Engine RegionBackendService (gcp_compute_region_backend_service, gcp_compute_region_backend_service_info)
* Compute Engine Disk (gcp_compute_disk, gcp_compute_disk_info)
* Compute Engine Firewall (gcp_compute_firewall, gcp_compute_firewall_info)
* Compute Engine ForwardingRule (gcp_compute_forwarding_rule, gcp_compute_forwarding_rule_info)
* Compute Engine GlobalAddress (gcp_compute_global_address, gcp_compute_global_address_info)
* Compute Engine GlobalForwardingRule (gcp_compute_global_forwarding_rule, gcp_compute_global_forwarding_rule_info)
* Compute Engine HttpHealthCheck (gcp_compute_http_health_check, gcp_compute_http_health_check_info)
* Compute Engine HttpsHealthCheck (gcp_compute_https_health_check, gcp_compute_https_health_check_info)
* Compute Engine HealthCheck (gcp_compute_health_check, gcp_compute_health_check_info)
* Compute Engine InstanceTemplate (gcp_compute_instance_template, gcp_compute_instance_template_info)
* Compute Engine Image (gcp_compute_image, gcp_compute_image_info)
* Compute Engine Instance (gcp_compute_instance, gcp_compute_instance_info)
* Compute Engine InstanceGroup (gcp_compute_instance_group, gcp_compute_instance_group_info)
* Compute Engine InstanceGroupManager (gcp_compute_instance_group_manager, gcp_compute_instance_group_manager_info)
* Compute Engine RegionInstanceGroupManager (gcp_compute_region_instance_group_manager, gcp_compute_region_instance_group_manager_info)
* Compute Engine InterconnectAttachment (gcp_compute_interconnect_attachment, gcp_compute_interconnect_attachment_info)
* Compute Engine Network (gcp_compute_network, gcp_compute_network_info)
* Compute Engine NetworkEndpointGroup (gcp_compute_network_endpoint_group, gcp_compute_network_endpoint_group_info)
* Compute Engine NodeGroup (gcp_compute_node_group, gcp_compute_node_group_info)
* Compute Engine NodeTemplate (gcp_compute_node_template, gcp_compute_node_template_info)
* Compute Engine RegionAutoscaler (gcp_compute_region_autoscaler, gcp_compute_region_autoscaler_info)
* Compute Engine RegionDisk (gcp_compute_region_disk, gcp_compute_region_disk_info)
* Compute Engine RegionUrlMap (gcp_compute_region_url_map, gcp_compute_region_url_map_info)
* Compute Engine RegionHealthCheck (gcp_compute_region_health_check, gcp_compute_region_health_check_info)
* Compute Engine ResourcePolicy (gcp_compute_resource_policy, gcp_compute_resource_policy_info)
* Compute Engine Route (gcp_compute_route, gcp_compute_route_info)
* Compute Engine Router (gcp_compute_router, gcp_compute_router_info)
* Compute Engine Snapshot (gcp_compute_snapshot, gcp_compute_snapshot_info)
* Compute Engine SslCertificate (gcp_compute_ssl_certificate, gcp_compute_ssl_certificate_info)
* Compute Engine Reservation (gcp_compute_reservation, gcp_compute_reservation_info)
* Compute Engine SslPolicy (gcp_compute_ssl_policy, gcp_compute_ssl_policy_info)
* Compute Engine Subnetwork (gcp_compute_subnetwork, gcp_compute_subnetwork_info)
* Compute Engine TargetHttpProxy (gcp_compute_target_http_proxy, gcp_compute_target_http_proxy_info)
* Compute Engine TargetHttpsProxy (gcp_compute_target_https_proxy, gcp_compute_target_https_proxy_info)
* Compute Engine RegionTargetHttpProxy (gcp_compute_region_target_http_proxy, gcp_compute_region_target_http_proxy_info)
* Compute Engine RegionTargetHttpsProxy (gcp_compute_region_target_https_proxy, gcp_compute_region_target_https_proxy_info)
* Compute Engine TargetInstance (gcp_compute_target_instance, gcp_compute_target_instance_info)
* Compute Engine TargetPool (gcp_compute_target_pool, gcp_compute_target_pool_info)
* Compute Engine TargetSslProxy (gcp_compute_target_ssl_proxy, gcp_compute_target_ssl_proxy_info)
* Compute Engine TargetTcpProxy (gcp_compute_target_tcp_proxy, gcp_compute_target_tcp_proxy_info)
* Compute Engine TargetVpnGateway (gcp_compute_target_vpn_gateway, gcp_compute_target_vpn_gateway_info)
* Compute Engine UrlMap (gcp_compute_url_map, gcp_compute_url_map_info)
* Compute Engine VpnTunnel (gcp_compute_vpn_tunnel, gcp_compute_vpn_tunnel_info)
* Google Kubernetes Engine Cluster (gcp_container_cluster, gcp_container_cluster_info)
* Google Kubernetes Engine NodePool (gcp_container_node_pool, gcp_container_node_pool_info)
* Cloud DNS ManagedZone (gcp_dns_managed_zone, gcp_dns_managed_zone_info)
* Cloud DNS ResourceRecordSet (gcp_dns_resource_record_set, gcp_dns_resource_record_set_info)
* Filestore Instance (gcp_filestore_instance, gcp_filestore_instance_info)
* Cloud IAM Role (gcp_iam_role, gcp_iam_role_info)
* Cloud IAM ServiceAccount (gcp_iam_service_account, gcp_iam_service_account_info)
* Cloud IAM ServiceAccountKey (gcp_iam_service_account_key, gcp_iam_service_account_key_info)
* Cloud Key Management Service KeyRing (gcp_kms_key_ring, gcp_kms_key_ring_info)
* Cloud Key Management Service CryptoKey (gcp_kms_crypto_key, gcp_kms_crypto_key_info)
* Cloud (Stackdriver) Logging Metric (gcp_logging_metric, gcp_logging_metric_info)
* ML Engine Model (gcp_mlengine_model, gcp_mlengine_model_info)
* ML Engine Version (gcp_mlengine_version, gcp_mlengine_version_info)
* Cloud Pub/Sub Topic (gcp_pubsub_topic, gcp_pubsub_topic_info)
* Cloud Pub/Sub Subscription (gcp_pubsub_subscription, gcp_pubsub_subscription_info)
* Memorystore (Redis) Instance (gcp_redis_instance, gcp_redis_instance_info)
* Resource Manager Project (gcp_resourcemanager_project, gcp_resourcemanager_project_info)
* Runtime Configurator Config (gcp_runtimeconfig_config, gcp_runtimeconfig_config_info)
* Runtime Configurator Variable (gcp_runtimeconfig_variable, gcp_runtimeconfig_variable_info)
* Service Usage Service (gcp_serviceusage_service, gcp_serviceusage_service_info)
* Cloud Source Repositories Repository (gcp_sourcerepo_repository, gcp_sourcerepo_repository_info)
* Cloud Spanner Instance (gcp_spanner_instance, gcp_spanner_instance_info)
* Cloud Spanner Database (gcp_spanner_database, gcp_spanner_database_info)
* Cloud SQL Instance (gcp_sql_instance, gcp_sql_instance_info)
* Cloud SQL Database (gcp_sql_database, gcp_sql_database_info)
* Cloud SQL User (gcp_sql_user, gcp_sql_user_info)
* Cloud SQL SslCert (gcp_sql_ssl_cert, gcp_sql_ssl_cert_info)
* Cloud Storage Bucket (gcp_storage_bucket, gcp_storage_bucket_info)
* Cloud Storage BucketAccessControl (gcp_storage_bucket_access_control, gcp_storage_bucket_access_control_info)
* Cloud Storage DefaultObjectACL (gcp_storage_default_object_acl, gcp_storage_default_object_acl_info)
* Cloud TPU Node (gcp_tpu_node, gcp_tpu_node_info)
* Secret Manager (gcp_secret_manager)

## Requirements

### Ansible version compatibility

This collection is tested to work with Ansible 2.16+.

### Python version compatibility

This collection is tested with to work Python 3.10+

## Installation

Before using this collection, you need to install it with the Ansible Galaxy
command-line tool:

```
ansible-galaxy collection install google.cloud
```

You can also include it in a requirements.yml file and install it with
ansible-galaxy collection install -r requirements.yml, using the format:


```yaml
collections:
  - name: google.cloud
```

Note that if you install any collections from Ansible Galaxy, they will not be
upgraded automatically when you upgrade the Ansible package.
To upgrade the collection to the latest available version, run the following
command:

```
ansible-galaxy collection install google.cloud --upgrade
```

You can also install a specific version of the collection, for example, if you
need to downgrade when something is broken in the latest version (please
report an issue in this repository). Use the following syntax to install
version 1.5.1:

```
ansible-galaxy collection install google.cloud:==1.5.1
```

See [using Ansible collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.

If you are using the google.cloud collection locally you will likely need
to install the [gcloud command line tool](https://cloud.google.com/sdk/docs/install#rpm)
in order to perform authentication The easiest way to
authenticate to GCP is using [application default credentials](https://cloud.google.com/sdk/docs/authorizing#adc).

Once you have installed `gcloud` and performed basic initialization
(via `gcloud init`) run:

```shell
gcloud auth application-default login
```

For more authentication options see the Use Cases section below.

## Use Cases

The google.cloud collection supports multiple methods to authenticate to Google
Cloud:

* Application Default Credentials (`auth_kind: "application"`)
* Service Account Key (`auth_kind: "serviceaccount"`)
* OAuth Credentials (`auth_kind: "accesstoken"`)

To use Application default credentials configured using `gcloud`:

```yaml
- name: Create a Google Cloud Storage bucket
  google.cloud.gcp_storage_bucket:
    name: "{{ bucket_name }}"
    project: "{{ gcp_project }}"
    auth_kind: "application"
    state: present
- name: Delete a Google Cloud Storage bucket
  google.cloud.gcp_storage_bucket:
    name: "{{ bucket_name }}"
    project: "{{ gcp_project }}"
    auth_kind: "application"
    state: absent
```

For unattended operation it is common to use service account keys. To use
these, set `auth_kind` to `serviceaccount` and `service_account_file` to
the path to the file containing your service account key.

```yaml
- name: Create a Google Cloud Storage bucket
  google.cloud.gcp_storage_bucket:
    name: "{{ bucket_name }}"
    project: "{{ gcp_project }}"
    auth_kind: "serviceaccount"
    service_account_file: "{{ gcp_cred_file }}"
    state: present
- name: Delete a Google Cloud Storage bucket
  google.cloud.gcp_storage_bucket:
    name: "{{ bucket_name }}"
    project: "{{ gcp_project }}"
    auth_kind: "serviceaccount"
    service_account_file: "{{ gcp_cred_file }}"
    state: absent
```

In place of `service_account_file` you may instead use
`service_account_contents` which contains the service account key
directly.

Read the [best practices for managing service account keys](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys)
to learn how to keep your service account key and your GCP resources safe.

Common options can also be set using environment variables, simplifying
automated operations. The available variables are:

```shell
export GCP_PROJECT=<project id>
export GCP_AUTH_KIND=<application|serviceaccount|accesstoken>
export GCP_SERVICE_ACCOUNT_FILE=</path/to/service/account/key.json>
export GCP_SERVICE_ACCOUNT_CONTENTS=<alternative that stores the service account key in the env var>
export GCP_SCOPES=<requested scopes such as https://www.googleapis.com/auth/compute>
export GCP_REGION=<default region such as us-central1>
export GCP_ZONE=<default zone such as us-central1-a>
```

## Testing

The google.cloud collection is tested with the two most recent releases of
Ansible with the versions of Python supported by those releases. The
current version matrix can be seen in the
[GitHub action configuration](https://github.com/ansible-collections/google.cloud/blob/master/.github/workflows/ansible-integration-tests.yml).

To learn how to run the tests locally, read
[CONTRIBUTING.md](https://github.com/ansible-collections/google.cloud/blob/master/CONTRIBUTING.md).

## Support

There are several avenues of commuication available for google.cloud users:

* Join the Ansible forum:
  * [Get Help](https://forum.ansible.com/c/help/6): get help or help others. Please use appropriate tags, for example `cloud`.
  * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

## Release Notes

See [CHANGELOG.md](https://github.com/ansible-collections/google.cloud/blob/master/CHANGELOG.rst).

## Related Information

Documentation for Google Cloud Platform can be found at [cloud.google.com](https://cloud.google.com/docs/).

Documentation for google.cloud resources can be found on the [Ansible Galaxy site](https://galaxy.ansible.com/ui/repo/published/google/cloud/docs/).

## License Information

GNU General Public License v3.0 or later.

See [LICENSE](https://github.com/ansible-collections/google.cloud/blob/master/LICENSE)
to view the full text.
