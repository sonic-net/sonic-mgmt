(
  {
    "google.cloud.gcp_bigquery_dataset": "Database",
    "google.cloud.gcp_bigquery_table": "Database",
    "google.cloud.gcp_compute_address": "Network",
    "google.cloud.gcp_compute_disk": "Storage",
    "google.cloud.gcp_compute_firewall": "Security & Identity",
    "google.cloud.gcp_compute_instance": "Compute",
    "google.cloud.gcp_compute_instance_group_manager": "Compute",
    "google.cloud.gcp_compute_instance_template": "Compute",
    "google.cloud.gcp_compute_network": "Network",
    "google.cloud.gcp_compute_ssl_certificate": "Security & Identity",
    "google.cloud.gcp_container_cluster": "Containers",
    "google.cloud.gcp_container_node_pool": "Containers",
    "google.cloud.gcp_dns_managed_zone": "Network",
    "google.cloud.gcp_dns_resource_record_set": "Network",
    "google.cloud.gcp_filestore_instance": "Storage",
    "google.cloud.gcp_iam_role": "Security & Identity",
    "google.cloud.gcp_iam_service_account": "Security & Identity",
    "google.cloud.gcp_kms_key_ring": "Security & Identity",
    "google.cloud.gcp_pubsub_subscription": "App Integration",
    "google.cloud.gcp_pubsub_topic": "App Integration",
    "google.cloud.gcp_resource_record_set": "Network",
    "google.cloud.gcp_sourcerepo_repository": "Developer Tools",
    "google.cloud.gcp_sql_instance": "Database",
    "google.cloud.gcp_storage_bucket": "Storage",
  } as $actions|
  .[] |
  (if has("results") then  # if ran in a loop, flatten it
    .results[] as $result |
    . + $result |
    del(.results)
  else
    .
  end) as $data |
  select($data.action | in($actions))  |  # only select objects defined in the action mapping
  ($data.id // $data.etag // $data.selfLink // $data.name) as $id |  # not everything returns an ID
  ($data.name // $id) as $name |  # not everything returns a name
  ($data.kind // "missing") as $kind |  # not everything returns a kind
  select($name != null and $id != null) |
    {
      name: $name,
      canonical_facts: {
        id: $id,
        name: $name,
        kind: $kind,
      },
      facts: {
        infra_type: "PublicCloud",
        infra_bucket: ($actions[$data.action] // "Unknown" | ascii_upcase),
        device_type: $kind,
      }
    }
)
