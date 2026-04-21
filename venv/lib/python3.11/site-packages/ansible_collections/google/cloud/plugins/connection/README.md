# Identity Aware Proxy Connection Plugin

This plugin uses the gcloud cli [start-iap-tunnel](https://cloud.google.com/sdk/gcloud/reference/compute/start-iap-tunnel)
method to prepare TCP forwarding to your compute instances, and then uses the
builtin ansible SSH connection plugin to communicate ansible commands to the
target nodes.

This makes it possible to start using ansible without the need to expose your
instances to the open web, or configure stringent firewall rules to ensure no
bad actors can potentially login to your infrastructure.

## Requisites

1. The [gcloud cli tool](https://cloud.google.com/sdk/gcloud?authuser=0) installed
2. Firewall rules in places for [IAP TCP Forwarding](https://cloud.google.com/iap/docs/using-tcp-forwarding)

## Configuring the connection plugin

The connection plugin can be configured by setting some values in the
`[gcloud]` section of your ansible.cfg, here's an example:

```ini
[gcloud]
account = my-service-account@my-project.iam.gserviceaccount.com
project = my-project
region = us-central1
zone = us-central1-a
```

With the above, you can now connect to all your instances in a single
`us-central1-a` zone via IAP.

You can also couple this with the GCP dynamic inventory like so:

```yaml
plugin: google.cloud.gcp_compute
zones:
  - us-central1-a
  - us-central1-b
  - us-central1-c
  - us-central1-f
projects:
  - my-project
service_account_file: /path/to/my/service-account.json
auth_kind: serviceaccount
scopes:
  - 'https://www.googleapis.com/auth/cloud-platform'
  - 'https://www.googleapis.com/auth/compute.readonly'

# Create groups from labels e.g.
keyed_groups:
  - prefix: gcp
    key: labels.gcp_role

# inventory_hostname needs to be the actual name of the instance
hostnames:
  - name

# fetch zone dynamically to feed IAP plugin
compose:
  ansible_gcloud_zone: zone

# maybe add some filters
filters:
  - 'status = RUNNING'
  - 'labels.my-special-label:some-value'
```

with the above, you don't need to statically set the zone, they will be
populated accordingly.

The rest of the connection behavior can be configured just like the builtin SSH
ansible plugin, e.g. remote user, etc.
