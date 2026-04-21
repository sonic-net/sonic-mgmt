theforeman.foreman.content_rhel
===============================

This role is an opinionated reuse of other roles in the collection, which creates a basic configuration for everything needed to register and patch existing RHEL clients.

That includes uploading a subscription manifest to an organization; enabling base RHEL7 and RHEL8 repositories (x86_64 architecture), syncing them immediately, and creating a sync plan for future syncs; and creating an activation key `base_rhel_key` to use when registering RHEL clients.

The subscription manifest will be retrieved from the specified path on the Ansible target host; optionally, it can be fetched first from the RHSM portal using the provided login credentials and manifest UUID. It will be uploaded to the specified organization.

By default, the role enables the rhel-7-server-rpms repository with the 7Server release and x86_64 architecture, as well as rhel-8-for-x86_64-baseos-rpms and rhel-8-for-x86_64-appstream-rpms. The manifest must provide access to all enabled content for the role to work properly.

The role creates a sync plan using any of the sync plan intervals supported by the basic [Sync Plan Role](https://github.com/theforeman/foreman-ansible-modules/blob/develop/roles/sync_plans/README.md).

The role creates an activation key with the provided name. This activation key will register client systems in the "Library" lifecycle environment and "Default Organization View" content view, using the subscription auto-attach feature.

Role Variables
--------------

This role supports the [Common Role Variables](https://github.com/theforeman/foreman-ansible-modules/blob/develop/README.md#common-role-variables).

This role supports the same variables used in the [Manifest Role](https://github.com/theforeman/foreman-ansible-modules/blob/develop/roles/manifest/README.md#role-variables).

It also supports customizing the included roles with:

`foreman_sync_plan_name`: Name of the sync plan to create. Default 'RHEL Sync Plan'

`foreman_sync_plan_interval`: 'hourly', 'daily', 'weekly', or 'custom cron'. See the [Sync Plan Role Documentation](https://github.com/theforeman/foreman-ansible-modules/blob/develop/roles/manifest/README.md#role-variables) for more information. Default 'daily'

`foreman_sync_plan_cron_expression`: Required when using the 'custom cron' `sync_plan_interval`.

`foreman_sync_plan_sync_date`: Initial sync date for the sync plan, formatted as 'YYYY-MM-DD HH:MM:SS UTC'.

`foreman_activation_key_name`: Name of the activation key to create. Default 'base_rhel_key'

Repository behavior is controlled via the variables:

`foreman_content_rhel_enable_rhel7`: Enable rhel-7-server-rpms repository (x86 architecture and 7Server release). Default true.

`foreman_content_rhel_enable_rhel8`: Enable rhel-8-for-x86_64-baseos-rpms and rhel-8-for-x86_64-appstream-rpms (x86 architecture). Default true.

`foreman_content_rhel_rhel8_releasever`: Version of RHEL 8 repositories. Default `8`.

`foreman_content_rhel_sync_now`: Sync repositories immediately after enabling. Default true.

`foreman_content_rhel_wait_for_syncs`: Monitor status of sync tasks. When false, the sync tasks will continue running in the background after the playbook has finished running. This option is most useful when other automation (for example, registering and patching a client) requires the repository syncs to have completed. Default true.

Example Playbooks
-----------------

This minimal example assumes the manifest has already been downloaded to ~/manifest.zip on localhost (the Ansible control node) and uploads that manifest to the ACME organization. It enables RHEL7 and RHEL8 repositories, creates the role default sync plan for them, and also syncs the repositories immediately. It creates an activation key with the role default name `base_rhel_key`.

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.content_rhel
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_organization: "ACME"
        foreman_manifest_download: false
        foreman_manifest_path: "~/manifest.zip"
```

This example is identical to the above example, except instead of assuming the manifest is already downloaded at ~/manifest.zip, we first use the provided rhsm_{username,password} and manifest_uuid to download it from the Red Hat Customer Portal.

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.content_rhel
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_organization: "ACME"
        foreman_manifest_download: true
        foreman_rhsm_username: "happycustomer"
        foreman_rhsm_password: "$ecur3p4$$w0rd"
        foreman_manifest_uuid: "01234567-89ab-cdef-0123-456789abcdef"
        foreman_manifest_path: "~/manifest.zip"
```

This example downloads a manifest with the provided UUID from the RHSM portal using the provided credentials and copies it to ~/manifest.zip before uploading it to "Default Organization". It then enables the RHEL7 and RHEL8 repositories without syncing them immediately, but creates a sync_plan which syncs the repositories at midnight each day. It creates an activation key "RHEL_Key" to register existing RHEL content hosts.

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.content_rhel
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_organization: "Default Organization"
        foreman_manifest_download: true
        foreman_rhsm_username: "happycustomer"
        foreman_rhsm_password: "$ecur3p4$$w0rd"
        foreman_manifest_uuid: "01234567-89ab-cdef-0123-456789abcdef"
        foreman_manifest_path: "~/manifest.zip"
        foreman_content_rhel_sync_now: false
        foreman_sync_plan_name: "Daily RHEL Sync"
        foreman_sync_plan_interval: daily
        foreman_sync_plan_sync_date: 2021-02-02 00:00:00 UTC
        foreman_activation_key_name: "RHEL_Key"
        foreman_content_rhel_rhel8_releasever: 8.4
```

This example assumes the manifest has already been downloaded to ~/my_subscription_manifesst.zip on localhost and uploads that manifest to the ACME organization. It enables the rhel-7-server-rpms repository only, syncs it immediately, and also creates a custom cron sync plan for it. It creates an activation key "RHEL_Key" to register existing RHEL content hosts.

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.content_rhel
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_organization: "ACME"
        foreman_manifest_download: false
        foreman_manifest_path: "~/my_subscription_manifest.zip"
        foreman_content_rhel_enable_rhel8: false
        foreman_sync_plan_name: "RHEL Sync Plan"
        foreman_sync_plan_interval: custom cron
        foreman_sync_plan_cron_expression: 0 6 8 * *
        foreman_sync_plan_sync_date: 2021-02-02 00:00:00 UTC
        foreman_activation_key_name: "RHEL_Key"
```
