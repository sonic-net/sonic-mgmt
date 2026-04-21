theforeman.foreman.convert2rhel
===============================

This role creates a basic configuration for everything needed to register and convert CentOS clients to Red Hat Enterprise Linux.

First step is upload of manifest and synchronization of RHEL repositories. For more detail see [content_rhel Role](https://github.com/theforeman/foreman-ansible-modules/blob/develop/roles/content_rhel/README.md).

Then the role creates Convert2RHEL products & repositories (and synchronizes them), activation keys and host groups for each OS.

If simple content access is disabled, subscriptions and repositories for RHEL activation keys must be added manually.

Role Variables
--------------

This role supports the [Common Role Variables](https://github.com/theforeman/foreman-ansible-modules/blob/develop/README.md#common-role-variables) and [Content RHEL variables](https://github.com/theforeman/foreman-ansible-modules/blob/develop/roles/content_rhel/README.md)

- `foreman_convert2rhel_manage_subscription`: Run [content_rhel Role](https://github.com/theforeman/foreman-ansible-modules/blob/develop/roles/content_rhel/README.md) role, default: `true`
- `foreman_convert2rhel_lifecycle_env`: Lifecycle environment for activation keys, default: Library.
- `foreman_convert2rhel_content_view`: Content view for activation keys, default: Default Organization View.
- `foreman_convert2rhel_enable_oracle7`: Create data for Oracle Linux 7 conversion, default: `false`

Example Playbooks
-----------------

Convert2RHEL

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.convert2rhel
      vars:
        foreman_server_url: "https://foreman.example.com"
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_organization: "Default Organization"
        foreman_manifest_path: "~/manifest.zip"
        foreman_content_rhel_enable_rhel7: true
        foreman_content_rhel_enable_rhel8: true
        foreman_content_rhel_rhel8_releasever: 8.5
        foreman_content_rhel_wait_for_syncs: false
        foreman_convert2rhel_lifecycle_env: "Library"
        foreman_convert2rhel_content_view: "Default Organization View"
        foreman_convert2rhel_enable_oracle7: true
```
