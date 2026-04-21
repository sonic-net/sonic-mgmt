theforeman.foreman.manifest
===========================

Upload Subscription Manifest

Role Variables
--------------

This role supports the [Common Role Variables](https://github.com/theforeman/foreman-ansible-modules/blob/develop/README.md#common-role-variables).

- `foreman_manifest_path`: Path to subscription Manifest file on Ansible target host. When using `manifest_download`, it is first downloaded to this location from the Red Hat Customer Portal before being uploaded to the Foreman server.
- `foreman_manifest_download`: Whether to first download the Manifest from the Red Hat Customer Portal. Defaults to `False`.
- `foreman_manifest_uuid`: UUID of the Manifest to download, corresponding to a [Subscription Allocation](https://access.redhat.com/management/subscription_allocations) defined on your Red Hat account. Required when `manifest_download` is `True`.
- `foreman_rhsm_username`: Your username for the Red Hat Customer Portal. Required when `foreman_manifest_download` is `true`.
- `foreman_rhsm_password`: Your password for the Red Hat Customer Portal. Required when `foreman_manifest_download` is `true`.

Example Playbooks
-----------------

Use a Subscription Manifest which has already been downloaded on localhost at `~/manifest.zip`:

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.manifest
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_organization: "Default Organization"
        foreman_manifest_path: "~/manifest.zip"
```

Download the Subscription Manifest from the Red Hat Customer Portal to localhost before uploading to Foreman server:

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.manifest
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_organization: "Default Organization"
        foreman_manifest_path: "~/manifest.zip"
        foreman_manifest_download: true
        foreman_rhsm_username: "happycustomer"
        foreman_rhsm_password: "$ecur3p4$$w0rd"
        foreman_manifest_uuid: "01234567-89ab-cdef-0123-456789abcdef"
```

Download the Subscription Manifest from the Red Hat Customer Portal, via a proxy, to localhost before uploading to Foreman server:

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.manifest
      environment:
        https_proxy: "http://proxy.example.com:3128"
        no_proxy: "foreman.example.com"
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_organization: "Default Organization"
        foreman_manifest_path: "~/manifest.zip"
        foreman_manifest_download: true
        foreman_rhsm_username: "happycustomer"
        foreman_rhsm_password: "$ecur3p4$$w0rd"
        foreman_manifest_uuid: "01234567-89ab-cdef-0123-456789abcdef"
```
