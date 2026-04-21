theforeman.foreman.compute_resources
====================================

This role creates and manages Compute Resources.

Role Variables
--------------

This role supports the [Common Role Variables](https://github.com/theforeman/foreman-ansible-modules/blob/develop/README.md#common-role-variables).

The main data structure for this role is the list of `foreman_compute_resources`. Each `compute_resource` requires the following fields:

- `name`: The name of the compute resource.

The following fields are optional and will be omitted by default:

- `description`: Description of the compute resource
- `provider`: Compute resource provider. Required if *state=present_with_defaults*.
- `provider_params`: Parameter specific to compute resource provider. Required if *state=present_with_defaults*.

Each `compute_resource` can also list a number of `images` associated with the compute resource.

Example Playbooks
-----------------

Create a compute resource for vSphere, with a single image for RHEL 8.4.

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.compute_resources
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_organization: "Default Organization"
        foreman_compute_resources:
          - name: "VMware"
            organizations:
              - "Default Organization"
              - "Second Organization"
            locations:
              - "Default Location"
            provider: "vmware"
            provider_params:
              url: "vcenter.example.com"
              user: "administrator@vsphere.local"
              password: "changeme"
              datacenter: "ha-datacenter"
              images:
                - name: "RHEL-8.4"
                  operatingsystem: "RedHat-8.4"
                  architecture: "x86_64"
                  user_data: true
                  image_username: "root"
                  image_password: "changeme"
                  uuid: "Templates/rhel-8.4-template"
```
