theforeman.foreman.compute_profiles
===================================

This role creates and manages Compute Profiles.

Role Variables
--------------

This role supports the [Common Role Variables](https://github.com/theforeman/foreman-ansible-modules/blob/develop/README.md#common-role-variables).

The main data structure for this role is the list of `foreman_compute_profiles`. Each `compute_profile` requires the following fields:

- `name`: The name of the compute profile.

The following fields are optional and will be omitted by default:

- `description`: Description of the compute profile
- `compute_attributes`: List of attributes for the profile on specific compute resources.

Example Playbooks
-----------------

Create a compute profile named `1-Small` with a VMware spec of 1 single core CPU, 2 GiB of memory, 15 GiB of disk, and a VMXNET3 network card connected to `VM Network`:

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.compute_profiles
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_organization: "Default Organization"
        foreman_compute_profiles:
          - name: "1-Small"
            compute_attributes:
              - compute_resource: "VMware"
                vm_attrs:
                  cluster: "cluster01"
                  path: /Datacenters/ha-datacenter/vm/
                  memoryHotAddEnabled: true
                  cpuHotAddEnabled: true
                  cpus: 1
                  corespersocket: 1
                  memory_mb: 2048
                  volumes_attributes:
                    0:
                      datastore: "datastore1"
                      size_gb: 15
                  interfaces_attributes:
                    0:
                      type: "VirtualVmxnet3"
                      network: "VM Network"
```
