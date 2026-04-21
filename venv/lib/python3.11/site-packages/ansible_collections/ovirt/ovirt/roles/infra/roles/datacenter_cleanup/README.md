oVirt Datacenter Cleanup
========================

The `datacenter_cleanup` role is used to cleanup all entities inside
oVirt datacenters and finally remove the datacenters themselves.

Role Variables
--------------

| Name                     | Default value         | Description                          |
|--------------------------|-----------------------|--------------------------------------|
| data_center_name         | UNDEF                 | Name of the data center.             |
| format_storages          | false                 | Whether role should format storages when removing them. |

Example Playbook
----------------

```yaml
- name: oVirt infra
  hosts: localhost
  connection: local
  gather_facts: false

  vars:
   data_center_name: mydatacenter
   format_storages: true

  roles:
    - ovirt.ovirt.infra.roles.datacenter_cleanup
```
