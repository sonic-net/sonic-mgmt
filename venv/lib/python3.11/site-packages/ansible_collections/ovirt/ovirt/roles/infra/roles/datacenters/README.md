oVirt Datacenters
=================

The `datacenters` role is used to set up or cleanup oVirt datacenters.

Role Variables
--------------

| Name                     | Default value         | Description                          |
|--------------------------|-----------------------|--------------------------------------|
| data_center_name         | UNDEF                 | Name of the data center.              |
| data_center_description  | UNDEF                 | Description of the data center.       |
| data_center_local        | false                 | Specify whether the data center is shared or local. |
| compatibility_version    | UNDEF                 | Compatibility version of data center. |
| data_center_state        | present               | Specify whether the datacenter should be present or absent. |
| recursive_cleanup        | false                 | Specify whether to recursively remove all entities inside DC. Valid only when state == absent. |
| format_storages          | false                 | Specify whether to format ALL the storages that are going to be removed as part of the DC. Valid only when data_center_state == absent and recursive_cleanup == true. |

Example Playbooks
----------------

```yaml
# Example 1

- name: Add oVirt datacenter
  hosts: localhost
  connection: local
  gather_facts: false

  vars:
   data_center_name: mydatacenter
   data_center_description: mydatacenter
   data_center_local: false
   compatibility_version: 4.4

  roles:
    - ovirt.ovirt.infra.roles.datacenters
```

```yaml
# Example 2

- name: Recursively remove oVirt datacenter
  hosts: localhost
  connection: local
  gather_facts: false

  vars:
   data_center_name: mydatacenter
   data_center_state: absent
   recursive_cleanup: true
   format_storages: true

  roles:
    - ovirt.ovirt.infra.roles.datacenters
```
