oVirt Mac Pools
=================

The `mac_pools` role is used to set up oVirt mac pools.

Role Variables
--------------

| Name                  | Default value         |  Description                                              |
|-----------------------|-----------------------|-----------------------------------------------------------|
| mac_pools             | UNDEF                 | List of dictionaries that describe the mac pool.          |

The items in `mac_pools` list can contain the following parameters:

| Name                      | Default value         | Description                                                       |
|---------------------------|-----------------------|-------------------------------------------------------------------|
| mac_pool_name             | UNDEF                 | Name of the the MAC pool to manage.                               |
| mac_pool_ranges           | UNDEF                 | List of MAC ranges. The from and to should be splitted by comma. For example: 00:1a:4a:16:01:51,00:1a:4a:16:01:61 |
| mac_pool_allow_duplicates | UNDEF                 | If (true) allow a MAC address to be used multiple times in a pool. Default value is set by oVirt engine to false. |

Example Playbook
----------------

```yaml
- name: oVirt set mac pool
  hosts: localhost
  connection: local
  gather_facts: false

  vars:
    mac_pools:
      - mac_pool_name: my_mac_pool
        mac_pool_allow_duplicates: false
        mac_pool_ranges:
          - 00:1a:4a:16:01:51,00:1a:4a:16:01:61

  roles:
    - ovirt.ovirt.infra.roles.mac_pools
```
