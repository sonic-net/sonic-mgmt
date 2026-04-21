oVirt Permissions
=================

The `permissions` role is used to set up oVirt permissions.

Role Variables
--------------

The `permissions` list can contain following parameters:

| Name          | Default value  | Description                |
|---------------|----------------|----------------------------|
| state         | present        | Specifies whether the state of the permission is `present` or `absent`.    |
| user_name     | UNDEF          | The user to manage the permission for. |
| group_name    | UNDEF          | Name of the group to manage the permission for. |
| authz_name    | UNDEF          | Name of the authorization provider of the group or user. |
| role          | UNDEF          | The role to be assigned to the user or group. |
| object_type   | UNDEF          | The object type which should be used to assign the permission. Possible object types are:<ul><li>data_center</li><li>cluster</li><li>host</li><li>storage_domain</li><li>network</li><li>disk</li><li>vm</li><li>vm_pool</li><li>template</li><li>cpu_profile</li><li>disk_profile</li><li>vnic_profile</li><li>system</li></ul> |
| object_name   | UNDEF          | Name of the object where the permission should be assigned. |


Example Playbook
----------------

```yaml
- name: oVirt infra
  hosts: localhost
  connection: local
  gather_facts: false

  vars:
    permissions:
      - state: present
        user_name: user1
        authz_name: internal-authz
        role: UserRole
        object_type: cluster
        object_name: production

      - state: present
        group_name: group1
        authz_name: internal-authz
        role: UserRole
        object_type: cluster
        object_name: production

  roles:
    - ovirt.ovirt.infra.roles.permissions
```
