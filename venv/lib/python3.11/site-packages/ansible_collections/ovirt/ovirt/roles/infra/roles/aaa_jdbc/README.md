oVirt AAA JDBC
==============

The `aaa_jdbc` role manages users and groups in an AAA JDBC extension.

Role Variables
--------------

The items in `users` list can contain the following parameters:

| Name          | Default value  | Description                           |
|---------------|----------------|---------------------------------------|
| state         | present        | Specifies whether the user is `present` or `absent`. |
| name          | UNDEF          | Name of the user.                      |
| authz_name    | UNDEF          | Authorization provider of the user.    |
| password      | UNDEF          | Password of the user.                  |
| valid_to      | UNDEF          | Specifies the date that the account remains valid. |
| attributes    | UNDEF          | A dict of attributes related to the user. Available attributes: <ul><li>department</li><li>description</li><li>displayName</li><li>email</li><li>firstName</li><li>lasName</li><li>title</li></ul>|

The items in `user_groups` list can contain the following parameters:

| Name          | Default value  | Description                           |
|---------------|----------------|---------------------------------------|
| state         | present        | Specifies whether the group is `present` or `absent`. |
| name          | UNDEF          | Name of the group.                     |
| authz_name    | UNDEF          | Authorization provider of the group.   |
| users         | UNDEF          | List of users that belong to this group. |

Example Playbook
----------------

```yaml
- name: oVirt AAA jdbc
  hosts: localhost
  connection: local
  gather_facts: false

  vars:
    users:
     - name: user1
       authz_name: internal-authz
       password: 1234568
       valid_to: "2018-01-01 00:00:00Z"
     - name: user2
       authz_name: internal-authz
       password: 1234568
       valid_to: "2018-01-01 00:00:00Z"
       attributes:
         firstName: 'alice'
         department: 'Quality Engineering'

    user_groups:
     - name: group1
       authz_name: internal-authz
       users:
        - user1

  roles:
    - ovirt.ovirt.infra.roles.aaa_jdbc
```
