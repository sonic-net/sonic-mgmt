theforeman.foreman.organizations
================================

This role creates and manages organizations.

Role Variables
--------------

This role supports the [Common Role Variables](https://github.com/theforeman/foreman-ansible-modules/blob/develop/README.md#common-role-variables).

The main data structure for this role is the list of `foreman_organizations`. Each `organization` requires the following fields:

- `name`: The name of the organization.

The following fields are optional in the sense that the server will use default values when they are omitted:

- `label`: The label of the organization.
- `description`: The description of the organization.
- `state`: The state of the organization. Can be `present` or `absent`.

Additionally you can pass any other parameters accepted by the `organization` module.

Example Playbooks
-----------------

```yaml
--- 
- name: add organizations to foreman
  hosts: localhost
  gather_facts: false
  roles:
    - role: theforeman.foreman.organizations
      vars: 
        foreman_server_url: https://foreman.example.com
        foreman_username: admin
        foreman_password: changeme
        foreman_organizations: 
          - name: raleigh
            label: rdu
            state: present
          - name: default
            label: boring
            state: absent
          - name: lanai 
            description: pacific datacenter 
```
