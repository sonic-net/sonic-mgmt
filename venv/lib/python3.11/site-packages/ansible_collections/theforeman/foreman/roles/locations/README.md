theforeman.foreman.locations
===================================

This role creates and manages locations.

Role Variables
--------------

This role supports the [Common Role Variables](https://github.com/theforeman/foreman-ansible-modules/blob/develop/README.md#common-role-variables).

The main data structure for this role is the list of `foreman_locations`. Each `location` requires the following fields:

- `name`: The name of the location.

For all other fields, see the `location` module.

Example Playbook
----------------

Create the 'UK' location and set its parent to EMEA.

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.locations
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_locations:
          - name: UK
            organisations: 
              - RedHat
            parent: EMEA
            parameters:
              - name: system_location
                value: UK
```
