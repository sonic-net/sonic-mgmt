theforeman.foreman.settings
===========================

This role creates and manages Settings.

Role Variables
--------------

This role supports the [Common Role Variables](https://github.com/theforeman/foreman-ansible-modules/blob/develop/README.md#common-role-variables).

The main data structure for this role is the list of `foreman_settings`. Each `setting` must contain the field `name` and may contain the optional field `value` which if empty will reset the setting to the default value.

Example Playbook
----------------

Enable *Destroy associated VM on host delete* and disable *Clean up failed deployment*:

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.settings
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_settings:
          - name: destroy_vm_on_host_delete
            value: true
          - name: clean_up_failed_deployment
            value: false
```
