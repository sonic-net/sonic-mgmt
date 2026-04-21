theforeman.foreman.operatingsystems
===================================

This role creates and manages Operatingsystems.

Role Variables
--------------

This role supports the [Common Role Variables](https://github.com/theforeman/foreman-ansible-modules/blob/develop/README.md#common-role-variables).

The main data structure for this role is the list of `foreman_operatingsystems`. Each `operatingsystem` requires the following fields:

- `name`: The name of the operatingsystem.

For all other fields see the `operatingsystem` module. The field `default_templates` can also be used to assign
default provisioning templates for the operatingsystem where each `template` consists of the fields from the module
`os_default_template`.

Example Playbook
----------------

Create operating system `RedHat 8.5` and assign it templates for provisioning using `cloud-init` and `open-vm-tools`:

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.operatingsystems
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_operatingsystems:
          - name: "RedHat"
            major: "8"
            minor: "5"
            os_family: "Redhat"
            password_hash: "SHA256"
            default_templates:
              - template_kind: "cloud-init"
                provisioning_template: "CloudInit default"
              - template_kind: "user_data"
                provisioning_template: "UserData open-vm-tools"
```
