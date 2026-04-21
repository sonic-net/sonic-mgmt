theforeman.foreman.provisioning_templates
=========================================

This role creates and manages Provisioning Templates.

Role Variables
--------------

This role supports the [Common Role Variables](https://github.com/theforeman/foreman-ansible-modules/blob/develop/README.md#common-role-variables).

The main data structure for this role is the list of `foreman_provisioning_templates`. Each `provisioning_template` accepts fields according to the module `provisioning_template`.

Example Playbook
----------------

Create a custom template `CloudInit vSphere` using the file `files/cloudinit_vsphere.erb` and assign it to the
operating systems `RedHat 7.9` and `RedHat 8.5`:

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.provisioning_templates
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_provisioning_templates:
          - name: CloudInit vSphere
            template: "{{ lookup('file', 'cloudinit_vsphere.erb') }}"
            operatingsystems:
              - RedHat 7.9
              - RedHat 8.5
```
