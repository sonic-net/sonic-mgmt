oVirt Remove Stale LUN
=========

The `remove_stale_lun` role iterates through all the hosts in a data center and remove stale LUN devices from these hosts.
Example playbook uses engine private ssh key for connection to the hosts and therefore assumes it's executed from the engine machine.
If the playbook is not executed on the engine, user ssh key has to be added on all hosts which belongs to the given data center or the user has to provide appropriate inventory file.

Role Variables
--------------

| Name                    | Default value         |                                                     |
|-------------------------|-----------------------|-----------------------------------------------------|
| data_center             | Default               | Name of the data center from which hosts stale LUN should be removed. |
| lun_wwid                | UNDEF                 | WWID of the stale LUN(s) which should be removed from the hosts. Separate multiple LUNs with spaces. |


Example Playbook
----------------

```yaml
---
- name: oVirt remove stale LUN
  hosts: localhost
  connection: local
  gather_facts: false

  vars_files:
    # Contains encrypted `engine_password` varibale using ansible-vault
    - passwords.yml

  vars:
    ansible_ssh_common_args: "-o StrictHostKeyChecking=no"
    ansible_user: root
    ansible_ssh_private_key_file: /etc/pki/ovirt-engine/keys/engine_id_rsa

    engine_fqdn: ovirt.example.com
    engine_user: admin@internal

    data_center: default
    lun_wwid: 36001405a77a1ee25cbf4439b7ddd2062 36001405ddefe8392bb8443e89bde4b40

  roles:
    - remove_stale_lun
  collections:
    - ovirt.ovirt
```
