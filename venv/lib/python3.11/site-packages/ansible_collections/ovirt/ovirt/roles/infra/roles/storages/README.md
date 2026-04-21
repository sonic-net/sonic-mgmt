oVirt Storages
==============

The `storages` role is used to set up oVirt storages.

Role Variables
--------------

The value of item in `storages` dictionary can contain following parameters (the key is always a name of the storage):

| Name            | Default value  | Description                           |
|-----------------|----------------|---------------------------------------|
| master          | false          | If true, the storage will be added as the first storage, meaning it will be the master storage. |
| domain_function | data           | The function of the storage domain. Possible values are: <ul><li>iso</li><li>export</li><li>data</li></ul>. |
| localfs         | UNDEF          | Dictionary defining local storage. |
| nfs             | UNDEF          | Dictionary defining NFS storage. |
| iscsi           | UNDEF          | Dictionary defining iSCSI storage. |
| posixfs         | UNDEF          | Dictionary defining PosixFS storage. |
| fcp             | UNDEF          | Dictionary defining FCP storage. |
| glusterfs       | UNDEF          | Dictionary defining glusterFS storage. |
| discard_after_delete  | UNDEF    | If True storage domain blocks will be discarded upon deletion. Enabled by default. This parameter is relevant only for block based storage domains. |

More information about the storages parameters can be found in the [Ansible documentation](http://docs.ansible.com/ansible/ovirt_storage_domains_module.html).

Example Playbook
----------------

```yaml
- name: oVirt infra
  hosts: localhost
  connection: local
  gather_facts: false

  vars:
    storages:
      mynfsstorage:
       master: true
       state: present
       nfs:
        address: 1.2.3.4
        path: /path
      myiscsistorage:
        state: present
        iscsi:
          target: iqn.2014-07.org.ovirt:storage
          port: 3260
          address: 10.11.12.13
          username: username
          password: password
          lun_id: 3600140551fcc8348ea74a99b6760fbb4
          discard_after_delete: false
      myexporttemplates:
        domain_function: export
        nfs:
          address: 100.101.102.103
          path: /templates
      myisostorage:
        domain_function: iso
        nfs:
          address: 111.222.111.222
          path: /iso

  roles:
    - ovirt.ovirt.infra.roles.storages
```
