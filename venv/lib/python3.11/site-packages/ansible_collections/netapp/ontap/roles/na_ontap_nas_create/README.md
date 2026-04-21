na_ontap_nas_create
=========

Create one or more NFS or CIFS exports

Requirements
------------

Since this uses the NetApp ONTAP modules it will require the python library netapp-lib as well as the Ansible 2.8 release.

Role Variables
--------------
```
cluster: <short ONTAP name of cluster>
netapp_hostname: <ONTAP mgmt ip or fqdn>
netapp_username: <ONTAP admin account>
netapp_password: <ONTAP admin account password>

nas:
  - { name: nfs_share, protocol: nfs, vserver: nfs_vserver, client: 172.32.0.201, ro: sys, rw: sys, su: sys, aggr: aggr1, size: 10, share: share_name }
# If you are creating an NFS export you will omit the share: section.
# If you are creating a CIFS share you may omit the ro, rw, su, client sections.

```
Dependencies
------------

The tasks in this role are dependent on information from the na_ontap_gather_facts module.
The task for na_ontap_gather_facts can not be excluded.

Example Playbook
----------------
```
---
- hosts: localhost
  collections:
    - netapp.ontap
  vars_files:
    - globals.yml
  roles:
  - na_ontap_nas_create
```

I use a globals file to hold my variables.
```
cluster_name: cluster

netapp_hostname: 172.32.0.182
netapp_username: admin
netapp_password: netapp123

nas:
  - { name: nfs_share, protocol: nfs, vserver: nfs_vserver, client: 172.32.0.201, ro: sys, rw: sys, su: sys, aggr: aggr1, size: 10 }
  - { name: cifs_share, protocol: cifs, vserver: cifs_vserver, aggr: aggr1, size: 10, share: cifs_share_1 }
```

License
-------

GNU v3

Author Information
------------------
NetApp
http://www.netapp.io
