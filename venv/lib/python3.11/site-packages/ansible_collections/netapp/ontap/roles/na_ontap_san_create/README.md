na_ontap_san_create
=========

Create one or more luns for iSCSI or FCP

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

igroups:
  - { name: igroup1, vserver: san_vserver, group_type: iscsi, ostype: linux, initiator: "<iqn or wwpn>" } # the quotes for iqn/wwpn are necessary because of the : in them.
luns:
 - { name: lun1, vol_name: lun_vol, aggr: aggr1, vserver: san_vserver, size: 10, ostype: linux, space_reserve: false, igroup: igroup1 }

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
  roles
  - na_ontap_san_create
```

I use a globals file to hold my variables.
```
cluster_name: cluster

netapp_hostname: 172.32.0.182
netapp_username: admin
netapp_password: netapp123

igroups:
  - { name: igroup1, vserver: san_vserver, group_type: iscsi, ostype: linux, initiator: "iqn.1994-05.com.redhat:2750d14d868d" }

luns:
  - { name: lun1, vol_name: lun_vol, vserver: san_vserver, size: 10, ostype: linux, space_reserve: false, igroup: igroup1 }
```

License
-------

GNU v3

Author Information
------------------
NetApp
http://www.netapp.io
