na_ontap_snapmirror_create
=========

Create or verify the following

Cluster peer
Vserver peer
Destination volume
Snapmirror relationship

Requirements
------------

Since this uses the NetApp ONTAP modules it will require the python library netapp-lib as well as the Ansible 2.8 release.

Role Variables
--------------
```
src_ontap: # IP or FQDN of the source ONTAP cluster
src_name: # Shortname of the source cluster 
src_lif: # IP address of a source Intercluster LIF
src_vserver: # Name of source Vserver
src_volume: # Name of source FlexVol
dst_ontap: # IP or FQDN of the destination ONTAP cluster
dst_name: # Shortname of the destination cluster
dst_lif: # IP address of a destination Intercluster LIF
dst_aggr: # Aggregate to create destination FlexVol on
dst_vserver: # Name of destination Vserver
username: # Admin username of both clusters
password: # Password for Admin username
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
  name: Snapmirror Create
  gather_facts: false
  vars:
    src_ontap: 172.32.0.182
    src_name: vsim
    src_lif: 172.32.0.187
    src_vserver: Marketing
    src_volume: Marketing_Presentation
    dst_ontap: 172.32.0.192
    dst_name: cvo
    dst_lif: 172.32.0.194
    dst_aggr: aggr1
    dst_vserver: backup_vserver
    username: admin
    password: netapp123
  roles:
    - na_ontap_snapmirror_create
```

License
-------

GNU v3

Author Information
------------------
NetApp
http://www.netapp.io
