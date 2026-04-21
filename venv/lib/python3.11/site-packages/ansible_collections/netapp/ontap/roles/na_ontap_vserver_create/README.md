na_ontap_vserver_create
=========

Create one or more Vservers.

Creates Vserver with specified protocol(s).  Will join to Windows Domain provided AD credintals are included.
Modifies default rule for NFS protocol to 0.0.0.0/0 ro to allow NFS connections

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

ontap_version: <version minor code> # OPTIONAL This defaults to ontap version minor code 140 (9.4) if running this against 9.3 or below add this variable and set to 120

#Based on if Variables != or == None determins if a section runs.  Each variable will take one or more dictonary entries.  Simply omit sections
#that you don't want to run.  The following would run all sections

vservers: # Vservers to create
  - { name: nfs_vserver, aggr: aggr1, protocol: nfs }
  # aggr_list is optional.  If not specified all aggregates will be added to the allowed list.
  - { name: nfs_vserver2, aggr: aggr1, protocol: nfs, aggr_list: "aggr1,aggr2" }
  # with protocol: nfs, the keys nfsv3, nfsv4, nfsv41 are optional, the default values are as shown below.
  - { name: nfs_vserver3, aggr: aggr1, protocol: nfs, nfsv3: enabled, nfsv4: disabled, nfsv41: disabled }
  - { name: cifs_vserver, aggr: aggr1, protocol: cifs }

vserver_dns: # DNS at the Vserver level.
  - { vserver: cifs_vserver, dns_domains: lab.local, dns_nameservers: 172.32.0.40 }

lifs: # interfaces for the Vservers being created - only IP interfaces are supported.
      # with REST, ipspace, broadcast_domain, service_policy, interface_type (but only with a value of "ip") are also supported.
  - { name: nfs_vserver_data_lif, vserver: nfs_vserver, node: cluster-01, port: e0c, protocol: nfs, address: 172.32.0.193, netmask: 255.255.255.0 }
  - { name: cifs_vserver_data_lif, vserver: cifs_vserver, node: cluster-01, port: e0d, protocol: cifs, address: 172.32.0.194, netmask: 255.255.255.0 }
  # With 21.24.0, protocol is not required when using REST.  When protocol is absent, role and firewall_policy are omitted.
  # With 21.24.0, vserver management interfaces can also be created when using REST:
  - { name: vserver_mgmt_lif, vserver: nfs_vserver, node: cluster-01, port: e0e, service_policy: default-management, address: 172.32.0.192, netmask: 255.255.255.0}

gateway: # To configure the default gateway for the Vserver.
  - { vserver: nfs_vserver, destination: 0.0.0.0/0, gateway: 172.32.0.1 }

cifs: # Vservers to join to an AD Domain
  - { vserver: cifs_vserver, cifs_server_name: netapp1, domain: ansible.local, force: true }

fcp: # sets FCP ports as Target
  - { adapter: 0e, node: cluster-01 }
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
  vars_prompt:
    - name: admin_user_name
      prompt: domain admin (enter if skipped)
    - name: admin_password
      prompt: domain admin password (enter if skipped)
  vars_files:
    - globals.yml
  roles:
  - na_ontap_vserver_create
```
I use a globals file to hold my variables.
```
---
globals.yml
cluster_name: cluster

netapp_hostname: 172.32.0.182
netapp_username: admin
netapp_password: netapp123

vservers:
  - { name: nfs_vserver, aggr: aggr1, protocol: NFS }
  - { name: cifs_vserver, aggr: aggr1, protocol: cifs }
  - { name: nas_vserver, aggr: aggr1, protocol: 'cifs,nfs' }

lifs:
  - { name: nfs_vserver_data_lif, vserver: nfs_vserver, node: vsim-01, port: e0c, protocol: nfs, address: 172.32.0.183, netmask: 255.255.255.0 }
  - { name: cifs_vserver_data_lif, vserver: cifs_vserver, node: vsim-01, port: e0c, protocol: nfs, address: 172.32.0.184, netmask: 255.255.255.0 }
  - { name: nas_vserver_data_lif, vserver: nas_vserver, node: vsim-02, port: e0c, protocol: nfs, address: 172.32.0.185, netmask: 255.255.255.0 }

vserver_dns:
  - { vserver: cifs_vserver, dns_domains: lab.local, dns_nameservers: 172.32.0.40 }

cifs:
  - { vserver: cifs_vserver, cifs_server_name: netapp1, domain: openstack.local, force: true }
```

License
-------

GNU v3

Author Information
------------------
NetApp
http://www.netapp.io
