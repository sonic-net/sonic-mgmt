Role Name
=========

This role deletes an ONTAP vserver and dependents:
- all volumes are deleted, including any user data !!!
- clones and snapshots are deleted as well !!!
- network interfaces are deleted
- as the vserver is deleted, the associated, DNS entries, routes, NFS/CIFS/iSCSI servers as applicable, export policies and rules, are automatically deleted by ONTAP.

Requirements
------------

- ONTAP collection.
- ONTAP with REST support (9.7 or later).

- The module requires the jmespath python package.
- If json_query is not found, you may need to install the community.general collection.
- C(ansible-galaxy collection install community.general)

Role Variables
--------------

This role expects the following variables to be set:
- netapp_hostname: IP address of ONTAP admin interface (can be vsadmin too).
- netapp_username: user account with admin or vsadmin role.
- netapp_password: for the user account with admin or vsadmin role.
- vserver_name: name of vserver to delete.

In order to delete a CIFS server, the following variables are required
- cifs_ad_admin_user_name: AD admin user name
- cifs_ad_admin_password: AD admin password

The following variables are preset but can be changed
- https: true 
- validate_certs: true      (true is strongly recommended)
- debug_level: 0
- enable_check_mode: false
- confirm_before_removing_cifs_server: true
- confirm_before_removing_igroups: true
- confirm_before_removing_interfaces: true
- confirm_before_removing_volumes: true
- cifs_force_delete: true   (delete the CIFS server regardless of communication errors)


Example Playbook
----------------



```
---
- hosts: localhost
  gather_facts: no
  vars:
    login: &login
      netapp_hostname: ip_address
      netapp_username: admin
      netapp_password: XXXXXXXXX
      https: true
      validate_certs: false
  roles:
    - role: netapp.ontap.na_ontap_vserver_delete
      vars:
        <<: *login
        vserver_name: ansibleSVM
        # uncomment the following line to accept volumes will be permanently deleted
        # removing_volumes_permanently_destroy_user_data: I agree
        # turn confirmation prompts on or off
        confirm_before_removing_cifs_server: false
        confirm_before_removing_igroups: false
        confirm_before_removing_interfaces: false
        # optional - change the following to false to remove any confirmation prompt before deleting volumes !!!
        # when confirmations are on, you may receive two prompts:
        # 1. delete all clones if they exist.  The prompt is not shown if no clone exists.
        # 2. delete all volumes if any.  The prompt is not shown if no volume exists.
        confirm_before_removing_volumes: true

```

License
-------

BSD

Author Information
------------------

https://github.com/ansible-collections/netapp.ontap
