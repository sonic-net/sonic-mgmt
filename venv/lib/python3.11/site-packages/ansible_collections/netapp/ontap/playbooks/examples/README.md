=============================================================

 netapp.ontap

 NetApp ONTAP Collection

 Copyright (c) 2020 NetApp, Inc. All rights reserved.
 Specifications subject to change without notice.

=============================================================
# Playbook examples

As the name indicates, these are examples, and while they are working at the time of publication, we do not support these playbooks.
We cannot guarantee they are working on other systems, or other configurations, or other versions than what we used at the time.
We will not maintain these playbooks as time passes.

## ONTAP Firmware Updates

By default, downloading a firmware image is enough to trigger an update.
The update happens automatically in background for the disk qualification package and for disk, shelf, and ACP firmwares.  It is designed to be non disruptive.

The SP firmware will be automatically installed, but requires a node reboot.  The reboot is not done in these playbooks.

The na_ontap_pb_upgrade_firmware playbooks are illustrating three ways to use variables in an Ansible playbook:
1. directly inside the playbook, under the `vars:` keyword
1. by importing an external file, under the `vars_file:` keyword
1. by adding `--extra-vars` to the `ansible-playbook` command line.  Using `@` enables to use a file rather than providing each variable explicitly.

```
ansible-playbook ansible_collections/netapp/ontap/playbooks/examples/na_ontap_pb_upgrade_firmware.yml

ansible-playbook ansible_collections/netapp/ontap/playbooks/examples/na_ontap_pb_upgrade_firmware_with_vars_file.yml

ansible-playbook ansible_collections/netapp/ontap/playbooks/examples/na_ontap_pb_upgrade_firmware_with_extra_vars.yml --extra-vars=@/tmp/ansible/ontap_vars_file.yml
```

The advantage of using a vars_file is that you can keep important variables private.  --extra-vars provides more flexibility regarding the location of the vars file.
