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

## ONTAP list volumes that are online, or offline

The na_ontap_pb_get_online_volumes playbook illustrate two ways to use json_query:
1. to flatten a complex structure and extract only the fields of interest,
2. to filter the fields of interest based on some criteria.

The na_ontap_pb_get_online_volumes playbook illustrates three ways to use variables in an Ansible playbook:
1. directly inside the playbook, under the `vars:` keyword,
1. by importing an external file, under the `vars_files:` keyword,
1. by adding `--extra-vars` to the `ansible-playbook` command line.  Using `@` enables to use a file rather than providing each variable explicitly.

Note that `--extra-vars` has the highest precedence.  `vars` has the lowest precedence.  It is possible to comnbine the 3 techniques within a single playbook.

The advantage of using a vars_file is that you can keep important variables private.  --extra-vars provides more flexibility regarding the location of the vars file.
