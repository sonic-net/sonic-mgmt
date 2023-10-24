Ansible Playbook for data center topology

###### Playbook:  dc_topo_config.yml

This is an example playbook to demonstrate data center admins on how Ansible can be used to backup and deploy SONiC switch configuration to all SONiC switches. The playbook can backup the configuration from all SONiC switches on the data center, allow to make required changes to it and deploy the modified configuration. The playbook can be used to apply the initial configuration for all the switches on the data center.

###### Usage and command line options

Use the command line option `-e config_backup` to backup each SONiC nodes configuration to the Ansible control node. Command line option `-e config_appy` can used to apply the saved configuration.

Examples :
```bash
ansible-playbook dc_topo_config.yml -e config_backup=yes
ansible-playbook dc_topo_config.yml -e config_apply=yes
```

###### Config file backup location and file format
This playbook backs up the `/etc/sonic/config_db.json` and `/etc/sonic/frr/frr.conf` files to role/dc/files folder with the switch name prepended to the actual config file. For example `config_db.json` from the switch having hostname `spine1` will be backed up as `spine1_config_db.json`

Note: This playbook expects unique hostname on each SONiC switch.

###### Design details
This playbook includes an Ansible role named `dc` which has task lists for backing up / applying configuration and a trigger handler to reload the SONiC configuration when it detects a change in device configuration. This playbooks can be modified to generate the configuration file from a jinja2 template, but that would force user to modify the template whenever he/she has additional switch configuration.

###### Ansible Inventory
Ansible relies on the inventory file `/etc/ansible/hosts` for knowing the switch groups and IP address of each switch. Its recommended to divide the switches into multiple groups based on their role on the DC topology like spine, leaf, edge and sonic-switches(all the switches)


```c
example inventory file
[spine]
spine1
spine2

[leaf]
leaf1
leaf2
leaf3
leaf4

[edge]
edge1
edge2
```

