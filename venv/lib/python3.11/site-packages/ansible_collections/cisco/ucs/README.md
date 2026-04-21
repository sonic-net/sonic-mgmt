# Ansible Collection - cisco.ucs

Ansible collection for managing and automing Cisco UCS Manager envrionments.  Modules and roles are provided for common Cisco UCS Manager tasks.

* Note: This collection is not compatible with versions of Ansible before v2.8.

## Requirements

- Ansible v2.8 or newer
- UCSM Python SDK (ucsmsdk)

## Install
- ansible must be installed
```
sudo pip install ansible
```
- ucsmsdk must be installed
```
sudo pip install ucsmsdk
```
We recommend verifying the ucsmsdk can connect to the domains you want to manage with Ansible.  Here is an example connection test using python:
```
# python
Python 2.7.14 (default, Apr 27 2018, 14:31:56) 
[GCC 4.8.5 20150623 (Red Hat 4.8.5-11)] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from ucsmsdk import ucshandle
>>> handle = ucshandle.UcsHandle(ip='172.22.250.236', username='admin', password='password')
>>> handle.login()
True
```

## Usage
Once Ansible is installed you can create inventory files and playbooks to manage your UCS domains.  Each module supports ansible-doc which includes example usage:
```
# ansible-doc cisco.ucs.ucs_vlans
<snip>
EXAMPLES:
- name: Configure VLAN
  cisco.ucs.ucs_vlans:
    hostname: 172.16.143.150
    username: admin
    password: password
    name: vlan2
    id: '2'
    native: 'yes'
```
This repository includes a playbooks directory with examples including an inventory file that can be edited with information for the UCSM domain you want to configure:
```
# vi inventory
[ucs]
13.58.22.56

[ucs:vars]
username=admin
password=password
```
An example_playbook.yml playbook is included to test VLAN configuration on the UCSM domain given in the inventory file:
```
# vi example_playbook.yml 

---
# Example Playbook: VLAN configuration using the [ucs] hosts group
- hosts: ucs
  connection: local
  collections:
    - cisco.ucs
  gather_facts: false
  tasks:
    - name: Configure VLAN
      ucs_vlans:
        hostname: "{{ inventory_hostname }}"
        username: "{{ username | default(omit) }}"
        password: "{{ password }}"
        state: "{{ state | default(omit) }}"
        name: vlan2
        id: '2'
        native: 'no'
      delegate_to: localhost
```
Ansible will use data from the inventory file for the hostname and other variables above.  Multiple UCSM domains can be listed in the inventory file and Ansible will configure all the listed domains in parallel using host specific data.

The ansible-playbook command can be used to run the above playbook and inventory file:
```
# ansible-playbook -i inventory example_playbook.yml 

PLAY [ucs] *********************************************************************

TASK [Configure VLAN] **********************************************************
ok: [13.58.22.56 -> localhost]

PLAY RECAP *********************************************************************
13.58.22.56                : ok=1    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0    
```

A more detailed configuration example is provided in the server_deploy.yml playbook.

# Support:

Please file Issues in this repository for any defects, feature requests, or questions on usage.
