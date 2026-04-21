# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
---
module: update_fact
short_description: Update currently set facts
version_added: "1.0.0"
description:
    - This module allows updating existing variables.
    - Variables are updated on a host-by-host basis.
    - Variables are not modified in place, instead they are returned by the module.
options:
  updates:
    description:
      - A list of dictionaries, each a desired update to make.
    type: list
    elements: dict
    required: True
    suboptions:
      path:
        description:
        - The path in a currently set variable to update.
        - The path can be in dot or bracket notation.
        - It should be a valid jinja reference.
        type: str
        required: True
      value:
        description:
        - The value to be set at the path.
        - Can be a simple or complex data structure.
        type: raw
        required: True


notes:

author:
- Bradley Thornton (@cidrblock)
"""

EXAMPLES = r"""

# Update an existing fact, dot or bracket notation
- name: Set a fact
  ansible.builtin.set_fact:
    a:
      b:
        c:
          - 1
          - 2

- name: Update the fact
  ansible.utils.update_fact:
    updates:
      - path: a.b.c.0
        value: 10
      - path: "a['b']['c'][1]"
        value: 20
  register: updated

- debug:
    var: updated.a

# updated:
#   a:
#     b:
#       c:
#       - 10
#       - 20
#   changed: true


# Lists can be appended, new keys added to dictionaries

- name: Set a fact
  ansible.builtin.set_fact:
    a:
      b:
        b1:
          - 1
          - 2

- name: Update, add to list, add new key
  ansible.utils.update_fact:
    updates:
      - path: a.b.b1.2
        value: 3
      - path: a.b.b2
        value:
          - 10
          - 20
          - 30
  register: updated

- debug:
    var: updated.a

# updated:
#   a:
#     b:
#       b1:
#       - 1
#       - 2
#       - 3
#       b2:
#       - 10
#       - 20
#       - 30
#   changed: true

#####################################################################
# Update every item in a list of dictionaries
# build the update list ahead of time using a loop
# and then apply the changes to the fact
#####################################################################

- name: Set fact
  ansible.builtin.set_fact:
    addresses:
      - raw: 10.1.1.0/255.255.255.0
        name: servers
      - raw: 192.168.1.0/255.255.255.0
        name: printers
      - raw: 8.8.8.8
        name: dns

- name: Build a list of updates
  ansible.builtin.set_fact:
    update_list: "{{ update_list + update }}"
  loop: "{{ addresses }}"
  loop_control:
    index_var: idx
  vars:
    update_list: []
    update:
      - path: addresses[{{ idx }}].network
        value: "{{ item['raw'] | ansible.netcommon.ipaddr('network') }}"
      - path: addresses[{{ idx }}].prefix
        value: "{{ item['raw'] | ansible.netcommon.ipaddr('prefix') }}"

- debug:
    var: update_list

# TASK [debug] *******************
# ok: [localhost] =>
#   update_list:
#   - path: addresses[0].network
#     value: 10.1.1.0
#   - path: addresses[0].prefix
#     value: '24'
#   - path: addresses[1].network
#     value: 192.168.1.0
#   - path: addresses[1].prefix
#     value: '24'
#   - path: addresses[2].network
#     value: 8.8.8.8
#   - path: addresses[2].prefix
#     value: '32'

- name: Make the updates
  ansible.utils.update_fact:
    updates: "{{ update_list }}"
  register: updated

- debug:
    var: updated

# TASK [debug] ***********************
# ok: [localhost] =>
#   updated:
#     addresses:
#     - name: servers
#       network: 10.1.1.0
#       prefix: '24'
#       raw: 10.1.1.0/255.255.255.0
#     - name: printers
#       network: 192.168.1.0
#       prefix: '24'
#       raw: 192.168.1.0/255.255.255.0
#     - name: dns
#       network: 8.8.8.8
#       prefix: '32'
#       raw: 8.8.8.8
#     changed: true
#     failed: false


#####################################################################
# Retrieve, update, and apply interface description change
# use index_of to locate Etherent1/1
#####################################################################

- name: Get the current interface config
  cisco.nxos.nxos_interfaces:
    state: gathered
  register: interfaces

- name: Update the description of Ethernet1/1
  ansible.utils.update_fact:
    updates:
      - path: "interfaces.gathered[{{ index }}].description"
        value: "Configured by ansible"
  vars:
    index: "{{ interfaces.gathered|ansible.utils.index_of('eq', 'Ethernet1/1', 'name') }}"
  register: updated

- name: Update the configuration
  cisco.nxos.nxos_interfaces:
    config: "{{ updated.interfaces.gathered }}"
    state: overridden
  register: result

- name: Show the commands issued
  debug:
    msg: "{{ result['commands'] }}"

# TASK [Show the commands issued] *************************************
# ok: [nxos101] => {
#     "msg": [
#         "interface Ethernet1/1",
#         "description Configured by ansible"
#     ]
# }


#####################################################################
# Retrieve, update, and apply an ipv4 ACL change
# finding the index of AFI ipv4 acls
# finding the index of the ACL named 'test1'
# finding the index of sequence 10
#####################################################################

- name: Retrieve the current acls
  arista.eos.eos_acls:
    state: gathered
  register: current

- name: Update the source of sequence 10 in the IPv4 ACL named test1
  ansible.utils.update_fact:
    updates:
      - path: current.gathered[{{ afi }}].acls[{{ acl }}].aces[{{ ace }}].source
        value:
          subnet_address: "192.168.2.0/24"
  vars:
    afi: "{{ current.gathered|ansible.utils.index_of('eq', 'ipv4', 'afi') }}"
    acl: "{{ current.gathered[afi|int].acls|ansible.utils.index_of('eq', 'test1', 'name') }}"
    ace: "{{ current.gathered[afi|int].acls[acl|int].aces|ansible.utils.index_of('eq', 10, 'sequence') }}"
  register: updated

- name: Apply the changes
  arista.eos.eos_acls:
    config: "{{ updated.current.gathered }}"
    state: overridden
  register: changes

- name: Show the commands issued
  debug:
    msg: "{{ changes['commands'] }}"

# TASK [Show the commands issued] *************************************
# ok: [eos101] => {
#     "msg": [
#         "ip access-list test1",
#         "no 10",
#         "10 permit ip 192.168.2.0/24 host 10.1.1.2"
#     ]
# }


#####################################################################
# Disable ip redirects on any layer3 interface
# find the layer 3 interfaces
# use each name to find their index in l3 interface
# build an 'update' list and apply the updates
#####################################################################

- name: Get the current interface and L3 interface configuration
  cisco.nxos.nxos_facts:
    gather_subset: min
    gather_network_resources:
      - interfaces
      - l3_interfaces

- name: Build the list of updates to make
  ansible.builtin.set_fact:
    updates: "{{ updates + [entry] }}"
  vars:
    updates: []
    entry:
      path: "ansible_network_resources.l3_interfaces[{{ item }}].redirects"
      value: false
    w_mode: "{{ ansible_network_resources.interfaces|selectattr('mode', 'defined') }}"
    m_l3: "{{ w_mode|selectattr('mode', 'eq', 'layer3') }}"
    names: "{{ m_l3|map(attribute='name')|list }}"
    l3_indicies: "{{ ansible_network_resources.l3_interfaces|ansible.utils.index_of('in', names, 'name', wantlist=True) }}"
  loop: "{{ l3_indicies }}"

# TASK [Build the list of updates to make] ****************************
# ok: [nxos101] => (item=99) => changed=false
#   ansible_facts:
#     updates:
#     - path: ansible_network_resources.l3_interfaces[99].redirects
#       value: false
#   ansible_loop_var: item
#   item: 99

- name: Update the l3 interfaces
  ansible.utils.update_fact:
    updates: "{{ updates }}"
  register: updated

# TASK [Update the l3 interfaces] *************************************
# changed: [nxos101] => changed=true
#   ansible_network_resources:
#     l3_interfaces:
#     <...>
#     - ipv4:
#       - address: 10.1.1.1/24
#       name: Ethernet1/100
#       redirects: false

- name: Apply the configuration changes
  cisco.nxos.l3_interfaces:
    config: "{{ updated.ansible_network_resources.l3_interfaces }}"
    state: overridden
  register: changes

# TASK [Apply the configuration changes] ******************************
# changed: [nxos101] => changed=true
#   commands:
#   - interface Ethernet1/100
#   - no ip redirects
"""
