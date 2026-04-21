# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


"""
The index_of filter plugin
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    name: index_of
    author: Bradley Thornton (@cidrblock)
    version_added: "1.0.0"
    short_description: Find the indices of items in a list matching some criteria
    description:
        - This plugin returns the indices of items matching some criteria in a list.
        - When working with a list of dictionaries, the key to evaluate can be specified.
        - B(index_of) is also available as a B(lookup plugin) for convenience.
        - Using the parameters below- C(data|ansible.utils.index_of(test, value, key, fail_on_missing, wantlist))
    options:
      data:
        description:
        - A list of items to enumerate and test against.
        - This option represents the value that is passed to the filter plugin in pipe format.
        - For example C(config_data|ansible.utils.index_of('x')), in this case C(config_data) represents this option.
        type: list
        required: True
      test:
        description:
        - The name of the test to run against the list, a valid jinja2 test or ansible test plugin.
        - Jinja2 includes the following tests U(http://jinja.palletsprojects.com/templates/#builtin-tests).
        - An overview of tests included in ansible U(https://docs.ansible.com/ansible/latest/user_guide/playbooks_tests.html)
        type: str
        required: True
      value:
        description:
        - The value used to test each list item against.
        - 'Not required for simple tests (eg: C(true), C(false), C(even), C(odd))'
        - May be a C(string), C(boolean), C(number), C(regular expression) C(dict) and so on, depending on the C(test) used
        type: raw
      key:
        description:
        - When the data provided is a list of dictionaries, run the test against this dictionary key.
        - When using a I(key), the I(data) must only contain dictionaries.
        - See I(fail_on_missing) below to determine the behavior when the I(key) is missing from a dictionary in the I(data).
        type: str
      fail_on_missing:
        description: When provided a list of dictionaries, fail if the key is missing from one or more of the dictionaries.
        type: bool
      wantlist:
        description:
        - When only a single entry in the I(data) is matched, the index of that entry is returned as an integer.
        - If set to C(True), the return value will always be a list, even if only a single entry is matched.
        type: bool

    notes:
"""

EXAMPLES = r"""

#### Simple examples

- name: Define a list
  ansible.builtin.set_fact:
    data:
      - 1
      - 2
      - 3

- name: Find the index of 2
  ansible.builtin.set_fact:
    indices: "{{ data|ansible.utils.index_of('eq', 2) }}"

# TASK [Find the index of 2] *************************************************
# ok: [nxos101] => changed=false
#   ansible_facts:
#     indices: '1'


- name: Find the index of 2, ensure list is returned
  ansible.builtin.set_fact:
    indices: "{{ data|ansible.utils.index_of('eq', 2, wantlist=True) }}"

# TASK [Find the index of 2, ensure list is returned] ************************
# ok: [nxos101] => changed=false
#   ansible_facts:
#     indices:
#     - 1


- name: Find the index of 3 using the long format
  ansible.builtin.set_fact:
    indices: "{{ data|ansible.utils.index_of(test='eq', value=value, wantlist=True) }}"
  vars:
    value: 3

# TASK [Find the index of 3 using the long format] ***************************
# ok: [nxos101] => changed=false
#   ansible_facts:
#     indices:
#     - 2


- name: Find numbers greater than 1, using loop
  debug:
    msg: "{{ data[item] }} is {{ test }} than {{ value }}"
  loop: "{{ data|ansible.utils.index_of(test, value) }}"
  vars:
    test: '>'
    value: 1

# TASK [Find numbers great than 1, using loop] *******************************
# ok: [sw01] => (item=1) =>
#   msg: 2 is > than 1
# ok: [sw01] => (item=2) =>
#   msg: 3 is > than 1


#### Working with lists of dictionaries

- name: Define a list with hostname and type
  ansible.builtin.set_fact:
    data:
      - name: sw01.example.lan
        type: switch
      - name: rtr01.example.lan
        type: router
      - name: fw01.example.corp
        type: firewall
      - name: fw02.example.corp
        type: firewall

- name: Find the index of all firewalls using the type key
  ansible.builtin.set_fact:
    firewalls: "{{ data|ansible.utils.index_of('eq', 'firewall', 'type') }}"

# TASK [Find the index of all firewalls using the type key] ******************
# ok: [nxos101] => changed=false
#   ansible_facts:
#     firewalls:
#     - 2
#     - 3

- name: Find the index of all firewalls, use in a loop
  debug:
    msg: "The type of {{ device_type }} at index {{ item }} has name {{ data[item].name }}."
  loop: "{{ data|ansible.utils.index_of('eq', device_type, 'type') }}"
  vars:
    device_type: firewall

# TASK [Find the index of all firewalls, use in a loop, as a filter] *********
# ok: [nxos101] => (item=2) =>
#   msg: The type of firewall at index 2 has name fw01.example.corp.
# ok: [nxos101] => (item=3) =>
#   msg: The type of firewall at index 3 has name fw02.example.corp.

- name: Find the index of all devices with a .corp name
  debug:
    msg: "The device named {{ data[item].name }} is a {{ data[item].type }}"
  loop: "{{ data|ansible.utils.index_of('regex', expression, 'name') }}"
  vars:
    expression: '\.corp$'

# TASK [Find the index of all devices with a .corp name] *********************
# ok: [nxos101] => (item=2) =>
#   msg: The device named fw01.example.corp is a firewall
# ok: [nxos101] => (item=3) =>
#   msg: The device named fw02.example.corp is a firewall


#### Working with complex structures from resource modules

- name: Retrieve the current L3 interface configuration
  cisco.nxos.nxos_l3_interfaces:
    state: gathered
  register: current_l3

# TASK [Retrieve the current L3 interface configuration] *********************
# ok: [sw01] => changed=false
#   gathered:
#   - name: Ethernet1/1
#   - name: Ethernet1/2
#   <...>
#   - name: Ethernet1/128
#   - ipv4:
#     - address: 192.168.101.14/24
#     name: mgmt0

- name: Find the indices interfaces with a 192.168.101.xx ip address
  ansible.builtin.set_fact:
    found: "{{ found + entry }}"
  with_indexed_items: "{{ current_l3.gathered }}"
  vars:
    found: []
    ip: '192.168.101.'
    address: "{{ item.1.ipv4|d([])|ansible.utils.index_of('search', ip, 'address', wantlist=True) }}"
    entry:
      - interface_idx: "{{ item.0 }}"
        address_idxs: "{{ address }}"
  when: address

# TASK [debug] ***************************************************************
# ok: [sw01] =>
#   found:
#   - address_idxs:
#     - 0
#     interface_idx: '128'

- name: Show all interfaces and their address
  debug:
    msg: "{{ interface.name }} has ip {{ address }}"
  loop: "{{ found|subelements('address_idxs') }}"
  vars:
    interface: "{{ current_l3.gathered[item.0.interface_idx|int] }}"
    address: "{{ interface.ipv4[item.1].address }}"

# TASK [Show all interfaces and their address] *******************************
# ok: [nxos101] => (item=[{'interface_idx': '128', 'address_idxs': [0]}, 0]) =>
#   msg: mgmt0 has ip 192.168.101.14/24


#### Working with deeply nested data

- name: Define interface configuration facts
  ansible.builtin.set_fact:
    data:
      interfaces:
        interface:
          - config:
              description: configured by Ansible - 1
              enabled: true
              loopback-mode: false
              mtu: 1024
              name: loopback0000
              type: eth
            name: loopback0000
            subinterfaces:
              subinterface:
                - config:
                    description: subinterface configured by Ansible - 1
                    enabled: true
                    index: 5
                  index: 5
                - config:
                    description: subinterface configured by Ansible - 2
                    enabled: false
                    index: 2
                  index: 2
          - config:
              description: configured by Ansible - 2
              enabled: false
              loopback-mode: false
              mtu: 2048
              name: loopback1111
              type: virt
            name: loopback1111
            subinterfaces:
              subinterface:
                - config:
                    description: subinterface configured by Ansible - 3
                    enabled: true
                    index: 10
                  index: 10
                - config:
                    description: subinterface configured by Ansible - 4
                    enabled: false
                    index: 3
                  index: 3


- name: Find the description of loopback111, subinterface index 10
  debug:
    msg: |-
      {{ data.interfaces.interface[int_idx|int]
          .subinterfaces.subinterface[subint_idx|int]
            .config.description }}
  vars:
    # the values to search for
    int_name: loopback1111
    sub_index: 10
    # retrieve the index in each nested list
    int_idx: |
      {{ data.interfaces.interface|
            ansible.utils.index_of('eq', int_name, 'name') }}
    subint_idx: |
      {{ data.interfaces.interface[int_idx|int]
            .subinterfaces.subinterface|
                ansible.utils.index_of('eq', sub_index, 'index') }}

# TASK [Find the description of loopback111, subinterface index 10] ************
# ok: [sw01] =>
#   msg: subinterface configured by Ansible - 3
"""

from ansible.errors import AnsibleFilterError

from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)
from ansible_collections.ansible.utils.plugins.plugin_utils.index_of import index_of


try:
    from jinja2.filters import pass_environment
except ImportError:
    from jinja2.filters import environmentfilter as pass_environment


@pass_environment
def _index_of(*args, **kwargs):
    """Find the indicies of items in a list matching some criteria."""

    keys = [
        "environment",
        "data",
        "test",
        "value",
        "key",
        "fail_on_missing",
        "wantlist",
    ]
    data = dict(zip(keys, args))
    data.update(kwargs)
    environment = data.pop("environment")
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="index_of")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    updated_data["tests"] = environment.tests
    return index_of(**updated_data)


class FilterModule(object):
    """index_of"""

    def filters(self):
        """a mapping of filter names to functions"""
        return {"index_of": _index_of}
