# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
---
module: fact_diff
short_description: Find the difference between currently set facts
version_added: "1.0.0"
description:
    - Compare two facts or variables and get a diff.
options:
  before:
    description:
      - The first fact to be used in the comparison.
    type: raw
    required: True
  after:
    description:
      - The second fact to be used in the comparison.
    type: raw
    required: True
  plugin:
    description:
      - Configure and specify the diff plugin to use
    type: dict
    default: {}
    suboptions:
      name:
        description:
        - The diff plugin to use, in fully qualified collection name format.
        default: ansible.utils.native
        type: str
      vars:
        description:
        - Parameters passed to the diff plugin.
        type: dict
        default: {}
        suboptions:
          skip_lines:
            description:
              - Skip lines matching these regular expressions.
              - Matches will be removed prior to the diff.
              - If the provided I(before) and I(after) are a string, they will be split.
              - Each entry in each list will be cast to a string for the comparison
            type: list
            elements: str

notes:

author:
- Bradley Thornton (@cidrblock)
"""

EXAMPLES = r"""
- ansible.builtin.set_fact:
    before:
      a:
        b:
          c:
            d:
              - 0
              - 1
    after:
      a:
        b:
          c:
            d:
              - 2
              - 3

- name: Show the difference in json format
  ansible.utils.fact_diff:
    before: "{{ before }}"
    after: "{{ after }}"

# TASK [ansible.utils.fact_diff] **************************************
# --- before
# +++ after
# @@ -3,8 +3,8 @@
#          "b": {
#              "c": {
#                  "d": [
# -                    0,
# -                    1
# +                    2,
# +                    3
#                  ]
#              }
#          }
#
# changed: [localhost]

- name: Show the difference in path format
  ansible.utils.fact_diff:
    before: "{{ before | ansible.utils.to_paths }}"
    after: "{{ after | ansible.utils.to_paths }}"

# TASK [ansible.utils.fact_diff] **************************************
# --- before
# +++ after
# @@ -1,4 +1,4 @@
#  {
# -    "a.b.c.d[0]": 0,
# -    "a.b.c.d[1]": 1
# +    "a.b.c.d[0]": 2,
# +    "a.b.c.d[1]": 3
#  }
#
# changed: [localhost]

- name: Show the difference in yaml format
  ansible.utils.fact_diff:
    before: "{{ before | to_nice_yaml }}"
    after: "{{ after | to_nice_yaml }}"

# TASK [ansible.utils.fact_diff] **************************************
# --- before
# +++ after
# @@ -2,5 +2,5 @@
#      b:
#          c:
#              d:
# -            - 0
# -            - 1
# +            - 2
# +            - 3

# changed: [localhost]


#### Show the difference between complex object using restconf
#  ansible_connection: ansible.netcommon.httpapi
#  ansible_httpapi_use_ssl: True
#  ansible_httpapi_validate_certs: False
#  ansible_network_os: ansible.netcommon.restconf

- name: Get the current interface config prior to changes
  ansible.netcommon.restconf_get:
    content: config
    path: /data/Cisco-NX-OS-device:System/intf-items/phys-items
  register: pre

- name: Update the description of eth1/100
  ansible.utils.update_fact:
    updates:
      - path: "pre['response']['phys-items']['PhysIf-list'][{{ index }}]['descr']"
        value: "Configured by ansible {{ 100 | random }}"
  vars:
    index: "{{ pre['response']['phys-items']['PhysIf-list'] | ansible.utils.index_of('eq', 'eth1/100', 'id') }}"
  register: updated

- name: Apply the configuration
  ansible.netcommon.restconf_config:
    path: 'data/Cisco-NX-OS-device:System/intf-items/'
    content: "{{ updated.pre.response}}"
    method: patch

- name: Get the current interface config after changes
  ansible.netcommon.restconf_get:
    content: config
    path: /data/Cisco-NX-OS-device:System/intf-items/phys-items
  register: post

- name: Show the difference
  ansible.utils.fact_diff:
    before: "{{ pre.response | ansible.utils.to_paths }}"
    after: "{{ post.response | ansible.utils.to_paths }}"

# TASK [ansible.utils.fact_diff] *********************************************
# --- before
# +++ after
# @@ -3604,7 +3604,7 @@
#      "phys-items['PhysIf-list'][37].bw": "0",
#      "phys-items['PhysIf-list'][37].controllerId": "",
#      "phys-items['PhysIf-list'][37].delay": "1",
# -    "phys-items['PhysIf-list'][37].descr": "Configured by ansible 95",
# +    "phys-items['PhysIf-list'][37].descr": "Configured by ansible 20",
#      "phys-items['PhysIf-list'][37].dot1qEtherType": "0x8100",
#      "phys-items['PhysIf-list'][37].duplex": "auto",
#      "phys-items['PhysIf-list'][37].id": "eth1/100",

# changed: [nxos101]
"""


RETURN = """

diff_text:
  description: The diff in text format.
  returned: always
  type: str
diff_lines:
  description: The I(diff_text) split into lines.
  returned: always
  type: list
  elements: str

"""
