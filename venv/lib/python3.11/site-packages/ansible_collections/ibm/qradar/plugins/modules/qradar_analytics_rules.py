#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: qradar_analytics_rules
short_description: Qradar Analytics Rules Management resource module
description:
  - This module allows for modification, deletion, and checking of Analytics Rules in QRadar
version_added: "2.1.0"
options:
  config:
    description: A dictionary of Qradar Analytics Rules options
    type: dict
    suboptions:
      id:
        description: The sequence ID of the rule.
        type: int
      name:
        description: The name of the rule.
        type: str
      enabled:
        description: Check if the rule is enabled
        type: bool
      owner:
        description: Manage ownership of a QRadar Rule
        type: str
      fields:
        description:
          - List of params filtered from the Rule config
          - NOTE, this param is valid only via state GATHERED.
        type: list
        elements: str
        choices:
          - average_capacity
          - base_capacity
          - base_host_id
          - capacity_timestamp
          - creation_date
          - enabled
          - id
          - identifier
          - linked_rule_identifier
          - modification_date
          - name
          - origin
          - owner
          - type
      range:
        description:
          - Parameter to restrict the number of elements that
            are returned in the list to a specified range.
          - NOTE, this param is valid only via state GATHERED.
        type: str
  state:
    description:
      - The state the configuration should be left in
      - The state I(gathered) will get the module API configuration from the device
        and transform it into structured data in the format as per the module argspec
        and the value is returned in the I(gathered) key within the result.
    type: str
    choices:
      - merged
      - gathered
      - deleted

author: Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>
"""

EXAMPLES = """

# Using MERGED state
# -------------------

- name: DISABLE Rule 'Ansible Example DDoS Rule'
  ibm.qradar.qradar_analytics_rules:
    config:
      name: 'Ansible Example DDOS Rule'
      enabled: false
    state: merged

# RUN output:
# -----------

#   qradar_analytics_rules:
#     after:
#       average_capacity: null
#       base_capacity: null
#       base_host_id: null
#       capacity_timestamp: null
#       creation_date: 1658929682568
#       enabled: false
#       id: 100443
#       identifier: ae5a1268-02a0-4976-84c5-dbcbcf854b9c
#       linked_rule_identifier: null
#       modification_date: 1658929682567
#       name: Ansible Example DDOS Rule
#       origin: USER
#       owner: admin
#       type: EVENT
#     before:
#       average_capacity: null
#       base_capacity: null
#       base_host_id: null
#       capacity_timestamp: null
#       creation_date: 1658929682568
#       enabled: true
#       id: 100443
#       identifier: ae5a1268-02a0-4976-84c5-dbcbcf854b9c
#       linked_rule_identifier: null
#       modification_date: 1658929682567
#       name: Ansible Example DDOS Rule
#       origin: USER
#       owner: admin
#       type: EVENT


# Using GATHERED state
# --------------------

- name: Get information about the Rule named "Ansible Example DDOS Rule"
  ibm.qradar.qradar_analytics_rules:
    config:
      name: "Ansible Example DDOS Rule"
    state: gathered

# RUN output:
# -----------

#   gathered:
#     average_capacity: null
#     base_capacity: null
#     base_host_id: null
#     capacity_timestamp: null
#     creation_date: 1658918848694
#     enabled: true
#     id: 100443
#     identifier: d6d37942-ba28-438f-b909-120df643a992
#     linked_rule_identifier: null
#     modification_date: 1658918848692
#     name: Ansible Example DDOS Rule
#     origin: USER
#     owner: admin
#     type: EVENT

- name: Get information about the Rule with ID 100443
  ibm.qradar.qradar_analytics_rules:
    config:
      id: 100443
    state: gathered

# RUN output:
# -----------

#   gathered:
#     average_capacity: null
#     base_capacity: null
#     base_host_id: null
#     capacity_timestamp: null
#     creation_date: 1658918848694
#     enabled: true
#     id: 100443
#     identifier: d6d37942-ba28-438f-b909-120df643a992
#     linked_rule_identifier: null
#     modification_date: 1658918848692
#     name: Ansible Example DDOS Rule
#     origin: USER
#     owner: admin
#     type: EVENT

- name: TO Get information about the Rule ID with a range
  ibm.qradar.qradar_analytics_rules:
  config:
    range: 100300-100500
    fields:
      - name
      - origin
      - owner
  state: gathered

# RUN output:
# -----------

# gathered:
#   - name: Devices with High Event Rates
#     origin: SYSTEM
#     owner: admin
#   - name: Excessive Database Connections
#     origin: SYSTEM
#     owner: admin
#   - name: 'Anomaly: Excessive Firewall Accepts Across Multiple Hosts'
#     origin: SYSTEM
#     owner: admin
#   - name: Excessive Firewall Denies from Single Source
#     origin: SYSTEM
#     owner: admin
#   - name: 'AssetExclusion: Exclude DNS Name By IP'
#     origin: SYSTEM
#     owner: admin
#   - name: 'AssetExclusion: Exclude DNS Name By MAC Address'
#     origin: SYSTEM
#     owner: admin

- name: Delete custom Rule by NAME
  ibm.qradar.qradar_analytics_rules:
    config:
      name: 'Ansible Example DDOS Rule'
    state: deleted

# RUN output:
# -----------

#   qradar_analytics_rules:
#     after: {}
#     before:
#       average_capacity: null
#       base_capacity: null
#       base_host_id: null
#       capacity_timestamp: null
#       creation_date: 1658929431239
#       enabled: true
#       id: 100444
#       identifier: 3c2cbd9d-d141-49fc-b5d5-29009a9b5308
#       linked_rule_identifier: null
#       modification_date: 1658929431238
#       name: Ansible Example DDOS Rule
#       origin: USER
#       owner: admin
#       type: EVENT

# Using DELETED state
# -------------------

- name: Delete custom Rule by ID
  ibm.qradar.qradar_analytics_rules:
    config:
      id: 100443
    state: deleted

# RUN output:
# -----------

#   qradar_analytics_rules:
#     after: {}
#     before:
#       average_capacity: null
#       base_capacity: null
#       base_host_id: null
#       capacity_timestamp: null
#       creation_date: 1658929431239
#       enabled: true
#       id: 100443
#       identifier: 3c2cbd9d-d141-49fc-b5d5-29009a9b5308
#       linked_rule_identifier: null
#       modification_date: 1658929431238
#       name: Ansible Example DDOS Rule
#       origin: USER
#       owner: admin
#       type: EVENT
"""

RETURN = """
before:
  description: The configuration as structured data prior to module invocation.
  returned: always
  type: dict
  sample: The configuration returned will always be in the same format of the parameters above.
after:
  description: The configuration as structured data after module completion.
  returned: when changed
  type: dict
  sample: The configuration returned will always be in the same format of the parameters above.
"""
