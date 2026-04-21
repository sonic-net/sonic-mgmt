#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2022 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for cp_mgmt_threat_layers
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
module: cp_mgmt_threat_layers
short_description: Manages THREAT LAYERS resource module
description:
  - This resource module allows for addition, deletion, or modification of CP Threat Layers.
  - This resource module also takes care of gathering Threat Layers config facts
  - Available from R80 management version.
version_added: "5.0.0"
author: Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>-
options:
  config:
    description: A dictionary of THREAT LAYERS options
    type: dict
    suboptions:
      name:
        description: Object name. Must be unique in the domain.
        type: str
      add_default_rule:
        description: Indicates whether to include a default rule in the new layer.
        type: bool
      tags:
        description: Collection of tag identifiers.
        type: list
        elements: str
      color:
        description: Color of the object. Should be one of existing colors.
        type: str
        choices:
        - aquamarine
        - black
        - blue
        - crete blue
        - burlywood
        - cyan
        - dark green
        - khaki
        - orchid
        - dark orange
        - dark sea green
        - pink
        - turquoise
        - dark blue
        - firebrick
        - brown
        - forest green
        - gold
        - dark gold
        - gray
        - dark gray
        - light green
        - lemon chiffon
        - coral
        - sea green
        - sky blue
        - magenta
        - purple
        - slate blue
        - violet red
        - navy blue
        - olive
        - orange
        - red
        - sienna
        - yellow
      comments:
        description: Comments string.
        type: str
      details_level:
        description: The level of detail for some of the fields in the response can
          vary from showing only the UID value of the object to a fully detailed representation
          of the object.
        type: str
        choices:
        - uid
        - standard
        - full
      ignore_warnings:
        description: Apply changes ignoring warnings.
        type: bool
      ignore_errors:
        description: Apply changes ignoring errors. You won't be able to publish such
          a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
        type: bool
      limit:
        description:
          - The maximal number of returned results.
          - NOTE, this parameter is a valid parameter only for the GATHERED state, for config states
            like, MERGED, REPLACED, and DELETED state it won't be applicable.
        type: int
      offset:
        description:
          - Number of the results to initially skip.
          - NOTE, this parameter is a valid parameter only for the GATHERED state, for config states
            like, MERGED, REPLACED, and DELETED state it won't be applicable.
        type: int
      order:
        description:
          - Sorts results by the given field. By default the results are sorted in the ascending order by name.
            This parameter is relevant only for getting few objects.
          - NOTE, this parameter is a valid parameter only for the GATHERED state, for config states
            like, MERGED, REPLACED, and DELETED state it won't be applicable.
        type: list
        elements: dict
        suboptions:
          ASC:
            description:
              - Sorts results by the given field in ascending order.
            type: str
          DESC:
            description:
              - Sorts results by the given field in descending order.
            type: str
      round_trip:
        description:
          - If set to True, the round trip will filter out the module parameters from the response param,
            which will enable the user to fire the config request using the structured gathered data.
          - NOTE, this parameter makes relevance only with the GATHERED state, as for config states like,
            MERGED, REPLACED, and DELETED state it won't make any config updates,
            as it's not a module config parameter.
      auto_publish_session:
        description:
          - Publish the current session if changes have been performed
            after task completes.
        type: bool
      version:
        description:
          - Version of checkpoint. If not given one, the latest version taken.
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
    - replaced
    - gathered
    - deleted
"""

EXAMPLES = """

# Using MERGED state
# -------------------

- name: To Add Merge Threat-Layers config
  cp_mgmt_threat_layers:
    state: merged
    config:
      name: New Layer 1
      add_default_rule: true
      tags:
        - test_threat_layer
      color: turquoise
      comments: test description
      ignore_warnings: false
      ignore_errors: false
      round_trip: true

# RUN output:
# -----------

# mgmt_threat_layers:
#   after:
#     color: turquoise
#     comments: test description
#     icon: ApplicationFirewall/rulebase
#     ips-layer: false
#     name: New Layer 1
#     tags:
#     - test_threat_layer
#   before: {}

# Using REPLACED state
# --------------------

- name: Replace Threat-layer config
  cp_mgmt_threat_layers:
    state: replaced
    config:
      name: New Layer 1
      add_default_rule: true
      tags:
        - test_threat_layer_replaced
      color: cyan
      comments: REPLACED description
      ignore_warnings: false
      ignore_errors: false
      round_trip: true

# RUN output:
# -----------

# mgmt_threat_layers:
#   after:
#     color: cyan
#     comments: REPLACED description
#     icon: ApplicationFirewall/rulebase
#     ips-layer: false
#     name: New Layer 1
#     tags:
#     - test_threat_layer_replaced
#   before:
#     color: turquoise
#     comments: test description
#     icon: ApplicationFirewall/rulebase
#     ips-layer: false
#     name: New Layer 1
#     tags:
#     - test_threat_layer

# Using GATHERED state
# --------------------

# 1. With Round Trip set to True

- name: To Gather threat-layer by Name
  cp_mgmt_threat_layers:
    config:
      name: New Layer 1
      round_trip: true
    state: gathered

# RUN output:
# -----------

# gathered:
#   color: turquoise
#   comments: test description
#   domain: SMC User
#   icon: ApplicationFirewall/rulebase
#   ips-layer: false
#   name: New Layer 1
#   read-only: false
#   tags:
#   - test_threat_layer
#   uid: 4dc060e2-0ed6-48c5-9b0f-3d2fbeb552ba

# 2. With Round Trip set to False which is the default behaviour

- name: To Gather threat-layer by Name
  cp_mgmt_threat_layers:
    config:
      name: New Layer 1
    state: gathered

# RUN output:
# -----------

# gathered:
#   color: turquoise
#   comments: test description
#   domain:
#     domain-type: domain
#     name: SMC User
#     uid: 41e821a0-3720-11e3-aa6e-0800200c9fde
#   icon: ApplicationFirewall/rulebase
#   ips-layer: false
#   meta-info:
#     creation-time:
#       iso-8601: 2022-11-21T07:30+0000
#       posix: 1669015820472
#     creator: admin
#     last-modifier: admin
#     last-modify-time:
#       iso-8601: 2022-11-21T07:30+0000
#       posix: 1669015821024
#     lock: unlocked
#     validation-state: ok
#   name: New Layer 1
#   read-only: false
#   tags:
#   - domain:
#       domain-type: domain
#       name: SMC User
#       uid: 41e821a0-3720-11e3-aa6e-0800200c9fde
#     name: test_threat_layer
#     type: tag
#     uid: 59f23149-ed5e-439f-9012-0cdf222a1c97
#   type: threat-layer
#   uid: ca196a80-fdc4-4e7b-8b25-e3eed125a25f

# 3. Gather ALL threat-layer config with DESC order filter

- name: To Gather ALL threat-layer and order by Name
  cp_mgmt_threat_layers:
    config:
      order:
        - DESC: name
    state: gathered

# RUN output:
# -----------

# gathered:
#   - color: black
#     comments: ''
#     domain:
#       domain-type: domain
#       name: SMC User
#       uid: 41e821a0-3720-11e3-aa6e-0800200c9fde
#     icon: ApplicationFirewall/sharedrulebase
#     ips-layer: true
#     meta-info:
#       creation-time:
#         iso-8601: 2020-01-20T09:43+0000
#         posix: 1579513387322
#       creator: System
#       last-modifier: System
#       last-modify-time:
#         iso-8601: 2020-01-20T09:43+0000
#         posix: 1579513387377
#       lock: unlocked
#       validation-state: ok
#     name: IPS
#     read-only: false
#     tags: []
#     type: threat-layer
#     uid: 90678011-1bcb-4296-8154-fa58c23ecf3b
#   - color: black
#     comments: ''
#     domain:
#       domain-type: domain
#       name: SMC User
#       uid: 41e821a0-3720-11e3-aa6e-0800200c9fde
#     icon: ApplicationFirewall/rulebase
#     ips-layer: false
#     meta-info:
#       creation-time:
#         iso-8601: 2020-01-20T09:43+0000
#         posix: 1579513386848
#       creator: System
#       last-modifier: System
#       last-modify-time:
#         iso-8601: 2020-01-20T09:43+0000
#         posix: 1579513387396
#       lock: unlocked
#       validation-state: ok
#     name: Standard Threat Prevention
#     read-only: false
#     tags: []
#     type: threat-layer
#     uid: 0dbe7c44-6d3f-4f28-8f2b-0e6790e57f8a

# Using DELETED state
# -------------------

- name: Delete Threat-layer config by Name and Layer
  cp_mgmt_threat_layers:
    config:
      layer: IPS
      name: First threat layer
      round_trip: true
    state: deleted

# RUN output:
# -----------

# mgmt_threat_layers:
#   after: {}
#   before:
#     action: Optimized
#     comments: This is the THREAT RULE
#     destination:
#     - Any
#     destination_negate: false
#     enabled: true
#     install_on:
#     - Policy Targets
#     layer: 90678011-1bcb-4296-8154-fa58c23ecf3b
#     name: First threat layer
#     protected_scope:
#     - All_Internet
#     protected_scope_negate: false
#     service:
#     - Any
#     service_negate: false
#     source:
#     - Any
#     source_negate: false
#     track: None
#     track_settings:
#       packet_capture: true
"""

RETURN = """
before:
  description: The configuration prior to the module execution.
  returned: when state is I(merged), I(replaced), I(deleted)
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
after:
  description: The resulting configuration after module execution.
  returned: when changed
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
gathered:
  description: Facts about the network resource gathered from the remote device as structured data.
  returned: when state is I(gathered)
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
"""
