#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2022 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for cp_mgmt_add_access_layers
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
module: cp_mgmt_access_layers
short_description: Manages ACCESS LAYERS resource module
description:
  - This resource module allows for addition, deletion, or modification of CP Access Layers.
  - This resource module also takes care of gathering Access layer config facts
  - Available from R80 management version.
version_added: "5.0.0"
author: Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>
options:
  config:
    description: A dictionary of ACCESS LAYERS options
    type: dict
    suboptions:
      name:
        description: Object name. Must be unique in the domain.
        type: str
      add_default_rule:
        description: Indicates whether to include a cleanup rule in the new layer.
        type: bool
      applications_and_url_filtering:
        description: Whether to enable Applications & URL Filtering blade on the layer.
        type: bool
      content_awareness:
        description: Whether to enable Content Awareness blade on the layer.
        type: bool
      detect_using_x_forward_for:
        description: Whether to use X-Forward-For HTTP header, which is added by the  proxy
          server to keep track of the original source IP.
        type: bool
      firewall:
        description: Whether to enable Firewall blade on the layer.
        type: bool
      implicit_cleanup_action:
        description: The default "catch-all" action for traffic that does not match
          any explicit or implied rules in the layer.
        type: str
        choices:
        - drop
        - accept
      mobile_access:
        description: Whether to enable Mobile Access blade on the layer.
        type: bool
      shared:
        description: Whether this layer is shared.
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
        type: bool
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

- name: Merge Access-layer config
  cp_mgmt_access_layers:
    state: merged
    config:
      name: New Layer 1
      add_default_rule: true
      applications_and_url_filtering: true
      content_awareness: true
      detect_using_x_forward_for: false
      firewall: true
      implicit_cleanup_action: drop
      mobile_access: true
      shared: false
      tags:
        - test_layer
      color: aquamarine
      comments: test description
      details_level: full
      ignore_warnings: false
      ignore_errors: false
      round_trip: true

# RUN output:
# -----------

# mgmt_access_layers:
#   after:
#     applications_and_url_filtering: true
#     color: aquamarine
#     comments: test description
#     content_awareness: true
#     detect_using_x_forward_for: false
#     domain: SMC User
#     firewall: true
#     icon: ApplicationFirewall/rulebase
#     implicit_cleanup_action: drop
#     mobile_access: true
#     name: New Layer 1
#     shared: false
#     tags:
#     - test_layer
#     uid: eb74d7fe-81a6-4e6c-aedb-d2d6599f965e
#   before: {}

# Using REPLACED state
# --------------------

- name: Replace Access-layer config
  cp_mgmt_access_layers:
    state: replaced
    config:
      name: New Layer 1
      add_default_rule: true
      applications_and_url_filtering: true
      content_awareness: false
      detect_using_x_forward_for: false
      firewall: true
      implicit_cleanup_action: drop
      mobile_access: true
      shared: true
      tags:
        - test_layer_replaced
      color: cyan
      comments: test REPLACE description
      details_level: full
      ignore_warnings: false
      ignore_errors: false
      round_trip: true

# RUN output:
# -----------

# mgmt_access_layers:
#   after:
#     applications_and_url_filtering: true
#     color: cyan
#     comments: test REPLACE description
#     content_awareness: false
#     detect_using_x_forward_for: false
#     domain: SMC User
#     firewall: true
#     icon: ApplicationFirewall/sharedrulebase
#     implicit_cleanup_action: drop
#     mobile_access: true
#     name: New Layer 1
#     shared: true
#     tags:
#     - test_layer_replaced
#     uid: a4e2bbc1-ec94-4b85-9b00-07ad1279ac12
#   before:
#     applications_and_url_filtering: true
#     color: aquamarine
#     comments: test description
#     content_awareness: true
#     detect_using_x_forward_for: false
#     firewall: true
#     icon: ApplicationFirewall/rulebase
#     implicit_cleanup_action: drop
#     mobile_access: true
#     name: New Layer 1
#     shared: false
#     tags:
#     - test_layer

# Using GATHERED state
# --------------------

# 1. With Round Trip set to True

- name: Gather Access-layers config by Name
  cp_mgmt_access_layers:
    state: gathered
    config:
      name: New Layer 1
      round_trip: true

# RUN output:
# -----------

# gathered:
#   applications_and_url_filtering: true
#   color: aquamarine
#   comments: test description
#   content_awareness: true
#   detect_using_x_forward_for: false
#   domain: SMC User
#   firewall: true
#   icon: ApplicationFirewall/rulebase
#   implicit_cleanup_action: drop
#   mobile_access: true
#   name: New Layer 1
#   shared: false
#   tags:
#   - test_layer
#   uid: eb74d7fe-81a6-4e6c-aedb-d2d6599f965e

# 2. With Round Trip set to False which is the default behaviour

- name: Gather Access-layers config by Name
  cp_mgmt_access_layers:
    state: gathered
    config:
      name: New Layer 1

# RUN output:
# -----------

# gathered:
#   applications_and_url_filtering: true
#   color: turquoise
#   comments: test description
#   content_awareness: true
#   detect_using_x_forward_for: false
#   domain:
#     domain-type: domain
#     name: SMC User
#     uid: 41e821a0-3720-11e3-aa6e-0800200c9fde
#   firewall: true
#   icon: ApplicationFirewall/rulebase
#   implicit_cleanup_action: drop
#   meta-info:
#     creation-time:
#       iso-8601: 2022-11-21T07:34+0000
#       posix: 1669016073937
#     creator: admin
#     last-modifier: admin
#     last-modify-time:
#       iso-8601: 2022-11-21T07:34+0000
#       posix: 1669016074765
#     lock: unlocked
#     validation-state: ok
#   mobile_access: true
#   name: New Layer 1
#   read-only: false
#   shared: false
#   tags:
#   - domain:
#       domain-type: domain
#       name: SMC User
#       uid: 41e821a0-3720-11e3-aa6e-0800200c9fde
#     name: test_layer
#     type: tag
#     uid: 22cc8b0d-984f-47de-b1f6-276b3377eb0c
#   type: access-layer
#   uid: a54e47d3-22fc-4aff-90d9-f644aa4a1522

# 3. Gather ALL threat-layer config with DESC order filter

- name: To Gather ALL access-layer and order by Name
  cp_mgmt_access_layers:
    config:
      order:
        - DESC: name
    state: gathered

# RUN output:
# -----------

# gathered:
#   - domain:
#       domain-type: domain
#       name: SMC User
#       uid: 41e821a0-3720-11e3-aa6e-0800200c9fde
#     name: New Layer 1
#     type: access-layer
#     uid: a54e47d3-22fc-4aff-90d9-f644aa4a1522
#   - domain:
#       domain-type: domain
#       name: SMC User
#       uid: 41e821a0-3720-11e3-aa6e-0800200c9fde
#     name: Network
#     type: access-layer
#     uid: 63b7fe60-76d2-4287-bca5-21af87337b0a

# Using DELETED state
# -------------------

- name: Delete Access-layer config by Name
  cp_mgmt_access_layers:
    state: deleted
    config:
      name: New Layer 1

# RUN output:
# -----------

# mgmt_access_layers:
#   after: {}
#   before:
#     applications_and_url_filtering: true
#     color: cyan
#     comments: test REPLACE description
#     content_awareness: false
#     detect_using_x_forward_for: false
#     domain: SMC User
#     firewall: true
#     icon: ApplicationFirewall/sharedrulebase
#     implicit_cleanup_action: drop
#     mobile_access: true
#     name: New Layer 1
#     shared: true
#     tags:
#     - test_layer_replaced
#     uid: a4e2bbc1-ec94-4b85-9b00-07ad1279ac12
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
