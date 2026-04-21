#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_bgp_ext_communities
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_bgp_ext_communities
version_added: 1.0.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
short_description: Manage BGP extended community-list and its parameters
description:
  - This module provides configuration management of BGP extcommunity-list for devices running
    Enterprise SONiC Distribution by Dell Technologies.
author: Kumaraguru Narayanan (@nkumaraguru)
options:
  config:
    description: A list of 'bgp_extcommunity_list' configurations.
    type: list
    elements: dict
    suboptions:
      name:
        required: True
        type: str
        description:
        - Name of the BGP ext communitylist.
      type:
        type: str
        description:
        - Whether it is a standard or expanded ext community_list entry.
        required: False
        choices:
        - standard
        - expanded
        default: standard
      permit:
        required: False
        type: bool
        description:
        - Permits or denies this community.
        - Default value while adding a new ext-community-list is False.
      members:
        required: False
        type: dict
        suboptions:
          regex:
            type: list
            elements: str
            required: False
            description:
              - Members of this BGP ext community list. Regular expression string can be given here. Applicable for expanded ext BGP community type.
          route_target:
            type: list
            elements: str
            required: False
            description:
              - Members of this BGP ext community list. The format of route_target is in either 0..65535:0..65535 or A.B.C.D:[1..65535] format.
          route_origin:
            type: list
            elements: str
            required: False
            description:
              - Members of this BGP ext community list. The format of route_origin is in either 0..65535:0..65535 or A.B.C.D:[1..65535] format.
        description:
        - Members of this BGP ext community list.
      match:
        required: False
        type: str
        description:
        - Matches any/all of the the members.
        choices:
        - all
        - any
        default: any
  state:
    description:
    - The state of the configuration after module completion.
    type: str
    choices:
    - merged
    - deleted
    - replaced
    - overridden
    default: merged
"""

EXAMPLES = """
# Using "deleted" state

# Before state:
# -------------
#
# show bgp ext-community-list
# Standard extended community list test:  match: ANY
#     permit rt:101:101
#     permit rt:201:201

- name: Deletes a BGP ext community member
  dellemc.enterprise_sonic.sonic_bgp_ext_communities:
    config:
      - name: test
        type: standard
        members:
          route_target:
            - 201:201
    state: deleted

# After state:
# ------------
#
# show bgp ext-community-list
# Standard extended community list test:  match: ANY
#     permit rt:101:101
#


# Using "deleted" state

# Before state:
# -------------
#
# show bgp ext-community-list
# Standard extended community list test:  match: ANY
#     permit rt:101:101
#     permit rt:201:201
# Expanded extended community list test1:   match: ALL
#     deny 101:102

- name: Deletes a single BGP extended community
  dellemc.enterprise_sonic.sonic_bgp_ext_communities:
    config:
      - name: test1
        members:
    state: deleted

# After state:
# ------------
#
# show bgp ext-community-list
# Standard extended community list test:  match: ANY
#     permit rt:101:101
#     permit rt:201:201
#


# Using "deleted" state

# Before state:
# -------------
#
# show bgp ext-community-list
# Standard extended community list test:  match: ANY
#     permit rt:101:101
#     permit rt:201:201
# Expanded extended community list test1:   match: ALL
#     deny 101:102

- name: Deletes all BGP extended communities
  dellemc.enterprise_sonic.sonic_bgp_ext_communities:
    config:
    state: deleted

# After state:
# ------------
#
# show bgp ext-community-list
#


# Using "deleted" state

# Before state:
# -------------
#
# show bgp ext-community-list
# Standard extended community list test:  match: ANY
#     permit rt:101:101
#     permit rt:201:201
# Expanded extended community list test1:   match: ALL
#     deny 101:102

- name: Deletes all members in a single BGP extended community
  dellemc.enterprise_sonic.sonic_bgp_ext_communities:
    config:
      - name: test1
        members:
          regex:
    state: deleted

# After state:
# ------------
#
# show bgp ext-community-list
# Standard extended community list test:  match: ANY
#     permit rt:101:101
#     permit rt:201:201
#


# Using "merged" state

# Before state:
# -------------
#
# show bgp ext-community-list
# Standard extended community list test:  match: ANY
#     permit rt:101:101
#     permit rt:201:201
# Expanded extended community list test1:   match: ALL
#     deny 101:102

- name: Adds new community list
  dellemc.enterprise_sonic.sonic_bgp_ext_communities:
    config:
      - name: test3
        type: standard
        match: any
        permit: true
        members:
          route_origin:
            - "301:301"
            - "401:401"
    state: merged

# After state:
# ------------
#
# show bgp ext-community-list
# Standard extended community list test:  match: ANY
#     permit rt:101:101
#     permit rt:201:201
# Expanded extended community list test1:   match: ALL
#     deny 101:102
# Standard extended community list test3:  match: ANY
#     permit soo:301:301
#     permit soo:401:401


# Using "replaced" state

# Before state:
# -------------
#
# show bgp ext-community-list
# Standard extended community list test:  match: ANY
#     permit rt:101:101
#     permit rt:201:201
# Expanded extended community list test1:   match: ALL
#     deny 101:102

- name: Replacing a single BGP extended community
  dellemc.enterprise_sonic.sonic_bgp_ext_communities:
    config:
      - name: test
        type: expanded
        permit: true
        match: all
        members:
          regex:
            - 301:302
    state: replaced

# After state:
# ------------
#
# show bgp ext-community-list
# Expanded extended community list test:  match: ALL
#     permit 301:302
# Expanded extended community list test1:   match: ALL
#     deny 101:102
#


# Using "overridden" state

# Before state:
# -------------
#
# show bgp ext-community-list
# Standard extended community list test:  match: ANY
#     permit rt:101:101
#     permit rt:201:201
# Expanded extended community list test1:   match: ALL
#     deny 101:102


- name: Override the entire list of BGP extended community
  dellemc.enterprise_sonic.sonic_bgp_ext_communities:
    config:
      - name: test3
        type: expanded
        permit: true
        match: all
        members:
          regex:
            - 301:302
    state: overridden

# After state:
# ------------
#
# show bgp ext-community-list
# Expanded extended community list test3:  match: ALL
#     permit 301:302
#
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: list
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
after:
  description: The resulting configuration module invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.bgp_ext_communities.bgp_ext_communities import (
    Bgp_ext_communitiesArgs,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.bgp_ext_communities.bgp_ext_communities import Bgp_ext_communities


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Bgp_ext_communitiesArgs.argument_spec,
                           supports_check_mode=True)

    result = Bgp_ext_communities(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
