#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_bgp_communities
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_bgp_communities
version_added: 1.0.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
short_description: Manage BGP community and its parameters
description:
  - This module provides configuration management of BGP bgp_communities for device
    running Enterprise SONiC Distribution by Dell Technologies.
author: Kumaraguru Narayanan (@nkumaraguru)
options:
  config:
    description: A list of 'bgp_communities' configurations.
    type: list
    elements: dict
    suboptions:
      name:
        required: True
        type: str
        description:
        - Name of the BGP community-list.
      type:
        type: str
        description:
        - Whether it is a standard or expanded community-list entry.
        - If unspecified, operational default value is C(standard).
        required: False
        choices:
        - standard
        - expanded
      permit:
        required: False
        type: bool
        description:
        - Permits or denies this community.
        - If unspecified, operational default value is C(False).
      local_as:
        required: False
        type: bool
        description:
        - Do not send outside local AS (well-known community); applicable for standard BGP community type.
      no_advertise:
        required: False
        type: bool
        description:
        - Do not advertise to any peer (well-known community); applicable for standard BGP community type.
      no_export:
        required: False
        type: bool
        description:
        - Do not export to next AS (well-known community); applicable for standard BGP community type.
      no_peer:
        required: False
        type: bool
        description:
        - Do not export to next AS (well-known community); applicable for standard BGP community type.
      members:
        required: False
        type: dict
        suboptions:
          aann:
            required: False
            type: list
            elements: str
            version_added: 3.0.0
            description:
            - Community number aa:nn format 0..65535:0..65535; applicable for standard BGP community type.
          regex:
            type: list
            elements: str
            required: False
            description:
              - Members of this BGP community list. Regular expression string can be given here. Applicable for expanded BGP community type.
        description:
        - Members of this BGP community list.
      match:
        required: False
        type: str
        description:
        - Matches any/all of the members.
        - If unspecified, operational default value is C(ANY).
        choices:
        - ALL
        - ANY
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
# show bgp community-list
# Standard community list test:  match: ANY
#     permit local-as
#     permit no-peer
# Expanded community list test1:   match: ANY
#     deny 101
#     deny 302

- name: Delete a BGP community-list member
  dellemc.enterprise_sonic.sonic_bgp_communities:
    config:
      - name: test1
        type: expanded
        permit: false
        members:
          regex:
            - 302
    state: deleted

# After state:
# ------------
#
# show bgp community-list
# Standard community list test:  match: ANY
#     permit local-as
#     permit no-peer
# Expanded community list test1:   match: ANY
#     deny 101


# Using "deleted" state

# Before state:
# -------------
#
# show bgp community-list
# Standard community list test:  match: ANY
#     permit local-as
#     permit no-peer
# Expanded community list test1:   match: ANY
#     deny 101
#     deny 302

- name: Delete a single BGP community-list
  dellemc.enterprise_sonic.sonic_bgp_communities:
    config:
      - name: test
        type: standard
    state: deleted

# After state:
# ------------
#
# show bgp community-list
# Expanded community list test1:   match: ANY
#     deny 101
#     deny 302


# Using "deleted" state

# Before state:
# -------------
#
# show bgp community-list
# Standard community list test:  match: ANY
#     permit local-as
#     permit no-peer
# Expanded community list test1:   match: ANY
#     deny 101
#     deny 302

- name: Delete All BGP community-lists
  dellemc.enterprise_sonic.sonic_bgp_communities:
    config:
    state: deleted

# After state:
# ------------
#
# show bgp community-list
#


# Using "deleted" state

# Before state:
# -------------
#
# show bgp community-list
# Standard community list test:  match: ANY
#     permit local-as
#     permit no-peer
# Expanded community list test1:   match: ANY
#     deny 101
#     deny 302

- name: Delete all members in a single BGP community-list
  dellemc.enterprise_sonic.sonic_bgp_communities:
    config:
      - name: test1
        type: expanded
        members:
          regex:
    state: deleted

# After state:
# ------------
#
# show bgp community-list
# Standard community list test:  match: ANY
#     permit local-as
#     permit no-peer


# Using "merged" state

# Before state:
# -------------
#
# show bgp community-list
# Expanded community list test1:   match: ANY
#     permit 101
#     permit 302

- name: Add new BGP community-lists
  dellemc.enterprise_sonic.sonic_bgp_communities:
    config:
      - name: test2
        type: expanded
        permit: true
        members:
          regex:
            - 909
      - name: test3
        type: standard
        permit: true
        no_peer: true
        members:
          aann:
            - 1000:10
    state: merged

# After state:
# ------------
#
# show bgp community-list
# Expanded community list test1:   match: ANY
#     permit 101
#     permit 302
# Expanded community list test2:   match: ANY
#     permit 909
# Standard community list test3:  match: ANY
#     permit 1000:10
#     permit no-peer


# Using "replaced" state

# Before state:
# -------------
#
# show bgp community-list
# Standard community list test:  match: ANY
#     permit local-as
#     permit no-peer
# Expanded community list test1:   match: ANY
#     deny 101
#     deny 302

- name: Replacing a single BGP community-list
  dellemc.enterprise_sonic.sonic_bgp_communities:
    config:
      - name: test
        type: expanded
        members:
          regex:
            - 301
      - name: test2
        type: standard
        members:
          aann:
            - 1000:10
            - 2000:20
      - name: test3
        type: standard
        no_advertise: true
        no_peer: true
        permit: false
        match: ALL
    state: replaced

# After state:
# ------------
#
# show bgp community-list
# Expanded community list test:   match: ANY
#     deny 301
# Expanded community list test1:   match: ANY
#     deny 101
#     deny 302
# Standard community list test2:  match: ANY
#     deny 1000:10
#     deny 2000:10
# Standard community list test3:  match: ALL
#     deny no-advertise
#     deny no-peer


# Using "overridden" state

# Before state:
# -------------
#
# show bgp community-list
# Standard community list test:  match: ANY
#     permit local-as
#     permit no-peer
# Expanded community list test1:   match: ANY
#     deny 101
#     deny 302

- name: Override entire BGP community-lists
  dellemc.enterprise_sonic.sonic_bgp_communities:
    config:
      - name: test3
        type: expanded
        members:
          regex:
            - 301
    state: overridden

# After state:
# ------------
#
# show bgp community-list
# Expanded community list test3:   match: ANY
#     deny 301
#
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: list
  sample: >
    The configuration that is returned is always in the same format
    as the parameters above.
after:
  description: The resulting configuration module invocation.
  returned: when changed
  type: list
  sample: >
    The configuration that is returned is always in the same format
    as the parameters above.
commands:
  description: The set of commands that are pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.bgp_communities.bgp_communities import Bgp_communitiesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.bgp_communities.bgp_communities import Bgp_communities


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Bgp_communitiesArgs.argument_spec,
                           supports_check_mode=True)

    result = Bgp_communities(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
