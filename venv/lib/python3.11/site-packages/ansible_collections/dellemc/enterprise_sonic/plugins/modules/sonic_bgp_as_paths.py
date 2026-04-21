#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_bgp_as_paths
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_bgp_as_paths
version_added: 1.0.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
short_description: Manage BGP autonomous system path (or as-path-list) and its parameters
description:
  - This module provides configuration management of BGP bgp_as_paths for devices
    running Enterprise SONiC Distribution by Dell Technologies.
author: Kumaraguru Narayanan (@nkumaraguru)
options:
  config:
    description: A list of 'bgp_as_paths' configurations.
    type: list
    elements: dict
    suboptions:
      name:
        required: True
        type: str
        description:
        - Name of as-path-list.
      members:
        required: False
        type: list
        elements: str
        description:
        - Members of this BGP as-path; regular expression string can be provided.
      permit:
        required: False
        type: bool
        description:
        - Permits or denies this as-path.
        - Default value while adding a new as-path-list is C(False).
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
# show bgp as-path-access-list
# AS path list test:
#   action: permit
#   members: 808.*,909.*

- name: Delete BGP as path list
  dellemc.enterprise_sonic.sonic_bgp_as_paths:
    config:
      - name: test
        members:
          - 909.*
        permit: true
    state: deleted

# After state:
# ------------
#
# show bgp as-path-access-list
# AS path list test:
#   action: permit
#   members: 808.*


# Using "deleted" state

# Before state:
# -------------
#
# show bgp as-path-access-list
# AS path list test:
#   action: permit
#   members: 808.*,909.*
# AS path list test1:
#   action: deny
#   members: 608.*,709.*

- name: Deletes BGP as-path list
  dellemc.enterprise_sonic.sonic_bgp_as_paths:
    config:
      - name: test
        members:
    state: deleted

# After state:
# ------------
#
# show bgp as-path-access-list
# AS path list test1:
#   action: deny
#   members: 608.*,709.*


# Using "deleted" state

# Before state:
# -------------
#
# show bgp as-path-access-list
# AS path list test:
#   action: permit
#   members: 808.*,909.*

- name: Deletes BGP as-path list
  dellemc.enterprise_sonic.sonic_bgp_as_paths:
    config:
    state: deleted

# After state:
# ------------
#
# show bgp as-path-access-list
# (No bgp as-path-access-list configuration present)


# Using "merged" state

# Before state:
# -------------
#
# show bgp as-path-access-list
# (No bgp as-path-access-list configuration present)

- name: Create a BGP as-path list
  dellemc.enterprise_sonic.sonic_bgp_as_paths:
    config:
      - name: test
        members:
          - 909.*
        permit: true
    state: merged

# After state:
# ------------
#
# show bgp as-path-access-list
# AS path list test:
#   action: permit
#   members: 909.*


# Using "replaced" state

# Before state:
# -------------
#
# show bgp as-path-access-list
# AS path list test:
#    action: permit
#    members: 800.*,808.*
# AS path list test1:
#    action: deny
#    members: 500.*

- name: Replace device configuration of specified BGP as-path lists with provided configuration
  dellemc.enterprise_sonic.sonic_bgp_as_paths:
    config:
      - name: test
        members:
          - 900.*
          - 901.*
        permit: true
      - name: test1
      - name: test2
        members:
          - 100.*
        permit: true
    state: replaced

# After state:
# ------------
#
# show bgp as-path-access-list
# AS path list test:
#    action: permit
#    members: 900.*,901.*
# AS path list test2:
#    action: permit
#    members: 100.*


# Using "overridden" state

# Before state:
# -------------
#
# show bgp as-path-access-list
# AS path list test:
#    action: permit
#    members: 800.*,808.*
# AS path list test1:
#    action: deny
#    members: 500.*

- name: Override device configuration of all BGP as-path lists with provided configuration
  dellemc.enterprise_sonic.sonic_bgp_as_paths:
    config:
      - name: test
        members:
          - 900.*
          - 901.*
        permit: true
    state: overridden

# After state:
# ------------
#
# show bgp as-path-access-list
# AS path list test:
#    action: permit
#    members: 900.*,901.*
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: list
  sample: >
    The configuration returned is always in the same format
    as the parameters above.
after:
  description: The resulting configuration module invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned is always in the same format
    as the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.bgp_as_paths.bgp_as_paths import Bgp_as_pathsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.bgp_as_paths.bgp_as_paths import Bgp_as_paths


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Bgp_as_pathsArgs.argument_spec,
                           supports_check_mode=True)

    result = Bgp_as_paths(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
