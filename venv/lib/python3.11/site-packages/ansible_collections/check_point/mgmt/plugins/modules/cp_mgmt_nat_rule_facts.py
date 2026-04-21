#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Ansible module to manage CheckPoint Firewall (c) 2019
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: cp_mgmt_nat_rule_facts
short_description: Get nat-rule objects facts on Checkpoint over Web Services API
description:
  - Get nat-rule objects facts on Checkpoint devices.
  - All operations are performed over Web Services API.
  - This module handles both operations, get a specific object and get several objects,
    For getting a specific object use the parameter 'name'.
  - Available from R80 management version.
version_added: "2.0.0"
author: "Or Soffer (@chkp-orso)"
options:
  rule_number:
    description:
      - Rule number.
    type: str
  name:
    description:
      - Rule name.
        This parameter is relevant only for getting a specific object. Minimum version required is 1.7.1.
      - Available from R81 management version.
    type: str
  package:
    description:
      - Name of the package.
    type: str
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
  filter:
    description:
      - Search expression to filter the rulebase. The provided text should be exactly the same as it would be given in Smart Console. The logical
        operators in the expression ('AND', 'OR') should be provided in capital letters. If an operator is not used, the default OR operator applies.
      - Available from R80.10 management version.
    type: str
  filter_settings:
    description:
      - Sets filter preferences.
    type: dict
    suboptions:
      search_mode:
        description:
          - When set to 'general', both the Full Text Search and Packet Search are enabled. In this mode, Packet Search will not match on 'Any'
            object, a negated cell or a group-with-exclusion. When the search-mode is set to 'packet', by default, the match on 'Any' object, a negated cell
            or a group-with-exclusion are enabled. packet-search-settings may be provided to change the default behavior.
        type: str
        choices: ['general', 'packet']
      packet_search_settings:
        description:
          - When 'search-mode' is set to 'packet', this object allows to set the packet search preferences.
        type: dict
        suboptions:
          expand_group_members:
            description:
              - When true, if the search expression contains a UID or a name of a group object, results will include rules that match on at
                least one member of the group.
              - Available from R80.20 management version.
            type: bool
          expand_group_with_exclusion_members:
            description:
              - When true, if the search expression contains a UID or a name of a group-with-exclusion object, results will include rules that
                match at least one member of the "include" part and is not a member of the "except" part.
              - Available from R80.20 management version.
            type: bool
          match_on_any:
            description:
              - Whether to match on 'Any' object.
            type: bool
          match_on_group_with_exclusion:
            description:
              - Whether to match on a group-with-exclusion.
            type: bool
          match_on_negate:
            description:
              - Whether to match on a negated cell.
            type: bool
  limit:
    description:
      - The maximal number of returned results.
        This parameter is relevant only for getting few objects.
    type: int
  offset:
    description:
      - Number of the results to initially skip.
        This parameter is relevant only for getting few objects.
    type: int
  order:
    description:
      - Sorts the results by search criteria. Automatically sorts the results by Name, in the ascending order.
        This parameter is relevant only for getting few objects.
    type: list
    elements: dict
    suboptions:
      ASC:
        description:
          - Sorts results by the given field in ascending order.
        type: str
        choices: ['name']
      DESC:
        description:
          - Sorts results by the given field in descending order.
        type: str
        choices: ['name']
  use_object_dictionary:
    description:
      - N/A
    type: bool
  dereference_group_members:
    description:
      - Indicates whether to dereference "members" field by details level for every object in reply.
      - Available from R80.10 management version.
    type: bool
  show_membership:
    description:
      - Indicates whether to calculate and show "groups" field for every object in reply.
      - Available from R80.10 management version.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_facts
"""

EXAMPLES = """
- name: show-nat-rule
  cp_mgmt_nat_rule_facts:
    package: standard
    name: nat_rule1

- name: show-nat-rulebase
  cp_mgmt_nat_rule_facts:
    details_level: standard
    limit: 2
    offset: 1
    package: standard
    use_object_dictionary: true
"""

RETURN = """
ansible_facts:
  description: The checkpoint object facts.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    checkpoint_argument_spec_for_facts,
    api_call_facts_for_rule,
)


def main():
    argument_spec = dict(
        rule_number=dict(type="str"),
        name=dict(type='str'),
        package=dict(type="str"),
        details_level=dict(type="str", choices=["uid", "standard", "full"]),
        filter=dict(type="str"),
        filter_settings=dict(
            type="dict",
            options=dict(
                search_mode=dict(type="str", choices=["general", "packet"]),
                packet_search_settings=dict(
                    type="dict",
                    options=dict(
                        expand_group_members=dict(type="bool"),
                        expand_group_with_exclusion_members=dict(type="bool"),
                        match_on_any=dict(type="bool"),
                        match_on_group_with_exclusion=dict(type="bool"),
                        match_on_negate=dict(type="bool"),
                    ),
                ),
            ),
        ),
        limit=dict(type="int"),
        offset=dict(type="int"),
        order=dict(
            type="list",
            elements="dict",
            options=dict(
                ASC=dict(type="str", choices=["name"]),
                DESC=dict(type="str", choices=["name"]),
            ),
        ),
        use_object_dictionary=dict(type="bool"),
        dereference_group_members=dict(type="bool"),
        show_membership=dict(type="bool"),
    )
    argument_spec.update(checkpoint_argument_spec_for_facts)

    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True
    )

    api_call_object = "nat-rule"
    api_call_object_plural_version = "nat-rulebase"

    result = api_call_facts_for_rule(
        module, api_call_object, api_call_object_plural_version
    )
    module.exit_json(ansible_facts=result)


if __name__ == "__main__":
    main()
