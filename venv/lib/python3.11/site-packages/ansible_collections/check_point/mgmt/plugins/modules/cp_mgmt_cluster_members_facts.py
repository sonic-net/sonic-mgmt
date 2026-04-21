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
module: cp_mgmt_cluster_members_facts
short_description: Retrieve all existing cluster members in domain.
description:
  - Retrieve all existing cluster members in domain.
  - All operations are performed over Web Services API.
  - Available from R81.10 JHF management version.
version_added: "3.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  uid:
    description:
      - Cluster member unique identifier.
    type: str
  limit_interfaces:
    description:
      - Limit number of cluster member interfaces to show.
    type: int
  filter:
    description:
      - Search expression to filter objects by. The provided text should be exactly the same as it would be given in SmartConsole Object Explorer. The
        logical operators in the expression ('AND', 'OR') should be provided in capital letters. The search involves both a IP search and a textual search in
        name, comment, tags etc.
    type: str
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
  show_membership:
    description:
      - Indicates whether to calculate and show "groups" field for every object in reply.
    type: bool
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
  domains_to_process:
    description:
      - Indicates which domains to process the commands on. It cannot be used with the details-level full, must be run from the System Domain only and
        with ignore-warnings true. Valid values are, CURRENT_DOMAIN, ALL_DOMAINS_ON_THIS_SERVER.
    type: list
    elements: str
extends_documentation_fragment: check_point.mgmt.checkpoint_facts
"""

EXAMPLES = """
- name: show-cluster-member
  cp_mgmt_cluster_members_facts:
    uid: 871a47b9-0000-4444-555-593c2111111

- name: show-cluster-members
  cp_mgmt_cluster_members_facts:
    details_level: standard
    limit: 5
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
    api_call_facts,
)


def main():
    argument_spec = dict(
        uid=dict(type="str"),
        limit_interfaces=dict(type="int"),
        filter=dict(type="str"),
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
        show_membership=dict(type="bool"),
        details_level=dict(type="str", choices=["uid", "standard", "full"]),
        domains_to_process=dict(type="list", elements="str"),
    )
    argument_spec.update(checkpoint_argument_spec_for_facts)

    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True
    )

    api_call_object = "cluster-member"
    api_call_object_plural_version = "cluster-members"

    result = api_call_facts(
        module, api_call_object, api_call_object_plural_version
    )
    module.exit_json(**result)


if __name__ == "__main__":
    main()
