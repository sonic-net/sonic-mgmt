#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Adam Miller (admiller@redhat.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: rule_info
short_description: Obtain information about one or many QRadar Rules, with filter options
description:
  - This module obtains information about one or many QRadar Rules, with filter options
version_added: "1.0.0"
deprecated:
  alternative: qradar_analytics_rules
  why: Newer and updated modules released with more functionality.
  removed_at_date: '2024-09-01'
options:
  id:
    description:
      - Obtain only information of the Rule with provided ID
    required: false
    type: int
  name:
    description:
      - Obtain only information of the Rule that matches the provided name
    required: false
    type: str
  type:
    description:
      - Obtain only information for the Rules of a certain type
    required: false
    choices: [ "EVENT", "FLOW", "COMMON", "USER"]
    type: str
  owner:
    description:
      - Obtain only information of Rules owned by a certain user
    required: false
    type: str
  origin:
    description:
      - Obtain only information of Rules that are of a certain origin
    required: false
    choices: ["SYSTEM", "OVERRIDE", "USER"]
    type: str
notes:
  - You may provide many filters and they will all be applied, except for C(id)
    as that will return only the Rule identified by the unique ID provided.

author: Ansible Security Automation Team (@maxamillion) <https://github.com/ansible-security>"
"""


# FIXME - provide correct example here
RETURN = """
"""

EXAMPLES = """
- name: Get information about the Rule named "Custom Company DDoS Rule"
  ibm.qradar.rule_info:
    name: "Custom Company DDoS Rule"
  register: custom_ddos_rule_info

- name: debugging output of the custom_ddos_rule_info registered variable
  debug:
    var: custom_ddos_rule_info
"""

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves.urllib.parse import quote

from ansible_collections.ibm.qradar.plugins.module_utils.qradar import QRadarRequest


def main():
    argspec = dict(
        id=dict(required=False, type="int"),
        name=dict(required=False, type="str"),
        owner=dict(required=False, type="str"),
        type=dict(
            required=False,
            choices=["EVENT", "FLOW", "COMMON", "USER"],
            type="str",
        ),
        origin=dict(
            required=False,
            choices=["SYSTEM", "OVERRIDE", "USER"],
            type="str",
        ),
    )

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)

    qradar_request = QRadarRequest(module)

    # if module.params['name']:
    #    # FIXME - QUERY HERE BY NAME NATIVELY VIA REST API (DOESN'T EXIST YET)
    #    found_offense = qradar_request.get('/api/analytics/rules?filter={0}'.format(module.params['name']))

    if module.params["id"]:
        code, rules = qradar_request.get(
            "/api/analytics/rules/{0}".format(module.params["id"]),
        )

    else:
        query_strs = []

        if module.params["name"]:
            query_strs.append(
                quote('name="{0}"'.format(to_text(module.params["name"]))),
            )

        if module.params["owner"]:
            query_strs.append(
                quote("owner={0}".format(module.params["owner"])),
            )

        if module.params["type"]:
            query_strs.append(quote("type={0}".format(module.params["type"])))

        if module.params["origin"]:
            query_strs.append(
                quote("origin={0}".format(module.params["origin"])),
            )

        if query_strs:
            code, rules = qradar_request.get(
                "/api/analytics/rules?filter={0}".format("&".join(query_strs)),
            )
        else:
            code, rules = qradar_request.get("/api/analytics/rules")

        module.exit_json(rules=rules, changed=False)


if __name__ == "__main__":
    main()
