#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Adam Miller (admiller@redhat.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: rule
short_description: Manage state of QRadar Rules, with filter options
description:
  - Manage state of QRadar Rules, with filter options
version_added: "1.0.0"
deprecated:
  alternative: qradar_analytics_rules
  why: Newer and updated modules released with more functionality.
  removed_at_date: '2024-09-01'
options:
  id:
    description:
      - Manage state of a QRadar Rule by ID
    required: false
    type: int
  name:
    description:
      - Manage state of a QRadar Rule by name
    required: false
    type: str
  state:
    description:
      - Manage state of a QRadar Rule
    required: True
    choices: [ "enabled", "disabled", "absent" ]
    type: str
  owner:
    description:
      - Manage ownership of a QRadar Rule
    required: false
    type: str

author: Ansible Security Automation Team (@maxamillion) <https://github.com/ansible-security>
"""


# FIXME - provide correct example here
RETURN = """
"""

EXAMPLES = """
- name: Enable Rule 'Ansible Example DDoS Rule'
  qradar_rule:
    name: 'Ansible Example DDOS Rule'
    state: enabled
"""

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves.urllib.parse import quote

from ansible_collections.ibm.qradar.plugins.module_utils.qradar import QRadarRequest


def main():
    argspec = dict(
        id=dict(required=False, type="int"),
        name=dict(required=False, type="str"),
        state=dict(
            required=True,
            choices=["enabled", "disabled", "absent"],
            type="str",
        ),
        owner=dict(required=False, type="str"),
    )

    module = AnsibleModule(
        argument_spec=argspec,
        supports_check_mode=True,
        required_one_of=[("name", "id")],
        mutually_exclusive=[("name", "id")],
    )

    qradar_request = QRadarRequest(
        module,
        not_rest_data_keys=["id", "name", "state", "owner"],
    )

    # if module.params['name']:
    #    # FIXME - QUERY HERE BY NAME NATIVELY VIA REST API (DOESN'T EXIST YET)
    #    found_offense = qradar_request.get('/api/analytics/rules?filter={0}'.format(module.params['name']))
    module.params["rule"] = {}

    if module.params["id"]:
        code, module.params["rule"] = qradar_request.get(
            "/api/analytics/rules/{0}".format(module.params["id"]),
        )

    elif module.params["name"]:
        code, rules = qradar_request.get(
            "/api/analytics/rules?filter={0}".format(
                quote('"{0}"'.format(module.params["name"])),
            ),
        )
        if rules:
            module.params["rule"] = rules[0]
            module.params["id"] = rules[0]["id"]

    if module.params["state"] == "enabled":
        if module.params["rule"]:
            if module.params["rule"]["enabled"] is True:
                # Already enabled
                if module.params["id"]:
                    module.exit_json(
                        msg="No change needed for rule ID: {0}".format(
                            module.params["id"],
                        ),
                        qradar_return_data={},
                        changed=False,
                    )
                if module.params["name"]:
                    module.exit_json(
                        msg="Successfully enabled rule named: {0}".format(
                            module.params["name"],
                        ),
                        qradar_return_data={},
                        changed=False,
                    )
            else:
                # Not enabled, enable It
                module.params["rule"]["enabled"] = True

                qradar_return_data = qradar_request.post_by_path(
                    "api/analytics/rules/{0}".format(
                        module.params["rule"]["id"],
                    ),
                    data=json.dumps(module.params["rule"]),
                )
                if module.params["id"]:
                    module.exit_json(
                        msg="Successfully enabled rule ID: {0}".format(
                            module.params["id"],
                        ),
                        qradar_return_data=qradar_return_data,
                        changed=True,
                    )
                if module.params["name"]:
                    module.exit_json(
                        msg="Successfully enabled rule named: {0}".format(
                            module.params["name"],
                        ),
                        qradar_return_data=qradar_return_data,
                        changed=True,
                    )
        else:
            if module.params["id"]:
                module.fail_json(
                    msg="Unable to find rule ID: {0}".format(
                        module.params["id"],
                    ),
                )
            if module.params["name"]:
                module.fail_json(
                    msg='Unable to find rule named: "{0}"'.format(
                        module.params["name"],
                    ),
                )

    elif module.params["state"] == "disabled":
        if module.params["rule"]:
            if module.params["rule"]["enabled"] is False:
                # Already disabled
                if module.params["id"]:
                    module.exit_json(
                        msg="No change needed for rule ID: {0}".format(
                            module.params["id"],
                        ),
                        qradar_return_data={},
                        changed=False,
                    )
                if module.params["name"]:
                    module.exit_json(
                        msg="Successfully enabled rule named: {0}".format(
                            module.params["name"],
                        ),
                        qradar_return_data={},
                        changed=False,
                    )
            else:
                # Not disabled, disable It
                module.params["rule"]["enabled"] = False

                qradar_return_data = qradar_request.post_by_path(
                    "api/analytics/rules/{0}".format(
                        module.params["rule"]["id"],
                    ),
                    data=json.dumps(module.params["rule"]),
                )
                if module.params["id"]:
                    module.exit_json(
                        msg="Successfully disabled rule ID: {0}".format(
                            module.params["id"],
                        ),
                        qradar_return_data=qradar_return_data,
                        changed=True,
                    )
                if module.params["name"]:
                    module.exit_json(
                        msg="Successfully disabled rule named: {0}".format(
                            module.params["name"],
                        ),
                        qradar_return_data=qradar_return_data,
                        changed=True,
                    )
        else:
            if module.params["id"]:
                module.fail_json(
                    msg="Unable to find rule ID: {0}".format(
                        module.params["id"],
                    ),
                )
            if module.params["name"]:
                module.fail_json(
                    msg='Unable to find rule named: "{0}"'.format(
                        module.params["name"],
                    ),
                )

    elif module.params["state"] == "absent":
        if module.params["rule"]:
            code, qradar_return_data = qradar_request.delete(
                "/api/analytics/rules/{0}".format(module.params["rule"]["id"]),
            )
            if module.params["id"]:
                module.exit_json(
                    msg="Successfully deleted rule ID: {0}".format(
                        module.params["id"],
                    ),
                    qradar_return_data=qradar_return_data,
                    changed=True,
                )
            if module.params["name"]:
                module.exit_json(
                    msg="Successfully deleted rule named: {0}".format(
                        module.params["name"],
                    ),
                    qradar_return_data=qradar_return_data,
                    changed=True,
                )
        else:
            module.exit_json(msg="Nothing to do, rule not found.")

        module.exit_json(rules=rules, changed=False)


if __name__ == "__main__":
    main()
