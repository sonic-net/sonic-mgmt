#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Adam Miller (admiller@redhat.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: offense_action
short_description: Take action on a QRadar Offense
description:
  - This module allows to assign, protect, follow up, set status, and assign closing reason to QRadar Offenses
version_added: "1.0.0"
options:
  id:
    description:
     - ID of Offense
    required: true
    type: int
  status:
    description:
      - One of "open", "hidden" or "closed". (Either all lower case or all caps)
    required: false
    choices: [ "open", "OPEN", "hidden", "HIDDEN", "closed", "CLOSED" ]
    type: str
  assigned_to:
    description:
      - Assign to an user, the QRadar username should be provided
    required: false
    type: str
  closing_reason:
    description:
      - Assign a predefined closing reason here, by name.
    required: false
    type: str
  closing_reason_id:
    description:
      - Assign a predefined closing reason here, by id.
    required: false
    type: int
  follow_up:
    description:
      - Set or unset the flag to follow up on a QRadar Offense
    required: false
    type: bool
  protected:
    description:
      - Set or unset the flag to protect a QRadar Offense
    required: false
    type: bool

notes:
  - Requires one of C(name) or C(id) be provided
  - Only one of C(closing_reason) or C(closing_reason_id) can be provided

author: Ansible Security Automation Team (@maxamillion) <https://github.com/ansible-security>
"""

"""
# FIXME - WOULD LIKE TO QUERY BY NAME BUT HOW TO ACCOMPLISH THAT IS NON-OBVIOUS
# name:
#   description:
#    - Name of Offense
#   required: true
#   type: str
"""

EXAMPLES = """
"""

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.ibm.qradar.plugins.module_utils.qradar import (
    QRadarRequest,
    set_offense_values,
)


def main():
    argspec = dict(
        # name=dict(required=False, type='str'),
        # id=dict(required=False, type='str'),
        id=dict(required=True, type="int"),
        assigned_to=dict(required=False, type="str"),
        closing_reason=dict(required=False, type="str"),
        closing_reason_id=dict(required=False, type="int"),
        follow_up=dict(required=False, type="bool"),
        protected=dict(required=False, type="bool"),
        status=dict(
            required=False,
            choices=["open", "OPEN", "hidden", "HIDDEN", "closed", "CLOSED"],
            type="str",
        ),
    )

    module = AnsibleModule(
        argument_spec=argspec,
        # required_one_of=[
        #    ('name', 'id',),
        # ],
        mutually_exclusive=[("closing_reason", "closing_reason_id")],
        supports_check_mode=True,
    )

    qradar_request = QRadarRequest(
        module,
        not_rest_data_keys=["name", "id", "assigned_to", "closing_reason"],
    )

    # if module.params['name']:
    #    # FIXME - QUERY HERE BY NAME
    #    found_offense = qradar_request.get('/api/siem/offenses?filter={0}'.format(module.params['name']))

    code, found_offense = qradar_request.get(
        "/api/siem/offenses/{0}".format(module.params["id"]),
    )

    if found_offense:
        set_offense_values(module, qradar_request)

        post_strs = []

        if module.params["status"] and (
            to_text(found_offense["status"]) != to_text(module.params["status"])
        ):
            post_strs.append(
                "status={0}".format(to_text(module.params["status"])),
            )

        if module.params["assigned_to"] and (
            to_text(found_offense["assigned_to"]) != to_text(module.params["assigned_to"])
        ):
            post_strs.append(
                "assigned_to={0}".format(module.params["assigned_to"]),
            )

        if module.params["closing_reason_id"] and (
            found_offense["closing_reason_id"] != module.params["closing_reason_id"]
        ):
            post_strs.append(
                "closing_reason_id={0}".format(
                    module.params["closing_reason_id"],
                ),
            )

        if module.params["follow_up"] and (
            found_offense["follow_up"] != module.params["follow_up"]
        ):
            post_strs.append(
                "follow_up={0}".format(module.params["follow_up"]),
            )

        if module.params["protected"] and (
            found_offense["protected"] != module.params["protected"]
        ):
            post_strs.append(
                "protected={0}".format(module.params["protected"]),
            )

        if post_strs:
            if module.check_mode:
                module.exit_json(
                    msg="A change would have been made but was not because of Check Mode.",
                    changed=True,
                )

            qradar_return_data = qradar_request.post_by_path(
                "api/siem/offenses/{0}?{1}".format(
                    module.params["id"],
                    "&".join(post_strs),
                ),
            )
            # FIXME - handle the scenario in which we can search by name and this isn't a required param anymore
            module.exit_json(
                msg="Successfully updated Offense ID: {0}".format(
                    module.params["id"],
                ),
                qradar_return_data=qradar_return_data,
                changed=True,
            )
        else:
            module.exit_json(
                msg="No changes necessary. Nothing to do.",
                changed=False,
            )
    else:
        # FIXME - handle the scenario in which we can search by name and this isn't a required param anymore
        module.fail_json(
            msg="Unable to find Offense ID: {0}".format(module.params["id"]),
        )


if __name__ == "__main__":
    main()
