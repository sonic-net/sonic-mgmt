#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Adam Miller (admiller@redhat.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: offense_info
short_description: Obtain information about one or many QRadar Offenses, with filter options
description:
  - This module allows to obtain information about one or many QRadar Offenses, with filter options
version_added: "1.0.0"
options:
  id:
    description:
      - Obtain only information of the Offense with provided ID
    required: false
    type: int
  name:
    description:
      - Obtain only information of the Offense that matches the provided name
    required: false
    type: str
  status:
    description:
      - Obtain only information of Offenses of a certain status
    required: false
    choices: [ "open", "OPEN", "hidden", "HIDDEN", "closed", "CLOSED" ]
    default: "open"
    type: str
  assigned_to:
    description:
      - Obtain only information of Offenses assigned to a certain user
    required: false
    type: str
  closing_reason:
    description:
      - Obtain only information of Offenses that were closed by a specific closing reason
    required: false
    type: str
  closing_reason_id:
    description:
      - Obtain only information of Offenses that were closed by a specific closing reason ID
    required: false
    type: int
  follow_up:
    description:
      - Obtain only information of Offenses that are marked with the follow up flag
    required: false
    type: bool
  protected:
    description:
      - Obtain only information of Offenses that are protected
    required: false
    type: bool
notes:
  - You may provide many filters and they will all be applied, except for C(id)
    as that will return only

author: Ansible Security Automation Team (@maxamillion) <https://github.com/ansible-security>
"""


# FIXME - provide correct example here
RETURN = """
offenses:
  description: Information
  returned: always
  type: list
  elements: dict
  contains:
    qradar_offenses:
      description: IBM QRadar Offenses found based on provided filters
      returned: always
      type: complex
      contains:
        source:
          description: Init system of the service. One of C(systemd), C(sysv), C(upstart).
          returned: always
          type: str
          sample: sysv
        state:
          description: State of the service. Either C(running), C(stopped), or C(unknown).
          returned: always
          type: str
          sample: running
        status:
          description: State of the service. Either C(enabled), C(disabled), or C(unknown).
          returned: systemd systems or RedHat/SUSE flavored sysvinit/upstart
          type: str
          sample: enabled
        name:
          description: Name of the service.
          returned: always
          type: str
          sample: arp-ethers.service
"""


EXAMPLES = """
- name: Get list of all currently OPEN IBM QRadar Offenses
  ibm.qradar.offense_info:
    status: OPEN
  register: offense_list

- name: display offense information for debug purposes
  debug:
    var: offense_list
"""

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves.urllib.parse import quote

from ansible_collections.ibm.qradar.plugins.module_utils.qradar import (
    QRadarRequest,
    find_dict_in_list,
    set_offense_values,
)


def main():
    argspec = dict(
        id=dict(required=False, type="int"),
        name=dict(required=False, type="str"),
        assigned_to=dict(required=False, type="str"),
        closing_reason=dict(required=False, type="str"),
        closing_reason_id=dict(required=False, type="int"),
        follow_up=dict(required=False, type="bool", default=None),
        protected=dict(required=False, type="bool", default=None),
        status=dict(
            required=False,
            choices=["open", "OPEN", "hidden", "HIDDEN", "closed", "CLOSED"],
            default="open",
            type="str",
        ),
    )

    module = AnsibleModule(
        argument_spec=argspec,
        mutually_exclusive=[("closing_reason", "closing_reason_id")],
        supports_check_mode=True,
    )

    qradar_request = QRadarRequest(module)

    # if module.params['name']:
    #    # FIXME - QUERY HERE BY NAME NATIVELY VIA REST API (DOESN'T EXIST YET)
    #    found_offense = qradar_request.get('/api/siem/offenses?filter={0}'.format(module.params['name']))

    set_offense_values(module, qradar_request)

    if module.params["id"]:
        code, offenses = qradar_request.get(
            "/api/siem/offenses/{0}".format(module.params["id"]),
        )

    else:
        query_strs = []

        if module.params["status"]:
            query_strs.append(
                quote("status={0}".format(to_text(module.params["status"]))),
            )

        if module.params["assigned_to"]:
            query_strs.append(
                quote("assigned_to={0}".format(module.params["assigned_to"])),
            )

        if module.params["closing_reason_id"]:
            query_strs.append(
                quote(
                    "closing_reason_id={0}".format(
                        module.params["closing_reason_id"],
                    ),
                ),
            )

        if module.params["follow_up"] is not None:
            query_strs.append(
                quote("follow_up={0}".format(module.params["follow_up"])),
            )

        if module.params["protected"] is not None:
            query_strs.append(
                quote("protected={0}".format(module.params["protected"])),
            )

        if query_strs:
            code, offenses = qradar_request.get(
                "/api/siem/offenses?filter={0}".format("&".join(query_strs)),
            )
        else:
            code, offenses = qradar_request.get("/api/siem/offenses")

        if module.params["name"]:
            named_offense = find_dict_in_list(
                offenses,
                "description",
                module.params["name"],
            )
            if named_offense:
                offenses = named_offense
            else:
                offenses = []

        module.exit_json(offenses=offenses, changed=False)


if __name__ == "__main__":
    main()
