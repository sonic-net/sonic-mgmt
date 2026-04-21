#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Adam Miller (admiller@redhat.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: offense_note
short_description: Create or update a QRadar Offense Note
description:
  - This module allows to create a QRadar Offense note
version_added: "1.0.0"
options:
  id:
    description:
      - Offense ID to operate on
    required: true
    type: int
  note_text:
    description: The note's text contents
    required: true
    type: str

author: Ansible Security Automation Team (@maxamillion) <https://github.com/ansible-security>
"""

"""
# FIXME - WOULD LIKE TO QUERY BY NAME BUT HOW TO ACCOMPLISH THAT IS NON-OBVIOUS
# offense_name:
#   description:
#    - Name of Offense
#   required: true
#   type: str

# FIXME - WOULD LIKE TO MANAGE STATE
# state:
#   description: Define state of the note: present or absent
#   required: false
#   choices: ["present", "absent"]
#   default: "present"
"""

EXAMPLES = """
- name: Add a note to QRadar Offense ID 1
  ibm.qradar.offense_note:
    id: 1
    note_text: This an example note entry that should be made on offense id 1
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves.urllib.parse import quote

from ansible_collections.ibm.qradar.plugins.module_utils.qradar import QRadarRequest


def set_offense_values(module, qradar_request):
    if module.params["closing_reason"]:
        code, found_closing_reason = qradar_request.get(
            "/api/siem/offense_closing_reasons?filter={0}".format(
                quote('text="{0}"'.format(module.params["closing_reason"])),
            ),
        )
        if found_closing_reason:
            module.params["closing_reason_id"] = found_closing_reason[0]["id"]
        else:
            module.fail_json(
                "Unable to find closing_reason text: {0}".format(
                    module.params["closing_reason"],
                ),
            )

    if module.params["status"]:
        module.params["status"] = module.params["status"].upper()


def main():
    argspec = dict(
        #        state=dict(required=False, choices=["present", "absent"], type='str', default="present"),
        id=dict(required=True, type="int"),
        note_text=dict(required=True, type="str"),
    )

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)

    qradar_request = QRadarRequest(
        module,
        not_rest_data_keys=["state", "id"],
    )

    # if module.params['name']:
    #    # FIXME - QUERY HERE BY NAME
    #    found_offense = qradar_request.get('/api/siem/offenses?filter={0}'.format(module.params['name']))
    # FIXME - once this is sorted, add it to module_utils

    code, found_notes = qradar_request.get(
        "/api/siem/offenses/{0}/notes?filter={1}".format(
            module.params["id"],
            quote('note_text="{0}"'.format(module.params["note_text"])),
        ),
    )

    # if module.params['state'] == 'present':

    if found_notes:
        # The note we want exists either by ID or by text name, verify

        note = found_notes[0]
        if note["note_text"] == module.params["note_text"]:
            module.exit_json(
                msg="No changes necessary. Nothing to do.",
                changed=False,
            )
        else:
            if module.check_mode:
                module.exit_json(
                    msg="A change would have occured but did not because Check Mode",
                    changed=True,
                )

            qradar_return_data = qradar_request.post_by_path(
                "api/siem/offenses/{0}/notes?note_text={1}".format(
                    module.params["id"],
                    quote("{0}".format(module.params["note_text"])),
                ),
                data=False,
            )
            module.exit_json(
                msg="Successfully created Offense Note ID: {0}".format(
                    qradar_return_data["id"],
                ),
                qradar_return_data=qradar_return_data,
                changed=False,
            )

    else:
        if module.check_mode:
            module.exit_json(
                msg="A change would have occured but did not because Check Mode",
                changed=True,
            )

        qradar_return_data = qradar_request.post_by_path(
            "api/siem/offenses/{0}/notes?note_text={1}".format(
                module.params["id"],
                quote("{0}".format(module.params["note_text"])),
            ),
            data=False,
        )
        module.exit_json(
            msg="Successfully created Offense Note ID: {0}".format(
                qradar_return_data["id"],
            ),
            qradar_return_data=qradar_return_data,
            changed=True,
        )

    module.exit_json(msg="No changes necessary. Nothing to do.", changed=False)

    # FIXME FIXME FIXME - can we actually delete these via the REST API?
    # if module.params['state'] == 'absent':
    #    if not found_notes:
    #        module.exit_json(msg="No changes necessary. Nothing to do.", changed=False)
    #    else:
    #        if module.check_mode:
    #            module.exit_json(msg="A change would have occured but did not because Check Mode", changed=True)
    #        # FIXME: fix the POST here to actually delete
    #        qradar_return_data = qradar_request.post_by_path(
    #            'api/siem/offenses/{0}/notes?note_text={1}'.format(
    #                module.params['id'],
    #                quote("{0}".format(module.params['note_text'])),
    #            ),
    #            data=False
    #        )
    #        module.exit_json(
    #            msg="Successfully created Offense Note ID: {0}".format(qradar_return_data['id']),
    #            qradar_return_data=qradar_return_data,
    #            changed=True
    #        )


if __name__ == "__main__":
    main()
