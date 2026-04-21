#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Adam Miller (admiller@redhat.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: deploy
short_description: Trigger a qradar configuration deployment
description:
  - This module allows for INCREMENTAL or FULL deployments
version_added: "1.0.0"
options:
  type:
    description:
     - Type of deployment
    required: false
    type: str
    choices:
      - "INCREMENTAL"
      - "FULL"
    default: "INCREMENTAL"
notes:
  - This module does not support check mode because the QRadar REST API does not offer stateful inspection of configuration deployments

author: "Ansible Security Automation Team (@maxamillion) <https://github.com/ansible-security>"
"""

EXAMPLES = """
- name: run an incremental deploy
  ibm.qradar.deploy:
    type: INCREMENTAL
"""

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.ibm.qradar.plugins.module_utils.qradar import QRadarRequest


def main():
    argspec = dict(
        type=dict(
            choices=["INCREMENTAL", "FULL"],
            required=False,
            default="INCREMENTAL",
        ),
    )

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=False)

    qradar_request = QRadarRequest(
        module,
        not_rest_data_keys=["state", "type_name", "identifier"],
    )

    qradar_return_data = qradar_request.post_by_path(
        "api/staged_config/deploy_status",
    )

    if "message" in qradar_return_data and (
        to_text("No changes to deploy") in to_text(qradar_return_data["message"])
    ):
        module.exit_json(
            msg="No changes to deploy",
            qradar_return_data=qradar_return_data,
            changed=False,
        )
    else:
        module.exit_json(
            msg="Successfully initiated {0} deployment.".format(
                module.params["type"],
            ),
            qradar_return_data=qradar_return_data,
            changed=True,
        )


if __name__ == "__main__":
    main()
