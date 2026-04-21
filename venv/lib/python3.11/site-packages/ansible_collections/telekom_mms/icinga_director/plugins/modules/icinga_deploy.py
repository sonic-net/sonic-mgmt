#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 T-Systems Multimedia Solutions GmbH
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: icinga_deploy
short_description: Trigger deployment in Icinga2
description:
  - Trigger a deployment to Icinga2 through the director API.
author: Falk Händler (@flkhndlr)
version_added: '1.33.0'
extends_documentation_fragment:
  - ansible.builtin.url
  - telekom_mms.icinga_director.common_options
options:
  timeout:
    description:
      - Default timeout to wait for deployment to finish in seconds.
    default: 2
    type: int
"""

EXAMPLES = """
- name: Deploy the icinga config
  telekom_mms.icinga_director.icinga_deploy:
    url: "{{ icinga_url }}"
    url_username: "{{ icinga_user }}"
    url_password: "{{ icinga_pass }}"
    timeout: 5
"""

RETURN = r"""
checksum:
  description:
    - Checksum of the configuration that should be rolled out
  returned: always
  type: str
  sample:
    checksum: 294bdfb53c4da471e37317beed549a953c939424
"""


from time import sleep
from ansible.module_utils.urls import url_argument_spec
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.telekom_mms.icinga_director.plugins.module_utils.icinga import (
    Icinga2APIObject,
)
# ===========================================
# Module execution.
#


def main():
    # use the predefined argument spec for url
    argument_spec = url_argument_spec()

    # add our own arguments
    argument_spec.update(
        url=dict(required=True),
        timeout=dict(required=False, default=2, type="int"),
        api_timeout=dict(required=False, default=10, type="int"),
    )

    # Define the main module
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
    )

    # get the current deployment status
    icinga_deploy_status = Icinga2APIObject(module=module, path="/config/deployment-status", data=[])

    # if there is no existing deployment (e.g. on a new instance), there is no config object
    if "config" in icinga_deploy_status.query_deployment()["data"]["active_configuration"]:
        active_deployment = icinga_deploy_status.query_deployment()["data"]["active_configuration"]["config"]
    else:
        active_deployment = ""

    # execute the deployment
    icinga_deployment = Icinga2APIObject(module=module, path="/config/deploy", data=[])
    result = icinga_deployment.create()
    # the deployment is asynchronous and I don't know of a way to check if it is finished.
    # so we need some sleep here. 2 seconds is a wild guess and a default, now it is a variable
    sleep(module.params["timeout"])

    # get the new deployment status
    create_deployment = icinga_deploy_status.query_deployment()["data"]["active_configuration"]["config"]

    # when the old checksum, the checksum to be created and the new checksum are the same, nothing changed
    if result["data"]["checksum"] == active_deployment == create_deployment:
        module.exit_json(
            changed=False,
            checksum=result["data"]["checksum"],
        )
    # when the current and new deployment are the same, but the checksum to be created is different, the deployment failed
    elif create_deployment == active_deployment:
        module.fail_json(msg="deployment failed")
    # in other cases the deployment succeeded and changed something
    else:
        module.exit_json(
            changed=True,
            checksum=result["data"]["checksum"],
        )


if __name__ == "__main__":
    main()
