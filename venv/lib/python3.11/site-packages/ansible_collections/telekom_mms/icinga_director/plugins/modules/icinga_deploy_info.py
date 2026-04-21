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
module: icinga_deploy_info
short_description: Get deployment information through the director API
description:
  -  Get deployment information through the director API.
author: Falk Händler (@flkhndlr)
version_added: '1.33.0'
extends_documentation_fragment:
  - ansible.builtin.url
  - telekom_mms.icinga_director.common_options
options:
  configs:
    description:
      - A list of checksums of configs to query information for
    type: list
    elements: str
  activities:
    description:
      - A list of checksums of activities to query information for
    type: list
    elements: str
"""

EXAMPLES = """
- name: Query the current deployment info in icinga
  telekom_mms.icinga_director.icinga_deploy_info:
    url: "{{ icinga_url }}"
    url_username: "{{ icinga_user }}"
    url_password: "{{ icinga_pass }}"
"""

RETURN = r"""
active_configuration:
  description:
    - Checksums of the active configuration
    - Contains current activity checksum, config checksum
    - and a checksum for the stage_name
  returned: if active configuration exists
  type: dict
  sample:
    active_configuration:
      activity: 3557598829f2a2fc4acc7b565fb54bae24754c67
      config: 299d9d49e03435c6de562c4b22a26e63990d30a9
      stage_name: 902cb282-e702-43ce-bb3c-962f850a1694
configs:
  description:
    - Checksum of the requested config and its state
  returned: only if requested
  type: list
  sample:
    configs:
      b175ca0562434deeb4fb1fc03fd80cd7361b56df: deployed
      b175ca0562434deeb4fb1fc03fd80cd7361b56de: active
activities:
  description:
    - checksum of the requested activities and its state
  returned: only if requested
  type: list
  sample:
    activities:
      a4c955364bc7b77efd0323fc87d95307f827e30c: deployed
      3557598829f2a2fc4acc7b565fb54bae24754c67: active
"""

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
        configs=dict(type="list", required=False, default=None, elements="str"),
        activities=dict(type="list", required=False, default=None, elements="str"),
        api_timeout=dict(required=False, default=10, type="int"),
    )

    # Define the main module
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    icinga_object = Icinga2APIObject(module=module, path="/config/deployment-status", data=[])

    object_list = icinga_object.query_deployment(
        configs=module.params["configs"], activities=module.params["activities"]
    )

    config_list = {}
    activity_list = {}

    if "configs" in object_list["data"].keys():
        config_list = dict(object_list["data"]["configs"].items())

    if "activities" in object_list["data"].keys():
        activity_list = dict(object_list["data"]["activities"].items())

    module.exit_json(
        objects=object_list,
        active_configuration=object_list["data"]["active_configuration"],
        configs=config_list,
        activities=activity_list
    )


if __name__ == "__main__":
    main()
