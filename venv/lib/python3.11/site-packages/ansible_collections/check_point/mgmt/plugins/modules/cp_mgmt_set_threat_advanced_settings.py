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
module: cp_mgmt_set_threat_advanced_settings
short_description: Edit Threat Prevention's Blades' Settings.
description:
  - Edit Threat Prevention's Blades' Settings.
  - All operations are performed over Web Services API.
  - Available from R81.20 management version.
version_added: "3.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  feed_retrieving_interval:
    description:
      - Feed retrieving intervals of External Feed, in the form of HH,MM.
    type: str
  httpi_non_standard_ports:
    description:
      - Enable HTTP Inspection on non standard ports for Threat Prevention blades.
    type: bool
  internal_error_fail_mode:
    description:
      - In case of internal system error, allow or block all connections.
    type: str
    choices: ['allow connections', 'block connections']
  log_unification_timeout:
    description:
      - Session unification timeout for logs (minutes).
    type: int
  resource_classification:
    description:
      - Allow (Background) or Block (Hold) requests until categorization is complete.
    type: dict
    suboptions:
      custom_settings:
        description:
          - On Custom mode, custom resources classification per service.
        type: dict
        suboptions:
          anti_bot:
            description:
              - Custom Settings for Anti Bot Blade.
            type: str
            choices: ['background', 'hold']
          anti_virus:
            description:
              - Custom Settings for Anti Virus Blade.
            type: str
            choices: ['background', 'hold']
          zero_phishing:
            description:
              - Custom Settings for Zero Phishing Blade.
            type: str
            choices: ['background', 'hold']
      mode:
        description:
          - Set all services to the same mode or choose a custom mode.
        type: str
        choices: ['background', 'hold', 'custom']
      web_service_fail_mode:
        description:
          - Block connections when the web service is unavailable.
        type: str
        choices: ['allow connections', 'block connections']
  ignore_warnings:
    description:
      - Apply changes ignoring warnings.
    type: bool
  ignore_errors:
    description:
      - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
    type: bool
  auto_publish_session:
    description:
    - Publish the current session if changes have been performed after task completes.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: set-threat-advanced-settings
  cp_mgmt_set_threat_advanced_settings:
    feed_retrieving_interval: 00:05
    httpi_non_standard_ports: true
    internal_error_fail_mode: allow connections
    log_unification_timeout: 600
    resource_classification.mode: hold
    resource_classification.web_service_fail_mode: block connections
"""

RETURN = """
cp_mgmt_set_threat_advanced_settings:
  description: The checkpoint set-threat-advanced-settings output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    checkpoint_argument_spec_for_commands,
    api_command,
)


def main():
    argument_spec = dict(
        feed_retrieving_interval=dict(type="str"),
        httpi_non_standard_ports=dict(type="bool"),
        internal_error_fail_mode=dict(
            type="str", choices=["allow connections", "block connections"]
        ),
        log_unification_timeout=dict(type="int"),
        resource_classification=dict(
            type="dict",
            options=dict(
                custom_settings=dict(
                    type="dict",
                    options=dict(
                        anti_bot=dict(
                            type="str", choices=["background", "hold"]
                        ),
                        anti_virus=dict(
                            type="str", choices=["background", "hold"]
                        ),
                        zero_phishing=dict(
                            type="str", choices=["background", "hold"]
                        ),
                    ),
                ),
                mode=dict(
                    type="str", choices=["background", "hold", "custom"]
                ),
                web_service_fail_mode=dict(
                    type="str",
                    choices=["allow connections", "block connections"],
                ),
            ),
        ),
        ignore_warnings=dict(type="bool"),
        ignore_errors=dict(type="bool"),
        auto_publish_session=dict(type="bool"),
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "set-threat-advanced-settings"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
