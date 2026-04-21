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
module: cp_mgmt_check_threat_ioc_feed
short_description: Check if a target can reach or parse a threat IOC feed; can work with an existing feed object or with
                   a new one (by providing all relevant feed parameters).
description:
  - Check if a target can reach or parse a threat IOC feed; can work with an existing feed object or with a new one (by providing all relevant feed
    parameters).
  - All operations are performed over Web Services API.
  - Available from R81.20 management version.
version_added: "3.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  ioc_feed:
    description:
      - threat ioc feed parameters.
    type: dict
    suboptions:
      name:
        description:
          - Object name.
        type: str
      feed_url:
        description:
          - URL of the feed. URL should be written as http or https.
        type: str
      action:
        description:
          - The feed indicator's action.
        type: str
        choices: ['Prevent', 'Detect']
      certificate_id:
        description:
          - Certificate SHA-1 fingerprint to access the feed.
        type: str
      custom_comment:
        description:
          - Custom IOC feed - the column number of comment.
        type: int
      custom_confidence:
        description:
          - Custom IOC feed - the column number of confidence.
        type: int
      custom_header:
        description:
          - Custom HTTP headers.
        type: list
        elements: dict
        suboptions:
          header_name:
            description:
              - The name of the HTTP header we wish to add.
            type: str
          header_value:
            description:
              - The name of the HTTP value we wish to add.
            type: str
      custom_name:
        description:
          - Custom IOC feed - the column number of name.
        type: int
      custom_severity:
        description:
          - Custom IOC feed - the column number of severity.
        type: int
      custom_type:
        description:
          - Custom IOC feed - the column number of type in case a specific type is not chosen.
        type: int
      custom_value:
        description:
          - Custom IOC feed - the column number of value in case a specific type is chosen.
        type: int
      enabled:
        description:
          - Sets whether this indicator feed is enabled.
        type: bool
      feed_type:
        description:
          - Feed type to be enforced.
        type: str
        choices: ['any type', 'domain', 'ip address', 'md5', 'url', 'ip range', 'mail subject', 'mail from', 'mail to', 'mail reply to',
                 'mail cc', 'sha1', 'sha256']
      password:
        description:
          - password for authenticating with the URL.
        type: str
      use_custom_feed_settings:
        description:
          - Set in order to configure a custom indicator feed.
        type: bool
      username:
        description:
          - username for authenticating with the URL.
        type: str
      fields_delimiter:
        description:
          - The delimiter that separates between the columns in the feed.
        type: str
      ignore_lines_that_start_with:
        description:
          - A prefix that will determine which lines to ignore.
        type: str
      use_gateway_proxy:
        description:
          - Use the gateway's proxy for retrieving the feed.
        type: bool
      details_level:
        description:
          - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
            representation of the object.
        type: str
        choices: ['uid', 'standard', 'full']
      ignore_warnings:
        description:
          - Apply changes ignoring warnings.
        type: bool
      ignore_errors:
        description:
          - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
        type: bool
  targets:
    description:
      - On what targets to execute this command. Targets may be identified by their name, or object unique identifier.
    type: list
    elements: str
  auto_publish_session:
    description:
      - Publish the current session if changes have been performed after task completes.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: check-threat-ioc-feed
  cp_mgmt_check_threat_ioc_feed:
    ioc_feed:
      name: existing_feed
    targets: corporate-gateway
"""

RETURN = """
cp_mgmt_check_threat_ioc_feed:
  description: The checkpoint check-threat-ioc-feed output.
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
        ioc_feed=dict(
            type="dict",
            options=dict(
                name=dict(type="str"),
                feed_url=dict(type="str"),
                action=dict(type="str", choices=["Prevent", "Detect"]),
                certificate_id=dict(type="str"),
                custom_comment=dict(type="int"),
                custom_confidence=dict(type="int"),
                custom_header=dict(
                    type="list",
                    elements="dict",
                    options=dict(
                        header_name=dict(type="str"),
                        header_value=dict(type="str"),
                    ),
                ),
                custom_name=dict(type="int"),
                custom_severity=dict(type="int"),
                custom_type=dict(type="int"),
                custom_value=dict(type="int"),
                enabled=dict(type="bool"),
                feed_type=dict(
                    type="str",
                    choices=[
                        "any type",
                        "domain",
                        "ip address",
                        "md5",
                        "url",
                        "ip range",
                        "mail subject",
                        "mail from",
                        "mail to",
                        "mail reply to",
                        "mail cc",
                        "sha1",
                        "sha256",
                    ],
                ),
                password=dict(type="str", no_log=True),
                use_custom_feed_settings=dict(type="bool"),
                username=dict(type="str"),
                fields_delimiter=dict(type="str"),
                ignore_lines_that_start_with=dict(type="str"),
                use_gateway_proxy=dict(type="bool"),
                details_level=dict(
                    type="str", choices=["uid", "standard", "full"]
                ),
                ignore_warnings=dict(type="bool"),
                ignore_errors=dict(type="bool"),
            ),
        ),
        targets=dict(type="list", elements="str"),
        auto_publish_session=dict(type="bool"),
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "check-threat-ioc-feed"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
