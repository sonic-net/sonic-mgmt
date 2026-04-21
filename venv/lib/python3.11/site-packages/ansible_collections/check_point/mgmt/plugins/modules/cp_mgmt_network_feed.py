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
module: cp_mgmt_network_feed
short_description: Manages network-feed objects on Checkpoint over Web Services API
description:
  - Manages network-feed objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R81.20 management version.
version_added: "3.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  feed_url:
    description:
      - URL of the feed. URL should be written as http or https.
    type: str
  certificate_id:
    description:
      - Certificate SHA-1 fingerprint to access the feed.
    type: str
  feed_format:
    description:
      - Feed file format.
    type: str
    choices: ['Flat List', 'JSON']
  feed_type:
    description:
      - Feed type to be enforced.
    type: str
    choices: ['Domain', 'IP Address', 'IP Address/Domain']
  password:
    description:
      - password for authenticating with the URL.
    type: str
  tags:
    description:
      - Collection of tag identifiers.
    type: list
    elements: str
  username:
    description:
      - username for authenticating with the URL.
    type: str
  custom_header:
    description:
      - Headers to allow different authentication methods with the URL.
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
  update_interval:
    description:
      - Interval in minutes for updating the feed on the Security Gateway.
    type: int
  data_column:
    description:
      - Number of the column that contains the feed's data.
    type: int
  fields_delimiter:
    description:
      - The delimiter that separates between the columns in the feed.
    type: str
  ignore_lines_that_start_with:
    description:
      - A prefix that will determine which lines to ignore.
    type: str
  json_query:
    description:
      - JQ query to be parsed.
    type: str
  use_gateway_proxy:
    description:
      - Use the gateway's proxy for retrieving the feed.
    type: bool
  color:
    description:
      - Color of the object. Should be one of existing colors.
    type: str
    choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange', 'dark sea green',
             'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon',
             'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna', 'yellow']
  comments:
    description:
      - Comments string.
    type: str
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
  domains_to_process:
    description:
      - Indicates which domains to process the commands on. It cannot be used with the details-level full, must be run from the System Domain only and
        with ignore-warnings true. Valid values are, CURRENT_DOMAIN, ALL_DOMAINS_ON_THIS_SERVER.
    type: list
    elements: str
  ignore_warnings:
    description:
      - Apply changes ignoring warnings.
    type: bool
  ignore_errors:
    description:
      - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_objects
"""

EXAMPLES = """
- name: add-network-feed
  cp_mgmt_network_feed:
    custom_header:
      - header_name: header1
        header_value: value1
      - header_name: header2
        header_value: value2
    data_column: 1
    feed_format: Flat List
    feed_type: IP Address
    feed_url: https://www.feedsresource.com/resource
    fields_delimiter: "\t"
    ignore_lines_that_start_with: '!'
    name: network_feed
    password: feed_password
    state: present
    update_interval: 60
    use_gateway_proxy: false
    username: feed_username

- name: set-network-feed
  cp_mgmt_network_feed:
    custom_header:
      - header_name: new_header
        header_value: new_value
    data_column: 1
    feed_format: Flat List
    feed_type: IP Address
    feed_url: https://www.feedsresource.com/new_resource
    fields_delimiter: ','
    ignore_lines_that_start_with: '!'
    name: network_feed
    password: new_password
    state: present
    update_interval: 60
    use_gateway_proxy: false
    username: new_username

- name: delete-network-feed
  cp_mgmt_network_feed:
    name: network_feed
    state: absent
"""

RETURN = """
cp_mgmt_network_feed:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    checkpoint_argument_spec_for_objects,
    api_call,
)


def main():
    argument_spec = dict(
        name=dict(type="str", required=True),
        feed_url=dict(type="str"),
        certificate_id=dict(type="str"),
        feed_format=dict(type="str", choices=["Flat List", "JSON"]),
        feed_type=dict(
            type="str", choices=["Domain", "IP Address", "IP Address/Domain"]
        ),
        password=dict(type="str", no_log=True),
        tags=dict(type="list", elements="str"),
        username=dict(type="str"),
        custom_header=dict(
            type="list",
            elements="dict",
            options=dict(
                header_name=dict(type="str"), header_value=dict(type="str")
            ),
        ),
        update_interval=dict(type="int"),
        data_column=dict(type="int"),
        fields_delimiter=dict(type="str"),
        ignore_lines_that_start_with=dict(type="str"),
        json_query=dict(type="str"),
        use_gateway_proxy=dict(type="bool"),
        color=dict(
            type="str",
            choices=[
                "aquamarine",
                "black",
                "blue",
                "crete blue",
                "burlywood",
                "cyan",
                "dark green",
                "khaki",
                "orchid",
                "dark orange",
                "dark sea green",
                "pink",
                "turquoise",
                "dark blue",
                "firebrick",
                "brown",
                "forest green",
                "gold",
                "dark gold",
                "gray",
                "dark gray",
                "light green",
                "lemon chiffon",
                "coral",
                "sea green",
                "sky blue",
                "magenta",
                "purple",
                "slate blue",
                "violet red",
                "navy blue",
                "olive",
                "orange",
                "red",
                "sienna",
                "yellow",
            ],
        ),
        comments=dict(type="str"),
        details_level=dict(type="str", choices=["uid", "standard", "full"]),
        domains_to_process=dict(type="list", elements="str"),
        ignore_warnings=dict(type="bool"),
        ignore_errors=dict(type="bool"),
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True
    )
    api_call_object = "network-feed"

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
