#!/usr/bin/python
#
# Copyright (c) 2023, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: snapshot_info
short_description: Gather information about the Vultr snapshots
description:
  - Gather information about snapshots available.
version_added: "1.7.0"
author:
  - "René Moser (@resmo)"
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
- name: Gather Vultr snapshots information
  vultr.cloud.snapshot_info:
  register: result

- name: Print the gathered information
  ansible.builtin.debug:
    var: result.vultr_snapshot_info
"""

RETURN = """
---
vultr_api:
  description: Response from Vultr API with a few additions/modification.
  returned: success
  type: dict
  contains:
    api_timeout:
      description: Timeout used for the API requests.
      returned: success
      type: int
      sample: 60
    api_retries:
      description: Amount of max retries for the API requests.
      returned: success
      type: int
      sample: 5
    api_retry_max_delay:
      description: Exponential backoff delay in seconds between retries up to this max delay value.
      returned: success
      type: int
      sample: 12
    api_endpoint:
      description: Endpoint used for the API requests.
      returned: success
      type: str
      sample: "https://api.vultr.com/v2"
vultr_snapshot_info:
  description: Response from Vultr API as list.
  returned: success
  type: list
  contains:
    id:
      description: ID of the snapshot.
      returned: success
      type: str
      sample: cb676a46-66fd-4dfb-b839-443f2e6c0b60
    description:
      description: Description of the snapshot.
      returned: success
      type: str
      sample: my vpc
    date_created:
      description: Date the snapshot was created.
      returned: success
      type: str
      sample: "2020-10-10T01:56:20+00:00"
    size:
      description: Size of the snapshot.
      returned: success
      type: int
      sample: 42949672960
    compressed_size:
      description: Compressed size of the snapshot.
      returned: success
      type: int
      sample: 949678560
    status:
      description: Status of the snapshot.
      returned: success
      type: str
      sample: complete
    os_id:
      description: ID of the OS.
      returned: success
      type: int
      sample: 215
    app_id:
      description: ID of the app.
      returned: success
      type: int
      sample: 0
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.vultr_v2 import AnsibleVultr, vultr_argument_spec


def main():
    argument_spec = vultr_argument_spec()

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    vultr = AnsibleVultr(
        module=module,
        namespace="vultr_snapshot_info",
        resource_path="/snapshots",
        ressource_result_key_singular="snapshot",
    )

    vultr.get_result(vultr.query_list())


if __name__ == "__main__":
    main()
