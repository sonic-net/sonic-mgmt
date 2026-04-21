#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2022, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: instance_info
short_description: Get information about the Vultr instances
description:
  - Get infos about available instances.
version_added: "1.5.0"
author:
  - "René Moser (@resmo)"
options:
  label:
    description:
      - Name of the instance.
    aliases: [ name ]
    type: str
  region:
    description:
      - Filter instances by region.
    type: str
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
- name: Get Vultr instance infos of region ams
  vultr.cloud.instance_info:
    region: ams

- name: Get Vultr instance infos of a single host
  vultr.cloud.instance_info:
    label: myhost

- name: Get all Vultr instance infos
  vultr.cloud.instance_info:
  register: results

- name: Print the gathered infos
  ansible.builtin.debug:
    var: results.vultr_instance_info
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
vultr_instance_info:
  description: Response from Vultr API as list.
  returned: available
  type: list
  contains:
    id:
      description: ID of the instance.
      returned: success
      type: str
      sample: cb676a46-66fd-4dfb-b839-443f2e6c0b60
    v6_main_ip:
      description: IPv6 of the instance.
      returned: success
      type: str
      sample: ""
    v6_network:
      description: IPv6 network of the instance.
      returned: success
      type: str
      sample: ""
    v6_network_size:
      description: IPv6 network size of the instance.
      returned: success
      type: int
      sample: 0
    main_ip:
      description: IPv4 of the instance.
      returned: success
      type: str
      sample: 95.179.189.95
    netmask_v4:
      description: Netmask IPv4 of the instance.
      returned: success
      type: str
      sample: 255.255.254.0
    hostname:
      description: Hostname of the instance.
      returned: success
      type: str
      sample: vultr.guest
    internal_ip:
      description: Internal IP of the instance.
      returned: success
      type: str
      sample: ""
    gateway_v4:
      description: Gateway IPv4.
      returned: success
      type: str
      sample: 95.179.188.1
    kvm:
      description: KVM of the instance.
      returned: success
      type: str
      sample: "https://my.vultr.com/subs/vps/novnc/api.php?data=..."
    disk:
      description: Disk size of the instance.
      returned: success
      type: int
      sample: 25
    allowed_bandwidth:
      description: Allowed bandwidth of the instance.
      returned: success
      type: int
      sample: 1000
    vcpu_count:
      description: vCPUs of the instance.
      returned: success
      type: int
      sample: 1
    firewall_group_id:
      description: Firewall group ID of the instance.
      returned: success
      type: str
      sample: ""
    plan:
      description: Plan of the instance.
      returned: success
      type: str
      sample: vc2-1c-1gb
    image_id:
      description: Image ID of the instance.
      returned: success
      type: str
      sample: ""
    os_id:
      description: OS ID of the instance.
      returned: success
      type: int
      sample: 186
    app_id:
      description: App ID of the instance.
      returned: success
      type: int
      sample: 37
    date_created:
      description: Date when the instance was created.
      returned: success
      type: str
      sample: "2020-10-10T01:56:20+00:00"
    label:
      description: Label of the instance.
      returned: success
      type: str
      sample: my instance
    region:
      description: Region the instance was deployed into.
      returned: success
      type: str
      sample: ews
    status:
      description: Status about the deployment of the instance.
      returned: success
      type: str
      sample: active
    server_status:
      description: Server status of the instance.
      returned: success
      type: str
      sample: installingbooting
    power_status:
      description: Power status of the instance.
      returned: success
      type: str
      sample: running
    ram:
      description: RAM in MB of the instance.
      returned: success
      type: int
      sample: 1024
    os:
      description: OS of the instance.
      returned: success
      type: str
      sample: Application
    tags:
      description: Tags of the instance.
      returned: success
      type: list
      sample: [ my-tag ]
    features:
      description: Features of the instance.
      returned: success
      type: list
      sample: [ ddos_protection, ipv6, auto_backups ]
    user_data:
      description: Base64 encoded user data (cloud init) of the instance.
      returned: success
      type: str
      sample: I2Nsb3VkLWNvbmZpZwpwYWNrYWdlczoKICAtIGh0b3AK

"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.vultr_v2 import AnsibleVultr, vultr_argument_spec


def main():
    argument_spec = vultr_argument_spec()
    argument_spec.update(
        dict(
            region=dict(type="str"),
            label=dict(type="str", aliases=["name"]),
        )  # type: ignore
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    vultr = AnsibleVultr(
        module=module,
        namespace="vultr_instance_info",
        resource_path="/instances",
        ressource_result_key_singular="instance",
        ressource_result_key_plural="instances",
    )

    query_params = dict()
    if module.params["region"] is not None:  # type: ignore
        query_params.update({"region": module.params["region"]})  # type: ignore

    if module.params["label"] is not None:  # type: ignore
        query_params.update({"label": module.params["label"]})  # type: ignore

    vultr.get_result(vultr.query_list(query_params=query_params))


if __name__ == "__main__":
    main()
