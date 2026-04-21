#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: bare_metal
short_description: Manages bare metal machines on Vultr.
description:
  - Manage bare metal machines on Vultr.
version_added: "1.9.0"
author:
  - "René Moser (@resmo)"
options:
  label:
    description:
      - Name of the bare metal machine.
    required: true
    aliases: [ name ]
    type: str
  hostname:
    description:
      - The hostname to assign to this bare metal machine.
    type: str
  os:
    description:
      - The operating system name.
      - Mutually exclusive with I(image) and I(app).
    type: str
  app:
    description:
      - The app deploy name of Vultr OneClick apps.
      - Mutually exclusive with I(image) and I(os).
    type: str
  image:
    description:
      - The image deploy name of Vultr Marketplace apps.
      - Mutually exclusive with I(os) and I(app).
    type: str
  plan:
    description:
      - The plan name to use for the bare metal machine.
      - Required if the bare metal machine does not yet exist.
    type: str
  activation_email:
    description:
      - Whether to send an activation email when the bare metal machine is ready or not.
      - Only considered on creation.
    type: bool
    default: false
  persistent_pxe:
    description:
      - Whether to enable persistent PXE or not.
    type: bool
  enable_ipv6:
    description:
      - Whether to enable IPv6 or not.
    type: bool
  tags:
    description:
      - Tags for the bare metal machine.
    type: list
    elements: str
  user_data:
    description:
      - User data to be passed to the bare metal machine.
    type: str
  startup_script:
    description:
      - Name or ID of the startup script to execute on boot.
      - Only considered while creating the bare metal machine.
    type: str
  ssh_keys:
    description:
      - List of SSH key names passed to the bare metal machine on creation.
    type: list
    elements: str
  snapshot:
    description:
      - Description or ID of the snapshot.
      - Only considered while creating the bare metal machine.
    type: str
  reserved_ipv4:
    description:
      - IP address of the floating IP to use as the main IP of this bare metal machine.
      - Only considered on creation.
    type: str
  region:
    description:
      - Region the bare metal machine is deployed into.
    type: str
    required: true
  vpc2s:
    description:
      - A list of VPCs (VPC 2.0) identified by their description to be assigned to the bare metal machine.
    type: list
    elements: str
  skip_wait:
    description:
      - Whether to skip the wait for the instance to be completely ready for access.
    type: bool
    default: false
    version_added: "1.13.0"
  state:
    description:
      - State of the bare metal machine.
    default: present
    choices: [ present, absent ]
    type: str
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
---
- name: Create an bare metal machine using OS
  vultr.cloud.bare_metal:
    label: my web server
    hostname: my-hostname
    user_data: |
      #cloud-config
      packages:
        - nginx
    plan: vbm-4c-32gb
    enable_ipv6: true
    ssh_keys:
      - my ssh key
    vpc2s:
      - my vpc description
    tags:
      - web
      - project-genesis
    region: ams
    os: Debian 12 x64 (bookworm)

- name: Deploy an bare metal machine of a marketplace app
  vultr.cloud.bare_metal:
    label: git-server
    hostname: git
    plan: vbm-4c-32gb
    enable_ipv6: true
    region: ams
    image: Gitea on Ubuntu 20.04

- name: Delete an bare metal machine
  vultr.cloud.bare_metal:
    label: my web server
    region: ams
    state: absent
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
vultr_bare_metal:
  description: Response from Vultr API.
  returned: success
  type: dict
  contains:
    id:
      description: ID of the bare metal machine.
      returned: success
      type: str
      sample: cb676a46-66fd-4dfb-b839-443f2e6c0b60
    v6_main_ip:
      description: IPv6 of the bare metal machine.
      returned: success
      type: str
      sample: ""
    v6_network:
      description: IPv6 network of the bare metal machine.
      returned: success
      type: str
      sample: ""
    v6_network_size:
      description: IPv6 network size of the bare metal machine.
      returned: success
      type: int
      sample: 0
    mac_address:
      description: MAC address of the bare metal machine.
      returned: success
      type: int
      sample: 2199756823533
    main_ip:
      description: IPv4 of the bare metal machine.
      returned: success
      type: str
      sample: 95.179.189.95
    netmask_v4:
      description: Netmask IPv4 of the bare metal machine.
      returned: success
      type: str
      sample: 255.255.254.0
    gateway_v4:
      description: Gateway IPv4.
      returned: success
      type: str
      sample: 95.179.188.1
    disk:
      description: Disk info of the bare metal machine.
      returned: success
      type: str
      sample: "2x 240GB SSD"
    cpu_count:
      description: CPU count of the bare metal machine.
      returned: success
      type: int
      sample: 1
    plan:
      description: Plan of the bare metal machine.
      returned: success
      type: str
      sample: vbm-4c-32gb
    image_id:
      description: Image ID of the bare metal machine.
      returned: success
      type: str
      sample: ""
    os_id:
      description: OS ID of the bare metal machine.
      returned: success
      type: int
      sample: 186
    app_id:
      description: App ID of the bare metal machine.
      returned: success
      type: int
      sample: 37
    date_created:
      description: Date when the bare metal machine was created.
      returned: success
      type: str
      sample: "2020-10-10T01:56:20+00:00"
    label:
      description: Label of the bare metal machine.
      returned: success
      type: str
      sample: my bare metal machine
    region:
      description: Region the bare metal machine was deployed into.
      returned: success
      type: str
      sample: ews
    status:
      description: Status about the deployment of the bare metal machine.
      returned: success
      type: str
      sample: active
    default_password:
      description: The default password assigned at deployment. Only available for ten minutes after deployment.
      returned: success
      type: str
      sample: "examplePassword"
    power_status:
      description: Power status of the bare metal machine.
      returned: success
      type: str
      sample: running
    ram:
      description: RAM info of the bare metal machine.
      returned: success
      type: str
      sample: "32768 MB"
    os:
      description: OS of the bare metal machine.
      returned: success
      type: str
      sample: Application
    tags:
      description: Tags of the bare metal machine.
      returned: success
      type: list
      sample: [ my-tag ]
    features:
      description: Features of the bare metal machine.
      returned: success
      type: list
      sample: [ ddos_protection, ipv6, auto_backups ]
    user_data:
      description: Base64 encoded user data (cloud init) of the bare metal machine.
      returned: success
      type: str
      sample: I2Nsb3VkLWNvbmZpZwpwYWNrYWdlczoKICAtIGh0b3AK
    enable_ipv6:
      description: Whether IPv6 is enabled or not.
      returned: success
      type: bool
      sample: true
    vpc2s:
      description: List of VPCs (VPC 2.0) attached.
      returned: success
      type: list
      contains:
        id:
          description: ID of the VPC.
          returned: success
          type: str
          sample: 5536d2a4-66fd-4dfb-b839-7672fd5bc116
        description:
          description: Description of the VPC.
          returned: success
          type: str
          sample: my vpc
        region:
          description: Region the VPC is assigned to.
          returned: success
          type: str
          sample: ews
        date_created:
          description: Date when the VPC was created.
          returned: success
          type: str
          sample: "2020-10-10T01:56:20+00:00"
        ip_block:
          description: IP block assigned to the VPC.
          returned: success
          type: str
          sample: "10.99.0.0"
        prefix_length:
          description: The number of bits for the netmask in CIDR notation.
          returned: success
          type: int
          sample: 24
"""


from ansible.module_utils.basic import AnsibleModule

from ..module_utils.common_instance import AnsibleVultrCommonInstance
from ..module_utils.vultr_v2 import vultr_argument_spec


def main():
    argument_spec = vultr_argument_spec()
    argument_spec.update(
        dict(
            label=dict(type="str", required=True, aliases=["name"]),
            hostname=dict(type="str"),
            app=dict(type="str"),
            image=dict(type="str"),
            snapshot=dict(type="str"),
            os=dict(type="str"),
            plan=dict(type="str"),
            activation_email=dict(type="bool", default=False),
            enable_ipv6=dict(type="bool"),
            persistent_pxe=dict(type="bool"),
            tags=dict(type="list", elements="str"),
            vpc2s=dict(type="list", elements="str"),
            reserved_ipv4=dict(type="str"),
            startup_script=dict(type="str"),
            user_data=dict(type="str"),
            ssh_keys=dict(type="list", elements="str", no_log=False),
            region=dict(type="str", required=True),
            skip_wait=dict(type="bool", default=False),
            state=dict(
                choices=[
                    "present",
                    "absent",
                ],
                default="present",
            ),
        )  # type: ignore
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=(("state", "present", ("plan",)),),
        mutually_exclusive=(("os", "app", "image", "snapshot"),),
        supports_check_mode=True,
    )

    vultr = AnsibleVultrCommonInstance(
        module=module,
        namespace="vultr_bare_metal",
        resource_path="/bare-metals",
        ressource_result_key_singular="bare_metal",
        resource_create_param_keys=[
            "label",
            "hostname",
            "plan",
            "app_id",
            "os_id",
            "iso_id",
            "image_id",
            "snapshot_id",
            "script_id",
            "region",
            "enable_ipv6",
            "reserved_ipv4",
            "user_data",
            "tags",
            "activation_email",
            "sshkey_id",
            "persistent_pxe",
            "attach_vpc2",
        ],
        resource_update_param_keys=[
            "plan",
            "tags",
            "enable_ipv6",
            "user_data",
            "attach_vpc2",
            "detach_vpc2",
        ],
        resource_key_name="label",
    )

    state = module.params.get("state")  # type: ignore
    if state == "absent":
        vultr.absent()
    else:
        vultr.present()


if __name__ == "__main__":
    main()
