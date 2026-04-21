#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Ansible Project
# Copyright: (c) 2020, Tyler Auerbeck <tauerbec@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: digital_ocean_droplet_info
short_description: Gather information about DigitalOcean Droplets
description:
    - This module can be used to gather information about Droplets.
author: "Tyler Auerbeck (@tylerauerbeck)"
version_added: 1.4.0

options:
  id:
    description:
      - Droplet ID that can be used to identify and reference a droplet.
    type: str
  name:
    description:
      - Droplet name that can be used to identify and reference a droplet.
    type: str

extends_documentation_fragment:
- community.digitalocean.digital_ocean
"""


EXAMPLES = r"""
- name: Gather information about all droplets
  community.digitalocean.digital_ocean_droplet_info:
    oauth_token: "{{ oauth_token }}"

- name: Gather information about a specific droplet by name
  community.digitalocean.digital_ocean_droplet_info:
    oauth_token: "{{ oauth_token }}"
    name: my-droplet-name

- name: Gather information about a specific droplet by id
  community.digitalocean.digital_ocean_droplet_info:
    oauth_token: "{{ oauth_token }}"
    id: abc-123-d45

- name: Get information about all droplets to loop through
  community.digitalocean.digital_ocean_droplet_info:
    oauth_token: "{{ oauth_token }}"
  register: droplets

- name: Get number of droplets
  set_fact:
    droplet_count: "{{ droplets.data | length }}"
"""

RETURN = r"""
data:
  description: "DigitalOcean droplet information"
  elements: dict
  returned: success
  sample:
    - backup_ids: []
      created_at: "2021-04-07T00:44:53Z"
      disk: 25
      features:
        - private_networking
      id: 123456789
      image:
        created_at: "2020-10-20T08:49:55Z"
        description: "Ubuntu 18.04 x86 image"
        distribution: Ubuntu
        id: 987654321
        min_disk_size: 15
        name: "18.04 (LTS) x64"
        public: false
        regions: []
        size_gigabytes: 0.34
        slug: ~
        status: retired
        tags: []
        type: base
      kernel: ~
      locked: false
      memory: 1024
      name: my-droplet-01
      networks:
        v4:
          - gateway: ""
            ip_address: "1.2.3.4"
            netmask: "255.255.240.0"
            type: private
          - gateway: "5.6.7.8"
            ip_address: "4.3.2.1"
            netmask: "255.255.240.0"
            type: public
        v6: []
      next_backup_window: ~
      region:
        available: true
        features:
          - backups
          - ipv6
          - metadata
          - install_agent
          - storage
          - image_transfer
        name: "New York 1"
        sizes:
          - s-1vcpu-1gb
          - s-1vcpu-1gb-intel
          - s-1vcpu-2gb
          - s-1vcpu-2gb-intel
          - s-2vcpu-2gb
          - s-2vcpu-2gb-intel
          - s-2vcpu-4gb
          - s-2vcpu-4gb-intel
          - s-4vcpu-8gb
          - c-2
          - c2-2vcpu-4gb
          - s-4vcpu-8gb-intel
          - g-2vcpu-8gb
          - gd-2vcpu-8gb
          - s-8vcpu-16gb
          - m-2vcpu-16gb
          - c-4
          - c2-4vcpu-8gb
          - s-8vcpu-16gb-intel
          - m3-2vcpu-16gb
          - g-4vcpu-16gb
          - so-2vcpu-16gb
          - m6-2vcpu-16gb
          - gd-4vcpu-16gb
          - so1_5-2vcpu-16gb
          - m-4vcpu-32gb
          - c-8
          - c2-8vcpu-16gb
          - m3-4vcpu-32gb
          - g-8vcpu-32gb
          - so-4vcpu-32gb
          - m6-4vcpu-32gb
          - gd-8vcpu-32gb
          - so1_5-4vcpu-32gb
          - m-8vcpu-64gb
          - c-16
          - c2-16vcpu-32gb
          - m3-8vcpu-64gb
          - g-16vcpu-64gb
          - so-8vcpu-64gb
          - m6-8vcpu-64gb
          - gd-16vcpu-64gb
          - so1_5-8vcpu-64gb
          - m-16vcpu-128gb
          - c-32
          - c2-32vcpu-64gb
          - m3-16vcpu-128gb
          - m-24vcpu-192gb
          - g-32vcpu-128gb
          - so-16vcpu-128gb
          - m6-16vcpu-128gb
          - gd-32vcpu-128gb
          - m3-24vcpu-192gb
          - g-40vcpu-160gb
          - so1_5-16vcpu-128gb
          - m-32vcpu-256gb
          - gd-40vcpu-160gb
          - so-24vcpu-192gb
          - m6-24vcpu-192gb
          - m3-32vcpu-256gb
          - so1_5-24vcpu-192gb
          - so-32vcpu-256gb
          - m6-32vcpu-256gb
          - so1_5-32vcpu-256gb
        slug: nyc1
      size:
        available: true
        description: Basic
        disk: 25
        memory: 1024
        price_hourly: 0.00744
        price_monthly: 5.0
        regions:
          - ams2
          - ams3
          - blr1
          - fra1
          - lon1
          - nyc1
          - nyc2
          - nyc3
          - sfo1
          - sfo3
          - sgp1
          - tor1
        slug: s-1vcpu-1gb
        transfer: 1.0
        vcpus: 1
      size_slug: s-1vcpu-1gb
      snapshot_ids: []
      status: active
      tags:
        - tag1
      vcpus: 1
      volume_ids: []
      vpc_uuid: 123-abc-567a
  type: list
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.digitalocean.plugins.module_utils.digital_ocean import (
    DigitalOceanHelper,
)


def run(module):
    rest = DigitalOceanHelper(module)

    if module.params["id"]:
        path = "droplets/" + module.params["id"]
        response = rest.get(path)
        if response.status_code != 200:
            module.fail_json(
                msg="Failed to fetch 'droplets' information due to error: %s"
                % response.json["message"]
            )
    else:
        response = rest.get_paginated_data(
            base_url="droplets?", data_key_name="droplets"
        )

    if module.params["id"]:
        data = [response.json["droplet"]]
    elif module.params["name"]:
        data = [d for d in response if d["name"] == module.params["name"]]
        if not data:
            module.fail_json(
                msg="Failed to fetch 'droplets' information due to error: Unable to find droplet with name %s"
                % module.params["name"]
            )
    else:
        data = response

    module.exit_json(changed=False, data=data)


def main():
    argument_spec = DigitalOceanHelper.digital_ocean_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=False, default=None),
        id=dict(type="str", required=False, default=None),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[("id", "name")],
    )
    run(module)


if __name__ == "__main__":
    main()
