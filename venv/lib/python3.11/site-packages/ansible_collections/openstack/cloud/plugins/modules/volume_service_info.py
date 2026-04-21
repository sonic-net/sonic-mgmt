#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Bitswalk, inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: volume_service_info
short_description: Fetch OpenStack Volume (Cinder) services
author: OpenStack Ansible SIG
description:
  - Fetch OpenStack Volume (Cinder) services.
options:
  binary:
    description:
      - Filter the service list result by binary name of the service.
    type: str
  host:
    description:
      - Filter the service list result by the host name.
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Fetch all OpenStack Volume (Cinder) services
  openstack.cloud.volume_service_info:
    cloud: awesomecloud

- name: Fetch a subset of OpenStack Volume (Cinder) services
  openstack.cloud.volume_service_info:
    cloud: awesomecloud
    binary: "cinder-volume"
    host: "localhost"
'''

RETURN = r'''
volume_services:
  description: List of dictionaries describing Volume (Cinder) services.
  returned: always
  type: list
  elements: dict
  contains:
    availability_zone:
      description: The availability zone name.
      type: str
    binary:
      description: The binary name of the service.
      type: str
    disabled_reason:
      description: The reason why the service is disabled
      type: str
    host:
      description: The name of the host.
      type: str
    name:
      description: Service name
      type: str
    state:
      description: The state of the service. One of up or down.
      type: str
    status:
      description: The status of the service. One of enabled or disabled.
      type: str
    update_at:
      description: The date and time when the resource was updated
      type: str
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class VolumeServiceInfoModule(OpenStackModule):

    argument_spec = dict(
        binary=dict(),
        host=dict(),
    )

    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        kwargs = {k: self.params[k]
                  for k in ['binary', 'host']
                  if self.params[k] is not None}
        volume_services = self.conn.block_storage.services(**kwargs)

        self.exit_json(changed=False,
                       volume_services=[s.to_dict(computed=False)
                                        for s in volume_services])


def main():
    module = VolumeServiceInfoModule()
    module()


if __name__ == '__main__':
    main()
