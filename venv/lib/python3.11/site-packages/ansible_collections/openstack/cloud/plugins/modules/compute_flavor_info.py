#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2015 IBM
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: compute_flavor_info
short_description: Fetch compute flavors from OpenStack cloud
author: OpenStack Ansible SIG
description:
  - Fetch OpenStack compute flavors.
options:
  ephemeral:
    description:
      - Filter flavors based on the amount of ephemeral storage.
      - I(ephemeral) supports same format as I(ram) option.
    type: str
  limit:
    description:
      - Limits number of flavors to I(limit) results.
      - By default all matching flavors are returned.
    type: int
  name:
    description:
      - Flavor name.
    type: str
  ram:
    description:
      - "A string used for filtering flavors based on the amount of RAM
         (in MB) desired. This string accepts the following special values:
         'MIN' (return flavors with the minimum amount of RAM), and 'MAX'
         (return flavors with the maximum amount of RAM)."
      - "A specific amount of RAM may also be specified. Any flavors with this
         exact amount of RAM will be returned."
      - "A range of acceptable RAM may be given using a special syntax. Simply
         prefix the amount of RAM with one of these acceptable range values:
         '<', '>', '<=', '>='. These values represent less than, greater than,
         less than or equal to, and greater than or equal to, respectively."
    type: str
  vcpus:
    description:
      - Filter flavors based on the number of virtual CPUs.
      - I(vcpus) supports same format as I(ram) option.
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Gather information about all available flavors
  openstack.cloud.compute_flavor_info:
    cloud: mycloud

- name: Gather information for the flavor named "xlarge-flavor"
  openstack.cloud.compute_flavor_info:
    cloud: mycloud
    name: "xlarge-flavor"

- name: Get all flavors with 512 MB of RAM
  openstack.cloud.compute_flavor_info:
    cloud: mycloud
    ram: "512"

- name: Get all flavors with >= 1024 MB RAM
  openstack.cloud.compute_flavor_info:
    cloud: mycloud
    ram: ">=1024"

- name: Get a single flavor with minimum amount of RAM
  openstack.cloud.compute_flavor_info:
    cloud: mycloud
    ram: "MIN"
    limit: 1

- name: Get all flavors with >=1024 MB RAM and 2 vCPUs
  openstack.cloud.compute_flavor_info:
    cloud: mycloud
    ram: ">=1024"
    vcpus: "2"

- name: Get flavors with >= 1024 MB RAM 2 vCPUs and < 30gb ephemeral storage
  openstack.cloud.compute_flavor_info:
    cloud: mycloud
    ram: ">=1024"
    vcpus: "2"
    ephemeral: "<30"
'''

RETURN = r'''
flavors:
  description: List of dictionaries describing the compute flavors.
  returned: always
  type: list
  elements: dict
  contains:
    description:
      description: Description of the flavor
      type: str
      sample: "Small flavor"
    disk:
      description: Size of local disk, in GB.
      type: int
      sample: 10
    ephemeral:
      description: Ephemeral space size, in GB.
      type: int
      sample: 10
    extra_specs:
      description: Optional parameters to configure different flavors
                   options.
      type: dict
      sample: "{'hw_rng:allowed': True}"
    id:
      description: Flavor ID.
      type: str
      sample: "515256b8-7027-4d73-aa54-4e30a4a4a339"
    is_disabled:
      description: Wether the flavor is enabled or not
      type: bool
      sample: False
    is_public:
      description: Make flavor accessible to the public.
      type: bool
      sample: true
    name:
      description: Flavor name.
      type: str
      sample: "tiny"
    original_name:
      description: Original flavor name
      type: str
      sample: "tiny"
    ram:
      description: Amount of memory, in MB.
      type: int
      sample: 1024
    rxtx_factor:
      description: Factor to be multiplied by the rxtx_base property of
                   the network it is attached to in order to have a
                   different bandwidth cap.
      type: float
      sample: 1.0
    swap:
      description: Swap space size, in MB.
      type: int
      sample: 100
    vcpus:
      description: Number of virtual CPUs.
      type: int
      sample: 2
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class ComputeFlavorInfoModule(OpenStackModule):
    argument_spec = dict(
        ephemeral=dict(),
        limit=dict(type='int'),
        name=dict(),
        ram=dict(),
        vcpus=dict(),
    )

    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        name = self.params['name']

        filters = dict((k, self.params[k])
                       for k in ['ephemeral', 'ram', 'vcpus']
                       if self.params[k] is not None)

        if name:
            flavor = self.conn.compute.find_flavor(name)
            flavors = [flavor] if flavor else []
        else:
            flavors = list(self.conn.compute.flavors())

        if filters:
            flavors = self.conn.range_search(flavors, filters)

        limit = self.params['limit']
        if limit is not None:
            flavors = flavors[:limit]

        self.exit_json(changed=False,
                       flavors=[f.to_dict(computed=False) for f in flavors])


def main():
    module = ComputeFlavorInfoModule()
    module()


if __name__ == '__main__':
    main()
