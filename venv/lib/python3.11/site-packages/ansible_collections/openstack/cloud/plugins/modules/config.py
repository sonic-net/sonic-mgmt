#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: config
short_description: Get OpenStack Client config
author: OpenStack Ansible SIG
description:
  - Get OpenStack cloud credentials and configuration,
    e.g. from clouds.yaml and environment variables.
options:
   clouds:
     description:
        - List of clouds to limit the return list to.
        - When I(clouds) is not defined, then data
          is returned for all configured clouds.
     default: []
     type: list
     elements: str
requirements:
  - "python >= 3.6"
  - "openstacksdk >= 1.0.0"
'''

RETURN = r'''
clouds:
  description: List of OpenStack cloud configurations.
  returned: always
  type: list
  elements: dict
  contains:
    name:
      description: Name of the cloud.
      type: str
    config:
      description: A dict of configuration values for the CloudRegion and
                   its services. The key for a ${config_option} for a
                   specific ${service} should be ${service}_${config_option}.
      type: dict
'''

EXAMPLES = r'''
- name: Read configuration of all defined clouds
  openstack.cloud.config:
  register: config

- name: Print clouds which do not support security groups
  loop: "{{ config.clouds }}"
  when: item.config.secgroup_source|default(None) != None
  debug:
    var: item

- name: Read configuration of a two specific clouds
  openstack.cloud.config:
    clouds:
      - devstack
      - mordred
'''

from ansible.module_utils.basic import AnsibleModule

try:
    import openstack.config
    from openstack import exceptions
    HAS_OPENSTACKSDK = True
except ImportError:
    HAS_OPENSTACKSDK = False


def main():
    module = AnsibleModule(
        argument_spec=dict(
            clouds=dict(type='list', default=[], elements='str'),
        )
    )

    if not HAS_OPENSTACKSDK:
        module.fail_json(msg='openstacksdk is required for this module')

    try:
        clouds = [dict(name=cloud.name, config=cloud.config)
                  for cloud in openstack.config.OpenStackConfig().get_all()
                  if not module.params['clouds']
                  or cloud.name in module.params['clouds']]

        module.exit_json(changed=False, clouds=clouds)

    except exceptions.SDKException as e:
        module.fail_json(msg=str(e))


if __name__ == "__main__":
    main()
