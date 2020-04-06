#!/usr/bin/env python
# This ansible module is for gathering image facts from SONiC device.
#
# The "sonic_installer list" command can list the images on SONiC device, including:
# * Current image
# * Next image that will be used after reboot
# * All installed images
# This module is to use the "sonic_installer list" command to gather the image facts.
#
# Example of module output:
# {
#     "ansible_facts": {
#         "ansible_image_facts": {
#             "available": [
#                 "SONiC-OS-HEAD.949-3198971",
#                 "SONiC-OS-HEAD.986-2e9b18db"
#             ],
#             "current": "SONiC-OS-HEAD.986-2e9b18db",
#             "next": "SONiC-OS-HEAD.986-2e9b18db"
#         }
#     },
#     "changed": false,
#     "invocation": {
#         "module_args": {},
#         "module_name": "image_facts"
#     }
# }

from ansible.module_utils.basic import *


DOCUMENTATION = '''
---
module: image_facts
version_added: "2.0"
author: Xin Wang (xinw@mellanox.com)
short_description: Retrive image facts from SONiC device.
description:
    - Retrieve image facts from SONiC device, the facts will be
      inserted to the ansible_facts key.
options:
    N/A
'''

EXAMPLES = '''
# Gather image facts
- name: Gathering image facts from SONiC device
  image_facts:
'''


def get_image_info(module):
    """
    @summary: Parse image info in output of command 'sonic_installer list'
    @param module: The AnsibleModule object
    @return: Return parsed image info in dict
    """
    cmd = "sudo sonic_installer list"
    rc, stdout, stderr = module.run_command(cmd)
    if rc != 0:
        module.fail_json(msg='Failed to run %s, rc=%s, stdout=%s, stderr=%s' % (cmd, rc, stdout, stderr))

    try:
        image_info = {}
        image_list_line = False
        for line in stdout.splitlines():
            if not image_list_line:
                if 'Current: ' in line:
                    image_info['current'] = line.split('Current: ')[1]
                if 'Next: ' in line:
                    image_info['next'] = line.split('Next: ')[1]
                if 'Available:' in line:
                    image_list_line = True
                    image_info['available'] = []
                    continue
            else:
                image_info['available'].append(line)
        return image_info
    except Exception as e:
        module.fail_json(msg='Failed to parse image info from output of "%s", err=%s' % (cmd, str(e)))

    return None


def main():

    module = AnsibleModule(argument_spec=dict())

    image_info = get_image_info(module)
    if not image_info:
        module.fail_json(msg='Failed to get image info')

    module.exit_json(ansible_facts={'ansible_image_facts': image_info})


if __name__ == '__main__':
    main()
