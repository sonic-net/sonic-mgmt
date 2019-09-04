#!/usr/bin/python
from ansible.module_utils.basic import *

DOCUMENTATION = '''
---
module:  blkid
version_added:  "2.0"
author: Joe Lazaro (@joeslazaro) and Joe Jacobs (@joej164)
short_description: Parse the blkid linux command and return a dict 
description: |
    Expects a text blob with partitions and details of the partitions
    Returns a dictionary of all the data
'''

def parse_blkid_output(text):
    """Extract a dictionary based on field names in each row

    Arguments:
        text: Text table to be parsed


    Example of text this tool will parse:

    /dev/sda2: LABEL="ONIE-BOOT" UUID="e88e09a3-c6c7-48e0-8ae1-e3a67efab4bb" TYPE="ext4" PTTYPE="dos" PARTLABEL="ONIE-BOOT" PARTUUID="6db4e50c-0fa1-4c00-b853-b1f66e05ab55"
    /dev/sda3: LABEL="SONiC-OS" UUID="0737fc07-6e7e-4f31-81c9-507b08dfe6d2" TYPE="ext4" PARTLABEL="SONiC-OS" PARTUUID="354b7df3-7280-48f5-af6d-7802308f9850"
    /dev/loop0: TYPE="squashfs"
    /dev/loop1: UUID="cf9c7646-b5f6-482e-bcf5-b1523b9f43e7" TYPE="ext4"
    /dev/sda1: PARTLABEL="GRUB-BOOT" PARTUUID="730500ba-46b7-435b-b057-94afc8cd1335"

    """
    device_attribs = {}

    for line in text.strip().splitlines():
        device, row_data = line.split(':')
        attrib_list = row_data.strip().split(' ')
        device_attribs[device] = {}
        for attrib_string in attrib_list:
            key, value = attrib_string.split('=')
            device_attribs[device][key] = value.strip('"')
 
    return device_attribs 


def main():
    module = AnsibleModule(
        argument_spec=dict(
            text=dict(required=True, type='str'),
        ),
        supports_check_mode=False)

    p = module.params
    dict_result = parse_blkid_output(p['text'])
    module.exit_json(ansible_facts={'blkid_dict': dict_result})

if __name__ == '__main__':
    main()
