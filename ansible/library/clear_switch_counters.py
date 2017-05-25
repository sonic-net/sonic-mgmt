#!/usr/bin/python

DOCUMENTATION = '''
---
module: clear_switch_counters
version_added: "1.9"
author: Guohan Lu (gulv@microsoft.com)
short_description: Clear switch counters for a device
description:
    - Clear switch counters for a device
options:
'''

EXAMPLES = '''
# Clear switch counters
- name: clear switch counters about the device
  clear_switch_counters:
'''

from ansible.module_utils.basic import *
import socket
import struct
import re
import json

def main():
    module = AnsibleModule(
        argument_spec=dict(),
        supports_check_mode=False)

    # assume it's broadcom switch
    rc, out, err = module.run_command("bcmcmd \"clear c all\"")
    if rc != 0:
        module.fail_json(msg="Command failed rc=%d, out=%s, err=%s" %
                (rc, out, err))

    module.exit_json(changed=True)

if __name__ == "__main__":
    main()
