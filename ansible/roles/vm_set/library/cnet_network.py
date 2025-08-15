#!/usr/bin/python
import subprocess
import re
import os
import os.path
import re
import docker
from ansible.module_utils.basic import *
import traceback
from pprint import pprint

DOCUMENTATION = '''
---
module: cnet_network

short_description: Create network for container
description:
    the module creates follow network interfaces
    - 1 management interface which is added to management bridge
'''
EXAMPLES = '''
- name: Create VMs network
  cnet_network:
    name:        net_{{ vm_set_name }}_{{ vm_name }}
    vm_name:     "{{ vm_name }}"
    fp_mtu:      "{{ fp_mtu_size }}"
'''

DEFAULT_MTU = 0
NUM_FP_VLANS_PER_FP = 4
VM_SET_NAME_MAX_LEN = 8  # used in interface names. So restricted
CMD_DEBUG_FNAME = "/tmp/cnet_network.cmds.%s.txt"
EXCEPTION_DEBUG_FNAME = "/tmp/cnet_network.exception.%s.txt"

OVS_FP_BRIDGE_REGEX = 'br-%s-\d+'
OVS_FP_BRIDGE_TEMPLATE = 'br-%s-%d'
def main():
    if __name__ == "__main__":
        main()